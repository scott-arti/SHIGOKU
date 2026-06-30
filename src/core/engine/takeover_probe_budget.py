"""Per-target probe budget, dedupe window, and shared probe cache.

Prevents parallel recon and takeover Recipe from duplicating probes against the
same target, which wastes rate limit budget and scope guard resources.

Classes
-------
ProbeCache    — TTL-backed result cache keyed by candidate/provider/probe_type.
ProbeBudget   — Per-target sliding-window probe budget.
DedupeWindow  — Sliding-window deduplication guard.
check_probe_allowed — Convenience function combining all three checks.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Optional


class ProbeCache:
    """TTL-backed probe result cache.

    Cache entries are keyed by a deterministic hash of (candidate_id, provider,
    probe_type).  Entries expire after *ttl_seconds* from insertion.
    """

    def __init__(self, ttl_seconds: float = 3600) -> None:
        self._ttl = ttl_seconds
        self._store: dict[str, tuple[float, dict[str, Any]]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def make_key(self, candidate_id: str, provider: str, probe_type: str) -> str:
        """Return a deterministic, stable cache key.

        The key is a hex digest of a short canonical string built from the
        three inputs.  This is faster than storing compound tuples and ensures
        consumers cannot accidentally mutate the key.
        """
        raw = f"{candidate_id}|{provider}|{probe_type}"
        return hashlib.md5(raw.encode("utf-8")).hexdigest()

    def get(self, key: str) -> Optional[dict[str, Any]]:
        """Return cached result for *key*, or ``None`` when missing or expired."""
        entry = self._store.get(key)
        if entry is None:
            return None
        ts, result = entry
        if time.time() - ts > self._ttl:
            # Lazy eviction — expired entry is removed on access.
            del self._store[key]
            return None
        return result

    def set(self, key: str, result: dict[str, Any]) -> None:
        """Store *result* under *key* with the current wall-clock timestamp."""
        self._store[key] = (time.time(), result)


class ProbeBudget:
    """Per-target sliding-window probe budget.

    Each target is tracked independently.  *consume()* returns ``True`` when
    a slot is still available within the current window; ``False`` when the
    budget is exhausted.

    Parameters
    ----------
    max_probes:
        Maximum number of probes allowed per target within *window_seconds*.
    window_seconds:
        Length of the sliding window in seconds.
    """

    def __init__(self, max_probes: int = 10, window_seconds: float = 3600) -> None:
        if max_probes < 0:
            raise ValueError("max_probes must be >= 0")
        self._max = max_probes
        self._window = window_seconds
        self._buckets: dict[str, list[float]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def consume(self, target: str) -> bool:
        """Try to consume one probe slot for *target*.

        Returns ``True`` when a slot is available, ``False`` when the budget
        for this target is already exhausted.
        """
        now = time.time()
        timestamps = self._buckets.get(target, [])
        # Prune expired entries outside the sliding window.
        cutoff = now - self._window
        active = [t for t in timestamps if t > cutoff]
        if len(active) >= self._max:
            # Budget exhausted — store the pruned list so next call sees it
            # already cleaned.
            self._buckets[target] = active
            return False
        active.append(now)
        self._buckets[target] = active
        return True

    def remaining(self, target: str) -> int:
        """Return the number of probe slots still available for *target*."""
        now = time.time()
        timestamps = self._buckets.get(target, [])
        cutoff = now - self._window
        active = [t for t in timestamps if t > cutoff]
        self._buckets[target] = active
        return max(0, self._max - len(active))

    def reset(self, target: str) -> None:
        """Clear the budget state for *target*, restoring full capacity."""
        self._buckets.pop(target, None)


class DedupeWindow:
    """Sliding-window duplicate probe guard.

    Records probe keys and blocks any key that was already seen within
    *window_seconds*.
    """

    def __init__(self, window_seconds: float = 300) -> None:
        self._window = window_seconds
        self._seen: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_duplicate(self, key: str) -> bool:
        """Return ``True`` when *key* was already recorded within the window."""
        ts = self._seen.get(key)
        if ts is None:
            return False
        if time.time() - ts > self._window:
            del self._seen[key]
            return False
        return True

    def record(self, key: str) -> None:
        """Record *key* as seen at the current wall-clock time."""
        self._seen[key] = time.time()


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def check_probe_allowed(
    candidate_id: str,
    target: str,
    provider: str,
    probe_type: str,
    budget: ProbeBudget,
    cache: ProbeCache,
    dedupe: DedupeWindow,
    is_stale: bool = False,
) -> dict[str, Any]:
    """Run all three guards (cache → budget → dedupe) and return a verdict.

    Parameters
    ----------
    candidate_id:
        Stable identifier for the takeover candidate.
    target:
        The target resource being probed (e.g. hostname).
    provider:
        Provider guess string (e.g. ``"github_pages"``).
    probe_type:
        Probe kind (e.g. ``"http_probe"``, ``"dns_probe"``).
    budget:
        Per-target probe budget tracker.
    cache:
        Shared probe result cache.
    dedupe:
        Sliding-window deduplication guard.
    is_stale:
        When ``True`` the cache is bypassed so that the candidate can be
        re-verified.  Budget and dedupe checks are still enforced.

    Returns
    -------
    dict:
        ``{"allowed": bool, "reason": str, "cached_result": Optional[dict]}``

        Possible reasons:

        * ``"cache_hit"`` — a valid cached result exists (allowed=False).
        * ``"budget_exceeded"`` — the target's probe budget is exhausted.
        * ``"duplicate_blocked"`` — same (candidate, provider, probe_type) was
          probed within the dedupe window.
        * ``"allowed"`` — all checks passed; caller should execute the probe
          and then call ``cache.set()`` with the result.
    """
    probe_key = cache.make_key(candidate_id, provider, probe_type)

    # 1. Cache check (skipped for stale candidates).
    if not is_stale:
        cached = cache.get(probe_key)
        if cached is not None:
            return {"allowed": False, "reason": "cache_hit", "cached_result": cached}

    # 2. Dedupe check (before budget so we don't consume a slot for duplicates).
    if dedupe.is_duplicate(probe_key):
        return {"allowed": False, "reason": "duplicate_blocked", "cached_result": None}

    # 3. Budget check.
    if not budget.consume(target):
        return {"allowed": False, "reason": "budget_exceeded", "cached_result": None}

    # 4. Allowed — record in dedupe so follow-up calls are blocked.
    dedupe.record(probe_key)
    return {"allowed": True, "reason": "allowed", "cached_result": None}
