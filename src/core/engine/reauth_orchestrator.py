"""
ReauthOrchestrator: 再認証の実行制御モジュール

MasterConductor の再認証関連ロジックを集約:
  - single-flight (同一 target + principal + auth_context_version に対して1件だけ)
  - cooldown window (短期間に連続する SESSION_EXPIRED の collapse)
  - REAUTH_FAILED 時の degradation 遷移
  - 待機中タスクの隔離
  - Resume Policy Matrix (read-only / stateful / auth-sensitive)

Spec: docs/shigoku/subtasks/2026-06-20_sgk-2026-0280_reauth_subtask_plan.md
  Section 3.2: 再認証ストーム制御と失敗時縮退
  Section 3.3: Resume Policy Matrix
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Resume Policy
# ---------------------------------------------------------------------------

class ResumeDecision(Enum):
    """Possible decisions from the resume policy matrix."""
    ALLOW_RETRY = "allow_retry"       # Idempotent re-dispatch is safe
    REQUIRE_STATE_CHECK = "require_state_check"  # Must verify state before retry
    DISCARD = "discard"               # Old credentials; discard and re-generate
    HOLD = "hold"                     # Keep in queue but don't retry yet


def classify_task_for_resume(task: Any) -> str:
    """Classify a task for the resume policy matrix.

    Returns one of: 'read-only', 'stateful', 'auth-sensitive', 'unknown'.
    """
    tags: list[str] = list(getattr(task, "tags", []) or [])
    tag_set = {t.lower().strip() for t in tags}
    params = getattr(task, "params", {}) or {}
    if not isinstance(params, dict):
        params = {}
    category = str(params.get("category", "") or "").lower()
    action = str(getattr(task, "action", "") or "").lower().strip()
    agent_type = str(getattr(task, "agent_type", "") or "").lower().strip()

    # Auth-sensitive — tasks that directly manipulate or depend on credentials
    auth_tags = {"auth", "reauth", "session", "login", "jwt", "token"}
    if tag_set & auth_tags or "auth" in agent_type or "reauth" in category:
        return "auth-sensitive"

    # Stateful — tasks with potential side-effects
    stateful_indicators = {
        "stateful", "write", "create", "update", "delete", "modify",
        "basket", "order", "checkout", "purchase", "vote", "upload",
    }
    if tag_set & stateful_indicators:
        return "stateful"
    if action in ("write", "create", "update", "delete", "modify", "post", "put", "patch", "upload"):
        return "stateful"

    # Read-only — idempotent reads
    read_indicators = {"read", "get", "scan", "fetch", "recon", "discovery", "enumerate"}
    if tag_set & read_indicators or action in ("read", "get", "scan", "fetch", "recon"):
        return "read-only"

    return "unknown"


def apply_resume_policy(
    task_classification: str,
    auth_context_version: int,
    task_auth_version: int,
) -> ResumeDecision:
    """Apply the resume policy matrix.

    Args:
        task_classification: 'read-only', 'stateful', 'auth-sensitive', or 'unknown'
        auth_context_version: Current auth context version
        task_auth_version: Auth context version when the task was created

    Returns:
        Resume decision for the task.
    """
    auth_mismatch = task_auth_version < auth_context_version

    if task_classification == "read-only":
        # Idempotent re-dispatch is safe
        return ResumeDecision.ALLOW_RETRY

    if task_classification == "stateful":
        # Side-effects possible — require state check
        if auth_mismatch:
            return ResumeDecision.REQUIRE_STATE_CHECK
        return ResumeDecision.ALLOW_RETRY

    if task_classification == "auth-sensitive":
        # Auth context must match; discard old-instance tasks with stale credentials
        if auth_mismatch:
            return ResumeDecision.DISCARD
        return ResumeDecision.ALLOW_RETRY

    # Unknown — safe default: hold until explicit decision
    return ResumeDecision.HOLD


# ---------------------------------------------------------------------------
# In-flight Reauth Tracker
# ---------------------------------------------------------------------------

@dataclass
class ReauthInFlight:
    """Tracks a single in-flight reauth attempt."""

    reauth_attempt_id: str
    target: str
    started_at: float
    auth_context_version: int


@dataclass
class ReauthCooldown:
    """Cooldown state for a reauth target after a failed attempt."""

    target: str
    cooldown_until: float
    reason_code: str
    failed_at: float


# ---------------------------------------------------------------------------
# ReauthOrchestrator
# ---------------------------------------------------------------------------


class ReauthOrchestrator:
    """Central orchestrator for re-auth flow control.

    Handles:
      - Single-flight enforcement per target
      - Cooldown window management
      - Degradation state tracking
      - Resume policy decisions
    """

    def __init__(self, cooldown_window_seconds: float = 60.0, max_inflight: int = 3):
        self._inflight: dict[str, ReauthInFlight] = {}
        self._cooldowns: dict[str, ReauthCooldown] = {}
        self._degraded_targets: set[str] = set()
        self._quarantined_tasks: list[Any] = []
        self._quarantined_task_ids: set[str] = set()
        self._cooldown_window = cooldown_window_seconds
        self._max_inflight = max_inflight
        self._reauth_count_total = 0
        self._reauth_count_failed = 0

        # Storm suppression threshold
        self._recent_expired_events: list[float] = []

    # ------------------------------------------------------------------
    # Single-flight
    # ------------------------------------------------------------------

    def can_launch_reauth(self, target: str, auth_context_version: int) -> bool:
        """Check if a new reauth attempt can be launched.

        Rules:
          - Same target+version must not already be in-flight
          - Must not be in cooldown
          - Must not exceed max inflight count
        """
        # Clean stale cooldowns
        now = time.time()
        expired_cooldowns = [
            t for t, cd in self._cooldowns.items() if now >= cd.cooldown_until
        ]
        for t in expired_cooldowns:
            del self._cooldowns[t]

        # Check cooldown
        if target in self._cooldowns:
            cd = self._cooldowns[target]
            if now < cd.cooldown_until:
                logger.info(
                    "[ReauthOrch] Skipping reauth for %s: in cooldown until %.0f (reason=%s)",
                    target, cd.cooldown_until, cd.reason_code,
                )
                return False

        # Check in-flight
        key = f"{target}:{auth_context_version}"
        if key in self._inflight:
            logger.info(
                "[ReauthOrch] Skipping reauth for %s: already in-flight (version %d)",
                target, auth_context_version,
            )
            return False

        # Max inflight
        if len(self._inflight) >= self._max_inflight:
            logger.warning(
                "[ReauthOrch] Skipping reauth: max inflight (%d) reached",
                self._max_inflight,
            )
            return False

        return True

    def register_inflight(
        self, target: str, reauth_attempt_id: str, auth_context_version: int
    ) -> None:
        """Mark a reauth attempt as in-flight."""
        key = f"{target}:{auth_context_version}"
        self._inflight[key] = ReauthInFlight(
            reauth_attempt_id=reauth_attempt_id,
            target=target,
            started_at=time.time(),
            auth_context_version=auth_context_version,
        )
        self._reauth_count_total += 1

    def unregister_inflight(self, target: str, auth_context_version: int) -> None:
        """Remove in-flight record after completion."""
        key = f"{target}:{auth_context_version}"
        self._inflight.pop(key, None)

    # ------------------------------------------------------------------
    # Cooldown management
    # ------------------------------------------------------------------

    def apply_cooldown(
        self, target: str, reason_code: str, cooldown_until: float
    ) -> None:
        """Apply a cooldown after a failed reauth."""
        self._cooldowns[target] = ReauthCooldown(
            target=target,
            cooldown_until=cooldown_until,
            reason_code=reason_code,
            failed_at=time.time(),
        )
        self._reauth_count_failed += 1

    def is_in_cooldown(self, target: str) -> bool:
        now = time.time()
        if target in self._cooldowns:
            return now < self._cooldowns[target].cooldown_until
        return False

    # ------------------------------------------------------------------
    # Storm suppression
    # ------------------------------------------------------------------

    def record_expired_event(self) -> bool:
        """Record a SESSION_EXPIRED event for storm detection.

        Returns True if the event should be collapsed (storm active).
        """
        now = time.time()
        cutoff = now - self._cooldown_window
        self._recent_expired_events = [
            ts for ts in self._recent_expired_events if ts >= cutoff
        ]
        self._recent_expired_events.append(now)

        # Storm threshold: more than 5 expired events in the cooldown window
        if len(self._recent_expired_events) > 5:
            logger.warning(
                "[ReauthOrch] Storm detected: %d SESSION_EXPIRED in %.0fs — suppressing reauth",
                len(self._recent_expired_events), self._cooldown_window,
            )
            return True
        return False

    @property
    def is_storm_active(self) -> bool:
        now = time.time()
        cutoff = now - self._cooldown_window
        return len([ts for ts in self._recent_expired_events if ts >= cutoff]) > 5

    # ------------------------------------------------------------------
    # Degradation
    # ------------------------------------------------------------------

    def mark_degraded(self, target: str) -> None:
        """Mark a target as degraded — no further auto-reauth for this target."""
        self._degraded_targets.add(target)
        logger.warning("[ReauthOrch] Target %s marked as DEGRADED", target)

    def is_degraded(self, target: str) -> bool:
        return target in self._degraded_targets

    def clear_degraded(self, target: str) -> None:
        self._degraded_targets.discard(target)

    # ------------------------------------------------------------------
    # Task quarantine
    # ------------------------------------------------------------------

    def quarantine_task(self, task: Any, reason: str) -> None:
        """Quarantine a task that cannot be retried during degraded reauth state."""
        task_id = getattr(task, "id", str(id(task)))
        if task_id not in self._quarantined_task_ids:
            self._quarantined_task_ids.add(task_id)
            self._quarantined_tasks.append(task)
            logger.info("[ReauthOrch] Task %s quarantined: %s", task_id, reason)

    def release_quarantine(self, auth_context_version: int) -> list[Any]:
        """Release all quarantined tasks that can be retried with new auth."""
        released: list[Any] = []
        remaining: list[Any] = []
        for task in self._quarantined_tasks:
            classification = classify_task_for_resume(task)
            decision = apply_resume_policy(classification, auth_context_version, 0)
            if decision == ResumeDecision.ALLOW_RETRY:
                released.append(task)
            else:
                remaining.append(task)
        self._quarantined_tasks = remaining
        self._quarantined_task_ids = {getattr(t, "id", str(id(t))) for t in remaining}
        return released

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        return {
            "inflight_count": len(self._inflight),
            "cooldown_count": len(self._cooldowns),
            "degraded_targets": sorted(self._degraded_targets),
            "quarantined_count": len(self._quarantined_tasks),
            "reauth_total": self._reauth_count_total,
            "reauth_failed": self._reauth_count_failed,
            "storm_active": self.is_storm_active,
        }
