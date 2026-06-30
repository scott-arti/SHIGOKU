from __future__ import annotations

from contextlib import contextmanager
import hashlib
import threading
import time
from typing import Any

from src.core.engine.origin_normalizer import normalize_origin_key


class MutexPolicy:
    """Phase 4 shadow mutex policy.

    Computes mutex_key (hash) for shadow observation only.
    Does NOT consume or enforce real mutex/budget.
    Phase 4: mutation_surface is always UNKNOWN (exact derivation deferred to Phase 7 D-1).
    would_wait/would_reject are always False in shadow mode.
    """

    @staticmethod
    def decide(
        task_metadata: dict[str, Any] | None,
    ) -> tuple[str, str, bool, bool]:
        """Compute shadow mutex decision from task metadata.

        Args:
            task_metadata: Task.metadata dict containing:
                - origin_key: normalized origin key (str)
                - target: target URL for normalize_origin_key fallback (str)
                - session_key: session identifier (str, optional)
                - auth_context_version: auth context version (int, optional)

        Returns:
            (mutex_key, mutation_surface, would_wait, would_reject)
        """
        if not task_metadata:
            return ("", "unknown", False, False)

        # Extract origin key: prefer metadata.origin_key, fallback to normalize on target
        origin_key = task_metadata.get("origin_key", "")
        if not origin_key:
            target = task_metadata.get("target", "")
            if target:
                try:
                    origin_key = normalize_origin_key(target)
                except (ValueError, Exception):
                    origin_key = "unknown_origin"
            else:
                origin_key = "unknown_origin"

        session_key = str(task_metadata.get("session_key", ""))
        auth_context_version = str(task_metadata.get("auth_context_version", "0"))
        mutation_surface = "unknown"  # Phase 4 always unknown

        # Build deterministic mutex key from ordered components
        components = f"{origin_key}|{session_key}|{auth_context_version}|{mutation_surface}"
        mutex_key = hashlib.sha256(components.encode("utf-8")).hexdigest()[:16]

        # Shadow mode: never wait or reject
        would_wait = False
        would_reject = False

        return mutex_key, mutation_surface, would_wait, would_reject


class TargetSessionMutexManager:
    """Runtime mutex manager for target/session scoped mutating work."""

    def __init__(self) -> None:
        self._condition = threading.Condition(threading.RLock())
        self._owners: dict[str, str] = {}
        self.audit_events: list[dict[str, Any]] = []

    def acquire(
        self,
        mutex_key: str,
        *,
        owner_id: str = "",
        timeout_seconds: float = 0.0,
    ) -> bool:
        owner = owner_id or threading.current_thread().name
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        started = time.monotonic()

        with self._condition:
            while mutex_key in self._owners and self._owners[mutex_key] != owner:
                remaining = deadline - time.monotonic()
                if timeout_seconds <= 0.0 or remaining <= 0.0:
                    self.audit_events.append({
                        "event": "timeout",
                        "mutex_key": mutex_key,
                        "owner_id": owner,
                        "wait_ms": int((time.monotonic() - started) * 1000),
                    })
                    return False
                self._condition.wait(timeout=remaining)

            self._owners[mutex_key] = owner
            self.audit_events.append({
                "event": "acquired",
                "mutex_key": mutex_key,
                "owner_id": owner,
                "wait_ms": int((time.monotonic() - started) * 1000),
            })
            return True

    def release(self, mutex_key: str, *, owner_id: str = "") -> None:
        owner = owner_id or threading.current_thread().name
        with self._condition:
            current_owner = self._owners.get(mutex_key)
            if current_owner is None:
                return
            if current_owner != owner:
                self.audit_events.append({
                    "event": "release_denied",
                    "mutex_key": mutex_key,
                    "owner_id": owner,
                    "current_owner": current_owner,
                })
                return

            self._owners.pop(mutex_key, None)
            self.audit_events.append({
                "event": "released",
                "mutex_key": mutex_key,
                "owner_id": owner,
            })
            self._condition.notify_all()

    def recover_orphan(self, mutex_key: str, *, owner_id: str | None = None) -> bool:
        """Force-release a stale owner after the caller has proven it is orphaned."""
        with self._condition:
            current_owner = self._owners.get(mutex_key)
            if current_owner is None:
                return False
            if owner_id is not None and current_owner != owner_id:
                return False

            self._owners.pop(mutex_key, None)
            self.audit_events.append({
                "event": "orphan_recovered",
                "mutex_key": mutex_key,
                "owner_id": current_owner,
            })
            self._condition.notify_all()
            return True

    @contextmanager
    def hold(
        self,
        mutex_key: str,
        *,
        owner_id: str = "",
        timeout_seconds: float = 0.0,
    ):
        if not self.acquire(mutex_key, owner_id=owner_id, timeout_seconds=timeout_seconds):
            raise TimeoutError(f"Timed out acquiring mutex {mutex_key}")
        try:
            yield
        finally:
            self.release(mutex_key, owner_id=owner_id)
