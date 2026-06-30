from __future__ import annotations

from dataclasses import dataclass
import threading


@dataclass(frozen=True)
class SuppressDecision:
    allowed: bool
    reason_code: str = ""
    owner_task_id: str = ""


class OriginSuppressor:
    """Aggressive lane origin suppressor for Phase 7 (SGK-2026-0316).

    When an aggressive_exclusive lane task is executing on an origin,
    other lane tasks targeting the same origin are suppressed.
    Releasing the aggressive owner lift the suppression.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._aggressive_by_origin: dict[str, str] = {}

    def enter(self, origin_key: str, *, lane: str, owner_task_id: str) -> None:
        if lane != "aggressive_exclusive" or not origin_key:
            return
        with self._lock:
            self._aggressive_by_origin[origin_key] = owner_task_id

    def release(self, origin_key: str, *, owner_task_id: str) -> None:
        with self._lock:
            if self._aggressive_by_origin.get(origin_key) == owner_task_id:
                self._aggressive_by_origin.pop(origin_key, None)

    def check(self, origin_key: str, *, lane: str, task_id: str) -> SuppressDecision:
        if not origin_key:
            return SuppressDecision(True)
        with self._lock:
            owner = self._aggressive_by_origin.get(origin_key, "")
        if owner and owner != task_id and lane != "aggressive_exclusive":
            return SuppressDecision(False, "origin_suppressed_by_aggressive", owner)
        return SuppressDecision(True)
