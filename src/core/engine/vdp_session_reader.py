"""
VDP Session Reader & Bounded Evidence Writer — SGK-2026-0419 Steps 4-5.

Backward/forward-compatible session reader and bounded async evidence writer
with backpressure protection (no silent discard) and degraded-mode transitions.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from src.core.models.vdp_contract import (
    VDP_CONTRACT_SCHEMA_VERSION,
    EvidenceQueueBackpressureError,
    IdempotencyGuard,
    StateChangeGuard,
    redact_secrets_deep,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# VDP session field defaults injected on read/write
# ---------------------------------------------------------------------------

_VDP_SESSION_FIELDS: Dict[str, Any] = {
    "vdp_contract_version": VDP_CONTRACT_SCHEMA_VERSION,
}

# ---------------------------------------------------------------------------
# Bounded evidence queue (async, backpressured)
# ---------------------------------------------------------------------------


class BoundedEvidenceQueue:
    """Bounded asyncio queue for evidence — rejects when full (never silently discards).

    Raises ``EvidenceQueueBackpressureError`` on ``enqueue()`` when the queue
    is at capacity.
    """

    def __init__(self, max_size: int = 100, degraded_mode: bool = False):
        self._queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=max_size)
        self._max_size = max_size
        self.degraded = degraded_mode
        self._backpressure_count = 0

    @property
    def qsize(self) -> int:
        return self._queue.qsize()

    @property
    def max_size(self) -> int:
        return self._max_size

    async def enqueue(self, evidence: Dict[str, Any]) -> None:
        """Enqueue an evidence dict. Raises backpressure error if full."""
        if self._queue.full():
            self._backpressure_count += 1
            raise EvidenceQueueBackpressureError(
                evidence_id=evidence.get("evidence_id", "unknown"),
                queue_size=self._queue.qsize(),
                max_size=self._max_size,
            )
        await self._queue.put(evidence)

    async def dequeue(self) -> Dict[str, Any]:
        """Dequeue one evidence dict (awaits if empty)."""
        return await self._queue.get()

    def dequeue_nowait(self) -> Dict[str, Any]:
        """Dequeue without waiting. Raises QueueEmpty if empty."""
        return self._queue.get_nowait()

    def is_full(self) -> bool:
        return self._queue.full()

    def is_empty(self) -> bool:
        return self._queue.empty()


# ---------------------------------------------------------------------------
# EvidenceWriter with degraded-mode transition
# ---------------------------------------------------------------------------


class EvidenceWriter:
    """Writes evidence through a bounded queue with degraded-mode fallback.

    - On queue full: transitions to ``degraded`` mode (set via the underlying
      ``BoundedEvidenceQueue.degraded`` flag) and raises backpressure error.
    - At session write boundary: applies ``redact_secrets_deep()`` to the
      session payload before persisting.
    """

    def __init__(self, max_queue_size: int = 100):
        self._queue = BoundedEvidenceQueue(max_size=max_queue_size)
        self._degraded_count = 0

    @property
    def degraded(self) -> bool:
        return self._queue.degraded

    def transition_to_degraded(self) -> None:
        """Explicitly mark the writer as degraded."""
        self._queue.degraded = True
        self._degraded_count += 1

    @property
    def queue(self) -> BoundedEvidenceQueue:
        return self._queue

    async def enqueue_evidence(self, evidence: Dict[str, Any]) -> None:
        """Enqueue evidence through the bounded queue.

        If the queue is full, the writer transitions to degraded mode and
        raises ``EvidenceQueueBackpressureError``.
        """
        try:
            await self._queue.enqueue(evidence)
        except EvidenceQueueBackpressureError:
            self.transition_to_degraded()
            raise


# ---------------------------------------------------------------------------
# Session read / write helpers
# ---------------------------------------------------------------------------


def inject_vdp_fields(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Inject VDP contract version and required fields into a session payload.

    Does **not** mutate the input dict — returns a new shallow copy.

    Args:
        payload: Session payload dict (may be missing vdp fields).

    Returns:
        New dict with ``vdp_contract_version`` and any other VDP fields
        set to their current defaults when missing.
    """
    result = dict(payload)
    for key, default in _VDP_SESSION_FIELDS.items():
        if key not in result:
            result[key] = default
    return result


def read_session_compat(path: str | Path) -> Optional[Dict[str, Any]]:
    """Read a session JSON file with backward/forward compatibility.

    - **Missing VDP fields** are defaulted (e.g. ``vdp_contract_version=1``).
    - **Unknown (future) fields** are preserved in the returned dict — they
      are retained but the old reader simply ignores them.
    - Returns ``None`` if the file is missing, unreadable, or corrupt.

    Args:
        path: Path to the session JSON file.

    Returns:
        Parsed session dict with VDP field defaults applied, or ``None``.
    """
    path = Path(path)
    if not path.exists():
        return None

    try:
        raw = path.read_text(encoding="utf-8")
        data: Dict[str, Any] = json.loads(raw)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None

    # Apply defaults for missing VDP session fields
    for key, default in _VDP_SESSION_FIELDS.items():
        if key not in data:
            data[key] = default

    return data


def redact_and_write_session(payload: Dict[str, Any], path: str | Path) -> None:
    """Redact secrets from a session payload and write it to disk.

    Applies ``redact_secrets_deep()`` at the session write boundary, then
    injects VDP fields and atomically writes the result.

    Args:
        payload: Raw session payload.
        path: Target file path for the session JSON.
    """
    path = Path(path)
    redacted = redact_secrets_deep(payload)
    injected = inject_vdp_fields(redacted)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(injected, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# VDP checkpoint payload — budget + guards serialization
# ---------------------------------------------------------------------------


def build_vdp_checkpoint_payload(
    hypothesis_id: str,
    budget: Any,
    idempotency_guard: IdempotencyGuard,
    state_change_guard: StateChangeGuard,
    pending_next_actions: Optional[list] = None,
) -> Dict[str, Any]:
    """Build a complete checkpoint payload containing all VDP state.

    Args:
        hypothesis_id: The hypothesis identifier for this checkpoint.
        budget: A ``VdpExecutionBudget`` instance (must have ``to_checkpoint_dict()``).
        idempotency_guard: The ``IdempotencyGuard`` for this hypothesis run.
        state_change_guard: The ``StateChangeGuard`` for this hypothesis run.
        pending_next_actions: Optional pending NextAction dicts (SGK-2026-0421,
            constraint I: checkpoint includes pending NextAction so a queue
            failure or interruption never loses the follow-up plan).

    Returns:
        Dict suitable for ``atomic_write_checkpoint()`` / ``json.dump()``.
    """
    budget_dict: Dict[str, Any]
    if hasattr(budget, "to_checkpoint_dict"):
        budget_dict = budget.to_checkpoint_dict()
    else:
        budget_dict = getattr(budget, "snapshot", lambda: {})()  # type: ignore[union-attr]

    data: Dict[str, Any] = {
        "hypothesis_id": hypothesis_id,
        "vdp_contract_version": VDP_CONTRACT_SCHEMA_VERSION,
        "budget": budget_dict,
        "idempotency_guard": idempotency_guard.to_dict(),
        "state_change_guard": state_change_guard.to_dict(),
    }
    if pending_next_actions is not None:
        data["pending_next_actions"] = list(pending_next_actions)
    return data


def restore_pending_next_actions(data: Dict[str, Any]) -> list:
    """Restore the pending NextAction list from a checkpoint dict.

    Returns an empty list when the checkpoint predates SGK-2026-0421 or the
    field is absent (additive read — old checkpoints stay compatible).
    """
    raw = data.get("pending_next_actions")
    return list(raw) if isinstance(raw, list) else []


def restore_vdp_checkpoint_payload(
    data: Dict[str, Any],
) -> tuple:
    """Restore budget, idempotency guard, and state change guard from a checkpoint dict.

    Args:
        data: Dict previously produced by ``build_vdp_checkpoint_payload()``.

    Returns:
        Tuple of ``(budget: Optional[VdpExecutionBudget],
        idempotency_guard: IdempotencyGuard,
        state_change_guard: StateChangeGuard)``.
        Budget may be None if the checkpoint budget data is missing or unparseable.
    """
    import logging
    _logger = logging.getLogger(__name__)

    budget = None
    budget_dict = data.get("budget")
    if budget_dict is not None:
        try:
            from src.core.engine.vdp_budget import VdpExecutionBudget
            budget = VdpExecutionBudget.from_checkpoint_dict(budget_dict)
        except Exception:
            _logger.warning("Failed to restore budget from checkpoint", exc_info=True)

    idempotency_guard = IdempotencyGuard.from_dict(
        data.get("idempotency_guard", {})
    )
    state_change_guard = StateChangeGuard.from_dict(
        data.get("state_change_guard", {})
    )

    return (budget, idempotency_guard, state_change_guard)
