"""
Run Ledger models for internal behavior visibility S1.

DecisionTrace / TaskExecutionRecord / AuditEvent = domain records.
RunLedgerEvent = chronological correlation index with source_refs to domain records.
Session payload = reader contract.

Design constraints:
- prompt全文やsecretは保存しない（input_summary + fingerprintのみ）
- LLM usageを取得できないproviderでは `unknown` とし、推定値はraw usageと分離
- event_idはMarkdown出力側が参照できる安定ID: `ledger_evt_<run_id>_<monotonic_seq>`
- 同一run内で単調増加・衝突なしを保証
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schema versions
# ---------------------------------------------------------------------------

RUN_LEDGER_SCHEMA_VERSION = 1
LLM_USAGE_SUMMARY_SCHEMA_VERSION = 1
DEFAULT_MAX_EVENTS = 1000
SPOOL_EVENT_THRESHOLD = 5  # 5+ events trigger JSONL spool flush


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RunLedgerEventType(str, Enum):
    """Run ledger event types."""
    DECISION_MADE = "decision_made"
    SWARM_DISPATCHED = "swarm_dispatched"
    SWARM_COMPLETED = "swarm_completed"
    SWARM_FAILED = "swarm_failed"
    SWARM_MERGED = "swarm_merged"
    SWARM_SKIPPED = "swarm_skipped"
    TOOL_EXECUTED = "tool_executed"
    ERROR_OCCURRED = "error_occurred"
    FINDING_CREATED = "finding_created"
    HITL_REQUESTED = "hitl_requested"
    HITL_RESOLVED = "hitl_resolved"
    LLM_CALLED = "llm_called"
    LLM_RETRY = "llm_retry"
    LLM_FAILED = "llm_failed"
    LLM_CACHE_HIT = "llm_cache_hit"
    PROVIDER_FALLBACK = "provider_fallback"


class UsageStatus(str, Enum):
    """LLM usage measurement status."""
    MEASURED = "measured"
    ESTIMATED = "estimated"
    UNKNOWN = "unknown"


class CacheStatus(str, Enum):
    """LLM cache status."""
    HIT = "hit"
    MISS = "miss"
    BYPASS = "bypass"
    UNKNOWN = "unknown"


class CostEstimateStatus(str, Enum):
    """Cost estimate accuracy."""
    EXACT = "exact"
    ESTIMATED = "estimated"
    UNAVAILABLE = "unavailable"


# ---------------------------------------------------------------------------
# LLMUsageRecord
# ---------------------------------------------------------------------------

@dataclass
class LLMUsageRecord:
    """
    Normalized LLM usage record.

    Design: provider-specific fields absorbed at boundary.
    `estimated` usage is NOT mixed into raw totals; summary keeps it separate.
    """
    model: str
    actor: str
    input_tokens: int = 0
    output_tokens: int = 0
    input_cache_tokens: int = 0
    request_id: Optional[str] = None
    raw_provider: Optional[str] = None
    usage_source: Optional[str] = None  # e.g. "litellm"
    usage_status: UsageStatus = UsageStatus.MEASURED
    cache_status: CacheStatus = CacheStatus.UNKNOWN
    cost_estimate_status: CostEstimateStatus = CostEstimateStatus.UNAVAILABLE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "actor": self.actor,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "input_cache_tokens": self.input_cache_tokens,
            "request_id": self.request_id,
            "raw_provider": self.raw_provider,
            "usage_source": self.usage_source,
            "usage_status": self.usage_status.value,
            "cache_status": self.cache_status.value,
            "cost_estimate_status": self.cost_estimate_status.value,
        }


# ---------------------------------------------------------------------------
# RunLedgerEvent
# ---------------------------------------------------------------------------

@dataclass
class RunLedgerEvent:
    """
    Chronological correlation index event.

    This is NOT a copy of domain records (DecisionTrace / TaskExecutionRecord / AuditEvent).
    It holds source_refs to them and provides a unified timeline index.

    secret/prompt-full-text/raw-response は保存禁止。
    input_summary と input_fingerprint で比較可能性を残す。
    """
    event_id: str
    event_type: RunLedgerEventType
    phase: str
    actor_type: str
    actor_name: str
    timestamp: str = ""
    task_id: Optional[str] = None
    decision_id: Optional[str] = None
    parent_event_id: Optional[str] = None
    input_summary: Optional[str] = None
    input_fingerprint: Optional[str] = None
    action: Optional[str] = None
    result: Optional[str] = None
    error: Optional[str] = None
    source_refs: Optional[Dict[str, Any]] = None
    inference_level: Optional[str] = None  # low/medium/high
    redaction_status: Optional[str] = None  # none/partial/full
    redacted_fields_count: int = 0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "phase": self.phase,
            "actor_type": self.actor_type,
            "actor_name": self.actor_name,
            "task_id": self.task_id,
            "decision_id": self.decision_id,
            "parent_event_id": self.parent_event_id,
            "input_summary": self.input_summary,
            "input_fingerprint": self.input_fingerprint,
            "action": self.action,
            "result": self.result,
            "error": self.error,
            "source_refs": self.source_refs,
            "inference_level": self.inference_level,
            "redaction_status": self.redaction_status,
            "redacted_fields_count": self.redacted_fields_count,
        }


# ---------------------------------------------------------------------------
# LLMUsageSummary
# ---------------------------------------------------------------------------

@dataclass
class LLMUsageSummary:
    """
    Aggregated LLM usage summary for session payload.

    `estimated` usage is NOT included in raw totals. Cache hits with
    `usage_status=UNKNOWN` are counted separately in `unknown_count`.
    """
    schema_version: int = LLM_USAGE_SUMMARY_SCHEMA_VERSION
    by_model: Dict[str, Dict[str, int]] = field(default_factory=dict)
    by_actor: Dict[str, Dict[str, int]] = field(default_factory=dict)
    totals: Dict[str, int] = field(default_factory=dict)
    cache_hit_ratio: float = 0.0
    unknown_count: int = 0
    estimated_count: int = 0

    @classmethod
    def from_records(cls, records: List[LLMUsageRecord]) -> "LLMUsageSummary":
        by_model: Dict[str, Dict[str, int]] = {}
        by_actor: Dict[str, Dict[str, int]] = {}
        raw_totals: Dict[str, int] = {
            "input_tokens": 0,
            "output_tokens": 0,
            "input_cache_tokens": 0,
            "call_count": 0,
        }
        unknown_count = 0
        estimated_count = 0
        cache_hit_count = 0
        total_non_bypass = 0

        for rec in records:
            # --- by_model aggregation ---
            if rec.model not in by_model:
                by_model[rec.model] = {
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "input_cache_tokens": 0,
                    "call_count": 0,
                }
            by_model[rec.model]["call_count"] += 1
            by_model[rec.model]["input_cache_tokens"] += rec.input_cache_tokens

            # --- by_actor aggregation ---
            if rec.actor not in by_actor:
                by_actor[rec.actor] = {
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "input_cache_tokens": 0,
                    "call_count": 0,
                }
            by_actor[rec.actor]["call_count"] += 1
            by_actor[rec.actor]["input_cache_tokens"] += rec.input_cache_tokens

            # --- status counting ---
            if rec.usage_status == UsageStatus.UNKNOWN:
                unknown_count += 1
            if rec.usage_status == UsageStatus.ESTIMATED:
                estimated_count += 1

            # --- cache hit ratio ---
            if rec.cache_status != CacheStatus.BYPASS:
                total_non_bypass += 1
                if rec.cache_status == CacheStatus.HIT:
                    cache_hit_count += 1

            # --- raw totals: only MEASURED usage (not estimated, not unknown) ---
            if rec.usage_status == UsageStatus.MEASURED:
                raw_totals["input_tokens"] += rec.input_tokens
                raw_totals["output_tokens"] += rec.output_tokens
                by_model[rec.model]["input_tokens"] += rec.input_tokens
                by_model[rec.model]["output_tokens"] += rec.output_tokens
                by_actor[rec.actor]["input_tokens"] += rec.input_tokens
                by_actor[rec.actor]["output_tokens"] += rec.output_tokens

            raw_totals["call_count"] += 1

        cache_hit_ratio = (cache_hit_count / total_non_bypass) if total_non_bypass > 0 else 0.0

        return cls(
            schema_version=LLM_USAGE_SUMMARY_SCHEMA_VERSION,
            by_model=by_model,
            by_actor=by_actor,
            totals=raw_totals,
            cache_hit_ratio=cache_hit_ratio,
            unknown_count=unknown_count,
            estimated_count=estimated_count,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "by_model": copy.deepcopy(self.by_model),
            "by_actor": copy.deepcopy(self.by_actor),
            "totals": copy.deepcopy(self.totals),
            "cache_hit_ratio": self.cache_hit_ratio,
            "unknown_count": self.unknown_count,
            "estimated_count": self.estimated_count,
        }


# ---------------------------------------------------------------------------
# RunLedgerRecorder
# ---------------------------------------------------------------------------


def _redact_source_refs_recursive(obj: Any) -> int:
    """
    Recursively redact string values within dicts/lists inside source_refs.
    Returns the total count of redacted fields found.
    Mutates the object in-place.
    """
    from src.core.engine.run_ledger_redactor import redact_content

    count = 0
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, str):
                result = redact_content(value)
                if result.redacted_fields_count > 0:
                    obj[key] = result.summary
                    count += result.redacted_fields_count
            elif isinstance(value, (dict, list)):
                count += _redact_source_refs_recursive(value)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, str):
                result = redact_content(item)
                if result.redacted_fields_count > 0:
                    obj[i] = result.summary
                    count += result.redacted_fields_count
            elif isinstance(item, (dict, list)):
                count += _redact_source_refs_recursive(item)
    return count


@dataclass
class RunLedgerRecorder:
    """
    Run ledger recorder: the authoritative persistence source.

    - EventBus is for realtime notifications; RunLedgerRecorder is the source of truth.
    - EventBus drop does NOT cause ledger event loss (synchronous recording).
    - Session holds max N important events + summary; full details spill to JSONL spool.
    - Call reset() between tests to avoid state leakage.
    """
    run_id: str
    max_events: int = DEFAULT_MAX_EVENTS
    _events: List[RunLedgerEvent] = field(default_factory=list, init=False)
    _event_counter: int = field(default=0, init=False)
    _llm_usage_records: List[LLMUsageRecord] = field(default_factory=list, init=False)
    _spool_path: Optional[str] = field(default=None, init=False)
    _spool_sha256: Optional[str] = field(default=None, init=False)
    _spool_event_count: int = field(default=0, init=False)

    # ---- event ID ----

    def _next_event_id(self) -> str:
        """Generate monotonically increasing, collision-free event ID."""
        self._event_counter += 1
        return f"ledger_evt_{self.run_id}_{self._event_counter:04d}"

    # ---- recording ----

    def record(
        self,
        event_type: RunLedgerEventType,
        phase: str,
        actor_type: str,
        actor_name: str,
        task_id: Optional[str] = None,
        decision_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        input_summary: Optional[str] = None,
        input_fingerprint: Optional[str] = None,
        action: Optional[str] = None,
        result: Optional[str] = None,
        error: Optional[str] = None,
        source_refs: Optional[Dict[str, Any]] = None,
        inference_level: Optional[str] = None,
        redaction_status: Optional[str] = None,
        redacted_fields_count: int = 0,
    ) -> RunLedgerEvent:
        """
        Record a new event synchronously (EventBus-independent).

        All content-bearing fields (input_summary, error) are auto-redacted
        through the common redactor to prevent secret leakage.
        Returns the created event (also appended to internal buffer).
        """
        # --- Redact content-bearing fields at the boundary ---
        from src.core.engine.run_ledger_redactor import redact_for_ledger

        if input_summary:
            redacted_summary, auto_fingerprint, auto_status, auto_count = redact_for_ledger(input_summary)
            input_summary = redacted_summary
            if input_fingerprint is None:
                input_fingerprint = auto_fingerprint
            if redaction_status is None:
                redaction_status = auto_status
            redacted_fields_count = max(redacted_fields_count, auto_count)

        if error:
            # Redact error text; don't fingerprint (errors are specific)
            redacted_err, _, err_status, err_count = redact_for_ledger(error)
            if err_status and err_status != "none":
                error = redacted_err
                if redaction_status is None or redaction_status == "none":
                    redaction_status = err_status
                redacted_fields_count += err_count

        if source_refs:
            sr_count = _redact_source_refs_recursive(source_refs)
            if sr_count > 0:
                redacted_fields_count += sr_count
                if redaction_status is None or redaction_status == "none":
                    redaction_status = "partial"
            elif redaction_status is None:
                redaction_status = "none"

        evt = RunLedgerEvent(
            event_id=self._next_event_id(),
            event_type=event_type,
            phase=phase,
            actor_type=actor_type,
            actor_name=actor_name,
            task_id=task_id,
            decision_id=decision_id,
            parent_event_id=parent_event_id,
            input_summary=input_summary,
            input_fingerprint=input_fingerprint,
            action=action,
            result=result,
            error=error,
            source_refs=source_refs,
            inference_level=inference_level,
            redaction_status=redaction_status,
            redacted_fields_count=redacted_fields_count,
        )
        self._events.append(evt)
        return evt

    # ---- LLM usage ----

    def add_llm_usage(self, record: LLMUsageRecord) -> None:
        """Record an LLM usage measurement."""
        self._llm_usage_records.append(record)

    def get_llm_usage_records(self) -> List[LLMUsageRecord]:
        """Return a copy of all LLM usage records."""
        return list(self._llm_usage_records)

    # ---- query ----

    def get_events(self) -> List[RunLedgerEvent]:
        """Return the most recent events (up to max_events)."""
        if len(self._events) <= self.max_events:
            return list(self._events)
        return list(self._events[-self.max_events:])

    @property
    def event_count(self) -> int:
        """Total events recorded (including evicted)."""
        return self._event_counter

    # ---- spool ----

    @property
    def spool_path(self) -> Optional[str]:
        return self._spool_path

    @property
    def spool_sha256(self) -> Optional[str]:
        return self._spool_sha256

    @property
    def spool_event_count(self) -> int:
        return self._spool_event_count

    def set_spool_metadata(
        self,
        spool_path: str,
        spool_sha256: str,
        spool_event_count: int,
    ) -> None:
        """Set spool metadata after writing JSONL spool."""
        self._spool_path = spool_path
        self._spool_sha256 = spool_sha256
        self._spool_event_count = spool_event_count

    def flush_to_spool(self, spool_dir: str) -> Optional[Path]:
        """
        Flush all in-memory events to a JSONL spool file.

        Only flushes when event_count >= SPOOL_EVENT_THRESHOLD.
        Returns the spool file Path if created, None otherwise.
        """
        if self._event_counter < SPOOL_EVENT_THRESHOLD:
            logger.debug(
                "RunLedger: skip spool flush (events=%d < threshold=%d)",
                self._event_counter, SPOOL_EVENT_THRESHOLD,
            )
            return None

        events_to_spill = list(self._events)
        if not events_to_spill:
            return None

        try:
            spool_path = Path(spool_dir)
            spool_path.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
            spool_file = spool_path / f"run_ledger_spool_{self.run_id}_{ts}.jsonl"

            # Write JSONL with one event per line
            lines: List[str] = []
            for evt in events_to_spill:
                lines.append(json.dumps(evt.to_dict(), ensure_ascii=False))
            content = "\n".join(lines) + "\n"
            content_bytes = content.encode("utf-8")
            spool_file.write_bytes(content_bytes)

            # Compute SHA256
            sha = "sha256:" + hashlib.sha256(content_bytes).hexdigest()

            # Track total spooled count (previous spool + this batch)
            total_spooled = self._spool_event_count + len(events_to_spill)

            self.set_spool_metadata(
                spool_path=str(spool_file),
                spool_sha256=sha,
                spool_event_count=total_spooled,
            )

            # Clear in-memory events (they are now in the spool)
            self._events.clear()

            logger.info(
                "RunLedger: flushed %d events to spool %s (sha256=%s)",
                total_spooled, spool_file.name, sha,
            )
            return spool_file
        except Exception as exc:
            logger.error("RunLedger: spool flush failed: %s", exc)
            # Fail-closed: keep events in memory, spool metadata unchanged
            return None

    # ---- summary ----

    def summary(self) -> Dict[str, Any]:
        """Generate a lightweight summary."""
        by_type: Dict[str, int] = {}
        for evt in self._events:
            by_type[evt.event_type.value] = by_type.get(evt.event_type.value, 0) + 1
        return {
            "schema_version": RUN_LEDGER_SCHEMA_VERSION,
            "total_events": self._event_counter,
            "in_memory_events": len(self._events),
            "by_type": by_type,
        }

    # ---- session payload ----

    def to_session_payload(self) -> Dict[str, Any]:
        """
        Build the session payload contract for run_ledger + llm_usage_summary.

        Only the last max_events events are included (session size control).
        Full event history is available via JSONL spool.
        Returns dict suitable for merging into session JSON.
        """
        llm_summary = LLMUsageSummary.from_records(self._llm_usage_records)
        return {
            "run_ledger_schema_version": RUN_LEDGER_SCHEMA_VERSION,
            "run_ledger": [evt.to_dict() for evt in self.get_events()],
            "llm_usage_summary": llm_summary.to_dict(),
            "spool_path": self._spool_path,
            "spool_sha256": self._spool_sha256,
            "spool_event_count": self._spool_event_count,
        }

    def prepare_for_session(self, spool_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Prepare recorder for session save: flush to spool if threshold exceeded,
        then return the session payload. Call this from async_save_session.

        Args:
            spool_dir: Directory to write JSONL spool files (or None to skip spool).

        Returns:
            Dict suitable for merging into session JSON.
        """
        if spool_dir is not None:
            self.flush_to_spool(spool_dir)
        return self.to_session_payload()

    # ---- lifecycle ----

    def clear(self) -> None:
        """Reset the recorder (use between test runs)."""
        self._events.clear()
        self._event_counter = 0
        self._llm_usage_records.clear()
        self._spool_path = None
        self._spool_sha256 = None
        self._spool_event_count = 0


# ---------------------------------------------------------------------------
# Singleton (with explicit reset for tests)
# ---------------------------------------------------------------------------

_run_ledger_recorder: Optional[RunLedgerRecorder] = None


def get_run_ledger_recorder(run_id: Optional[str] = None) -> RunLedgerRecorder:
    """Get or create the singleton RunLedgerRecorder."""
    global _run_ledger_recorder
    if _run_ledger_recorder is None:
        if run_id is None:
            from uuid import uuid4
            run_id = str(uuid4())[:8]
        _run_ledger_recorder = RunLedgerRecorder(run_id=run_id)
    return _run_ledger_recorder


def reset_run_ledger_recorder() -> None:
    """Reset the singleton (for test isolation)."""
    global _run_ledger_recorder
    _run_ledger_recorder = None
