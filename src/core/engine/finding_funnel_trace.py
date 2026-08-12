"""
SGK-2026-0440: finding-pipeline funnel trace (Lane A, measurement only).

The finding funnel records the real attack path (candidate -> validation ->
report) per candidate finding as an ordered F0..F6 stage trace, with the
FIRST failure (0425 convention) and the reason it happened. This module is
the shared contract between Lane A (engine emit hooks) and Lane B (session /
report side):

- ``FindingFunnelRecorder``: additive, bounded-in-memory, deterministic
  recorder. ``record()`` / ``record_task_event()`` never change detection /
  confirmation / threshold / suppression decisions; they only observe.
- ``get_finding_funnel()``: module accessor returning the singleton recorder
  when ``diagnostics.enabled`` is on (same config flag as the SGK-2026-0425
  VDP diagnostics; cfg None or enabled False -> None), else None. Every emit
  hook guards on None, so a disabled run is bit-identical to today.
- ``url_fingerprint()``: one-way opaque fingerprint of a target URL. URLs
  never appear in the section; identical URLs always map to the same
  fingerprint so pre-finding (F0/F1) events can be merged into finding
  entries via ``attach()``.

Section contract (``finding_funnel_v1``, exact keys for Lane B):

    {"schema_version": 1,
     "entries": [{"finding_id": "...", "first_failure_stage": "F3",
                  "first_failure_reason": "phase2_skipped_early_return",
                  "block_reasons": [...], "max_stage_reached": "F3",
                  "stages": {"F0": "reached", ...}, "producer": "..."}],
     "summary": {"by_stage": {"F0": 16, ...}, "by_reason": {...},
                 "suppressed_tasks": 0, "total_candidates": 16}}

Deterministic output: entries sorted by finding_id; no timestamps, no random
ids, no URLs. ``to_section()`` returns None when disabled or empty.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple

# --- Frozen schema / vocab (Lane B contract) -------------------------------

FINDING_FUNNEL_SCHEMA_VERSION = 1

# Session-payload section key (injected by Lane B, never by Lane A engine
# code; defined here so both lanes reference one constant).
FINDING_FUNNEL_SECTION_KEY = "finding_funnel_v1"

# Stage order matters: it defines the first-failure scan order (F0 -> F6).
STAGES: Tuple[str, ...] = (
    "F0", "F1", "F2", "F3", "F4", "F5", "F6",
)

OUTCOMES: Tuple[str, ...] = ("reached", "skipped", "blocked", "failed")

REASON_CODES: Tuple[str, ...] = (
    "url_skipped_dedupe",
    "url_skipped_low_ssrf_score",
    "url_skipped_ssrf_reachability",
    "url_skipped_timeout_circuit",
    "url_timeout",
    "url_error",
    "phase2_skipped_early_return",
    "budget_exhausted",
    "phase2_timeout",
    "finding_validator_rejected",
    "evidence_insufficient",
    "false_positive_refuted",
    "task_suppressed_ownership",
    # SGK-2026-0445 T3: hybrid-verdict terminal states (additive; OUTCOMES
    # vocabulary unchanged — the final state is expressed via reason_code).
    "hybrid_confirmed",
    "hybrid_refuted",
    "hybrid_parked",
    "hybrid_needs_human",
    "reproduction_transport_error",
)

_STAGE_INDEX: Dict[str, int] = {stage: i for i, stage in enumerate(STAGES)}
_FAILURE_OUTCOMES: frozenset = frozenset({"skipped", "blocked", "failed"})


def url_fingerprint(url: Any) -> str:
    """Opaque, deterministic fingerprint of a target URL (sha256 prefix).

    One-way: the URL never appears in funnel output. Identical URLs always
    produce the same fingerprint so F0/F1 pre-finding events (keyed by
    fingerprint) can be merged into finding entries via ``attach()``.
    """
    raw = str(url or "").strip()
    if not raw:
        return ""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _validate_stage_outcome_reason(
    stage: str, outcome: str, reason_code: Optional[str]
) -> None:
    """Strict vocabulary check (like vdp_diagnostic_trace): unknown values
    raise ValueError so programmer errors surface instead of being recorded."""
    if stage not in STAGES:
        raise ValueError(f"unknown funnel stage {stage!r}")
    if outcome not in OUTCOMES:
        raise ValueError(f"unknown funnel outcome {outcome!r}")
    if reason_code is not None and reason_code not in REASON_CODES:
        raise ValueError(f"unknown funnel reason_code {reason_code!r}")


def _apply_stage(
    stages: Dict[str, Dict[str, Any]],
    stage: str,
    outcome: str,
    reason_code: Optional[str],
    block_reasons: Optional[List[str]],
) -> bool:
    """Apply one stage record with the 0425 first-failure idempotency rules.

    - A failure outcome ({skipped, blocked, failed}) is NEVER overwritten
      (later success does not erase an earlier failure).
    - Otherwise the FIRST record of the stage wins (retries are same-stage
      iterations; recording the same stage+outcome twice keeps the first).
    - A failure supersedes an earlier non-failure at the same stage (e.g. an
      auto-reverified F4 reached that is later rejected by the validator).

    Returns True when the record was applied (used for side counters).
    """
    existing = stages.get(stage)
    if existing is not None:
        if existing["outcome"] in _FAILURE_OUTCOMES:
            return False  # a recorded failure is never overwritten
        if outcome not in _FAILURE_OUTCOMES:
            return False  # non-failure: first record wins (idempotent)
        # failure supersedes a recorded non-failure at the same stage
    stages[stage] = {
        "outcome": outcome,
        "reason_code": reason_code,
        "block_reasons": list(block_reasons) if block_reasons else [],
    }
    return True


class FindingFunnelRecorder:
    """Additive, deterministic recorder for the finding-pipeline funnel.

    - ``record`` is finding-keyed (finding_id), ``record_task_event`` is
      keyed by opaque URL fingerprint (pre-finding F0/F1 events).
    - ``attach(finding_id, url_fingerprint)`` merges pending fingerprint
      events into the finding entry and links the fingerprint so later
      fingerprint events also reach already-attached findings.
    - All methods are strict on vocabulary (ValueError) but otherwise never
      raise and never influence the recorded pipeline.
    """

    def __init__(self, enabled: bool = True) -> None:
        self.enabled: bool = bool(enabled)
        self.reset()

    def reset(self) -> None:
        """Clear all recorded state (called by MasterConductor at run start
        when enabled). The ``enabled`` flag is preserved."""
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._pending: Dict[str, Dict[str, Any]] = {}
        self._attached: Dict[str, Set[str]] = {}
        self._suppressed_tasks: int = 0

    # -- finding-keyed records ----------------------------------------------

    def record(
        self,
        finding_id: str,
        stage: str,
        outcome: str,
        reason_code: Optional[str] = None,
        block_reasons: Optional[List[str]] = None,
        producer: Optional[str] = None,
    ) -> None:
        """Record one finding-keyed stage event. No-op when disabled."""
        if not self.enabled:
            return
        _validate_stage_outcome_reason(stage, outcome, reason_code)
        finding_id = str(finding_id or "").strip()
        if not finding_id:
            return
        entry = self._entries.setdefault(
            finding_id, {"stages": {}, "producer": None}
        )
        if entry["producer"] is None and producer:
            entry["producer"] = str(producer)
        _apply_stage(
            entry["stages"], stage, outcome, reason_code, block_reasons
        )

    # -- task-level (pre-finding) records -----------------------------------

    def record_task_event(
        self,
        url_fingerprint: str,
        stage: str,
        outcome: str,
        reason_code: Optional[str] = None,
        block_reasons: Optional[List[str]] = None,
    ) -> None:
        """Record one URL-fingerprint-keyed pre-finding event (F0/F1).

        The event also propagates to every finding entry already attached to
        this fingerprint. ``task_suppressed_ownership`` events additionally
        increment the summary ``suppressed_tasks`` counter (only when the
        record is actually applied, so duplicates never double-count).
        """
        if not self.enabled:
            return
        _validate_stage_outcome_reason(stage, outcome, reason_code)
        fp = str(url_fingerprint or "").strip()
        if not fp:
            return
        pending = self._pending.setdefault(
            fp, {"stages": {}, "producer": None}
        )
        applied = _apply_stage(
            pending["stages"], stage, outcome, reason_code, block_reasons
        )
        if (
            applied
            and stage == "F0"
            and outcome == "blocked"
            and reason_code == "task_suppressed_ownership"
        ):
            self._suppressed_tasks += 1
        for finding_id in tuple(self._attached.get(fp, ())):
            entry = self._entries.get(finding_id)
            if entry is not None:
                _apply_stage(
                    entry["stages"], stage, outcome, reason_code, block_reasons
                )

    # -- merge ---------------------------------------------------------------

    def attach(self, finding_id: str, url_fingerprint: str) -> None:
        """Merge pending fingerprint-keyed stages into the finding entry.

        After the merge the fingerprint stays linked, so later task events
        for the same URL also reach this finding (e.g. retry iterations).
        Finding-keyed records always win over pending ones.
        """
        if not self.enabled:
            return
        finding_id = str(finding_id or "").strip()
        fp = str(url_fingerprint or "").strip()
        if not finding_id:
            return
        entry = self._entries.setdefault(
            finding_id, {"stages": {}, "producer": None}
        )
        if not fp:
            return
        pending = self._pending.get(fp)
        if pending is not None:
            for stage, rec in pending["stages"].items():
                _apply_stage(
                    entry["stages"],
                    stage,
                    rec["outcome"],
                    rec["reason_code"],
                    rec["block_reasons"],
                )
        self._attached.setdefault(fp, set()).add(finding_id)

    # -- serialization -------------------------------------------------------

    def to_section(self) -> Optional[Dict[str, Any]]:
        """The ``finding_funnel_v1`` section dict, or None when disabled or
        empty. Entries are sorted by finding_id; output is deterministic."""
        if not self.enabled:
            return None
        if not self._entries:
            return None

        entries: List[Dict[str, Any]] = []
        for finding_id in sorted(self._entries):
            raw = self._entries[finding_id]
            stages: Dict[str, Dict[str, Any]] = raw["stages"]

            first_failure_stage: Optional[str] = None
            first_failure_reason: Optional[str] = None
            block_reasons: List[str] = []
            for stage in STAGES:
                rec = stages.get(stage)
                if rec is not None and rec["outcome"] in _FAILURE_OUTCOMES:
                    first_failure_stage = stage
                    first_failure_reason = rec["reason_code"]
                    block_reasons = list(rec["block_reasons"])
                    break

            max_stage: Optional[str] = None
            if stages:
                max_stage = max(
                    (stage for stage in stages), key=lambda s: _STAGE_INDEX[s]
                )

            entries.append(
                {
                    "finding_id": finding_id,
                    "first_failure_stage": first_failure_stage,
                    "first_failure_reason": first_failure_reason,
                    "block_reasons": block_reasons,
                    "max_stage_reached": max_stage,
                    "stages": {
                        stage: stages[stage]["outcome"]
                        for stage in STAGES
                        if stage in stages
                    },
                    "producer": raw["producer"],
                }
            )

        by_stage: Dict[str, int] = {stage: 0 for stage in STAGES}
        by_reason: Dict[str, int] = {}
        for finding_id in self._entries:
            stages = self._entries[finding_id]["stages"]
            for stage in stages:
                by_stage[stage] = by_stage.get(stage, 0) + 1
        for entry in entries:
            reason = entry["first_failure_reason"]
            if reason is not None:
                by_reason[reason] = by_reason.get(reason, 0) + 1

        return {
            "schema_version": FINDING_FUNNEL_SCHEMA_VERSION,
            "entries": entries,
            "summary": {
                "by_stage": by_stage,
                "by_reason": by_reason,
                "suppressed_tasks": self._suppressed_tasks,
                "total_candidates": len(self._entries),
            },
        }


# --- Singleton accessor -----------------------------------------------------

_funnel: Optional[FindingFunnelRecorder] = None


def get_finding_funnel() -> Optional[FindingFunnelRecorder]:
    """Return the singleton recorder, or None when diagnostics are disabled.

    Enabled when the SAME config as the SGK-2026-0425 VDP diagnostics is on:
    ``config/shigoku.yaml`` -> ``diagnostics.enabled`` (cfg None or enabled
    False -> None, mirroring ``MasterConductor._ensure_vdp_diagnostics``).
    When None every emit hook no-ops, so disabled runs stay bit-identical.
    """
    global _funnel
    try:
        from src.core.config.settings import get_settings

        settings = get_settings()
        cfg = getattr(settings, "diagnostics", None)
    except Exception:
        cfg = None
    if cfg is None or not getattr(cfg, "enabled", False):
        return None
    if _funnel is None:
        _funnel = FindingFunnelRecorder(enabled=True)
    return _funnel
