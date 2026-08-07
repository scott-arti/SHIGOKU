"""
SGK-2026-0425: VDP diagnostic telemetry.

M0 contract (this module): frozen event schema constants, taxonomy
vocabulary (mirror of ``config/diagnostics/taxonomy_v1.json``) and the
fail-closed ``validate_diagnostic_section()`` gate for the additive
``vdp_diagnostics_v1`` session section.

M1 (same file, later steps): bounded DiagnosticEventV1 collector with
deterministic event IDs, redaction-safe serialization, checkpoint/resume
and the ``required=true`` kill-switch guard.

The diagnostic section is an additive, read-only telemetry section. It
never grants "confirmed" rights, never changes the vdp_contract records,
and never carries raw bodies / cookies / authorization / tokens /
credentials / known payloads (URLs and parameters appear only as
normalized fingerprints and source references).
"""
from __future__ import annotations

import dataclasses as _dc
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.core.models.vdp_contract import deterministic_id, redact_secrets_deep

# --- Frozen event schema (M0) ------------------------------------------------

DIAGNOSTIC_SECTION_VERSION = 1
DIAGNOSTIC_TAXONOMY_VERSION = "v2"

# Section keys (stable contract of ``vdp_diagnostics_v1``)
SECTION_KEYS = (
    "schema_version",
    "taxonomy_version",
    "diagnostic_active",
    "run_id",
    "events",
)

EVENT_KEYS = (
    "event_id",
    "run_id",
    "stage_id",
    "outcome",
    "reason_codes",
    "predecessor_ids",
    "successor_ids",
    "opaque_asset_fingerprint",
    "producer_id",
    "agent_id",
    "tool_id",
    "recipe_id",
    "budget_snapshot_hash",
    "source_refs",
    "schema_version",
    "taxonomy_version",
)

# --- Taxonomy v1 vocabulary (mirror of config/diagnostics/taxonomy_v1.json) --

# Primary classification: first failed transition (plan §3.1).
STAGE_IDS: tuple[str, ...] = (
    "S00", "S01", "S02", "S03", "S04", "S05", "S06", "S07",
    "S08", "S09", "S10", "S11", "S12", "U00",
)

OUTCOMES: tuple[str, ...] = ("reached", "skipped", "blocked", "failed")

# Secondary classification: cause families (plan §3.2).
CAUSE_FAMILIES: Dict[str, str] = {
    "C01": "prerequisite/contract",
    "C02": "producer coverage",
    "C03": "normalization/schema",
    "C04": "deterministic reasoning rule",
    "C05": "model reasoning/context",
    "C06": "priority/orchestration",
    "C07": "agent/tool/recipe routing",
    "C08": "attempt strategy",
    "C09": "budget/termination",
    "C10": "infrastructure/dependency",
    "C11": "safety/policy",
    "C12": "evidence/verdict/report",
    "C13": "telemetry insufficient",
}

# Mechanism codes (plan §3.2). C06/C09 and C10/C11 share a code list in the
# frozen vocabulary, exactly as specified in the plan text.
MECHANISM_CODES: Dict[str, List[str]] = {
    "C01": [],
    "C02": [
        "source_not_connected", "asset_not_in_inventory",
        "route_depth_exhausted", "required_state_not_reached",
        "protocol_not_supported", "producer_failed", "producer_budget_cutoff",
    ],
    "C03": [
        "parse_rejected", "field_dropped", "normalization_collision",
        "wrong_dedup", "stale_discarded", "type_contract_mismatch",
    ],
    "C04": [
        "capability_misclassified", "actor_owner_not_inferred",
        "control_template_missing", "success_falsification_mismatch",
    ],
    "C05": ["schema_noncompliance", "semantic_misinterpretation", "unstable_reasoning"],
    "C06": [
        "priority_starvation", "exploration_slot_missing",
        "replan_not_triggered", "premature_stop_with_pending_action",
        "budget_spent_on_duplicates", "iteration_cap_binding",
    ],
    "C07": [
        "specialist_capability_mismatch", "tool_capability_mismatch",
        "recipe_contract_mismatch", "dependency_not_routed",
    ],
    "C08": [
        "wrong_actor_owner_pair", "wrong_input_location",
        "missing_baseline", "missing_inverse", "missing_falsification",
        "request_fingerprint_mismatch",
    ],
    "C09": [
        "priority_starvation", "exploration_slot_missing",
        "replan_not_triggered", "premature_stop_with_pending_action",
        "budget_spent_on_duplicates", "iteration_cap_binding",
    ],
    "C10": [
        "dependency_unavailable", "transport_timeout", "queue_backpressure",
        "scope_block_expected", "scope_block_incorrect",
        "hitl_missing", "rate_limit_stop",
        # SGK-2026-0426 W1 (taxonomy v2): thread-confinement violation of the
        # task_queue (PCR-P1) surfaced as follow-up enqueue failure.
        "queue_mutation_off_main_thread",
    ],
    "C11": [
        "dependency_unavailable", "transport_timeout", "queue_backpressure",
        "scope_block_expected", "scope_block_incorrect",
        "hitl_missing", "rate_limit_stop",
    ],
    "C12": [
        "marker_not_extracted", "independent_evidence_missing",
        "validator_misclassification", "proof_unverifiable",
        "canonical_projection_missing", "consistency_mismatch",
    ],
    "C13": [
        "producer_trace_missing", "stage_event_missing",
        "lineage_broken", "counterfactual_not_constructible",
        # Unknown mechanisms are NOT rounded into existing vocabulary: they
        # are held as C13 until the taxonomy version is bumped (plan §3.2).
        "c13_unclassified_hold",
    ],
}

_ALL_MECHANISM_CODES: set[str] = set()
for _codes in MECHANISM_CODES.values():
    _ALL_MECHANISM_CODES.update(_codes)
ALL_MECHANISM_CODES: tuple[str, ...] = tuple(sorted(_ALL_MECHANISM_CODES))


@dataclass
class DiagnosticSectionValidation:
    """Fail-closed result of the M0 diagnostic section gate."""

    passed: bool
    reason_codes: List[str] = field(default_factory=list)
    detail: str = ""
    errors: List[str] = field(default_factory=list)


def validate_diagnostic_section(section: Any) -> DiagnosticSectionValidation:
    """Fail-closed M0 validation of the ``vdp_diagnostics_v1`` session section.

    Rejects (stable reason codes):
    - non-dict section                        -> diagnostic_section_not_dict
    - unknown / absent schema_version         -> diagnostic_schema_version_unknown
    - unknown taxonomy_version                -> diagnostic_taxonomy_version_unknown
    - diagnostic_active not a strict bool     -> diagnostic_active_not_bool
    - missing / blank run_id                  -> diagnostic_run_id_missing
    - events not a list                       -> diagnostic_events_not_list
    - non-dict event                          -> diagnostic_event_not_dict
    - missing / blank event_id                -> diagnostic_event_id_invalid
    - duplicate event_id                      -> diagnostic_event_id_duplicate
    - unknown stage_id                        -> diagnostic_stage_unknown
    - unknown outcome                         -> diagnostic_outcome_unknown
    - unknown mechanism reason code           -> diagnostic_reason_code_unknown
    - malformed reference lists               -> diagnostic_reference_broken
    - reference to an unknown event_id        -> diagnostic_reference_broken
    - event schema_version unknown            -> diagnostic_event_version_unknown
    - event taxonomy_version unknown          -> diagnostic_taxonomy_version_unknown
    - non-str opaque_asset_fingerprint        -> diagnostic_event_fingerprint_invalid

    A valid section with an EMPTY event list passes: Hypothesis-0 runs must
    still be able to carry S00..S03 events (plan §5.1).
    """
    if not isinstance(section, dict):
        return DiagnosticSectionValidation(
            passed=False,
            reason_codes=["diagnostic_section_not_dict"],
            detail=f"vdp_diagnostics_v1 is not a dict: {type(section).__name__}",
        )

    errors: List[str] = []
    reasons: List[str] = []

    def _fail(code: str, detail: str) -> None:
        reasons.append(code)
        errors.append(detail)

    sv = section.get("schema_version")
    if type(sv) is not int or sv != DIAGNOSTIC_SECTION_VERSION:
        _fail(
            "diagnostic_schema_version_unknown",
            f"schema_version is {sv!r}, must be {DIAGNOSTIC_SECTION_VERSION}",
        )

    tv = section.get("taxonomy_version")
    if tv != DIAGNOSTIC_TAXONOMY_VERSION:
        _fail(
            "diagnostic_taxonomy_version_unknown",
            f"taxonomy_version is {tv!r}, must be {DIAGNOSTIC_TAXONOMY_VERSION}",
        )

    active = section.get("diagnostic_active")
    if type(active) is not bool:
        _fail(
            "diagnostic_active_not_bool",
            f"diagnostic_active is not a strict bool: {type(active).__name__}",
        )

    run_id = section.get("run_id")
    if not isinstance(run_id, str) or not run_id.strip():
        _fail("diagnostic_run_id_missing", "run_id missing or blank")

    events = section.get("events")
    if not isinstance(events, list):
        _fail(
            "diagnostic_events_not_list",
            f"events is not a list: {type(events).__name__}",
        )
        events = []

    ids: Dict[str, int] = {}
    for i, ev in enumerate(events):
        if not isinstance(ev, dict):
            _fail(
                "diagnostic_event_not_dict",
                f"events[{i}] is not a dict: {type(ev).__name__}",
            )
            continue

        eid = ev.get("event_id")
        if not isinstance(eid, str) or not eid.strip():
            _fail("diagnostic_event_id_invalid", f"events[{i}] event_id missing or blank")
        else:
            if eid in ids:
                _fail("diagnostic_event_id_duplicate", f"events[{i}] duplicate event_id {eid!r}")
            ids[eid] = i

        if ev.get("stage_id") not in STAGE_IDS:
            _fail(
                "diagnostic_stage_unknown",
                f"events[{i}] unknown stage_id {ev.get('stage_id')!r}",
            )

        if ev.get("outcome") not in OUTCOMES:
            _fail(
                "diagnostic_outcome_unknown",
                f"events[{i}] unknown outcome {ev.get('outcome')!r}",
            )

        codes = ev.get("reason_codes")
        if not isinstance(codes, list) or not all(
            isinstance(c, str) and c in ALL_MECHANISM_CODES for c in codes
        ):
            _fail(
                "diagnostic_reason_code_unknown",
                f"events[{i}] unknown reason_codes {codes!r}",
            )

        ev_sv = ev.get("schema_version")
        if type(ev_sv) is not int or ev_sv != DIAGNOSTIC_SECTION_VERSION:
            _fail(
                "diagnostic_event_version_unknown",
                f"events[{i}] unknown event schema_version {ev_sv!r}",
            )

        ev_tv = ev.get("taxonomy_version")
        if ev_tv != DIAGNOSTIC_TAXONOMY_VERSION:
            _fail(
                "diagnostic_taxonomy_version_unknown",
                f"events[{i}] unknown event taxonomy_version {ev_tv!r}",
            )

        fp = ev.get("opaque_asset_fingerprint")
        if not isinstance(fp, str):
            _fail(
                "diagnostic_event_fingerprint_invalid",
                f"events[{i}] opaque_asset_fingerprint is not a str: {type(fp).__name__}",
            )

    # Reference integrity: every predecessor/successor must exist in the
    # section's own event set (second pass over dict events only).
    for i, ev in enumerate(events):
        if not isinstance(ev, dict):
            continue
        for ref_key in ("predecessor_ids", "successor_ids"):
            refs = ev.get(ref_key)
            if not isinstance(refs, list) or not all(
                isinstance(r, str) and r for r in refs
            ):
                _fail(
                    "diagnostic_reference_broken",
                    f"events[{i}] {ref_key} malformed",
                )
                continue
            for r in refs:
                if r not in ids:
                    _fail(
                        "diagnostic_reference_broken",
                        f"events[{i}] {ref_key} references unknown event_id {r!r}",
                    )

    if reasons:
        return DiagnosticSectionValidation(
            passed=False,
            reason_codes=sorted(set(reasons)),
            detail="; ".join(errors),
            errors=errors,
        )
    return DiagnosticSectionValidation(
        passed=True,
        reason_codes=[],
        detail="vdp_diagnostics_v1 section valid",
    )


# --- M1: DiagnosticEventV1 (additive event record) ----------------------------
#
# Deterministic, redaction-safe event record. The event_id is derived from the
# canonical ``to_dict()`` payload (minus event_id) via
# ``vdp_contract.deterministic_id``, so identical events always produce the
# same ID and the collector can dedupe without any wall clock / UUID input.

_EVENT_STR_FIELDS = (
    "event_id",
    "run_id",
    "stage_id",
    "outcome",
    "opaque_asset_fingerprint",
    "producer_id",
    "agent_id",
    "tool_id",
    "recipe_id",
    "budget_snapshot_hash",
    "taxonomy_version",
)
_EVENT_LIST_FIELDS = ("reason_codes", "predecessor_ids", "successor_ids", "source_refs")


@dataclass(frozen=True)
class DiagnosticEventV1:
    """Frozen, additive diagnostic event record (``vdp_diagnostics_v1``)."""

    event_id: str
    run_id: str
    stage_id: str
    outcome: str
    reason_codes: Tuple[str, ...] = ()
    predecessor_ids: Tuple[str, ...] = ()
    successor_ids: Tuple[str, ...] = ()
    opaque_asset_fingerprint: str = ""
    producer_id: str = ""
    agent_id: str = ""
    tool_id: str = ""
    recipe_id: str = ""
    budget_snapshot_hash: str = ""
    source_refs: Tuple[str, ...] = ()
    schema_version: int = DIAGNOSTIC_SECTION_VERSION
    taxonomy_version: str = DIAGNOSTIC_TAXONOMY_VERSION

    def to_dict(self) -> Dict[str, Any]:
        """Canonical dict form: tuples become lists, versions included."""
        return {
            "event_id": self.event_id,
            "run_id": self.run_id,
            "stage_id": self.stage_id,
            "outcome": self.outcome,
            "reason_codes": list(self.reason_codes),
            "predecessor_ids": list(self.predecessor_ids),
            "successor_ids": list(self.successor_ids),
            "opaque_asset_fingerprint": self.opaque_asset_fingerprint,
            "producer_id": self.producer_id,
            "agent_id": self.agent_id,
            "tool_id": self.tool_id,
            "recipe_id": self.recipe_id,
            "budget_snapshot_hash": self.budget_snapshot_hash,
            "source_refs": list(self.source_refs),
            "schema_version": self.schema_version,
            "taxonomy_version": self.taxonomy_version,
        }

    @classmethod
    def from_dict(cls, d: Any) -> "DiagnosticEventV1":
        """Strict reconstruction: any wrong type (or unknown key) raises TypeError."""
        if not isinstance(d, dict):
            raise TypeError(
                f"DiagnosticEventV1.from_dict expects a dict, got {type(d).__name__}"
            )
        unknown = set(d) - set(EVENT_KEYS)
        if unknown:
            raise TypeError(
                f"DiagnosticEventV1 unknown fields: {sorted(unknown)}"
            )
        kwargs: Dict[str, Any] = {}
        for name in _EVENT_STR_FIELDS:
            value = d.get(name)
            if not isinstance(value, str):
                raise TypeError(
                    f"DiagnosticEventV1 field {name!r} must be str, got "
                    f"{type(value).__name__}"
                )
            kwargs[name] = value
        for name in _EVENT_LIST_FIELDS:
            value = d.get(name)
            if not isinstance(value, (list, tuple)) or not all(
                isinstance(item, str) for item in value
            ):
                raise TypeError(
                    f"DiagnosticEventV1 field {name!r} must be a list of str, got "
                    f"{type(value).__name__}"
                )
            kwargs[name] = tuple(value)
        schema_version = d.get("schema_version")
        if type(schema_version) is not int:
            raise TypeError(
                "DiagnosticEventV1 field 'schema_version' must be int, got "
                f"{type(schema_version).__name__}"
            )
        kwargs["schema_version"] = schema_version
        return cls(**kwargs)


# --- M1: DiagnosticCollector (bounded, deterministic, fail-closed) ------------

_BACKPRESSURE_REASON_CAP = 100
_DUPLICATE_COUNTS_CAP = 1000
_HOOK_DETAIL_MAX_LEN = 200


class DiagnosticCollector:
    """Bounded collector for ``DiagnosticEventV1`` records.

    - ``emit`` is deterministic: identical inputs produce identical event_ids
      (no wall clock / UUID), so duplicates are skipped and counted instead of
      appended. ``validate_diagnostic_section`` rejects duplicate event_ids,
      which is why the collector MUST dedupe.
    - Backpressure is recorded, never silently dropped: when the pending queue
      (``event_queue_capacity``) or the total artifact (``max_events``) would
      be exceeded, a reason dict is appended to ``backpressure_reasons``
      (capped at 100) and ``emit`` returns None. ``event_count`` in a reason is
      the collector's stored unique event count at rejection time. The
      ``max_events`` artifact limit is checked first
      (``artifact_limit_exceeded``), then the pending queue
      (``queue_full``).
    - ``to_section`` / ``checkpoint`` redact deep secrets at the lowest writer
      and are fail-closed: an invalid section raises RuntimeError instead of
      being emitted. ``required`` (kill-switch guard) is carried as state for
      the later M2 gate; this M1 step only records it.
    """

    def __init__(
        self,
        enabled: bool = False,
        required: bool = False,
        max_events: int = 2000,
        event_queue_capacity: int = 5000,
        run_id: str = "",
        taxonomy_version: str = DIAGNOSTIC_TAXONOMY_VERSION,
    ) -> None:
        self.enabled = enabled
        self.required = required
        self.max_events = max_events
        self.event_queue_capacity = event_queue_capacity
        self.run_id = run_id
        self.taxonomy_version = taxonomy_version
        self.hook_failed: bool = False
        self._events: List[DiagnosticEventV1] = []
        self._event_ids: set[str] = set()
        # Events emitted since the last successful checkpoint (pending queue).
        self._pending_count: int = 0
        self._duplicate_event_counts: Dict[str, int] = {}
        self._backpressure_reasons: List[Dict[str, Any]] = []

    @property
    def backpressure_reasons(self) -> List[Dict[str, Any]]:
        """Copy of the recorded backpressure reasons (capped at 100)."""
        return [dict(r) for r in self._backpressure_reasons]

    @property
    def duplicate_event_counts(self) -> Dict[str, int]:
        """Copy of the duplicate event_id counters (capped at 1000 entries)."""
        return dict(self._duplicate_event_counts)

    def is_enabled(self) -> bool:
        return self.enabled

    def event_count(self) -> int:
        """Number of unique events currently held by the collector."""
        return len(self._events)

    def emit(
        self,
        *,
        stage_id: str,
        outcome: str,
        reason_codes: Tuple[str, ...] = (),
        predecessor_ids: Tuple[str, ...] = (),
        successor_ids: Tuple[str, ...] = (),
        opaque_asset_fingerprint: str = "",
        producer_id: str = "",
        agent_id: str = "",
        tool_id: str = "",
        recipe_id: str = "",
        budget_snapshot_hash: str = "",
        source_refs: Tuple[str, ...] = (),
    ) -> Optional[str]:
        """Record one event; returns its deterministic event_id.

        Returns None when the collector is disabled or the event is rejected by
        backpressure. Raises ValueError for non-vocabulary stage/outcome/reason
        codes. ``event_id`` and ``run_id`` are not accepted: event_id is
        derived, run_id is owned by the collector.
        """
        if not self.enabled:
            return None
        if stage_id not in STAGE_IDS:
            raise ValueError(f"unknown stage_id {stage_id!r}")
        if outcome not in OUTCOMES:
            raise ValueError(f"unknown outcome {outcome!r}")
        bad_codes = [c for c in reason_codes if c not in ALL_MECHANISM_CODES]
        if bad_codes:
            raise ValueError(f"unknown reason code(s) {bad_codes!r}")

        ev = DiagnosticEventV1(
            event_id="",
            run_id=self.run_id,
            stage_id=stage_id,
            outcome=outcome,
            reason_codes=tuple(reason_codes),
            predecessor_ids=tuple(predecessor_ids),
            successor_ids=tuple(successor_ids),
            opaque_asset_fingerprint=opaque_asset_fingerprint,
            producer_id=producer_id,
            agent_id=agent_id,
            tool_id=tool_id,
            recipe_id=recipe_id,
            budget_snapshot_hash=budget_snapshot_hash,
            source_refs=tuple(source_refs),
            schema_version=DIAGNOSTIC_SECTION_VERSION,
            taxonomy_version=self.taxonomy_version,
        )
        payload = ev.to_dict()
        payload.pop("event_id")
        event_id = deterministic_id("dgev", payload)
        ev = _dc.replace(ev, event_id=event_id)

        if event_id in self._event_ids:
            # Duplicate: skip append, count it (dedupe is NOT backpressure).
            if event_id in self._duplicate_event_counts:
                self._duplicate_event_counts[event_id] += 1
            elif len(self._duplicate_event_counts) < _DUPLICATE_COUNTS_CAP:
                self._duplicate_event_counts[event_id] = 1
            return event_id

        if len(self._events) >= self.max_events:
            self._record_backpressure(
                "artifact_limit_exceeded", len(self._events), stage_id
            )
            return None
        if self._pending_count >= self.event_queue_capacity:
            self._record_backpressure("queue_full", len(self._events), stage_id)
            return None

        self._events.append(ev)
        self._event_ids.add(event_id)
        self._pending_count += 1
        return event_id

    def _record_backpressure(self, reason: str, event_count: int, stage_id: str) -> None:
        if len(self._backpressure_reasons) >= _BACKPRESSURE_REASON_CAP:
            return
        self._backpressure_reasons.append(
            {"reason": reason, "event_count": event_count, "stage_id": stage_id}
        )

    def mark_hook_failed(self, reason: str) -> None:
        """Record a hook failure; the detail is sanitized (truncated + redacted)."""
        self.hook_failed = True
        if len(self._backpressure_reasons) >= _BACKPRESSURE_REASON_CAP:
            return
        detail = str(reason)[:_HOOK_DETAIL_MAX_LEN]
        detail = redact_secrets_deep(detail)[:_HOOK_DETAIL_MAX_LEN]
        self._backpressure_reasons.append(
            {"reason": "hook_failed", "detail": detail}
        )

    def to_section(self) -> Optional[Dict[str, Any]]:
        """The ``vdp_diagnostics_v1`` section (redacted), or None when disabled.

        Redaction happens at the lowest writer (this method and ``checkpoint``),
        so nested dict/list secrets can never reach serialized output. The
        redacted section is validated before returning; on failure a
        RuntimeError with the reason codes is raised (fail-closed).
        """
        if not self.enabled:
            return None
        section: Dict[str, Any] = {
            "schema_version": DIAGNOSTIC_SECTION_VERSION,
            "taxonomy_version": self.taxonomy_version,
            "diagnostic_active": True,
            "run_id": self.run_id,
            "events": [ev.to_dict() for ev in self._events],
        }
        if self._duplicate_event_counts:
            section["duplicate_event_counts"] = dict(self._duplicate_event_counts)
        if self._backpressure_reasons:
            section["backpressure_reasons"] = [
                dict(r) for r in self._backpressure_reasons
            ]
        redacted = redact_secrets_deep(section)
        validation = validate_diagnostic_section(redacted)
        if not validation.passed:
            raise RuntimeError(
                "refusing to emit invalid vdp_diagnostics_v1 section; reason_codes="
                + ",".join(validation.reason_codes)
            )
        return redacted

    def checkpoint(self, path: str) -> None:
        """Atomically persist the section as canonical JSON (redacted first).

        The temp file lives in the same directory and is replaced via
        ``os.replace``; PermissionError/OSError propagate (never swallowed) and
        the temp file is cleaned up on failure.
        """
        section = self.to_section()
        if section is None:
            section = {
                "schema_version": DIAGNOSTIC_SECTION_VERSION,
                "taxonomy_version": self.taxonomy_version,
                "diagnostic_active": False,
                "run_id": self.run_id,
                "events": [],
            }
        else:
            section = dict(section)
        # Checkpoint always carries the optional blocks (empty when absent).
        section["duplicate_event_counts"] = section.get(
            "duplicate_event_counts", {}
        )
        section["backpressure_reasons"] = section.get("backpressure_reasons", [])

        target = Path(path)
        tmp_path: Optional[Path] = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=str(target.parent),
                prefix=f"{target.name}.",
                suffix=".tmp",
                delete=False,
            ) as fh:
                tmp_path = Path(fh.name)
                json.dump(
                    section, fh, sort_keys=True, ensure_ascii=False, indent=2
                )
            os.replace(str(tmp_path), str(target))
            tmp_path = None
            # Pending queue is drained by a successful checkpoint.
            self._pending_count = 0
        finally:
            # Best-effort cleanup of the temp file when the replace failed;
            # never mask the original exception.
            if tmp_path is not None:
                try:
                    tmp_path.unlink(missing_ok=True)
                except OSError:
                    pass

    def resume(self, path: str) -> bool:
        """Restore collector state from a checkpoint file.

        Returns False when the file is missing. Garbage / non-dict / invalid
        checkpoints raise RuntimeError (fail-closed; nothing is partially
        resumed). Restored events are re-emitted-safe: identical events are
        skipped by dedupe, so state is never doubled.
        """
        p = Path(path)
        if not p.exists():
            return False
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError(
                f"cannot resume diagnostic checkpoint {path}: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise RuntimeError(
                f"cannot resume diagnostic checkpoint {path}: not a dict"
            )
        validation = validate_diagnostic_section(data)
        if not validation.passed:
            raise RuntimeError(
                "refusing to resume invalid diagnostic checkpoint; reason_codes="
                + ",".join(validation.reason_codes)
            )
        events = [DiagnosticEventV1.from_dict(ev) for ev in data["events"]]
        self._events = events
        self._event_ids = {ev.event_id for ev in events}
        self._pending_count = 0
        self.run_id = data["run_id"]
        self.taxonomy_version = data["taxonomy_version"]
        self._duplicate_event_counts = dict(data.get("duplicate_event_counts") or {})
        self._backpressure_reasons = [
            dict(r) for r in (data.get("backpressure_reasons") or [])
        ]
        return True

    @classmethod
    def from_section(cls, section: Dict[str, Any]) -> "DiagnosticCollector":
        """Reconstruct a collector from an existing ``vdp_diagnostics_v1`` section.

        The section is validated first; invalid input raises RuntimeError
        (fail-closed). The returned collector is enabled and continues emitting
        with the section's run_id.
        """
        validation = validate_diagnostic_section(section)
        if not validation.passed:
            raise RuntimeError(
                "refusing to construct collector from invalid section; reason_codes="
                + ",".join(validation.reason_codes)
            )
        collector = cls(
            enabled=True,
            run_id=section["run_id"],
            taxonomy_version=section["taxonomy_version"],
        )
        collector._events = [
            DiagnosticEventV1.from_dict(ev) for ev in section["events"]
        ]
        collector._event_ids = {ev.event_id for ev in collector._events}
        collector._pending_count = 0
        collector._duplicate_event_counts = dict(
            section.get("duplicate_event_counts") or {}
        )
        collector._backpressure_reasons = [
            dict(r) for r in (section.get("backpressure_reasons") or [])
        ]
        return collector
