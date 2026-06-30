from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


ALLOWED_GATE_NAMES = {
    "compatibility",
    "distributed_control",
    "fault_injection",
    "shadow_mode",
    "kpi",
    "rollback_drill",
}

# Phase 9 specific gate name sets
PHASE9_ALLOWED_GATE_NAMES = sorted({
    "finding_parity",
    "scope_budget",
    "event_drop",
    "reader_compatibility",
    "rollback_drill",
    "secret_leak",
    "promotion_matrix",
    "operator_approval",
    "budget_enforcement",
})

PHASE9_CRITICAL_GATE_NAMES = [
    "finding_parity",
    "scope_budget",
    "event_drop",
    "reader_compatibility",
    "rollback_drill",
    "secret_leak",
]

PHASE9_EXTENDED_FIELDS = {
    "finding_parity",
    "scope_violation_count",
    "origin_budget_violation_count",
    "request_budget_violation_count",
    "critical_event_drop_count",
    "reader_compatibility_status",
    "rollback_drill_status",
    "secret_leak_count",
    "promotion_stage",
    "candidate_default_flags",
}

PHASE9_ALLOWED_READER_STATUS = {"pass", "fail"}
PHASE9_ALLOWED_ROLLBACK_STATUS = {"pass", "fail"}
PHASE9_ALLOWED_PROMOTION_STAGES = {"shadow", "canary", "limited_default", "broader_default"}
ALLOWED_STATUS = {"pass", "fail", "waived"}
ALLOWED_DECISION = {"proceed", "hold"}


@dataclass
class GateEvidenceValidationResult:
    valid: bool
    errors: List[str]


def validate_gate_evidence_record(
    record: Dict[str, Any], *, critical: bool = False,
    allowed_gate_names: Any = None,
) -> GateEvidenceValidationResult:
    errors: List[str] = []
    required = {
        "gate_name",
        "status",
        "date",
        "evidence_source",
        "evidence_summary",
        "risk_if_failed",
        "decision",
        "approver",
    }
    missing = sorted(k for k in required if k not in record or record.get(k) in (None, ""))
    if missing:
        errors.append(f"missing_required:{','.join(missing)}")

    gate_name = str(record.get("gate_name", "") or "").strip().lower()
    status = str(record.get("status", "") or "").strip().lower()
    decision = str(record.get("decision", "") or "").strip().lower()
    waiver_reason = str(record.get("waiver_reason", "") or "").strip()

    _allowed = frozenset(allowed_gate_names) if allowed_gate_names is not None else ALLOWED_GATE_NAMES
    if gate_name and gate_name not in _allowed:
        errors.append("invalid_gate_name")
    if status and status not in ALLOWED_STATUS:
        errors.append("invalid_status")
    if decision and decision not in ALLOWED_DECISION:
        errors.append("invalid_decision")

    if status == "fail" and decision != "hold":
        errors.append("fail_must_hold")
    if status == "waived" and not waiver_reason:
        errors.append("waived_requires_reason")
    if critical and status == "waived":
        errors.append("critical_cannot_be_waived")

    return GateEvidenceValidationResult(valid=not errors, errors=errors)


def evaluate_gate_evidence_bundle(records: List[Dict[str, Any]], *, critical_gate_names: List[str]) -> GateEvidenceValidationResult:
    errors: List[str] = []
    seen = set()
    for record in records:
        gate_name = str(record.get("gate_name", "") or "").strip().lower()
        seen.add(gate_name)
        is_critical = gate_name in {name.strip().lower() for name in critical_gate_names}
        verdict = validate_gate_evidence_record(record, critical=is_critical)
        if not verdict.valid:
            errors.extend([f"{gate_name}:{err}" for err in verdict.errors])

    missing_gates = sorted(ALLOWED_GATE_NAMES - seen)
    if missing_gates:
        errors.append(f"missing_gate_records:{','.join(missing_gates)}")

    return GateEvidenceValidationResult(valid=not errors, errors=errors)


def validate_phase9_evidence_record(
    record: Dict[str, Any], *, critical: bool = False
) -> GateEvidenceValidationResult:
    """Validates a Phase 9 release gate evidence record.

    Extends the base gate validation with Phase 9-specific metric fields:
    finding_parity, scope/origin/request budget violation counts,
    critical event drop count, reader compatibility status,
    rollback drill status, secret leak count, promotion stage,
    and candidate default flags.

    Args:
        record: Phase 9 evidence record dict with base gate fields + extended metrics.
        critical: If True, waived status is rejected for this gate.

    Returns:
        GateEvidenceValidationResult with accumulated errors (empty errors = valid).
    """
    # Base generic validation first (with Phase 9 + generic gate names allowed)
    _phase9_allowed_names = ALLOWED_GATE_NAMES | frozenset(PHASE9_ALLOWED_GATE_NAMES)
    base_result = validate_gate_evidence_record(
        record, critical=critical, allowed_gate_names=_phase9_allowed_names
    )
    errors: List[str] = list(base_result.errors)

    # Phase 9 extended field presence
    missing_extended = sorted(
        k for k in PHASE9_EXTENDED_FIELDS
        if k not in record or record.get(k) in (None, "")
    )
    if missing_extended:
        errors.append(f"missing_phase9_field:{','.join(missing_extended)}")

    # Validate extended field values (only if present)
    if "finding_parity" in record and isinstance(record["finding_parity"], dict):
        fp = record["finding_parity"]
        if not isinstance(fp.get("serial_gated_match"), bool):
            errors.append("finding_parity.invalid_serial_gated_match")
        parity = fp.get("high_critical_parity", -1.0)
        if not isinstance(parity, (int, float)) or parity < 0.0 or parity > 100.0:
            errors.append("finding_parity.invalid_high_critical_parity")

    for field in (
        "scope_violation_count",
        "origin_budget_violation_count",
        "request_budget_violation_count",
        "critical_event_drop_count",
        "secret_leak_count",
    ):
        val = record.get(field)
        if val is not None and (not isinstance(val, int) or val < 0):
            errors.append(f"{field}_negative")

    reader_status = str(record.get("reader_compatibility_status", "") or "").strip().lower()
    if reader_status and reader_status not in PHASE9_ALLOWED_READER_STATUS:
        errors.append("invalid_reader_compatibility_status")

    rollback_status = str(record.get("rollback_drill_status", "") or "").strip().lower()
    if rollback_status and rollback_status not in PHASE9_ALLOWED_ROLLBACK_STATUS:
        errors.append("invalid_rollback_drill_status")

    promotion_stage = str(record.get("promotion_stage", "") or "").strip().lower()
    if promotion_stage and promotion_stage not in PHASE9_ALLOWED_PROMOTION_STAGES:
        errors.append("invalid_promotion_stage")

    if "candidate_default_flags" in record:
        cdf = record["candidate_default_flags"]
        if not isinstance(cdf, dict):
            errors.append("candidate_default_flags_not_dict")

    # Phase 9 semantic enforcement: No-Go metric values must not pass
    _enforce_phase9_no_go_metrics(record, errors, critical)

    return GateEvidenceValidationResult(valid=not errors, errors=errors)


def _enforce_phase9_no_go_metrics(
    record: Dict[str, Any], errors: List[str], critical: bool
) -> None:
    """Enforce Phase 9 No-Go conditions at the schema validation level.

    Any violation count > 0, or fail-status for reader/rollback/parity
    triggers a validation error. Critical gates cannot pass with any
    non-zero violation.
    """
    # Track how many metric-level errors we add
    metric_error_count_before = len(errors)

    # Count-type metrics: any > 0 is No-Go
    count_metrics = {
        "scope_violation_count": "scope_violation_count_nonzero",
        "origin_budget_violation_count": "origin_budget_violation_count_nonzero",
        "request_budget_violation_count": "request_budget_violation_count_nonzero",
        "critical_event_drop_count": "critical_event_drop_count_nonzero",
        "secret_leak_count": "secret_leak_count_nonzero",
    }
    for field, error_code in count_metrics.items():
        val = record.get(field)
        if isinstance(val, int) and val > 0:
            errors.append(error_code)

    # Status-type metrics: "fail" is No-Go
    reader_status = str(record.get("reader_compatibility_status", "") or "").strip().lower()
    if reader_status == "fail":
        errors.append("reader_compatibility_status_fail")

    rollback_status = str(record.get("rollback_drill_status", "") or "").strip().lower()
    if rollback_status == "fail":
        errors.append("rollback_drill_status_fail")

    # finding_parity: must have serial_gated_match=True and high_critical_parity==100.0
    if "finding_parity" in record and isinstance(record["finding_parity"], dict):
        fp = record["finding_parity"]
        if fp.get("serial_gated_match") is not True:
            errors.append("finding_parity.serial_gated_match_false")
        parity = fp.get("high_critical_parity")
        if isinstance(parity, (int, float)) and parity < 100.0:
            errors.append("finding_parity.high_critical_parity_below_100")

    # Force fail/hold when No-Go metrics are violated but record claims pass
    metric_errors_added = len(errors) - metric_error_count_before
    if metric_errors_added > 0:
        record_status = str(record.get("status", "") or "").strip().lower()
        if record_status == "pass":
            errors.append("no_go_metrics_require_fail_status")


def evaluate_phase9_evidence_bundle(
    records: List[Dict[str, Any]],
) -> GateEvidenceValidationResult:
    """Evaluates a Phase 9 release gate evidence bundle.

    Validates each record with Phase 9 extended field rules, marks
    critical gates as non-waivable, and ensures all Phase 9 gate
    names are present.

    Args:
        records: List of Phase 9 evidence record dicts.

    Returns:
        GateEvidenceValidationResult — valid=True only when all gates
        are present and all pass/waived-appropriately.
    """
    errors: List[str] = []
    seen = set()

    critical_set = {name.strip().lower() for name in PHASE9_CRITICAL_GATE_NAMES}

    for record in records:
        gate_name = str(record.get("gate_name", "") or "").strip().lower()
        seen.add(gate_name)
        is_critical = gate_name in critical_set

        verdict = validate_phase9_evidence_record(record, critical=is_critical)
        if not verdict.valid:
            errors.extend([f"{gate_name}:{err}" for err in verdict.errors])

    missing_gates = sorted(set(PHASE9_ALLOWED_GATE_NAMES) - seen)
    if missing_gates:
        errors.append(f"missing_gate_records:{','.join(missing_gates)}")

    return GateEvidenceValidationResult(valid=not errors, errors=errors)
