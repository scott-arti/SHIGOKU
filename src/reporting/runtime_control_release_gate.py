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
ALLOWED_STATUS = {"pass", "fail", "waived"}
ALLOWED_DECISION = {"proceed", "hold"}


@dataclass
class GateEvidenceValidationResult:
    valid: bool
    errors: List[str]


def validate_gate_evidence_record(record: Dict[str, Any], *, critical: bool = False) -> GateEvidenceValidationResult:
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

    if gate_name and gate_name not in ALLOWED_GATE_NAMES:
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
