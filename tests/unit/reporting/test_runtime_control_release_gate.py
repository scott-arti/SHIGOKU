from src.reporting.runtime_control_release_gate import evaluate_gate_evidence_bundle
from src.reporting.runtime_control_release_gate import validate_gate_evidence_record
from src.reporting.runtime_control_release_gate import (
    validate_phase9_evidence_record,
    evaluate_phase9_evidence_bundle,
    PHASE9_CRITICAL_GATE_NAMES,
    PHASE9_ALLOWED_GATE_NAMES,
)


def _base_record(gate_name: str) -> dict:
    return {
        "gate_name": gate_name,
        "status": "pass",
        "date": "2026-05-26",
        "evidence_source": "pytest",
        "evidence_summary": "ok",
        "risk_if_failed": "degradation",
        "decision": "proceed",
        "approver": "cto",
    }


#
# Existing generic gate tests
#

def test_fail_status_must_hold():
    record = _base_record("compatibility")
    record["status"] = "fail"
    record["decision"] = "proceed"
    result = validate_gate_evidence_record(record)
    assert result.valid is False
    assert "fail_must_hold" in result.errors


def test_waived_requires_reason():
    record = _base_record("kpi")
    record["status"] = "waived"
    result = validate_gate_evidence_record(record, critical=False)
    assert result.valid is False
    assert "waived_requires_reason" in result.errors


def test_critical_cannot_be_waived():
    record = _base_record("distributed_control")
    record["status"] = "waived"
    record["waiver_reason"] = "temporary"
    result = validate_gate_evidence_record(record, critical=True)
    assert result.valid is False
    assert "critical_cannot_be_waived" in result.errors


def test_bundle_requires_all_gate_records():
    records = [_base_record("compatibility"), _base_record("kpi")]
    result = evaluate_gate_evidence_bundle(records, critical_gate_names=["compatibility", "distributed_control"])
    assert result.valid is False
    assert any(err.startswith("missing_gate_records:") for err in result.errors)


#
# Phase 9 evidence schema TDD (T-1.1, T-1.2)
#

def _phase9_base_record(gate_name: str) -> dict:
    """Phase 9 record with all extended metrics fields."""
    return {
        "gate_name": gate_name,
        "status": "pass",
        "date": "2026-06-30",
        "evidence_source": "pytest",
        "evidence_summary": "ok",
        "risk_if_failed": "degradation",
        "decision": "proceed",
        "approver": "cto",
        "finding_parity": {"serial_gated_match": True, "high_critical_parity": 100.0},
        "scope_violation_count": 0,
        "origin_budget_violation_count": 0,
        "request_budget_violation_count": 0,
        "critical_event_drop_count": 0,
        "reader_compatibility_status": "pass",
        "rollback_drill_status": "pass",
        "secret_leak_count": 0,
        "promotion_stage": "canary",
        "candidate_default_flags": {"parallelism.enabled": False},
    }


# T-1.1: evidence schema validation — extended fields required
def test_phase9_record_missing_extended_fields_fails():
    """T-1.1 RED: Phase 9 record without the extended metrics fields must fail."""
    record = _base_record("finding_parity")
    result = validate_phase9_evidence_record(record)
    assert result.valid is False
    missing_fields = [e for e in result.errors if e.startswith("missing_phase9_field:")]
    assert len(missing_fields) > 0


def test_phase9_record_all_extended_fields_passes():
    """T-1.1 GREEN: Fully populated Phase 9 record must pass."""
    record = _phase9_base_record("finding_parity")
    result = validate_phase9_evidence_record(record)
    assert result.valid is True, result.errors


def test_phase9_invalid_metric_values_fail():
    """T-1.1: Invalid metric values (negative counts, invalid status) must fail."""
    record = _phase9_base_record("scope_budget")
    record["scope_violation_count"] = -1
    result = validate_phase9_evidence_record(record)
    assert result.valid is False
    assert any("scope_violation_count_negative" in e for e in result.errors)

    record2 = _phase9_base_record("reader_compatibility")
    record2["reader_compatibility_status"] = "unknown"
    result2 = validate_phase9_evidence_record(record2)
    assert result2.valid is False
    assert any("invalid_reader_compatibility_status" in e for e in result2.errors)


# T-1.2: critical gate cannot be waived
def test_phase9_finding_parity_cannot_be_waived():
    """T-1.2 RED: finding_parity gate cannot be waived."""
    record = _phase9_base_record("finding_parity")
    record["status"] = "waived"
    record["waiver_reason"] = "temporary reduction"
    result = validate_phase9_evidence_record(record, critical=True)
    assert result.valid is False
    assert "critical_cannot_be_waived" in result.errors


def test_phase9_scope_budget_cannot_be_waived():
    """T-1.2: scope_budget is a Phase 9 critical gate."""
    record = _phase9_base_record("scope_budget")
    record["status"] = "waived"
    record["waiver_reason"] = "scope unknown"
    result = validate_phase9_evidence_record(record, critical=True)
    assert result.valid is False
    assert "critical_cannot_be_waived" in result.errors


def test_phase9_event_drop_cannot_be_waived():
    """T-1.2: event_drop is a Phase 9 critical gate."""
    record = _phase9_base_record("event_drop")
    record["status"] = "waived"
    record["waiver_reason"] = "best effort only"
    result = validate_phase9_evidence_record(record, critical=True)
    assert result.valid is False
    assert "critical_cannot_be_waived" in result.errors


def test_phase9_reader_compatibility_cannot_be_waived():
    """T-1.2: reader_compatibility is a Phase 9 critical gate."""
    record = _phase9_base_record("reader_compatibility")
    record["status"] = "waived"
    record["waiver_reason"] = "backward compatible"
    result = validate_phase9_evidence_record(record, critical=True)
    assert result.valid is False
    assert "critical_cannot_be_waived" in result.errors


def test_phase9_rollback_drill_cannot_be_waived():
    """T-1.2: rollback_drill is a Phase 9 critical gate."""
    record = _phase9_base_record("rollback_drill")
    record["status"] = "waived"
    record["waiver_reason"] = "serial fallback exists"
    result = validate_phase9_evidence_record(record, critical=True)
    assert result.valid is False
    assert "critical_cannot_be_waived" in result.errors


def test_phase9_secret_leak_cannot_be_waived():
    """T-1.2: secret_leak is a Phase 9 critical gate."""
    record = _phase9_base_record("secret_leak")
    record["status"] = "waived"
    record["waiver_reason"] = "no secrets in scope"
    result = validate_phase9_evidence_record(record, critical=True)
    assert result.valid is False
    assert "critical_cannot_be_waived" in result.errors


# T-1.1 extended: bundle validation with Phase 9 gates
def test_phase9_bundle_missing_critical_gate_fails():
    """Bundle missing a critical Phase 9 gate must fail."""
    records = [
        _phase9_base_record("finding_parity"),
        _phase9_base_record("scope_budget"),
    ]
    result = evaluate_phase9_evidence_bundle(records)
    assert result.valid is False
    assert any("missing_gate_records:" in e for e in result.errors)


def test_phase9_full_bundle_passes():
    """All Phase 9 gates present with valid data must pass."""
    records = [
        _phase9_base_record(name)
        for name in sorted(PHASE9_ALLOWED_GATE_NAMES)
    ]
    result = evaluate_phase9_evidence_bundle(records)
    assert result.valid is True, result.errors


def test_phase9_gate_names_are_registered():
    """All Phase 9 gate names must be in the union of ALLOWED_GATE_NAMES."""
    expected = {
        "finding_parity", "scope_budget", "event_drop",
        "reader_compatibility", "rollback_drill", "secret_leak",
        "promotion_matrix", "operator_approval", "budget_enforcement",
    }
    assert set(PHASE9_ALLOWED_GATE_NAMES) == expected


def test_phase9_critical_gates_set():
    """Critical gates must match Phase 9 spec: parity, scope, event, reader, rollback, secret."""
    expected_critical = {
        "finding_parity", "scope_budget", "event_drop",
        "reader_compatibility", "rollback_drill", "secret_leak",
    }
    assert set(PHASE9_CRITICAL_GATE_NAMES) == expected_critical
