from src.reporting.runtime_control_release_gate import evaluate_gate_evidence_bundle
from src.reporting.runtime_control_release_gate import validate_gate_evidence_record


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
