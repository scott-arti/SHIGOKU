"""T-4.1: Rollback drill evidence tests.

Tests for src/reporting/rollback_drill.py:
  - generate_rollback_evidence
  - verify_rollback_serial_compatibility
"""

from src.reporting.rollback_drill import (
    generate_rollback_evidence,
    verify_rollback_serial_compatibility,
)


# -- helpers -------------------------------------------------------------------

def _make_session(findings_count: int = 1, severity: str = "High") -> dict:
    """Build a minimal session dict with the standard completed_tasks structure."""
    findings = [
        {"id": f"finding-{i}", "severity": severity, "target": "example.com"}
        for i in range(findings_count)
    ]
    return {
        "completed_tasks": [
            {
                "id": "task-1",
                "result": {"findings": findings},
            }
        ],
        "session_id": "test-session",
        "status": "completed",
    }


# -- T-4.1 test 1: kill_switch_flip_generates_evidence -------------------------

def test_kill_switch_flip_generates_evidence():
    """kill_switch False -> True flip must produce a pass evidence bundle."""
    config_diff = {
        "before": {"parallelism.kill_switch": False},
        "after": {"parallelism.kill_switch": True},
    }
    verification = {
        "serial_path_confirmed": True,
        "finding_parity_maintained": True,
        "reader_compatible": True,
    }
    evidence = generate_rollback_evidence(
        kill_switch_before=False,
        kill_switch_after=True,
        config_diff=config_diff,
        verification_result=verification,
    )
    assert evidence["rollback_drill_status"] == "pass"
    assert evidence["reason_code"] == "ROLLBACK_DRILL_PASS"
    assert evidence["operator_command"] == "SET parallelism.kill_switch = true"
    assert evidence["config_diff"] == config_diff
    assert evidence["verification_result"] == verification
    assert "timestamp" in evidence


# -- T-4.1 test 2: rollback_drill_fail_when_serial_not_confirmed ---------------

def test_rollback_drill_fail_when_serial_not_confirmed():
    """When serial_path_confirmed is False (all three not met), status must be fail."""
    verification = {
        "serial_path_confirmed": False,
        "finding_parity_maintained": True,
        "reader_compatible": True,
    }
    evidence = generate_rollback_evidence(
        kill_switch_before=False,
        kill_switch_after=True,
        config_diff={},
        verification_result=verification,
    )
    assert evidence["rollback_drill_status"] == "fail"
    assert evidence["reason_code"] == "SERIAL_PATH_NOT_CONFIRMED"
    # Verify all three conditions are present and evaluated
    assert evidence["verification_result"]["serial_path_confirmed"] is False
    assert evidence["verification_result"]["finding_parity_maintained"] is True
    assert evidence["verification_result"]["reader_compatible"] is True


def test_parity_false_fails_rollback():
    """When finding_parity_maintained is False, status must be fail."""
    verification = {
        "serial_path_confirmed": True,
        "finding_parity_maintained": False,
        "reader_compatible": True,
    }
    evidence = generate_rollback_evidence(
        kill_switch_before=False,
        kill_switch_after=True,
        config_diff={},
        verification_result=verification,
    )
    assert evidence["rollback_drill_status"] == "fail"
    assert evidence["reason_code"] == "FINDING_PARITY_BROKEN"


def test_reader_false_fails_rollback():
    """When reader_compatible is False, status must be fail."""
    verification = {
        "serial_path_confirmed": True,
        "finding_parity_maintained": True,
        "reader_compatible": False,
    }
    evidence = generate_rollback_evidence(
        kill_switch_before=False,
        kill_switch_after=True,
        config_diff={},
        verification_result=verification,
    )
    assert evidence["rollback_drill_status"] == "fail"
    assert evidence["reason_code"] == "READER_INCOMPATIBLE"


# -- T-4.1 test 3: config_diff_captured ----------------------------------------

def test_config_diff_captured():
    """config_diff must be captured verbatim in the evidence bundle."""
    config_diff = {
        "before": {"parallelism.kill_switch": True},
        "after": {"parallelism.kill_switch": False},
    }
    verification = {
        "serial_path_confirmed": True,
        "finding_parity_maintained": True,
        "reader_compatible": True,
    }
    evidence = generate_rollback_evidence(
        kill_switch_before=True,
        kill_switch_after=False,
        config_diff=config_diff,
        verification_result=verification,
    )
    assert evidence["config_diff"] == config_diff
    assert evidence["config_diff"]["before"]["parallelism.kill_switch"] is True
    assert evidence["config_diff"]["after"]["parallelism.kill_switch"] is False


# -- T-4.1 test 4: operator_command_recorded -----------------------------------

def test_operator_command_recorded():
    """operator_command must reflect the desired kill_switch state."""
    # True case
    evidence_true = generate_rollback_evidence(
        kill_switch_before=False,
        kill_switch_after=True,
        config_diff={},
        verification_result={"serial_path_confirmed": True},
    )
    assert "SET parallelism.kill_switch = true" == evidence_true["operator_command"]

    # False case
    evidence_false = generate_rollback_evidence(
        kill_switch_before=True,
        kill_switch_after=False,
        config_diff={},
        verification_result={"serial_path_confirmed": True},
    )
    assert "SET parallelism.kill_switch = false" == evidence_false["operator_command"]


# -- T-4.1 test 5: verification_result_included --------------------------------

def test_verification_result_included():
    """verification_result must be passed through to the evidence bundle."""
    verification = {
        "serial_path_confirmed": True,
        "finding_parity_maintained": False,
        "reader_compatible": True,
        "serial_finding_count": 3,
        "gated_finding_count": 5,
    }
    evidence = generate_rollback_evidence(
        kill_switch_before=False,
        kill_switch_after=True,
        config_diff={},
        verification_result=verification,
    )
    assert evidence["verification_result"] == verification
    assert evidence["verification_result"]["serial_finding_count"] == 3


# -- verify_rollback_serial_compatibility tests --------------------------------

class TestVerifyRollbackSerialCompatibility:
    def test_both_paths_produce_findings(self):
        """Both serial and gated paths have findings -> confirmed + parity."""
        serial = _make_session(findings_count=2, severity="High")
        gated = _make_session(findings_count=2, severity="High")
        result = verify_rollback_serial_compatibility(serial, gated)
        assert result["serial_path_confirmed"] is True
        assert result["finding_parity_maintained"] is True
        assert result["reader_compatible"] is True
        assert result["serial_finding_count"] == 2
        assert result["gated_finding_count"] == 2

    def test_serial_path_empty(self):
        """Zero-finding well-formed session -> serial_path_confirmed is True (zero findings is valid)."""
        serial = _make_session(findings_count=0, severity="High")
        gated = _make_session(findings_count=3, severity="High")
        result = verify_rollback_serial_compatibility(serial, gated)
        assert result["serial_path_confirmed"] is True  # well-formed session, zero findings is valid
        assert result["reader_compatible"] is True

    def test_parity_broken_when_mismatched(self):
        """Mismatched findings between serial and gated -> finding_parity_maintained False."""
        serial = _make_session(findings_count=1, severity="High")
        gated = _make_session(findings_count=1, severity="High")
        # Mutate gated to have a different finding id
        gated["completed_tasks"][0]["result"]["findings"][0]["id"] = "different-id"
        result = verify_rollback_serial_compatibility(serial, gated)
        assert result["finding_parity_maintained"] is False

    def test_medium_severity_ignored_in_parity(self):
        """Medium findings should not affect High/Critical parity."""
        serial = {
            "completed_tasks": [
                {
                    "id": "task-1",
                    "result": {"findings": [
                        {"id": "med-1", "severity": "Medium", "target": "x.com"}
                    ]},
                }
            ],
        }
        gated = {
            "completed_tasks": [
                {
                    "id": "task-1",
                    "result": {"findings": [
                        {"id": "med-2", "severity": "Medium", "target": "x.com"}
                    ]},
                }
            ],
        }
        result = verify_rollback_serial_compatibility(serial, gated)
        # Both have zero HC findings -> parity maintained
        assert result["finding_parity_maintained"] is True

    def test_empty_sessions(self):
        """Empty sessions should return compatible with no parity issues."""
        result = verify_rollback_serial_compatibility({}, {})
        assert result["serial_path_confirmed"] is False
        assert result["finding_parity_maintained"] is True  # both empty

    def test_reader_compatible_with_standard_session(self):
        """Standard session format is reader_compatible True."""
        serial = _make_session(findings_count=1, severity="Critical")
        gated = _make_session(findings_count=1, severity="Critical")
        result = verify_rollback_serial_compatibility(serial, gated)
        assert result["reader_compatible"] is True

    def test_non_dict_session_is_not_reader_compatible(self):
        """A non-dict session is not reader_compatible."""
        result = verify_rollback_serial_compatibility("not-a-dict", {})  # type: ignore[arg-type]
        assert result["reader_compatible"] is False
        assert result["serial_path_confirmed"] is False

    def test_zero_finding_serial_session_is_valid(self):
        """A session with 0 findings but valid structure is reader-compatible and serial_path_confirmed."""
        serial = _make_session(findings_count=0, severity="High")
        gated = _make_session(findings_count=3, severity="High")
        result = verify_rollback_serial_compatibility(serial, gated)
        assert result["reader_compatible"] is True
        assert result["serial_path_confirmed"] is True
        assert result["serial_finding_count"] == 0
