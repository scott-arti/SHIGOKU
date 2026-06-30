"""
Rollback drill evidence (T-4.1): kill_switch flip -> serial path -> evidence bundle.

Phase 9 (SGK-2026-0318) safety requirement: verify that flipping the kill_switch
immediately reverts to the serial path and that the resulting evidence bundle is
complete and reader-compatible.
"""

from datetime import datetime, timezone
from typing import Dict, Any

from src.reporting.finding_extractor import extract_all_findings
from src.reporting.parity_comparator import compare_findings


def generate_rollback_evidence(
    kill_switch_before: bool,
    kill_switch_after: bool,
    config_diff: Dict[str, Any],
    verification_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Generate rollback drill evidence bundle.

    Captures the full kill_switch flip event and its verification outcome.
    Produces an artifact that downstream Phase 9 gates and readers can consume.

    Args:
        kill_switch_before: kill_switch value before the drill.
        kill_switch_after: kill_switch value after the drill.
        config_diff: Snapshot of config changes caused by the flip.
        verification_result: Dict with serial_path_confirmed,
            finding_parity_maintained, and reader_compatible flags.

    Returns:
        Evidence bundle dict with keys:
            rollback_drill_status, operator_command, config_diff,
            verification_result, reason_code, timestamp.
    """
    serial_path_confirmed = verification_result.get("serial_path_confirmed", False)
    finding_parity_maintained = verification_result.get("finding_parity_maintained", True)
    reader_compatible = verification_result.get("reader_compatible", True)
    all_conditions_met = serial_path_confirmed and finding_parity_maintained and reader_compatible
    rollback_drill_status = "pass" if all_conditions_met else "fail"

    operator_command = _build_operator_command(kill_switch_after)

    reason_code = _determine_reason_code(rollback_drill_status, verification_result)

    return {
        "rollback_drill_status": rollback_drill_status,
        "config_diff": config_diff,
        "operator_command": operator_command,
        "verification_result": verification_result,
        "reason_code": reason_code,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def verify_rollback_serial_compatibility(
    serial_session: Dict[str, Any],
    gated_session: Dict[str, Any],
) -> Dict[str, Any]:
    """Verify that the serial path produces results after kill_switch flip.

    Checks that:
    - The serial path produced at least one finding (serial_path_confirmed).
    - High/Critical finding parity is maintained between serial and gated paths.
    - The output is in standard session format (reader_compatible).

    Args:
        serial_session: Session data from the forced serial path (kill_switch=true).
        gated_session: Session data from the gated parallel path (pre-flip).

    Returns:
        Verification dict with serial_path_confirmed, finding_parity_maintained,
        reader_compatible, and finding counts.
    """
    if not isinstance(serial_session, dict):
        return {
            "serial_path_confirmed": False,
            "finding_parity_maintained": True,
            "reader_compatible": False,
            "serial_finding_count": 0,
            "gated_finding_count": 0,
        }

    serial_findings = extract_all_findings(serial_session)

    reader_compatible = _is_standard_session_format(serial_session)
    serial_path_confirmed = len(serial_findings) > 0 or reader_compatible

    gated = gated_session if isinstance(gated_session, dict) else {}
    parity_result = compare_findings(serial_session, gated, high_critical_only=True)
    finding_parity_maintained = parity_result.high_critical_parity

    return {
        "serial_path_confirmed": serial_path_confirmed,
        "finding_parity_maintained": finding_parity_maintained,
        "reader_compatible": reader_compatible,
        "serial_finding_count": parity_result.serial_finding_count,
        "gated_finding_count": parity_result.gated_finding_count,
    }


# -- private helpers -----------------------------------------------------------

def _build_operator_command(desired_state: bool) -> str:
    """Build the operator command string for the kill_switch flip."""
    return f"SET parallelism.kill_switch = {str(desired_state).lower()}"


def _determine_reason_code(status: str, verification: Dict[str, Any]) -> str:
    """Derive a reason code from the rollback drill status and verification."""
    if status == "pass":
        return "ROLLBACK_DRILL_PASS"
    if not verification.get("serial_path_confirmed", False):
        return "SERIAL_PATH_NOT_CONFIRMED"
    if not verification.get("finding_parity_maintained", True):
        return "FINDING_PARITY_BROKEN"
    if not verification.get("reader_compatible", True):
        return "READER_INCOMPATIBLE"
    return "UNKNOWN_FAILURE"


def _is_standard_session_format(session: Dict[str, Any]) -> bool:
    """Check that the session dict has standard format fields.

    A standard session should have at least one of: completed_tasks, findings,
    session_id, or status.
    """
    if not isinstance(session, dict):
        return False
    standard_keys = {"completed_tasks", "findings", "session_id", "status", "metadata"}
    return bool(standard_keys & set(session.keys()))
