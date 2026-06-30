"""T-8.1 (B-1 fix): shigoku-ops runtime-control gate route test for Phase 9.

Verifies:
  - --phase phase9 routes to evaluate_phase9_evidence_bundle()
  - Phase 9-only bundle passes with --phase phase9
  - Generic bundle still works without --phase
  - No-Go metric enforcement works through CLI
"""

import json
import tempfile
from pathlib import Path


def _phase9_record(gate_name: str, status: str = "pass", **overrides) -> dict:
    """Phase 9 record with all extended fields clean."""
    record = {
        "gate_name": gate_name,
        "status": status,
        "date": "2026-06-30",
        "evidence_source": "pytest-t8.1",
        "evidence_summary": f"{gate_name} verified",
        "risk_if_failed": "no_go",
        "decision": "proceed" if status == "pass" else "hold",
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
    record.update(overrides)
    return record


def _generic_record(gate_name: str, status: str = "pass") -> dict:
    """Generic gate record (no Phase 9 fields)."""
    return {
        "gate_name": gate_name,
        "status": status,
        "date": "2026-05-26",
        "evidence_source": "pytest",
        "evidence_summary": "ok",
        "risk_if_failed": "degradation",
        "decision": "proceed" if status == "pass" else "hold",
        "approver": "cto",
    }


def _write_temp_evidence(payload) -> str:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(payload, f)
        return f.name


def _make_args(evidence_file: str, *, phase: str = "generic", critical_gates: str = "compatibility,distributed_control,fault_injection"):
    """Build argparse.Namespace for runtime-control gate."""
    import argparse
    ns = argparse.Namespace()
    ns.evidence_file = evidence_file
    ns.critical_gates = critical_gates
    ns.integrity_manifest = None
    ns.approval_evidence_file = None
    ns.require_code_owner_reviews = False
    ns.phase = phase
    return ns


# ── B-1: Correct routing via --phase phase9 ──

def test_phase9_routing_all_critical_passes():
    """--phase phase9 with all 9 gates clean → exit 0."""
    from scripts.shigoku_ops_cli import _run_runtime_control_gate
    from src.reporting.runtime_control_release_gate import PHASE9_ALLOWED_GATE_NAMES

    records = [_phase9_record(name) for name in sorted(PHASE9_ALLOWED_GATE_NAMES)]
    evidence_path = _write_temp_evidence(records)
    try:
        args = _make_args(evidence_path, phase="phase9")
        exit_code = _run_runtime_control_gate(args)
        assert exit_code == 0, f"All 9 Phase 9 gates clean must pass, got {exit_code}"
    finally:
        Path(evidence_path).unlink(missing_ok=True)


def test_phase9_full_bundle_passes_phase9():
    """All 9 Phase 9 gates + --phase phase9 → exit 0."""
    from scripts.shigoku_ops_cli import _run_runtime_control_gate
    from src.reporting.runtime_control_release_gate import PHASE9_ALLOWED_GATE_NAMES

    records = [_phase9_record(name) for name in sorted(PHASE9_ALLOWED_GATE_NAMES)]
    evidence_path = _write_temp_evidence(records)
    try:
        args = _make_args(evidence_path, phase="phase9")
        exit_code = _run_runtime_control_gate(args)
        assert exit_code == 0, f"Phase 9 full bundle must pass, got {exit_code}"
    finally:
        Path(evidence_path).unlink(missing_ok=True)


# ── B-1 regression: generic bundle still works ──

def test_generic_bundle_still_passes():
    """Generic (non-Phase9) gate bundle with original 6 gates passes."""
    from scripts.shigoku_ops_cli import _run_runtime_control_gate
    from src.reporting.runtime_control_release_gate import ALLOWED_GATE_NAMES

    records = [_generic_record(name) for name in sorted(ALLOWED_GATE_NAMES)]
    evidence_path = _write_temp_evidence(records)
    try:
        args = _make_args(evidence_path, phase="generic")
        exit_code = _run_runtime_control_gate(args)
        assert exit_code == 0
    finally:
        Path(evidence_path).unlink(missing_ok=True)


def test_generic_bundle_rejects_missing_generic_gate():
    """Generic bundle missing a required gate fails."""
    from scripts.shigoku_ops_cli import _run_runtime_control_gate

    records = [_generic_record("compatibility")]
    evidence_path = _write_temp_evidence(records)
    try:
        args = _make_args(evidence_path, phase="generic")
        exit_code = _run_runtime_control_gate(args)
        assert exit_code == 3
    finally:
        Path(evidence_path).unlink(missing_ok=True)


# ── B-2: No-Go metric enforcement through CLI ──

def test_phase9_scope_violation_fails():
    """scope_violation_count > 0 → fail via CLI."""
    from scripts.shigoku_ops_cli import _run_runtime_control_gate

    records = [_phase9_record("scope_budget", scope_violation_count=1)]
    evidence_path = _write_temp_evidence(records)
    try:
        args = _make_args(evidence_path, phase="phase9")
        exit_code = _run_runtime_control_gate(args)
        assert exit_code == 3, "scope_budget with violation_count=1 must fail"
    finally:
        Path(evidence_path).unlink(missing_ok=True)


def test_phase9_secret_leak_fails():
    """secret_leak_count > 0 → fail via CLI."""
    from scripts.shigoku_ops_cli import _run_runtime_control_gate

    records = [_phase9_record("secret_leak", secret_leak_count=1)]
    evidence_path = _write_temp_evidence(records)
    try:
        args = _make_args(evidence_path, phase="phase9")
        exit_code = _run_runtime_control_gate(args)
        assert exit_code == 3, "secret_leak with count=1 must fail"
    finally:
        Path(evidence_path).unlink(missing_ok=True)


def test_phase9_reader_fail_fails():
    """reader_compatibility_status=fail → fail via CLI."""
    from scripts.shigoku_ops_cli import _run_runtime_control_gate

    records = [_phase9_record("reader_compatibility", reader_compatibility_status="fail")]
    evidence_path = _write_temp_evidence(records)
    try:
        args = _make_args(evidence_path, phase="phase9")
        exit_code = _run_runtime_control_gate(args)
        assert exit_code == 3, "reader_compatibility_status=fail must fail"
    finally:
        Path(evidence_path).unlink(missing_ok=True)


def test_phase9_parity_below_100_fails():
    """high_critical_parity < 100 → fail via CLI."""
    from scripts.shigoku_ops_cli import _run_runtime_control_gate

    records = [_phase9_record("finding_parity",
        finding_parity={"serial_gated_match": True, "high_critical_parity": 95.0})]
    evidence_path = _write_temp_evidence(records)
    try:
        args = _make_args(evidence_path, phase="phase9")
        exit_code = _run_runtime_control_gate(args)
        assert exit_code == 3, "finding_parity at 95% must fail"
    finally:
        Path(evidence_path).unlink(missing_ok=True)


# ── Edge cases ──

def test_phase9_evidence_file_missing():
    """Missing evidence file → exit 2."""
    from scripts.shigoku_ops_cli import _run_runtime_control_gate

    args = _make_args("/nonexistent/p9.json", phase="phase9")
    exit_code = _run_runtime_control_gate(args)
    assert exit_code == 2


def test_phase9_waived_critical_fails():
    """Waiver on critical gate → exit 3."""
    from scripts.shigoku_ops_cli import _run_runtime_control_gate

    record = _phase9_record("finding_parity", status="waived")
    record["waiver_reason"] = "temporary"
    records = [record]
    evidence_path = _write_temp_evidence(records)
    try:
        args = _make_args(evidence_path, phase="phase9")
        exit_code = _run_runtime_control_gate(args)
        assert exit_code == 3
    finally:
        Path(evidence_path).unlink(missing_ok=True)


def test_phase9_nogo_metric_with_pass_status_fails():
    """No-Go metric violated but status=pass → still fails."""
    from scripts.shigoku_ops_cli import _run_runtime_control_gate

    # status=pass on a record with scope_violation_count=5
    record = _phase9_record("scope_budget", status="pass", scope_violation_count=5)
    records = [record]
    evidence_path = _write_temp_evidence(records)
    try:
        args = _make_args(evidence_path, phase="phase9")
        exit_code = _run_runtime_control_gate(args)
        assert exit_code == 3, "status=pass with violation must still fail"
    finally:
        Path(evidence_path).unlink(missing_ok=True)
