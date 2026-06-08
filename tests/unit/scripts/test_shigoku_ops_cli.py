from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _write_session(path: Path, *, covered: int, required: int, missing: list[str]) -> None:
    payload = {
        "completed_tasks": [
            {
                "id": "scenario_probe_1",
                "result": {
                    "findings": [
                        {
                            "title": "Potential IDOR/BOLA Object Access Surface",
                            "target_url": "http://127.0.0.1:8888/account/settings",
                            "vuln_type": "broken_access_control",
                            "additional_info": {
                                "detection_class": "idor_bola",
                                "heuristic_candidate": True,
                                "verification_required": True,
                            },
                        }
                    ],
                    "data": {},
                },
            }
        ],
        "task_queue": [],
        "scenario_coverage": {
            "covered_count": covered,
            "required_count": required,
            "missing_scenarios": missing,
        },
        "context": {
            "coverage_gate": {
                "missing_families": ["xss", "csrf"],
            }
        },
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _write_report(path: Path, *, source_session: str, coverage_line: str) -> None:
    lines = [
        "# Vulnerability Report",
        "",
        "**Target:** http://127.0.0.1:8888/",
        "**Generated:** 2026-04-12 13:58:07",
        f"**Source Session:** {source_session}",
        "**Tool:** SHIGOKU - Sovereign VAPT Engine",
        "",
        "## 🧪 Scenario Coverage (SCN01-12)",
        "",
        coverage_line,
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_ops_cli_report_consistency_json_success(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260412_135804.json"
    report_file = tmp_path / "haddix_report_20260412_135807.md"
    missing = ["scn_01_idor_bola_object_access"]
    _write_session(session_file, covered=11, required=12, missing=missing)
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 11/12 (91.7%), Missing: scn_01_idor_bola_object_access",
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "consistency",
            "--report",
            str(report_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "consistent"
    assert payload["session"]["path"] == str(session_file.resolve())


def test_ops_cli_session_findings_json_success(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260412_135804.json"
    _write_session(
        session_file,
        covered=11,
        required=12,
        missing=["scn_01_idor_bola_object_access"],
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "session",
            "findings",
            "--session",
            str(session_file),
            "--detection-class",
            "idor_bola",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["findings_count"] == 1
    assert payload["filters"]["detection_class"] == "idor_bola"


def test_ops_cli_validate_pytest_dry_run(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "validate",
            "pytest",
            "--suite",
            "report",
            "--dry-run",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "dry_run"
    assert "pytest" in payload["command"]
    assert "tests/unit/reporting/test_report_session_consistency.py" in payload["selected_tests"]


def test_ops_cli_session_resolve_from_report_json_success(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260412_135804.json"
    report_file = tmp_path / "haddix_report_20260412_135807.md"
    _write_session(
        session_file,
        covered=11,
        required=12,
        missing=["scn_01_idor_bola_object_access"],
    )
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 11/12 (91.7%), Missing: scn_01_idor_bola_object_access",
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "session",
            "resolve-from-report",
            "--report",
            str(report_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "consistent"
    assert payload["session_path"] == str(session_file.resolve())
    assert payload["session_selection"] == "source_session_header"


def test_ops_cli_report_loop_json_success(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260412_135804.json"
    report_file = tmp_path / "haddix_report_20260412_135807.md"
    missing = ["scn_01_idor_bola_object_access"]
    _write_session(session_file, covered=11, required=12, missing=missing)
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 11/12 (91.7%), Missing: scn_01_idor_bola_object_access",
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "loop",
            "--report",
            str(report_file),
            "--include-findings",
            "--max-findings",
            "1",
            "--finding-fields",
            "title,target_url",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 3, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "failed"
    assert [stage["name"] for stage in payload["stages"]] == ["consistency", "gate", "findings"]
    assert payload["stages"][0]["status"] == "consistent"
    assert payload["stages"][1]["status"] == "fail"
    assert payload["stages"][2]["status"] == "ok"
    assert payload["stages"][2]["result"]["findings_count"] == 1
    assert sorted(payload["stages"][2]["result"]["findings"][0].keys()) == ["target_url", "title"]


def test_ops_cli_validate_pytest_report_loop_suite_dry_run(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "validate",
            "pytest",
            "--suite",
            "report_loop",
            "--dry-run",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "dry_run"
    assert "tests/unit/reporting/test_report_session_consistency.py" in payload["selected_tests"]
    assert "tests/unit/reporting/test_initial_release_gate.py" in payload["selected_tests"]
    assert "tests/unit/reporting/test_session_finding_inspector.py" in payload["selected_tests"]


def test_ops_cli_phase1_correlation_ids_json_success(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "phase1",
            "correlation-ids",
            "--build-id",
            "build-xyz",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["correlation"]["build_id"] == "build-xyz"
    assert payload["correlation"]["trace_id"]
    assert payload["correlation"]["request_id"]


def test_ops_cli_phase1_check_event_missing_fields_fails(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "phase1",
            "check-event",
            "--event-json",
            '{"trace_id":"abc"}',
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 3, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "missing_fields"
    assert "request_id" in payload["missing_fields"]


def test_ops_cli_phase1_check_event_all_required_fields_ok(tmp_path: Path) -> None:
    event_json = json.dumps(
        {
            "trace_id": "t",
            "request_id": "r",
            "test_case_id": "tc",
            "build_id": "b",
            "endpoint": "/graphql",
            "error_type": "none",
            "timeout_ms": 10,
            "retry_count": 0,
            "dns_ms": 1,
            "connect_ms": 1,
            "tls_ms": 1,
            "ttfb_ms": 1,
            "read_ms": 1,
        },
        ensure_ascii=False,
    )
    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "phase1",
            "check-event",
            "--event-json",
            event_json,
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"


def test_ops_cli_phase2_classify_failure_json_success(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "phase2",
            "classify-failure",
            "--reason-code",
            "TIMEOUT_PHASE2",
            "--error-message",
            "timeout occurred",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["failure_category"] == "timeout"


def test_ops_cli_phase2_schema_severity_json_success(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "phase2",
            "schema-severity",
            "--removed",
            "1",
            "--type-changed",
            "1",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["severity"] in {"high", "critical"}


def test_ops_cli_phase2_flaky_evaluate_quarantine(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "phase2",
            "flaky-evaluate",
            "--outcomes-csv",
            "ok,fail,ok,fail,ok",
            "--window-size",
            "5",
            "--min-failures",
            "2",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 3, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "quarantine"


def test_ops_cli_json_envelope_wraps_payload(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260412_135804.json"
    report_file = tmp_path / "haddix_report_20260412_135807.md"
    missing = ["scn_01_idor_bola_object_access"]
    _write_session(session_file, covered=11, required=12, missing=missing)
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 11/12 (91.7%), Missing: scn_01_idor_bola_object_access",
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "--json-envelope",
            "report",
            "consistency",
            "--report",
            str(report_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    wrapped = json.loads(result.stdout)
    assert wrapped["schema_version"] == "shigoku.ops.v1"
    assert wrapped["command"] == "report.consistency"
    assert wrapped["payload"]["status"] == "consistent"


def test_ops_cli_session_findings_supports_field_preset(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260412_135804.json"
    _write_session(
        session_file,
        covered=11,
        required=12,
        missing=["scn_01_idor_bola_object_access"],
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "session",
            "findings",
            "--session",
            str(session_file),
            "--finding-preset",
            "minimal",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["findings_count"] == 1
    assert sorted(payload["findings"][0].keys()) == ["target_url", "title"]


def test_ops_cli_session_findings_fields_override_preset(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260412_135804.json"
    _write_session(
        session_file,
        covered=11,
        required=12,
        missing=["scn_01_idor_bola_object_access"],
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "session",
            "findings",
            "--session",
            str(session_file),
            "--finding-preset",
            "minimal",
            "--finding-fields",
            "title,target_url,vuln_type",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["findings_count"] == 1
    assert sorted(payload["findings"][0].keys()) == ["target_url", "title", "vuln_type"]


def test_ops_cli_report_loop_includes_retry_policy_hints(tmp_path: Path) -> None:
    missing_report = tmp_path / "haddix_report_20990101_000000.md"
    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "loop",
            "--report",
            str(missing_report),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert "next_commands" in payload
    assert any("report consistency" in cmd for cmd in payload["next_commands"])


def test_ops_cli_runtime_control_gate_pass(tmp_path: Path) -> None:
    evidence_file = tmp_path / "runtime_control_gate_evidence.json"
    records = [
        {
            "gate_name": "compatibility",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
        {
            "gate_name": "distributed_control",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
        {
            "gate_name": "fault_injection",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
        {
            "gate_name": "shadow_mode",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
        {
            "gate_name": "kpi",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
        {
            "gate_name": "rollback_drill",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
    ]
    evidence_file.write_text(json.dumps(records, ensure_ascii=False), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "runtime-control",
            "gate",
            "--evidence-file",
            str(evidence_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "pass"
    assert payload["decision"] == "proceed"
    assert payload["record_count"] == 6


def test_ops_cli_runtime_control_gate_missing_file_hold(tmp_path: Path) -> None:
    evidence_file = tmp_path / "not_found_runtime_control_gate_evidence.json"
    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "runtime-control",
            "gate",
            "--evidence-file",
            str(evidence_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert payload["decision"] == "hold"
    assert "runtime_control_evidence_missing" in payload["reason_codes"]


def test_ops_cli_runtime_control_gate_hash_mismatch_fails(tmp_path: Path) -> None:
    evidence_file = tmp_path / "runtime_control_gate_evidence.json"
    manifest_file = tmp_path / "runtime_control_integrity_manifest.json"
    records = [
        {
            "gate_name": "compatibility",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
        {
            "gate_name": "distributed_control",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
        {
            "gate_name": "fault_injection",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
        {
            "gate_name": "shadow_mode",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
        {
            "gate_name": "kpi",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
        {
            "gate_name": "rollback_drill",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
    ]
    evidence_file.write_text(json.dumps(records, ensure_ascii=False), encoding="utf-8")
    manifest_file.write_text(
        json.dumps({"gate_evidence_sha256": "deadbeef"}, ensure_ascii=False),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "runtime-control",
            "gate",
            "--evidence-file",
            str(evidence_file),
            "--integrity-manifest",
            str(manifest_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 3, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "fail"
    assert payload["decision"] == "hold"
    assert "runtime_control_evidence_hash_mismatch" in payload["errors"]


def test_ops_cli_runtime_control_gate_approval_source_mismatch_fails(tmp_path: Path) -> None:
    evidence_file = tmp_path / "runtime_control_gate_evidence.json"
    approval_file = tmp_path / "runtime_control_approval_evidence.json"
    records = [
        {
            "gate_name": "compatibility",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
            "review_id": "org/repo#10:12345",
        },
        {
            "gate_name": "distributed_control",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
            "review_id": "org/repo#10:99999",
        },
        {
            "gate_name": "fault_injection",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
            "review_id": "org/repo#10:77777",
        },
        {
            "gate_name": "shadow_mode",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
        {
            "gate_name": "kpi",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
        {
            "gate_name": "rollback_drill",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
    ]
    evidence_file.write_text(json.dumps(records, ensure_ascii=False), encoding="utf-8")
    approval_file.write_text(
        json.dumps({"approved_review_ids": ["org/repo#10:12345"]}, ensure_ascii=False),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "runtime-control",
            "gate",
            "--evidence-file",
            str(evidence_file),
            "--approval-evidence-file",
            str(approval_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 3, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "fail"
    assert "approval_source_mismatch" in payload["errors"]


def test_ops_cli_runtime_control_gate_insufficient_approvals_fails(tmp_path: Path) -> None:
    evidence_file = tmp_path / "runtime_control_gate_evidence.json"
    approval_file = tmp_path / "runtime_control_approval_evidence.json"
    records = [
        {
            "gate_name": "compatibility",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
            "review_id": "org/repo#10:12345",
        },
        {
            "gate_name": "distributed_control",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
            "review_id": "org/repo#10:12345",
        },
        {
            "gate_name": "fault_injection",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
            "review_id": "org/repo#10:12345",
        },
        {
            "gate_name": "shadow_mode",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
        {
            "gate_name": "kpi",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
        {
            "gate_name": "rollback_drill",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
    ]
    evidence_file.write_text(json.dumps(records, ensure_ascii=False), encoding="utf-8")
    approval_file.write_text(
        json.dumps(
            {
                "approved_review_ids": ["org/repo#10:12345"],
                "required_approving_review_count": 2,
                "approved_unique_count": 1,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "runtime-control",
            "gate",
            "--evidence-file",
            str(evidence_file),
            "--approval-evidence-file",
            str(approval_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 3, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "fail"
    assert "approval_source_insufficient_approvals" in payload["errors"]


def test_ops_cli_runtime_control_gate_branch_protection_mismatch_fails(tmp_path: Path) -> None:
    evidence_file = tmp_path / "runtime_control_gate_evidence.json"
    approval_file = tmp_path / "runtime_control_approval_evidence.json"
    records = [
        {
            "gate_name": "compatibility",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
            "review_id": "org/repo#10:12345",
        },
        {
            "gate_name": "distributed_control",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
            "review_id": "org/repo#10:12345",
        },
        {
            "gate_name": "fault_injection",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
            "review_id": "org/repo#10:12345",
        },
        {
            "gate_name": "shadow_mode",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
        {
            "gate_name": "kpi",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
        {
            "gate_name": "rollback_drill",
            "status": "pass",
            "date": "2026-05-26",
            "evidence_source": "pytest",
            "evidence_summary": "ok",
            "risk_if_failed": "degradation",
            "decision": "proceed",
            "approver": "cto",
        },
    ]
    evidence_file.write_text(json.dumps(records, ensure_ascii=False), encoding="utf-8")
    approval_file.write_text(
        json.dumps(
            {
                "approved_review_ids": ["org/repo#10:12345"],
                "required_approving_review_count": 1,
                "approved_unique_count": 1,
                "require_code_owner_reviews": False,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "runtime-control",
            "gate",
            "--evidence-file",
            str(evidence_file),
            "--approval-evidence-file",
            str(approval_file),
            "--require-code-owner-reviews",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 3, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "fail"
    assert "approval_source_branch_protection_mismatch" in payload["errors"]
