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


# ---------------------------------------------------------------------------
# report narrative / report target-profile の CLI テスト
# ---------------------------------------------------------------------------

def _write_full_session(path: Path) -> None:
    """Write a comprehensive session JSON for narrative/profile formatter testing."""
    payload = {
        "start_time": 1719240000.0,
        "timestamp": 1719240360.0,
        "session_id": "test-session-ops",
        "completed_tasks": [
            {
                "id": "task_1",
                "state": "success",
                "target_url": "http://example.com/login",
                "vulnerabilities_found": [
                    {"title": "XSS on login", "severity": "high", "type": "xss"}
                ],
            }
        ],
        "task_queue": [],
        "context": {
            "target_info": {"url": "http://example.com", "domain": "example.com"},
            "scenario_coverage": {
                "missing_scenarios": [],
                "covered_count": 12,
                "required_count": 12,
            },
        },
        "run_ledger": [
            {
                "event_id": "ledger_evt_run1_0001",
                "event_type": "llm_called",
                "timestamp": "2026-06-24T10:00:00Z",
                "phase": "init",
                "actor_type": "MasterConductor",
                "actor_name": "conductor",
                "action": "plan",
                "result": "ok",
            }
        ],
        "llm_usage_summary": {
            "by_model": {},
            "totals": {"input_tokens": 100, "output_tokens": 50, "input_cache_tokens": 0, "call_count": 1},
            "cache_hit_ratio": 0.0,
        },
        "scenario_coverage": {
            "missing_scenarios": [],
            "covered_count": 12,
            "required_count": 12,
        },
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_ops_cli_report_narrative_with_session(tmp_path: Path) -> None:
    session_file = tmp_path / "session_test.json"
    _write_full_session(session_file)

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "narrative",
            "--session",
            str(session_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"


def test_ops_cli_report_target_profile_with_session(tmp_path: Path) -> None:
    session_file = tmp_path / "session_test.json"
    _write_full_session(session_file)

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "target-profile",
            "--session",
            str(session_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"


def test_ops_cli_report_narrative_output_to_file(tmp_path: Path) -> None:
    session_file = tmp_path / "session_test.json"
    _write_full_session(session_file)
    output_file = tmp_path / "narrative_output.md"

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "narrative",
            "--session",
            str(session_file),
            "--output",
            str(output_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")
    assert "SHIGOKU" in content or "Run Narrative" in content or "実行" in content


def test_ops_cli_report_target_profile_output_to_file(tmp_path: Path) -> None:
    session_file = tmp_path / "session_test.json"
    _write_full_session(session_file)
    output_file = tmp_path / "profile_output.md"

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "target-profile",
            "--session",
            str(session_file),
            "--output",
            str(output_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")
    assert "ターゲットプロファイル" in content or "Target Profile" in content


def test_ops_cli_report_narrative_missing_session(tmp_path: Path) -> None:
    nonexistent = tmp_path / "nonexistent.json"

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "narrative",
            "--session",
            str(nonexistent),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2, f"Expected exit 2, got {result.returncode}: {result.stderr}"
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert "session_not_resolved" in payload.get("reason_codes", [])


# ---------------------------------------------------------------------------
# report narrative / report target-profile with --report consistency gate
# ---------------------------------------------------------------------------


def test_ops_cli_report_narrative_with_report_inconsistent_blocks(tmp_path: Path) -> None:
    """When --report is used and coverage mismatches, generation must be blocked."""
    session_file = tmp_path / "session_20260412_135804.json"
    report_file = tmp_path / "haddix_report_20260412_135807.md"
    # Session has 11/12 coverage
    _write_session(
        session_file,
        covered=11,
        required=12,
        missing=["scn_01_idor_bola_object_access"],
    )
    # Report claims 12/12 — MISMATCH with session
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 12/12 (100%), Missing: none",
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "narrative",
            "--report",
            str(report_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0, f"Expected non-zero exit for inconsistent, got {result.returncode}: {result.stderr}"
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert any("coverage" in rc.lower() for rc in payload.get("reason_codes", [])), (
        f"Expected coverage-related reason code in {payload.get('reason_codes')}"
    )


def test_ops_cli_report_target_profile_with_report_inconsistent_blocks(tmp_path: Path) -> None:
    """When --report is used with target-profile and coverage mismatches, block."""
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
        coverage_line="Coverage: 12/12 (100%), Missing: none",
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "target-profile",
            "--report",
            str(report_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0, f"Expected non-zero exit for inconsistent, got {result.returncode}: {result.stderr}"
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert any("coverage" in rc.lower() for rc in payload.get("reason_codes", [])), (
        f"Expected coverage-related reason code in {payload.get('reason_codes')}"
    )


def test_ops_cli_report_narrative_with_report_consistent_succeeds(tmp_path: Path) -> None:
    """When --report is used and coverage matches, generation must proceed."""
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
            "narrative",
            "--report",
            str(report_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, (
        f"Expected exit 0 for consistent pair, got {result.returncode}: {result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok", f"Expected ok status, got {payload}"


def test_ops_cli_narrative_extracts_deep_findings(tmp_path: Path) -> None:
    session_file = tmp_path / "session_deep.json"
    payload = {
        "completed_tasks": [
            {
                "id": "task_1",
                "result": {
                    "findings": [{"title": "Deep Finding from result.findings", "severity": "high"}],
                },
            },
            {
                "id": "task_2",
                "result": {
                    "data": {
                        "findings": [{"title": "Deeper Finding from data.findings", "severity": "critical"}],
                    },
                },
            },
        ],
        "start_time": 1719240000.0,
        "task_queue": [],
        "context": {},
    }
    session_file.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "narrative",
            "--session",
            str(session_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["status"] == "ok"
    markdown = data["markdown"]
    assert "Deep Finding from result.findings" in markdown
    assert "Deeper Finding from data.findings" in markdown


# ============================================================================
# SGK-2026-0334: report decision-tree CLI tests
# ============================================================================


def _write_decision_tree_session(path: Path) -> None:
    """Write a minimal session JSON with run_ledger events for decision-tree."""
    events = [
        {"event_id": "evt_0", "event_type": "decision_made", "phase": "recon",
         "timestamp": "2026-07-01T00:00:00Z", "action": "dispatch_recon",
         "actor_type": "MasterConductor", "actor_name": "MC"},
        {"event_id": "evt_1", "event_type": "swarm_dispatched", "phase": "recon",
         "timestamp": "2026-07-01T00:01:00Z", "parent_event_id": "evt_0",
         "actor_type": "DiscoverySwarm", "actor_name": "DS"},
        {"event_id": "evt_2", "event_type": "swarm_completed", "phase": "recon",
         "timestamp": "2026-07-01T00:02:00Z", "parent_event_id": "evt_1",
         "actor_type": "DiscoverySwarm", "actor_name": "DS"},
        {"event_id": "evt_3", "event_type": "decision_made", "phase": "attack",
         "timestamp": "2026-07-01T00:03:00Z", "parent_event_id": "evt_2",
         "actor_type": "MasterConductor", "actor_name": "MC",
         "decision_id": "dec_atk_1"},
        {"event_id": "evt_4", "event_type": "error_occurred", "phase": "attack",
         "timestamp": "2026-07-01T00:04:00Z", "parent_event_id": "evt_3",
         "actor_type": "InjectionSwarm", "actor_name": "IS",
         "error": "InjectionSwarm timeout"},
    ]
    payload = {
        "run_ledger": events,
        "task_queue": [],
        "completed_tasks": [],
        "start_time": 1719240000.0,
        "context": {"target_info": {}},
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_ops_cli_decision_tree_json_basic(tmp_path: Path) -> None:
    """decision-tree --session with JSON output returns ok status with markdown."""
    session_file = tmp_path / "session_test.json"
    _write_decision_tree_session(session_file)

    result = subprocess.run(
        ["python3", "scripts/shigoku_ops_cli.py", "--json",
         "report", "decision-tree", "--session", str(session_file)],
        cwd=_repo_root(), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["status"] == "ok"
    assert "markdown" in data
    assert "graph TD" in data["markdown"]
    assert "evt_0" in data["markdown"]


def test_ops_cli_decision_tree_output_file(tmp_path: Path) -> None:
    """decision-tree --session --output writes to a file."""
    session_file = tmp_path / "session_test.json"
    out_file = tmp_path / "decision_tree.md"
    _write_decision_tree_session(session_file)

    result = subprocess.run(
        ["python3", "scripts/shigoku_ops_cli.py",
         "report", "decision-tree", "--session", str(session_file),
         "--output", str(out_file)],
        cwd=_repo_root(), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "graph TD" in content


def test_ops_cli_decision_tree_only_failures(tmp_path: Path) -> None:
    """--only-failures filters to error/failure nodes only."""
    session_file = tmp_path / "session_test.json"
    _write_decision_tree_session(session_file)

    result = subprocess.run(
        ["python3", "scripts/shigoku_ops_cli.py", "--json",
         "report", "decision-tree", "--session", str(session_file),
         "--only-failures"],
        cwd=_repo_root(), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    # Only evt_4 (error_occurred) should remain
    # evt_0-3 are decision_made/swarm_dispatched/swarm_completed — not failures
    markdown = data["markdown"]
    assert "n_evt_4" in markdown
    # Non-failure nodes should be absent
    assert "n_evt_0" not in markdown
    assert "n_evt_1" not in markdown


def test_ops_cli_decision_tree_phase_filter(tmp_path: Path) -> None:
    """--phase attack filters to attack-phase events."""
    session_file = tmp_path / "session_test.json"
    _write_decision_tree_session(session_file)

    result = subprocess.run(
        ["python3", "scripts/shigoku_ops_cli.py", "--json",
         "report", "decision-tree", "--session", str(session_file),
         "--phase", "attack"],
        cwd=_repo_root(), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    markdown = data["markdown"]
    # Attack phase nodes: evt_3, evt_4
    assert "n_evt_3" in markdown
    assert "n_evt_4" in markdown
    # Recon phase nodes should be absent
    assert "n_evt_0" not in markdown
    assert "n_evt_1" not in markdown


def test_ops_cli_decision_tree_actor_filter(tmp_path: Path) -> None:
    """--actor filter by actor type."""
    session_file = tmp_path / "session_test.json"
    _write_decision_tree_session(session_file)

    result = subprocess.run(
        ["python3", "scripts/shigoku_ops_cli.py", "--json",
         "report", "decision-tree", "--session", str(session_file),
         "--actor", "MasterConductor"],
        cwd=_repo_root(), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    markdown = data["markdown"]
    assert "n_evt_0" in markdown
    assert "n_evt_3" in markdown
    # DiscoverySwarm / InjectionSwarm nodes absent
    assert "n_evt_1" not in markdown
    assert "n_evt_2" not in markdown
    assert "n_evt_4" not in markdown


def test_ops_cli_decision_tree_max_nodes(tmp_path: Path) -> None:
    """--max-nodes limits output and marks degraded."""
    session_file = tmp_path / "session_test.json"
    _write_decision_tree_session(session_file)

    result = subprocess.run(
        ["python3", "scripts/shigoku_ops_cli.py", "--json",
         "report", "decision-tree", "--session", str(session_file),
         "--max-nodes", "2"],
        cwd=_repo_root(), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["status"] == "degraded"
    assert "degraded_max_nodes" in data["reason_codes"]


def test_ops_cli_decision_tree_json_envelope(tmp_path: Path) -> None:
    """--json-envelope wraps output in stable envelope."""
    session_file = tmp_path / "session_test.json"
    _write_decision_tree_session(session_file)

    result = subprocess.run(
        ["python3", "scripts/shigoku_ops_cli.py", "--json", "--json-envelope",
         "report", "decision-tree", "--session", str(session_file)],
        cwd=_repo_root(), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["schema_version"] == "shigoku.ops.v1"
    assert "decision-tree" in data["command"]
    assert "payload" in data
    assert data["payload"]["status"] == "ok"


def test_ops_cli_decision_tree_no_session_blocked(tmp_path: Path) -> None:
    """No --session or --report returns blocked."""
    result = subprocess.run(
        ["python3", "scripts/shigoku_ops_cli.py", "--json",
         "report", "decision-tree"],
        cwd=_repo_root(), capture_output=True, text=True,
    )
    assert result.returncode == 2
    data = json.loads(result.stdout)
    assert data["status"] == "blocked"


def test_ops_cli_decision_tree_legacy_session(tmp_path: Path) -> None:
    """Legacy session with only decision_traces (no run_ledger) works."""
    session_file = tmp_path / "session_legacy.json"
    payload = {
        "decision_traces": [
            {"trace_id": "dt_1", "timestamp": "2026-07-01T00:00:00Z",
             "phase": "recon", "action": "dispatch_recon"},
            {"trace_id": "dt_2", "timestamp": "2026-07-01T00:01:00Z",
             "phase": "attack", "action": "run_swarm"},
        ],
        "context": {"target_info": {}},
    }
    session_file.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    result = subprocess.run(
        ["python3", "scripts/shigoku_ops_cli.py", "--json",
         "report", "decision-tree", "--session", str(session_file)],
        cwd=_repo_root(), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["status"] == "ok"
    assert "graph TD" in data["markdown"]


def test_ops_cli_decision_tree_inconsistent_report_blocked(tmp_path: Path) -> None:
    """--report with inconsistent session blocks output."""
    session_file = tmp_path / "session_test.json"
    report_file = tmp_path / "haddix_report_test.md"
    _write_decision_tree_session(session_file)

    # Write a report that points to a different session
    report_file.write_text("\n".join([
        "# Vulnerability Report",
        "",
        "**Target:** http://example.com/",
        "**Generated:** 2026-07-01 12:00:00",
        "**Source Session:** /nonexistent/session_nonexistent.json",
        "**Tool:** SHIGOKU - Sovereign VAPT Engine",
        "",
        "Coverage: 5/12 (41%), Missing: scn_01,scn_02,scn_03,scn_04,scn_05,scn_06,scn_07",
    ]), encoding="utf-8")

    result = subprocess.run(
        ["python3", "scripts/shigoku_ops_cli.py", "--json",
         "report", "decision-tree", "--report", str(report_file),
         "--sessions-dir", str(tmp_path)],
        cwd=_repo_root(), capture_output=True, text=True,
    )
    # Should be blocked: inconsistent or session not found
    data = json.loads(result.stdout)
    assert data["status"] in ("blocked", "inconsistent")


def test_ops_cli_decision_tree_json_output_writes_file(tmp_path: Path) -> None:
    """--json --output writes the output file AND includes markdown in JSON payload."""
    session_file = tmp_path / "session_test.json"
    out_file = tmp_path / "decision_tree.md"
    _write_decision_tree_session(session_file)

    result = subprocess.run(
        ["python3", "scripts/shigoku_ops_cli.py", "--json",
         "report", "decision-tree", "--session", str(session_file),
         "--output", str(out_file)],
        cwd=_repo_root(), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    # Output file must exist
    assert out_file.exists(), f"Output file not created: {out_file}"
    content = out_file.read_text(encoding="utf-8")
    assert "graph TD" in content
    # JSON payload should reference the output path
    data = json.loads(result.stdout)
    assert data["status"] == "ok"
    assert data["output"] == str(out_file.resolve())


def test_ops_cli_decision_tree_json_includes_degraded_nodes(tmp_path: Path) -> None:
    """JSON summary must include degraded_nodes when nodes are degraded."""
    session_file = tmp_path / "session_test.json"
    _write_decision_tree_session(session_file)

    result = subprocess.run(
        ["python3", "scripts/shigoku_ops_cli.py", "--json",
         "report", "decision-tree", "--session", str(session_file),
         "--max-depth", "1"],
        cwd=_repo_root(), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    summary = data.get("summary", {})
    # "degraded_nodes" must be a present key in the JSON summary
    assert "degraded_nodes" in summary, (
        f"JSON summary missing 'degraded_nodes' key. Got keys: {sorted(summary.keys())}"
    )
    assert isinstance(summary["degraded_nodes"], int)
