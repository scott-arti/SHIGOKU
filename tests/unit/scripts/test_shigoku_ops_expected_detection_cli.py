from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _write_session(path: Path, findings: list[dict], *, security_level: str = "low") -> None:
    payload = {
        "completed_tasks": [
            {
                "id": "fixture-task",
                "params": {"cookies": f"security={security_level}"},
                "result": {"findings": findings},
            }
        ],
        "task_queue": [],
        "scenario_coverage": {
            "covered_count": 9,
            "required_count": 12,
            "missing_scenarios": [
                "scn_08_oob_external_channel_flow",
                "scn_10_semantic_business_logic",
                "scn_12_advanced_ssrf_internal_topology",
            ],
        },
        "coverage_gate": {"coverage_items": [{"reached": True}]},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _write_report(path: Path, source_session: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "# 🔒 Vulnerability Report",
                "",
                "**Target:** http://localhost:4280/",
                "**Generated:** 2026-07-24 16:47:50",
                f"**Source Session:** {source_session.resolve()}",
                "**Tool:** SHIGOKU - Sovereign VAPT Engine",
                "",
                "## 🧪 Scenario Coverage (SCN01-12)",
                "",
                (
                    "Coverage: 9/12 (75.0%), Missing: "
                    "scn_08_oob_external_channel_flow, "
                    "scn_10_semantic_business_logic, "
                    "scn_12_advanced_ssrf_internal_topology"
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )


def test_ops_cli_report_expected_detections_reports_missing_authbypass(tmp_path: Path) -> None:
    session = tmp_path / "projects" / "localhost:4280" / "sessions" / "session_20260724_164750.json"
    report = tmp_path / "projects" / "localhost:4280" / "reports" / "haddix_report_20260724_164750.md"
    _write_session(
        session,
        [
            {
                "vuln_type": "sqli",
                "title": "SQL Injection in parameter 'id'",
                "target_url": "http://localhost:4280/vulnerabilities/sqli/",
            }
        ],
    )
    _write_report(report, session)

    result = subprocess.run(
        [
            ".venv/bin/python",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "expected-detections",
            "--report",
            str(report),
            "--profile",
            "dvwa-low-regression",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    missing = {item["detection_id"] for item in payload["missing_required"]}
    assert "authbypass_idor" in missing


def test_ops_cli_report_expected_detections_uses_generic_profile_for_high(tmp_path: Path) -> None:
    session = tmp_path / "projects" / "localhost:4280" / "sessions" / "session_20260724_164751.json"
    report = tmp_path / "projects" / "localhost:4280" / "reports" / "haddix_report_20260724_164751.md"
    _write_session(session, [], security_level="high")
    _write_report(report, session)

    result = subprocess.run(
        [
            ".venv/bin/python",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "expected-detections",
            "--report",
            str(report),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["assessment_type"] == "generic_capability"


def test_ops_cli_report_compare_findings_reports_missing_open_redirect(tmp_path: Path) -> None:
    project_dir = tmp_path / "projects" / "localhost:4280"
    baseline_session = project_dir / "sessions" / "session_20260723_162936.json"
    current_session = project_dir / "sessions" / "session_20260724_164750.json"
    baseline_report = project_dir / "reports" / "haddix_report_20260723_162936.md"
    current_report = project_dir / "reports" / "haddix_report_20260724_164750.md"

    _write_session(
        baseline_session,
        [
            {
                "vuln_type": "open_redirect",
                "title": "Open Redirect in parameter 'redirect'",
                "target_url": "http://127.0.0.1:4280/vulnerabilities/open_redirect/source/low.php?redirect=info.php&id=1",
            }
        ],
    )
    _write_session(
        current_session,
        [
            {
                "vuln_type": "crlf_injection",
                "title": "CRLF Injection via parameter 'redirect'",
                "target_url": "http://localhost:4280/vulnerabilities/open_redirect/source/low.php?id=1&redirect=info.php",
            }
        ],
    )
    _write_report(baseline_report, baseline_session)
    _write_report(current_report, current_session)

    result = subprocess.run(
        [
            ".venv/bin/python",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "compare-findings",
            "--baseline-report",
            str(baseline_report),
            "--report",
            str(current_report),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["missing_in_current"][0]["vuln_type"] == "open_redirect"
