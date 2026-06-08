from __future__ import annotations

import json
from pathlib import Path

from src.reporting.report_loop_orchestrator import run_report_loop


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


def test_run_report_loop_executes_consistency_gate_findings(tmp_path: Path) -> None:
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

    result = run_report_loop(
        report_file,
        include_findings=True,
        max_findings=1,
        finding_fields=["title", "target_url"],
    )

    assert result["status"] == "failed"
    assert [stage["name"] for stage in result["stages"]] == ["consistency", "gate", "findings"]
    assert result["stages"][0]["status"] == "consistent"
    assert result["stages"][1]["status"] == "fail"
    assert result["stages"][2]["status"] == "ok"
    assert result["stages"][2]["result"]["findings_count"] == 1


def test_run_report_loop_blocks_when_report_missing(tmp_path: Path) -> None:
    result = run_report_loop(tmp_path / "haddix_report_20990101_000000.md")
    assert result["status"] == "blocked"
    assert result["stages"][0]["name"] == "consistency"
    assert result["stages"][0]["status"] == "blocked"
    assert "next_commands" in result
    assert any("report consistency" in cmd for cmd in result["next_commands"])
