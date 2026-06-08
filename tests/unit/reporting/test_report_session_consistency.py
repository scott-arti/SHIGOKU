from __future__ import annotations

import json
from pathlib import Path

from src.reporting.report_session_consistency import verify_report_session_consistency


def _write_session(path: Path, *, covered: int, required: int, missing: list[str]) -> None:
    payload = {
        "completed_tasks": [],
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
        "# 🔒 Vulnerability Report",
        "",
        "**Target:** http://127.0.0.1:8888/",
        "**Generated:** 2026-04-12 13:58:07",
    ]
    if source_session:
        lines.append(f"**Source Session:** {source_session}")
    lines.extend(
        [
            "**Tool:** SHIGOKU - Sovereign VAPT Engine",
            "",
            "## 🧪 Scenario Coverage (SCN01-12)",
            "",
            coverage_line,
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def test_verify_report_session_consistency_is_consistent_with_source_session(tmp_path: Path) -> None:
    project_dir = tmp_path / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260412_135804.json"
    missing = [
        "scn_01_idor_bola_object_access",
        "scn_08_oob_external_channel_flow",
        "scn_09_multi_step_state_machine",
    ]
    _write_session(session_file, covered=9, required=12, missing=missing)

    report_file = reports_dir / "haddix_report_20260412_135807.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line=f"Coverage: 9/12 (75.0%), Missing: {', '.join(missing)}",
    )

    verdict = verify_report_session_consistency(report_file)
    assert verdict["status"] == "consistent"
    assert verdict["rerun_required"] is False
    assert verdict["session"]["selection"] == "source_session_header"
    assert verdict["session"]["path"] == str(session_file.resolve())


def test_verify_report_session_consistency_marks_empty_missing_sets_as_match(tmp_path: Path) -> None:
    project_dir = tmp_path / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260412_135804.json"
    _write_session(session_file, covered=12, required=12, missing=[])

    report_file = reports_dir / "haddix_report_20260412_135807.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 12/12 (100.0%), Missing: -",
    )

    verdict = verify_report_session_consistency(report_file)
    assert verdict["status"] == "consistent"
    assert verdict["comparison"]["scenario_missing_set_match"] is True


def test_verify_report_session_consistency_detects_coverage_mismatch(tmp_path: Path) -> None:
    project_dir = tmp_path / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260412_135804.json"
    _write_session(
        session_file,
        covered=9,
        required=12,
        missing=["scn_01_idor_bola_object_access", "scn_08_oob_external_channel_flow", "scn_09_multi_step_state_machine"],
    )

    report_file = reports_dir / "haddix_report_20260412_135807.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 8/12 (66.7%), Missing: scn_01_idor_bola_object_access, scn_08_oob_external_channel_flow, scn_09_multi_step_state_machine, scn_12_advanced_ssrf_internal_topology",
    )

    verdict = verify_report_session_consistency(report_file)
    assert verdict["status"] == "inconsistent"
    assert verdict["rerun_required"] is True
    assert "scenario_coverage_count_mismatch" in verdict["reason_codes"]


def test_verify_report_session_consistency_blocks_when_source_session_missing(tmp_path: Path) -> None:
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_file = reports_dir / "haddix_report_20260412_135807.md"

    _write_report(
        report_file,
        source_session=str((tmp_path / "missing" / "session_20260412_135804.json").resolve()),
        coverage_line="Coverage: 6/12 (50.0%), Missing: scn_01_idor_bola_object_access",
    )

    verdict = verify_report_session_consistency(report_file)
    assert verdict["status"] == "blocked"
    assert verdict["rerun_required"] is False
    assert "source_session_not_found" in verdict["reason_codes"]


def test_verify_report_session_consistency_falls_back_to_timestamp_nearest(tmp_path: Path) -> None:
    project_dir = tmp_path / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    near_file = sessions_dir / "session_20260412_135804.json"
    far_file = sessions_dir / "session_20260412_130000.json"
    _write_session(near_file, covered=6, required=12, missing=["scn_01_idor_bola_object_access"])
    _write_session(far_file, covered=1, required=12, missing=["scn_01_idor_bola_object_access"])

    report_file = reports_dir / "haddix_report_20260412_135807.md"
    _write_report(
        report_file,
        source_session="",
        coverage_line="Coverage: 6/12 (50.0%), Missing: scn_01_idor_bola_object_access",
    )

    verdict = verify_report_session_consistency(report_file)
    assert verdict["status"] == "consistent"
    assert verdict["session"]["selection"] == "report_timestamp_nearest"
    assert verdict["session"]["path"] == str(near_file.resolve())


def test_verify_report_session_consistency_resolves_docker_workspace_source_session(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260412_135804.json"
    missing = ["scn_01_idor_bola_object_access"]
    _write_session(session_file, covered=11, required=12, missing=missing)

    report_file = reports_dir / "haddix_report_20260412_135807.md"
    _write_report(
        report_file,
        source_session="/workspace/projects/127.0.0.1:8888/sessions/session_20260412_135804.json",
        coverage_line="Coverage: 11/12 (91.7%), Missing: scn_01_idor_bola_object_access",
    )

    verdict = verify_report_session_consistency(report_file)
    assert verdict["status"] == "consistent"
    assert verdict["session"]["selection"] == "source_session_header"
    assert verdict["session"]["path"] == str(session_file.resolve())
