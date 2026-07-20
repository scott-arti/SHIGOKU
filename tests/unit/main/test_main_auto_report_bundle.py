from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from src import main as main_module


def _sample_session_payload() -> dict:
    return {
        "start_time": 1719240000.0,
        "timestamp": 1719240360.0,
        "session_id": "test-session-auto-report",
        "goal_target": "http://example.com",
        "program_name": "Example Program",
        "completed_tasks": [
            {
                "id": "task_1",
                "name": "xss-check",
                "state": "success",
                "agent_type": "web_tester",
                "action": "scan",
                "target_url": "http://example.com/login",
                "result": {
                    "data": {
                        "findings": [
                            {
                                "title": "Reflected XSS on login",
                                "severity": "high",
                                "vuln_type": "xss",
                                "target_url": "http://example.com/login",
                                "summary": "Potential reflected XSS in login form.",
                                "poc_request": "GET /login?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1",
                                "poc_response": "HTTP/1.1 200 OK",
                            }
                        ]
                    }
                },
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
            "discovered_assets": ["http://example.com/login"],
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
            "totals": {
                "input_tokens": 100,
                "output_tokens": 50,
                "input_cache_tokens": 0,
                "call_count": 1,
            },
            "cache_hit_ratio": 0.0,
        },
        "scenario_coverage": {
            "missing_scenarios": [],
            "covered_count": 12,
            "required_count": 12,
        },
    }


def test_auto_generate_standard_reports_for_target_creates_all_reports(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    # ProjectManager resolves the relative ``workspace/projects`` base against
    # ``_project_root()`` (the repo root), not cwd. Point the project root at
    # the temp dir so the bundle writes under tmp_path instead of the real
    # workspace. (SGK-2026-0347 auto-report-bundle test isolation)
    monkeypatch.setattr(
        "src.core.project.project_manager._project_root",
        lambda: tmp_path,
    )
    project_dir = tmp_path / "workspace" / "projects" / "example.com"
    sessions_dir = project_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260703_120000.json"
    session_file.write_text(
        json.dumps(_sample_session_payload(), ensure_ascii=False),
        encoding="utf-8",
    )

    artifacts = main_module._auto_generate_standard_reports_for_target("https://example.com")

    assert artifacts is not None
    assert artifacts["project_dir"] == project_dir.resolve()
    assert artifacts["session_path"] == session_file.resolve()
    assert artifacts["run_narrative_path"].exists()
    assert artifacts["target_profile_path"].exists()
    assert artifacts["haddix_report_path"].exists()
    assert artifacts["haddix_gate_path"].exists()
    assert artifacts["run_narrative_path"].name.startswith("run_narrative_")
    assert artifacts["target_profile_path"].name.startswith("target_profile_")
    assert artifacts["haddix_report_path"].name.startswith("haddix_report_")

    narrative = artifacts["run_narrative_path"].read_text(encoding="utf-8")
    profile = artifacts["target_profile_path"].read_text(encoding="utf-8")
    haddix = artifacts["haddix_report_path"].read_text(encoding="utf-8")

    assert "実行" in narrative or "Run Narrative" in narrative
    assert "Target Profile" in profile or "ターゲットプロファイル" in profile
    assert f"**Source Session:** {session_file.resolve()}" in haddix
    assert "# 提出用レポート / Submission Report" in haddix
    assert "# 内部評価（私用） / Internal Review Notes" in haddix


def test_auto_generate_standard_reports_for_target_keeps_history_and_injects_target_profile_diff(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "src.core.project.project_manager._project_root",
        lambda: tmp_path,
    )
    project_dir = tmp_path / "workspace" / "projects" / "example.com"
    sessions_dir = project_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260703_120000.json"
    session_file.write_text(
        json.dumps(_sample_session_payload(), ensure_ascii=False),
        encoding="utf-8",
    )

    first_artifacts = main_module._auto_generate_standard_reports_for_target("https://example.com")
    assert first_artifacts is not None

    time.sleep(1.1)

    second_artifacts = main_module._auto_generate_standard_reports_for_target("https://example.com")
    assert second_artifacts is not None
    assert first_artifacts["run_narrative_path"] != second_artifacts["run_narrative_path"]
    assert first_artifacts["target_profile_path"] != second_artifacts["target_profile_path"]

    second_profile = second_artifacts["target_profile_path"].read_text(encoding="utf-8")
    assert "## 前回レポートとの差分" in second_profile
    assert f"`{first_artifacts['target_profile_path'].name}`" in second_profile
    assert "- 判定: 差分なし" in second_profile


def test_print_auto_report_bundle_summary_lists_project_and_report_paths(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    monkeypatch.setattr(main_module, "print_step", lambda icon, text: calls.append((icon, text)))

    main_module._print_auto_report_bundle_summary(
        {
            "project_dir": Path("/tmp/project"),
            "session_path": Path("/tmp/project/sessions/session_20260703_120000.json"),
            "run_narrative_path": Path("/tmp/project/reports/run_narrative_20260703_120000.md"),
            "target_profile_path": Path("/tmp/project/reports/target_profile_20260703_120000.md"),
            "haddix_report_path": Path("/tmp/project/reports/haddix_report_20260703_120000.md"),
            "haddix_gate_path": Path("/tmp/project/reports/haddix_gate_20260703_120000.json"),
            "haddix_deferred_path": Path("/tmp/project/reports/haddix_deferred_20260703_120000.json"),
        }
    )

    assert ("📁", "Project Folder: /tmp/project") in calls
    assert ("🗂️", "Session JSON: /tmp/project/sessions/session_20260703_120000.json") in calls
    assert ("📄", "Run Narrative: /tmp/project/reports/run_narrative_20260703_120000.md") in calls
    assert ("📄", "Target Profile: /tmp/project/reports/target_profile_20260703_120000.md") in calls
    assert (
        "📄",
        "Haddix Report: /tmp/project/reports/haddix_report_20260703_120000.md",
    ) in calls
    assert ("🧾", "Haddix Gate JSON: /tmp/project/reports/haddix_gate_20260703_120000.json") in calls
    assert ("🧾", "Haddix Deferred JSON: /tmp/project/reports/haddix_deferred_20260703_120000.json") in calls


def test_print_auto_report_bundle_summary_maps_runtime_workspace_to_host_path(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    monkeypatch.setenv("SHIGOKU_WORKSPACE_ROOT", "/workspace")
    monkeypatch.setenv("SHIGOKU_HOST_WORKSPACE_ROOT", "/home/bbb/Documents/App/Shigoku/workspace")
    monkeypatch.setattr(main_module, "print_step", lambda icon, text: calls.append((icon, text)))

    main_module._print_auto_report_bundle_summary(
        {
            "project_dir": Path("/workspace/projects/localhost:4280"),
            "session_path": Path("/workspace/projects/localhost:4280/sessions/session_20260714_114645.json"),
            "run_narrative_path": Path("/workspace/projects/localhost:4280/reports/run_narrative_20260714_114645.md"),
            "target_profile_path": Path("/workspace/projects/localhost:4280/reports/target_profile_20260714_114645.md"),
            "haddix_report_path": Path("/workspace/projects/localhost:4280/reports/haddix_report_20260714_114645.md"),
            "haddix_gate_path": Path("/workspace/projects/localhost:4280/reports/haddix_gate_20260714_114645.json"),
            "haddix_deferred_path": Path("/workspace/projects/localhost:4280/reports/haddix_deferred_20260714_114645.json"),
        }
    )

    assert (
        "🗂️",
        "Session JSON: /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/sessions/session_20260714_114645.json",
    ) in calls
    assert (
        "📄",
        "Haddix Report: /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260714_114645.md",
    ) in calls
