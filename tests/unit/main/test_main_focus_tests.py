import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from src import main as main_module
from src.cli.handlers import focus_tests as focus_tests_module
from src.cli.handlers import quality_loop as quality_loop_module


def test_main_focus_list_outputs_groups(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["shigoku", "--focus-list"])

    main_module.main()

    captured = capsys.readouterr()
    assert "Focused test groups:" in captured.out
    assert "- density" in captured.out
    assert "- report" in captured.out


def test_main_focus_tests_runs_selected_group(monkeypatch):
    called: dict[str, list[str]] = {}

    def _fake_run(cmd, check=False):
        called["cmd"] = list(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(focus_tests_module.subprocess, "run", _fake_run)
    monkeypatch.setattr(quality_loop_module.subprocess, "run", _fake_run)
    monkeypatch.setattr(sys, "argv", ["shigoku", "--focus-tests", "--focus-group", "density"])

    main_module.main()

    cmd = called.get("cmd", [])
    assert cmd[:3] == [sys.executable, "-m", "pytest"]
    assert "-q" in cmd
    assert "tests/core/engine/test_attack_planner_scope_filter.py" in cmd
    assert "tests/unit/agents/swarm/test_fuzzing.py" in cmd


def test_main_focus_tests_exits_nonzero_on_failure(monkeypatch):
    called: dict[str, list[str]] = {}

    def _fake_run(cmd, check=False):
        called["cmd"] = list(cmd)
        return SimpleNamespace(returncode=2)

    monkeypatch.setattr(focus_tests_module.subprocess, "run", _fake_run)
    monkeypatch.setattr(quality_loop_module.subprocess, "run", _fake_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "shigoku",
            "--focus-tests",
            "--focus-group",
            "report",
            "--focus-fail-fast",
        ],
    )

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 2
    cmd = called.get("cmd", [])
    assert "-x" in cmd
    assert "tests/unit/reporting/test_report_session_consistency.py" in cmd


def test_main_quality_loop_short_runs_focus_then_short_attack(monkeypatch):
    calls: list[list[str]] = []

    def _fake_run(cmd, check=False):
        calls.append(list(cmd))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(focus_tests_module.subprocess, "run", _fake_run)
    monkeypatch.setattr(quality_loop_module.subprocess, "run", _fake_run)
    monkeypatch.setattr(main_module, "write_quality_loop_precheck_artifact", lambda **_kwargs: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "shigoku",
            "--quality-loop",
            "short",
            "--target",
            "http://example.com",
        ],
    )

    main_module.main()

    assert len(calls) == 2
    assert calls[0][:3] == [sys.executable, "-m", "pytest"]
    short_cmd = calls[1]
    assert short_cmd[:3] == [sys.executable, "-m", "src.main"]
    assert "--target" in short_cmd
    assert "http://example.com" in short_cmd
    assert "--skip-initial-recon" in short_cmd
    assert "--recon-start-step" in short_cmd
    assert "--recon-end-step" in short_cmd


def test_main_quality_loop_with_full_scan_runs_third_command(monkeypatch):
    calls: list[list[str]] = []

    def _fake_run(cmd, check=False):
        calls.append(list(cmd))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(focus_tests_module.subprocess, "run", _fake_run)
    monkeypatch.setattr(quality_loop_module.subprocess, "run", _fake_run)
    monkeypatch.setattr(main_module, "write_quality_loop_precheck_artifact", lambda **_kwargs: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "shigoku",
            "--quality-loop",
            "short",
            "--quality-loop-full-scan",
            "--target",
            "http://example.com",
        ],
    )

    main_module.main()

    assert len(calls) == 3
    short_cmd = calls[1]
    full_cmd = calls[2]
    assert "--skip-initial-recon" in short_cmd
    assert "--skip-initial-recon" not in full_cmd
    assert full_cmd[:3] == [sys.executable, "-m", "src.main"]
    assert "--target" in full_cmd


def test_main_quality_loop_exits_when_precheck_fails(monkeypatch):
    calls: list[list[str]] = []

    def _fake_run(cmd, check=False):
        calls.append(list(cmd))
        if len(calls) == 1:
            return SimpleNamespace(returncode=3)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(focus_tests_module.subprocess, "run", _fake_run)
    monkeypatch.setattr(quality_loop_module.subprocess, "run", _fake_run)
    monkeypatch.setattr(main_module, "write_quality_loop_precheck_artifact", lambda **_kwargs: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "shigoku",
            "--quality-loop",
            "short",
            "--target",
            "http://example.com",
        ],
    )

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 3
    assert len(calls) == 1


def test_main_quality_loop_continues_when_precheck_tests_are_unavailable(monkeypatch):
    calls: list[list[str]] = []

    def _fake_run(cmd, check=False):
        calls.append(list(cmd))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(focus_tests_module.subprocess, "run", _fake_run)
    monkeypatch.setattr(quality_loop_module.subprocess, "run", _fake_run)
    monkeypatch.setattr(
        quality_loop_module,
        "run_focused_tests",
        lambda **_kwargs: (2, ["density", "report"], [], []),
    )
    monkeypatch.setattr(main_module, "write_quality_loop_precheck_artifact", lambda **_kwargs: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "shigoku",
            "--quality-loop",
            "short",
            "--target",
            "http://example.com",
        ],
    )

    main_module.main()

    assert len(calls) == 1
    short_cmd = calls[0]
    assert short_cmd[:3] == [sys.executable, "-m", "src.main"]
    assert "--skip-initial-recon" in short_cmd


def test_main_focus_tests_resolves_repo_root_paths_when_cwd_differs(monkeypatch, tmp_path):
    called: dict[str, list[str]] = {}

    def _fake_run(cmd, check=False):
        called["cmd"] = list(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(focus_tests_module.subprocess, "run", _fake_run)
    monkeypatch.setattr(quality_loop_module.subprocess, "run", _fake_run)
    monkeypatch.setattr(sys, "argv", ["shigoku", "--focus-tests", "--focus-group", "density"])

    main_module.main()

    cmd = called.get("cmd", [])
    from src.cli.handlers._shared import REPO_ROOT
    repo_root = Path(REPO_ROOT)
    expected_test = str(repo_root / "tests/core/engine/test_attack_planner_scope_filter.py")
    assert expected_test in cmd
