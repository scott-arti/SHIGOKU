from __future__ import annotations

import json
import importlib.util
from pathlib import Path


def _load_target():
    script_path = Path(__file__).resolve().parents[3] / "scripts" / "check_runtime_control_required_check.py"
    spec = importlib.util.spec_from_file_location("check_runtime_control_required_check", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


target = _load_target()


def _write_pr_event(path: Path, *, base_ref: str = "main") -> None:
    payload = {"pull_request": {"base": {"ref": base_ref}}}
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_parse_required_contexts_prefers_cli(monkeypatch) -> None:
    monkeypatch.setenv("SHIGOKU_RUNTIME_CONTROL_REQUIRED_CHECKS", "a,b")
    assert target._parse_required_contexts(["x", "y"]) == ["x", "y"]


def test_parse_required_contexts_from_env(monkeypatch) -> None:
    monkeypatch.setenv("SHIGOKU_RUNTIME_CONTROL_REQUIRED_CHECKS", "alpha,beta")
    assert target._parse_required_contexts(None) == ["alpha", "beta"]


def test_parse_required_contexts_default(monkeypatch) -> None:
    monkeypatch.delenv("SHIGOKU_RUNTIME_CONTROL_REQUIRED_CHECKS", raising=False)
    assert target._parse_required_contexts(None) == ["runtime-control-governance"]


def test_main_fails_with_runbook_url_when_required_context_missing(tmp_path: Path, monkeypatch, capsys) -> None:
    event_path = tmp_path / "event.json"
    _write_pr_event(event_path, base_ref="main")
    monkeypatch.setenv("GITHUB_TOKEN", "dummy-token")

    def fake_api_get(url: str, token: str):  # noqa: ARG001
        return {"required_status_checks": {"contexts": ["other-check"]}}

    monkeypatch.setattr(target, "_api_get", fake_api_get)
    monkeypatch.setattr(
        "sys.argv",
        [
            "check_runtime_control_required_check.py",
            "--event-path",
            str(event_path),
            "--repo",
            "org/repo",
            "--required-context",
            "runtime-control-governance",
            "--runbook-url",
            "https://example.com/runbook",
        ],
    )

    rc = target.main()
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 3
    assert payload["status"] == "fail"
    assert payload["runbook_url"] == "https://example.com/runbook"
    assert "runtime-control-governance" in payload["missing_contexts"]


def test_main_passes_when_required_context_present(tmp_path: Path, monkeypatch, capsys) -> None:
    event_path = tmp_path / "event.json"
    _write_pr_event(event_path, base_ref="main")
    monkeypatch.setenv("GITHUB_TOKEN", "dummy-token")

    def fake_api_get(url: str, token: str):  # noqa: ARG001
        return {"required_status_checks": {"contexts": ["runtime-control-governance"]}}

    monkeypatch.setattr(target, "_api_get", fake_api_get)
    monkeypatch.setattr(
        "sys.argv",
        [
            "check_runtime_control_required_check.py",
            "--event-path",
            str(event_path),
            "--repo",
            "org/repo",
        ],
    )

    rc = target.main()
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 0
    assert payload["status"] == "pass"
    assert "runtime-control-governance" in payload["required_contexts"]
