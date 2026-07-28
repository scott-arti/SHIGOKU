from __future__ import annotations

import argparse
import builtins
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import scripts.shigoku_ops_cli as ops_cli

from src.cli.intent_parser import ExecutionPreview, OperatorIntent, PreviewStep, OpsIntentSettings
from src.core.models.ops_artifacts import IntentCommand


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _write_session_with_tagged_file(session_file: Path, tagged_file: Path) -> None:
    tagged_file.parent.mkdir(parents=True, exist_ok=True)
    tagged_file.write_text(
        json.dumps(
            {
                "url": "http://127.0.0.1:8888/chatbot/genai/state",
                "method": "GET",
                "tags": ["api_endpoint", "has_params"],
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    payload = {
        "completed_tasks": [
            {
                "id": "task_002",
                "result": {
                    "data": {
                        "results": {
                            "tagged_api_data": {
                                "file": str(tagged_file),
                                "count": 1,
                                "description": "Tagged URLs (api_data)",
                                "tags": ["api_endpoint", "has_params"],
                            }
                        }
                    }
                },
            }
        ]
    }
    session_file.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _write_report(path: Path, *, source_session: str) -> None:
    lines = [
        "# Vulnerability Report",
        "",
        "**Target:** http://127.0.0.1:8888/",
        "**Generated:** 2026-07-21 12:01:00",
        f"**Source Session:** {source_session}",
        "**Tool:** SHIGOKU - Sovereign VAPT Engine",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def test_ops_cli_intent_preview_builds_attack_flow_from_report(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260721_120000.json"
    tagged_file = tmp_path / "tagged_urls" / "tagged_api_data.jsonl"
    report_file = tmp_path / "haddix_report_20260721_120100.md"
    _write_session_with_tagged_file(session_file, tagged_file)
    _write_report(report_file, source_session=str(session_file.resolve()))

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "ops",
            "intent",
            "--intent",
            "このレポートから API だけ Fuzz して",
            "--report",
            str(report_file),
            "--target",
            "http://127.0.0.1:8888",
            "--wordlist",
            "/tmp/custom-wordlist.txt",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "preview"
    assert payload["translated"]["command"] == "main.attack-targets"
    assert payload["translated"]["requires_confirmation"] is True
    assert payload["preview_steps"][0]["intent_command"] == "report.export-targets"
    assert "--report" in payload["preview_steps"][0]["command"]
    assert payload["preview_steps"][1]["intent_command"] == "main.attack-targets"
    assert "--attack-targets" in payload["preview_steps"][1]["command"]
    assert "--wordlist" in payload["preview_steps"][1]["command"]


def test_ops_cli_intent_execute_attack_non_tty_requires_explicit_approval(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260721_120000.json"
    tagged_file = tmp_path / "tagged_urls" / "tagged_api_data.jsonl"
    report_file = tmp_path / "haddix_report_20260721_120100.md"
    _write_session_with_tagged_file(session_file, tagged_file)
    _write_report(report_file, source_session=str(session_file.resolve()))

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "ops",
            "intent",
            "--intent",
            "このレポートから API だけ Fuzz して",
            "--report",
            str(report_file),
            "--target",
            "http://127.0.0.1:8888",
            "--execute",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert "approval_required_non_tty" in payload["reason_codes"]


def test_ops_cli_intent_execute_attack_with_main_dry_run(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260721_120000.json"
    tagged_file = tmp_path / "tagged_urls" / "tagged_api_data.jsonl"
    report_file = tmp_path / "haddix_report_20260721_120100.md"
    _write_session_with_tagged_file(session_file, tagged_file)
    _write_report(report_file, source_session=str(session_file.resolve()))

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "ops",
            "intent",
            "--intent",
            "このレポートから API だけ Fuzz して",
            "--report",
            str(report_file),
            "--target",
            "http://127.0.0.1:8888",
            "--execute",
            "--approve",
            "--main-dry-run",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert len(payload["executed_steps"]) == 2
    assert payload["executed_steps"][1]["intent_command"] == "main.attack-targets"
    assert "--dry-run" in payload["executed_steps"][1]["command"]
    assert payload["executed_steps"][1]["returncode"] == 0


def _handler_args(**overrides) -> argparse.Namespace:
    payload = {
        "json": False,
        "json_envelope": False,
        "domain": "ops",
        "action": "intent",
        "intent": "step3 から再開して",
        "target": "https://example.com",
        "report": None,
        "session": None,
        "sessions_dir": None,
        "attack_targets": None,
        "wordlist": None,
        "mode": "bugbounty",
        "output_dir": None,
        "python": None,
        "ttl_days": 7,
        "max_records": 25,
        "main_dry_run": False,
        "execute": True,
        "approve": False,
    }
    payload.update(overrides)
    return argparse.Namespace(**payload)


def _translated_resume_intent() -> OperatorIntent:
    return OperatorIntent(
        status="ok",
        correlation_id="ops-test123456",
        intent_hash="deadbeef",
        raw_intent="step3 から再開して",
        command=IntentCommand.MAIN_RECON_RESUME,
        target="https://example.com",
        recon_start_step=3,
        requires_confirmation=True,
        reason_codes=["intent_recon_resume"],
    )


def _resume_preview(*, requires_confirmation: bool = True) -> ExecutionPreview:
    return ExecutionPreview(
        status="ok",
        steps=[
            PreviewStep(
                intent_command=IntentCommand.MAIN_RECON_RESUME.value,
                description="Resume recon from the requested step.",
                command=["python3", "-m", "src.main", "--recon", "https://example.com"],
                requires_confirmation=requires_confirmation,
                mutating=True,
            )
        ],
    )


def test_run_ops_intent_blocks_when_kill_switch_enabled(monkeypatch) -> None:
    emitted: dict[str, object] = {}
    monkeypatch.setattr(
        ops_cli,
        "load_ops_intent_settings",
        lambda: OpsIntentSettings(kill_switch=True),
    )
    monkeypatch.setattr(ops_cli, "parse_operator_intent", lambda *_args, **_kwargs: _translated_resume_intent())
    monkeypatch.setattr(ops_cli, "build_execution_preview", lambda *_args, **_kwargs: _resume_preview())
    monkeypatch.setattr(ops_cli, "_emit_command_payload", lambda _args, payload: emitted.setdefault("payload", payload))

    result = ops_cli._run_ops_intent(_handler_args(approve=True))

    assert result == 2
    payload = emitted["payload"]
    assert isinstance(payload, dict)
    assert payload["status"] == "blocked"
    assert "ops_intent_kill_switch" in payload["reason_codes"]


def test_run_ops_intent_returns_approval_denied_when_operator_rejects(monkeypatch) -> None:
    emitted: dict[str, object] = {}
    monkeypatch.setattr(
        ops_cli,
        "load_ops_intent_settings",
        lambda: OpsIntentSettings(),
    )
    monkeypatch.setattr(ops_cli, "parse_operator_intent", lambda *_args, **_kwargs: _translated_resume_intent())
    monkeypatch.setattr(ops_cli, "build_execution_preview", lambda *_args, **_kwargs: _resume_preview())
    monkeypatch.setattr(ops_cli, "_emit_command_payload", lambda _args, payload: emitted.setdefault("payload", payload))
    monkeypatch.setattr(builtins, "input", lambda _prompt: "n")
    monkeypatch.setattr(ops_cli.sys, "stdin", SimpleNamespace(isatty=lambda: True))

    result = ops_cli._run_ops_intent(_handler_args())

    assert result == 2
    payload = emitted["payload"]
    assert isinstance(payload, dict)
    assert payload["status"] == "blocked"
    assert "approval_denied" in payload["reason_codes"]


def test_run_ops_intent_returns_command_timeout(monkeypatch) -> None:
    emitted: dict[str, object] = {}
    monkeypatch.setattr(
        ops_cli,
        "load_ops_intent_settings",
        lambda: OpsIntentSettings(command_timeout_sec=1),
    )
    monkeypatch.setattr(ops_cli, "parse_operator_intent", lambda *_args, **_kwargs: _translated_resume_intent())
    monkeypatch.setattr(
        ops_cli,
        "build_execution_preview",
        lambda *_args, **_kwargs: _resume_preview(requires_confirmation=False),
    )
    monkeypatch.setattr(ops_cli, "_emit_command_payload", lambda _args, payload: emitted.setdefault("payload", payload))

    def _raise_timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["python3", "-m", "src.main"], timeout=1)

    monkeypatch.setattr(ops_cli.subprocess, "run", _raise_timeout)

    result = ops_cli._run_ops_intent(_handler_args(approve=True))

    assert result == 3
    payload = emitted["payload"]
    assert isinstance(payload, dict)
    assert payload["status"] == "blocked"
    assert "command_timeout" in payload["reason_codes"]


def test_ops_cli_intent_blocks_malformed_intent(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260721_120000.json"
    tagged_file = tmp_path / "tagged_urls" / "tagged_api_data.jsonl"
    report_file = tmp_path / "haddix_report_20260721_120100.md"
    _write_session_with_tagged_file(session_file, tagged_file)
    _write_report(report_file, source_session=str(session_file.resolve()))

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "ops",
            "intent",
            "--intent",
            "!!!! ??? broken-intent",
            "--report",
            str(report_file),
            "--target",
            "http://127.0.0.1:8888",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert "intent_unresolved" in payload["reason_codes"]
