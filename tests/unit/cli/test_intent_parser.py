from __future__ import annotations

from src.cli.intent_parser import (
    OpsIntentSettings,
    parse_operator_intent,
)
from src.core.models.ops_artifacts import IntentCommand


def test_parse_operator_intent_recognizes_recon_resume_step() -> None:
    parsed = parse_operator_intent(
        "1回目の step3 から再開して",
        target="https://example.com",
        settings=OpsIntentSettings(),
    )

    assert parsed.status == "ok"
    assert parsed.command == IntentCommand.MAIN_RECON_RESUME
    assert parsed.recon_start_step == 3
    assert parsed.target == "https://example.com"
    assert "intent_recon_resume" in parsed.reason_codes


def test_parse_operator_intent_recognizes_attack_from_report_context() -> None:
    parsed = parse_operator_intent(
        "このレポートから API だけ Fuzz して",
        report_path="/tmp/haddix_report_20260721_120000.md",
        target="https://example.com",
        wordlist_path="/tmp/words.txt",
        settings=OpsIntentSettings(),
    )

    assert parsed.status == "ok"
    assert parsed.command == IntentCommand.MAIN_ATTACK_TARGETS
    assert parsed.report_path == "/tmp/haddix_report_20260721_120000.md"
    assert parsed.wordlist_path == "/tmp/words.txt"
    assert parsed.requires_confirmation is True
    assert "intent_attack_targets" in parsed.reason_codes


def test_parse_operator_intent_rejects_unknown_command() -> None:
    parsed = parse_operator_intent(
        "今日は雑談だけしたい",
        settings=OpsIntentSettings(),
    )

    assert parsed.status == "blocked"
    assert parsed.command is None
    assert "intent_unresolved" in parsed.reason_codes
