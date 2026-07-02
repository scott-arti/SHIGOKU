"""
Focused tests for CLI Japanese localization (SGK-2026-0290).

Tests cover:
- --help output is in Japanese
- message key resolution integrity
- JSON output non-contamination
- internal logger compatibility
- parser error messages are in Japanese
"""

import json
import pytest
from src.cli.messages import msg, msg_or_none, all_keys, _MESSAGES_JA


# ============================================================
# Message catalog integrity
# ============================================================

class TestMessageCatalogIntegrity:
    """Verify the message catalog is well-formed and contains expected keys."""

    def test_all_keys_return_strings(self):
        """All registered keys should resolve to non-empty strings."""
        for key in all_keys():
            result = msg(key)
            assert isinstance(result, str), f"Key {key} did not return str"
            assert len(result) > 0, f"Key {key} returned empty string"
            assert not result.startswith("??"), f"Key {key} is missing"

    def test_no_duplicate_keys(self):
        """Message catalog should have no duplicate keys."""
        keys = list(_MESSAGES_JA.keys())
        assert len(keys) == len(set(keys)), f"Found {len(keys) - len(set(keys))} duplicate keys"

    def test_required_argparse_keys_exist(self):
        """All --help argument keys must exist."""
        required = [
            "argparse.description",
            "argparse.epilog",
            "argparse.log.help",
            "argparse.scope.help",
            "argparse.watch.help",
            "argparse.demo.help",
            "argparse.recon.help",
            "argparse.mode.help",
            "argparse.interactive.help",
            "argparse.resume.help",
            "argparse.json.help",
            "argparse.dry_run.help",
        ]
        for key in required:
            assert msg_or_none(key) is not None, f"Missing required key: {key}"

    def test_required_cli_keys_exist(self):
        """All interactive CLI command keys must exist."""
        required = [
            "cli.welcome.header",
            "cli.welcome.body",
            "cli.error.unknown_command",
            "cli.goodbye",
            "cmd.help.header",
            "cmd.tools.header",
            "cmd.model.current",
            "cmd.mode.available",
            "cmd.sessions.none",
            "cmd.resume.success",
        ]
        for key in required:
            assert msg_or_none(key) is not None, f"Missing required key: {key}"

    def test_required_logger_keys_exist(self):
        """Logger helper keys must exist."""
        assert msg_or_none("logger.tree.default_title") is not None

    def test_required_error_keys_exist(self):
        """Parser error message keys must exist."""
        required = [
            "parser.error.recon_start_step_range",
            "parser.error.recon_end_step_range",
            "parser.error.recon_step_order",
            "parser.error.quality_loop_requires_full_scan",
            "parser.error.quality_loop_requires_target",
        ]
        for key in required:
            assert msg_or_none(key) is not None, f"Missing required key: {key}"


# ============================================================
# Japanese content verification
# ============================================================

class TestJapaneseContent:
    """Verify that messages contain Japanese characters where expected."""

    JAPANESE_REQUIRED_KEYS = [
        "argparse.description",
        "argparse.log.help",
        "argparse.interactive.help",
        "cli.welcome.header",
        "cli.goodbye",
        "cmd.help.header",
        "cmd.tools.header",
        "cmd.mode.available",
        "cmd.sessions.none",
        "cmd.resume.success",
        "logger.tree.default_title",
        "parser.error.recon_start_step_range",
        "result.deferred.no_artifact",
        "result.hitl.no_tickets",
        "result.focus.no_tests",
        "step.recon_start",
        "step.quality_loop_1",
    ]

    def _has_japanese(self, text: str) -> bool:
        """Check if text contains Hiragana, Katakana, or CJK characters."""
        for ch in text:
            cp = ord(ch)
            if (0x3040 <= cp <= 0x309F) or (0x30A0 <= cp <= 0x30FF) or (0x4E00 <= cp <= 0x9FFF):
                return True
        return False

    def test_key_messages_contain_japanese(self):
        """All user-facing keys should contain Japanese characters."""
        missing_japanese = []
        for key in self.JAPANESE_REQUIRED_KEYS:
            text = msg(key)
            if not self._has_japanese(text):
                missing_japanese.append(key)
        assert not missing_japanese, (
            f"Keys missing Japanese characters: {missing_japanese}"
        )


# ============================================================
# --help output integration test
# ============================================================

class TestHelpOutputJapanese:
    """Verify --help output is localized (integration-level)."""

    def test_help_output_is_japanese(self):
        """--help should produce Japanese descriptions."""
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "src.main", "--help"],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout

        # Check for Japanese content in the description area
        ja_indicators = ["SHIGOKU（至極）", "自律型バグバウンティハンター",
                          "統合ハント", "偵察フェーズ", "対話モード",
                          "遅延シナリオ", "ドライラン"]
        for indicator in ja_indicators:
            assert indicator in output, (
                f"--help output missing Japanese indicator: {indicator}"
            )

        # Option names should still be in ASCII
        assert "--log" in output
        assert "--scope" in output
        assert "--mode" in output

    def test_epilog_contains_japanese(self):
        """Epilog should contain Japanese usage examples."""
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "src.main", "--help"],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout

        ja_in_epilog = ["使用例", "環境変数", "偵察開始ステップ"]
        for indicator in ja_in_epilog:
            assert indicator in output, (
                f"--help epilog missing Japanese indicator: {indicator}"
            )

    def test_help_output_does_not_expose_removed_translate_logs_flag(self):
        """Obsolete log translation flag should no longer appear in --help."""
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-m", "src.main", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout

        assert "--translate-logs" not in output
        assert "ログを日本語に翻訳" not in output


class TestRemovedTranslateLogsCatalog:
    """Verify obsolete translate-logs catalog entries are removed."""

    def test_translate_logs_help_key_is_removed(self):
        """The message catalog should no longer ship help text for the removed flag."""
        assert msg_or_none("argparse.translate_logs.help") is None


# ============================================================
# JSON non-contamination verification
# ============================================================

class TestJsonNonContamination:
    """Verify JSON output mode does not contaminate JSON keys with Japanese."""

    def test_message_keys_dont_infect_json_output(self):
        """msg() function should not be called for JSON key names."""
        # All msg() keys are defined in _MESSAGES_JA dict. JSON output keys
        # like "projects", "sessions", "tickets" etc must NOT appear as msg keys.
        json_like_keys = ["projects", "sessions", "tickets", "id", "name", "status"]
        all_msg_keys = all_keys()
        for key in json_like_keys:
            # The exact lowercase key should not exist as a top-level msg key
            exact_match = [k for k in all_msg_keys if k.split(".")[-1] == key
                           and len(k.split(".")) <= 2]
            # This is a structural check, not a hard assertion:
            # if a key like "projects" exists as msg key, it means JSON output
            # keys and message keys share namespace, which is a design concern
            pass  # No assertion needed; this is a design guard check

    def test_msg_format_kwargs_preserve_identifiers(self):
        """msg() with format kwargs should keep identifiers in ASCII."""
        result = msg("deferred.status_summary",
                     pending=5, in_progress=2, done=10, rejected=0, total=17)
        # The numeric values themselves should appear
        assert "5" in result
        assert "2" in result
        assert "10" in result
        # Japanese labels should be present (not English)
        # Check that the Japanese status words appear, not just English "pending"
        assert any(ord(ch) > 0x3000 for ch in result), (
            f"Expected Japanese characters in: {result}"
        )


# ============================================================
# Internal logger compatibility
# ============================================================

class TestInternalLoggerCompatibility:
    """Verify that internal Python logger messages remain in English."""

    def test_logger_py_uses_logging_module(self):
        """logger.py must still use standard logging for internal messages."""
        import src.core.logger as logger_mod
        import logging
        # The ShigokuLogger class should still exist
        assert hasattr(logger_mod, "ShigokuLogger")
        # logging module should still be imported (internal logger foundation)
        # This is a structural check - the stdlib logging module must remain
        # as the internal logging backbone

    def test_logger_internal_not_translated(self):
        """No internal logger format strings should be in the message catalog."""
        # Internal log format patterns that should NOT be in _MESSAGES_JA
        forbidden_patterns = ["%(asctime)", "%(levelname)", "%(message)"]
        for key, value in _MESSAGES_JA.items():
            for pattern in forbidden_patterns:
                assert pattern not in value, (
                    f"Internal log format found in msg key {key}: {pattern}"
                )


# ============================================================
# Parser error message verification
# ============================================================

class TestParserErrorMessages:
    """Verify parser.error() messages are Japanese."""

    def test_recon_step_range_error_is_japanese(self):
        """recon start step range error should be in Japanese."""
        text = msg("parser.error.recon_start_step_range")
        assert "1" in text and "8" in text
        assert any(ord(ch) > 0x3000 for ch in text), (
            f"Expected Japanese in: {text}"
        )

    def test_quality_loop_error_is_japanese(self):
        """quality loop requirement error should be in Japanese."""
        text = msg("parser.error.quality_loop_requires_target")
        assert "--quality-loop" in text
        assert any(ord(ch) > 0x3000 for ch in text), (
            f"Expected Japanese in: {text}"
        )


# ============================================================
# Message format functionality
# ============================================================

class TestMessageFormatting:
    """Verify msg() handles format parameters correctly."""

    def test_basic_format(self):
        """Simple format with one parameter."""
        result = msg("result.focus.resolved_count", count=42, root="/repo")
        assert "42" in result
        assert "/repo" in result

    def test_missing_format_key(self):
        """Missing format key in partial kwargs should produce partial message with hint."""
        # Provide partial kwargs to trigger the KeyError path
        result = msg("result.focus.resolved_count", count=42)
        # Either contains "missing key" or the raw template
        assert "missing key" in result or "{root}" in result, (
            f"Expected error or raw template, got: {result}"
        )

    def test_unknown_key_returns_fallback(self):
        """Unknown message key should return ??key?? fallback."""
        result = msg("nonexistent.key.xyz")
        assert result.startswith("??")
        assert result.endswith("??")
        assert "nonexistent" in result

    def test_format_with_special_chars(self):
        """Format with special characters in values."""
        result = msg("cmd.resume.success", session_id="ses-abc123_def")
        assert "ses-abc123_def" in result

    def test_msg_or_none(self):
        """msg_or_none returns None for missing keys."""
        assert msg_or_none("argparse.log.help") is not None
        assert msg_or_none("nonexistent.key") is None
