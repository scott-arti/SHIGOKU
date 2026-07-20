"""Tests for recon logger Japanese localization (SGK-2026-0344)."""
import logging

from src.core.logging.recon_log_setup import (
    JapaneseConsoleFormatter,
    FileLogFormatter,
    setup_recon_logging,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_log_record(msg, logger_name="src.recon.pipeline", level=logging.INFO,
                     args=None):
    """Create a minimal LogRecord suitable for formatter tests."""
    record = logging.LogRecord(
        logger_name, level, "/fake/path.py", 42,
        msg, args or (), None
    )
    return record


# ===================================================================
# JapaneseConsoleFormatter
# ===================================================================

class TestJapaneseConsoleFormatter:
    """Unit tests for JapaneseConsoleFormatter."""

    def test_executing_translated(self):
        """'Executing: ... (timeout=Ns)' becomes Japanese."""
        formatter = JapaneseConsoleFormatter()
        record = _make_log_record("Executing: /usr/bin/httpx (timeout=30s)")
        result = formatter.format(record)
        # Japanese output should contain 「実行中」(executing)
        assert "実行" in result, f"Expected Japanese for 'executing', got: {result}"
        assert "httpx" in result  # tool name preserved
        assert "30" in result     # timeout value preserved

    def test_httpx_found_translated(self):
        """'httpx found N live subdomains' becomes Japanese."""
        formatter = JapaneseConsoleFormatter()
        record = _make_log_record("httpx found 12 live subdomains")
        result = formatter.format(record)
        # Should contain Japanese for "found" and "live"
        assert any(kw in result for kw in ["検出", "発見", "見つかり"]), \
            f"Expected Japanese for 'found', got: {result}"
        assert "httpx" in result
        assert "12" in result

    def test_whatweb_not_found_translated(self):
        """'whatweb not found, skipping' becomes Japanese."""
        formatter = JapaneseConsoleFormatter()
        record = _make_log_record("whatweb not found, skipping")
        result = formatter.format(record)
        assert "スキップ" in result or "skip" not in result.lower(), \
            f"Expected Japanese for 'skipping', got: {result}"
        assert "whatweb" in result

    def test_step_started_translated(self):
        """'[Step N] ... started' becomes Japanese."""
        formatter = JapaneseConsoleFormatter()
        record = _make_log_record("[Step 2] url_discovery started")
        result = formatter.format(record)
        # Should contain Japanese for step/start
        assert any(kw in result for kw in ["ステップ", "工程", "開始"]), \
            f"Expected Japanese for step/started, got: {result}"
        assert "2" in result

    def test_step_completed_translated(self):
        """'[Step N] ... completed: ...' becomes Japanese."""
        formatter = JapaneseConsoleFormatter()
        record = _make_log_record("[Step 2] url_discovery completed: 450 URLs found")
        result = formatter.format(record)
        assert any(kw in result for kw in ["完了", "終了", "終わり"]), \
            f"Expected Japanese for 'completed', got: {result}"
        assert "450" in result

    def test_unknown_message_preserved(self):
        """Unknown messages remain in English (redacted only)."""
        formatter = JapaneseConsoleFormatter()
        original = "Some custom log message with no known pattern"
        record = _make_log_record(original)
        result = formatter.format(record)
        # The original English text should still be present for unmatched messages
        assert "custom log message" in result

    def test_redaction_applied_before_translation(self):
        """Secrets are redacted before Japanese translation."""
        formatter = JapaneseConsoleFormatter()
        record = _make_log_record(
            "Executing: /usr/bin/httpx -H 'Cookie: PHPSESSID=16de57463925e1d6a8f8f4c3b7a9d2e1'"
        )
        result = formatter.format(record)
        # The cookie value must not appear in the formatted output
        assert "16de57463925e1d6a8f8f4c3b7a9d2e1" not in result
        # Should still have Japanese translation
        assert "httpx" in result


# ===================================================================
# FileLogFormatter
# ===================================================================

class TestFileLogFormatter:
    """Unit tests for FileLogFormatter."""

    def test_preserves_english(self):
        """File log preserves English text (not Japanese)."""
        formatter = FileLogFormatter()
        record = _make_log_record("Executing: /usr/bin/httpx (timeout=30s)")
        result = formatter.format(record)
        assert "Executing:" in result
        assert "httpx" in result
        # File log should NOT contain Japanese (unlike console)
        assert "実行" not in result, f"File log should not contain Japanese: {result}"

    def test_includes_logger_name(self):
        """File log includes logger name."""
        formatter = FileLogFormatter()
        record = _make_log_record("test message", logger_name="src.recon.tool_runner")
        result = formatter.format(record)
        assert "src.recon.tool_runner" in result

    def test_includes_level(self):
        """File log includes log level."""
        formatter = FileLogFormatter()
        for level in [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR]:
            record = _make_log_record("test message", level=level)
            result = formatter.format(record)
            assert logging.getLevelName(level) in result, \
                f"Level {level} not in: {result}"

    def test_includes_numbers(self):
        """File log preserves numbers (counts)."""
        formatter = FileLogFormatter()
        record = _make_log_record("httpx found 42 live subdomains")
        result = formatter.format(record)
        assert "42" in result

    def test_includes_paths(self):
        """File log preserves file paths."""
        formatter = FileLogFormatter()
        record = _make_log_record("Loaded wordlist from /usr/share/wordlists/common.txt")
        result = formatter.format(record)
        assert "/usr/share/wordlists/common.txt" in result

    def test_redacts_secrets(self):
        """File log redacts secrets even though English is preserved."""
        formatter = FileLogFormatter()
        record = _make_log_record(
            "httpx -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNw2D5H0HqN2qP7Yt'"
        )
        result = formatter.format(record)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result


# ===================================================================
# setup_recon_logging
# ===================================================================

class TestReconLogSetup:
    """Unit tests for recon log setup function."""

    def test_setup_adds_handlers(self):
        """After setup, src.recon.* logger has handlers configured."""
        logger = logging.getLogger("src.recon.pipeline")
        # Remove any existing handlers for a clean test
        logger.handlers.clear()
        assert len(logger.handlers) == 0

        setup_recon_logging()
        assert len(logger.handlers) > 0, "setup_recon_logging should add handlers"

    def test_console_handler_uses_japanese_formatter(self):
        """Console handler uses JapaneseConsoleFormatter."""
        logger = logging.getLogger("src.recon.tool_runner")
        logger.handlers.clear()

        setup_recon_logging()

        console_handler = None
        for h in logger.handlers:
            if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
                console_handler = h
                break

        assert console_handler is not None, "Console handler not found"
        assert isinstance(console_handler.formatter, JapaneseConsoleFormatter), \
            f"Expected JapaneseConsoleFormatter, got {type(console_handler.formatter)}"

    def test_file_handler_uses_file_formatter(self):
        """File handler uses FileLogFormatter (or equivalent)."""
        logger = logging.getLogger("src.recon.tool_runner")
        logger.handlers.clear()

        setup_recon_logging()

        file_handler = None
        for h in logger.handlers:
            if isinstance(h, logging.FileHandler):
                file_handler = h
                break

        assert file_handler is not None, "File handler not found"
        assert isinstance(file_handler.formatter, FileLogFormatter), \
            f"Expected FileLogFormatter, got {type(file_handler.formatter)}"

    def test_no_duplicate_handlers(self):
        """Calling setup twice doesn't add duplicate handlers."""
        logger = logging.getLogger("src.recon.pipeline")
        logger.handlers.clear()

        setup_recon_logging()
        first_count = len(logger.handlers)
        assert first_count > 0

        setup_recon_logging()
        second_count = len(logger.handlers)
        assert second_count == first_count, \
            f"Handler count changed: {first_count} -> {second_count}"
