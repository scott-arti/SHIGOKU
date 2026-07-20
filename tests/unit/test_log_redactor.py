"""Tests for log redaction helper (SGK-2026-0344)."""
import logging

from src.core.logging.log_redactor import LogRedactor, RedactionFilter, redact_log_value


# ---------------------------------------------------------------------------
# Shared test data (realistic secret examples)
# ---------------------------------------------------------------------------

COOKIE_VALUE = "PHPSESSID=16de57463925e1d6a8f8f4c3b7a9d2e1; security=low"
BEARER_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNw2D5H0HqN2qP7Yt"
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNw2D5H0HqN2qP7YtE8f9g"
API_KEY = "X-Api-Key: abc123def456ghi789jkl"
CLI_COOKIE_CMD = ['/usr/bin/httpx', '-H', 'Cookie: PHPSESSID=16de57463925e1d6a8f8f4c3b7a9d2e1']
REDACTION_MARKER = "[REDACTED]"


# ===================================================================
# LogRedactor
# ===================================================================

class TestLogRedactor:
    """Unit tests for LogRedactor – one-way redaction of secrets in log values."""

    def test_redact_cookie_header(self):
        """Cookie header values are redacted."""
        input_str = f"Cookie: {COOKIE_VALUE}"
        result = redact_log_value(input_str)
        assert COOKIE_VALUE not in result
        # The function may return a shorter marker or keep non-secret prefix
        assert len(result) < len(input_str) or REDACTION_MARKER in result

    def test_redact_bearer_token(self):
        """Authorization: Bearer tokens are redacted."""
        input_str = f"Authorization: {BEARER_TOKEN}"
        result = redact_log_value(input_str)
        assert BEARER_TOKEN not in result
        assert "Bearer" in result.lower() or REDACTION_MARKER in result

    def test_redact_jwt_standalone(self):
        """Standalone JWT tokens are redacted."""
        result = redact_log_value(JWT_TOKEN)
        assert JWT_TOKEN not in result
        # The JWT is at least 20 chars – redacted output should differ materially
        assert len(result) < len(JWT_TOKEN) or REDACTION_MARKER in result

    def test_redact_api_key_header(self):
        """X-Api-Key header values are redacted."""
        result = redact_log_value(API_KEY)
        assert "abc123def456ghi789jkl" not in result
        assert REDACTION_MARKER in result or "***" in result

    def test_redact_cli_arg_cookie(self):
        """CLI argument '-H Cookie: ...' is redacted."""
        input_str = "-H Cookie: PHPSESSID=16de57463925e1d6a8f8f4c3b7a9d2e1"
        result = redact_log_value(input_str)
        assert "16de57463925e1d6a8f8f4c3b7a9d2e1" not in result

    def test_redact_password_key(self):
        """'password=value' in strings is redacted."""
        input_str = "login admin password=super_secret_123!"
        result = redact_log_value(input_str)
        assert "super_secret_123" not in result
        assert "password" in result.lower()  # key name is preserved

    def test_redact_token_key(self):
        """'token=value' in strings is redacted."""
        input_str = "api token=ghp_abc123def456ghi789jklmnopqrstuv"
        result = redact_log_value(input_str)
        assert "ghp_abc123def456ghi789jklmnopqrstuv" not in result

    def test_preserves_paths(self):
        """File paths are preserved, not redacted."""
        path_str = "/home/user/tools/httpx"
        result = redact_log_value(path_str)
        assert path_str == result

    def test_preserves_numbers(self):
        """Numbers (counts, timeouts) are preserved."""
        input_str = "httpx found 42 live subdomains"
        result = redact_log_value(input_str)
        assert "42" in result
        assert "live subdomains" in result

    def test_preserves_tool_names(self):
        """Tool names (httpx, subfinder, whatweb, etc.) are preserved."""
        input_str = "Executing: /usr/bin/subfinder -d example.com"
        result = redact_log_value(input_str)
        assert "subfinder" in result
        assert "example.com" in result

    def test_redact_recursive_list(self):
        """Secrets inside lists are recursively redacted."""
        input_list = ["safe_value", f"Cookie: {COOKIE_VALUE}", "also safe"]
        result = redact_log_value(input_list)
        assert isinstance(result, list)
        assert COOKIE_VALUE not in str(result)
        assert "safe_value" in result[0]
        assert "also safe" in result[2]

    def test_redact_recursive_dict(self):
        """Secrets inside dicts are recursively redacted."""
        input_dict = {"name": "test", "headers": {"Cookie": COOKIE_VALUE}}
        result = redact_log_value(input_dict)
        assert isinstance(result, dict)
        assert COOKIE_VALUE not in str(result)
        assert result["name"] == "test"

    def test_redact_recursive_tuple(self):
        """Secrets inside tuples are recursively redacted."""
        input_tuple = ("status", f"Authorization: {BEARER_TOKEN}")
        result = redact_log_value(input_tuple)
        assert isinstance(result, tuple)
        assert BEARER_TOKEN not in str(result)
        assert result[0] == "status"

    def test_redact_nested_containers(self):
        """Secrets at depth >= 2 in nested containers are redacted."""
        nested = {
            "step": 1,
            "details": {
                "command": CLI_COOKIE_CMD,
                "env": {"AUTH_HEADER": f"Bearer {JWT_TOKEN}"}
            }
        }
        result = redact_log_value(nested)
        assert isinstance(result, dict)
        # Secret values must not leak at any depth
        as_text = str(result)
        assert "PHPSESSID" not in as_text
        assert JWT_TOKEN not in as_text

    def test_redact_string(self):
        """String input returns redacted string."""
        result = redact_log_value(f"Cookie: {COOKIE_VALUE}")
        assert isinstance(result, str)
        assert COOKIE_VALUE not in result


# ===================================================================
# RedactionFilter
# ===================================================================

class TestRedactionFilter:
    """Unit tests for RedactionFilter – logging.Filter that redacts LogRecord fields."""

    def test_filter_redacts_msg(self):
        """LogRecord.msg containing secrets is redacted."""
        f = RedactionFilter()
        record = logging.LogRecord(
            "test", logging.INFO, "/fake/path", 10,
            f"Executing: httpx -H 'Cookie: {COOKIE_VALUE}'",
            (), None
        )
        result = f.filter(record)
        assert result is True  # filter returns True (doesn't block)
        assert COOKIE_VALUE not in record.msg

    def test_filter_redacts_args(self):
        """LogRecord.args containing secrets are redacted."""
        f = RedactionFilter()
        record = logging.LogRecord(
            "test", logging.INFO, "/fake/path", 10,
            "Tool output: %s",
            (f"Authorization: {BEARER_TOKEN}",),
            None
        )
        result = f.filter(record)
        assert result is True
        assert BEARER_TOKEN not in str(record.args)

    def test_filter_preserves_non_secret_args(self):
        """Non-secret LogRecord.args are preserved."""
        f = RedactionFilter()
        record = logging.LogRecord(
            "test", logging.INFO, "/fake/path", 10,
            "Step %d: %s",
            (1, "url_discovery"),
            None
        )
        result = f.filter(record)
        assert result is True
        assert record.args == (1, "url_discovery")

    def test_filter_handles_cmd_list_in_args(self):
        """'cmd': list[str] in LogRecord.args is redacted."""
        f = RedactionFilter()
        record = logging.LogRecord(
            "test", logging.INFO, "/fake/path", 10,
            "Running command: %s",
            (CLI_COOKIE_CMD,),  # tuple containing list (standard logging convention)
            None
        )
        result = f.filter(record)
        assert result is True
        args_str = str(record.args)
        assert "PHPSESSID" not in args_str

    def test_filter_handles_stderr_in_args(self):
        """'stderr' string in LogRecord.args is redacted."""
        f = RedactionFilter()
        record = logging.LogRecord(
            "test", logging.WARNING, "/fake/path", 10,
            "Command failed: %s",
            ({"stderr": f"Error: sent Cookie: {COOKIE_VALUE}"},),
            None
        )
        result = f.filter(record)
        assert result is True
        assert COOKIE_VALUE not in str(record.args)


# ===================================================================
# redact_log_value convenience function
# ===================================================================

class TestRedactLogValue:
    """Unit tests for redact_log_value() convenience function."""

    def test_redact_none(self):
        """None is returned as-is."""
        assert redact_log_value(None) is None

    def test_redact_empty_string(self):
        """Empty string is returned as-is."""
        assert redact_log_value("") == ""

    def test_redact_int(self):
        """Non-string/non-container scalar values are returned as-is."""
        assert redact_log_value(42) == 42

    def test_redact_bool(self):
        """Boolean values are returned as-is."""
        assert redact_log_value(True) is True
