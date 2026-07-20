"""
One-way log redaction helper (SGK-2026-0344).

Provides ``redact_log_value()`` for recursive secret redaction in log values,
and ``RedactionFilter`` for applying redaction at the logging handler boundary.

Redaction is **one-way** (irreversible) — `[REDACTED]` markers replace
secret values without token maps.  This is distinct from ``PIIMasker`` which
is bidirectional and used for AI-API masking.

Patterns are derived from ``JapaneseBodyBuilder.REDACT_PATTERNS`` and extended
with CLI-argument header patterns.
"""

from __future__ import annotations

import logging
import re
from typing import Any


# ---------------------------------------------------------------------------
# Redaction patterns (one-way, derived from JapaneseBodyBuilder.REDACT_PATTERNS)
# ---------------------------------------------------------------------------

_REDACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # ── Authorization headers ──────────────────────────────────────────
    (
        re.compile(r"(Authorization:\s*)(Bearer\s+\S+)", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(Authorization:\s*)(Basic\s+\S+)", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # ── Proxy-Authorization header ─────────────────────────────────────
    (
        re.compile(r"(Proxy-Authorization:\s*)\S+", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # ── Cookie / Set-Cookie headers ────────────────────────────────────
    # Match the full cookie value including semicolon-separated pairs
    # and optional spaces (e.g. "PHPSESSID=abc; security=low; token=xyz").
    # Stops at the next CLI option flag (-x), end-of-string, or quote.
    (
        re.compile(r"(Cookie:\s*).+?(?=\s+-\w|$)", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(Set-Cookie:\s*).+?(?=\s+-\w|$)", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # ── API key headers ────────────────────────────────────────────────
    (
        re.compile(r"(X-Api-Key:\s*)\S+", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(api[_-]?key[\s]*[=:]\s*)\S+", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # ── Passwords ──────────────────────────────────────────────────────
    (
        re.compile(r"(password[\s]*[=:]\s*)\S+", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(passwd[\s]*[=:]\s*)\S+", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # ── Tokens / secrets ───────────────────────────────────────────────
    (
        re.compile(r"(token[\s]*[=:]\s*)\S+", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(secret[\s]*[=:]\s*)\S+", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # ── Standalone JWT ─────────────────────────────────────────────────
    (
        re.compile(
            r"(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?)"
        ),
        r"[REDACTED-JWT]",
    ),
    # ── Bearer + JWT / Bearer + sk-* token / Bearer + any token ────────
    (
        re.compile(
            r"Bearer\s+(eyJ[A-Za-z0-9_-]{20,}\S*)", re.IGNORECASE
        ),
        r"Bearer [REDACTED]",
    ),
    (
        re.compile(
            r"Bearer\s+(sk-[A-Za-z0-9_-]{10,}\S*)", re.IGNORECASE
        ),
        r"Bearer [REDACTED]",
    ),
    # Generic standalone Bearer <token> (catches any unrecognized token format)
    (
        re.compile(r"Bearer\s+(\S{8,})", re.IGNORECASE),
        r"Bearer [REDACTED]",
    ),
    # ── CLI-argument header patterns (-H "Cookie: ..." etc.) ───────────
    (
        re.compile(
            r"(\s-H\s+[""']?(?:Cookie|Set-Cookie|Authorization|X-Api-Key"
            r"|Proxy-Authorization):\s*)\S+",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
]


# ---------------------------------------------------------------------------
# LogRedactor
# ---------------------------------------------------------------------------


class LogRedactor:
    """One-way redaction engine for log values.

    Applies all registered redaction patterns recursively through
    strings, lists, tuples, and dict nesting.
    """

    def __init__(self, patterns: list[tuple[re.Pattern[str], str]] | None = None) -> None:
        self._patterns: list[tuple[re.Pattern[str], str]] = (
            patterns if patterns is not None else list(_REDACT_PATTERNS)
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def redact(self, value: Any) -> Any:
        """Recursively redact secrets in *value*.

        Returns a new object of the same shape with secrets replaced.
        Scalars (int, bool, None, etc.) and empty strings are returned
        as-is.
        """
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, str):
            return self._redact_string(value)
        if isinstance(value, (list, tuple)):
            return type(value)(self.redact(item) for item in value)
        if isinstance(value, dict):
            return self._redact_dict(value)
        # Fallback: convert to string and redact
        return self._redact_string(str(value))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    # Keys whose values are always fully redacted (case-insensitive).
    # Per SGK-2026-0344 spec: key-name-based value redaction.
    _SECRET_KEYS: frozenset[str] = frozenset({
        "cookie",
        "set-cookie",
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "api_key",
        "apikey",
        "api-key",
        "password",
        "passwd",
        "token",
        "secret",
        "bearer_token",
        "access_token",
        "refresh_token",
        "auth_headers",
        "auth_header",
    })

    def _redact_string(self, text: str) -> str:
        """Apply all redaction patterns to a single string."""
        if not text:
            return text
        result = text
        for pattern, replacement in self._patterns:
            result = pattern.sub(replacement, result)
        return result

    def _redact_dict(self, d: dict) -> dict:
        """Redact a dict, fully redacting values under secret-bearing keys."""
        result: dict = {}
        for k, v in d.items():
            key_lower = str(k).lower()
            if key_lower in self._SECRET_KEYS:
                result[k] = "[REDACTED]"
            else:
                result[k] = self.redact(v)
        return result


# ---------------------------------------------------------------------------
# Module-level convenience API
# ---------------------------------------------------------------------------

_default_redactor = LogRedactor()


def redact_log_value(value: Any) -> Any:
    """Convenience function: one-way redact *value* recursively.

    >>> redact_log_value("Cookie: PHPSESSID=abc123")
    'Cookie: [REDACTED]'
    >>> redact_log_value(None) is None
    True
    >>> redact_log_value(42)
    42
    """
    return _default_redactor.redact(value)


# ---------------------------------------------------------------------------
# RedactionFilter — logging.Filter subclass
# ---------------------------------------------------------------------------


class RedactionFilter(logging.Filter):
    """``logging.Filter`` that redacts secrets from ``LogRecord`` fields.

    Attach this filter to console and file handlers so every log record
    passing through is automatically redacted, regardless of which
    callsite emitted it.
    """

    def __init__(self, name: str = "") -> None:
        super().__init__(name)
        self._redactor = LogRedactor()

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact ``record.msg`` and ``record.args`` in-place.

        Always returns ``True`` (never blocks a log message).
        """
        record.msg = self._redactor.redact(record.msg)
        if record.args:
            record.args = self._redactor.redact(record.args)
        return True
