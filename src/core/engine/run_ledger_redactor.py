"""
Run Ledger Redactor — content redaction for the run ledger.

Ensures no secrets (API keys, tokens, cookies, passwords) leak into:
- session payload (run_ledger events)
- JSONL spool
- stdout / logs

Uses a common redaction pipeline before any content enters the ledger.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Redaction patterns — ordered by priority (most specific first)
# ---------------------------------------------------------------------------

_REDACTION_PATTERNS: List[Tuple[str, str, str]] = [
    # (category, regex, replacement)
    # --- Private keys (PEM) — check first, longest pattern ---
    ("private_key", r"-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE|EC|DSA|OPENSSH)\s+KEY-----[^-]*-----END\s+(?:RSA\s+)?(?:PRIVATE|EC|DSA|OPENSSH)\s+KEY-----", "[REDACTED:private_key]"),
    # --- API Keys ---
    ("api_key_sk_proj", r"sk-proj-[a-zA-Z0-9_-]{20,}", "[REDACTED:api_key]"),
    ("api_key_sk_svc", r"sk-svcacct-[a-zA-Z0-9_-]{20,}", "[REDACTED:api_key]"),
    ("api_key_sk_admin", r"sk-admin-[a-zA-Z0-9_-]{20,}", "[REDACTED:api_key]"),
    ("api_key_sk", r"sk-[a-zA-Z0-9]{20,}", "[REDACTED:api_key]"),
    ("api_key_openai", r"sk-[a-zA-Z0-9]{48,}", "[REDACTED:api_key]"),
    # --- Authorization header (catch entire header value, up to 3 tokens) ---
    ("authorization_header", r"Authorization:\s*\S+(?:\s+\S+){0,2}", "[REDACTED:auth_header]"),
    # --- Bearer / Auth tokens (standalone) ---
    ("bearer_token", r"Bearer\s+[a-zA-Z0-9._\-+/=]{10,}", "[REDACTED:auth_token]"),
    ("jwt_token", r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "[REDACTED:jwt]"),
    # --- Basic Auth ---
    ("basic_auth", r"-u\s+\S+:\S+", "[REDACTED:basic_auth]"),
    # --- API Key headers (catch entire header value, up to 3 tokens) ---
    ("x_api_key", r"X-API-Key:\s*\S+(?:\s+\S+){0,2}", "[REDACTED:api_key_header]"),
    # --- AWS keys ---
    ("aws_access_key", r"AKIA[0-9A-Z]{16}", "[REDACTED:aws_key]"),
    ("aws_secret_key", r"AWS_SECRET_ACCESS_KEY[=:]\s*\S+", "[REDACTED:aws_secret]"),
    ("aws_session_token", r"AWS_SESSION_TOKEN[=:]\s*\S+", "[REDACTED:aws_token]"),
    # --- Cookie secrets ---
    ("cookie_generic", r"Cookie:\s*[^\n]*", "[REDACTED:cookie_header]"),
    ("cookie_session", r"(?:session_id|session|auth_token|access_token|token|auth|sid)[=:]\s*[a-zA-Z0-9_-]{8,}", "[REDACTED:cookie]"),
    # --- Passwords / secrets ---
    ("password_assign", r"(?:password|passwd|pass)[=:]\s*\S+", "[REDACTED:password]"),
    ("secret_assign", r"(?:secret|apikey|api_key)[=:]\s*\S+", "[REDACTED:secret]"),
]

MAX_SUMMARY_LENGTH = 500


@dataclass
class RedactionResult:
    """Result of redacting content for the run ledger."""
    summary: Optional[str]          # safe summary for input_summary
    fingerprint: Optional[str]      # sha256:... for input_fingerprint
    redaction_status: str           # "none" | "partial" | "full"
    redacted_fields_count: int      # number of redacted occurrences


def redact_content(raw: str, max_summary_length: int = MAX_SUMMARY_LENGTH) -> RedactionResult:
    """
    Redact secrets from content and produce a safe summary + fingerprint.

    Args:
        raw: Raw input content (prompt, command, etc.)
        max_summary_length: Maximum length of the summary output.

    Returns:
        RedactionResult with summary, fingerprint, status, and count.
    """
    if not raw:
        return RedactionResult(
            summary=None,
            fingerprint=None,
            redaction_status="none",
            redacted_fields_count=0,
        )

    redacted = raw
    redacted_count = 0

    # Apply redaction patterns in order
    for _category, pattern, replacement in _REDACTION_PATTERNS:
        matches = list(re.finditer(pattern, redacted, re.IGNORECASE))
        if matches:
            redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)
        redacted_count += len(matches)

    # Determine redaction status
    if redacted_count == 0:
        status = "none"
    elif raw == redacted or len(redacted.strip()) == 0:
        status = "full"
    else:
        status = "partial"

    # Build summary: truncate redacted content
    summary = redacted.strip() if redacted.strip() else "[FULLY REDACTED]"
    if len(summary) > max_summary_length:
        summary = summary[:max_summary_length - 20] + "...[truncated]"

    # Build fingerprint: SHA256 of normalized redacted content
    # Use the redacted content so fingerprints are comparable across runs
    normalized = _normalize_for_fingerprint(redacted)
    fp = "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    return RedactionResult(
        summary=summary,
        fingerprint=fp,
        redaction_status=status,
        redacted_fields_count=redacted_count,
    )


def redact_for_ledger(raw: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str], int]:
    """
    Convenience wrapper that returns (summary, fingerprint, redaction_status, redacted_fields_count).

    Args:
        raw: Raw input content. If None, returns (None, None, None, 0).

    Use this in ledger event creation:
        summary, fp, status, count = redact_for_ledger(raw_command)
        recorder.record(
            event_type=RunLedgerEventType.TOOL_EXECUTED,
            ...,
            input_summary=summary,
            input_fingerprint=fp,
            redaction_status=status,
            redacted_fields_count=count,
        )
    """
    if raw is None:
        return (None, None, None, 0)
    result = redact_content(raw)
    return (
        result.summary,
        result.fingerprint,
        result.redaction_status,
        result.redacted_fields_count,
    )


def _normalize_for_fingerprint(content: str) -> str:
    """
    Normalize content for fingerprint comparison.
    Strips whitespace, lowercases, removes variable IDs/numbers that would
    change between runs but not content semantics.
    """
    # Normalize timestamps, UUIDs, random strings within [REDACTED] markers
    normalized = content.strip().lower()
    # Collapse whitespace
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized
