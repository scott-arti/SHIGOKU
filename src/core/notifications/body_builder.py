"""
Japanese notification body builder with redaction.

Builds detailed Japanese Discord notification bodies from Finding objects
or FindingNotificationDTOs. Applies automatic secret redaction and
enforces Discord message length limits.

Part of SGK-2026-0297 Phase A: Discord全Finding詳細通知.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)


class JapaneseBodyBuilder:
    """
    Builds detailed Japanese notification bodies for Discord.

    Responsibilities:
    - Generate structured Japanese message with all key fields
    - Redact secrets (Bearer tokens, JWT, cookies, passwords, API keys)
    - Build safe evidence summary (truncated, no raw bodies)
    - Enforce max length limit

    Design: stateless, safe-by-default. Every build() call redacts.
    """

    # Maximum body length (Discord message limit)
    DEFAULT_MAX_LENGTH = 4000

    # Patterns for secret redaction (case-insensitive for keys)
    REDACT_PATTERNS: list[tuple[re.Pattern, str]] = [
        # Authorization headers (Bearer, Basic, etc.)
        (
            re.compile(r"(Authorization:\s*)(Bearer\s+\S+)", re.IGNORECASE),
            r"\1[REDACTED]",
        ),
        (
            re.compile(r"(Authorization:\s*)(Basic\s+\S+)", re.IGNORECASE),
            r"\1[REDACTED]",
        ),
        # Cookie headers
        (
            re.compile(r"(Cookie:\s*)\S+", re.IGNORECASE),
            r"\1[REDACTED]",
        ),
        # Set-Cookie headers
        (
            re.compile(r"(Set-Cookie:\s*)\S+", re.IGNORECASE),
            r"\1[REDACTED]",
        ),
        # API keys (X-API-Key, api_key=, apiKey=)
        (
            re.compile(r"(X-API-Key:\s*)\S+", re.IGNORECASE),
            r"\1[REDACTED]",
        ),
        (
            re.compile(r"(api[_-]?key[\s]*[=:]\s*)\S+", re.IGNORECASE),
            r"\1[REDACTED]",
        ),
        # Passwords
        (
            re.compile(r"(password[\s]*[=:]\s*)\S+", re.IGNORECASE),
            r"\1[REDACTED]",
        ),
        (
            re.compile(r"(passwd[\s]*[=:]\s*)\S+", re.IGNORECASE),
            r"\1[REDACTED]",
        ),
        # Tokens/Secrets
        (
            re.compile(r"(token[\s]*[=:]\s*)\S+", re.IGNORECASE),
            r"\1[REDACTED]",
        ),
        (
            re.compile(r"(secret[\s]*[=:]\s*)\S+", re.IGNORECASE),
            r"\1[REDACTED]",
        ),
        # JWT tokens (standalone eyJ... strings with >= 20 chars)
        (
            re.compile(
                r"(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?)"
            ),
            r"[REDACTED-JWT]",
        ),
        # Bearer token in text (not in header context)
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
    ]

    def __init__(self, max_length: int | None = None):
        self.max_length = max_length or self.DEFAULT_MAX_LENGTH

    def build(self, finding) -> str:
        """
        Build a Japanese detailed notification body.

        Args:
            finding: Finding object, FindingNotificationDTO, or dict.

        Returns:
            Redacted, Japanese-formatted, length-limited notification body.
        """
        # Convert to dict for uniform access
        d = self._to_dict(finding)

        lines: list[str] = []

        # Header with severity icon
        severity = d.get("severity", "info")
        icon = self._severity_icon(severity)
        severity_jp = self._severity_japanese(severity)
        lines.append(f"{icon} **【{severity_jp}】脆弱性を検出しました**")
        lines.append("")

        # Basic info table
        finding_id = d.get("finding_id", d.get("id", "N/A"))
        lines.append(f"🔑 **脆弱性ID**: `{finding_id}`")
        lines.append(
            f"📛 **種類**: {d.get('vuln_type', d.get('type', 'N/A'))}"
        )
        lines.append(
            f"🎯 **対象URL**: {d.get('target_url', d.get('target', d.get('url', 'N/A')))}"
        )
        lines.append(f"📝 **タイトル**: {d.get('title', 'N/A')}")
        lines.append("")

        # Description
        desc = d.get("description", "")
        if desc:
            lines.append("📖 **説明**")
            lines.append(str(desc))
            lines.append("")

        # Impact
        impact = d.get("impact", "")
        if impact:
            lines.append("💥 **影響**")
            lines.append(str(impact))
            lines.append("")

        # Reproduction steps
        steps = d.get("reproduction_steps", [])
        if steps:
            if isinstance(steps, str):
                steps = [steps]
            lines.append("🔄 **再現手順**")
            for i, step in enumerate(steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        # Evidence summary (safe/truncated)
        evidence_summary = d.get("evidence_summary", "")
        if not evidence_summary:
            evidence_summary = self._build_safe_evidence_summary(d)
        if evidence_summary:
            lines.append("📎 **エビデンス概要**")
            lines.append(evidence_summary)
            lines.append("")

        # Meta footer
        confidence = d.get("confidence", 0.0)
        if isinstance(confidence, (int, float)) and confidence > 0:
            lines.append(f"📊 **信頼度**: {int(confidence * 100)}%")

        source_agent = d.get("source_agent", "")
        if source_agent:
            lines.append(f"🤖 **発見エージェント**: {source_agent}")

        source_component = d.get("source_component", "")
        ingress_path = d.get("ingress_path", "")
        if source_component:
            if ingress_path:
                lines.append(
                    f"🔗 **経路**: {source_component}/{ingress_path}"
                )
            else:
                lines.append(f"🔗 **経路**: {source_component}")

        discovered_at = d.get("discovered_at", "")
        if discovered_at:
            lines.append(f"🕐 **発見日時**: {discovered_at}")

        # Normalization warning
        warning = d.get("normalization_warning", "")
        if warning:
            lines.append(f"⚠️ 注意: {warning}")

        body = "\n".join(lines)

        # Redact secrets
        body = self.redact(body)

        # Enforce max length
        body = self._truncate(body)

        return body

    def redact(self, text: str) -> str:
        """Apply all redaction patterns to text. Returns redacted text."""
        result = text
        for pattern, replacement in self.REDACT_PATTERNS:
            result = pattern.sub(replacement, result)
        return result

    def _build_safe_evidence_summary(self, d: dict) -> str:
        """
        Build a safe (redacted, truncated) evidence summary from a finding dict.

        Only includes: request method, request URL (no query), response status.
        Does NOT include raw headers or bodies.
        """
        evidence = d.get("evidence", {})
        if not evidence or not isinstance(evidence, dict):
            return ""

        parts: list[str] = []
        method = str(evidence.get("request_method", ""))
        url = str(evidence.get("request_url", ""))
        if method and url:
            # Strip query params from URL for safety
            url_clean = url.split("?")[0] if "?" in url else url
            parts.append(f"Request: {method} {url_clean}")
        elif method:
            parts.append(f"Request method: {method}")
        elif url:
            url_clean = url.split("?")[0] if "?" in url else url
            parts.append(f"URL: {url_clean}")

        status = evidence.get("response_status", 0)
        if status:
            parts.append(f"Response status: {status}")

        # Redact before returning
        return self.redact("\n".join(parts)) if parts else ""

    def _to_dict(self, finding) -> dict:
        """Convert any finding representation to a dict."""
        if isinstance(finding, dict):
            return finding
        if hasattr(finding, "to_dict"):
            return finding.to_dict()
        if hasattr(finding, "__dict__"):
            return {
                k: v
                for k, v in finding.__dict__.items()
                if not k.startswith("_")
            }
        return {}

    def _severity_icon(self, severity: str) -> str:
        icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵",
        }
        return icons.get(str(severity).lower(), "⚪")

    def _severity_japanese(self, severity: str) -> str:
        names = {
            "critical": "緊急",
            "high": "高",
            "medium": "中",
            "low": "低",
            "info": "情報",
        }
        return names.get(str(severity).lower(), str(severity).upper())

    def _truncate(self, body: str) -> str:
        """Truncate body to max_length with Japanese indicator."""
        if len(body) <= self.max_length:
            return body
        suffix = "\n\n... (長さ制限のため切り詰めました)"
        return body[: self.max_length - len(suffix)] + suffix


# --------------------------------------------------------------------------- #
# Golden fixture for testing
# --------------------------------------------------------------------------- #


def create_golden_finding_dict() -> dict:
    """Return a well-known finding dict for golden fixture testing."""
    return {
        "finding_id": "abc123def456",
        "severity": "high",
        "vuln_type": "sqli",
        "title": "SQL Injection in Login Form",
        "target_url": "https://example.com/login",
        "description": "UNION-based SQL injection via username parameter.",
        "impact": "Full database exfiltration possible.",
        "reproduction_steps": [
            "1. Visit https://example.com/login",
            "2. Enter ' OR 1=1 -- in username field",
            "3. Observe bypass of authentication",
        ],
        "evidence_summary": "Request: POST /login\nResponse status: 200",
        "confidence": 0.92,
        "source_agent": "sqli_hunter",
        "source_component": "master_conductor",
        "ingress_path": "handle_finding",
        "discovered_at": "2026-06-24T10:30:00",
    }
