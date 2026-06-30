"""Takeover tool result normalization adapter (SGK-2026-0283-D03).

Normalizes subjack/subzy/nuclei/manual_curl outputs into a common schema.

Per plan section 4.11, this module provides:
  - ``NormalizedTakeoverToolResult``: common schema for normalized tool results.
  - ``parse_subjack_output()``: parse subjack bracket-format output.
  - ``parse_subzy_output()``: parse subzy table-format output.
  - ``parse_nuclei_output()``: parse nuclei JSONL/info output.
  - ``normalize_manual_curl_result()``: normalize HTTP curl-level results.
  - ``normalize_tool_result()``: dispatcher that routes by tool name.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Data model ───────────────────────────────────────────────────────────

@dataclass
class NormalizedTakeoverToolResult:
    """Common schema for normalized takeover tool results.

    Fields match the plan section 4.11 specification.
    """
    tool: str
    subdomain: str
    provider: str = "unknown"
    matched: bool = False
    evidence_type: str = "none"
    confidence: str = "none"
    http_status: int = 0
    error_token: Optional[str] = None
    cname_chain: List[str] = field(default_factory=list)
    raw_excerpt: Optional[str] = None
    tool_error: Optional[str] = None
    manual_review_required: bool = True


# ── Internal helpers ─────────────────────────────────────────────────────

_SUBJACK_VULNERABLE_RE = re.compile(
    r"\[Vulnerable(?:\s*[-–]\s*(\S+?))?\]\s+(\S+)",
    re.IGNORECASE,
)
_SUBJACK_NOT_VULNERABLE_RE = re.compile(
    r"\[Not\s+Vulnerable\]\s+(\S+)",
    re.IGNORECASE,
)

# subjack service name extraction from the bracket portion
_SUBJACK_SERVICE_IN_BRACKET_RE = re.compile(
    r"\[Vulnerable\s*[-–]\s*(\S+)\]",
    re.IGNORECASE,
)

_SUBZY_TABLE_HEADER_RE = re.compile(
    r"Domain\s+Service\s+.*Status\s+.*Vulnerable",
    re.IGNORECASE,
)

_NUCLEI_TAKEOVER_TEMPLATE_RE = re.compile(
    r"takeover",
    re.IGNORECASE,
)

_MAX_RAW_EXCERPT_LENGTH = 1000


def _safe_raw_excerpt(raw_output: Optional[str]) -> Optional[str]:
    """Truncate raw output to a manageable excerpt length."""
    if raw_output is None:
        return None
    text = str(raw_output).strip()
    if not text:
        return None
    if len(text) > _MAX_RAW_EXCERPT_LENGTH:
        return text[:_MAX_RAW_EXCERPT_LENGTH]
    return text


def _is_empty_or_none(raw_output: Optional[str]) -> bool:
    """Check if raw_output is None or contains only whitespace."""
    if raw_output is None:
        return True
    return not raw_output.strip()


# ── subjack parser ───────────────────────────────────────────────────────

def parse_subjack_output(
    raw_output: Optional[str],
    subdomain: str,
) -> NormalizedTakeoverToolResult:
    """Parse subjack bracket-format output.

    subjack outputs lines like::

        [Not Vulnerable] example.com
        [Vulnerable - GitHub] dead.example.com
        [Vulnerable] bare.example.com

    Only the first matching line for the requested *subdomain* is used.
    """
    if _is_empty_or_none(raw_output):
        return NormalizedTakeoverToolResult(
            tool="subjack",
            subdomain=subdomain,
            matched=False,
            evidence_type="none",
            confidence="none",
        )

    cleaned = str(raw_output).strip()

    # Try vulnerable pattern first
    for match in _SUBJACK_VULNERABLE_RE.finditer(cleaned):
        service = (match.group(1) or "unknown").strip()
        matched_domain = match.group(2)
        if matched_domain == subdomain:
            return NormalizedTakeoverToolResult(
                tool="subjack",
                subdomain=subdomain,
                provider=service,
                matched=True,
                evidence_type="tool_signal",
                confidence="tool_signal",
                raw_excerpt=_safe_raw_excerpt(cleaned),
            )

    # Check Not Vulnerable for the subdomain
    for match in _SUBJACK_NOT_VULNERABLE_RE.finditer(cleaned):
        matched_domain = match.group(1)
        if matched_domain == subdomain:
            return NormalizedTakeoverToolResult(
                tool="subjack",
                subdomain=subdomain,
                matched=False,
                evidence_type="none",
                confidence="tool_negative",
                raw_excerpt=_safe_raw_excerpt(cleaned),
            )

    # Subdomain not found in output
    return NormalizedTakeoverToolResult(
        tool="subjack",
        subdomain=subdomain,
        matched=False,
        evidence_type="none",
        confidence="none",
        raw_excerpt=_safe_raw_excerpt(cleaned),
    )


# ── subzy parser ─────────────────────────────────────────────────────────

def parse_subzy_output(
    raw_output: Optional[str],
    subdomain: str,
) -> NormalizedTakeoverToolResult:
    """Parse subzy table-format output.

    subzy outputs a table with columns: Domain, Service, Status, Vulnerable.
    Example::

        dead.example.com    Github    404    VULNERABLE

    Additional columns (CNAME, Error) may also be present.
    """
    if _is_empty_or_none(raw_output):
        return NormalizedTakeoverToolResult(
            tool="subzy",
            subdomain=subdomain,
            matched=False,
            evidence_type="none",
            confidence="none",
        )

    cleaned = str(raw_output).strip()
    lines = cleaned.splitlines()

    # Detect if only stderr output, no table data
    has_table = False
    for line in lines:
        if _SUBZY_TABLE_HEADER_RE.search(line):
            has_table = True
            break

    if not has_table:
        # No header row — try to detect data rows directly via token patterns.
        # Check if output appears to be only stderr
        stderr_lines = [ln for ln in lines if "stderr" in ln.lower() or "error" in ln.lower()]
        is_likely_stderr = len(stderr_lines) > 0 and not any(
            _SUBZY_TABLE_HEADER_RE.search(ln) for ln in lines
        )
        if is_likely_stderr:
            return NormalizedTakeoverToolResult(
                tool="subzy",
                subdomain=subdomain,
                matched=False,
                evidence_type="none",
                confidence="none",
                tool_error=cleaned,
                raw_excerpt=_safe_raw_excerpt(cleaned),
            )

        # Try headerless parsing: look for rows with 4+ tokens where
        # the 4th token is a recognised vulnerability status.
        _VALID_VULN_STATUSES = {"VULNERABLE", "NOT_VULNERABLE", "ERROR", "TRUE", "FALSE", "YES", "NO"}
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            tokens = stripped.split()
            if len(tokens) < 4:
                continue
            domain = tokens[0]
            if domain != subdomain:
                continue
            vulnerable_status = tokens[3]
            if vulnerable_status.upper() not in _VALID_VULN_STATUSES:
                continue
            service = tokens[1] if len(tokens) > 1 else "unknown"
            status_code_str = tokens[2] if len(tokens) > 2 else "0"
            is_vulnerable = vulnerable_status.upper() in ("VULNERABLE", "ERROR", "TRUE", "YES")
            http_status = 0
            try:
                http_status = int(status_code_str)
            except (ValueError, TypeError):
                http_status = 0
            return NormalizedTakeoverToolResult(
                tool="subzy",
                subdomain=subdomain,
                provider=service if service.lower() != "none" else "unknown",
                matched=is_vulnerable,
                evidence_type="tool_signal" if is_vulnerable else "none",
                confidence="tool_signal" if is_vulnerable else "tool_negative",
                http_status=http_status,
                raw_excerpt=_safe_raw_excerpt(cleaned),
                manual_review_required=is_vulnerable,
            )

        # No matching data row found
        return NormalizedTakeoverToolResult(
            tool="subzy",
            subdomain=subdomain,
            matched=False,
            evidence_type="none",
            confidence="none",
            raw_excerpt=_safe_raw_excerpt(cleaned),
        )

    # Parse table data rows (skip the header row(s))
    header_seen = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if _SUBZY_TABLE_HEADER_RE.search(stripped):
            header_seen = True
            continue
        if not header_seen:
            continue

        # Tokenize the line by whitespace
        tokens = stripped.split()
        if len(tokens) < 4:
            continue

        domain = tokens[0]
        if domain != subdomain:
            continue

        service = tokens[1] if len(tokens) > 1 else "unknown"
        status_code_str = tokens[2] if len(tokens) > 2 else "0"
        vulnerable_status = tokens[3] if len(tokens) > 3 else ""

        # Determine matched status
        is_vulnerable = vulnerable_status.upper() in ("VULNERABLE", "ERROR", "TRUE", "YES")

        # Parse HTTP status code
        http_status = 0
        try:
            http_status = int(status_code_str)
        except (ValueError, TypeError):
            http_status = 0

        return NormalizedTakeoverToolResult(
            tool="subzy",
            subdomain=subdomain,
            provider=service if service.lower() != "none" else "unknown",
            matched=is_vulnerable,
            evidence_type="tool_signal" if is_vulnerable else "none",
            confidence="tool_signal" if is_vulnerable else "tool_negative",
            http_status=http_status,
            raw_excerpt=_safe_raw_excerpt(cleaned),
            manual_review_required=is_vulnerable,  # always review subzy hits
        )

    # Subdomain not found in table
    return NormalizedTakeoverToolResult(
        tool="subzy",
        subdomain=subdomain,
        matched=False,
        evidence_type="none",
        confidence="none",
        raw_excerpt=_safe_raw_excerpt(cleaned),
    )


# ── nuclei parser ────────────────────────────────────────────────────────

def parse_nuclei_output(
    raw_output: Optional[str],
    subdomain: str,
) -> NormalizedTakeoverToolResult:
    """Parse nuclei JSONL (JSON Lines) or plain-text output.

    Nuclei typically outputs one JSON object per line. Only lines
    whose ``template-id`` contains "takeover" are considered matches.
    Non-JSON lines (info/warn logs) are silently skipped.
    """
    if _is_empty_or_none(raw_output):
        return NormalizedTakeoverToolResult(
            tool="nuclei",
            subdomain=subdomain,
            matched=False,
            evidence_type="none",
            confidence="none",
        )

    cleaned = str(raw_output).strip()
    lines = cleaned.splitlines()

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Try JSONL parsing
        try:
            data = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            # Skip non-JSON lines (info, warn, etc.)
            continue
        except Exception:
            continue

        if not isinstance(data, dict):
            continue

        template_id = str(data.get("template-id", "") or "")
        if not _NUCLEI_TAKEOVER_TEMPLATE_RE.search(template_id):
            continue

        # Matched a takeover template
        info = data.get("info", {}) if isinstance(data.get("info"), dict) else {}
        host = str(data.get("host", "") or data.get("matched-at", "") or "")
        template_name = str(info.get("name", "") or "")

        # Extract subdomain from host if not already present
        matched_subdomain = subdomain

        return NormalizedTakeoverToolResult(
            tool="nuclei",
            subdomain=matched_subdomain,
            provider=template_id.replace("takeover-", "").replace("takeover_", ""),
            matched=True,
            evidence_type="tool_signal",
            confidence="tool_signal",
            raw_excerpt=_safe_raw_excerpt(cleaned),
        )

    # No matching template found
    return NormalizedTakeoverToolResult(
        tool="nuclei",
        subdomain=subdomain,
        matched=False,
        evidence_type="none",
        confidence="none",
        raw_excerpt=_safe_raw_excerpt(cleaned),
    )


# ── manual_curl normalizer ───────────────────────────────────────────────

# Known provider error tokens used for provider matching in body text.
# In a full implementation these come from the provider matrix; here we
# embed a small built-in set for standalone use.
_BUILTIN_ERROR_TOKENS: Dict[str, str] = {
    "There isn't a GitHub Pages site here.": "github_pages",
    "NoSuchBucket": "aws_s3",
    "The specified bucket does not exist": "aws_s3",
    "No such app": "heroku",
    "Web App not found": "azure_websites",
    "This web app is stopped": "azure_websites",
    "Fastly error: unknown domain": "fastly",
    "There's nothing here.": "shopify",
    "No settings were found for this company": "readme",
}


def normalize_manual_curl_result(
    status: int,
    body: Optional[str],
    headers: Dict[str, Any],
    subdomain: str,
) -> NormalizedTakeoverToolResult:
    """Normalize manual curl-level HTTP results.

    Args:
        status: HTTP status code (0 for connection errors).
        body: HTTP response body text.
        headers: HTTP response headers dict.
        subdomain: The target subdomain.

    Returns:
        NormalizedTakeoverToolResult.
    """
    body_text = body if body is not None else ""

    # Connection-level error
    if status == 0:
        return NormalizedTakeoverToolResult(
            tool="manual_curl",
            subdomain=subdomain,
            matched=False,
            evidence_type="none",
            confidence="none",
            http_status=0,
            tool_error="Connection failed or no HTTP response received.",
            raw_excerpt=_safe_raw_excerpt(body_text),
            manual_review_required=True,
        )

    # Check for known provider error tokens in body
    matched_provider = "unknown"
    matched_token: Optional[str] = None
    for token, provider_id in _BUILTIN_ERROR_TOKENS.items():
        if token in body_text:
            matched_provider = provider_id
            matched_token = token
            break

    if matched_token is not None:
        return NormalizedTakeoverToolResult(
            tool="manual_curl",
            subdomain=subdomain,
            provider=matched_provider,
            matched=True,
            evidence_type="provider_error_token",
            confidence="tool_signal",
            http_status=status,
            error_token=matched_token,
            raw_excerpt=_safe_raw_excerpt(body_text),
            manual_review_required=True,
        )

    # No known error token found
    return NormalizedTakeoverToolResult(
        tool="manual_curl",
        subdomain=subdomain,
        matched=False,
        evidence_type="none",
        confidence="none",
        http_status=status,
        raw_excerpt=_safe_raw_excerpt(body_text),
    )


# ── Dispatcher ───────────────────────────────────────────────────────────

_PARSER_REGISTRY: Dict[str, Any] = {
    "subjack": parse_subjack_output,
    "subzy": parse_subzy_output,
    "nuclei": parse_nuclei_output,
}


def normalize_tool_result(
    tool: str,
    raw_output: Optional[str],
    subdomain: str,
    provider_matrix: Any = None,
) -> NormalizedTakeoverToolResult:
    """Dispatch to the correct parser based on tool name.

    Args:
        tool: Tool name (subjack, subzy, nuclei, manual_curl).
        raw_output: Raw tool output text (stdout + stderr).
        subdomain: The target subdomain being checked.
        provider_matrix: Optional TakeoverProviderMatrix for provider enrichment.

    Returns:
        NormalizedTakeoverToolResult with fields populated by the parser.
    """
    tool_lower = tool.lower().strip()

    parser = _PARSER_REGISTRY.get(tool_lower)
    if parser is not None:
        result = parser(raw_output, subdomain)
        # Enrich provider name if matrix is available and provider is still unknown
        if provider_matrix is not None and result.provider == "unknown":
            # Try to enrich from provider matrix via error token or cname analysis
            # This is a placeholder for future matrix integration
            pass
        return result

    # Unknown tool or manual_curl with raw output → generic fallback
    return NormalizedTakeoverToolResult(
        tool=tool_lower,
        subdomain=subdomain,
        matched=False,
        evidence_type="none",
        confidence="none",
        raw_excerpt=_safe_raw_excerpt(str(raw_output) if raw_output else None),
    )
