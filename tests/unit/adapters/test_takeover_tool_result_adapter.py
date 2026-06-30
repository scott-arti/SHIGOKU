"""Tests for takeover tool result normalization adapter (SGK-2026-0283-D03).

Covers: subjack, subzy, nuclei, manual_curl parsers and the normalize_tool_result dispatcher.
"""
import pytest

from src.core.adapters.external.takeover_tool_result_adapter import (
    NormalizedTakeoverToolResult,
    parse_subjack_output,
    parse_subzy_output,
    parse_nuclei_output,
    normalize_manual_curl_result,
    normalize_tool_result,
)


# ── NormalizedTakeoverToolResult dataclass ─────────────────────────────

def test_dataclass_defaults():
    """All fields have sensible defaults."""
    result = NormalizedTakeoverToolResult(
        tool="subjack",
        subdomain="example.com",
    )
    assert result.tool == "subjack"
    assert result.subdomain == "example.com"
    assert result.provider == "unknown"
    assert result.matched is False
    assert result.evidence_type == "none"
    assert result.confidence == "none"
    assert result.http_status == 0
    assert result.error_token is None
    assert result.cname_chain == []
    assert result.raw_excerpt is None
    assert result.tool_error is None
    assert result.manual_review_required is True


def test_dataclass_full():
    """All fields can be set explicitly."""
    result = NormalizedTakeoverToolResult(
        tool="subzy",
        subdomain="dead.example.com",
        provider="github_pages",
        matched=True,
        evidence_type="provider_error_token",
        confidence="tool_signal",
        http_status=404,
        error_token="There isn't a GitHub Pages site here",
        cname_chain=["dead.example.com", "example.github.io"],
        raw_excerpt="<html>GitHub Pages...</html>",
        tool_error=None,
        manual_review_required=False,
    )
    assert result.provider == "github_pages"
    assert result.matched is True
    assert result.http_status == 404
    assert result.error_token == "There isn't a GitHub Pages site here"
    assert result.cname_chain == ["dead.example.com", "example.github.io"]
    assert result.evidence_type == "provider_error_token"
    assert result.confidence == "tool_signal"
    assert result.manual_review_required is False


# ── parse_subjack_output ───────────────────────────────────────────────

def test_subjack_not_vulnerable():
    """subjack reports [Not Vulnerable] for a domain."""
    raw = "[Not Vulnerable] example.com"
    result = parse_subjack_output(raw, "example.com")
    assert result.tool == "subjack"
    assert result.subdomain == "example.com"
    assert result.matched is False
    assert result.evidence_type == "none"
    assert result.confidence == "tool_negative"


def test_subjack_vulnerable_with_service():
    """subjack reports [Vulnerable - GitHub] for a vulnerable domain."""
    raw = "[Vulnerable - GitHub] dead.example.com"
    result = parse_subjack_output(raw, "dead.example.com")
    assert result.tool == "subjack"
    assert result.subdomain == "dead.example.com"
    assert result.matched is True
    assert result.provider == "GitHub"
    assert result.evidence_type == "tool_signal"
    assert result.confidence == "tool_signal"


def test_subjack_vulnerable_multiple_lines():
    """Only the first match is returned; additional lines are skipped."""
    raw = (
        "[Not Vulnerable] safe.example.com\n"
        "[Vulnerable - Azure] dead.example.com\n"
        "[Vulnerable - AWS] another.example.com"
    )
    result = parse_subjack_output(raw, "dead.example.com")
    assert result.matched is True
    assert result.provider == "Azure"


def test_subjack_empty_output():
    """Empty output → not matched, evidence_type 'none'."""
    result = parse_subjack_output("", "empty.example.com")
    assert result.matched is False
    assert result.evidence_type == "none"
    assert result.confidence == "none"


def test_subjack_none_output():
    """None output → not matched, evidence_type 'none'."""
    result = parse_subjack_output(None, "none.example.com")  # type: ignore[arg-type]
    assert result.matched is False
    assert result.evidence_type == "none"


def test_subjack_only_whitespace():
    """Whitespace-only output → not matched."""
    result = parse_subjack_output("   \n  \n   ", "ws.example.com")
    assert result.matched is False


def test_subjack_no_match_for_subdomain():
    """When subdomain is not found in output, matched=False."""
    result = parse_subjack_output(
        "[Vulnerable - GitHub] other.example.com",
        "my.target.com",
    )
    assert result.matched is False


def test_subjack_vulnerable_without_service():
    """[Vulnerable] without service name is still matched."""
    raw = "[Vulnerable] bare.example.com"
    result = parse_subjack_output(raw, "bare.example.com")
    assert result.matched is True
    assert result.provider == "unknown"


def test_subjack_mixed_warning_lines():
    """Non-matching lines (warnings, info) are ignored."""
    raw = (
        "WARNING: some warning message\n"
        "[Not Vulnerable] safe.example.com\n"
        "INFO: processing done\n"
        "[Vulnerable - GitHub] dead.example.com\n"
    )
    result = parse_subjack_output(raw, "dead.example.com")
    assert result.matched is True
    assert result.provider == "GitHub"


def test_subjack_vulnerable_service_no_subdomain():
    """Lines with a matching service bracket but no following subdomain are skipped."""
    raw = "Processing...\n[Vulnerable - GitHub]\n[Not Vulnerable] example.com"
    result = parse_subjack_output(raw, "example.com")
    assert result.matched is False


# ── parse_subzy_output ─────────────────────────────────────────────────

def test_subzy_vulnerable_table_row():
    """subzy table row with VULNERABLE status."""
    raw = (
        "Domain           Service        Status      Vulnerable\n"
        "dead.example.com  Github         404         VULNERABLE\n"
    )
    result = parse_subzy_output(raw, "dead.example.com")
    assert result.tool == "subzy"
    assert result.subdomain == "dead.example.com"
    assert result.matched is True
    assert result.provider == "Github"
    assert result.evidence_type == "tool_signal"
    assert result.confidence == "tool_signal"


def test_subzy_not_vulnerable_table_row():
    """subzy table row with NOT_VULNERABLE status."""
    raw = (
        "Domain           Service        Status      Vulnerable\n"
        "safe.example.com  None           200         NOT_VULNERABLE\n"
    )
    result = parse_subzy_output(raw, "safe.example.com")
    assert result.matched is False
    assert result.evidence_type == "none"
    assert result.confidence == "tool_negative"


def test_subzy_multiple_rows_first_match():
    """Multiple subzy rows; first match for subdomain is returned."""
    raw = (
        "Domain               Service     Status  Vulnerable\n"
        "dead1.example.com    Github      404     VULNERABLE\n"
        "dead2.example.com    AWS         404     VULNERABLE\n"
    )
    result = parse_subzy_output(raw, "dead2.example.com")
    assert result.matched is True
    assert result.provider == "AWS"
    assert result.subdomain == "dead2.example.com"


def test_subzy_empty_output():
    """Empty subzy output → not matched."""
    result = parse_subzy_output("", "empty.example.com")
    assert result.matched is False
    assert result.evidence_type == "none"


def test_subzy_none_output():
    """None output → not matched."""
    result = parse_subzy_output(None, "none.example.com")  # type: ignore[arg-type]
    assert result.matched is False


def test_subzy_only_header_row():
    """Header-only table → not matched (no data rows)."""
    raw = "Domain           Service        Status      Vulnerable\n"
    result = parse_subzy_output(raw, "example.com")
    assert result.matched is False


def test_subzy_no_match_for_subdomain():
    """Subdomain not in table → matched=False."""
    raw = (
        "Domain           Service     Status  Vulnerable\n"
        "other.com        Github      404     VULNERABLE\n"
    )
    result = parse_subzy_output(raw, "my.target.com")
    assert result.matched is False


def test_subzy_vulnerable_lowercase():
    """Case-insensitive VULNERABLE matching."""
    raw = "dead.example.com    Github    404    vulnerable\n"
    result = parse_subzy_output(raw, "dead.example.com")
    assert result.matched is True


def test_subzy_with_extra_columns():
    """subzy output with extra columns (CNAME, error token)."""
    raw = (
        "Domain           Service   Status  Vulnerable       CNAME                     Error\n"
        "dead.example.com  Github    404     VULNERABLE       dead.github.io            There isn't a GitHub Pages site\n"
    )
    result = parse_subzy_output(raw, "dead.example.com")
    assert result.matched is True
    assert result.provider == "Github"


def test_subzy_error_status():
    """Row with ERROR status is still matched (potential issue)."""
    raw = (
        "Domain           Service   Status  Vulnerable\n"
        "err.example.com  None      ERROR   ERROR\n"
    )
    result = parse_subzy_output(raw, "err.example.com")
    assert result.matched is True
    assert result.manual_review_required is True


def test_subzy_stderr_only_output():
    """Output containing only stderr lines (no table)."""
    raw = "[STDERR]\nsome stderr output\nNo table data"
    result = parse_subzy_output(raw, "example.com")
    assert result.matched is False
    assert "stderr" in (result.tool_error or "").lower()


# ── parse_nuclei_output ────────────────────────────────────────────────

def test_nuclei_jsonl_takeover_finding():
    """Nuclei JSONL with a takeover template match."""
    raw = (
        '{"template-id":"takeover-azure","info":{"name":"Azure Takeover","severity":"high"},'
        '"host":"https://dead.example.com","matched-at":"https://dead.example.com","type":"http"}\n'
    )
    result = parse_nuclei_output(raw, "dead.example.com")
    assert result.tool == "nuclei"
    assert result.subdomain == "dead.example.com"
    assert result.matched is True
    assert result.evidence_type == "tool_signal"
    assert result.confidence == "tool_signal"


def test_nuclei_jsonl_no_takeover_template():
    """Nuclei JSONL with non-takeover template → not matched."""
    raw = (
        '{"template-id":"http-missing-security-headers","info":{"name":"Missing Headers","severity":"info"},'
        '"host":"https://example.com"}\n'
    )
    result = parse_nuclei_output(raw, "example.com")
    assert result.matched is False


def test_nuclei_empty_output():
    """Empty nuclei output → not matched."""
    result = parse_nuclei_output("", "example.com")
    assert result.matched is False


def test_nuclei_none_output():
    """None nuclei output → not matched."""
    result = parse_nuclei_output(None, "none.example.com")  # type: ignore[arg-type]
    assert result.matched is False


def test_nuclei_partial_json():
    """Partially valid JSON line → graceful degradation, not matched."""
    raw = '{"template-id":"tak\n'  # truncated JSON
    result = parse_nuclei_output(raw, "example.com")
    assert result.matched is False
    assert result.evidence_type == "none"


def test_nuclei_info_only_lines():
    """Nuclei output with info-level only lines (no JSON)."""
    raw = (
        "[INF] Current nuclei version: v3.1.0\n"
        "[INF] Using templates from: /templates\n"
        "[WRN] No templates matched for the target\n"
    )
    result = parse_nuclei_output(raw, "example.com")
    assert result.matched is False


def test_nuclei_mixed_json_and_plain():
    """Mixed JSON and plain lines → parses valid JSON, ignores plain."""
    raw = (
        "[INF] Starting scan...\n"
        '{"template-id":"takeover-github","info":{"name":"GitHub Takeover","severity":"medium"},'
        '"host":"https://dead.example.com"}\n'
        "[INF] Scan completed.\n"
    )
    result = parse_nuclei_output(raw, "dead.example.com")
    assert result.matched is True
    assert "github" in result.provider.lower()


# ── normalize_manual_curl_result ───────────────────────────────────────

def test_manual_curl_github_pages_404():
    """404 with GitHub Pages error token."""
    result = normalize_manual_curl_result(
        status=404,
        body="There isn't a GitHub Pages site here.",
        headers={"Server": "GitHub.com"},
        subdomain="dead.example.com",
    )
    assert result.tool == "manual_curl"
    assert result.subdomain == "dead.example.com"
    assert result.http_status == 404
    assert result.error_token == "There isn't a GitHub Pages site here."
    assert result.evidence_type == "provider_error_token"
    assert result.matched is True


def test_manual_curl_200_not_takeover():
    """200 OK without error tokens → not matched."""
    result = normalize_manual_curl_result(
        status=200,
        body="<html>Welcome to my site</html>",
        headers={"Content-Type": "text/html"},
        subdomain="live.example.com",
    )
    assert result.matched is False
    assert result.evidence_type == "none"


def test_manual_curl_connection_error():
    """Connection error → matched=False, tool_error set."""
    result = normalize_manual_curl_result(
        status=0,
        body="",
        headers={},
        subdomain="nonexistent.example.com",
    )
    assert result.matched is False
    assert result.tool_error is not None


def test_manual_curl_empty_body_excerpt():
    """Long body is truncated in raw_excerpt."""
    long_body = "x" * 2000
    result = normalize_manual_curl_result(
        status=404,
        body=long_body,
        headers={},
        subdomain="big.example.com",
    )
    assert result.raw_excerpt is not None
    assert len(result.raw_excerpt) <= 1000


def test_manual_curl_body_none():
    """body=None is handled gracefully."""
    result = normalize_manual_curl_result(
        status=200,
        body=None,  # type: ignore[arg-type]
        headers={},
        subdomain="test.example.com",
    )
    assert result.raw_excerpt is None
    assert result.matched is False


# ── normalize_tool_result dispatcher ────────────────────────────────────

def test_dispatcher_routes_to_subjack():
    """Dispatcher routes 'subjack' to parse_subjack_output."""
    raw = "[Vulnerable - GitHub] dead.example.com"
    result = normalize_tool_result("subjack", raw, "dead.example.com")
    assert result.tool == "subjack"
    assert result.matched is True
    assert result.provider == "GitHub"


def test_dispatcher_routes_to_subzy():
    """Dispatcher routes 'subzy' to parse_subzy_output."""
    raw = "dead.example.com    Github    404    VULNERABLE\n"
    result = normalize_tool_result("subzy", raw, "dead.example.com")
    assert result.tool == "subzy"
    assert result.matched is True


def test_dispatcher_routes_to_nuclei():
    """Dispatcher routes 'nuclei' to parse_nuclei_output."""
    raw = (
        '{"template-id":"takeover-azure","info":{"name":"Azure Takeover"},'
        '"host":"https://dead.example.com"}\n'
    )
    result = normalize_tool_result("nuclei", raw, "dead.example.com")
    assert result.tool == "nuclei"
    assert result.matched is True


def test_dispatcher_unknown_tool():
    """Unknown tool name → normalized result with tool name preserved."""
    result = normalize_tool_result("unknown_tool", "some output", "example.com")
    assert result.tool == "unknown_tool"
    assert result.subdomain == "example.com"
    assert result.matched is False
    assert result.raw_excerpt is not None
    assert "some output" in (result.raw_excerpt or "")


def test_dispatcher_none_output():
    """None output from any tool → not matched, evidence_type 'none'."""
    result = normalize_tool_result("subjack", None, "example.com")  # type: ignore[arg-type]
    assert result.matched is False
    assert result.evidence_type == "none"


def test_dispatcher_empty_string():
    """Empty string from any tool → not matched."""
    result = normalize_tool_result("subzy", "", "example.com")
    assert result.matched is False


def test_dispatcher_manual_curl_not_routable():
    """manual_curl is not a parser-only tool; dispatcher returns not-matched for raw text."""
    result = normalize_tool_result("manual_curl", "some raw output", "example.com")
    assert result.tool == "manual_curl"
    assert result.matched is False
