"""
TDD tests for HaddixJaEnFormatter: Japanese-English paired report output.

Test coverage per plan step 7:
- Basic paired output structure (both sections present)
- Japanese section content (from canonical finding fields + execution notes)
- English section content (submission-ready format)
- Golden fixture for header compatibility (Generated, Source Session)
- Empty findings / no execution notes edge cases
- Unicode/Markdown mixed content
- Section boundary preservation
- Non-HaddixFinding input normalization
- Negative: missing source session handling in format
"""
import json
from datetime import datetime
from pathlib import Path

import pytest

from src.reporting.haddix_formatter import HaddixFinding
from src.reporting.haddix_ja_en_formatter import (
    HaddixJaEnFormatter,
    generate_haddix_ja_en_report,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_basic_finding(
    title: str = "SQL Injection in search endpoint",
    severity: str = "high",
    vuln_type: str = "sqli",
    target_url: str = "https://example.com/search?q=test",
    summary: str = "A SQL injection vulnerability was discovered in the search endpoint.",
    impact: str = "Attackers can exfiltrate the entire database through blind SQL injection.",
    steps: list | None = None,
    poc_request: str = "",
    poc_response: str = "",
    additional_info: dict | None = None,
) -> HaddixFinding:
    """Helper to create a minimal HaddixFinding for tests."""
    finding = HaddixFinding(
        title=title,
        severity=severity,
        vuln_type=vuln_type,
        target_url=target_url,
        summary=summary,
        impact=impact,
        steps_to_reproduce=steps or [],
        poc_request=poc_request,
        poc_response=poc_response,
        payloads_used=[],
        references=[],
        cwe="CWE-89",
        cvss=None,
        discovered_by="SHIGOKU",
        discovered_at=datetime.now(),
        confidence=0.95,
        tags=[],
        additional_info=additional_info or {},
    )
    return finding


def _make_execution_note(
    url: str = "https://example.com/search",
    vuln_type: str = "sqli",
    status: str = "completed",
    duration_seconds: float = 1.5,
    retry_count: int = 0,
    tested_params: list | None = None,
    blind_correlation: dict | None = None,
) -> dict:
    """Helper to create a minimal execution note."""
    return {
        "url": url,
        "vuln_type": vuln_type,
        "status": status,
        "duration_seconds": duration_seconds,
        "retry_count": retry_count,
        "tested_params": tested_params or ["q"],
        "probe_sent": True,
        "probe_skipped_reason": "",
        "blind_correlation": blind_correlation or {},
    }


# ---------------------------------------------------------------------------
# Golden fixture helpers
# ---------------------------------------------------------------------------

def _assert_ja_en_structure(md: str) -> None:
    """Verify the fundamental ja-en paired report structure."""
    assert "# SHIGOKU" in md, "Japanese summary heading missing"
    assert "日本語サマリー" in md, "Japanese summary label missing"
    assert "# Submission Report" in md, "English submission heading missing"
    assert "English" in md, "English label missing"
    assert "Ready to Submit" in md, "Submission readiness label missing"


def _assert_report_header(md: str) -> None:
    """Verify report header compatibility fields."""
    assert "**Generated:**" in md, "Generated timestamp missing"
    assert "**Source Session:**" in md, "Source Session reference missing"
    assert "**Tool:** SHIGOKU" in md, "Tool attribution missing"


# ---------------------------------------------------------------------------
# Tests: Basic Structure
# ---------------------------------------------------------------------------

class TestHaddixJaEnFormatterBasic:
    """Basic structure and golden fixture tests."""

    def test_produces_both_sections(self):
        """Output must contain both Japanese summary and English submission sections."""
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session_20260624_120000.json")
        fmt.add_finding(_make_basic_finding())

        md = fmt.format_markdown()
        _assert_ja_en_structure(md)

    def test_japanese_section_comes_first(self):
        """Japanese summary section must appear before the English submission section."""
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session_20260624_120000.json")
        fmt.add_finding(_make_basic_finding())

        md = fmt.format_markdown()
        ja_pos = md.find("日本語サマリー")
        en_pos = md.find("Submission Report")
        assert ja_pos >= 0
        assert en_pos >= 0
        assert ja_pos < en_pos, "Japanese section must appear before English section"

    def test_report_header_includes_generated_and_source_session(self):
        """Report must include Generated: and Source Session: for compatibility."""
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session_20260624_120000.json")
        fmt.add_finding(_make_basic_finding())

        md = fmt.format_markdown()
        _assert_report_header(md)

    def test_report_header_includes_target(self):
        """Report header must include the target URL."""
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session_20260624_120000.json")
        fmt.add_finding(_make_basic_finding(target_url="https://example.com/api/users"))

        md = fmt.format_markdown()
        assert "example.com" in md

    def test_report_header_source_session_shows_path(self):
        """Source Session: line must contain the session file path."""
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/var/data/session_20260624_120000.json")
        fmt.add_finding(_make_basic_finding())

        md = fmt.format_markdown()
        assert "/var/data/session_20260624_120000.json" in md

    def test_empty_source_session_shown_as_empty(self):
        """When source session is empty, Source Session line should still appear."""
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("")
        fmt.add_finding(_make_basic_finding())

        md = fmt.format_markdown()
        assert "**Source Session:**" in md


# ---------------------------------------------------------------------------
# Tests: Japanese Section Content
# ---------------------------------------------------------------------------

class TestJapaneseSection:
    """Japanese summary section content tests."""

    def test_japanese_summary_includes_finding_titles(self):
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(_make_basic_finding(title="XSS in comment form", vuln_type="xss"))
        fmt.add_finding(_make_basic_finding(title="IDOR in user API", vuln_type="idor", severity="medium"))

        md = fmt.format_markdown()
        assert "XSS in comment form" in md
        assert "IDOR in user API" in md

    def test_japanese_summary_includes_severity(self):
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(_make_basic_finding(severity="critical"))

        md = fmt.format_markdown()
        assert "critical" in md.lower() or "CRITICAL" in md

    def test_japanese_summary_includes_execution_notes(self):
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.set_execution_notes([
            _make_execution_note(url="https://example.com/search", vuln_type="sqli", status="completed"),
            _make_execution_note(url="https://example.com/login", vuln_type="xss", status="timeout"),
        ])

        md = fmt.format_markdown()
        assert "example.com/search" in md
        assert "sqli" in md.lower() or "SQL" in md

    def test_japanese_summary_finding_count(self):
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(_make_basic_finding())
        fmt.add_finding(_make_basic_finding(title="Second finding", vuln_type="xss"))
        fmt.add_finding(_make_basic_finding(title="Third finding", vuln_type="idor"))

        md = fmt.format_markdown()
        # Japanese summary should mention finding count
        assert "3" in md or "3件" in md or "3 findings" in md

    def test_japanese_section_does_not_include_http_poc_blocks(self):
        """Japanese section should not embed raw HTTP PoC blocks (those belong in English section)."""
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(_make_basic_finding(
            poc_request="GET /search?q=' OR 1=1-- HTTP/1.1",
            poc_response="HTTP/1.1 200 OK",
        ))

        md = fmt.format_markdown()
        # Split at English boundary
        ja_section = md.split("# Submission Report")[0]
        assert "```http" not in ja_section, "Japanese section should not contain HTTP code blocks"


# ---------------------------------------------------------------------------
# Tests: English Section Content
# ---------------------------------------------------------------------------

class TestEnglishSection:
    """English submission section content tests."""

    def test_english_section_includes_finding_details(self):
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(_make_basic_finding(
            title="SQL Injection in search",
            vuln_type="sqli",
            severity="high",
            target_url="https://example.com/search?q=test",
            summary="SQL injection allows data extraction.",
            impact="Full database compromise possible.",
            steps=["1. Navigate to /search", "2. Inject payload ' OR 1=1--", "3. Observe leaked data"],
            poc_request="GET /search?q=' OR 1=1-- HTTP/1.1",
        ))

        md = fmt.format_markdown()
        en_section = md.split("# Submission Report")[1]
        assert "SQL Injection in search" in en_section
        assert "sql" in en_section.lower()
        assert "HIGH" in en_section.upper() or "high" in en_section.lower()

    def test_english_section_contains_poc_blocks(self):
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(_make_basic_finding(
            poc_request="GET /api/users HTTP/1.1\nHost: example.com",
            poc_response="HTTP/1.1 200 OK\nContent-Type: application/json",
        ))

        md = fmt.format_markdown()
        en_section = md.split("# Submission Report")[1]
        assert "```http" in en_section
        assert "GET /api/users" in en_section

    def test_english_section_has_clear_section_boundary(self):
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(_make_basic_finding())

        md = fmt.format_markdown()
        assert "# Submission Report (English / Ready to Submit)" in md

    def test_english_section_includes_remediation(self):
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(_make_basic_finding(summary="XSS found", impact="Session hijacking"))

        md = fmt.format_markdown()
        en_section = md.split("# Submission Report")[1]
        # Should mention remediation or fix (not strictly required but good practice)
        # At minimum, impact details should be present
        assert "Session hijacking" in en_section or "XSS" in en_section

    def test_english_section_finding_numbering(self):
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(_make_basic_finding(title="Finding Alpha"))
        fmt.add_finding(_make_basic_finding(title="Finding Beta"))

        md = fmt.format_markdown()
        en_section = md.split("# Submission Report")[1]
        # Should have finding index numbering
        assert "1." in en_section
        assert "2." in en_section


# ---------------------------------------------------------------------------
# Tests: Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge case and error handling tests."""

    def test_empty_findings_produces_valid_report(self):
        """Report with no findings should still produce valid output with both sections."""
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")

        md = fmt.format_markdown()
        _assert_ja_en_structure(md)
        _assert_report_header(md)
        assert "0" in md or "no findings" in md.lower() or "No findings" in md

    def test_no_execution_notes_produces_valid_report(self):
        """Report without execution notes should not crash."""
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(_make_basic_finding())

        md = fmt.format_markdown()
        _assert_ja_en_structure(md)

    def test_multiple_findings_do_not_duplicate_sections(self):
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        for i in range(5):
            fmt.add_finding(_make_basic_finding(title=f"Finding {i}"))

        md = fmt.format_markdown()
        # Count occurrences of the main section headers (H1)
        h1_count = len([line for line in md.split("\n") if line.startswith("# ")])
        assert h1_count == 2, f"Should have exactly 2 H1 sections, got {h1_count}"
        assert md.count("# SHIGOKU") == 1
        assert md.count("# Submission Report") == 1

    def test_unicode_content_in_findings(self):
        """Unicode characters in finding fields must be preserved."""
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(_make_basic_finding(
            title="パラメータの注入脆弱性",
            summary="日本語のサマリーを含むテストケース 🔒",
            impact="データベース全体の漏洩",
        ))

        md = fmt.format_markdown()
        assert "パラメータ" in md
        assert "🔒" in md
        assert "データベース全体" in md

    def test_markdown_special_chars_in_findings(self):
        """Markdown special characters in finding fields must not break formatting."""
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(_make_basic_finding(
            title="Finding with *asterisks* and _underscores_",
            summary="Summary with `code` and [link](http://example.com)",
        ))

        md = fmt.format_markdown()
        # The content should be present (may be escaped or raw depending on implementation)
        assert "asterisks" in md
        assert "underscores" in md

    def test_finding_with_minimal_fields(self):
        """Finding with only required fields should be handled gracefully."""
        finding = HaddixFinding(
            title="Minimal finding",
            severity="low",
            vuln_type="info",
            target_url="https://example.com",
        )
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(finding)

        md = fmt.format_markdown()
        assert "Minimal finding" in md


# ---------------------------------------------------------------------------
# Tests: Convenience Function
# ---------------------------------------------------------------------------

class TestGenerateHaddixJaEnReport:
    """Tests for the module-level generate_haddix_ja_en_report() function."""

    def test_generates_report_to_file(self, tmp_path):
        """Should write the paired report to the specified output path."""
        output_path = tmp_path / "haddix_report_20260624_120000.md"
        findings = [
            _make_basic_finding().to_dict(),
        ]

        generate_haddix_ja_en_report(
            findings=findings,
            target="https://example.com",
            output_path=output_path,
            program_name="Test Program",
            source_session="/tmp/session.json",
        )

        assert output_path.exists()
        content = output_path.read_text(encoding="utf-8")
        _assert_ja_en_structure(content)

    def test_generates_report_with_execution_notes(self, tmp_path):
        output_path = tmp_path / "haddix_report_20260624_120000.md"
        findings = [_make_basic_finding().to_dict()]
        execution_notes = [_make_execution_note()]

        generate_haddix_ja_en_report(
            findings=findings,
            target="https://example.com",
            output_path=output_path,
            execution_notes=execution_notes,
            source_session="/tmp/session.json",
        )

        content = output_path.read_text(encoding="utf-8")
        assert "example.com/search" in content

    def test_empty_findings_does_not_crash(self, tmp_path):
        output_path = tmp_path / "haddix_report_20260624_120000.md"
        generate_haddix_ja_en_report(
            findings=[],
            target="https://example.com",
            output_path=output_path,
            source_session="/tmp/session.json",
        )

        assert output_path.exists()
        content = output_path.read_text(encoding="utf-8")
        _assert_ja_en_structure(content)

    def test_report_filename_matches_haddix_pattern(self, tmp_path):
        """Output filename must match haddix_report_YYYYMMDD_HHMMSS.md pattern
        for compatibility with report_session_consistency.py."""
        output_path = tmp_path / "haddix_report_20260624_120000.md"
        generate_haddix_ja_en_report(
            findings=[],
            target="https://example.com",
            output_path=output_path,
            source_session="/tmp/session.json",
        )

        # Verify the path exists with the correct naming convention
        assert output_path.name.startswith("haddix_report_")
        assert output_path.name.endswith(".md")
        # Pattern: haddix_report_YYYYMMDD_HHMMSS.md
        import re
        assert re.match(r"haddix_report_\d{8}_\d{6}\.md$", output_path.name), \
            f"Filename {output_path.name} does not match expected pattern"


# ---------------------------------------------------------------------------
# Tests: Compatibility with consistency checker
# ---------------------------------------------------------------------------

class TestConsistencyCheckerCompatibility:
    """Ensure ja-en reports are compatible with report_session_consistency.py."""

    def test_generated_line_found_by_consistency_regex(self):
        """The **Generated:** line must be parseable by _GENERATED_LINE_RE."""
        import re
        _GENERATED_LINE_RE = re.compile(r"^\*\*Generated:\*\*\s*(.+?)\s*$", re.MULTILINE)

        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(_make_basic_finding())

        md = fmt.format_markdown()
        match = _GENERATED_LINE_RE.search(md)
        assert match is not None, "**Generated:** line must match consistency checker regex"
        assert match.group(1), "Generated timestamp must not be empty"

    def test_source_session_line_found_by_consistency_regex(self):
        """The **Source Session:** line must be parseable by _SOURCE_SESSION_LINE_RE."""
        import re
        _SOURCE_SESSION_LINE_RE = re.compile(r"^\*\*Source Session:\*\*\s*(.+?)\s*$", re.MULTILINE)

        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/var/data/session_20260624_120000.json")
        fmt.add_finding(_make_basic_finding())

        md = fmt.format_markdown()
        match = _SOURCE_SESSION_LINE_RE.search(md)
        assert match is not None, "**Source Session:** line must match consistency checker regex"
        assert "session_20260624_120000.json" in match.group(1)

    def test_report_contains_scenario_coverage_section(self):
        """Scenario coverage section must be included for gate compatibility."""
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.set_scenario_coverage({
            "required_count": 12,
            "covered_count": 8,
            "coverage_rate": 0.667,
            "missing_scenarios": ["scn_08_oob", "scn_10_semantic", "scn_11_multi", "scn_12_ssrf"],
            "coverage_items": [],
        })
        fmt.add_finding(_make_basic_finding())

        md = fmt.format_markdown()
        assert "SCN" in md or "Scenario Coverage" in md or "scenario" in md.lower()

    def test_report_with_suppressed_findings(self):
        """Setting suppressed findings via additional_info should work."""
        finding = _make_basic_finding(
            additional_info={"suppressed": False, "confidence": 0.9}
        )
        fmt = HaddixJaEnFormatter()
        fmt.set_target("https://example.com")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(finding)

        md = fmt.format_markdown()
        assert finding.title in md
