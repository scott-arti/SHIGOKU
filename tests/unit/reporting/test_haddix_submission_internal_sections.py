"""
TDD tests for HaddixSubmissionInternalFormatter (SGK-2026-0345 P0).

Covers the plan's acceptance criteria for the submission/internal split and
Japanese-first ordering. These tests are written before the implementation
and drive the minimum clean design.

Reference: docs/shigoku/plans/2026-07-07_haddix-submission-internal-ja-first-report-plan_plan.md
           sections 3.1, 6, 10 (acceptance criteria).
"""
from datetime import datetime
from pathlib import Path

import pytest

from src.reporting.haddix_formatter import HaddixFinding, generate_haddix_report
from src.reporting.haddix_submission_internal_formatter import (
    HaddixSubmissionInternalFormatter,
    generate_haddix_submission_internal_report,
    generate_separated_report_files,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_confirmed_finding(
    title: str = "Reflected XSS in `name` on `/vulnerabilities/xss_r/`",
    severity: str = "medium",
    vuln_type: str = "xss",
    target_url: str = "http://127.0.0.1:4280/vulnerabilities/xss_r/?name=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    summary: str = "Reflected XSS payload executes in the browser.",
    impact: str = "Session theft and DOM manipulation.",
    poc_request: str = (
        "GET /vulnerabilities/xss_r/?name=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\n"
        "Host: 127.0.0.1:4280\n"
        "Cookie: PHPSESSID=secret-session-token; security=low"
    ),
    poc_response: str = (
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/html\n"
        "\n"
        "<html><body><script>alert(1)</script></body></html>"
    ),
    payloads_used: list | None = None,
    additional_info: dict | None = None,
) -> HaddixFinding:
    return HaddixFinding(
        title=title,
        severity=severity,
        vuln_type=vuln_type,
        target_url=target_url,
        summary=summary,
        impact=impact,
        steps_to_reproduce=["Send the payload to the `name` parameter."],
        poc_request=poc_request,
        poc_response=poc_response,
        payloads_used=payloads_used or ['"><script>alert(1)</script>'],
        references=[],
        cwe="CWE-79",
        cvss=None,
        discovered_by="SHIGOKU",
        discovered_at=datetime.now(),
        confidence=0.9,
        tags=[],
        additional_info=additional_info or {
            "tested_params": ["name"],
            "detection_mode": "phase1",
            "browser_execution": {
                "dialog_observed": True,
                "dialog_text": "alert(1)",
                "executor": "playwright",
            },
        },
    )


def _make_candidate_finding() -> HaddixFinding:
    """A finding that the quality filter demotes to candidate (no full PoC)."""
    return HaddixFinding(
        title="Potential SQL injection surface (candidate)",
        severity="medium",
        vuln_type="sqli",
        target_url="http://127.0.0.1:4280/vulnerabilities/sqli/",
        summary="Heuristic candidate generated from execution telemetry; manual verification required.",
        poc_request="",
        poc_response="",
        payloads_used=[],
        references=[],
        cwe=None,
        cvss=None,
        discovered_by="SHIGOKU",
        discovered_at=datetime.now(),
        confidence=0.3,
        tags=["manual_verify"],
        additional_info={
            "heuristic_candidate": True,
            "verification_required": True,
            "detection_mode": "heuristic_fallback",
            "reason_code": "insufficient_validation",
        },
    )


def _basic_formatter_with_confirmed_finding() -> HaddixSubmissionInternalFormatter:
    fmt = HaddixSubmissionInternalFormatter()
    fmt.set_target("http://127.0.0.1:4280", program_name="DVWA Lab")
    fmt.set_source_session("/tmp/sessions/session_20260707_004741.json")
    fmt.add_finding(_make_confirmed_finding())
    return fmt


# ---------------------------------------------------------------------------
# Top-level structural headings
# ---------------------------------------------------------------------------

class TestTopLevelStructure:
    def test_starts_with_submission_report_heading(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        assert md.startswith("# 提出用レポート / Submission Report"), \
            "Report must begin with the submission report heading"

    def test_has_copy_scope_section_in_submission_scope(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        assert "## コピー範囲 / Copy Scope" in submission_scope

    def test_has_japanese_summary_heading(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        assert "## 日本語サマリー" in submission_scope

    def test_has_english_summary_heading(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        english_scope = md.split("# Report")[1]
        assert "## English Summary" in english_scope

    def test_has_submission_findings_heading(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        assert "## Findings" in submission_scope

    def test_has_internal_review_heading(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        assert "# 内部評価（私用） / Internal Review Notes" in md

    def test_internal_section_has_execution_notes_heading(self):
        fmt = _basic_formatter_with_confirmed_finding()
        fmt.set_execution_notes([
            {"url": "http://127.0.0.1:4280/x", "vuln_type": "xss", "status": "completed",
             "duration_seconds": 1.0, "retry_count": 0, "tested_params": ["name"],
             "blind_correlation": {}},
        ])
        md = fmt.format_markdown()
        internal_scope = md.split("# 内部評価（私用） / Internal Review Notes")[1]
        assert "## 実行ログ / Execution Notes" in internal_scope

    def test_internal_section_has_scenario_coverage_heading(self):
        fmt = _basic_formatter_with_confirmed_finding()
        fmt.set_scenario_coverage({
            "required_count": 12, "covered_count": 9, "coverage_rate": 9 / 12,
            "missing_scenarios": ["scn_08_oob_external_channel_flow"],
            "coverage_items": [],
        })
        md = fmt.format_markdown()
        internal_scope = md.split("# 内部評価（私用） / Internal Review Notes")[1]
        assert "## Scenario Coverage" in internal_scope

    def test_internal_section_has_initial_release_gate_heading(self):
        fmt = _basic_formatter_with_confirmed_finding()
        fmt.set_initial_release_gate({
            "status": "fail", "reason_codes": ["confirmed_below_minimum"],
            "policy": {"confirmed_min": 3, "candidate_max": 2},
        })
        md = fmt.format_markdown()
        internal_scope = md.split("# 内部評価（私用） / Internal Review Notes")[1]
        assert "## Initial Release Gate" in internal_scope

    def test_internal_section_has_submission_readiness_diagnostics_heading(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        internal_scope = md.split("# 内部評価（私用） / Internal Review Notes")[1]
        assert "## Submission Readiness Diagnostics" in internal_scope

    def test_internal_section_has_non_submission_candidates_heading(self):
        fmt = _basic_formatter_with_confirmed_finding()
        fmt.add_finding(_make_candidate_finding())
        md = fmt.format_markdown()
        internal_scope = md.split("# 内部評価（私用） / Internal Review Notes")[1]
        assert "## 候補・保留項目 / Non-Submission Candidates" in internal_scope

    def test_internal_section_has_third_party_review_memo_heading(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        internal_scope = md.split("# 内部評価（私用） / Internal Review Notes")[1]
        assert "## 第三者指摘対応メモ" in internal_scope


# ---------------------------------------------------------------------------
# Copy scope isolation
# ---------------------------------------------------------------------------

class TestCopyScopeIsolation:
    """Acceptance: copy scope must exclude execution notes, scenario coverage,
    gate, candidate appendix, submission readiness diagnostics."""

    def test_execution_notes_excluded_from_copy_scope(self):
        fmt = _basic_formatter_with_confirmed_finding()
        fmt.set_execution_notes([
            {"url": "http://127.0.0.1:4280/x", "vuln_type": "xss", "status": "completed",
             "duration_seconds": 1.0, "retry_count": 0, "tested_params": [],
             "blind_correlation": {}},
        ])
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        assert "Injection Execution Notes" not in submission_scope
        assert "KPI:" not in submission_scope

    def test_scenario_coverage_excluded_from_copy_scope(self):
        fmt = _basic_formatter_with_confirmed_finding()
        fmt.set_scenario_coverage({
            "required_count": 12, "covered_count": 9, "coverage_rate": 9 / 12,
            "missing_scenarios": ["scn_08_oob_external_channel_flow"],
            "coverage_items": [],
        })
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        assert "## Scenario Coverage" not in submission_scope
        assert "## 🧪 Scenario Coverage" not in submission_scope

    def test_vulnerability_family_gate_excluded_from_copy_scope(self):
        fmt = _basic_formatter_with_confirmed_finding()
        fmt.set_vulnerability_family_coverage({
            "required_families": ["xss", "sqli"], "reached_families": ["xss"],
            "missing_families": ["sqli"], "gate_passed": False, "coverage_rate": 0.5,
            "coverage_items": [],
        })
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        assert "Vulnerability Family Coverage Gate" not in submission_scope

    def test_initial_release_gate_excluded_from_copy_scope(self):
        fmt = _basic_formatter_with_confirmed_finding()
        fmt.set_initial_release_gate({
            "status": "fail", "reason_codes": ["confirmed_below_minimum"],
            "policy": {"confirmed_min": 3, "candidate_max": 2},
        })
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        assert "Initial Release Gate" not in submission_scope

    def test_candidate_findings_excluded_from_copy_scope(self):
        fmt = _basic_formatter_with_confirmed_finding()
        fmt.add_finding(_make_candidate_finding())
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        # The candidate finding title must not leak into the submission scope
        assert "Potential SQL injection surface (candidate)" not in submission_scope
        assert "Non-Submission Candidates" not in submission_scope
        assert "Manual Verification Required" not in submission_scope

    def test_submission_readiness_diagnostics_excluded_from_copy_scope(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        assert "Submission Readiness Diagnostics" not in submission_scope
        assert "Confirmed PoC Missing" not in submission_scope


# ---------------------------------------------------------------------------
# Japanese-first ordering
# ---------------------------------------------------------------------------

class TestLanguageOrder:
    def test_japanese_report_before_internal_before_english_report(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        ja_pos = md.find("## 日本語サマリー")
        internal_pos = md.find("# 内部評価（私用） / Internal Review Notes")
        en_pos = md.find("# Report")
        assert ja_pos >= 0 and internal_pos >= 0 and en_pos >= 0
        assert ja_pos < internal_pos < en_pos

    def test_submission_scope_is_japanese_only_and_english_report_is_copyable(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        english_scope = md.split("# Report")[1]
        assert "## English Summary" not in submission_scope
        assert "- Impact:" not in submission_scope
        assert "Copy only this section for an English-only external submission." in english_scope
        assert "- Impact:" in english_scope

    def test_internal_finding_notes_use_finding_id_index_map(self):
        fmt = _basic_formatter_with_confirmed_finding()
        fmt.add_finding(_make_candidate_finding())
        md = fmt.format_markdown()
        internal_scope = md.split("# 内部評価（私用） / Internal Review Notes")[1]
        # Per plan 3.2: finding-level internal notes use a `Finding ID -> 内部メモ` map.
        assert "Finding ID" in internal_scope or "Finding Memo Map" in internal_scope


# ---------------------------------------------------------------------------
# Compatibility with consistency checker & gate script
# ---------------------------------------------------------------------------

class TestMachineReadableCompatibility:
    """Acceptance: consistency checker & gate script must still parse the report."""

    def test_generated_line_present(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        import re
        generated_re = re.compile(r"^\*\*Generated:\*\*\s*(.+?)\s*$", re.MULTILINE)
        assert generated_re.search(md) is not None

    def test_generated_line_ends_with_jst(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        generated_line = next(
            (line for line in md.splitlines() if line.startswith("**Generated:** ")),
            "",
        )
        assert generated_line.endswith(" JST")

    def test_source_session_line_present_with_value(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        import re
        source_re = re.compile(r"^\*\*Source Session:\*\*\s*(.+?)\s*$", re.MULTILINE)
        match = source_re.search(md)
        assert match is not None
        assert "session_20260707_004741.json" in match.group(1)

    def test_confirmed_candidate_line_present(self):
        """Gate script regex `^Confirmed:\\s*(\\d+)\\s*/\\s*Candidate:\\s*(\\d+)$`."""
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        import re
        line_re = re.compile(r"^Confirmed:\s*(\d+)\s*/\s*Candidate:\s*(\d+)\s*$", re.MULTILINE)
        match = line_re.search(md)
        assert match is not None
        assert int(match.group(1)) >= 1

    def test_confirmed_poc_missing_line_present(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        import re
        line_re = re.compile(r"^Confirmed PoC Missing:\s*(\d+)\s*$", re.MULTILINE)
        assert line_re.search(md) is not None

    def test_candidate_reason_code_missing_line_present(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        import re
        line_re = re.compile(r"^Candidate Reason-Code Missing:\s*(\d+)\s*$", re.MULTILINE)
        assert line_re.search(md) is not None

    def test_scenario_coverage_line_parses_for_consistency_checker(self):
        """Consistency checker regex requires `Coverage: X/Y (Z%), Missing: ...` line."""
        fmt = _basic_formatter_with_confirmed_finding()
        fmt.set_scenario_coverage({
            "required_count": 12, "covered_count": 9, "coverage_rate": 9 / 12,
            "missing_scenarios": ["scn_08_oob_external_channel_flow",
                                  "scn_10_semantic_business_logic",
                                  "scn_12_advanced_ssrf_internal_topology"],
            "coverage_items": [],
        })
        md = fmt.format_markdown()
        import re
        cov_re = re.compile(
            r"^Coverage:\s*(\d+)\s*/\s*(\d+)\s*\([^)]*\)\s*,\s*Missing:\s*(.+?)\s*$",
            re.MULTILINE,
        )
        match = cov_re.search(md)
        assert match is not None, "Scenario Coverage line must remain machine-readable"
        assert int(match.group(1)) == 9
        assert int(match.group(2)) == 12

    def test_family_gate_line_parses_for_gate_script(self):
        fmt = _basic_formatter_with_confirmed_finding()
        fmt.set_vulnerability_family_coverage({
            "required_families": ["xss", "sqli"], "reached_families": ["xss"],
            "missing_families": ["sqli"], "gate_passed": False, "coverage_rate": 0.5,
            "coverage_items": [],
        })
        md = fmt.format_markdown()
        import re
        gate_re = re.compile(
            r"^Gate:\s*(PASS|FAIL)\s*,\s*Coverage:\s*(\d+)\s*/\s*(\d+)\s*\([^)]*\)\s*,\s*Missing:\s*(.+?)\s*$",
            re.IGNORECASE | re.MULTILINE,
        )
        assert gate_re.search(md) is not None


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_findings_produces_valid_structure(self):
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        md = fmt.format_markdown()
        assert md.startswith("# 提出用レポート / Submission Report")
        assert "# 内部評価（私用） / Internal Review Notes" in md

    def test_no_execution_notes_produces_valid_structure(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        # Execution Notes section heading may be omitted when there are no notes
        assert md.startswith("# 提出用レポート / Submission Report")

    def test_two_findings_one_confirmed_one_candidate(self):
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(_make_confirmed_finding())
        fmt.add_finding(_make_candidate_finding())
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        # Only the confirmed finding should appear in copy scope
        assert "Reflected XSS in `name`" in submission_scope
        assert "Potential SQL injection surface (candidate)" not in submission_scope

    def test_save_markdown_writes_file(self, tmp_path):
        out = tmp_path / "haddix_report_20260707_004743.md"
        fmt = _basic_formatter_with_confirmed_finding()
        fmt.save_markdown(out)
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert content.startswith("# 提出用レポート / Submission Report")


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

class TestConvenienceFunction:
    def test_generate_writes_paired_report(self, tmp_path):
        out = tmp_path / "haddix_report_20260707_004743.md"
        findings = [_make_confirmed_finding().to_dict()]
        generate_haddix_submission_internal_report(
            findings=findings,
            target="http://127.0.0.1:4280",
            output_path=out,
            program_name="DVWA Lab",
            source_session="/tmp/sessions/session_20260707_004741.json",
        )
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert content.startswith("# 提出用レポート / Submission Report")
        assert "# 内部評価（私用） / Internal Review Notes" in content

    def test_generate_with_execution_notes_and_coverage(self, tmp_path):
        out = tmp_path / "haddix_report_20260707_004743.md"
        findings = [_make_confirmed_finding().to_dict()]
        generate_haddix_submission_internal_report(
            findings=findings,
            target="http://127.0.0.1:4280",
            output_path=out,
            program_name="DVWA Lab",
            execution_notes=[
                {"url": "http://127.0.0.1:4280/x", "vuln_type": "xss", "status": "completed",
                 "duration_seconds": 1.0, "retry_count": 0, "tested_params": [],
                 "blind_correlation": {}},
            ],
            scenario_coverage={
                "required_count": 12, "covered_count": 9, "coverage_rate": 9 / 12,
                "missing_scenarios": ["scn_08_oob_external_channel_flow"],
                "coverage_items": [],
            },
            source_session="/tmp/sessions/session_20260707_004741.json",
        )
        content = out.read_text(encoding="utf-8")
        submission_scope = content.split("# 内部評価（私用） / Internal Review Notes")[0]
        internal_scope = content.split("# 内部評価（私用） / Internal Review Notes")[1]
        assert "Coverage: 9/12" in internal_scope
        assert "Coverage: 9/12" not in submission_scope

    def test_legacy_generate_haddix_report_markdown_uses_split_renderer(self, tmp_path):
        out = tmp_path / "haddix_report_20260713_120000.md"
        findings = [_make_confirmed_finding().to_dict()]

        generate_haddix_report(
            findings=findings,
            target="http://127.0.0.1:4280",
            output_path=out,
            program_name="DVWA Lab",
            source_session="/tmp/sessions/session_20260713_115959.json",
        )

        content = out.read_text(encoding="utf-8")
        assert content.startswith("# 提出用レポート / Submission Report")
        assert "# 内部評価（私用） / Internal Review Notes" in content
        assert "**Source Session:** /tmp/sessions/session_20260713_115959.json" in content


# ---------------------------------------------------------------------------
# Real artifact compatibility simulation
# ---------------------------------------------------------------------------

class TestRealArtifactCompat:
    """Mirror the canonical report path: simulate the existing artifact shape
    so verify_report_session_consistency and check_initial_release_gate keep working."""

    def test_parse_report_metadata_extracts_expected_fields(self, tmp_path):
        out = tmp_path / "haddix_report_20260707_004743.md"
        fmt = _basic_formatter_with_confirmed_finding()
        fmt.set_scenario_coverage({
            "required_count": 12, "covered_count": 9, "coverage_rate": 9 / 12,
            "missing_scenarios": ["scn_08_oob_external_channel_flow",
                                  "scn_10_semantic_business_logic",
                                  "scn_12_advanced_ssrf_internal_topology"],
            "coverage_items": [],
        })
        fmt.save_markdown(out)

        from src.reporting.report_session_consistency import parse_report_metadata
        meta = parse_report_metadata(out)
        assert meta["source_session"] == "/tmp/sessions/session_20260707_004741.json"
        assert meta["scenario_coverage"]["covered_count"] == 9
        assert meta["scenario_coverage"]["required_count"] == 12
        assert meta["scenario_coverage"]["missing_scenarios"] == [
            "scn_08_oob_external_channel_flow",
            "scn_10_semantic_business_logic",
            "scn_12_advanced_ssrf_internal_topology",
        ]


# ---------------------------------------------------------------------------
# P1 integration: shadow verdict + redaction + synthetic exclusion
# ---------------------------------------------------------------------------

class TestEvidenceQualityShadowVerdictIntegration:
    """SGK-2026-0345 P1: shadow verdict section is rendered in the internal
    review notes and never bleeds into the submission copy scope."""

    def test_shadow_verdict_section_in_internal_scope(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        internal_scope = md.split("# 内部評価（私用） / Internal Review Notes")[1]
        assert "## Evidence Quality Shadow Verdict (P1)" in internal_scope
        assert "Evidence Quality Shadow Verdict" not in submission_scope

    def test_shadow_verdict_section_summary_counts_appear(self):
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        internal_scope = md.split("# 内部評価（私用） / Internal Review Notes")[1]
        assert "Shadow diff: total=1" in internal_scope

    def test_shadow_verdict_does_not_change_confirmed_count(self):
        """Shadow mode MUST NOT alter the existing confirmed/candidate split."""
        fmt = _basic_formatter_with_confirmed_finding()
        md = fmt.format_markdown()
        # The confirmed count in Submission Readiness Diagnostics reflects the
        # existing split, not the shadow verdict.
        assert "Confirmed: 1 / Candidate: 0" in md


class TestSubmissionRedactionIntegration:
    """Cookie/Authorization/PHPSESSID/security tokens must not appear in the
    submission copy scope even when present in the raw PoC artifacts."""

    def test_cookie_phpsessid_stripped_from_submission_scope(self):
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(HaddixFinding(
            title="XSS with cookie-bearing PoC",
            severity="medium",
            vuln_type="xss",
            target_url="http://127.0.0.1:4280/x?name=payload",
            summary="Reflected XSS with browser execution.",
            poc_request=(
                "GET /x?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\n"
                "Host: 127.0.0.1:4280\n"
                "Cookie: PHPSESSID=secret-session-id; security=low\n"
            ),
            poc_response="HTTP/1.1 200 OK\n\n<script>alert(1)</script>",
            payloads_used=["<script>alert(1)</script>"],
            additional_info={
                "tested_params": ["name"],
                "browser_execution": {"dialog_observed": True},
            },
        ))
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        assert "secret-session-id" not in submission_scope
        assert "PHPSESSID=secret-session-id" not in submission_scope

    def test_authorization_bearer_stripped_from_submission_scope(self):
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(HaddixFinding(
            title="AuthZ exposure with bearer token",
            severity="high",
            vuln_type="broken_access_control",
            target_url="http://127.0.0.1:4280/api/users/2",
            summary="User-scoped data reachable cross-account.",
            poc_request=(
                "GET /api/users/2 HTTP/1.1\n"
                "Host: 127.0.0.1:4280\n"
                "Authorization: Bearer super-secret-bearer-token\n"
            ),
            poc_response=(
                "HTTP/1.1 200 OK\n\n"
                "{\"id\":2,\"email\":\"victim@example.com\",\"api_key\":\"leaked\"}"
            ),
            payloads_used=["2"],
            additional_info={
                "authz_differential": {
                    "baseline_status": 401,
                    "test_status": 200,
                    "signals": ["email_exposed", "api_key_exposed"],
                },
            },
        ))
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        assert "super-secret-bearer-token" not in submission_scope


# ---------------------------------------------------------------------------
# SGK-2026-0348: CSRF finding type normalization
# ---------------------------------------------------------------------------

class TestCSRFNormalization:
    """SGK-2026-0348: CSRF findings stored as `misconfiguration` in raw sessions
    must be normalized to `csrf` at report-time so the evidence quality
    validator applies CSRF-specific rules (state_change_not_verified) and
    CORS remediation is not emitted for CSRF findings."""

    def _make_csrf_misconfig_finding(
        self,
        *,
        csrf_state_change: dict | None = None,
    ) -> HaddixFinding:
        return HaddixFinding(
            title="CSRF Protection Missing (Tokenless Stateful Form)",
            severity="medium",
            vuln_type="misconfiguration",
            target_url="http://127.0.0.1:4280/vulnerabilities/csrf/",
            summary="The password change form submits without anti-CSRF token validation.",
            impact="A forged request can change the victim password silently.",
            steps_to_reproduce=[
                "Submit the password change form without a CSRF token.",
                "Confirm the forged request succeeds.",
            ],
            poc_request=(
                "POST /vulnerabilities/csrf/ HTTP/1.1\n"
                "Host: 127.0.0.1:4280\n"
                "Cookie: PHPSESSID=secret-session; security=low\n"
                "\n"
                "password_new=hacked&password_conf=hacked&Change=Change"
            ),
            poc_response="HTTP/1.1 200 OK\n\nPassword Changed.",
            payloads_used=["password_new=hacked"],
            references=[],
            cwe=None,
            cvss=None,
            discovered_by="SHIGOKU",
            discovered_at=datetime.now(),
            confidence=0.7,
            tags=[],
            additional_info={
                "detection_mode": "phase1",
                "csrf_state_change": csrf_state_change or {},
            },
        )

    def test_csrf_misconfig_excluded_from_submission_scope(self):
        """A CSRF finding with vuln_type=misconfiguration and no state change
        evidence must not appear in the submission scope."""
        finding = self._make_csrf_misconfig_finding(csrf_state_change={})
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(finding)
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        assert "CSRF Protection Missing" not in submission_scope

    def test_csrf_state_change_not_verified_in_candidate_section(self):
        """The CSRF finding without state change must appear in the
        candidate section with state_change_not_verified reason code."""
        finding = self._make_csrf_misconfig_finding(csrf_state_change={})
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(finding)
        md = fmt.format_markdown()
        internal_scope = md.split("# 内部評価（私用） / Internal Review Notes")[1]
        assert "state_change_not_verified" in internal_scope
        # The finding title must appear in candidate section
        assert "CSRF Protection Missing" in internal_scope

    def test_csrf_remediation_not_cors(self):
        """A normalized CSRF finding must NOT emit CORS-based remediation
        (Access-Control-Allow-Origin) in the submission scope."""
        # Use a finding WITH state change so it stays confirmed and we
        # can check remediation text in the submission scope.
        finding = self._make_csrf_misconfig_finding(
            csrf_state_change={
                "before_state": "password=old",
                "after_state": "password=hacked",
                "forged_html_captured": True,
            },
        )
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(finding)
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        assert "Access-Control-Allow-Origin" not in submission_scope
        # CSRF-specific remediation should be present
        assert "CSRF" in submission_scope or "csrf" in submission_scope.lower()

    def test_csrf_with_state_change_stays_confirmed_and_shows_csrf_remediation(self):
        """A normalized CSRF finding with complete state change evidence
        stays confirmed and shows CSRF-specific remediation."""
        finding = self._make_csrf_misconfig_finding(
            csrf_state_change={
                "before_state": "password=old",
                "after_state": "password=hacked",
                "forged_html_captured": True,
            },
        )
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(finding)
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        # Confirmed count should include this finding
        assert "Confirmed: 1 / Candidate: 0" in md
        # Japanese remediation should be CSRF-specific
        assert "CSRFトークン" in submission_scope or "SameSite" in submission_scope


class TestSyntheticResponseExclusion:
    """HTTP/1.1 0 (and similar synthetic detector notes) must not appear as
    response evidence in the submission copy scope."""

    def test_http_zero_response_excluded_from_submission_scope(self):
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(HaddixFinding(
            title="Reflected XSS with synthetic placeholder response",
            severity="medium",
            vuln_type="xss",
            target_url="http://127.0.0.1:4280/x?name=payload",
            summary="Reflected XSS detected via response reflection.",
            poc_request=(
                "GET /x?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\n"
                "Host: 127.0.0.1:4280\n"
            ),
            poc_response="HTTP/1.1 0\n\n(internal synthetic placeholder)",
            payloads_used=["<script>alert(1)</script>"],
            additional_info={},
        ))
        md = fmt.format_markdown()
        submission_scope = md.split("# 内部評価（私用） / Internal Review Notes")[0]
        assert "HTTP/1.1 0" not in submission_scope
        # The placeholder note must also be excluded
        assert "(internal synthetic placeholder)" not in submission_scope
        # Internal scope Shadow Verdict records the synthetic classification
        internal_scope = md.split("# 内部評価（私用） / Internal Review Notes")[1]
        assert "synthetic_detector_note" in internal_scope


class TestVerificationSectionNoDuplication:
    """SGK-2026-0357 regression: reproduction steps must not be duplicated into
    the verification section of the submission report.

    The submission formatter renders reproduction steps in the dedicated
    ``再現手順`` / ``Steps to reproduce`` section. The base ``_verification_steps``
    also inlines ``steps_to_reproduce``, which leaks attack steps (e.g. "Use the
    PoC HTML to confirm data exfiltration") into the verification section and
    contradicts "confirm the vulnerability does not reproduce". The submission
    formatter must filter them out.
    """

    def test_reproduction_steps_not_inlined_into_verification(self):
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        attack_step = "4. Use the PoC HTML to confirm data exfiltration from a controlled origin."
        finding = HaddixFinding(
            title="CORS Misconfiguration: arbitrary_origin_reflection_with_credentials",
            severity="high",
            vuln_type="cors_misconfiguration",
            target_url="http://127.0.0.1:4280/vulnerabilities/api/v2/user/",
            summary="Origin reflected in ACAO header with credentials.",
            poc_request="GET /vulnerabilities/api/v2/user/ HTTP/1.1\nOrigin: https://evil.com\n",
            poc_response=(
                "HTTP/1.1 200 OK\n"
                "Access-Control-Allow-Origin: https://evil.com\n"
                "Access-Control-Allow-Credentials: true\n"
                "\n"
                '{"email":"user@example.com","role":"admin"}'
            ),
            steps_to_reproduce=[
                "1. Send GET with header: Origin: https://evil.com",
                attack_step,
            ],
            additional_info={"detection_mode": "phase1"},
        )
        fmt.add_finding(finding)
        # Direct unit-level check: the override must filter repro steps out
        steps = fmt._verification_steps(finding)
        assert attack_step not in steps
        assert "1. Send GET with header: Origin: https://evil.com" not in steps
        # The standard post-fix verification bullets must be present
        assert "修正前に成立したPoCリクエストを同条件で再送する。" in steps
        assert "修正後レスポンスで脆弱挙動（反射・実行・注入）が再現しないことを確認する。" in steps
        assert "正常系リクエストが影響を受けず動作することを回帰確認する。" in steps
        # The detection-mode line must survive (it is not a repro step)
        assert any("phase1" in s for s in steps)

        # End-to-end: render and confirm reproduce section still shows the steps
        md = fmt.format_markdown()
        assert attack_step in md  # shown in 再現手順 section


# ---------------------------------------------------------------------------
# P1-3: Reproduction steps auto-generation and validation
# ---------------------------------------------------------------------------

def _make_finding_no_repro(
    title: str = "Reflected XSS in `name` on `/vulnerabilities/xss_r/`",
    severity: str = "medium",
    vuln_type: str = "xss",
    target_url: str = "http://127.0.0.1:4280/vulnerabilities/xss_r/?name=test",
    summary: str = "Reflected XSS payload executes in the browser.",
    impact: str = "Session theft and DOM manipulation.",
    poc_request: str | None = None,
    poc_response: str | None = None,
    payloads_used: list | None = None,
    additional_info: dict | None = None,
    steps_to_reproduce: list | None = None,
) -> HaddixFinding:
    """Create a finding with optional/empty steps_to_reproduce for testing."""
    return HaddixFinding(
        title=title,
        severity=severity,
        vuln_type=vuln_type,
        target_url=target_url,
        summary=summary,
        impact=impact,
        steps_to_reproduce=steps_to_reproduce if steps_to_reproduce is not None else [],
        poc_request=poc_request or (
            "GET /vulnerabilities/xss_r/?name=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\n"
            "Host: 127.0.0.1:4280\n"
            "Cookie: PHPSESSID=redacted; security=low"
        ),
        poc_response=poc_response or (
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/html\n"
            "\n"
            "<html><body><script>alert(1)</script></body></html>"
        ),
        payloads_used=payloads_used or ['"><script>alert(1)</script>'],
        references=[],
        cwe="CWE-79",
        cvss=None,
        discovered_by="SHIGOKU",
        discovered_at=datetime.now(),
        confidence=0.9,
        tags=[],
        additional_info=additional_info or {
            "tested_params": ["name"],
            "detection_mode": "phase1",
            "browser_execution": {
                "dialog_observed": True,
                "dialog_text": "alert(1)",
                "executor": "playwright",
            },
        },
    )


def _render_submission_scope(fmt: HaddixSubmissionInternalFormatter) -> str:
    md = fmt.format_markdown()
    return md.split("# 内部評価（私用） / Internal Review Notes")[0]


def _render_english_scope(fmt: HaddixSubmissionInternalFormatter) -> str:
    md = fmt.format_markdown()
    return md.split("# Report")[1] if "# Report" in md else ""


class TestReproductionSteps:
    """P1-3: auto-generated reproduction steps and forbidden-string validation."""

    def test_repro_steps_placeholder_not_present_in_submission(self):
        """A finding with no steps_to_reproduce must NOT emit the old
        placeholder '再構成してください'."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        fmt.add_finding(_make_finding_no_repro())
        md = fmt.format_markdown()
        submission = _render_submission_scope(fmt)
        assert "再構成してください" not in submission

    def test_repro_steps_auto_generated_for_xss(self):
        """XSS finding with no steps gets auto-generated steps."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        finding = _make_finding_no_repro(
            vuln_type="xss",
            target_url="http://127.0.0.1:4280/vulnerabilities/xss_r/?name=test",
            payloads_used=['"><script>alert(1)</script>'],
            additional_info={
                "tested_params": ["name"],
                "browser_execution": {"dialog_observed": True},
            },
        )
        fmt.add_finding(finding)
        submission = _render_submission_scope(fmt)
        assert "認証済みセッションで" in submission
        assert "ペイロード" in submission
        assert "JavaScriptとして実行" in submission

    def test_repro_steps_auto_generated_for_sqli(self):
        """SQLi finding gets timing-related steps."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        finding = _make_finding_no_repro(
            vuln_type="sqli",
            target_url="http://127.0.0.1:4280/vulnerabilities/sqli/?id=1",
            payloads_used=["' OR SLEEP(3)--"],
            additional_info={
                "tested_params": ["id"],
                "sql_error_observed": True,
            },
            poc_request=(
                "GET /vulnerabilities/sqli/?id=1%27+OR+SLEEP%283%29-- HTTP/1.1\n"
                "Host: 127.0.0.1:4280\n"
                "Cookie: PHPSESSID=redacted; security=low"
            ),
            poc_response="HTTP/1.1 200 OK\n\nSQL syntax error in your SQL syntax",
        )
        fmt.add_finding(finding)
        submission = _render_submission_scope(fmt)
        assert "遅延" in submission or "timing" in submission

    def test_repro_steps_auto_generated_for_csrf(self):
        """CSRF finding gets state-change steps."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        finding = _make_finding_no_repro(
            vuln_type="csrf",
            target_url="http://127.0.0.1:4280/vulnerabilities/csrf/",
            payloads_used=["password_new=hacked"],
            additional_info={
                "tested_params": ["password_new"],
                "csrf_state_change": {
                    "before_state": "password=old",
                    "after_state": "password=hacked",
                },
            },
            poc_request=(
                "POST /vulnerabilities/csrf/ HTTP/1.1\n"
                "Host: 127.0.0.1:4280\n"
                "Cookie: PHPSESSID=redacted; security=low\n"
                "\n"
                "password_new=hacked&password_conf=hacked&Change=Change"
            ),
            poc_response="HTTP/1.1 200 OK\n\nPassword Changed.",
        )
        fmt.add_finding(finding)
        submission = _render_submission_scope(fmt)
        assert "状態変更" in submission or "Forged request" in submission

    def test_repro_steps_auto_generated_for_cors(self):
        """CORS finding gets origin-related steps."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        finding = _make_finding_no_repro(
            vuln_type="cors",
            target_url="http://127.0.0.1:4280/api/user",
            payloads_used=["Origin: https://evil.com"],
            additional_info={"tested_params": ["Origin"]},
            poc_request=(
                "GET /api/user HTTP/1.1\n"
                "Host: 127.0.0.1:4280\n"
                "Origin: https://evil.com\n"
            ),
            poc_response=(
                "HTTP/1.1 200 OK\n"
                "Access-Control-Allow-Origin: *\n"
                "\n"
                '{"user":"test"}'
            ),
        )
        fmt.add_finding(finding)
        submission = _render_submission_scope(fmt)
        assert "Origin" in submission or "Access-Control-Allow-Origin" in submission

    def test_repro_steps_forbidden_string_todo_detected(self):
        """Steps containing 'TODO' cause fail-closed."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        finding = _make_finding_no_repro(
            vuln_type="xss",
            steps_to_reproduce=["Step 1 TODO"],
        )
        fmt.add_finding(finding)
        submission = _render_submission_scope(fmt)
        assert "再現手順を自動生成できませんでした" in submission

    def test_repro_steps_forbidden_string_tbd_detected(self):
        """Steps containing 'TBD' cause fail-closed."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        finding = _make_finding_no_repro(
            vuln_type="sqli",
            steps_to_reproduce=["TBD: need to verify"],
            additional_info={
                "tested_params": ["id"],
                "sql_error_observed": True,
            },
            poc_response="HTTP/1.1 200 OK\n\nSQL syntax error",
        )
        fmt.add_finding(finding)
        submission = _render_submission_scope(fmt)
        assert "再現手順を自動生成できませんでした" in submission

    def test_repro_steps_manual_verification_required_detected(self):
        """Steps containing 'manual verification required' cause fail-closed."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        finding = _make_finding_no_repro(
            vuln_type="lfi",
            steps_to_reproduce=["manual verification required"],
            payloads_used=["../../etc/passwd"],
            additional_info={
                "tested_params": ["file"],
                "file_marker_excerpt": "root:x:0:0:",
            },
            poc_request=(
                "GET /vulnerabilities/fi/?file=../../etc/passwd HTTP/1.1\n"
                "Host: 127.0.0.1:4280\n"
                "Cookie: PHPSESSID=redacted; security=low"
            ),
            poc_response="HTTP/1.1 200 OK\n\nroot:x:0:0:root:/root:/bin/bash",
        )
        fmt.add_finding(finding)
        submission = _render_submission_scope(fmt)
        assert "再現手順を自動生成できませんでした" in submission

    def test_repro_steps_empty_string_forbidden(self):
        """Empty step strings are filtered."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        finding = _make_finding_no_repro(
            vuln_type="xss",
            steps_to_reproduce=["   "],
        )
        fmt.add_finding(finding)
        submission = _render_submission_scope(fmt)
        # Empty/whitespace steps → _has_placeholder_steps returns True
        # → auto-generate. The generated steps should be present.
        assert "JavaScriptとして実行" in submission

    def test_existing_explicit_steps_preserved(self):
        """When user-provided steps exist and are valid, they are used as-is."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        finding = _make_finding_no_repro(
            vuln_type="xss",
            steps_to_reproduce=["Send the XSS payload to parameter `name`."],
        )
        fmt.add_finding(finding)
        submission = _render_submission_scope(fmt)
        assert "Send the XSS payload" in submission
        # Auto-generated steps must NOT appear
        assert "自動生成できませんでした" not in submission

    def test_auto_generated_steps_include_target_url(self):
        """Generated steps reference the actual target URL."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        target = "http://127.0.0.1:4280/vulnerabilities/xss_r/?name=test"
        finding = _make_finding_no_repro(
            vuln_type="xss",
            target_url=target,
        )
        fmt.add_finding(finding)
        submission = _render_submission_scope(fmt)
        assert "/vulnerabilities/xss_r/" in submission

    def test_auto_generated_steps_include_payload(self):
        """Generated steps reference actual payloads."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        finding = _make_finding_no_repro(
            vuln_type="sqli",
            payloads_used=["' OR SLEEP(3)--"],
            additional_info={
                "tested_params": ["id"],
                "sql_error_observed": True,
            },
            poc_request=(
                "GET /vulnerabilities/sqli/?id=1%27+OR+SLEEP%283%29-- HTTP/1.1\n"
                "Host: 127.0.0.1:4280\n"
                "Cookie: PHPSESSID=redacted; security=low"
            ),
            poc_response="HTTP/1.1 200 OK\n\nSQL syntax error",
        )
        fmt.add_finding(finding)
        submission = _render_submission_scope(fmt)
        assert "OR SLEEP(3)" in submission


# ---------------------------------------------------------------------------
# P2-2: CORS expected result and remediation verification
# ---------------------------------------------------------------------------

class TestCORSExpectedResult:
    """P2-2: CORS findings must show CORS-specific expected result and
    remediation, not generic 入力値検証・出力エンコード text."""

    def _make_cors_finding(self) -> HaddixFinding:
        return HaddixFinding(
            title="CORS Misconfiguration: wildcard_no_credentials",
            severity="low",
            vuln_type="cors_misconfiguration",
            target_url="http://127.0.0.1:4280/vulnerabilities/api/v2/user/",
            summary="Origin reflected in ACAO header. Arbitrary origin can read response.",
            impact="Cross-origin data theft possible.",
            steps_to_reproduce=[
                "1. Send GET with header: Origin: https://evil.com",
                "2. Confirm ACAO reflects Origin",
            ],
            poc_request=(
                "GET /vulnerabilities/api/v2/user/ HTTP/1.1\n"
                "Host: 127.0.0.1:4280\n"
                "Origin: https://evil.com\n"
            ),
            poc_response=(
                "HTTP/1.1 200 OK\n"
                "Access-Control-Allow-Origin: https://evil.com\n"
                "Access-Control-Allow-Credentials: true\n"
                "\n"
                '{"email":"user@example.com","token":"secret"}'
            ),
            payloads_used=["Origin: https://evil.com"],
            additional_info={"tested_params": ["Origin"], "detection_mode": "phase1"},
        )

    def test_cors_finding_has_cors_specific_expected_result(self):
        """CORS finding should render expected result about ACAO, not generic."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        finding = self._make_cors_finding()
        result = fmt._expected_result_text(finding)
        # Must mention ACAO — the key CORS header
        assert "Access-Control-Allow-Origin" in result
        # Must NOT be the generic fallback (no ACAO mention)
        assert "入力値検証" not in result

    def test_cors_finding_remediation_is_cors_specific(self):
        """CORS finding remediation must mention ACAO/origin allow-list,
        not generic 入力値検証・出力エンコード."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        finding = self._make_cors_finding()
        remediation = fmt._remediation(finding)
        # CORS-specific keywords
        assert "Origin" in remediation or "ACAO" in remediation or "ACAO" in remediation.upper()
        # Must NOT contain generic unrelated remediation
        assert "入力値検証" not in remediation
        assert "出力エンコード" not in remediation

    def test_cors_finding_does_not_contain_reproduce_same_vulnerable_result(self):
        """CORS finding must not contain text like
        '修正後も同じ脆弱結果になることを確認する' (confirm same vulnerable result after fix)."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        finding = self._make_cors_finding()
        fmt.add_finding(finding)
        md = fmt.format_markdown()
        assert "修正後も同じ脆弱結果になることを確認する" not in md

    def test_csrf_finding_remediation_is_csrf_specific_not_cors(self):
        """CSRF finding remediation must be about token/SameSite/re-auth,
        not CORS headers."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        csrf_finding = HaddixFinding(
            title="CSRF on password change form",
            severity="medium",
            vuln_type="csrf",
            target_url="http://127.0.0.1:4280/vulnerabilities/csrf/",
            summary="Password change form lacks anti-CSRF token.",
            impact="Attacker can silently change victim password.",
            steps_to_reproduce=[
                "Submit forged password change request without CSRF token."
            ],
            poc_request=(
                "POST /vulnerabilities/csrf/ HTTP/1.1\n"
                "Host: 127.0.0.1:4280\n"
                "Cookie: PHPSESSID=redacted\n"
                "\n"
                "password_new=hacked&password_conf=hacked&Change=Change"
            ),
            poc_response="HTTP/1.1 200 OK\n\nPassword Changed.",
            payloads_used=["password_new=hacked"],
            additional_info={
                "tested_params": ["password_new"],
                "csrf_state_change": {
                    "before_state": "password=old",
                    "after_state": "password=hacked",
                    "forged_html_captured": True,
                },
            },
        )
        remediation = fmt._remediation(csrf_finding)
        # CSRF-specific keywords
        has_csrf_specific = (
            "CSRF" in remediation
            or "トークン" in remediation
            or "SameSite" in remediation
        )
        assert has_csrf_specific, f"CSRF remediation should mention token/SameSite, got: {remediation!r}"
        # Must NOT contain CORS-specific text
        assert "Access-Control-Allow-Origin" not in remediation
        assert "ACAO" not in remediation
        # "CORS設定に依存しない" (don't rely on CORS) is valid CSRF guidance.
        # Only fail if CORS appears as the primary remediation strategy
        # (e.g. "ACAO にワイルドカード").
        assert "ACAO にワイルドカード" not in remediation
        assert "Access-Control-Allow-Origin に" not in remediation


# ---------------------------------------------------------------------------
# P2-2: Vulnerability class template tests
# ---------------------------------------------------------------------------

class TestClassTemplates:
    """P2-2: Verify vulnerability class templates and template access methods."""

    def test_xss_template_contains_negative_test_and_regression_test(self):
        """XSS template must have negative test and regression test."""
        template = HaddixSubmissionInternalFormatter._CLASS_TEMPLATES["xss"]
        assert "negative_test_ja" in template
        assert "negative_test_en" in template
        assert "regression_test_ja" in template
        assert "regression_test_en" in template
        # Verify content
        assert "ペイロード" in template["negative_test_ja"]
        assert "正常" in template["regression_test_ja"]

    def test_sqli_template_contains_negative_test_and_regression_test(self):
        """SQLi template must have negative test and regression test."""
        template = HaddixSubmissionInternalFormatter._CLASS_TEMPLATES["sqli"]
        assert "negative_test_ja" in template
        assert "regression_test_ja" in template
        assert "SQLエラー" in template["negative_test_ja"] or "SQL" in template["negative_test_ja"]

    def test_cors_template_contains_negative_test_and_regression_test(self):
        """CORS template must have negative test and regression test."""
        template = HaddixSubmissionInternalFormatter._CLASS_TEMPLATES["cors"]
        assert "negative_test_ja" in template
        assert "regression_test_ja" in template
        # CORS-specific negative test
        assert "ACAO" in template["negative_test_ja"] or "Origin" in template["negative_test_ja"]

    def test_csrf_template_contains_negative_test_and_regression_test(self):
        """CSRF template must have negative test and regression test."""
        template = HaddixSubmissionInternalFormatter._CLASS_TEMPLATES["csrf"]
        assert "negative_test_ja" in template
        assert "regression_test_ja" in template
        # CSRF-specific — token or rejected
        assert (
            "トークン" in template["negative_test_ja"]
            or "拒否" in template["negative_test_ja"]
            or "403" in template["negative_test_ja"]
        )

    def test_unknown_class_falls_back_to_generic(self):
        """Unknown vuln type returns empty template dict and falls back to
        generic methods."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        # Unknown type
        finding = HaddixFinding(
            title="Unknown vulnerability",
            severity="medium",
            vuln_type="exotic_unknown_class",
            target_url="http://127.0.0.1:4280/test",
            summary="Some exotic finding.",
            poc_request="GET /test HTTP/1.1\nHost: 127.0.0.1:4280\n",
            poc_response="HTTP/1.1 200 OK\n\nok",
        )
        # Template should be empty for unknown type
        template = HaddixSubmissionInternalFormatter._get_template("exotic_unknown_class")
        assert template == {}
        # Methods should fall back gracefully
        result = fmt._expected_result_text(finding)
        # Should return non-empty fallback
        assert len(result) > 0

    def test_template_payload_substitution(self):
        """{payload} placeholder is substituted with actual payload."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        # Use a template field that contains {payload}
        result = fmt._format_template_field("xss", "negative_test", "ja", "<script>alert(1)</script>")
        assert "<script>alert(1)</script>" in result
        assert "{payload}" not in result

        # When payload is empty, the {payload} placeholder should remain
        result_no_payload = fmt._format_template_field("xss", "negative_test", "ja", "")
        assert "{payload}" in result_no_payload

    def test_verification_steps_include_negative_test(self):
        """Rendered verification steps must include template-based negative test."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        finding = _make_confirmed_finding(vuln_type="xss")
        steps = fmt._verification_steps(finding)
        # XSS negative test: "同一ペイロード" + script execution not occurring
        has_negative = any(
            "同一ペイロード" in step and ("実行されない" in step or "does not occur" in step)
            for step in steps
        )
        assert has_negative, f"Negative test not found in verification steps: {steps}"

    def test_verification_steps_include_regression_test(self):
        """Rendered verification steps must include template-based regression test."""
        fmt = HaddixSubmissionInternalFormatter()
        fmt.set_target("http://127.0.0.1:4280")
        fmt.set_source_session("/tmp/session.json")
        finding = _make_confirmed_finding(vuln_type="xss")
        steps = fmt._verification_steps(finding)
        # XSS regression test: "正常な" or "正しく表示"
        has_regression = any(
            ("正常な" in step or "正しく表示" in step)
            for step in steps
        )
        assert has_regression, f"Regression test not found in verification steps: {steps}"


# ===========================================================================
# P6-3: Submission/Internal File Separation
# ===========================================================================


class TestSeparatedReportFiles:
    def _make_finding_for_separate(self) -> dict:
        return {
            "title": "Confirmed XSS in name param",
            "severity": "high",
            "vuln_type": "xss",
            "target_url": "http://127.0.0.1:4280/vulnerabilities/xss_r/?name=test",
            "summary": "Reflected XSS confirmed.",
            "impact": "Session theft and DOM manipulation.",
            "poc_request": (
                "GET /vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\n"
                "Host: 127.0.0.1:4280\n"
            ),
            "poc_response": "HTTP/1.1 200 OK\n\n<script>alert(1)</script>",
            "payloads_used": ["<script>alert(1)</script>"],
            "steps_to_reproduce": ["Send the XSS payload to the `name` parameter."],
            "additional_info": {
                "tested_params": ["name"],
                "detection_mode": "phase1",
                "browser_execution": {
                    "dialog_observed": True,
                    "dialog_text": "alert(1)",
                    "executor": "playwright",
                    "browser_trace_id": "trace-001",
                },
            },
        }

    def _make_candidate_for_separate(self) -> dict:
        return {
            "title": "Potential SQL injection",
            "severity": "medium",
            "vuln_type": "sqli",
            "target_url": "http://127.0.0.1:4280/vulnerabilities/sqli/",
            "summary": "Heuristic candidate; manual verification required.",
            "confidence": 0.6,
            "payloads_used": ["' OR 1=1--"],
            "additional_info": {
                "heuristic_candidate": True,
                "verification_required": True,
                "detection_mode": "heuristic_fallback",
                "reason_code": "insufficient_validation",
            },
        }

    def test_submission_file_excludes_candidates(self, tmp_path):
        """submission.md has no candidate findings."""
        output_dir = tmp_path / "reports"
        result = generate_separated_report_files(
            findings=[self._make_finding_for_separate(), self._make_candidate_for_separate()],
            target="http://127.0.0.1:4280",
            output_dir=output_dir,
            source_session="/tmp/session.json",
        )
        submission_content = result["submission"].read_text(encoding="utf-8")
        assert "Potential SQL injection (candidate)" not in submission_content

    def test_submission_file_excludes_scenario_coverage(self, tmp_path):
        """No scenario coverage in submission.md."""
        output_dir = tmp_path / "reports"
        result = generate_separated_report_files(
            findings=[self._make_finding_for_separate()],
            target="http://127.0.0.1:4280",
            output_dir=output_dir,
            scenario_coverage={
                "required_count": 12, "covered_count": 9, "coverage_rate": 0.75,
                "missing_scenarios": [],
            },
            source_session="/tmp/session.json",
        )
        submission_content = result["submission"].read_text(encoding="utf-8")
        assert "Scenario Coverage" not in submission_content
        assert "12" not in submission_content.split("Coverage") if "Coverage" in submission_content else True

    def test_submission_file_excludes_internal_gate(self, tmp_path):
        """No internal gate section in submission.md."""
        output_dir = tmp_path / "reports"
        result = generate_separated_report_files(
            findings=[self._make_finding_for_separate()],
            target="http://127.0.0.1:4280",
            output_dir=output_dir,
            initial_release_gate={
                "status": "pass", "reason_codes": [],
                "policy": {"confirmed_min": 1, "candidate_max": 0},
            },
            source_session="/tmp/session.json",
        )
        submission_content = result["submission"].read_text(encoding="utf-8")
        assert "Initial Release Gate" not in submission_content

    def test_submission_file_excludes_shadow_verdict(self, tmp_path):
        """No shadow verdict section in submission.md."""
        output_dir = tmp_path / "reports"
        result = generate_separated_report_files(
            findings=[self._make_finding_for_separate()],
            target="http://127.0.0.1:4280",
            output_dir=output_dir,
            source_session="/tmp/session.json",
        )
        submission_content = result["submission"].read_text(encoding="utf-8")
        # Check section headings, not incidental mentions in header description
        assert "## Evidence Quality Shadow Verdict" not in submission_content

    def test_submission_file_excludes_finding_memo(self, tmp_path):
        """No finding memo map section in submission.md."""
        output_dir = tmp_path / "reports"
        result = generate_separated_report_files(
            findings=[self._make_finding_for_separate(), self._make_candidate_for_separate()],
            target="http://127.0.0.1:4280",
            output_dir=output_dir,
            source_session="/tmp/session.json",
        )
        submission_content = result["submission"].read_text(encoding="utf-8")
        # Finding Memo Map section heading must not appear
        assert "Finding Memo Map" not in submission_content

    def test_internal_file_contains_candidates(self, tmp_path):
        """internal.md has candidate details."""
        output_dir = tmp_path / "reports"
        result = generate_separated_report_files(
            findings=[self._make_finding_for_separate(), self._make_candidate_for_separate()],
            target="http://127.0.0.1:4280",
            output_dir=output_dir,
            source_session="/tmp/session.json",
        )
        internal_content = result["internal_md"].read_text(encoding="utf-8")
        assert "Potential SQL injection" in internal_content

    def test_internal_file_contains_gate_details(self, tmp_path):
        """internal.md has gate results."""
        output_dir = tmp_path / "reports"
        result = generate_separated_report_files(
            findings=[self._make_finding_for_separate()],
            target="http://127.0.0.1:4280",
            output_dir=output_dir,
            initial_release_gate={
                "status": "fail", "reason_codes": ["confirmed_below_minimum"],
                "policy": {"confirmed_min": 2, "candidate_max": 0},
            },
            source_session="/tmp/session.json",
        )
        internal_content = result["internal_md"].read_text(encoding="utf-8")
        assert "Initial Release Gate" in internal_content
        assert "confirmed_below_minimum" in internal_content

    def test_internal_json_produces_valid_json(self, tmp_path):
        """internal.json is valid parseable JSON."""
        import json
        output_dir = tmp_path / "reports"
        result = generate_separated_report_files(
            findings=[self._make_finding_for_separate(), self._make_candidate_for_separate()],
            target="http://127.0.0.1:4280",
            output_dir=output_dir,
            source_session="/tmp/session.json",
        )
        json_content = result["internal_json"].read_text(encoding="utf-8")
        data = json.loads(json_content)
        assert isinstance(data, dict)
        assert "meta" in data
        assert "findings" in data
        assert "finding_memo_maps" in data

    def test_internal_json_contains_evidence_ids(self, tmp_path):
        """JSON has evidence IDs."""
        import json
        output_dir = tmp_path / "reports"
        result = generate_separated_report_files(
            findings=[self._make_finding_for_separate()],
            target="http://127.0.0.1:4280",
            output_dir=output_dir,
            source_session="/tmp/session.json",
        )
        json_content = result["internal_json"].read_text(encoding="utf-8")
        data = json.loads(json_content)
        assert "evidence_ids" in data
        assert len(data["evidence_ids"]) >= 1

    def test_same_finding_id_in_both_files(self, tmp_path):
        """Same finding has same ID in both files."""
        output_dir = tmp_path / "reports"
        result = generate_separated_report_files(
            findings=[self._make_finding_for_separate()],
            target="http://127.0.0.1:4280",
            output_dir=output_dir,
            source_session="/tmp/session.json",
        )
        submission_content = result["submission"].read_text(encoding="utf-8")
        internal_content = result["internal_md"].read_text(encoding="utf-8")
        # Both should mention the confirmed finding title
        assert "Confirmed XSS in name param" in submission_content
        assert "Confirmed XSS in name param" in internal_content

    def test_no_duplicate_findings_within_single_file(self, tmp_path):
        """No finding appears twice in same file."""
        output_dir = tmp_path / "reports"
        result = generate_separated_report_files(
            findings=[self._make_finding_for_separate()],
            target="http://127.0.0.1:4280",
            output_dir=output_dir,
            source_session="/tmp/session.json",
        )
        submission_content = result["submission"].read_text(encoding="utf-8")
        # Count occurrences of the finding title
        count = submission_content.count("Confirmed XSS in name param")
        assert count == 1, f"Finding appears {count} times in submission (expected 1)"
