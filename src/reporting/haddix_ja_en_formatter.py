"""
HaddixJaEnFormatter: Japanese-English paired vulnerability report formatter.

Produces a paired report with:
1. Japanese summary section (comprehension aid for Japanese-speaking teams)
2. English submission section (ready-to-submit Bug Bounty report)

English submission section is the **authoritative** text for severity, impact,
remediation, and reproduction. Japanese section is generated from canonical
finding fields and execution notes for understanding purposes only.

Initial version: no free-form translation layer. Japanese content is
template-generated from canonical finding fields.
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from pathlib import Path

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover - fallback only
    ZoneInfo = None

from src.reporting.haddix_formatter import HaddixFinding


# ---------------------------------------------------------------------------
# HaddixJaEnFormatter
# ---------------------------------------------------------------------------

class HaddixJaEnFormatter:
    """
    Japanese-English paired Haddix report formatter.

    Takes normalized findings, execution notes, and metadata, and produces
    a Markdown report with two sections:

    - **Japanese summary**: template-generated from canonical finding fields
      (title, severity, target_url, summary, impact) and execution notes.
      Purpose: comprehension aid for Japanese-speaking team members.

    - **English submission**: submission-ready report formatted from canonical
      finding fields with English labels. This is the authoritative section
      for Bug Bounty program submission.
    """

    def __init__(self):
        self._findings: List[HaddixFinding] = []
        self._target: str = ""
        self._program_name: str = ""
        self._source_session: str = ""
        self._execution_notes: List[Dict[str, Any]] = []
        self._scenario_coverage: Dict[str, Any] = {}
        self._vulnerability_family_coverage: Dict[str, Any] = {}
        self._initial_release_gate: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Setters (mirror HaddixFormatter interface)
    # ------------------------------------------------------------------

    @staticmethod
    def _now_jst() -> datetime:
        if ZoneInfo is not None:
            try:
                return datetime.now(ZoneInfo("Asia/Tokyo"))
            except Exception:
                pass
        return datetime.now(timezone(timedelta(hours=9)))

    @staticmethod
    def _normalize_url_string(url: str) -> str:
        from urllib.parse import urlsplit, urlunsplit
        try:
            parts = urlsplit(str(url or "").strip())
            scheme = parts.scheme.lower() if parts.scheme else "https"
            netloc = parts.netloc.lower() or parts.hostname or ""
            path = parts.path or "/"
            query = parts.query
            return str(urlunsplit((scheme, netloc, path, query, ""))).strip().rstrip("/")
        except Exception:
            return str(url or "").strip()

    def set_target(self, target: str, program_name: str = "") -> None:
        self._target = self._normalize_url_string(target)
        self._program_name = program_name

    def set_source_session(self, session_path: str) -> None:
        self._source_session = str(session_path or "").strip()

    def add_finding(self, finding: HaddixFinding) -> None:
        self._findings.append(finding)

    def add_finding_from_dict(self, data: Dict[str, Any]) -> None:
        finding = HaddixFinding(
            title=str(data.get("title", "") or ""),
            severity=str(data.get("severity", "") or "info"),
            vuln_type=str(data.get("vuln_type", "") or ""),
            target_url=str(data.get("target_url", "") or ""),
            summary=str(data.get("summary", "") or ""),
            impact=str(data.get("impact", "") or ""),
            steps_to_reproduce=data.get("steps_to_reproduce", []) or [],
            poc_request=str(data.get("poc_request", "") or ""),
            poc_response=str(data.get("poc_response", "") or ""),
            payloads_used=data.get("payloads_used", []) or [],
            references=data.get("references", []) or [],
            cwe=data.get("cwe"),
            cvss=data.get("cvss"),
            discovered_by=str(data.get("discovered_by", "SHIGOKU") or "SHIGOKU"),
            discovered_at=datetime.now(),
            confidence=float(data.get("confidence", 0.0) or 0.0),
            tags=data.get("tags", []) or [],
            additional_info=data.get("additional_info", {}) or {},
        )
        self._findings.append(finding)

    def set_execution_notes(self, notes: List[Dict[str, Any]]) -> None:
        self._execution_notes = self._deduplicate_execution_notes(notes or [])

    def set_scenario_coverage(self, coverage: Dict[str, Any]) -> None:
        self._scenario_coverage = coverage if isinstance(coverage, dict) else {}

    def set_vulnerability_family_coverage(self, coverage: Dict[str, Any]) -> None:
        self._vulnerability_family_coverage = coverage if isinstance(coverage, dict) else {}

    def set_initial_release_gate(self, gate: Dict[str, Any]) -> None:
        self._initial_release_gate = gate if isinstance(gate, dict) else {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate_execution_notes(notes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: set = set()
        result: List[Dict[str, Any]] = []
        for note in notes:
            if not isinstance(note, dict):
                continue
            key = (
                str(note.get("url", "")),
                str(note.get("vuln_type", "")),
                str(note.get("status", "")),
            )
            if key not in seen:
                seen.add(key)
                result.append(note)
        return result

    @staticmethod
    def _severity_emoji(severity: str) -> str:
        mapping = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵",
        }
        return mapping.get(str(severity).lower(), "⚪")

    def _sorted_findings(self) -> List[HaddixFinding]:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(
            self._findings,
            key=lambda f: (
                severity_order.get(f.severity.lower(), 99),
                f.title.lower(),
            ),
        )

    # ------------------------------------------------------------------
    # Japanese Section
    # ------------------------------------------------------------------

    def _format_japanese_section(self) -> List[str]:
        """Generate the Japanese summary section."""
        lines: List[str] = []
        generated_now = self._now_jst()
        sorted_findings = self._sorted_findings()

        # --- Header ---
        lines.append("# SHIGOKU 脆弱性レポート（日本語サマリー）")
        lines.append("")
        lines.append(f"**Target:** {self._target}")
        if self._program_name:
            lines.append(f"**Program:** {self._program_name}")
        lines.append(f"**Generated:** {generated_now.strftime('%Y-%m-%d %H:%M:%S')} JST")
        lines.append(f"**Source Session:** {self._source_session}")
        lines.append("**Tool:** SHIGOKU - Sovereign VAPT Engine")
        lines.append("")

        # --- 概要 ---
        lines.append("## 概要")
        lines.append("")
        finding_count = len(sorted_findings)
        if finding_count == 0:
            lines.append("本スキャンでは検出された脆弱性はありませんでした。")
        else:
            lines.append(f"本レポートは {finding_count} 件の脆弱性を検出しました。")
            severity_counts: Dict[str, int] = {}
            for f in sorted_findings:
                sev = f.severity.lower()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            sev_parts = []
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = severity_counts.get(sev, 0)
                if count > 0:
                    emoji = self._severity_emoji(sev)
                    sev_parts.append(f"{emoji} {sev.upper()}: {count}件")
            if sev_parts:
                lines.append("深刻度内訳: " + ", ".join(sev_parts))
        lines.append("")

        # --- 重要Finding一覧 ---
        if sorted_findings:
            lines.append("## 検出された脆弱性一覧")
            lines.append("")
            lines.append("| # | 深刻度 | 種類 | タイトル | 対象URL |")
            lines.append("|---|--------|------|----------|---------|")
            for i, f in enumerate(sorted_findings, 1):
                emoji = self._severity_emoji(f.severity)
                lines.append(
                    f"| {i} | {emoji} {f.severity.upper()} | {f.vuln_type} | {f.title} | `{f.target_url}` |"
                )
            lines.append("")

        # --- Finding Details ---
        if sorted_findings:
            lines.append("## 各脆弱性の詳細サマリー")
            lines.append("")
            for i, f in enumerate(sorted_findings, 1):
                emoji = self._severity_emoji(f.severity)
                lines.append(f"### {i}. {emoji} [{f.severity.upper()}] {f.title}")
                lines.append("")
                lines.append(f"- **種類:** {f.vuln_type}")
                lines.append(f"- **対象URL:** `{f.target_url}`")
                if f.cwe:
                    lines.append(f"- **CWE:** {f.cwe}")
                if f.summary:
                    lines.append(f"- **概要:** {f.summary}")
                if f.impact:
                    lines.append(f"- **影響:** {f.impact}")
                if f.steps_to_reproduce:
                    lines.append("- **再現手順:**")
                    for step in f.steps_to_reproduce:
                        lines.append(f"  1. {step}")
                lines.append("")
                lines.append(f"詳細な英語提出用レポートは「Submission Report」セクションを参照してください。")
                lines.append("")

        # --- Execution Notes ---
        if self._execution_notes:
            lines.append("## 実行ログサマリー")
            lines.append("")
            lines.append("| URL | 種類 | ステータス | 所要時間(秒) | リトライ |")
            lines.append("|-----|------|------------|--------------|----------|")
            for note in self._execution_notes:
                url = str(note.get("url", ""))
                vuln_type = str(note.get("vuln_type", ""))
                status = str(note.get("status", ""))
                duration = note.get("duration_seconds")
                retry = int(note.get("retry_count", 0) or 0)
                duration_str = f"{duration}" if duration is not None else "-"
                lines.append(
                    f"| `{url}` | {vuln_type} | {status} | {duration_str} | {retry} |"
                )
            lines.append("")
            total = len(self._execution_notes)
            completed = sum(1 for n in self._execution_notes
                          if str(n.get("status", "")).lower() in {"completed", "cache_hit"})
            lines.append(f"合計: {total} 件, 成功: {completed} 件")
            lines.append("")

        # --- 提出時の注意 ---
        lines.append("## 提出時の注意")
        lines.append("")
        lines.append("- 本セクションは日本語での理解補助を目的としています。")
        lines.append("- 企業への脆弱性提出には「Submission Report (English / Ready to Submit)」セクションを使用してください。")
        lines.append("- 深刻度・影響・修正策の正式な内容は英語セクションを正本とします。")
        lines.append("- 日本語サマリーの内容は canonical finding fields から自動生成されており、翻訳精度を保証するものではありません。")
        lines.append("")

        return lines

    # ------------------------------------------------------------------
    # English Section
    # ------------------------------------------------------------------

    def _format_english_section(self) -> List[str]:
        """Generate the English submission section."""
        lines: List[str] = []
        sorted_findings = self._sorted_findings()

        # --- Header ---
        lines.append("# Submission Report (English / Ready to Submit)")
        lines.append("")
        lines.append(f"**Target:** {self._target}")
        if self._program_name:
            lines.append(f"**Program:** {self._program_name}")
        generated_now = self._now_jst()
        lines.append(f"**Generated:** {generated_now.strftime('%Y-%m-%d %H:%M:%S')} JST")
        lines.append(f"**Source Session:** {self._source_session}")
        lines.append("**Tool:** SHIGOKU - Sovereign VAPT Engine")
        lines.append("")

        # --- Summary ---
        finding_count = len(sorted_findings)
        if finding_count == 0:
            lines.append("## Summary")
            lines.append("")
            lines.append("No vulnerabilities were detected in this scan.")
            lines.append("")
        else:
            lines.append("## Executive Summary")
            lines.append("")
            lines.append(f"This report contains {finding_count} vulnerability finding(s) "
                         f"discovered during automated security assessment of the target.")
            lines.append("")
            severity_counts: Dict[str, int] = {}
            for f in sorted_findings:
                sev = f.severity.lower()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            lines.append("### Severity Breakdown")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = severity_counts.get(sev, 0)
                if count > 0:
                    emoji = self._severity_emoji(sev)
                    lines.append(f"| {emoji} {sev.upper()} | {count} |")
            lines.append("")

        # --- Findings ---
        if sorted_findings:
            lines.append("## Vulnerability Findings")
            lines.append("")
            for i, f in enumerate(sorted_findings, 1):
                lines.extend(self._format_english_finding(i, f))
                lines.append("")

        # --- Scenario Coverage ---
        if self._scenario_coverage:
            lines.append("## Scenario Coverage")
            lines.append("")
            covered = int(self._scenario_coverage.get("covered_count", 0) or 0)
            required = int(self._scenario_coverage.get("required_count", 0) or 0)
            rate = float(self._scenario_coverage.get("coverage_rate", 0.0) or 0.0)
            missing = self._scenario_coverage.get("missing_scenarios", [])
            if not isinstance(missing, list):
                missing = []
            lines.append(f"Coverage: {covered}/{required} ({rate * 100:.1f}%), "
                         f"Missing: {', '.join(str(s) for s in missing) if missing else '-'}")
            lines.append("")

        # --- Gate ---
        if self._vulnerability_family_coverage:
            gate_passed = bool(self._vulnerability_family_coverage.get("gate_passed", False))
            reached = self._normalize_string_list(
                self._vulnerability_family_coverage.get("reached_families", [])
            )
            required_fams = self._normalize_string_list(
                self._vulnerability_family_coverage.get("required_families", [])
            )
            missing_fams = self._normalize_string_list(
                self._vulnerability_family_coverage.get("missing_families", [])
            )
            lines.append("## Vulnerability Family Coverage Gate")
            lines.append("")
            lines.append(f"Gate: {'PASS' if gate_passed else 'FAIL'}, "
                         f"Coverage: {len(reached)}/{len(required_fams)}")
            lines.append(f"Missing families: {', '.join(missing_fams) if missing_fams else '-'}")
            lines.append("")

        if self._initial_release_gate:
            gate_status = str(self._initial_release_gate.get("status", "") or "").strip()
            lines.append("## Initial Release Gate")
            lines.append("")
            lines.append(f"Status: **{gate_status.upper() if gate_status else '-'}**")
            reason_codes = self._normalize_string_list(
                self._initial_release_gate.get("reason_codes", [])
            )
            lines.append(f"Reason Codes: {', '.join(reason_codes) if reason_codes else '-'}")
            lines.append("")

        return lines

    def _format_english_finding(self, index: int, finding: HaddixFinding) -> List[str]:
        """Format a single finding for the English submission section."""
        lines: List[str] = []
        emoji = self._severity_emoji(finding.severity)
        report_date = finding.discovered_at.strftime("%Y-%m-%d")

        lines.append(f"### {index}. {emoji} [{finding.severity.upper()}] {finding.title}")
        lines.append("")

        # Description
        lines.append("#### Description")
        lines.append(f"- **Vulnerability Type:** {finding.vuln_type}")
        if finding.cwe:
            lines.append(f"- **CWE:** {finding.cwe}")
        lines.append(f"- **Endpoint:** `{finding.target_url}`")
        lines.append(f"- **Discovery Date:** {report_date}")
        lines.append(f"- **Discovered By:** {finding.discovered_by}")
        lines.append("")

        if finding.summary:
            lines.append("#### Summary")
            lines.append("")
            lines.append(finding.summary)
            lines.append("")

        # Steps to Reproduce
        if finding.steps_to_reproduce:
            lines.append("#### Steps to Reproduce")
            lines.append("")
            for j, step in enumerate(finding.steps_to_reproduce, 1):
                lines.append(f"{j}. {step}")
            lines.append("")

        # Proof of Concept
        if finding.poc_request:
            lines.append("#### Proof of Concept — Request")
            lines.append("")
            lines.append("```http")
            lines.append(finding.poc_request)
            lines.append("```")
            lines.append("")

        if finding.poc_response:
            lines.append("#### Proof of Concept — Response")
            lines.append("")
            lines.append("```http")
            lines.append(finding.poc_response)
            lines.append("```")
            lines.append("")

        # Payloads
        if finding.payloads_used:
            lines.append("#### Payloads Used")
            lines.append("")
            for payload in finding.payloads_used:
                lines.append(f"- `{payload}`")
            lines.append("")

        # Impact
        if finding.impact:
            lines.append("#### Impact")
            lines.append("")
            lines.append(finding.impact)
            lines.append("")

        # Remediation
        if finding.impact or finding.vuln_type:
            lines.append("#### Remediation")
            lines.append("")
            lines.append(self._english_remediation_text(finding))
            lines.append("")

        lines.append("---")
        return lines

    @staticmethod
    def _english_remediation_text(finding: HaddixFinding) -> str:
        """Generate English remediation text based on vulnerability type."""
        vuln_type = finding.vuln_type.lower() if finding.vuln_type else ""
        _remediations: Dict[str, str] = {
            "sqli": (
                "Use parameterized queries (prepared statements) for all database "
                "access. Never concatenate user input into SQL queries. Apply "
                "input validation and use an ORM with safe query builders."
            ),
            "xss": (
                "Apply context-aware output encoding for all user-supplied content. "
                "Use Content-Security-Policy headers. Validate and sanitize input, "
                "and prefer framework-provided auto-escaping templates."
            ),
            "idor": (
                "Implement proper authorization checks for every resource access. "
                "Use indirect object references (e.g., UUIDs or random tokens) "
                "instead of predictable sequential IDs. Verify ownership on every request."
            ),
            "csrf": (
                "Implement anti-CSRF tokens in all state-changing requests. "
                "Use SameSite cookie attribute set to Strict or Lax. "
                "Validate the Origin/Referer header."
            ),
            "ssrf": (
                "Implement a strict allow-list for outbound requests. Validate "
                "and sanitize all user-supplied URLs. Block requests to internal "
                "IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."
            ),
        }
        for key, text in _remediations.items():
            if key in vuln_type:
                return text

        return (
            "Apply the principle of least privilege. Validate and sanitize all "
            "user inputs at the boundary. Use secure defaults and follow "
            "OWASP guidelines for the identified vulnerability class."
        )

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_string_list(value: Any) -> list:
        if isinstance(value, str):
            return [value.strip()] if value.strip() else []
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()]
        return []

    # ------------------------------------------------------------------
    # Main output
    # ------------------------------------------------------------------

    def format_markdown(self) -> str:
        """Generate the ja-en paired Markdown report."""
        lines: List[str] = []

        # Japanese Summary Section
        lines.extend(self._format_japanese_section())

        # English Submission Section
        lines.extend(self._format_english_section())

        return "\n".join(lines)

    def save_markdown(self, output_path: Path) -> None:
        """Write the paired report to a file."""
        content = self.format_markdown()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")

    def get_findings_count(self) -> int:
        return len(self._findings)

    def clear(self) -> None:
        self._findings.clear()
        self._target = ""
        self._program_name = ""
        self._source_session = ""
        self._execution_notes.clear()
        self._scenario_coverage.clear()
        self._vulnerability_family_coverage.clear()
        self._initial_release_gate.clear()


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def generate_haddix_ja_en_report(
    findings: List[Dict[str, Any]],
    target: str,
    output_path: Path,
    program_name: str = "",
    execution_notes: Optional[List[Dict[str, Any]]] = None,
    scenario_coverage: Optional[Dict[str, Any]] = None,
    vulnerability_family_coverage: Optional[Dict[str, Any]] = None,
    initial_release_gate: Optional[Dict[str, Any]] = None,
    source_session: str = "",
) -> None:
    """
    Generate a ja-en paired Haddix report from findings.

    Args:
        findings: List of finding dicts with canonical fields.
        target: Target URL.
        output_path: Output file path (haddix_report_<timestamp>.md).
        program_name: Optional program name.
        execution_notes: Execution log entries.
        scenario_coverage: SCN01-12 scenario coverage data.
        vulnerability_family_coverage: Vulnerability family coverage gate data.
        initial_release_gate: Initial release gate evaluation result.
        source_session: Path to the source session file.
    """
    formatter = HaddixJaEnFormatter()
    formatter.set_target(target, program_name)
    formatter.set_source_session(source_session)
    formatter.set_execution_notes(execution_notes or [])
    formatter.set_scenario_coverage(scenario_coverage or {})
    formatter.set_vulnerability_family_coverage(vulnerability_family_coverage or {})
    formatter.set_initial_release_gate(initial_release_gate or {})

    for f in findings:
        formatter.add_finding_from_dict(f)

    formatter.save_markdown(output_path)
