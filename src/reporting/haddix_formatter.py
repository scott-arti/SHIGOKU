"""
HaddixFormatter: Jason Haddix スタイルの脆弱性レポートフォーマッター

Phase 6.5: Bug Bounty 向けレポート生成
"""
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover - fallback only
    ZoneInfo = None

_STANDARD_UNCONFIRMED_REASON_CODES = {
    "insufficient_discovery",
    "insufficient_payload",
    "insufficient_validation",
    "insufficient_privilege",
    "insufficient_state_transition",
}

_DETECTION_CLASS_ALIASES = {
    "access_control": {
        "access_control",
        "broken_access_control",
        "broken_object_level_authorization",
        "unauthenticated_api_access",
        "authorization_bypass",
    },
    "idor_bola": {
        "idor_bola",
        "idor",
        "bola",
        "object_level_auth",
    },
    "mass_assignment": {
        "mass_assignment",
        "bopla",
        "broken_object_property_level_authorization",
    },
    "endpoint_bfla": {
        "endpoint_bfla",
        "bfla",
        "endpoint_enumeration_bfla",
        "api",
        "admin_api",
    },
}

_SCENARIO_TO_DETECTION_CLASS = {
    "scn_01_idor_bola_object_access": "idor_bola",
    "scn_02_mass_assignment_object_update": "mass_assignment",
    "scn_04_endpoint_enumeration_bfla": "endpoint_bfla",
    "scn_07_token_trust_boundary": "access_control",
}


@dataclass
class HaddixFinding:
    """Jason Haddix スタイルのファインディング"""
    # 必須フィールド
    title: str
    severity: str  # critical, high, medium, low, info
    vuln_type: str
    target_url: str
    
    # 詳細
    summary: str = ""
    impact: str = ""
    
    # 再現手順
    steps_to_reproduce: List[str] = field(default_factory=list)
    
    # PoC
    poc_request: str = ""
    poc_response: str = ""
    payloads_used: List[str] = field(default_factory=list)
    
    # 参照情報
    references: List[str] = field(default_factory=list)
    cwe: Optional[str] = None
    cvss: Optional[str] = None
    
    # メタデータ
    discovered_by: str = "SHIGOKU"
    discovered_at: datetime = field(default_factory=datetime.now)
    confidence: float = 0.0
    tags: List[str] = field(default_factory=list)
    additional_info: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return {
            "title": self.title,
            "severity": self.severity,
            "vuln_type": self.vuln_type,
            "target_url": self.target_url,
            "summary": self.summary,
            "impact": self.impact,
            "steps_to_reproduce": self.steps_to_reproduce,
            "poc_request": self.poc_request,
            "poc_response": self.poc_response,
            "payloads_used": self.payloads_used,
            "references": self.references,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "discovered_by": self.discovered_by,
            "discovered_at": self.discovered_at.isoformat(),
            "confidence": self.confidence,
            "tags": self.tags,
            "additional_info": self.additional_info,
        }


class HaddixFormatter:
    """
    Jason Haddix スタイルのレポートフォーマッター
    
    Bug Bounty Program 向けに最適化されたレポートを生成。
    
    参考: https://www.bugcrowd.com/blog/how-to-write-a-great-vulnerability-report/
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
        self._suppressed_findings: List[Dict[str, Any]] = []

    @staticmethod
    def _now_jst() -> datetime:
        if ZoneInfo is not None:
            try:
                return datetime.now(ZoneInfo("Asia/Tokyo"))
            except Exception:
                pass
        return datetime.now(timezone(timedelta(hours=9)))
    
    def set_target(self, target: str, program_name: str = "") -> None:
        """ターゲット情報を設定"""
        self._target = self._normalize_url_string(target)
        self._program_name = program_name

    def set_source_session(self, session_path: str) -> None:
        """レポート生成元セッションのパスを設定"""
        self._source_session = str(session_path or "").strip()

    def add_finding(self, finding: HaddixFinding) -> None:
        """ファインディングを追加"""
        self._findings.append(finding)

    def set_execution_notes(self, notes: List[Dict[str, Any]]) -> None:
        """実行ログ由来の補足情報（URL別試行パラメータ等）を設定"""
        self._execution_notes = self._deduplicate_execution_notes(notes or [])

    def set_scenario_coverage(self, coverage: Dict[str, Any]) -> None:
        """Interventionシナリオ(SCN01-12)のカバレッジを設定"""
        self._scenario_coverage = coverage if isinstance(coverage, dict) else {}

    def set_vulnerability_family_coverage(self, coverage: Dict[str, Any]) -> None:
        """脆弱性ファミリーカバレッジゲート情報を設定"""
        self._vulnerability_family_coverage = coverage if isinstance(coverage, dict) else {}

    def set_initial_release_gate(self, gate: Dict[str, Any]) -> None:
        """初期版リリースゲート情報を設定"""
        self._initial_release_gate = gate if isinstance(gate, dict) else {}

    def _deduplicate_execution_notes(self, notes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not notes:
            return []

        merged_notes: Dict[tuple[str, str, str], Dict[str, Any]] = {}
        ordered_keys: List[tuple[str, str, str]] = []

        for raw_note in notes:
            if not isinstance(raw_note, dict):
                continue

            url = self._normalize_url_string(str(raw_note.get("url", "") or ""))
            vuln_type = str(raw_note.get("vuln_type", "") or "").strip()
            status = str(raw_note.get("status", "") or "").strip()
            key = (url, vuln_type.lower(), status.lower())

            normalized_note: Dict[str, Any] = {
                "url": url,
                "vuln_type": vuln_type,
                "status": status,
                "duration_seconds": raw_note.get("duration_seconds"),
                "retry_count": int(raw_note.get("retry_count", 0) or 0),
                "tested_params": self._normalize_string_list(raw_note.get("tested_params", [])),
                "probe_sent": raw_note.get("probe_sent") if isinstance(raw_note.get("probe_sent"), bool) else None,
                "probe_skipped_reason": str(raw_note.get("probe_skipped_reason", "") or "").strip(),
                "blind_correlation": raw_note.get("blind_correlation", {})
                if isinstance(raw_note.get("blind_correlation"), dict)
                else {},
            }

            if key not in merged_notes:
                merged_notes[key] = normalized_note
                ordered_keys.append(key)
                continue

            current = merged_notes[key]
            if (not current.get("vuln_type") or str(current.get("vuln_type")).lower() == "unknown") and normalized_note["vuln_type"]:
                current["vuln_type"] = normalized_note["vuln_type"]
            if not current.get("status") and normalized_note["status"]:
                current["status"] = normalized_note["status"]

            current["duration_seconds"] = self._pick_stronger_duration(
                current.get("duration_seconds"),
                normalized_note.get("duration_seconds"),
            )
            current["retry_count"] = max(
                int(current.get("retry_count", 0) or 0),
                int(normalized_note.get("retry_count", 0) or 0),
            )
            current["tested_params"] = self._merge_unique_tokens(
                current.get("tested_params", []),
                normalized_note.get("tested_params", []),
            )
            current_probe_sent = current.get("probe_sent")
            normalized_probe_sent = normalized_note.get("probe_sent")
            if normalized_probe_sent is True:
                current["probe_sent"] = True
                current["probe_skipped_reason"] = ""
            elif current_probe_sent is None and normalized_probe_sent is False:
                current["probe_sent"] = False
            if current.get("probe_sent") is not True:
                current_reason = str(current.get("probe_skipped_reason", "") or "").strip()
                normalized_reason = str(normalized_note.get("probe_skipped_reason", "") or "").strip()
                if not current_reason and normalized_reason:
                    current["probe_skipped_reason"] = normalized_reason
            current["blind_correlation"] = self._pick_stronger_blind_correlation(
                current.get("blind_correlation", {}),
                normalized_note.get("blind_correlation", {}),
            )

        return [merged_notes[key] for key in ordered_keys]

    def _normalize_string_list(self, raw_values: Any) -> List[str]:
        if isinstance(raw_values, str):
            token = raw_values.strip()
            return [token] if token else []
        if not isinstance(raw_values, list):
            return []
        tokens: List[str] = []
        for value in raw_values:
            token = str(value or "").strip()
            if token and token not in tokens:
                tokens.append(token)
        return tokens

    def _merge_unique_tokens(self, first: Any, second: Any) -> List[str]:
        merged: List[str] = []
        for token in self._normalize_string_list(first) + self._normalize_string_list(second):
            if token not in merged:
                merged.append(token)
        return merged

    def _normalize_unconfirmed_reason_code(self, value: Any) -> str:
        token = str(value or "").strip().lower()
        if token in _STANDARD_UNCONFIRMED_REASON_CODES:
            return token
        return ""

    def _extract_unconfirmed_reason_codes(self, additional_info: Dict[str, Any]) -> List[str]:
        if not isinstance(additional_info, dict):
            return []

        candidates: List[str] = []
        candidates.extend(self._normalize_string_list(additional_info.get("reason_codes", [])))
        candidates.extend(self._normalize_string_list(additional_info.get("candidate_reason_codes", [])))
        candidates.extend(self._normalize_string_list(additional_info.get("demotion_reason_codes", [])))

        for key in ("reason_code", "candidate_reason_code", "demotion_reason_code"):
            token = str(additional_info.get(key, "") or "").strip()
            if token:
                candidates.append(token)

        normalized: List[str] = []
        for candidate in candidates:
            code = self._normalize_unconfirmed_reason_code(candidate)
            if code and code not in normalized:
                normalized.append(code)
        return normalized

    def _infer_unconfirmed_reason_code(
        self,
        finding: HaddixFinding,
        *,
        demoted_for_missing_poc: bool,
    ) -> str:
        if demoted_for_missing_poc:
            return "insufficient_validation"

        info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        if bool(info.get("verification_required")) or bool(info.get("heuristic_candidate")):
            return "insufficient_validation"

        scenario_hints = {token.lower() for token in self._normalize_string_list(info.get("scenario_hints", []))}
        if scenario_hints.intersection(
            {
                "scn_08_oob_external_channel_flow",
                "scn_09_multi_step_state_machine",
                "scn_10_semantic_business_logic",
                "scn_11_multi_vector_chain",
                "scn_12_advanced_ssrf_internal_topology",
            }
        ):
            return "insufficient_state_transition"

        authz = info.get("authz_differential", {}) if isinstance(info.get("authz_differential"), dict) else {}
        denied_markers = {"401", "403", "unauthorized", "forbidden"}
        if authz:
            baseline_status = str(authz.get("baseline_status", "") or "").strip().lower()
            test_status = str(authz.get("test_status", "") or "").strip().lower()
            if baseline_status in denied_markers or test_status in denied_markers:
                return "insufficient_privilege"

        status = str(info.get("status", "") or "").strip().lower()
        if status in denied_markers:
            return "insufficient_privilege"

        tested_params = self._normalize_string_list(info.get("tested_params", []))
        payloads = self._normalize_string_list(finding.payloads_used)
        blind = info.get("blind_correlation", {}) if isinstance(info.get("blind_correlation"), dict) else {}
        has_blind_signal = False
        if blind:
            time_based = blind.get("time_based", {}) if isinstance(blind.get("time_based"), dict) else {}
            oob = blind.get("oob", {}) if isinstance(blind.get("oob"), dict) else {}
            has_blind_signal = bool(blind.get("correlated")) or bool(time_based.get("confirmed")) or bool(oob.get("confirmed"))
        has_authz_signal = bool(authz)
        has_request = bool(str(finding.poc_request or "").strip())
        has_response = bool(str(finding.poc_response or "").strip())

        if not tested_params and not payloads and not has_blind_signal and not has_authz_signal and not has_request and not has_response:
            return "insufficient_discovery"
        if tested_params and not payloads and not has_blind_signal and not has_authz_signal:
            return "insufficient_payload"
        return "insufficient_validation"

    def _ensure_unconfirmed_reason_codes(
        self,
        finding: HaddixFinding,
        *,
        demoted_for_missing_poc: bool,
    ) -> List[str]:
        additional_info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        finding.additional_info = additional_info

        reason_codes = self._extract_unconfirmed_reason_codes(additional_info)
        if not reason_codes:
            reason_codes = [self._infer_unconfirmed_reason_code(finding, demoted_for_missing_poc=demoted_for_missing_poc)]

        additional_info["reason_codes"] = reason_codes
        additional_info["reason_code"] = reason_codes[0]
        return reason_codes

    def _pick_stronger_duration(self, first: Any, second: Any) -> Any:
        first_num = self._coerce_float_or_none(first)
        second_num = self._coerce_float_or_none(second)
        if first_num is None:
            return second
        if second_num is None:
            return first
        return second if second_num > first_num else first

    def _coerce_float_or_none(self, value: Any) -> Optional[float]:
        if value is None:
            return None
        try:
            return float(value)
        except Exception:
            return None

    def _pick_stronger_blind_correlation(self, first: Any, second: Any) -> Dict[str, Any]:
        first_dict = first if isinstance(first, dict) else {}
        second_dict = second if isinstance(second, dict) else {}
        if self._blind_score(second_dict) > self._blind_score(first_dict):
            return second_dict
        if self._blind_score(second_dict) == self._blind_score(first_dict) and len(second_dict) > len(first_dict):
            return second_dict
        return first_dict

    def _blind_score(self, blind: Dict[str, Any]) -> int:
        if not isinstance(blind, dict) or not blind:
            return 0
        score = 0
        time_based = blind.get("time_based", {}) if isinstance(blind.get("time_based"), dict) else {}
        oob = blind.get("oob", {}) if isinstance(blind.get("oob"), dict) else {}
        if bool(blind.get("correlated")):
            score += 4
        if bool(time_based.get("confirmed")):
            score += 2
        if bool(oob.get("confirmed")):
            score += 2
        if time_based.get("observed_latency_seconds") is not None:
            score += 1
        hits = oob.get("hits", []) if isinstance(oob.get("hits"), list) else []
        if hits:
            score += 1
        return score

    def _missing_family_reason(
        self,
        family: str,
        category_evidence: List[str],
        finding_evidence: List[str],
    ) -> str:
        if category_evidence or finding_evidence:
            return "inconsistent_coverage_state"
        reason_map = {
            "csrf": "no_completed_csrf_candidate_task",
            "xss": "no_completed_xss_candidate_task_or_xss_finding",
            "api": "no_completed_api_candidate_task_or_api_finding",
            "injection": "no_completed_injection_task_or_finding",
            "auth": "no_completed_auth_task_or_auth_finding",
            "access_control": "no_completed_access_control_task_or_finding",
            "business_logic": "no_completed_business_logic_task_or_finding",
        }
        return reason_map.get(str(family or "").strip().lower(), "no_category_or_finding_evidence")
    
    def add_finding_from_dict(self, data: Dict[str, Any]) -> None:
        """辞書からファインディングを追加"""
        additional_info = data.get("additional_info", {}) if isinstance(data.get("additional_info"), dict) else {}
        blind_note = self._blind_evidence_note(additional_info)
        authz_note = self._authz_differential_note(additional_info)
        confidence = self._coerce_confidence(data.get("confidence", 0.0))

        summary = data.get("summary", data.get("description", ""))
        if blind_note:
            summary = f"{summary} | Blind evidence: {blind_note}" if summary else f"Blind evidence: {blind_note}"
        if authz_note:
            summary = f"{summary} | AuthZ differential: {authz_note}" if summary else f"AuthZ differential: {authz_note}"

        steps = list(data.get("steps_to_reproduce", []))
        payloads_used = self._extract_payloads(data, additional_info)
        blind_steps = self._build_blind_repro_steps(additional_info)
        authz_steps = self._build_authz_repro_steps(additional_info)
        for step in blind_steps:
            if step not in steps:
                steps.append(step)
        for step in authz_steps:
            if step not in steps:
                steps.append(step)

        finding = HaddixFinding(
            title=data.get("title", "Unknown Vulnerability"),
            severity=data.get("severity", "low"),
            vuln_type=data.get("vuln_type", data.get("type", "unknown")),
            target_url=self._normalize_url_string(data.get("target_url", data.get("target", self._target))),
            summary=summary,
            impact=data.get("impact", ""),
            steps_to_reproduce=steps,
            poc_request=(
                data.get("poc_request")
                or additional_info.get("poc_request")
                or data.get("request", "")
            ),
            poc_response=(
                data.get("poc_response")
                or additional_info.get("poc_response")
                or data.get("response", "")
            ),
            payloads_used=payloads_used,
            references=data.get("references", []),
            cwe=data.get("cwe"),
            cvss=data.get("cvss"),
            discovered_by=data.get("discovered_by", data.get("source_agent", "SHIGOKU")),
            confidence=confidence,
            tags=self._normalize_string_list(data.get("tags", [])),
            additional_info=additional_info,
        )
        include, reason = self._should_include_finding(finding)
        if include:
            self._findings.append(finding)
            return

        self._suppressed_findings.append(
            {
                "title": finding.title,
                "vuln_type": finding.vuln_type,
                "severity": finding.severity,
                "target_url": finding.target_url,
                "confidence": finding.confidence,
                "reason": reason,
            }
        )
    
    def format_markdown(self) -> str:
        """Markdown 形式でレポートを生成"""
        lines = []
        sorted_findings = self._sorted_findings()
        
        # ヘッダー
        lines.append("# 🔒 Vulnerability Report")
        lines.append("")
        lines.append(f"**Target:** {self._target}")
        if self._program_name:
            lines.append(f"**Program:** {self._program_name}")
        generated_now = self._now_jst()
        lines.append(f"**Generated:** {generated_now.strftime('%Y-%m-%d %H:%M:%S')} JST")
        if self._source_session:
            lines.append(f"**Source Session:** {self._source_session}")
        lines.append("**Tool:** SHIGOKU - Sovereign VAPT Engine")
        lines.append("")

        if self._execution_notes:
            lines.append("## 🧭 Injection Execution Notes")
            lines.append("")
            lines.append("| URL | Type | Status | Duration(s) | Retry | Tested Params | Probe Sent | Probe Skip Reason | Blind Evidence |")
            lines.append("|-----|------|--------|-------------|-------|---------------|------------|-------------------|----------------|")
            timeout_count = 0
            completed_count = 0
            error_count = 0
            retry_total = 0
            for note in self._execution_notes:
                url = self._normalize_url_string(str(note.get("url", "")))
                vuln_type = str(note.get("vuln_type", ""))
                status = str(note.get("status", ""))
                status_lower = status.lower()
                if status_lower == "timeout":
                    timeout_count += 1
                elif status_lower in {"completed", "cache_hit"}:
                    completed_count += 1
                elif status_lower == "error":
                    error_count += 1
                duration = note.get("duration_seconds")
                duration_str = f"{duration}" if duration is not None else "-"
                retry_count = note.get("retry_count", 0)
                retry_total += int(retry_count or 0)
                tested_params = note.get("tested_params", [])
                tested_params_str = ", ".join(str(p) for p in tested_params) if tested_params else "-"
                probe_sent = note.get("probe_sent")
                if probe_sent is True:
                    probe_sent_str = "yes"
                elif probe_sent is False:
                    probe_sent_str = "no"
                else:
                    probe_sent_str = "-"
                probe_skipped_reason = str(note.get("probe_skipped_reason", "") or "").strip() or "-"
                blind_correlation = note.get("blind_correlation", {})
                blind_summary = self._format_blind_summary(blind_correlation)
                lines.append(
                    f"| `{url}` | {vuln_type} | {status} | {duration_str} | {retry_count} | {tested_params_str} | {probe_sent_str} | {probe_skipped_reason} | {blind_summary} |"
                )
            lines.append("")
            total_notes = len(self._execution_notes)
            timeout_rate = (timeout_count / total_notes * 100.0) if total_notes else 0.0
            avg_retry = (retry_total / total_notes) if total_notes else 0.0
            lines.append(
                f"KPI: total={total_notes}, completed={completed_count}, timeout={timeout_count}, "
                f"error={error_count}, timeout_rate={timeout_rate:.1f}%, avg_retry={avg_retry:.2f}"
            )
            lines.append("")

        if self._scenario_coverage:
            lines.append("## 🧪 Scenario Coverage (SCN01-12)")
            lines.append("")
            required_count = int(self._scenario_coverage.get("required_count", 0) or 0)
            covered_count = int(self._scenario_coverage.get("covered_count", 0) or 0)
            coverage_rate = float(self._scenario_coverage.get("coverage_rate", 0.0) or 0.0)
            missing_scenarios = self._scenario_coverage.get("missing_scenarios", [])
            if not isinstance(missing_scenarios, list):
                missing_scenarios = []
            lines.append(
                f"Coverage: {covered_count}/{required_count} ({coverage_rate * 100:.1f}%), "
                f"Missing: {', '.join(str(s) for s in missing_scenarios) if missing_scenarios else '-'}"
            )
            lines.append("")
            items = self._scenario_coverage.get("coverage_items", [])
            if isinstance(items, list) and items:
                lines.append("| Scenario | Title | Route | Covered | Count |")
                lines.append("|----------|-------|-------|---------|-------|")
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    number = int(item.get("number", 0) or 0)
                    scenario_id = str(item.get("scenario_id", "") or "").strip()
                    scenario_label = f"SCN{number:02d}" if number > 0 else (scenario_id or "-")
                    title = str(item.get("title", "") or scenario_id or "-")
                    route = str(item.get("route", "-") or "-")
                    covered = bool(item.get("covered", False))
                    count = int(item.get("count", 0) or 0)
                    lines.append(
                        f"| {scenario_label} | {title} | {route} | {'YES' if covered else 'NO'} | {count} |"
                    )
                lines.append("")

            high_friction_missing = {
                "scn_08_oob_external_channel_flow": {
                    "surface": "Password reset / email verification / invite flows",
                    "attack_path": "Token delivery channel abuse -> reset token replay -> account takeover validation",
                },
                "scn_10_semantic_business_logic": {
                    "surface": "Approval, pricing, and policy-enforced business actions",
                    "attack_path": "State/value tampering across workflow steps -> unauthorized business outcome",
                },
                "scn_11_multi_vector_chain": {
                    "surface": "Cross-endpoint trust transitions (authz + data mutation paths)",
                    "attack_path": "BOLA/IDOR foothold -> mass assignment or role mutation -> privilege escalation chain",
                },
                "scn_12_advanced_ssrf_internal_topology": {
                    "surface": "URL fetchers and server-side connector endpoints",
                    "attack_path": "Controlled callback URL -> internal host probing -> metadata/internal API access",
                },
            }
            suspicious_rows = [
                (sid, high_friction_missing[sid])
                for sid in missing_scenarios
                if sid in high_friction_missing
            ]
            if suspicious_rows:
                lines.append("### ⚠️ Suspicious High-Friction Scenarios")
                lines.append("")
                lines.append("| Scenario | Suspicious Surface | Suggested Attack Path |")
                lines.append("|----------|--------------------|-----------------------|")
                for sid, data in suspicious_rows:
                    lines.append(f"| {sid} | {data['surface']} | {data['attack_path']} |")
                lines.append("")

        if self._vulnerability_family_coverage:
            lines.append("## 🧱 Vulnerability Family Coverage Gate")
            lines.append("")
            required_families = self._normalize_string_list(self._vulnerability_family_coverage.get("required_families", []))
            missing_families = self._normalize_string_list(self._vulnerability_family_coverage.get("missing_families", []))
            reached_families = self._normalize_string_list(self._vulnerability_family_coverage.get("reached_families", []))
            gate_passed = bool(self._vulnerability_family_coverage.get("gate_passed", False))
            coverage_rate = float(self._vulnerability_family_coverage.get("coverage_rate", 0.0) or 0.0)
            lines.append(
                f"Gate: {'PASS' if gate_passed else 'FAIL'}, "
                f"Coverage: {len(reached_families)}/{len(required_families)} ({coverage_rate * 100:.1f}%), "
                f"Missing: {', '.join(missing_families) if missing_families else '-'}"
            )
            lines.append("")
            coverage_items = self._vulnerability_family_coverage.get("coverage_items", [])
            if isinstance(coverage_items, list) and coverage_items:
                lines.append("| Family | Reached | Category Evidence | Finding Evidence | Missing Reason |")
                lines.append("|--------|---------|-------------------|------------------|----------------|")
                for item in coverage_items:
                    if not isinstance(item, dict):
                        continue
                    family = str(item.get("family", "") or "").strip().lower() or "-"
                    reached = bool(item.get("reached", False))
                    category_evidence = self._normalize_string_list(item.get("category_evidence", []))
                    finding_evidence = self._normalize_string_list(item.get("finding_evidence", []))
                    category_text = ", ".join(category_evidence) if category_evidence else "-"
                    finding_text = ", ".join(finding_evidence) if finding_evidence else "-"
                    if reached:
                        missing_reason = "-"
                    else:
                        missing_reason = self._missing_family_reason(
                            family=family,
                            category_evidence=category_evidence,
                            finding_evidence=finding_evidence,
                        )
                    lines.append(
                        f"| {family} | {'YES' if reached else 'NO'} | {category_text} | {finding_text} | {missing_reason} |"
                    )
                lines.append("")

        if self._initial_release_gate:
            lines.append("## 🚦 Initial Release Gate")
            lines.append("")
            gate_status = str(self._initial_release_gate.get("status", "") or "").strip().lower()
            if gate_status == "pass":
                gate_label = "PASS"
            elif gate_status == "blocked":
                gate_label = "BLOCKED"
            else:
                gate_label = "FAIL"

            reason_codes = self._normalize_string_list(self._initial_release_gate.get("reason_codes", []))
            policy = self._initial_release_gate.get("policy", {})
            if not isinstance(policy, dict):
                policy = {}
            allowed_missing = self._normalize_string_list(policy.get("allowed_missing_scenarios", []))
            policy_notes = self._normalize_string_list(policy.get("notes", []))
            confirmed_min = int(policy.get("confirmed_min", 0) or 0)
            candidate_max = int(policy.get("candidate_max", 0) or 0)
            confirmed_poc_missing_max = int(policy.get("confirmed_poc_missing_max", 0) or 0)
            reason_code_missing_max = int(policy.get("reason_code_missing_max", 0) or 0)

            lines.append(f"Status: **{gate_label}**")
            lines.append(
                f"Policy: confirmed_min={confirmed_min}, candidate_max={candidate_max}, "
                f"confirmed_poc_missing_max={confirmed_poc_missing_max}, "
                f"reason_code_missing_max={reason_code_missing_max}, "
                f"allowed_missing={', '.join(allowed_missing) if allowed_missing else '-'}"
            )
            if policy_notes:
                for note in policy_notes:
                    lines.append(f"- {note}")
            lines.append(
                f"Reason Codes: {', '.join(reason_codes) if reason_codes else '-'}"
            )
            lines.append("")

            evaluation_context = self._initial_release_gate.get("evaluation_context", {})
            if isinstance(evaluation_context, dict) and evaluation_context:
                baseline_id = str(evaluation_context.get("baseline_id", "") or "-")
                comparison_mode = str(evaluation_context.get("comparison_mode", "") or "self_baseline")
                baseline_report_path = str(evaluation_context.get("baseline_report_path", "") or "").strip()
                baseline_session_path = str(evaluation_context.get("baseline_session_path", "") or "").strip()
                lines.append(f"Baseline: id={baseline_id}, mode={comparison_mode}")
                if baseline_report_path:
                    lines.append(f"- baseline_report_path: `{baseline_report_path}`")
                if baseline_session_path:
                    lines.append(f"- baseline_session_path: `{baseline_session_path}`")
                lines.append("")

            report_metrics = self._initial_release_gate.get("report_metrics", {})
            if isinstance(report_metrics, dict):
                baseline_diff = report_metrics.get("baseline_diff", {})
                if isinstance(baseline_diff, dict):
                    findings_diff = baseline_diff.get("findings", {})
                    if isinstance(findings_diff, dict):
                        confirmed_delta = findings_diff.get("confirmed_delta")
                        candidate_delta = findings_diff.get("candidate_delta")
                        if confirmed_delta is not None or candidate_delta is not None:
                            lines.append(
                                "Baseline Diff: "
                                f"confirmed_delta={confirmed_delta if confirmed_delta is not None else '-'}, "
                                f"candidate_delta={candidate_delta if candidate_delta is not None else '-'}"
                            )
                            lines.append("")

            actions = self._initial_release_gate.get("recommended_actions", [])
            if isinstance(actions, list) and actions:
                lines.append("### Auto Actions (Reason Code Driven)")
                lines.append("")
                lines.append("| Action ID | Priority | Owner | Summary | Command Hint |")
                lines.append("|-----------|----------|-------|---------|--------------|")
                for action in actions:
                    if not isinstance(action, dict):
                        continue
                    action_id = str(action.get("id", "") or "-")
                    priority = str(action.get("priority", "") or "-")
                    owner = str(action.get("owner", "") or "-")
                    summary = str(action.get("summary", "") or "-")
                    command_hint = str(action.get("command_hint", "") or "-")
                    lines.append(
                        f"| {action_id} | {priority} | {owner} | {summary} | `{command_hint}` |"
                    )
                lines.append("")

            deferred_scenarios = self._initial_release_gate.get("deferred_scenarios", [])
            if isinstance(deferred_scenarios, list) and deferred_scenarios:
                lines.append("### Deferred Scenario Backlog (Post-Release Track)")
                lines.append("")
                lines.append("| Scenario | Route | Trigger | Operator Input | Success Criteria |")
                lines.append("|----------|-------|---------|----------------|------------------|")
                for item in deferred_scenarios:
                    if not isinstance(item, dict):
                        continue
                    sid = str(item.get("scenario_id", "") or "-")
                    route = str(item.get("route", "") or "-")
                    trigger = str(item.get("trigger", "") or "-")
                    operator_input = str(item.get("operator_input", "") or "-")
                    success_criteria = str(item.get("success_criteria", "") or "-")
                    lines.append(
                        f"| {sid} | {route} | {trigger} | {operator_input} | {success_criteria} |"
                    )
                lines.append("")

        # サマリー
        lines.append("## 📊 Summary")
        lines.append("")
        severity_counts = {}
        for f in sorted_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            emoji = self._severity_emoji(sev)
            lines.append(f"| {emoji} {sev.upper()} | {severity_counts.get(sev, 0)} |")
        lines.append("")

        if self._suppressed_findings:
            lines.append(
                f"品質フィルタ: 低シグナル候補を {len(self._suppressed_findings)} 件除外"
            )
            lines.append("")
        
        # ファインディング詳細
        lines.append("## 🐛 Findings")
        lines.append("")

        confirmed_findings, candidate_findings = self._split_findings_by_confirmation(sorted_findings)
        lines.append(
            f"Confirmed: {len(confirmed_findings)} / Candidate: {len(candidate_findings)}"
        )
        lines.append("")
        lines.append("## 📮 Submission Readiness")
        lines.append("")
        lines.append(f"Submission-ready findings: {len(confirmed_findings)}")
        lines.append(f"Hold-back candidates: {len(candidate_findings)}")
        if candidate_findings:
            lines.append("Candidate items are separated into a non-submission appendix until manual verification is complete.")
        else:
            lines.append("All listed findings are submission-ready under the current report policy.")
        lines.append("")
        confirmed_poc_missing = 0
        for finding in confirmed_findings:
            has_request = bool(str(finding.poc_request or "").strip())
            has_response = bool(str(finding.poc_response or "").strip())
            if not (has_request and has_response):
                confirmed_poc_missing += 1
        candidate_reason_missing = 0
        if candidate_findings:
            reason_breakdown: Dict[str, int] = {}
            with_reason = 0
            for finding in candidate_findings:
                reason_codes = self._ensure_unconfirmed_reason_codes(
                    finding,
                    demoted_for_missing_poc=not (
                        bool(str(finding.poc_request or "").strip())
                        and bool(str(finding.poc_response or "").strip())
                    ),
                )
                if reason_codes:
                    with_reason += 1
                    code = reason_codes[0]
                    reason_breakdown[code] = reason_breakdown.get(code, 0) + 1
            missing_reason = len(candidate_findings) - with_reason
            candidate_reason_missing = missing_reason
            reason_breakdown_text = (
                ", ".join(f"{code}:{count}" for code, count in sorted(reason_breakdown.items()))
                if reason_breakdown
                else "-"
            )
            lines.append(
                f"Candidate Reason-Code Coverage: {with_reason}/{len(candidate_findings)} (missing={missing_reason})"
            )
            lines.append(f"Candidate Reason-Code Breakdown: {reason_breakdown_text}")
            lines.append("")
        lines.append(f"Confirmed PoC Missing: {confirmed_poc_missing}")
        lines.append(f"Candidate Reason-Code Missing: {candidate_reason_missing}")
        lines.append("")
        findings_class_summary = self._build_findings_class_summary(
            confirmed_findings=confirmed_findings,
            candidate_findings=candidate_findings,
        )
        class_rows = findings_class_summary.get("rows", [])
        if isinstance(class_rows, list) and class_rows:
            lines.append("### Findings by Vulnerability Class")
            lines.append("")
            lines.append("| Vulnerability Class | Confirmed | Candidate | Total |")
            lines.append("|---------------------|-----------|-----------|-------|")
            for row in class_rows:
                if not isinstance(row, dict):
                    continue
                vuln_class = str(row.get("vuln_class", "") or "").strip()
                if not vuln_class:
                    continue
                confirmed_count = int(row.get("confirmed", 0) or 0)
                candidate_count = int(row.get("candidate", 0) or 0)
                total_count = int(row.get("total", confirmed_count + candidate_count) or 0)
                lines.append(
                    f"| {vuln_class} | {confirmed_count} | {candidate_count} | {total_count} |"
                )
            lines.append("")

        detection_class_summary = self._build_detection_class_summary(
            confirmed_findings=confirmed_findings,
            candidate_findings=candidate_findings,
        )
        detection_rows = detection_class_summary.get("rows", [])
        if isinstance(detection_rows, list) and detection_rows:
            lines.append("### Findings by Detection Class")
            lines.append("")
            lines.append("| Detection Class | Confirmed | Candidate | Total | Scenario Backfill |")
            lines.append("|-----------------|-----------|-----------|-------|-------------------|")
            for row in detection_rows:
                if not isinstance(row, dict):
                    continue
                detection_class = str(row.get("detection_class", "") or "").strip()
                if not detection_class:
                    continue
                confirmed_count = int(row.get("confirmed", 0) or 0)
                candidate_count = int(row.get("candidate", 0) or 0)
                total_count = int(row.get("total", confirmed_count + candidate_count) or 0)
                scenario_backfill = int(row.get("scenario_backfill", 0) or 0)
                lines.append(
                    f"| {detection_class} | {confirmed_count} | {candidate_count} | {total_count} | {scenario_backfill} |"
                )
            lines.append("")

        if confirmed_findings:
            lines.append("### ✅ Confirmed Findings")
            lines.append("")
            for i, finding in enumerate(confirmed_findings, 1):
                lines.extend(self._format_finding(i, finding, include_confirmed_evidence_template=True))
                lines.append("")
        else:
            lines.append("### ✅ Confirmed Findings")
            lines.append("")
            lines.append("No confirmed findings in this run.")
            lines.append("")

        if candidate_findings:
            lines.append("### Appendix A. Non-Submission Candidates (Manual Verification Required)")
            lines.append("")
            for i, finding in enumerate(candidate_findings, 1):
                lines.extend(self._format_finding(i, finding, include_confirmed_evidence_template=False))
                lines.append("")
        
        return "\n".join(lines)
    
    def _format_finding(
        self,
        index: int,
        finding: HaddixFinding,
        *,
        include_confirmed_evidence_template: bool,
    ) -> List[str]:
        """個別ファインディングを6章テンプレートでフォーマット"""
        lines = []
        emoji = self._severity_emoji(finding.severity)
        report_date = finding.discovered_at.strftime("%Y-%m-%d")
        cvss_v4_estimate = self._estimated_cvss_v4(finding)
        component = self._component_from_url(finding.target_url)
        discovery_method = self._discovery_method(finding)
        technical_details = self._technical_details(finding)
        promotion_note = self._heuristic_promotion_note(
            finding.additional_info if isinstance(finding.additional_info, dict) else {}
        )
        cia_impact = self._cia_impact_assessment(finding)
        attack_scenario = self._attack_scenario(finding)
        remediation = self._remediation(finding)
        verification_steps = self._verification_steps(finding)
        references = self._references(finding)
        
        lines.append(f"### {index}. {emoji} [{finding.severity.upper()}] {finding.title}")
        lines.append("")

        lines.append("#### 1. 概要")
        lines.append(f"- タイトル: {finding.title}")
        lines.append(f"- 脆弱性の種類: {finding.vuln_type}")
        detection_class = self._resolve_detection_class(finding)
        if detection_class:
            lines.append(f"- Detection Class: {detection_class}")
        lines.append(f"- CVSS v4の深刻度: {cvss_v4_estimate}")
        lines.append(f"- 日付: {report_date}")
        lines.append("")

        lines.append("#### 2. 詳細な説明")
        lines.append(f"- 発見方法: {discovery_method}")
        lines.append(f"- 影響を受けるコンポーネント: {component}")
        lines.append(f"- 技術的詳細: {technical_details}")
        if not include_confirmed_evidence_template:
            reason_codes = self._ensure_unconfirmed_reason_codes(
                finding,
                demoted_for_missing_poc=not (
                    bool(str(finding.poc_request or "").strip())
                    and bool(str(finding.poc_response or "").strip())
                ),
            )
            lines.append(f"- 未成立 Reason Code: {', '.join(reason_codes) if reason_codes else '-'}")
        if promotion_note:
            lines.append(f"- 自動昇格理由: {promotion_note}")
        if include_confirmed_evidence_template:
            lines.extend(self._format_standardized_evidence_template(index, finding))
        if finding.poc_request:
            lines.append("")
            lines.append("```http")
            lines.append(finding.poc_request)
            lines.append("```")
        if finding.poc_response:
            lines.append("")
            lines.append("##### Response Evidence")
            lines.append("")
            lines.append("```http")
            lines.append(finding.poc_response)
            lines.append("```")
        if finding.payloads_used:
            lines.append("")
            lines.append("- 使用ペイロード:")
            for payload in finding.payloads_used:
                lines.append(f"  - `{payload}`")
        lines.append("")

        lines.append("#### 3. 影響分析")
        lines.append(f"- リスク評価 (CIA): {cia_impact}")
        lines.append(f"- 対象固有の影響: {self._target_specific_impact(finding)}")
        lines.append(f"- 攻撃の可能性: {attack_scenario}")
        lines.append("")

        lines.append("#### 4. 修正策の提案")
        lines.append(f"- 修正方法: {remediation}")
        lines.append("- ベストプラクティス: 入力値検証・出力時エスケープ・権限制御・セキュア設定の標準化を継続運用する。")
        lines.append("")

        lines.append("#### 5. 検証手順")
        for step_idx, step in enumerate(verification_steps, 1):
            lines.append(f"- テスト手順 {step_idx}: {step}")
        lines.append("")

        lines.append("#### 6. 参考資料とリソース")
        lines.append("- 公式ドキュメント:")
        for ref in references["official"]:
            lines.append(f"  - {ref}")
        lines.append("- 追加の参考資料:")
        for ref in references["additional"]:
            lines.append(f"  - {ref}")
        lines.append("")
        
        lines.append("---")
        
        return lines

    def _format_standardized_evidence_template(
        self,
        index: int,
        finding: HaddixFinding,
    ) -> List[str]:
        additional_info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        tested_params = self._normalize_string_list(additional_info.get("tested_params", []))
        payloads = finding.payloads_used or []
        detection_mode = str(additional_info.get("detection_mode", "") or "").strip() or "-"
        blind_note = self._blind_evidence_note(additional_info) or "-"
        authz_note = self._authz_differential_note(additional_info) or "-"
        request_available = "yes" if str(finding.poc_request or "").strip() else "no"
        response_available = "yes" if str(finding.poc_response or "").strip() else "no"
        confidence = f"{float(finding.confidence):.2f}" if finding.confidence is not None else "0.00"
        evidence_id = f"EV-{index:03d}-{str(finding.vuln_type or 'unknown').upper()}"

        payload_text = ", ".join(f"`{p}`" for p in payloads) if payloads else "-"
        params_text = ", ".join(f"`{p}`" for p in tested_params) if tested_params else "-"

        lines: List[str] = []
        lines.append("")
        lines.append("##### Evidence Template (Standardized)")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| Evidence ID | {evidence_id} |")
        lines.append(f"| Endpoint | `{finding.target_url}` |")
        lines.append(f"| Vulnerability Type | {finding.vuln_type} |")
        lines.append(f"| Detection Mode | {detection_mode} |")
        lines.append(f"| Tested Parameters | {params_text} |")
        lines.append(f"| Payload Evidence | {payload_text} |")
        lines.append(f"| Blind Evidence | {blind_note} |")
        lines.append(f"| AuthZ Differential | {authz_note} |")
        lines.append(f"| PoC Request Captured | {request_available} |")
        lines.append(f"| PoC Response Captured | {response_available} |")
        lines.append(f"| Confidence | {confidence} |")
        lines.append("")
        lines.extend(self._format_baseline_attack_comparison(finding))
        return lines

    def _format_baseline_attack_comparison(self, finding: HaddixFinding) -> List[str]:
        additional_info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        differential = additional_info.get("authz_differential", {})
        if not isinstance(differential, dict) or not differential:
            return []

        baseline_status = differential.get("baseline_status")
        attack_status = differential.get("test_status")
        original_id = differential.get("original_id")
        test_id = differential.get("test_id")
        baseline_len = differential.get("auth_body_length")
        attack_len = differential.get("test_body_length")
        delta = differential.get("body_length_delta")
        delta_ratio = differential.get("body_length_delta_ratio")
        signals = self._normalize_authz_signals(differential.get("signals", []))

        lines = ["##### Baseline vs Attack Comparison", "| Field | Value |", "|-------|-------|"]
        lines.append(f"| Baseline Status | {baseline_status if baseline_status is not None else '-'} |")
        lines.append(f"| Attack Status | {attack_status if attack_status is not None else '-'} |")
        if original_id is not None or test_id is not None:
            lines.append(f"| Resource ID Transition | {original_id if original_id is not None else '-'} -> {test_id if test_id is not None else '-'} |")
        if baseline_len is not None or attack_len is not None:
            lines.append(f"| Response Lengths | baseline={baseline_len if baseline_len is not None else '-'}, attack={attack_len if attack_len is not None else '-'} |")
        if delta is not None:
            ratio_text = f"{delta_ratio:.2f}" if isinstance(delta_ratio, (int, float)) else "-"
            lines.append(f"| Response Length Delta | {delta} (ratio={ratio_text}) |")
        if signals:
            lines.append(f"| Differential Signals | {', '.join(signals)} |")
        lines.append("")
        return lines

    def _extract_response_body_text(self, finding: HaddixFinding) -> str:
        raw_response = str(finding.poc_response or "").strip()
        if not raw_response:
            return ""
        separator = "\n\n"
        if separator in raw_response:
            return raw_response.split(separator, 1)[1].strip()
        return raw_response

    def _response_field_hints(self, finding: HaddixFinding) -> List[str]:
        response_text = self._extract_response_body_text(finding).lower()
        hints: List[str] = []
        for token in ("email", "balance", "role", "is_admin", "token", "order", "user_id", "account_id"):
            if token in response_text and token not in hints:
                hints.append(token)
        return hints

    def _target_specific_impact(self, finding: HaddixFinding) -> str:
        url = self._normalize_url_string(finding.target_url)
        split = urlsplit(url)
        path = split.path or "/"
        additional_info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        differential = additional_info.get("authz_differential", {})
        if not isinstance(differential, dict):
            differential = {}

        hints = self._response_field_hints(finding)
        hint_text = f" Observed response fields: {', '.join(hints)}." if hints else ""
        baseline_status = differential.get("baseline_status")
        attack_status = differential.get("test_status")

        vtype = str(finding.vuln_type or "").lower()
        if vtype in {"broken_access_control", "idor"} or "access_control" in vtype:
            return (
                f"The endpoint `{path}` accepted an unauthorized or cross-context request"
                f" ({baseline_status if baseline_status is not None else '-'} -> {attack_status if attack_status is not None else '-'})"
                f", which suggests attacker access to another user's resource or data path.{hint_text}"
            ).strip()
        if "mass_assignment" in vtype:
            return (
                f"The endpoint `{path}` accepted privilege-sensitive parameters during the attack request,"
                f" indicating a risk of unauthorized property mutation or privilege state tampering.{hint_text}"
            ).strip()
        return (
            f"The endpoint `{path}` produced a materially useful response for the crafted request,"
            f" which indicates a target-specific security impact that should be validated for direct business exposure.{hint_text}"
        ).strip()

    def _estimated_cvss_v4(self, finding: HaddixFinding) -> str:
        if finding.cvss:
            return str(finding.cvss)
        severity_map = {
            "critical": "9.0-10.0 (Critical)",
            "high": "7.0-8.9 (High)",
            "medium": "4.0-6.9 (Medium)",
            "low": "0.1-3.9 (Low)",
            "info": "0.0 (Informational)",
        }
        return severity_map.get((finding.severity or "").lower(), "N/A")

    def _component_from_url(self, target_url: str) -> str:
        normalized = self._normalize_url_string(target_url)
        split = urlsplit(normalized)
        if split.scheme and split.netloc:
            return urlunsplit((split.scheme, split.netloc, split.path or "/", "", ""))
        parsed = Path(normalized)
        return str(parsed) if str(parsed) else normalized

    def _normalize_url_string(self, value: str) -> str:
        """`http:/` などの崩れた URL をレポート表示用に正規化"""
        if not value:
            return ""

        normalized = str(value).strip()
        if normalized.startswith("http:/") and not normalized.startswith("http://"):
            normalized = normalized.replace("http:/", "http://", 1)
        if normalized.startswith("https:/") and not normalized.startswith("https://"):
            normalized = normalized.replace("https:/", "https://", 1)

        split = urlsplit(normalized)
        if split.scheme and split.netloc:
            path = split.path or "/"
            return urlunsplit((split.scheme.lower(), split.netloc, path, split.query, split.fragment))

        return normalized

    def _format_blind_summary(self, blind_correlation: Dict[str, Any]) -> str:
        if not isinstance(blind_correlation, dict) or not blind_correlation:
            return "-"

        time_based = blind_correlation.get("time_based", {}) if isinstance(blind_correlation.get("time_based"), dict) else {}
        oob = blind_correlation.get("oob", {}) if isinstance(blind_correlation.get("oob"), dict) else {}
        correlated = bool(blind_correlation.get("correlated"))

        time_flag = "T✅" if time_based.get("confirmed") else "T❌"
        oob_flag = "O✅" if oob.get("confirmed") else "O❌"

        parts = [f"{time_flag}/{oob_flag}"]
        if correlated:
            parts.append("correlated")

        observed_latency = time_based.get("observed_latency_seconds")
        if observed_latency:
            parts.append(f"lat={observed_latency}s")

        hit_count = len(oob.get("hits", [])) if isinstance(oob.get("hits"), list) else 0
        if hit_count:
            parts.append(f"hits={hit_count}")

        return "; ".join(parts)

    def _blind_evidence_note(self, additional_info: Dict[str, Any]) -> str:
        if not isinstance(additional_info, dict):
            return ""
        blind = additional_info.get("blind_correlation", {})
        if not isinstance(blind, dict) or not blind:
            return ""
        return self._format_blind_summary(blind)

    def _build_blind_repro_steps(self, additional_info: Dict[str, Any]) -> List[str]:
        if not isinstance(additional_info, dict):
            return []

        blind = additional_info.get("blind_correlation", {})
        if not isinstance(blind, dict) or not blind:
            return []

        steps: List[str] = []
        time_based = blind.get("time_based", {}) if isinstance(blind.get("time_based"), dict) else {}
        oob = blind.get("oob", {}) if isinstance(blind.get("oob"), dict) else {}

        if time_based.get("confirmed"):
            payload = str(time_based.get("payload", "") or "")
            latency = time_based.get("observed_latency_seconds")
            if payload:
                steps.append(f"Time-based payload `{payload}` を対象パラメータへ送信する。")
            if latency:
                steps.append(f"レスポンス遅延が約 {latency}s 観測されることを確認する。")

        oob_hits = oob.get("hits", []) if isinstance(oob.get("hits"), list) else []
        if oob.get("confirmed") and oob_hits:
            token = oob_hits[0].get("token", "")
            steps.append("OOBコールバック待受を有効化した状態で同条件リクエストを送信する。")
            if token:
                steps.append(f"トークン `{token}` へのコールバック記録が生成されることを確認する。")

        if blind.get("correlated"):
            steps.append("time-based遅延とOOB callbackが同一検証系列で同時成立することを確認する。")

        return steps

    def _authz_differential_note(self, additional_info: Dict[str, Any]) -> str:
        if not isinstance(additional_info, dict):
            return ""
        differential = additional_info.get("authz_differential", {})
        if not isinstance(differential, dict) or not differential:
            return ""
        scenario = str(differential.get("scenario", "authz_diff"))
        confidence = differential.get("confidence")
        original_id = differential.get("original_id")
        test_id = differential.get("test_id")
        baseline_status = differential.get("baseline_status")
        test_status = differential.get("test_status")
        signals = self._normalize_authz_signals(differential.get("signals", []))

        detail_tokens: List[str] = []
        if confidence is not None:
            detail_tokens.append(f"score={confidence}")
        if original_id is not None or test_id is not None:
            detail_tokens.append(f"id={original_id}->{test_id}")
        if baseline_status is not None or test_status is not None:
            detail_tokens.append(f"status={baseline_status}->{test_status}")
        if signals:
            detail_tokens.append(f"signals={', '.join(signals)}")

        if not detail_tokens:
            return scenario
        return f"{scenario} ({', '.join(detail_tokens)})"

    def _build_authz_repro_steps(self, additional_info: Dict[str, Any]) -> List[str]:
        if not isinstance(additional_info, dict):
            return []
        differential = additional_info.get("authz_differential", {})
        if not isinstance(differential, dict) or not differential:
            return []

        scenario = str(differential.get("scenario", "authz_differential"))
        baseline_status = differential.get("baseline_status")
        test_status = differential.get("test_status")
        original_id = differential.get("original_id")
        test_id = differential.get("test_id")
        signals = self._normalize_authz_signals(differential.get("signals", []))

        steps: List[str] = [f"AuthZ差分シナリオ `{scenario}` でベースラインと比較リクエストを実行する。"]
        if original_id is not None or test_id is not None:
            steps.append(f"ベースラインID `{original_id}` と検証ID `{test_id}` でアクセス差を確認する。")
        if baseline_status is not None or test_status is not None:
            steps.append(f"HTTPステータス差分（baseline={baseline_status}, test={test_status}）を確認する。")
        if signals:
            steps.append(f"レスポンス差分シグナル（{', '.join(signals)}）が再現されることを確認する。")
        return steps

    def _normalize_authz_signals(self, raw_signals: Any) -> List[str]:
        if not isinstance(raw_signals, list):
            return []

        normalized: List[str] = []
        for signal in raw_signals:
            if isinstance(signal, str):
                token = signal.strip()
                if token:
                    normalized.append(token)
                continue
            if isinstance(signal, dict):
                name = str(signal.get("name", "") or "").strip()
                if name:
                    normalized.append(name)

        deduped: List[str] = []
        for token in normalized:
            if token not in deduped:
                deduped.append(token)
        return deduped

    def _discovery_method(self, finding: HaddixFinding) -> str:
        source = finding.discovered_by or "SHIGOKU"
        return f"{source} による自動検査とペイロード検証で検出"

    def _heuristic_promotion_note(self, additional_info: Dict[str, Any]) -> str:
        if not isinstance(additional_info, dict):
            return ""

        detection_mode = str(additional_info.get("detection_mode", "") or "").strip().lower()
        if detection_mode != "heuristic_promoted":
            return ""

        repeat_signal = additional_info.get("repeat_signal", {})
        if not isinstance(repeat_signal, dict):
            return "repeated successful probes exceeded configured promotion thresholds."

        def _as_int(value: Any) -> int | None:
            try:
                return int(value)
            except Exception:
                return None

        privilege_probe = _as_int(repeat_signal.get("privilege_probe"))
        privilege_probe_min = _as_int(repeat_signal.get("privilege_probe_min"))
        completed_probe = _as_int(repeat_signal.get("completed_with_probe"))
        completed_probe_min = _as_int(repeat_signal.get("completed_with_probe_min"))
        total_signals = _as_int(repeat_signal.get("total"))

        tokens: List[str] = []
        if privilege_probe is not None and privilege_probe_min is not None:
            tokens.append(f"privilege_probe={privilege_probe}/{privilege_probe_min}")
        elif privilege_probe is not None:
            tokens.append(f"privilege_probe={privilege_probe}")

        if completed_probe is not None and completed_probe_min is not None:
            tokens.append(f"completed_with_probe={completed_probe}/{completed_probe_min}")
        elif completed_probe is not None:
            tokens.append(f"completed_with_probe={completed_probe}")

        if total_signals is not None:
            tokens.append(f"total={total_signals}")

        if not tokens:
            return "repeated successful probes exceeded configured promotion thresholds."
        return f"repeat_signal({', '.join(tokens)})"

    def _technical_details(self, finding: HaddixFinding) -> str:
        details = finding.summary or finding.impact or "詳細情報なし"
        return details.replace("\n", " ")

    def _cia_impact_assessment(self, finding: HaddixFinding) -> str:
        vtype = (finding.vuln_type or "").lower()
        if "xss" in vtype:
            return "機密性: 中 / 完全性: 中 / 可用性: 低（セッション窃取・改ざんの可能性）"
        if "sqli" in vtype or "sql" in vtype:
            return "機密性: 高 / 完全性: 高 / 可用性: 中（DB漏えい・改ざんの可能性）"
        if "csrf" in vtype:
            return "機密性: 低 / 完全性: 高 / 可用性: 低（不正操作の可能性）"
        if "cors" in vtype or "misconfiguration" in vtype:
            return "機密性: 高 / 完全性: 中 / 可用性: 低（クロスオリジンでの認証情報窃取の可能性）"
        if "ssrf" in vtype:
            return (
                "機密性: 高（内部ネットワーク・クラウドメタデータへの到達で機密情報漏えいの可能性） / "
                "完全性: 中（内部管理APIへの到達で状態変更操作の踏み台化の可能性） / "
                "可用性: 低（内部サービスへの過剰アクセスによる負荷増大の可能性）"
            )
        if "crlf" in vtype:
            return (
                "機密性: 中（注入ヘッダー経由でセッショントークンやリダイレクトURLを再設定可能） / "
                "完全性: 中（レスポンスヘッダー改ざんによりフィッシング・キャッシュポイズニングの可能性） / "
                "可用性: 低"
            )
        if "graphql" in vtype:
            return (
                "機密性: 高（スキーマ全体が露出し、機密フィールド・認証不要エンドポイントが判明） / "
                "完全性: 中（Mutation分析によりデータ改ざん攻撃の設計が可能） / "
                "可用性: 低（深いネストクエリによるDoSの可能性）"
            )
        return "機密性: 中 / 完全性: 中 / 可用性: 中（詳細評価が必要）"

    def _attack_scenario(self, finding: HaddixFinding) -> str:
        base = finding.impact or finding.summary
        if base:
            return base.replace("\n", " ")
        return "攻撃者が細工したリクエストを送信し、対象機能で不正な処理または情報取得を行う可能性がある。"

    def _remediation(self, finding: HaddixFinding) -> str:
        vtype = (finding.vuln_type or "").lower()
        if "xss" in vtype:
            return "ユーザー入力をコンテキストに応じてエスケープし、危険なHTML/JSを許可しないバリデーションを実装する。"
        if "sqli" in vtype or "sql" in vtype:
            return "プレースホルダ付きクエリ（Prepared Statement）へ統一し、動的SQL連結を廃止する。"
        if "csrf" in vtype:
            return "全状態変更リクエストにCSRFトークン検証とSameSite Cookie設定を適用する。"
        if "cors" in vtype or "misconfiguration" in vtype:
            return (
                "Access-Control-Allow-Origin にワイルドカード（*）や任意Origin反射を使用せず、"
                "許可するOriginを明示的なホワイトリストで管理する。"
                "Access-Control-Allow-Credentials: true の場合は特に厳格に制御する。"
            )
        if "ssrf" in vtype:
            return (
                "URL入力を許可リスト方式で検証し、スキーム（http/https）・ホスト・ポートを厳格に制限する。"
                "169.254.169.254、localhost、RFC1918/ULA など内部宛先を明示的に遮断する。"
                "リダイレクト先も再検証し、最終到達先で同じポリシーを適用する。"
            )
        if "crlf" in vtype:
            return (
                "HTTPレスポンスヘッダーに出力するユーザー入力から \\r\\n シーケンスを必ずサニタイズまたは拒否する。"
                "Location ・ Content-Type ・ Set-Cookie などヘッダーにリダイレクト先URLをそのまま挿入しない。"
                "フレームワークのヘッダー設定APIを使用し、生文字列互接を避ける。"
            )
        if "graphql" in vtype:
            return (
                "本番環境ではGraphQL Introspectionを無効化する。"
                "Apollo Server: introspection: false。Strawberry: disable_introspection=True。"
                "クエリ深度制限・複雑度分析を実装し、過剰なスキーマ探索を防止する。"
            )
        return "入力検証、出力エンコード、認可チェックを見直し、脆弱な処理経路を修正する。"

    def _verification_steps(self, finding: HaddixFinding) -> List[str]:
        payload_steps = [
            f"ペイロード `{payload}` を同一条件（URL/パラメータ/HTTPメソッド）で送信し、再現性を確認する。"
            for payload in finding.payloads_used
        ]
        additional_info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        tested_params_raw = additional_info.get("tested_params", [])
        detection_mode = str(additional_info.get("detection_mode", "") or "").strip()

        tested_params: List[str] = []
        if isinstance(tested_params_raw, list):
            tested_params = [str(p).strip() for p in tested_params_raw if str(p).strip()]
        elif isinstance(tested_params_raw, str) and tested_params_raw.strip():
            tested_params = [tested_params_raw.strip()]

        if tested_params:
            payload_steps.append(
                f"検証対象パラメータ `{', '.join(tested_params)}` に同条件で再入力し、同一挙動を確認する。"
            )
        if detection_mode:
            payload_steps.append(f"検知モード `{detection_mode}` で同手順を再実行し、同じ結果になることを確認する。")

        if finding.steps_to_reproduce:
            steps = payload_steps + finding.steps_to_reproduce
            deduped: List[str] = []
            for step in steps:
                if step not in deduped:
                    deduped.append(step)
            return deduped
        return payload_steps + [
            "修正前に成立したPoCリクエストを同条件で再送する。",
            "修正後レスポンスで脆弱挙動（反射・実行・注入）が再現しないことを確認する。",
            "正常系リクエストが影響を受けず動作することを回帰確認する。",
        ]

    def _extract_payloads(self, data: Dict[str, Any], additional_info: Dict[str, Any]) -> List[str]:
        payloads: List[str] = []

        def _collect(value: Any) -> None:
            if value is None:
                return
            if isinstance(value, str):
                token = value.strip()
                if token:
                    payloads.append(token)
                return
            if isinstance(value, list):
                for item in value:
                    _collect(item)
                return
            if isinstance(value, dict):
                for key in ("payload", "value", "mutated", "input"):
                    if key in value:
                        _collect(value.get(key))

        candidate_keys = (
            "payload",
            "payload_used",
            "payloads_used",
            "tested_payloads",
            "successful_payload",
            "successful_payloads",
        )
        for key in candidate_keys:
            if key in data:
                _collect(data.get(key))
            if key in additional_info:
                _collect(additional_info.get(key))

        blind = additional_info.get("blind_correlation", {})
        if isinstance(blind, dict):
            time_based = blind.get("time_based", {})
            if isinstance(time_based, dict):
                _collect(time_based.get("payload"))

        deduped: List[str] = []
        for payload in payloads:
            if payload not in deduped:
                deduped.append(payload)
        return deduped

    def _references(self, finding: HaddixFinding) -> Dict[str, List[str]]:
        official = []
        additional = []
        for ref in finding.references:
            if "owasp.org" in ref.lower() or "cwe.mitre.org" in ref.lower() or "nvd.nist.gov" in ref.lower():
                official.append(ref)
            else:
                additional.append(ref)

        if not official:
            official = [
                "OWASP Top 10: https://owasp.org/www-project-top-ten/",
                "CWE: https://cwe.mitre.org/",
            ]

        if not additional:
            additional = [
                "Bug Bounty reporting best practices: https://www.bugcrowd.com/blog/how-to-write-a-great-vulnerability-report/"
            ]

        return {"official": official, "additional": additional}
    
    def _severity_emoji(self, severity: str) -> str:
        """severity に応じた絵文字"""
        mapping = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵",
        }
        return mapping.get(severity.lower(), "⚪")
    
    def format_json(self) -> str:
        """JSON 形式でレポートを生成"""
        sorted_findings = self._sorted_findings()
        report = {
            "meta": {
                "target": self._target,
                "program_name": self._program_name,
                "generated_at": datetime.now().isoformat(),
                "tool": "SHIGOKU",
            },
            "summary": {
                "total_findings": len(sorted_findings),
                "by_severity": {},
                "suppressed_low_signal": len(self._suppressed_findings),
            },
            "findings": [f.to_dict() for f in sorted_findings],
        }

        for f in sorted_findings:
            sev = f.severity.lower()
            report["summary"]["by_severity"][sev] = report["summary"]["by_severity"].get(sev, 0) + 1
        
        return json.dumps(report, indent=2, ensure_ascii=False)
    
    def save_markdown(self, output_path: Path) -> None:
        """Markdown ファイルとして保存"""
        content = self.format_markdown()
        output_path.write_text(content, encoding="utf-8")
    
    def save_json(self, output_path: Path) -> None:
        """JSON ファイルとして保存"""
        content = self.format_json()
        output_path.write_text(content, encoding="utf-8")
    
    def get_findings_count(self) -> int:
        """ファインディング数を取得"""
        return len(self._findings)
    
    def clear(self) -> None:
        """ファインディングをクリア"""
        self._findings.clear()
        self._suppressed_findings.clear()

    def _coerce_confidence(self, value: Any) -> float:
        try:
            confidence = float(value)
        except Exception:
            return 0.0
        return min(1.0, max(0.0, confidence))

    def _is_injection_like_vuln(self, vuln_type: str) -> bool:
        normalized = str(vuln_type or "").strip().lower().replace("-", "_")
        injection_tokens = (
            "xss",
            "sqli",
            "sql_injection",
            "nosql_injection",
            "ssrf",
            "cmd",
            "command",
            "lfi",
            "ssti",
            "open_redirect",
            "crlf_injection",
            "host_header_injection",
            "deserialization",
            "prototype_pollution",
            "injection",
        )
        return any(token in normalized for token in injection_tokens)

    def _has_verification_signal(self, finding: HaddixFinding) -> bool:
        info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        tested_params = info.get("tested_params", [])
        if isinstance(tested_params, str):
            tested_params = [tested_params]

        has_payload = bool(finding.payloads_used)
        has_tested_params = isinstance(tested_params, list) and any(str(p).strip() for p in tested_params)
        has_reflection = bool(info.get("reflection_observed", False))
        has_poc = bool(str(finding.poc_request or "").strip() or str(finding.poc_response or "").strip())

        blind = info.get("blind_correlation", {})
        blind_confirmed = False
        if isinstance(blind, dict):
            time_based = blind.get("time_based", {}) if isinstance(blind.get("time_based"), dict) else {}
            oob = blind.get("oob", {}) if isinstance(blind.get("oob"), dict) else {}
            blind_confirmed = bool(blind.get("correlated")) or bool(time_based.get("confirmed")) or bool(oob.get("confirmed"))

        return has_payload or has_tested_params or has_reflection or has_poc or blind_confirmed

    def _should_include_finding(self, finding: HaddixFinding) -> tuple[bool, str]:
        if not self._is_injection_like_vuln(finding.vuln_type):
            return True, ""

        severity = str(finding.severity or "").lower()
        # critical/high は誤検知より見逃しコストが高いため除外しない
        if severity in {"critical", "high"}:
            return True, ""

        if self._has_verification_signal(finding):
            return True, ""

        if finding.confidence < 0.5:
            return False, "low_confidence_and_no_verification_signal"

        return True, ""

    def _quality_score(self, finding: HaddixFinding) -> float:
        severity_weight = {
            "critical": 100.0,
            "high": 80.0,
            "medium": 60.0,
            "low": 40.0,
            "info": 20.0,
        }
        score = severity_weight.get(str(finding.severity or "").lower(), 0.0)
        score += finding.confidence * 15.0

        info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        if finding.payloads_used:
            score += 8.0

        tested_params = info.get("tested_params", [])
        if isinstance(tested_params, str):
            tested_params = [tested_params]
        if isinstance(tested_params, list) and any(str(p).strip() for p in tested_params):
            score += 5.0

        if bool(info.get("reflection_observed", False)):
            score += 8.0

        blind = info.get("blind_correlation", {})
        if isinstance(blind, dict):
            time_based = blind.get("time_based", {}) if isinstance(blind.get("time_based"), dict) else {}
            oob = blind.get("oob", {}) if isinstance(blind.get("oob"), dict) else {}
            if bool(blind.get("correlated")):
                score += 12.0
            elif bool(time_based.get("confirmed")) or bool(oob.get("confirmed")):
                score += 8.0

        return score

    def _is_candidate_finding(self, finding: HaddixFinding) -> bool:
        info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        if bool(info.get("heuristic_candidate")) or bool(info.get("verification_required")):
            return True

        detection_mode = str(info.get("detection_mode", "") or "").strip().lower()
        if detection_mode == "heuristic_fallback":
            return True

        merged_tags = self._normalize_string_list(getattr(finding, "tags", []))
        merged_tags.extend(self._normalize_string_list(info.get("tags", [])))
        merged_tags_norm = {str(tag or "").strip().lower() for tag in merged_tags if str(tag or "").strip()}
        if "manual_verify" in merged_tags_norm:
            return True

        text = " ".join(
            [
                str(finding.summary or ""),
                str(info.get("summary", "") or ""),
                str(finding.impact or ""),
            ]
        ).lower()
        if "manual verification required" in text:
            return True
        return False

    def _split_findings_by_confirmation(
        self,
        findings: List[HaddixFinding],
    ) -> tuple[List[HaddixFinding], List[HaddixFinding]]:
        confirmed: List[HaddixFinding] = []
        candidates: List[HaddixFinding] = []

        def _has_full_poc_evidence(item: HaddixFinding) -> bool:
            has_request = bool(str(item.poc_request or "").strip())
            has_response = bool(str(item.poc_response or "").strip())
            return has_request and has_response

        for finding in findings:
            if self._is_candidate_finding(finding):
                self._ensure_unconfirmed_reason_codes(finding, demoted_for_missing_poc=False)
                candidates.append(finding)
                continue

            # Step2 (Quality-First): Confirmed は request/response 両PoCが必須
            if not _has_full_poc_evidence(finding):
                self._ensure_unconfirmed_reason_codes(finding, demoted_for_missing_poc=True)
                candidates.append(finding)
            else:
                confirmed.append(finding)
        return confirmed, candidates

    def _normalize_vulnerability_class(self, value: Any) -> str:
        token = str(value or "").strip().lower().replace(" ", "_")
        return token if token else "unknown"

    def _normalize_detection_class(self, value: Any) -> str:
        token = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
        if not token:
            return ""
        for canonical, aliases in _DETECTION_CLASS_ALIASES.items():
            if token in aliases:
                return canonical
        return token

    def _resolve_detection_class(self, finding: HaddixFinding) -> str:
        additional_info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        explicit_detection_class = self._normalize_detection_class(additional_info.get("detection_class"))
        if explicit_detection_class:
            return explicit_detection_class
        return self._normalize_detection_class(getattr(finding, "vuln_type", ""))

    def _build_findings_class_summary(
        self,
        *,
        confirmed_findings: List[HaddixFinding],
        candidate_findings: List[HaddixFinding],
    ) -> Dict[str, Any]:
        confirmed_counts: Dict[str, int] = {}
        candidate_counts: Dict[str, int] = {}

        for finding in confirmed_findings:
            vuln_class = self._normalize_vulnerability_class(getattr(finding, "vuln_type", ""))
            confirmed_counts[vuln_class] = confirmed_counts.get(vuln_class, 0) + 1

        for finding in candidate_findings:
            vuln_class = self._normalize_vulnerability_class(getattr(finding, "vuln_type", ""))
            candidate_counts[vuln_class] = candidate_counts.get(vuln_class, 0) + 1

        all_classes = sorted(set(confirmed_counts.keys()) | set(candidate_counts.keys()))
        rows: List[Dict[str, Any]] = []
        total_counts: Dict[str, int] = {}
        for vuln_class in all_classes:
            confirmed = int(confirmed_counts.get(vuln_class, 0) or 0)
            candidate = int(candidate_counts.get(vuln_class, 0) or 0)
            total = confirmed + candidate
            total_counts[vuln_class] = total
            rows.append(
                {
                    "vuln_class": vuln_class,
                    "confirmed": confirmed,
                    "candidate": candidate,
                    "total": total,
                }
            )

        return {
            "confirmed_by_vuln_class": dict(sorted(confirmed_counts.items())),
            "candidate_by_vuln_class": dict(sorted(candidate_counts.items())),
            "total_by_vuln_class": dict(sorted(total_counts.items())),
            "rows": rows,
        }

    def _build_scenario_detection_backfill(self) -> Dict[str, int]:
        coverage = self._scenario_coverage if isinstance(self._scenario_coverage, dict) else {}
        backfill: Dict[str, int] = {}

        covered_scenarios = coverage.get("covered_scenarios", [])
        if isinstance(covered_scenarios, list):
            for scenario_id in covered_scenarios:
                sid = str(scenario_id or "").strip().lower()
                detection_class = _SCENARIO_TO_DETECTION_CLASS.get(sid)
                if detection_class:
                    backfill[detection_class] = max(int(backfill.get(detection_class, 0) or 0), 1)

        coverage_items = coverage.get("coverage_items", [])
        if isinstance(coverage_items, list):
            for item in coverage_items:
                if not isinstance(item, dict):
                    continue
                if not bool(item.get("covered", False)):
                    continue
                scenario_id = str(item.get("scenario_id", "") or "").strip().lower()
                detection_class = _SCENARIO_TO_DETECTION_CLASS.get(scenario_id)
                if detection_class:
                    backfill[detection_class] = max(int(backfill.get(detection_class, 0) or 0), 1)

        return dict(sorted(backfill.items()))

    def _build_detection_class_summary(
        self,
        *,
        confirmed_findings: List[HaddixFinding],
        candidate_findings: List[HaddixFinding],
    ) -> Dict[str, Any]:
        confirmed_counts: Dict[str, int] = {}
        candidate_counts: Dict[str, int] = {}

        for finding in confirmed_findings:
            detection_class = self._resolve_detection_class(finding)
            if not detection_class:
                continue
            confirmed_counts[detection_class] = confirmed_counts.get(detection_class, 0) + 1

        for finding in candidate_findings:
            detection_class = self._resolve_detection_class(finding)
            if not detection_class:
                continue
            candidate_counts[detection_class] = candidate_counts.get(detection_class, 0) + 1

        scenario_backfill = self._build_scenario_detection_backfill()
        for detection_class, count in scenario_backfill.items():
            if int(count or 0) <= 0:
                continue
            confirmed_counts[detection_class] = max(int(confirmed_counts.get(detection_class, 0) or 0), int(count))

        all_classes = sorted(set(confirmed_counts.keys()) | set(candidate_counts.keys()))
        rows: List[Dict[str, Any]] = []
        total_counts: Dict[str, int] = {}
        for detection_class in all_classes:
            confirmed = int(confirmed_counts.get(detection_class, 0) or 0)
            candidate = int(candidate_counts.get(detection_class, 0) or 0)
            total = confirmed + candidate
            total_counts[detection_class] = total
            rows.append(
                {
                    "detection_class": detection_class,
                    "confirmed": confirmed,
                    "candidate": candidate,
                    "total": total,
                    "scenario_backfill": int(scenario_backfill.get(detection_class, 0) or 0),
                }
            )

        return {
            "confirmed_by_detection_class": dict(sorted(confirmed_counts.items())),
            "candidate_by_detection_class": dict(sorted(candidate_counts.items())),
            "total_by_detection_class": dict(sorted(total_counts.items())),
            "scenario_backfill_by_detection_class": dict(sorted(scenario_backfill.items())),
            "rows": rows,
        }

    def _sorted_findings(self) -> List[HaddixFinding]:
        return sorted(
            self._findings,
            key=lambda f: (
                -self._quality_score(f),
                (f.discovered_at.isoformat() if isinstance(f.discovered_at, datetime) else str(f.discovered_at)),
                f.title.lower(),
            ),
        )


def generate_haddix_report(
    findings: List[Dict[str, Any]],
    target: str,
    output_path: Path,
    program_name: str = "",
    format_type: str = "markdown",
    execution_notes: Optional[List[Dict[str, Any]]] = None,
    scenario_coverage: Optional[Dict[str, Any]] = None,
    vulnerability_family_coverage: Optional[Dict[str, Any]] = None,
    initial_release_gate: Optional[Dict[str, Any]] = None,
    source_session: str = "",
) -> None:
    """
    ファインディングからHaddixスタイルレポートを生成
    
    Args:
        findings: ファインディングの辞書リスト
        target: ターゲットURL
        output_path: 出力ファイルパス
        program_name: プログラム名（オプション）
        format_type: "markdown" or "json"
        execution_notes: 実行ログ由来の補足情報
        scenario_coverage: SCN01-12 のシナリオカバレッジ情報
        vulnerability_family_coverage: 脆弱性ファミリーカバレッジゲート情報
        initial_release_gate: 初期版リリースゲート評価結果
        source_session: レポート生成元セッションファイル
    """
    formatter = HaddixFormatter()
    formatter.set_target(target, program_name)
    formatter.set_source_session(source_session)
    formatter.set_execution_notes(execution_notes or [])
    formatter.set_scenario_coverage(scenario_coverage or {})
    formatter.set_vulnerability_family_coverage(vulnerability_family_coverage or {})
    formatter.set_initial_release_gate(initial_release_gate or {})
    
    for f in findings:
        formatter.add_finding_from_dict(f)
    
    if format_type == "json":
        formatter.save_json(output_path)
    else:
        formatter.save_markdown(output_path)
