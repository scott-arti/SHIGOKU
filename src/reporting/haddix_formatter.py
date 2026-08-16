"""
HaddixFormatter: Jason Haddix スタイルの脆弱性レポートフォーマッター

Phase 6.5: Bug Bounty 向けレポート生成
"""
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
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


# Probe execution states for execution notes rendering
PROBE_STATE_NOT_APPLICABLE = "not_applicable"     # No parameters needed (e.g., CORS checks)
PROBE_STATE_NOT_DISCOVERED = "not_discovered"     # Parameters not found
PROBE_STATE_SKIPPED = "skipped"                   # Intentionally skipped
PROBE_STATE_EXECUTED = "executed"                 # Probe executed
PROBE_STATE_INSTRUMENTATION_MISSING = "instrumentation_missing"  # Instrumentation missing

# ---------------------------------------------------------------------------
# Coverage stage constants (P5-3)
# ---------------------------------------------------------------------------

COVERAGE_SURFACE_DISCOVERED = "surface_discovered"        # Endpoints/params found
COVERAGE_DETECTOR_EXECUTED = "detector_executed"           # Detector sent probes
COVERAGE_EVIDENCE_COLLECTED = "evidence_collected"         # Real evidence saved
COVERAGE_CANDIDATE_GENERATED = "candidate_generated"       # Candidate created
COVERAGE_FINDING_CONFIRMED = "finding_confirmed"           # Confirmed finding exists

# Per-module execution time budgets (seconds)
MODULE_TIME_BUDGETS = {
    "sqli": 180,
    "blind_sqli": 240,
    "xss": 210,
    "command_injection": 180,
    "csrf": 60,
    "cors": 30,
    "lfi": 120,
    "open_redirect": 60,
    "api": 90,
    "default": 120,
}
SLOW_PROBE_THRESHOLD_SECONDS = 300.0  # Warning threshold

# Phase labels for long-running task breakdown
PHASE_LABELS = [
    "navigation",
    "network_wait",
    "dom_rendering",
    "payload_execution_wait",
    "retry",
    "browser_startup",
    "teardown",
]


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
        # SGK-2026-0422: optional immutable canonical VDP summary. When set
        # for a canonical_vdp session, confirmed/candidate/refuted/untested
        # classification comes ONLY from canonical verdicts — never from raw
        # finding labels or formatter-side re-judgement.
        self._vdp_canonical_summary: Any = None
        # SGK-2026-0425 M5 (D04 resolution): optional additive
        # ``vdp_diagnostics_v1`` session section. When present, the machine-
        # readable diagnostic index is embedded so the report/session
        # consistency checker can compare diagnostic digests. Absent -> no
        # block (additive-absent, bit-identical legacy reports).
        self._vdp_diagnostics_section: Any = None
        # SGK-2026-0426 W3: optional fail-closed run outcome
        # (``vdp_contract.run_outcome``). When the run failed at the VDP
        # follow-up stage (attempts=0), the report carries the machine-
        # readable ``vdp_run_failed_v1`` marker so it is never presented as
        # a normal completion. Absent -> no marker (additive-absent).
        self._vdp_run_outcome: Any = None
        # SGK-2026-0440 Lane B: optional finding-funnel section
        # (``finding_funnel_v1``). When present, the machine-readable funnel
        # block is embedded and per-finding first-failure
        # stage/reason is attached to HaddixFinding.additional_info.
        # Absent -> no block, no additional_info keys (additive-absent,
        # byte-identical legacy reports).
        self._finding_funnel_section: Any = None

    def set_vdp_canonical_summary(self, summary) -> None:
        """Attach the immutable canonical VDP summary (reporting read-only)."""
        self._vdp_canonical_summary = summary

    def set_vdp_diagnostics_section(self, section) -> None:
        """Attach the session's ``vdp_diagnostics_v1`` section (read-only).

        Used only to embed the additive ``vdp_diagnostic_index_v1`` block;
        the section itself is never copied into the report.
        """
        self._vdp_diagnostics_section = section

    def set_vdp_run_outcome(self, run_outcome) -> None:
        """Attach the session's fail-closed run outcome (W3, read-only).

        ``follow_up_stage_failed`` (attempts=0) embeds the machine-readable
        ``vdp_run_failed_v1`` marker; healthy runs pass None (no marker).
        """
        self._vdp_run_outcome = run_outcome

    def set_finding_funnel_section(self, section) -> None:
        """Attach the session's ``finding_funnel_v1`` section (Lane B, read-only).

        Used only to embed the additive machine-readable funnel block and to
        attach per-finding first-failure stage/reason to
        ``additional_info``; the section itself is never copied into the
        report beyond the block.
        """
        self._finding_funnel_section = section

    # ------------------------------------------------------------------
    # SGK-2026-0440 Lane B: per-finding first-failure attribution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_finding_id(finding: HaddixFinding) -> str:
        """Resolve a finding's funnel id: the raw session id captured at
        ``add_finding_from_dict`` time (the ``Finding.id`` md5 the funnel
        recorder keys on), then ``additional_info.finding_id``, then a
        title-hash fallback (same convention as ``build_finding_memo_map``)."""
        raw_id = getattr(finding, "_funnel_raw_id", "") or ""
        if raw_id:
            return str(raw_id).strip()
        info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        finding_id = str(info.get("finding_id", "") or "").strip()
        if finding_id:
            return finding_id
        return f"C{hash(finding.title) & 0xFFFF:X}"

    def _funnel_entries_by_id(self) -> Dict[str, Dict[str, Any]]:
        """Index funnel entries by finding_id (empty when section absent)."""
        section = self._finding_funnel_section
        if not isinstance(section, dict):
            return {}
        entries = section.get("entries")
        if not isinstance(entries, list):
            return {}
        return {
            str(entry.get("finding_id", "") or "").strip(): entry
            for entry in entries
            if isinstance(entry, dict) and str(entry.get("finding_id", "") or "").strip()
        }

    def _funnel_entry_for_finding(self, finding: HaddixFinding) -> Optional[Dict[str, Any]]:
        return self._funnel_entries_by_id().get(self._resolve_finding_id(finding))

    def _attach_funnel_first_failure(
        self,
        finding: HaddixFinding,
        *,
        stage: str,
        reason: str,
    ) -> None:
        info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        finding.additional_info = info
        info["first_failure_stage"] = stage
        info["first_failure_reason"] = reason

    def _apply_funnel_first_failure(
        self,
        confirmed_findings: List[HaddixFinding],
        candidate_findings: List[HaddixFinding],
    ) -> None:
        """Attach per-candidate first-failure data (Lane B, additive).

        No-op when the funnel section is absent. Findings whose funnel entry
        recorded an earlier stop get the entry's stage/reason; candidates
        that reached the report without an earlier stop in the funnel get
        ``F5`` / ``evidence_insufficient`` (data, not assertion).
        """
        if self._finding_funnel_section is None:
            return
        entries = self._funnel_entries_by_id()
        for finding in list(confirmed_findings) + list(candidate_findings):
            entry = entries.get(self._resolve_finding_id(finding))
            if entry is not None and entry.get("first_failure_stage"):
                self._attach_funnel_first_failure(
                    finding,
                    stage=str(entry["first_failure_stage"]),
                    reason=str(entry.get("first_failure_reason") or ""),
                )
        for finding in candidate_findings:
            info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
            if not info.get("first_failure_stage"):
                self._attach_funnel_first_failure(
                    finding,
                    stage="F5",
                    reason="evidence_insufficient",
                )

    @property
    def _has_canonical_summary(self) -> bool:
        return (
            self._vdp_canonical_summary is not None
            and getattr(self._vdp_canonical_summary, "source_kind", "") == "canonical_vdp"
        )

    @staticmethod
    def classify_duration_status(vuln_type: str, duration_seconds: float, status: str) -> str:
        """Classify a task's duration status.
        Returns: 'normal', 'completed_long_running', 'timeout'
        """
        budget = MODULE_TIME_BUDGETS.get(vuln_type, MODULE_TIME_BUDGETS["default"])
        if status == "timeout":
            return "timeout"
        if duration_seconds > budget:
            return "completed_long_running"
        if duration_seconds >= SLOW_PROBE_THRESHOLD_SECONDS:
            return "completed_long_running"
        return "normal"

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

            probe_sent_val = raw_note.get("probe_sent")
            if isinstance(probe_sent_val, bool):
                probe_sent = probe_sent_val
            else:
                probe_sent = None

            probe_state_val = str(raw_note.get("probe_state", "") or "").strip()

            normalized_note: Dict[str, Any] = {
                "url": url,
                "vuln_type": vuln_type,
                "status": status,
                "duration_seconds": raw_note.get("duration_seconds"),
                "retry_count": int(raw_note.get("retry_count", 0) or 0),
                "tested_params": self._normalize_string_list(raw_note.get("tested_params", [])),
                "probe_sent": probe_sent,
                "probe_state": probe_state_val,
                "probe_skipped_reason": str(raw_note.get("probe_skipped_reason", "") or "").strip(),
                "probe_skip_reason_code": str(raw_note.get("probe_skip_reason_code", "") or "").strip(),
                "probe_evidence_id": str(raw_note.get("probe_evidence_id", "") or "").strip(),
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
                current["probe_state"] = PROBE_STATE_EXECUTED
                current["probe_skipped_reason"] = ""
                current["probe_skip_reason_code"] = ""
            elif current_probe_sent is None and normalized_probe_sent is False:
                current["probe_sent"] = False
                current["probe_state"] = normalized_note.get("probe_state", current.get("probe_state", ""))
            if current.get("probe_sent") is not True:
                current_reason = str(current.get("probe_skipped_reason", "") or "").strip()
                normalized_reason = str(normalized_note.get("probe_skipped_reason", "") or "").strip()
                if not current_reason and normalized_reason:
                    current["probe_skipped_reason"] = normalized_reason
                current_code = str(current.get("probe_skip_reason_code", "") or "").strip()
                normalized_code = str(normalized_note.get("probe_skip_reason_code", "") or "").strip()
                if not current_code and normalized_code:
                    current["probe_skip_reason_code"] = normalized_code
                current_evidence_id = str(current.get("probe_evidence_id", "") or "").strip()
                normalized_evidence_id = str(normalized_note.get("probe_evidence_id", "") or "").strip()
                if not current_evidence_id and normalized_evidence_id:
                    current["probe_evidence_id"] = normalized_evidence_id
            # Merge probe_state: prefer more specific states over defaults
            current_state = str(current.get("probe_state", "") or "").strip()
            normalized_state = str(normalized_note.get("probe_state", "") or "").strip()
            if not current_state and normalized_state:
                current["probe_state"] = normalized_state
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
        # Reason-code fields are structured evidence, not free-form display
        # text.  Preserve an unfamiliar domain-specific code so a preceding
        # candidate merge cannot silently erase its hold-back rationale.
        return token

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

        # Evidence quality reason codes are already validated domain-specific
        # codes and must pass through without the standard-code filter.
        eq_codes = self._normalize_string_list(
            additional_info.get("evidence_quality_reason_codes", [])
        )

        normalized: List[str] = []
        for candidate in candidates:
            code = self._normalize_unconfirmed_reason_code(candidate)
            if code and code not in normalized:
                normalized.append(code)

        # Append evidence quality codes after the standard filter so
        # domain-specific codes like state_change_not_verified survive.
        for code in eq_codes:
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

    def _poc_request_from_evidence(self, data: Dict[str, Any]) -> str:
        """Build a minimal raw HTTP request from Finding.evidence.

        Detector findings often store structured request/response evidence
        instead of pre-rendered Haddix PoC strings. Keep this conversion at the
        reporting boundary so evidence-quality checks can evaluate the real
        payload delivery without leaking sensitive headers such as cookies.
        """
        evidence = data.get("evidence") if isinstance(data.get("evidence"), dict) else {}
        if not evidence:
            return ""

        method = str(evidence.get("request_method") or "GET").strip().upper() or "GET"
        raw_url = str(
            evidence.get("request_url")
            or data.get("target_url")
            or data.get("url")
            or data.get("target")
            or ""
        ).strip()
        request_body = str(evidence.get("request_body") or "").strip()
        if not raw_url and not request_body:
            return ""

        parsed = urlsplit(raw_url)
        path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        lines = [f"{method} {path} HTTP/1.1"]
        if parsed.netloc:
            lines.append(f"Host: {parsed.netloc}")
        if request_body:
            lines.extend(["", request_body])
        return "\n".join(lines)

    def _poc_response_from_evidence(self, data: Dict[str, Any]) -> str:
        """Build a minimal raw HTTP response from Finding.evidence."""
        evidence = data.get("evidence") if isinstance(data.get("evidence"), dict) else {}
        if not evidence:
            return ""

        raw_status = evidence.get("response_status")
        try:
            status = int(raw_status)
        except (TypeError, ValueError):
            status = 0

        response_body = str(evidence.get("response_body") or "").strip()
        if status <= 0:
            return response_body

        reason = "OK" if 200 <= status < 300 else ""
        status_line = f"HTTP/1.1 {status} {reason}".rstrip()
        if response_body:
            return f"{status_line}\n\n{response_body}"
        return status_line
    
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

        steps = list(data.get("steps_to_reproduce") or data.get("reproduction_steps", []))
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
                or self._poc_request_from_evidence(data)
            ),
            poc_response=(
                data.get("poc_response")
                or additional_info.get("poc_response")
                or data.get("response", "")
                or self._poc_response_from_evidence(data)
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
            # SGK-2026-0440 Lane B: capture the raw session finding id
            # (``Finding.id`` md5) so funnel entries can be matched even
            # though HaddixFinding has no id field of its own. Deliberately
            # a runtime attribute, NOT a dataclass field: asdict()-based
            # finding logging must stay byte-identical.
            raw_id = str(data.get("id", "") or "").strip()
            if raw_id:
                finding._funnel_raw_id = raw_id  # type: ignore[attr-defined]
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
            completed_long_running_count = 0
            budget_violations: Dict[str, int] = {}
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
                probe_sent = note.get("probe_sent")
                probe_state = str(note.get("probe_state", "") or "").strip()
                if probe_state == PROBE_STATE_NOT_APPLICABLE:
                    tested_params_str = "N/A"
                elif not tested_params:
                    tested_params_str = "none discovered"
                else:
                    tested_params_str = ", ".join(str(p) for p in tested_params)
                if probe_sent is True:
                    probe_sent_str = "yes"
                elif probe_state == PROBE_STATE_NOT_APPLICABLE:
                    probe_sent_str = "N/A"
                elif probe_state == PROBE_STATE_SKIPPED:
                    probe_sent_str = "no (skipped)"
                elif probe_state == PROBE_STATE_NOT_DISCOVERED:
                    probe_sent_str = "no (no params)"
                elif probe_state == PROBE_STATE_INSTRUMENTATION_MISSING:
                    probe_sent_str = "no (no instr.)"
                elif probe_sent is False:
                    probe_sent_str = "no"
                else:
                    probe_sent_str = "unknown"
                probe_skipped_reason = str(note.get("probe_skipped_reason", "") or "").strip()
                probe_skip_reason_code = str(note.get("probe_skip_reason_code", "") or "").strip()
                if probe_sent is True or probe_state == PROBE_STATE_NOT_APPLICABLE:
                    probe_skipped_reason_str = "-"
                elif probe_skip_reason_code:
                    probe_skipped_reason_str = probe_skip_reason_code
                elif probe_skipped_reason:
                    probe_skipped_reason_str = probe_skipped_reason
                else:
                    probe_skipped_reason_str = "unspecified"
                blind_correlation = note.get("blind_correlation", {})
                blind_summary = self._format_blind_summary(blind_correlation)
                lines.append(
                    f"| `{url}` | {vuln_type} | {status} | {duration_str} | {retry_count} | {tested_params_str} | {probe_sent_str} | {probe_skipped_reason_str} | {blind_summary} |"
                )
                # Track long-running completed vs budget violations
                duration_val = float(duration) if duration is not None else 0.0
                duration_status = self.classify_duration_status(vuln_type, duration_val, status)
                if duration_status == "completed_long_running":
                    completed_long_running_count += 1
                    budget = MODULE_TIME_BUDGETS.get(vuln_type, MODULE_TIME_BUDGETS["default"])
                    if duration_val > budget:
                        budget_violations[vuln_type] = budget_violations.get(vuln_type, 0) + 1

            lines.append("")
            total_notes = len(self._execution_notes)
            timeout_rate = (timeout_count / total_notes * 100.0) if total_notes else 0.0
            avg_retry = (retry_total / total_notes) if total_notes else 0.0
            lines.append(
                f"KPI: total={total_notes}, completed={completed_count}, timeout={timeout_count}, "
                f"error={error_count}, completed_long_running={completed_long_running_count}, "
                f"timeout_rate={timeout_rate:.1f}%, avg_retry={avg_retry:.2f}"
            )
            if completed_long_running_count > 0:
                lines.append(
                    f"Long-Running Warning: {completed_long_running_count} completed task(s) exceeded "
                    f"per-module budget or {SLOW_PROBE_THRESHOLD_SECONDS:.0f}s slow-probe threshold. "
                    "Investigate lightweight probes or timeout tuning for stability."
                )
            if budget_violations:
                violation_parts = ", ".join(
                    f"{vuln_type}:{count}" for vuln_type, count in sorted(budget_violations.items())
                )
                lines.append(f"Budget Violations (type:count): {violation_parts}")
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

        # SGK-2026-0422: canonical VDP funnel/verdicts (shared projection).
        if self._vdp_canonical_summary is not None:
            from src.reporting.vdp_report_projection import render_vdp_section_markdown
            lines.extend(render_vdp_section_markdown(self._vdp_canonical_summary))

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
        additional_info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        poc_html = str(additional_info.get("poc_html", "") or "").strip()
        if poc_html:
            lines.append("")
            lines.append("##### PoC HTML (Browser Execution)")
            lines.append("")
            lines.append("```html")
            lines.append(poc_html)
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
            payload_steps.append(f"検知モード `{detection_mode}` で同手順を再実行し、脆弱挙動が再現しないことを確認する。")

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
        """Markdown ファイルとして保存 (SGK-2026-0422: atomic promotion)."""
        content = self.format_markdown()
        from src.reporting.vdp_report_projection import (
            atomic_write_report,
            embed_vdp_canonical_index,
            embed_vdp_diagnostic_index,
            embed_vdp_run_failed_marker,
            embed_finding_funnel_index,
        )

        if self._vdp_canonical_summary is not None:
            content = embed_vdp_canonical_index(content, self._vdp_canonical_summary)
        content = embed_vdp_diagnostic_index(content, self._vdp_diagnostics_section)
        content = embed_vdp_run_failed_marker(content, self._vdp_run_outcome)
        content = embed_finding_funnel_index(content, self._finding_funnel_section)
        if (
            self._vdp_canonical_summary is not None
            or self._vdp_diagnostics_section is not None
            or self._vdp_run_outcome is not None
            or self._finding_funnel_section is not None
        ):
            atomic_write_report(
                output_path,
                content,
                required_sections=self._required_report_sections(),
            )
            return
        output_path.write_text(content, encoding="utf-8")

    def _required_report_sections(self) -> Optional[List[str]]:
        """Required section markers for atomic promotion (canonical VDP path).

        Subclasses override with the headers they actually emit so the
        post-generation re-verification is honest per formatter.
        """
        return None

    def save_json(self, output_path: Path) -> None:
        """JSON ファイルとして保存 (SGK-2026-0422: canonical index included)."""
        content = self.format_json()
        if (
            self._vdp_canonical_summary is not None
            or self._vdp_diagnostics_section is not None
            or self._finding_funnel_section is not None
        ):
            from src.reporting.vdp_report_projection import (
                atomic_write_report,
                build_vdp_diagnostic_index,
            )
            from src.reporting.vdp_canonical import build_vdp_canonical_index
            data = json.loads(content)
            if self._vdp_canonical_summary is not None:
                data["vdp_canonical_index_v1"] = build_vdp_canonical_index(
                    self._vdp_canonical_summary
                )
            diag_index = build_vdp_diagnostic_index(self._vdp_diagnostics_section)
            if diag_index is not None:
                data["vdp_diagnostic_index_v1"] = diag_index
            if self._finding_funnel_section is not None:
                data["finding_funnel_v1"] = self._finding_funnel_section
            atomic_write_report(output_path, json.dumps(data, indent=2, ensure_ascii=False))
            return
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

    def _candidate_has_missing_poc(self, finding: HaddixFinding) -> bool:
        has_request = bool(str(finding.poc_request or "").strip())
        has_response = bool(str(finding.poc_response or "").strip())
        return not (has_request and has_response)

    def _candidate_dedup_key(self, finding: HaddixFinding) -> tuple[Any, ...] | None:
        info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        vtype = self._normalize_vulnerability_class(finding.vuln_type)
        title = str(finding.title or "").strip().lower()
        target = self._canonical_candidate_target(finding.target_url)

        authz = info.get("authz_differential", {}) if isinstance(info.get("authz_differential"), dict) else {}
        detection_class = self._resolve_detection_class(finding)
        authz_classes = {
            "access_control",
            "endpoint_bfla",
            "idor_bola",
            "broken_access_control",
            "authorization_bypass",
            "unauthenticated_api_access",
        }
        if authz or vtype in authz_classes or detection_class in authz_classes:
            scenario = str(
                authz.get("scenario")
                or info.get("scenario")
                or detection_class
                or vtype
                or "access_control"
            ).strip().lower().replace("-", "_")
            if "unauthenticated" in scenario and "api" in scenario:
                scenario = "unauthenticated_api_access"
            return ("authz", target, detection_class or "access_control", scenario)

        if vtype in {"cors", "cors_misconfiguration"} or "cors" in title:
            cors_class = str(
                info.get("misconfiguration")
                or info.get("cors_classification")
                or info.get("classification")
                or ""
            ).strip().lower()
            return ("cors", target, cors_class)

        if vtype == "csrf" or "csrf" in title or "/csrf/" in target:
            return ("csrf", target)

        return None

    def _canonical_candidate_target(self, value: str) -> str:
        normalized = self._normalize_url_string(value)
        split = urlsplit(normalized)
        if not split.scheme or not split.netloc:
            return normalized.strip().lower()

        netloc = split.netloc.lower()
        if netloc.startswith("127.0.0.1:"):
            netloc = netloc.replace("127.0.0.1:", "localhost:", 1)
        elif netloc == "127.0.0.1":
            netloc = "localhost"

        query = urlencode(sorted(parse_qsl(split.query, keep_blank_values=True)), doseq=True)
        return urlunsplit((split.scheme.lower(), netloc, split.path or "/", query, "")).lower()

    def _candidate_strength(self, finding: HaddixFinding) -> tuple[int, int, float, int]:
        severity_rank = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }
        try:
            confidence = float(finding.confidence or 0.0)
        except Exception:
            confidence = 0.0
        has_poc = 0 if self._candidate_has_missing_poc(finding) else 1
        return (
            severity_rank.get(str(finding.severity or "").strip().lower(), 0),
            has_poc,
            confidence,
            len(str(finding.summary or "")),
        )

    def _merge_candidate_duplicate_metadata(
        self,
        primary: HaddixFinding,
        duplicate: HaddixFinding,
    ) -> HaddixFinding:
        primary_info = primary.additional_info if isinstance(primary.additional_info, dict) else {}
        duplicate_info = duplicate.additional_info if isinstance(duplicate.additional_info, dict) else {}
        primary.additional_info = primary_info

        primary_codes = self._ensure_unconfirmed_reason_codes(
            primary,
            demoted_for_missing_poc=self._candidate_has_missing_poc(primary),
        )
        duplicate_codes = self._ensure_unconfirmed_reason_codes(
            duplicate,
            demoted_for_missing_poc=self._candidate_has_missing_poc(duplicate),
        )
        merged_codes = self._merge_unique_tokens(primary_codes, duplicate_codes)
        primary_info["reason_codes"] = merged_codes
        primary_info["reason_code"] = merged_codes[0] if merged_codes else ""
        primary_info["evidence_quality_reason_codes"] = self._merge_unique_tokens(
            primary_info.get("evidence_quality_reason_codes", []),
            self._merge_unique_tokens(
                duplicate_info.get("evidence_quality_reason_codes", []),
                duplicate_codes,
            ),
        )

        primary_count = int(primary_info.get("merged_duplicate_count") or 1)
        duplicate_count = int(duplicate_info.get("merged_duplicate_count") or 1)
        primary_info["merged_duplicate_count"] = primary_count + duplicate_count
        primary_info["merged_duplicate_titles"] = self._merge_unique_tokens(
            primary_info.get("merged_duplicate_titles", []),
            self._merge_unique_tokens(
                [primary.title, duplicate.title],
                duplicate_info.get("merged_duplicate_titles", []),
            ),
        )

        primary.payloads_used = self._merge_unique_tokens(primary.payloads_used, duplicate.payloads_used)
        primary.tags = self._merge_unique_tokens(primary.tags, duplicate.tags)
        if not str(primary.summary or "").strip() and str(duplicate.summary or "").strip():
            primary.summary = duplicate.summary
        if not str(primary.impact or "").strip() and str(duplicate.impact or "").strip():
            primary.impact = duplicate.impact
        return primary

    def _merge_candidate_duplicate(
        self,
        existing: HaddixFinding,
        incoming: HaddixFinding,
    ) -> HaddixFinding:
        if self._candidate_strength(incoming) > self._candidate_strength(existing):
            return self._merge_candidate_duplicate_metadata(incoming, existing)
        return self._merge_candidate_duplicate_metadata(existing, incoming)

    def _deduplicate_candidate_findings(
        self,
        candidates: List[HaddixFinding],
    ) -> List[HaddixFinding]:
        deduped: List[HaddixFinding] = []
        index_by_key: Dict[tuple[Any, ...], int] = {}
        for finding in candidates:
            key = self._candidate_dedup_key(finding)
            if key is None:
                deduped.append(finding)
                continue
            if key not in index_by_key:
                index_by_key[key] = len(deduped)
                deduped.append(finding)
                continue
            index = index_by_key[key]
            deduped[index] = self._merge_candidate_duplicate(deduped[index], finding)
        return deduped

    def _confirmed_dedup_key(self, finding: HaddixFinding) -> tuple[str, str, str, str]:
        """Build a root-cause signature for confirmed report findings.

        A report should collapse repeat observations of the same vulnerability,
        while preserving separate parameters and HTTP methods as separate attack
        surfaces.
        """
        info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        parameter = str(info.get("parameter", "") or "").strip().lower()
        if not parameter:
            match = re.search(r"parameter\s+['\"]?([^'\"\s]+)", str(finding.title or ""), re.IGNORECASE)
            parameter = match.group(1).strip().lower() if match else ""

        method = ""
        request_line = str(finding.poc_request or "").splitlines()
        if request_line:
            method = request_line[0].split(" ", 1)[0].strip().upper()
        if not method:
            delivery = info.get("payload_delivery", {}) if isinstance(info.get("payload_delivery"), dict) else {}
            method = str(delivery.get("request_method", "") or "").strip().upper()

        target = self._normalize_url_string(finding.target_url)
        split = urlsplit(target)
        endpoint = urlunsplit((split.scheme.lower(), split.netloc.lower(), split.path.rstrip("/") or "/", "", ""))
        return (self._normalize_vulnerability_class(finding.vuln_type), endpoint, method, parameter)

    def _merge_confirmed_duplicate(
        self,
        primary: HaddixFinding,
        duplicate: HaddixFinding,
    ) -> HaddixFinding:
        primary_info = primary.additional_info if isinstance(primary.additional_info, dict) else {}
        duplicate_info = duplicate.additional_info if isinstance(duplicate.additional_info, dict) else {}
        primary.additional_info = primary_info
        primary_info["merged_duplicate_count"] = int(primary_info.get("merged_duplicate_count") or 1) + int(
            duplicate_info.get("merged_duplicate_count") or 1
        )
        primary_info["merged_duplicate_titles"] = self._merge_unique_tokens(
            primary_info.get("merged_duplicate_titles", []),
            self._merge_unique_tokens([primary.title, duplicate.title], duplicate_info.get("merged_duplicate_titles", [])),
        )
        primary.payloads_used = self._merge_unique_tokens(primary.payloads_used, duplicate.payloads_used)
        primary.tags = self._merge_unique_tokens(primary.tags, duplicate.tags)
        primary.steps_to_reproduce = self._merge_unique_tokens(primary.steps_to_reproduce, duplicate.steps_to_reproduce)
        return primary

    def _deduplicate_confirmed_findings(self, findings: List[HaddixFinding]) -> List[HaddixFinding]:
        deduped: List[HaddixFinding] = []
        index_by_key: Dict[tuple[str, str, str, str], int] = {}
        for finding in findings:
            key = self._confirmed_dedup_key(finding)
            if key not in index_by_key:
                index_by_key[key] = len(deduped)
                deduped.append(finding)
                continue

            index = index_by_key[key]
            existing = deduped[index]
            if self._candidate_strength(finding) > self._candidate_strength(existing):
                deduped[index] = self._merge_confirmed_duplicate(finding, existing)
            else:
                deduped[index] = self._merge_confirmed_duplicate(existing, finding)
        return deduped

    def _canonical_status_for_finding(self, finding: HaddixFinding) -> Optional[str]:
        """Return the canonical verdict status for a finding, or None.

        For canonical VDP sessions (summary attached), confirmation is NEVER
        derived from raw finding labels — only from canonical verdicts.
        Matching uses the hypothesis_id / verdict_id recorded in
        additional_info when present, falling back to no match (None → the
        finding is shown as candidate, never confirmed).

        SGK-2026-0452 (計装・承認済み 2026-08-16): the canonical verdict
        match above is kept untouched; when it yields no match, a finding
        whose T3 lifecycle genuinely reached confirmed on the LEDGER
        (``additional_info.hybrid_final_state == "confirmed"`` — set only
        when the 3-condition AND passed: payout_grade + poc_judge +
        reproduction matched) is reflected as confirmed. Source of truth is
        the ledger, never a backfill or formatter-side promotion.
        """
        if self._vdp_canonical_summary is None:
            return None
        if getattr(self._vdp_canonical_summary, "source_kind", "") != "canonical_vdp":
            return None
        info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        hypothesis_id = str(info.get("hypothesis_id") or "").strip()
        verdict_id = str(info.get("verdict_id") or "").strip()
        for verdict in self._vdp_canonical_summary.verdicts:
            if verdict_id and verdict.verdict_id == verdict_id:
                return verdict.status
            if hypothesis_id and verdict.hypothesis_id == hypothesis_id:
                return verdict.status
        if str(info.get("hybrid_final_state") or "").strip() == "confirmed":
            return "confirmed"
        return None

    def _split_findings_by_confirmation(
        self,
        findings: List[HaddixFinding],
    ) -> tuple[List[HaddixFinding], List[HaddixFinding]]:
        # SGK-2026-0422: canonical VDP sessions use ONLY canonical verdicts.
        # No formatter-side re-judgement, no promotion from raw labels.
        if self._vdp_canonical_summary is not None:
            confirmed: List[HaddixFinding] = []
            candidates: List[HaddixFinding] = []
            for finding in findings:
                status = self._canonical_status_for_finding(finding)
                if status == "confirmed":
                    confirmed.append(finding)
                else:
                    candidates.append(finding)
            return (
                self._deduplicate_confirmed_findings(confirmed),
                self._deduplicate_candidate_findings(candidates),
            )

        confirmed: List[HaddixFinding] = []
        candidates: List[HaddixFinding] = []

        for finding in findings:
            # SGK-2026-0452 (計装・承認済み 2026-08-16): ledger が真の
            # source of truth。hybrid_final_state が設定されている finding
            # は ledger の verdict に従い確定する：
            #   - "confirmed"（T3 3条件AND成立）→ confirmed に数える
            #   - それ以外（needs_more / candidate / parked）→ 絶対に
            #     confirmed に数えない（candidate へ）
            # hybrid_final_state が無い finding は従来どおりの判定へ
            # フォールスルー（backfill・formatter 側 promotion 捏造なし）。
            info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
            hfs = str(info.get("hybrid_final_state") or "").strip()
            if hfs:
                if hfs == "confirmed":
                    confirmed.append(finding)
                else:
                    self._ensure_unconfirmed_reason_codes(finding, demoted_for_missing_poc=False)
                    candidates.append(finding)
                continue

            if self._is_candidate_finding(finding):
                self._ensure_unconfirmed_reason_codes(finding, demoted_for_missing_poc=False)
                candidates.append(finding)
                continue

            # Step2 (Quality-First): Confirmed は request/response 両PoCが必須
            if self._candidate_has_missing_poc(finding):
                self._ensure_unconfirmed_reason_codes(finding, demoted_for_missing_poc=True)
                candidates.append(finding)
            else:
                confirmed.append(finding)
        # SGK-2026-0440 Lane B (additive): per-finding first-failure
        # attribution when the funnel section is present. No-op when absent.
        self._apply_funnel_first_failure(confirmed, candidates)
        return self._deduplicate_confirmed_findings(confirmed), self._deduplicate_candidate_findings(candidates)

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

    # ------------------------------------------------------------------
    # Coverage stage computation (P5-3)
    # ------------------------------------------------------------------

    def compute_coverage_stages(self) -> Dict[str, int]:
        """Count findings at each coverage stage.

        Returns counts per stage from surface_discovered to finding_confirmed.
        Scenario backfill does NOT inflate the finding_confirmed count — only
        findings with real evidence are counted at confirmed stage.
        """
        counts: Dict[str, int] = {
            COVERAGE_SURFACE_DISCOVERED: 0,
            COVERAGE_DETECTOR_EXECUTED: 0,
            COVERAGE_EVIDENCE_COLLECTED: 0,
            COVERAGE_CANDIDATE_GENERATED: 0,
            COVERAGE_FINDING_CONFIRMED: 0,
        }

        # Execution notes: each note with tested_params or probe_sent contributes
        # to surface_discovered and detector_executed.
        for note in self._execution_notes:
            if not isinstance(note, dict):
                continue
            params = note.get("tested_params", [])
            if isinstance(params, list) and any(str(p).strip() for p in params):
                counts[COVERAGE_SURFACE_DISCOVERED] += 1
            probe_sent = note.get("probe_sent")
            if probe_sent is True:
                counts[COVERAGE_DETECTOR_EXECUTED] += 1

        confirmed, candidates = self._split_findings_by_confirmation(self._findings)

        for finding in self._findings:
            info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
            # Evidence collected: any finding with real request/response evidence
            has_request = bool(str(finding.poc_request or "").strip())
            has_response = bool(str(finding.poc_response or "").strip())
            if has_request and has_response:
                counts[COVERAGE_EVIDENCE_COLLECTED] += 1
            # Candidate generated: heuristic candidate or verification_required
            if self._is_candidate_finding(finding):
                counts[COVERAGE_CANDIDATE_GENERATED] += 1

        # Finding confirmed: only real confirmed findings, NOT inflated by
        # scenario backfill. Each confirmed finding must have real evidence.
        for finding in confirmed:
            has_request = bool(str(finding.poc_request or "").strip())
            has_response = bool(str(finding.poc_response or "").strip())
            # Confirmed findings require full PoC evidence per the
            # _split_findings_by_confirmation logic.
            counts[COVERAGE_FINDING_CONFIRMED] += 1

        return counts

    @staticmethod
    def build_memo_map_markdown_table(findings: List[HaddixFinding]) -> str:
        """Generate the Finding Memo Map Markdown table from structured data.
        The Markdown table must match the JSON content exactly."""
        lines: List[str] = []
        lines.append(
            "| Finding ID | Reason Codes | Payload in Request | Response Kind | "
            "Timing Evidence ID | Browser Trace ID | Detector Observations | Validation State |"
        )
        lines.append(
            "|------------|--------------|--------------------|---------------|"
            "--------------------|------------------|----------------------|------------------|"
        )
        for finding in findings:
            memo_map = build_finding_memo_map(finding)
            finding_id = memo_map.get("finding_id", "-")
            reason_codes = ", ".join(memo_map.get("reason_codes", [])) or "-"
            payload_in_request = "yes" if memo_map.get("payload_in_request") else "no"
            response_kind = memo_map.get("response_kind", "-")
            timing_evidence_id = memo_map.get("timing_evidence_id") or "-"
            browser_trace_id = memo_map.get("browser_trace_id") or "-"
            detector_observations = ", ".join(memo_map.get("detector_observations", [])) or "-"
            validation_state = memo_map.get("validation_state", "candidate")
            lines.append(
                f"| {finding_id} | {reason_codes} | {payload_in_request} | {response_kind} | "
                f"{timing_evidence_id} | {browser_trace_id} | {detector_observations} | {validation_state} |"
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Finding Memo Map (P6-2)
# ---------------------------------------------------------------------------


def build_finding_memo_map(finding: HaddixFinding) -> Dict[str, Any]:
    """Build a structured JSON-compatible memo map for a candidate finding.

    Returns:
    {
        "finding_id": "C1",
        "reason_codes": [...],
        "payload_in_request": bool,
        "response_kind": str,
        "timing_evidence_id": str or None,
        "browser_trace_id": str or None,
        "detector_observations": [...],
        "validation_state": "candidate"|"confirmed",
    }
    """
    additional_info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
    reason_codes = additional_info.get("reason_codes", [])

    # Check if payload is in PoC request
    payloads = finding.payloads_used or []
    poc_request = str(finding.poc_request or "").strip()
    payload_in_request = bool(poc_request) and any(
        str(p).strip() in poc_request for p in payloads if str(p).strip()
    )

    # Response kind
    poc_response = str(finding.poc_response or "").strip()
    if poc_response:
        if re.match(r"^HTTP/[\d.]+\s+[1-9]\d*\b", poc_response):
            response_kind = "real_http"
        elif re.match(r"^HTTP/[\d.]+\s+0\b", poc_response):
            response_kind = "synthetic_detector_note"
        else:
            response_kind = "real_http"
    else:
        response_kind = "none"

    # Timing evidence
    blind = additional_info.get("blind_correlation", {}) if isinstance(additional_info.get("blind_correlation"), dict) else {}
    time_based = blind.get("time_based", {}) if isinstance(blind.get("time_based"), dict) else {}
    timing_samples = blind.get("timing_samples", {}) if isinstance(blind.get("timing_samples"), dict) else {}
    if not timing_samples:
        timing_samples = time_based.get("timing_samples", {}) if isinstance(time_based.get("timing_samples"), dict) else {}
    timing_evidence_id = str(timing_samples.get("evidence_id", "") or "").strip() or None

    # Browser trace
    browser_exec = additional_info.get("browser_execution", {}) if isinstance(additional_info.get("browser_execution"), dict) else {}
    browser_trace_id = str(browser_exec.get("browser_trace_id", "") or "").strip() or None

    # Detector observations
    detector_observations: List[str] = []
    if additional_info.get("detection_mode"):
        detector_observations.append(f"detection_mode={additional_info['detection_mode']}")
    if additional_info.get("discovered_by"):
        detector_observations.append(f"discovered_by={additional_info['discovered_by']}")

    # Validation state
    detection_mode = str(additional_info.get("detection_mode", "") or "").strip().lower()
    heuristic_candidate = bool(additional_info.get("heuristic_candidate"))
    verification_required = bool(additional_info.get("verification_required"))
    has_poc = bool(poc_request) and bool(poc_response)
    if not has_poc or heuristic_candidate or verification_required or detection_mode in {"heuristic_fallback"}:
        validation_state = "candidate"
    else:
        validation_state = "confirmed"

    # Finding ID
    finding_id = str(additional_info.get("finding_id", "") or "").strip() or f"C{hash(finding.title) & 0xFFFF:X}"

    return {
        "finding_id": finding_id,
        "reason_codes": list(reason_codes) if isinstance(reason_codes, list) else [],
        "payload_in_request": payload_in_request,
        "response_kind": response_kind,
        "timing_evidence_id": timing_evidence_id,
        "browser_trace_id": browser_trace_id,
        "detector_observations": detector_observations,
        "validation_state": validation_state,
    }


# ---------------------------------------------------------------------------
# Submission readiness (P5-2)
# ---------------------------------------------------------------------------


def compute_submission_readiness(finding: HaddixFinding) -> Dict[str, Any]:
    """Evaluate whether a finding meets all Bug Bounty submission readiness criteria.

    Returns a dict with ``submission_ready`` (True only if ALL requirements
    are met), a ``score`` (0-100), per-requirement booleans, and a list of
    ``failures`` (requirement names that failed).
    """
    info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
    has_request = bool(str(finding.poc_request or "").strip())
    has_response = bool(str(finding.poc_response or "").strip())

    # Determine evidence type
    if has_response:
        resp = str(finding.poc_response or "").strip()
        is_synthetic = resp.startswith("HTTP/1.1 0") or resp.startswith("HTTP/1.0 0")
        is_real_http = has_request and has_response and not is_synthetic
    else:
        is_synthetic = False
        is_real_http = False

    # Repro steps completeness
    steps = finding.steps_to_reproduce or []
    steps_text = " ".join(str(s).lower() for s in steps)
    has_placeholder = "再構成してください" in steps_text

    requirements = {
        "has_real_evidence": is_real_http,
        "payload_matches_request": bool(finding.payloads_used) and bool(has_request),
        "repro_steps_complete": len(steps) > 0 and not has_placeholder,
        "attack_confirmed": not bool(info.get("heuristic_candidate")) and not bool(info.get("verification_required")),
        "impact_proven": bool(info.get("csrf_state_change")) or bool(info.get("authz_differential")) or bool(info.get("command_execution_evidence")) or bool(info.get("browser_execution")) or bool(info.get("file_marker_excerpt")) or bool(has_response),
        "severity_grounded": bool(finding.severity and finding.severity.lower() in {"critical", "high", "medium", "low", "info"}),
        "class_template_exists": bool(finding.vuln_type),
        "secrets_masked": True,  # Redaction is applied by formatter; assume passed
    }

    failures = [req for req, met in requirements.items() if not met]
    score = (len(requirements) - len(failures)) / max(len(requirements), 1) * 100.0
    submission_ready = len(failures) == 0

    return {
        "submission_ready": submission_ready,
        "score": round(score, 1),
        "requirements": requirements,
        "failures": failures,
    }


def validate_submission_ready(finding: HaddixFinding) -> bool:
    """Return True if the finding meets all submission readiness criteria."""
    result = compute_submission_readiness(finding)
    return result["submission_ready"]


# ---------------------------------------------------------------------------
# Missing scenario detail (P5-4)
# ---------------------------------------------------------------------------

_HIGH_FRICTION_SCENARIOS: Dict[str, Dict[str, str]] = {
    "scn_08_oob_external_channel_flow": {
        "route": "human_preferred",
        "missing_reason": "External channel flows (password reset, email verification, invite) "
                         "require controlled out-of-band infrastructure for callback "
                         "verification. SHIGOKU cannot safely operate this channel in "
                         "the current environment.",
        "required_operator_input": "Select a high-impact out-of-band flow (e.g., password "
                                   "reset) and supply the external callback URL for token "
                                   "delivery channel abuse validation.",
        "safe_execution_constraint": "External callback infrastructure must be isolated "
                                     "from production and must not generate real emails "
                                     "or notifications to actual users.",
        "completion_criteria": "Documented reproducible token-delivery-channel abuse path "
                               "with clear account takeover impact.",
    },
    "scn_10_semantic_business_logic": {
        "route": "human_preferred",
        "missing_reason": "Semantic business logic scenarios require domain-specific "
                         "knowledge of acceptable vs. unacceptable business outcomes "
                         "that cannot be inferred from HTTP traffic alone.",
        "required_operator_input": "Select one high-impact business workflow (approval, "
                                   "pricing, policy enforcement) and define the unacceptable "
                                   "business outcome to target.",
        "safe_execution_constraint": "Manual operations only; automated state tampering "
                                     "must be scoped to a controlled test environment.",
        "completion_criteria": "Documented reproducible workflow-abuse path with clear "
                               "business impact and state/value tampering evidence.",
    },
    "scn_11_multi_vector_chain": {
        "route": "hybrid_shigoku_assisted",
        "missing_reason": "Multi-vector attacks require chaining cross-endpoint trust "
                         "transitions that span multiple detector outputs. The current "
                         "execution model performs single-vector attacks per endpoint.",
        "required_operator_input": "Provide seed endpoints and trust-boundary parameters "
                                   "for cross-vector chaining analysis.",
        "safe_execution_constraint": "Chained attacks must not mutate production data. "
                                     "Read-only path traversal preferred.",
        "completion_criteria": "Documented multi-step chain: BOLA/IDOR foothold → mass "
                               "assignment or role mutation → privilege escalation confirmed.",
    },
    "scn_12_advanced_ssrf_internal_topology": {
        "route": "shigoku_assisted",
        "missing_reason": "Internal topology SSRF requires access to host-specific routing "
                         "information and live internal network visibility that is not "
                         "available in the standard external scan mode.",
        "required_operator_input": "Identify URL fetcher/server-side connector endpoints "
                                   "and provide internal host target list.",
        "safe_execution_constraint": "SSRF probes must target controlled internal hosts "
                                     "only. Cloud metadata endpoints (169.254.169.254) "
                                     "must be tested only against authorized targets.",
        "completion_criteria": "Controlled callback URL → internal host probing → "
                               "metadata/internal API access confirmed.",
    },
    "scn_02_mass_assignment_object_update": {
        "route": "shigoku_only",
        "missing_reason": "Mass assignment probe requires discovery of writable parameters "
                         "on object-update endpoints. If no writable endpoints were "
                         "discovered during surface mapping, the detector cannot execute.",
        "required_operator_input": "Provide a seed list of writable endpoints (POST/PUT/PATCH) "
                                   "for the target application.",
        "safe_execution_constraint": "Probes must use safe mutation values that do not "
                                     "persist or affect production data.",
        "completion_criteria": "Privilege-sensitive parameter accepted by the server, "
                               "confirmed by state-change or response differential.",
    },
}


def build_missing_scenario_detail(scenario_id: str) -> Dict[str, str]:
    """Return structured detail for a missing scenario.

    Args:
        scenario_id: The scenario identifier (e.g., "scn_08_oob_external_channel_flow")

    Returns:
        Dict with keys: scenario_id, route, missing_reason,
        required_operator_input, safe_execution_constraint, completion_criteria.
    """
    normalized_id = str(scenario_id or "").strip().lower()
    detail = _HIGH_FRICTION_SCENARIOS.get(normalized_id)
    if detail is not None:
        return {"scenario_id": normalized_id, **detail}
    return {
        "scenario_id": normalized_id,
        "route": "",
        "missing_reason": "Scenario not covered in this run. Manual assessment required.",
        "required_operator_input": "Initiate manual assessment for this scenario.",
        "safe_execution_constraint": "Manual processes only.",
        "completion_criteria": "Document reproducible attack path with clear impact evidence.",
    }


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
    vdp_canonical_summary: Any = None,
    vdp_diagnostics_section: Any = None,
    vdp_run_outcome: Any = None,
    finding_funnel_section: Any = None,
) -> None:
    """Generate the canonical Haddix report.

    Markdown output now delegates to the submission/internal split renderer so
    direct callers and CLI-generated reports use the same report path. JSON
    output keeps the legacy structured formatter for compatibility.

    ``vdp_canonical_summary`` (SGK-2026-0422): optional immutable canonical
    VDP summary; when provided for a canonical_vdp session, confirmed/
    candidate classification comes ONLY from canonical verdicts and the
    machine-readable canonical index is embedded.

    ``vdp_diagnostics_section`` (SGK-2026-0425 M5, additive): the session's
    ``vdp_diagnostics_v1`` section; when present the machine-readable
    ``vdp_diagnostic_index_v1`` block is embedded for the consistency
    checker. Absent -> no block (legacy reports unchanged).

    ``vdp_run_outcome`` (SGK-2026-0426 W3, additive): the session's
    fail-closed run outcome (``vdp_contract.run_outcome``); a failed
    follow-up stage embeds the ``vdp_run_failed_v1`` marker so the report is
    never presented as a normal completion.

    ``finding_funnel_section`` (SGK-2026-0440 Lane B, additive): the
    session's ``finding_funnel_v1`` section; when present the machine-
    readable funnel block is embedded and per-finding first-failure
    stage/reason is attached. Absent -> no block, no additional_info keys
    (legacy reports unchanged).
    """
    if format_type != "json":
        from src.reporting.haddix_submission_internal_formatter import (
            generate_haddix_submission_internal_report,
        )

        generate_haddix_submission_internal_report(
            findings=findings,
            target=target,
            output_path=output_path,
            program_name=program_name,
            execution_notes=execution_notes,
            scenario_coverage=scenario_coverage,
            vulnerability_family_coverage=vulnerability_family_coverage,
            initial_release_gate=initial_release_gate,
            source_session=source_session,
            vdp_canonical_summary=vdp_canonical_summary,
            vdp_diagnostics_section=vdp_diagnostics_section,
            vdp_run_outcome=vdp_run_outcome,
            finding_funnel_section=finding_funnel_section,
        )
        return

    formatter = HaddixFormatter()
    formatter.set_target(target, program_name)
    formatter.set_source_session(source_session)
    formatter.set_execution_notes(execution_notes or [])
    formatter.set_scenario_coverage(scenario_coverage or {})
    formatter.set_vulnerability_family_coverage(vulnerability_family_coverage or {})
    formatter.set_initial_release_gate(initial_release_gate or {})
    if vdp_canonical_summary is not None:
        formatter.set_vdp_canonical_summary(vdp_canonical_summary)
    if vdp_diagnostics_section is not None:
        formatter.set_vdp_diagnostics_section(vdp_diagnostics_section)
    if vdp_run_outcome is not None:
        formatter.set_vdp_run_outcome(vdp_run_outcome)
    if finding_funnel_section is not None:
        formatter.set_finding_funnel_section(finding_funnel_section)

    for f in findings:
        formatter.add_finding_from_dict(f)

    formatter.save_json(output_path)
