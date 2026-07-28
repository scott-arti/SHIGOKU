"""Expected detection matrix and regression comparison helpers.

This module is intentionally report-side.  It must not make scanner decisions
from DVWA path names.  The matrix is a fixture for evaluating whether a run
covered real-world-plausible vulnerability classes while avoiding DVWA-only
curve fitting.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit, urlunsplit, urlencode

from src.reporting.haddix_evidence_quality import (
    EvidenceVerdict,
    HaddixEvidenceQualityValidator,
)
from src.reporting.haddix_formatter import HaddixFinding, HaddixFormatter
from src.reporting.finding_extractor import extract_all_findings


@dataclass(frozen=True)
class ExpectedDetection:
    detection_id: str
    label: str
    vuln_type_aliases: tuple[str, ...]
    target_path: str
    expected_level: str
    real_world_relevance: str
    required_evidence: tuple[str, ...]
    confirmed_criteria: tuple[str, ...]
    candidate_criteria: tuple[str, ...] = ()
    out_of_scope_condition: str = ""
    query_must_contain: dict[str, str] = field(default_factory=dict)

    def matches(self, finding: dict[str, Any]) -> bool:
        vuln_type = _normalize_vuln_type(finding.get("vuln_type") or finding.get("type"))
        if vuln_type not in {alias.lower() for alias in self.vuln_type_aliases}:
            return False

        target = extract_finding_target(finding)
        parsed = _split_target(target)
        path = (parsed.path or "").lower()
        expected_path = self.target_path.lower()
        if not path.startswith(expected_path):
            return False

        if self.query_must_contain:
            query = {
                str(key).lower(): str(value)
                for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            }
            for key, value in self.query_must_contain.items():
                if query.get(str(key).lower()) != str(value):
                    return False

        return True

    @property
    def is_required(self) -> bool:
        return self.expected_level in {
            "required_confirmed",
            "candidate_to_confirm",
            "required_phase2",
        }

    @property
    def is_conditional(self) -> bool:
        return not self.is_required

    @property
    def requires_confirmed_match(self) -> bool:
        return self.expected_level in {
            "required_confirmed",
            "required_phase2",
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "label": self.label,
            "vuln_type_aliases": list(self.vuln_type_aliases),
            "target_path": self.target_path,
            "query_must_contain": dict(self.query_must_contain),
            "expected_level": self.expected_level,
            "real_world_relevance": self.real_world_relevance,
            "required_evidence": list(self.required_evidence),
            "confirmed_criteria": list(self.confirmed_criteria),
            "candidate_criteria": list(self.candidate_criteria),
            "out_of_scope_condition": self.out_of_scope_condition,
        }


@dataclass(frozen=True, order=True)
class FindingComparisonKey:
    vuln_type: str
    title: str
    target: str

    def to_dict(self) -> dict[str, str]:
        return {
            "vuln_type": self.vuln_type,
            "title": self.title,
            "target": self.target,
        }


DEFAULT_DVWA_LOW_EXPECTED_DETECTIONS: tuple[ExpectedDetection, ...] = (
    ExpectedDetection(
        detection_id="sqli_normal",
        label="SQLi normal",
        vuln_type_aliases=("sqli", "sql_injection"),
        target_path="/vulnerabilities/sqli/",
        expected_level="required_confirmed",
        real_world_relevance="high",
        required_evidence=("request_response_diff", "sql_error_or_boolean_or_extracted_data"),
        confirmed_criteria=("real HTTP request/response evidence", "one deterministic SQLi signal"),
    ),
    ExpectedDetection(
        detection_id="sqli_blind",
        label="SQLi blind",
        vuln_type_aliases=("sqli", "blind_sqli", "sql_injection"),
        target_path="/vulnerabilities/sqli_blind/",
        expected_level="required_confirmed",
        real_world_relevance="high",
        required_evidence=("baseline_true_false_or_timing_comparison",),
        confirmed_criteria=("baseline and positive/negative comparison evidence",),
    ),
    ExpectedDetection(
        detection_id="command_injection",
        label="Command Injection",
        vuln_type_aliases=("os_command_injection", "command_injection", "rce"),
        target_path="/vulnerabilities/exec/",
        expected_level="required_confirmed",
        real_world_relevance="high",
        required_evidence=("safe_output_or_deterministic_comparison",),
        confirmed_criteria=("real response output or strong timing comparison",),
    ),
    ExpectedDetection(
        detection_id="xss_reflected",
        label="Reflected XSS",
        vuln_type_aliases=("xss", "reflected_xss"),
        target_path="/vulnerabilities/xss_r/",
        expected_level="required_confirmed",
        real_world_relevance="high",
        required_evidence=("browser_execution_evidence",),
        confirmed_criteria=("JavaScript execution observed in browser",),
    ),
    ExpectedDetection(
        detection_id="xss_stored",
        label="Stored XSS",
        vuln_type_aliases=("xss", "stored_xss"),
        target_path="/vulnerabilities/xss_s/",
        expected_level="required_confirmed",
        real_world_relevance="high",
        required_evidence=("post_then_revisit_browser_execution",),
        confirmed_criteria=("stored payload executes after revisit",),
    ),
    ExpectedDetection(
        detection_id="xss_dom",
        label="DOM XSS",
        vuln_type_aliases=("xss", "dom_xss"),
        target_path="/vulnerabilities/xss_d/",
        expected_level="required_confirmed",
        real_world_relevance="high",
        required_evidence=("dom_sink_browser_execution",),
        confirmed_criteria=("DOM-triggered JavaScript execution observed",),
    ),
    ExpectedDetection(
        detection_id="lfi",
        label="LFI",
        vuln_type_aliases=("lfi", "path_traversal", "file_inclusion"),
        target_path="/vulnerabilities/fi/",
        expected_level="required_confirmed",
        real_world_relevance="high",
        required_evidence=("payload_request_url", "file_content_or_response_diff"),
        confirmed_criteria=("readable file fragment or stable response difference",),
    ),
    ExpectedDetection(
        detection_id="csrf_state_change",
        label="CSRF state change",
        vuln_type_aliases=("csrf", "misconfiguration"),
        target_path="/vulnerabilities/csrf/",
        expected_level="candidate_to_confirm",
        real_world_relevance="medium",
        required_evidence=("before_after_state_change",),
        confirmed_criteria=("state change observed without anti-CSRF protection",),
        candidate_criteria=("tokenless stateful form observed",),
    ),
    ExpectedDetection(
        detection_id="weak_session_impact",
        label="Weak Session ID / predictable ID impact",
        vuln_type_aliases=("broken_access_control", "session_fixation", "weak_session_id"),
        target_path="/vulnerabilities/weak_id/",
        expected_level="conditional",
        real_world_relevance="medium",
        required_evidence=("session_or_authorization_impact",),
        confirmed_criteria=("predictable identifier impact or ID tampering impact is proven",),
        out_of_scope_condition="Predictability has no session, authorization, or data exposure impact.",
    ),
    ExpectedDetection(
        detection_id="authbypass_idor",
        label="AuthBypass / IDOR",
        vuln_type_aliases=("broken_access_control", "idor"),
        target_path="/vulnerabilities/authbypass/get_user_data.php",
        query_must_contain={"id": "2"},
        expected_level="required_confirmed",
        real_world_relevance="high",
        required_evidence=("authz_differential", "sensitive_data_exposure"),
        confirmed_criteria=("low/no privilege request returns another user's data",),
    ),
    ExpectedDetection(
        detection_id="api_bfla",
        label="API BFLA",
        vuln_type_aliases=("broken_access_control", "idor"),
        target_path="/vulnerabilities/api/v2/user/",
        expected_level="candidate_to_confirm",
        real_world_relevance="high",
        required_evidence=("unauth_vs_auth_diff", "sensitive_field_confirmation"),
        confirmed_criteria=("unauthorized request exposes non-public user data",),
        candidate_criteria=("unauthenticated API data read observed",),
    ),
    ExpectedDetection(
        detection_id="cors",
        label="CORS",
        vuln_type_aliases=("cors", "cors_misconfiguration"),
        target_path="/vulnerabilities/api/v2/user/",
        expected_level="conditional",
        real_world_relevance="medium",
        required_evidence=("credentialed_cross_origin_read_or_sensitive_data",),
        confirmed_criteria=("credentialed cross-origin read exposes sensitive data",),
        out_of_scope_condition="Public data with wildcard-no-credentials only; do not overstate impact.",
    ),
    ExpectedDetection(
        detection_id="open_redirect_control",
        label="Open Redirect",
        vuln_type_aliases=("open_redirect",),
        target_path="/vulnerabilities/open_redirect/source/low.php",
        expected_level="conditional",
        real_world_relevance="medium",
        required_evidence=("location_header_external_control",),
        confirmed_criteria=("attacker-controlled external redirect target is reflected in Location",),
        out_of_scope_condition="Redirect control has no realistic phishing/OAuth/SSO abuse path.",
    ),
    ExpectedDetection(
        detection_id="crlf_header_injection",
        label="CRLF Header Injection",
        vuln_type_aliases=("crlf_injection", "crlf"),
        target_path="/vulnerabilities/open_redirect/source/low.php",
        expected_level="conditional",
        real_world_relevance="medium",
        required_evidence=("real_response_header_diff",),
        confirmed_criteria=("response headers are modified by attacker input",),
        out_of_scope_condition="No header mutation or cache/header abuse path is observed.",
    ),
    ExpectedDetection(
        detection_id="file_upload",
        label="File Upload",
        vuln_type_aliases=("file_upload", "unrestricted_file_upload"),
        target_path="/vulnerabilities/upload/",
        expected_level="required_phase2",
        real_world_relevance="high",
        required_evidence=("upload_allowed", "retrieval_or_execution_impact"),
        confirmed_criteria=("uploaded file is retrievable or executable in a meaningful way",),
    ),
    ExpectedDetection(
        detection_id="brute_force_controls",
        label="Brute Force controls",
        vuln_type_aliases=("brute_force", "weak_password"),
        target_path="/vulnerabilities/brute/",
        expected_level="conditional_phase3",
        real_world_relevance="medium",
        required_evidence=("rate_limit_or_lockout_absence",),
        confirmed_criteria=("few deterministic attempts prove missing practical control",),
        out_of_scope_condition="Only DVWA exercise semantics are observable; no general auth control signal.",
    ),
    ExpectedDetection(
        detection_id="captcha_validation",
        label="CAPTCHA validation",
        vuln_type_aliases=("captcha_bypass", "misconfiguration"),
        target_path="/vulnerabilities/captcha/",
        expected_level="conditional_or_out_of_scope",
        real_world_relevance="low_to_medium",
        required_evidence=("token_reuse_or_server_side_validation_failure",),
        confirmed_criteria=("CAPTCHA/state validation bypass generalizes to real app behavior",),
        out_of_scope_condition="DVWA CAPTCHA exercise is fixture-only and does not generalize.",
    ),
    ExpectedDetection(
        detection_id="csp_policy",
        label="CSP policy",
        vuln_type_aliases=("csp", "misconfiguration"),
        target_path="/vulnerabilities/csp/",
        expected_level="supporting_evidence_or_out_of_scope",
        real_world_relevance="low_to_medium",
        required_evidence=("header_policy_and_xss_impact_context",),
        confirmed_criteria=("policy meaningfully changes exploitability of another finding",),
        out_of_scope_condition="DVWA CSP bypass exercise only; no standalone real-world impact.",
    ),
)


REASON_EXPECTED_PROFILE_NOT_DEFINED = "expected_detection_profile_not_defined_for_security_level"
REASON_EXPECTED_SECURITY_LEVEL_UNRESOLVED = "expected_detection_security_level_unresolved"
REASON_CAPABILITY_COVERAGE_INCOMPLETE = "capability_coverage_incomplete"
REASON_CAPABILITY_CANDIDATE_REASON_MISSING = "capability_candidate_reason_missing"


def extract_session_security_level(session_data: dict[str, Any]) -> str | None:
    """Return one unambiguous security level from persisted cookie contexts.

    Cookie values are inspected only in memory and never returned.  A session
    that mixes levels is not safe to compare to a single benchmark profile.
    """
    levels: set[str] = set()

    def visit(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                visit(child_value, str(child_key))
            return
        if isinstance(value, list):
            for child_value in value:
                visit(child_value, key)
            return
        if key.lower() not in {"cookie", "cookies"} or not isinstance(value, str):
            return
        match = re.search(r"(?:^|;\s*)security=([^;\s]+)", value, re.IGNORECASE)
        if match:
            levels.add(match.group(1).strip().lower())

    visit(session_data)
    return next(iter(levels)) if len(levels) == 1 else None


def _normalize_vuln_type(value: Any) -> str:
    raw = getattr(value, "value", value)
    text = str(raw or "").strip().lower()
    if text.startswith("vulntype."):
        text = text.split(".", 1)[1]
    return text


def _split_target(target: str):
    text = str(target or "").strip()
    if "://" not in text and text.startswith("/"):
        text = f"http://placeholder.local{text}"
    return urlsplit(text)


def normalize_target_url(target: str) -> str:
    parsed = _split_target(target)
    scheme = (parsed.scheme or "http").lower()
    host = (parsed.netloc or "").lower()
    if host.startswith("127.0.0.1:"):
        host = host.replace("127.0.0.1:", "localhost:", 1)
    elif host == "127.0.0.1":
        host = "localhost"
    if host == "placeholder.local":
        host = ""

    path = parsed.path or "/"
    query_pairs = sorted(parse_qsl(parsed.query, keep_blank_values=True))
    query = urlencode(query_pairs, doseq=True)
    if not host:
        return urlunsplit(("", "", path, query, "")).lower()
    return urlunsplit((scheme, host, path, query, "")).lower()


def extract_finding_target(finding: dict[str, Any]) -> str:
    for key in ("target_url", "target", "url", "source_url", "endpoint"):
        value = finding.get(key)
        if value:
            return str(value)

    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        for key in ("request_url", "url", "target_url"):
            value = evidence.get(key)
            if value:
                return str(value)

    additional_info = finding.get("additional_info")
    if isinstance(additional_info, dict):
        for key in ("target_url", "target", "url", "request_url"):
            value = additional_info.get(key)
            if value:
                return str(value)

    return ""


def normalize_finding_key(finding: dict[str, Any]) -> FindingComparisonKey:
    return FindingComparisonKey(
        vuln_type=_normalize_vuln_type(finding.get("vuln_type") or finding.get("type")),
        title=str(finding.get("title") or "").strip().lower(),
        target=normalize_target_url(extract_finding_target(finding)),
    )


def _serialize_finding(
    finding: dict[str, Any],
    *,
    verdict: EvidenceVerdict | None = None,
) -> dict[str, Any]:
    item = {
        "vuln_type": _normalize_vuln_type(finding.get("vuln_type") or finding.get("type")),
        "title": finding.get("title"),
        "target_url": extract_finding_target(finding),
        "source_task_id": finding.get("_source_task_id"),
    }
    if verdict is not None:
        item.update(
            {
                "evidence_status": verdict.shadow_status,
                "reason_codes": list(verdict.reason_codes),
                "payload_in_request": verdict.payload_in_request,
                "response_kind": verdict.response_kind,
            }
        )
    return item


def _extract_findings_from_session(session_data: dict[str, Any]) -> list[dict[str, Any]]:
    return [finding for finding in extract_all_findings(session_data) if isinstance(finding, dict)]


def _raw_finding_to_haddix_finding(
    finding: dict[str, Any],
    *,
    converter: HaddixFormatter,
) -> HaddixFinding:
    additional_info = finding.get("additional_info", {}) if isinstance(finding.get("additional_info"), dict) else {}
    target_url = (
        finding.get("target_url")
        or finding.get("target")
        or extract_finding_target(finding)
    )
    payloads_used = converter._extract_payloads(finding, additional_info)
    normalized = HaddixFinding(
        title=str(finding.get("title") or "Unknown Vulnerability"),
        severity=str(finding.get("severity") or "low"),
        vuln_type=str(finding.get("vuln_type") or finding.get("type") or "unknown"),
        target_url=converter._normalize_url_string(str(target_url or "")),
        summary=str(finding.get("summary") or finding.get("description") or ""),
        impact=str(finding.get("impact") or ""),
        steps_to_reproduce=list(finding.get("steps_to_reproduce") or finding.get("reproduction_steps") or []),
        poc_request=(
            str(finding.get("poc_request") or "")
            or str(additional_info.get("poc_request") or "")
            or str(finding.get("request") or "")
            or converter._poc_request_from_evidence(finding)
        ),
        poc_response=(
            str(finding.get("poc_response") or "")
            or str(additional_info.get("poc_response") or "")
            or str(finding.get("response") or "")
            or converter._poc_response_from_evidence(finding)
        ),
        payloads_used=payloads_used,
        references=list(finding.get("references") or []),
        cwe=finding.get("cwe"),
        cvss=finding.get("cvss"),
        discovered_by=str(finding.get("discovered_by") or finding.get("source_agent") or "SHIGOKU"),
        confidence=converter._coerce_confidence(finding.get("confidence", 0.0)),
        tags=converter._normalize_string_list(finding.get("tags", [])),
        additional_info=additional_info,
    )
    _normalize_csrf_quality_type(normalized)
    return normalized


def _normalize_csrf_quality_type(finding: HaddixFinding) -> None:
    vuln_type = _normalize_vuln_type(finding.vuln_type)
    if vuln_type not in {"misconfiguration", "other", "unknown", ""}:
        return

    info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
    title = str(finding.title or "").lower()
    target = str(finding.target_url or "").lower()
    summary = str(finding.summary or "").lower()
    has_csrf_signal = (
        "csrf" in title
        or "cross site request forgery" in title
        or "/csrf/" in target
        or target.endswith("/csrf")
        or "csrf" in summary
        or bool(info.get("csrf_state_change"))
        or "forged_request_succeeded" in info
        or "active_verify" in info
    )
    if has_csrf_signal:
        finding.vuln_type = "csrf"


def _evaluate_finding_evidence(
    finding: dict[str, Any],
    *,
    converter: HaddixFormatter,
    validator: HaddixEvidenceQualityValidator,
) -> EvidenceVerdict:
    normalized = _raw_finding_to_haddix_finding(finding, converter=converter)
    return validator.evaluate_finding(normalized, current_status="confirmed")


def _session_mapping(session_data: dict[str, Any], key: str) -> dict[str, Any]:
    value = session_data.get(key)
    if isinstance(value, dict):
        return value
    context = session_data.get("context")
    value = context.get(key) if isinstance(context, dict) else None
    return value if isinstance(value, dict) else {}


def evaluate_generic_capability(session_data: dict[str, Any]) -> dict[str, Any]:
    """Assess evidence discipline without assuming a known vulnerable fixture."""
    findings = _extract_findings_from_session(session_data)
    converter = HaddixFormatter()
    validator = HaddixEvidenceQualityValidator(mode="shadow")
    verdicts = [
        _evaluate_finding_evidence(finding, converter=converter, validator=validator)
        for finding in findings
    ]
    confirmed = [verdict for verdict in verdicts if verdict.shadow_status == "confirmed"]
    candidates = [verdict for verdict in verdicts if verdict.shadow_status != "confirmed"]
    family_items = _session_mapping(session_data, "coverage_gate").get("coverage_items", [])
    scenario = _session_mapping(session_data, "scenario_coverage")
    coverage_ok = (
        isinstance(family_items, list)
        and bool(family_items)
        and all(isinstance(item, dict) and bool(item.get("reached")) for item in family_items)
        and bool(scenario)
        and int(scenario.get("required_count", 0) or 0) > 0
    )
    candidate_reason_ok = all(bool(verdict.reason_codes) for verdict in candidates)
    reason_codes: list[str] = []
    if not coverage_ok:
        reason_codes.append(REASON_CAPABILITY_COVERAGE_INCOMPLETE)
    if not candidate_reason_ok:
        reason_codes.append(REASON_CAPABILITY_CANDIDATE_REASON_MISSING)
    return {
        "status": "ok" if not reason_codes else "needs_review",
        "reason_codes": reason_codes,
        "assessment_type": "generic_capability",
        "security_level": extract_session_security_level(session_data),
        "dimensions": {
            "coverage_integrity": {"status": "pass" if coverage_ok else "needs_review"},
            "confirmed_evidence_integrity": {"status": "pass", "count": len(confirmed)},
            "candidate_holdback_integrity": {"status": "pass" if candidate_reason_ok else "needs_review", "count": len(candidates)},
            "observed_security_signals": {"confirmed_count": len(confirmed), "candidate_count": len(candidates)},
        },
        "findings_count": len(findings),
        "matched_count": 0,
        "missing_required_count": 0,
        "missing_conditional_count": 0,
        "matched": [],
        "missing_required": [],
        "missing_conditional": [],
    }


def compare_expected_detections(
    session_data: dict[str, Any],
    *,
    matrix: Iterable[ExpectedDetection] | None = None,
    require_security_level: bool = False,
    profile: str = "generic",
) -> dict[str, Any]:
    security_level = extract_session_security_level(session_data)
    if profile == "generic" and require_security_level:
        if security_level is None:
            return {
                "status": "blocked", "reason_codes": [REASON_EXPECTED_SECURITY_LEVEL_UNRESOLVED],
                "security_level": None, "findings_count": len(_extract_findings_from_session(session_data)),
                "matched_count": 0, "missing_required_count": 0, "missing_conditional_count": 0,
                "matched": [], "missing_required": [], "missing_conditional": [],
            }
        return evaluate_generic_capability(session_data)
    if profile == "dvwa-low-regression":
        if security_level != "low":
            return {
                "status": "blocked", "reason_codes": [REASON_EXPECTED_PROFILE_NOT_DEFINED],
                "security_level": security_level, "findings_count": len(_extract_findings_from_session(session_data)),
                "matched_count": 0, "missing_required_count": 0, "missing_conditional_count": 0,
                "matched": [], "missing_required": [], "missing_conditional": [],
            }
        matrix = DEFAULT_DVWA_LOW_EXPECTED_DETECTIONS
    if matrix is None:
        if security_level == "low" or (security_level is None and not require_security_level):
            matrix = DEFAULT_DVWA_LOW_EXPECTED_DETECTIONS
        else:
            reason_code = (
                REASON_EXPECTED_SECURITY_LEVEL_UNRESOLVED
                if security_level is None
                else REASON_EXPECTED_PROFILE_NOT_DEFINED
            )
            return {
                "status": "blocked",
                "reason_codes": [reason_code],
                "security_level": security_level,
                "findings_count": len(_extract_findings_from_session(session_data)),
                "matched_count": 0,
                "missing_required_count": 0,
                "missing_conditional_count": 0,
                "matched": [],
                "missing_required": [],
                "missing_conditional": [],
            }

    matrix = tuple(matrix)
    findings = _extract_findings_from_session(session_data)
    converter = HaddixFormatter()
    validator = HaddixEvidenceQualityValidator(mode="shadow")
    evaluated_findings = [
        {
            "finding": finding,
            "verdict": _evaluate_finding_evidence(
                finding,
                converter=converter,
                validator=validator,
            ),
        }
        for finding in findings
    ]
    matched: list[dict[str, Any]] = []
    missing_required: list[dict[str, Any]] = []
    missing_conditional: list[dict[str, Any]] = []

    for entry in matrix:
        entry_matches = [evaluated for evaluated in evaluated_findings if entry.matches(evaluated["finding"])]
        confirmed_matches = [
            evaluated for evaluated in entry_matches
            if evaluated["verdict"].shadow_status == "confirmed"
        ]
        candidate_matches = [
            evaluated for evaluated in entry_matches
            if evaluated["verdict"].shadow_status != "confirmed"
        ]
        item = entry.to_dict()
        if entry_matches:
            item["match_count"] = len(entry_matches)
            item["confirmed_match_count"] = len(confirmed_matches)
            item["candidate_match_count"] = len(candidate_matches)
            item["match_status"] = "confirmed" if confirmed_matches else "candidate"
            item["reason_codes"] = sorted({
                code
                for evaluated in candidate_matches
                for code in evaluated["verdict"].reason_codes
            })
            item["findings"] = [
                _serialize_finding(
                    evaluated["finding"],
                    verdict=evaluated["verdict"],
                )
                for evaluated in entry_matches
            ]
            matched.append(item)
            if entry.requires_confirmed_match and not confirmed_matches:
                missing_required.append(item)
            continue

        item["match_count"] = 0
        item["confirmed_match_count"] = 0
        item["candidate_match_count"] = 0
        item["match_status"] = "missing"
        item["reason_codes"] = []
        if entry.is_required:
            missing_required.append(item)
        else:
            missing_conditional.append(item)

    return {
        "status": "ok",
        "reason_codes": [],
        "security_level": security_level,
        "matrix": [entry.to_dict() for entry in matrix],
        "findings_count": len(findings),
        "matched_count": len(matched),
        "missing_required_count": len(missing_required),
        "missing_conditional_count": len(missing_conditional),
        "matched": matched,
        "missing_required": missing_required,
        "missing_conditional": missing_conditional,
    }


def compare_finding_sets(
    baseline_findings: Iterable[dict[str, Any]],
    current_findings: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    baseline_map = {
        normalize_finding_key(finding): finding
        for finding in baseline_findings
        if isinstance(finding, dict)
    }
    current_map = {
        normalize_finding_key(finding): finding
        for finding in current_findings
        if isinstance(finding, dict)
    }

    missing_keys = sorted(set(baseline_map) - set(current_map))
    new_keys = sorted(set(current_map) - set(baseline_map))
    shared_keys = sorted(set(baseline_map) & set(current_map))

    return {
        "baseline_count": len(baseline_map),
        "current_count": len(current_map),
        "shared_count": len(shared_keys),
        "missing_in_current_count": len(missing_keys),
        "new_in_current_count": len(new_keys),
        "missing_in_current": [key.to_dict() for key in missing_keys],
        "new_in_current": [key.to_dict() for key in new_keys],
    }


def compare_session_finding_sets(
    baseline_session_data: dict[str, Any],
    current_session_data: dict[str, Any],
) -> dict[str, Any]:
    return compare_finding_sets(
        _extract_findings_from_session(baseline_session_data),
        _extract_findings_from_session(current_session_data),
    )
