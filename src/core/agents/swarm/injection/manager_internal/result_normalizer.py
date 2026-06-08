from typing import Any, Callable, Dict, List, Optional, Set, Tuple


def normalize_detection_class_token(value: Any) -> str:
    raw = getattr(value, "value", value)
    return str(raw or "").strip().lower().replace(" ", "_").replace("-", "_")


def sanitize_tested_params(
    params: List[str] | None,
    *,
    excluded_params: Set[str],
) -> List[str]:
    cleaned: List[str] = []
    for name in params or []:
        key = str(name or "").strip()
        if not key:
            continue
        if key.lower() in excluded_params:
            continue
        if key not in cleaned:
            cleaned.append(key)
    return cleaned


def normalize_blind_correlation(blind: Any) -> Dict[str, Any]:
    src = blind if isinstance(blind, dict) else {}
    time_based = src.get("time_based", {}) if isinstance(src.get("time_based", {}), dict) else {}
    oob = src.get("oob", {}) if isinstance(src.get("oob", {}), dict) else {}
    dns = src.get("dns", {}) if isinstance(src.get("dns", {}), dict) else {}

    tb_confirmed = bool(time_based.get("confirmed", False))
    oob_confirmed = bool(oob.get("confirmed", False))
    dns_confirmed = bool(dns.get("confirmed", False))

    confirmed_count = sum(1 for v in (tb_confirmed, oob_confirmed, dns_confirmed) if v)
    correlated = confirmed_count >= 2
    if correlated:
        verdict = "confirmed"
    elif confirmed_count == 1:
        verdict = "tentative"
    else:
        verdict = "none"

    normalized: Dict[str, Any] = {
        "time_based": {"confirmed": tb_confirmed, **time_based},
        "oob": {"confirmed": oob_confirmed, **oob},
        "dns": {"confirmed": dns_confirmed, **dns},
        "correlated": correlated,
        "verdict": verdict,
    }
    return normalized


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    deduped: List[str] = []
    for item in items:
        if item and item not in deduped:
            deduped.append(item)
    return deduped


def infer_detection_class_for_finding(finding: Any, info: Dict[str, Any]) -> str:
    existing = normalize_detection_class_token(info.get("detection_class"))
    if existing:
        return existing

    vuln_type = normalize_detection_class_token(getattr(finding, "vuln_type", ""))
    tags_raw = getattr(finding, "tags", []) or []
    tags = {
        normalize_detection_class_token(tag)
        for tag in tags_raw
        if normalize_detection_class_token(tag)
    }
    authz = info.get("authz_differential", {}) if isinstance(info.get("authz_differential"), dict) else {}
    authz_scenario = normalize_detection_class_token(authz.get("scenario"))

    if vuln_type == "mass_assignment":
        return "mass_assignment"
    if vuln_type == "idor" or "idor" in tags:
        return "idor_bola"
    if vuln_type == "broken_access_control":
        if authz_scenario in {"unauthenticated_api_access", "unauthenticated_discovered_api_access"}:
            return "endpoint_bfla"
        if "api_candidate" in tags:
            return "endpoint_bfla"
        return "access_control"
    if vuln_type == "api":
        return "endpoint_bfla"
    return ""


def normalize_findings_additional_info(
    findings: List[Any],
    tested_params: Optional[List[str]],
    detection_mode: str,
    *,
    excluded_params: Set[str],
) -> None:
    normalized_params = sanitize_tested_params(
        tested_params or [],
        excluded_params=excluded_params,
    )
    for finding in findings or []:
        existing = getattr(finding, "additional_info", {}) or {}
        if not isinstance(existing, dict):
            existing = {}

        payload = str(existing.get("payload", "") or "").strip()
        payloads_used_raw = existing.get("payloads_used", [])
        payloads_used: List[str] = []
        if isinstance(payloads_used_raw, list):
            payloads_used = [str(p).strip() for p in payloads_used_raw if str(p).strip()]
        elif isinstance(payloads_used_raw, str) and payloads_used_raw.strip():
            payloads_used = [payloads_used_raw.strip()]
        if not payloads_used and payload:
            payloads_used = [payload]

        info: Dict[str, Any] = dict(existing)
        info["payloads_used"] = _dedupe_preserve_order(payloads_used)
        if info["payloads_used"] and not payload:
            info["payload"] = info["payloads_used"][-1]
        info["tested_params"] = sanitize_tested_params(
            info.get("tested_params", []) or normalized_params,
            excluded_params=excluded_params,
        )
        info["detection_mode"] = str(info.get("detection_mode", detection_mode) or detection_mode)
        inferred_detection_class = infer_detection_class_for_finding(finding, info)
        if inferred_detection_class:
            info["detection_class"] = inferred_detection_class
        setattr(finding, "additional_info", info)


def validate_manager_findings(
    findings: List[Any] | None,
    *,
    validate_one: Callable[[Any], Any],
) -> Tuple[List[Any], List[Tuple[Any, Any]]]:
    """Finding の採否判定を行う。"""
    if not findings:
        return [], []

    valid: List[Any] = []
    rejected: List[Tuple[Any, Any]] = []

    for finding in findings:
        result = validate_one(finding)
        if result.reject:
            rejected.append((finding, result))
        else:
            valid.append(finding)

    return valid, rejected


def filter_manager_findings(
    context: Dict[str, Any] | None,
    *,
    validate_one: Callable[[Any], Any],
) -> List[Any]:
    """context 内の findings を採否判定し、有効なものだけを残す。"""
    if not isinstance(context, dict):
        return []

    all_findings = context.get("findings", [])
    valid, rejected = validate_manager_findings(
        all_findings if isinstance(all_findings, list) else [],
        validate_one=validate_one,
    )

    if rejected:
        rejected_set = {id(finding) for finding, _result in rejected}
        context["findings"] = [finding for finding in all_findings if id(finding) not in rejected_set]

    return valid


def build_process_url_cache_entry(
    *,
    vuln_type: str,
    findings_count: int,
    findings: List[Any],
    tested_params: List[str],
    reflection_observed: bool,
    xss_evidence: str,
    blind_correlation: Dict[str, Any],
    unknown_profile: Dict[str, Any],
    probe_sent: bool,
    probe_skipped_reason: str,
    probe_request_raw: str,
    probe_response_raw: str,
    comparison_checks: List[Any],
    auth_context_matrix: Dict[str, Any],
    object_ab_comparison: Dict[str, Any],
    schema_candidate_params: List[str],
    single_request_validation: bool,
    detection_mode: str,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "findings_count": findings_count,
        "findings": findings,
        "vuln_type": vuln_type,
        "tested_params": tested_params,
        "reflection_observed": reflection_observed,
        "xss_evidence": xss_evidence,
        "blind_correlation": blind_correlation,
        "unknown_profile": unknown_profile,
        "probe_sent": probe_sent,
        "probe_skipped_reason": probe_skipped_reason,
        "probe_request_raw": probe_request_raw,
        "probe_response_raw": probe_response_raw,
        "comparison_checks": comparison_checks,
        "auth_context_matrix": auth_context_matrix,
        "object_ab_comparison": object_ab_comparison,
        "schema_candidate_params": schema_candidate_params,
        "single_request_validation": single_request_validation,
        "detection_mode": detection_mode,
    }
    if error is not None:
        entry["error"] = error
    return entry


def build_url_result_from_cache(
    *,
    target_url: str,
    vuln_type: str,
    priority_score: int,
    priority_signals: List[str],
    cached_result: Dict[str, Any],
    ssrf_score: int = 0,
    score_breakdown: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "url": target_url,
        "vuln_type": vuln_type,
        "status": "cache_hit",
        "priority_score": priority_score,
        "priority_signals": list(priority_signals),
        "findings_count": cached_result.get("findings_count", 0),
        "tested_params": cached_result.get("tested_params", []),
        "probe_sent": cached_result.get("probe_sent"),
        "probe_skipped_reason": cached_result.get("probe_skipped_reason", ""),
        "poc_request": cached_result.get("probe_request_raw", ""),
        "poc_response": cached_result.get("probe_response_raw", ""),
        "reflection_observed": cached_result.get("reflection_observed", False),
        "xss_evidence": cached_result.get("xss_evidence", ""),
        "blind_correlation": cached_result.get("blind_correlation", {}),
        "unknown_profile": cached_result.get("unknown_profile", {}),
        "comparison_checks": cached_result.get("comparison_checks", []),
        "auth_context_matrix": cached_result.get("auth_context_matrix", {}),
        "object_ab_comparison": cached_result.get("object_ab_comparison", {}),
        "schema_candidate_params": cached_result.get("schema_candidate_params", []),
        "single_request_validation": cached_result.get("single_request_validation", True),
        "detection_mode": cached_result.get("detection_mode", "phase1"),
        "ssrf_score": ssrf_score,
        "score_breakdown": score_breakdown or {},
    }
