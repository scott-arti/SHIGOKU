from typing import Any, Dict, List

from src.core.engine.skip_reason_registry import (
    KNOWN_SKIP_REASONS,
    normalize_skip_reason,
)


def has_actionable_blind_signal(blind: Any) -> bool:
    if not isinstance(blind, dict) or not blind:
        return False
    if bool(blind.get("correlated", False)):
        return True

    time_based = blind.get("time_based", {})
    if isinstance(time_based, dict) and bool(time_based.get("confirmed", False)):
        return True

    oob = blind.get("oob", {})
    if isinstance(oob, dict):
        if bool(oob.get("confirmed", False)):
            return True
        hits = oob.get("hits", [])
        if isinstance(hits, list) and bool(hits):
            return True

    dns = blind.get("dns", {})
    if isinstance(dns, dict):
        if bool(dns.get("confirmed", False)):
            return True
        hits = dns.get("hits", [])
        if isinstance(hits, list) and bool(hits):
            return True

    return False


def summarize_skip_reason_counts(phase1_url_results: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for entry in phase1_url_results or []:
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status", "") or "").lower()
        if status != "skipped":
            continue
        reason_raw = normalize_skip_reason(entry.get("skip_reason", ""))
        reason = reason_raw if reason_raw in KNOWN_SKIP_REASONS else "other"
        counts[reason] = int(counts.get(reason, 0) or 0) + 1
    return counts


def summarize_skip_reason_unknown_counts(phase1_url_results: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for entry in phase1_url_results or []:
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status", "") or "").lower()
        if status != "skipped":
            continue
        reason = normalize_skip_reason(entry.get("skip_reason", ""))
        if reason in KNOWN_SKIP_REASONS:
            continue
        counts[reason] = int(counts.get(reason, 0) or 0) + 1
    return counts


def summarize_low_ssrf_score_breakdown(phase1_url_results: List[Dict[str, Any]]) -> Dict[str, int]:
    missing_counts: Dict[str, int] = {}
    for entry in phase1_url_results or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("status", "") or "").lower() != "skipped":
            continue
        if normalize_skip_reason(entry.get("skip_reason", "")) != "low_ssrf_score":
            continue
        breakdown = entry.get("score_breakdown", {})
        if not isinstance(breakdown, dict):
            breakdown = {}
        for feature, raw_value in breakdown.items():
            key = str(feature or "").strip().lower() or "unknown_feature"
            try:
                value = int(raw_value or 0)
            except (TypeError, ValueError):
                value = 0
            if value <= 0:
                missing_counts[key] = int(missing_counts.get(key, 0) or 0) + 1
    return missing_counts


def extract_max_ssrf_score(phase1_url_results: List[Dict[str, Any]]) -> int:
    max_score = 0
    for entry in phase1_url_results or []:
        if not isinstance(entry, dict):
            continue
        try:
            score = int(entry.get("ssrf_score", 0) or 0)
        except (TypeError, ValueError):
            score = 0
        if score > max_score:
            max_score = score
    return max_score


def collect_phase1_vuln_types(phase1_url_results: List[Dict[str, Any]]) -> set[str]:
    vuln_types: set[str] = set()
    for entry in phase1_url_results or []:
        if not isinstance(entry, dict):
            continue
        token = str(entry.get("vuln_type", "") or "").strip().lower()
        if token:
            vuln_types.add(token)
    return vuln_types
