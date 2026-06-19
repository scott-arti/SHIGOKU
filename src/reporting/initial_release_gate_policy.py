from __future__ import annotations

from typing import Any

_SCN08 = "scn_08_oob_external_channel_flow"
_SCN10 = "scn_10_semantic_business_logic"
_SCN12 = "scn_12_advanced_ssrf_internal_topology"

DEFAULT_ALLOWED_MISSING_SCENARIOS = [
    _SCN08,
    _SCN10,
    _SCN12,
]
DEFAULT_REQUIRED_CONFIRMED_CLASSES: list[str] = []

_DETECTION_CLASS_ALIASES: dict[str, set[str]] = {
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
    "injection_xss": {
        "injection_xss",
        "xss",
    },
    "injection_sqli_nosqli": {
        "injection_sqli_nosqli",
        "sqli",
        "sql_injection",
        "nosql_injection",
    },
    "injection_ssrf": {
        "injection_ssrf",
        "ssrf",
    },
    "injection_other": {
        "injection_other",
        "ssti",
        "lfi",
        "rce",
        "os_command_injection",
        "deserialization",
        "prototype_pollution",
        "crlf_injection",
        "open_redirect",
        "host_header_injection",
    },
    "rate_limit_bruteforce": {
        "rate_limit_bruteforce",
        "rate_limit",
        "bruteforce",
        "weak_password",
    },
}

_SCENARIO_TO_DETECTION_CLASS: dict[str, str] = {
    "scn_01_idor_bola_object_access": "idor_bola",
    "scn_02_mass_assignment_object_update": "mass_assignment",
    "scn_04_endpoint_enumeration_bfla": "endpoint_bfla",
    "scn_07_token_trust_boundary": "access_control",
}

_DEFERRED_SCENARIO_PLAYBOOK: dict[str, dict[str, str]] = {
    _SCN08: {
        "title": "Out-of-Band External Channel",
        "route": "human_preferred",
        "why_deferred": "Depends on mailbox/SMS/OOB callback validation that is high-friction for full automation.",
        "trigger": "Initial release gate passed with SCN08 still missing.",
        "operator_input": "Provide reachable OOB channels (mailbox/SMS/callback sink) and verification boundaries.",
        "success_criteria": "Reproducible OOB evidence trail or documented negative verification with trace logs.",
    },
    _SCN10: {
        "title": "Semantic Business Logic",
        "route": "human_preferred",
        "why_deferred": "Requires intent/business-policy interpretation across multi-step workflows.",
        "trigger": "Initial release gate passed with SCN10 still missing.",
        "operator_input": "Select high-impact workflow and define unacceptable business outcome.",
        "success_criteria": "Documented reproducible workflow-abuse path with clear business impact.",
    },
    _SCN12: {
        "title": "Advanced SSRF Internal Topology",
        "route": "human_preferred",
        "why_deferred": "Depends on internal topology hypotheses and high-friction callback validation.",
        "trigger": "Initial release gate passed with SCN12 still missing.",
        "operator_input": "Provide internal target hypotheses/callback strategy and safe test boundaries.",
        "success_criteria": "Verified internal reachability pattern or disproved hypothesis with evidence.",
    },
}


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except Exception:
        return None


def _normalize_tokens(raw: Any) -> list[str]:
    if isinstance(raw, str):
        value = raw.strip().lower()
        if not value or value == "-":
            return []
        return [value]
    if not isinstance(raw, list):
        return []
    normalized: list[str] = []
    for item in raw:
        token = str(item or "").strip().lower()
        if not token or token == "-":
            continue
        if token not in normalized:
            normalized.append(token)
    return sorted(normalized)


def _normalize_detection_class(value: Any) -> str:
    token = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    if not token:
        return ""
    for canonical, aliases in _DETECTION_CLASS_ALIASES.items():
        if token in aliases:
            return canonical
    return token


def _normalize_required_detection_classes(raw: Any) -> list[str]:
    normalized: list[str] = []
    if isinstance(raw, str):
        tokens = [str(token or "").strip() for token in raw.split(",")]
    elif isinstance(raw, list):
        tokens = [str(token or "").strip() for token in raw]
    else:
        tokens = []
    for token in tokens:
        if not token:
            continue
        canonical = _normalize_detection_class(token)
        if canonical and canonical not in normalized:
            normalized.append(canonical)
    return normalized


def _build_policy_notes(allowed_missing: list[str]) -> list[str]:
    notes: list[str] = []
    allowed_set = {str(item or "").strip().lower() for item in allowed_missing}
    if _SCN08 in allowed_set and _SCN10 in allowed_set and _SCN12 in allowed_set:
        notes.append(
            "Initial-release exception (Ver.1): SCN08/SCN10/SCN12 can remain missing when routed to HITL/manual validation."
        )
    elif _SCN10 in allowed_set and _SCN12 in allowed_set:
        notes.append(
            "Initial-release exception: SCN10/SCN12 can remain missing and are handled in a later phase (HITL/manual)."
        )
    elif _SCN08 in allowed_set:
        notes.append(
            "Initial-release exception: SCN08 can remain missing and is handled in a later phase (HITL/manual)."
        )
    elif _SCN10 in allowed_set:
        notes.append(
            "Initial-release exception: SCN10 can remain missing and is handled in a later phase (HITL/manual)."
        )
    elif _SCN12 in allowed_set:
        notes.append(
            "Initial-release exception: SCN12 can remain missing and is handled in a later phase (HITL/manual)."
        )
    return notes
