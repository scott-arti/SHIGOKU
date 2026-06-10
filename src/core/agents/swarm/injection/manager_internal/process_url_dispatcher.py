"""_process_single_url の branch 単位分割用モジュール。

unknown classification-only など、_process_single_url の特定ブランチを
個別関数として保持し、facade 側のコード量を削減する。
"""

import logging
from typing import Any, Callable, Dict, List, Optional, Set

from src.core.agents.swarm.injection.manager_internal.result_normalizer import (
    normalize_blind_correlation,
    normalize_findings_additional_info,
    sanitize_tested_params,
)
from src.core.agents.swarm.injection.manager_internal.unknown_hypotheses import (
    build_unknown_hypotheses,
    build_unknown_idor_candidate_finding,
)

logger = logging.getLogger(__name__)


def process_unknown_classification_only(
    *,
    url: str,
    base_params: Dict[str, Any],
    available_specialists: Set[str],
    source_agent_name: str,
    excluded_params: set,
) -> Dict[str, Any]:
    unknown_profile = build_unknown_hypotheses(
        url, base_params,
        available_specialists=available_specialists,
    )
    tested_params = sanitize_tested_params(
        list(unknown_profile.get("query_keys", [])) + list(unknown_profile.get("form_fields", [])),
        excluded_params=excluded_params,
    )
    idor_candidate = build_unknown_idor_candidate_finding(
        url=url,
        tested_params=tested_params,
        unknown_profile=unknown_profile,
        source_agent_name=source_agent_name,
        excluded_params=excluded_params,
    )

    findings_list = [idor_candidate] if idor_candidate is not None else []
    return {
        "findings_count": 1 if idor_candidate is not None else 0,
        "findings_list": findings_list,
        "tested_params": tested_params,
        "unknown_profile": unknown_profile,
        "idor_candidate": idor_candidate,
    }


async def dispatch_vuln_type_branch(
    *,
    url: str,
    vuln_type: str,
    base_params: Dict[str, Any],
    quick_mode: bool,
    detection_mode: str,
    callables: Dict[str, Callable[..., Any]],
    current_context: Dict[str, Any],
    specialists: Dict[str, Any],
    excluded_params: frozenset,
    agent_name: str,
) -> Dict[str, Any]:
    findings_count = 0
    findings_list: List[Any] = []
    tested_params: List[str] = []
    reflection_observed = False
    xss_evidence = ""
    blind_correlation: Dict[str, Any] = {}
    unknown_profile: Dict[str, Any] = {}
    idor_candidate = None

    if vuln_type == "sqli":
        sqli_result = await callables["sqli"](url=url, params=base_params, quick_mode=quick_mode)
        findings_count = sqli_result.get("findings_count", 0)
        tested_params = sanitize_tested_params(sqli_result.get("tested_params", []), excluded_params=excluded_params)
        blind_correlation = normalize_blind_correlation(sqli_result.get("blind_correlation", {}) or {})
        findings_list = current_context["findings"][-findings_count:] if findings_count > 0 else []
        if findings_count == 0:
            xss_result = await callables["xss"](url=url, params=base_params, quick_mode=quick_mode)
            tested_params = sanitize_tested_params(tested_params + xss_result.get("tested_params", []), excluded_params=excluded_params)
            reflection_observed = bool(xss_result.get("reflection_observed", False))
            xss_evidence = str(xss_result.get("evidence", "") or "")

    elif vuln_type == "xss":
        xss_result = await callables["xss"](url=url, params=base_params, quick_mode=quick_mode)
        findings_count = xss_result.get("findings_count", 0)
        tested_params = sanitize_tested_params(xss_result.get("tested_params", []), excluded_params=excluded_params)
        findings_list = current_context["findings"][-findings_count:] if findings_count > 0 else []
        reflection_observed = bool(xss_result.get("reflection_observed", False))
        xss_evidence = str(xss_result.get("evidence", "") or "")

    elif vuln_type == "lfi":
        lfi_result = await callables["lfi"](url=url, params=base_params)
        findings_count = lfi_result.get("findings_count", 0)
        tested_params = sanitize_tested_params(lfi_result.get("tested_params", []), excluded_params=excluded_params)
        findings_list = current_context["findings"][-findings_count:] if findings_count > 0 else []

    elif vuln_type == "ssti":
        ssti_result = await callables["ssti"](url=url, params=base_params)
        findings_count = ssti_result.get("findings_count", 0)
        tested_params = sanitize_tested_params(ssti_result.get("tested_params", []), excluded_params=excluded_params)
        findings_list = current_context["findings"][-findings_count:] if findings_count > 0 else []

    elif vuln_type == "cors":
        cors_result = await callables["cors"](url=url, params=base_params)
        findings_count = cors_result.get("findings_count", 0)
        tested_params = sanitize_tested_params(cors_result.get("tested_params", []), excluded_params=excluded_params)
        findings_list = current_context["findings"][-findings_count:] if findings_count > 0 else []

    elif vuln_type == "crlf":
        crlf_result = await callables["crlf"](url=url, params=base_params)
        findings_count = crlf_result.get("findings_count", 0)
        tested_params = sanitize_tested_params(crlf_result.get("tested_params", []), excluded_params=excluded_params)
        findings_list = current_context["findings"][-findings_count:] if findings_count > 0 else []

    elif vuln_type == "redirect":
        redirect_result = await callables["redirect"](url=url, params=base_params)
        findings_count = redirect_result.get("findings_count", 0)
        findings_list = current_context["findings"][-findings_count:] if findings_count > 0 else []

    elif vuln_type == "cmd_ssrf":
        cmd_result = await callables["cmd_ssrf"](url=url, params=base_params)
        findings_count = cmd_result.get("findings_count", 0)
        tested_params = sanitize_tested_params(cmd_result.get("tested_params", []), excluded_params=excluded_params)
        blind_correlation = normalize_blind_correlation(cmd_result.get("blind_correlation", {}) or {})
        findings_list = current_context["findings"][-findings_count:] if findings_count > 0 else []

    elif vuln_type == "ssrf":
        ssrf_result = await callables["ssrf"](url=url, params=base_params)
        findings_count = ssrf_result.get("findings_count", 0)
        tested_params = sanitize_tested_params(ssrf_result.get("tested_params", []), excluded_params=excluded_params)
        findings_list = current_context["findings"][-findings_count:] if findings_count > 0 else []

    elif vuln_type == "csrf":
        csrf_result = await callables["csrf"](url=url, base_params=base_params)
        findings_count = csrf_result.get("findings_count", 0)
        tested_params = sanitize_tested_params(csrf_result.get("tested_params", []), excluded_params=excluded_params)
        findings_list = current_context["findings"][-findings_count:] if findings_count > 0 else []

    elif vuln_type == "api":
        api_result = await callables["api"](url=url, base_params=base_params)
        findings_count = api_result.get("findings_count", 0)
        tested_params = sanitize_tested_params(api_result.get("tested_params", []), excluded_params=excluded_params)

    elif vuln_type == "admin":
        admin_result = await callables["admin"](url=url, params=base_params)
        findings_count = admin_result.get("findings_count", 0)
        tested_params = sanitize_tested_params(admin_result.get("tested_params", []), excluded_params=excluded_params)
        findings_list = current_context["findings"][-findings_count:] if findings_count > 0 else []
        blind_correlation = {}

    else:  # unknown
        ctx = current_context if isinstance(current_context, dict) else {}
        unknown_raw = ctx.get("params", {}).get("unknown_classification_only")
        unknown_classification_only = (
            True if unknown_raw is None
            else unknown_raw if isinstance(unknown_raw, bool)
            else str(unknown_raw).strip().lower() not in {"false", "0", "no", "off"}
        )
        if unknown_classification_only:
            result = process_unknown_classification_only(
                url=url,
                base_params=base_params,
                available_specialists=set(specialists.keys()),
                source_agent_name=agent_name,
                excluded_params=excluded_params,
            )
            findings_count = result["findings_count"]
            findings_list = result["findings_list"]
            tested_params = result["tested_params"]
            unknown_profile = result["unknown_profile"]
            idor_candidate = result["idor_candidate"]
            if idor_candidate is not None:
                current_context["findings"].append(idor_candidate)
            logger.info(
                "[%s] unknown classification-only mode: url=%s hypotheses=%s specialists=%s",
                agent_name, url,
                unknown_profile.get("hypotheses", []),
                unknown_profile.get("selected_specialists", []),
            )
        else:
            unknown_result = await callables["unknown_scans"](
                url=url, base_params=base_params, quick_mode=quick_mode,
            )
            findings_count = unknown_result.get("findings_count", 0)
            findings_list = unknown_result.get("findings", [])
            tested_params = sanitize_tested_params(unknown_result.get("tested_params", []), excluded_params=excluded_params)
            reflection_observed = bool(unknown_result.get("reflection_observed", False))
            xss_evidence = str(unknown_result.get("xss_evidence", "") or "")
            blind_correlation = normalize_blind_correlation(unknown_result.get("blind_correlation", {}) or {})
            unknown_profile = unknown_result.get("unknown_profile", {}) or {}
            logger.debug("[%s] unknown profile for %s => %s", agent_name, url, unknown_profile)
            if findings_count == 0:
                idor_candidate = build_unknown_idor_candidate_finding(
                    url=url, tested_params=tested_params,
                    unknown_profile=unknown_profile,
                    source_agent_name=agent_name,
                    excluded_params=excluded_params,
                )
                if idor_candidate is not None:
                    current_context["findings"].append(idor_candidate)
                    findings_count = 1
                    findings_list = [idor_candidate]

    normalize_findings_additional_info(findings_list, tested_params, detection_mode, excluded_params=excluded_params)

    return {
        "findings_count": findings_count,
        "findings_list": findings_list,
        "tested_params": tested_params,
        "reflection_observed": reflection_observed,
        "xss_evidence": xss_evidence,
        "blind_correlation": blind_correlation,
        "unknown_profile": unknown_profile,
    }
