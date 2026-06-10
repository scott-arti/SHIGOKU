"""run_*_hunter 系メソッドの共通 boilerplate 抽出。

各 hunter に共通する「パラメータ正規化→auth構築→Task生成」と
結果フォーマットロジックのほか、各 hunter の実装本体を集約する。
"""

import logging
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.manager_internal.result_normalizer import (
    normalize_blind_correlation,
    normalize_findings_additional_info,
    sanitize_tested_params,
)

logger = logging.getLogger(__name__)


def build_hunter_task(
    *,
    url: str,
    specialist_key: str,
    task_name: str,
    tags: List[str],
    params: Optional[Dict[str, Any]],
    kwargs: Dict[str, Any],
    current_context: Dict[str, Any],
    phase2_detection_mode: str,
    normalize_tool_supplied_params: Callable[[Optional[Dict[str, Any]], Dict[str, Any]], Dict[str, Any]],
    resolve_detection_mode: Callable[[Dict[str, Any], str], str],
) -> Tuple[Task, str]:
    effective_params = normalize_tool_supplied_params(params, kwargs)
    detection_mode = resolve_detection_mode(effective_params, phase2_detection_mode)

    if "method" not in effective_params:
        effective_params["method"] = kwargs.get("method", "GET")

    ctx = current_context if isinstance(current_context, dict) else {}
    cookies_str = kwargs.get("cookies") or ctx.get("params", {}).get("cookies", "")
    effective_params["_auth"] = {
        "auth_headers": kwargs.get("auth_headers", ctx.get("auth_headers", {})),
        "cookies": cookies_str,
    }

    target_task = Task(
        id=f"inj_{specialist_key}_{id(url)}",
        name=task_name,
        target=url,
        params=effective_params,
        tags=tags,
    )
    return target_task, detection_mode


def _extract_tested_params_from_finding(finding: Any) -> List[str]:
    if not hasattr(finding, "additional_info") or not isinstance(finding.additional_info, dict):
        return []
    tp = finding.additional_info.get("tested_params", []) or []
    if not tp:
        param = finding.additional_info.get("parameter")
        if param:
            tp = [param]
    return tp


def _extract_payloads_used_from_finding(finding: Any) -> List[str]:
    if not hasattr(finding, "additional_info") or not isinstance(finding.additional_info, dict):
        return []
    pu = finding.additional_info.get("payloads_used", []) or []
    if not pu:
        payload = finding.additional_info.get("payload")
        if payload:
            pu = [payload]
    return pu


def _fallback_tested_params_from_url(url: str) -> List[str]:
    return list(parse_qs(urlparse(str(url or "")).query).keys())


def format_simple_hunter_result(
    *,
    findings: List[Any],
    url: str,
    excluded_params: set,
    vuln_name: str,
    severity: str,
    not_found_message: str,
) -> Dict[str, Any]:
    if findings:
        finding = findings[0]
        tested_params = _extract_tested_params_from_finding(finding)
        payloads_used = _extract_payloads_used_from_finding(finding)
        return {
            "findings_count": len(findings),
            "success": True,
            "vulnerability": vuln_name,
            "parameter": finding.additional_info.get("parameter", "") if hasattr(finding, "additional_info") else "",
            "payload": finding.additional_info.get("payload", "") if hasattr(finding, "additional_info") else "",
            "payloads_used": payloads_used,
            "tested_params": sanitize_tested_params(tested_params, excluded_params=excluded_params),
            "evidence": finding.description if hasattr(finding, "description") else str(finding),
            "severity": severity,
            "info": f"{vuln_name} vulnerability confirmed in parameter '{finding.additional_info.get('parameter', 'unknown')}'"
        }
    else:
        fallback = sanitize_tested_params(_fallback_tested_params_from_url(url), excluded_params=excluded_params)
        return {
            "findings_count": 0,
            "success": False,
            "tested_params": fallback,
            "message": not_found_message,
        }


def format_cors_hunter_result(findings: List[Any]) -> Dict[str, Any]:
    if findings:
        finding = findings[0]
        return {
            "findings_count": len(findings),
            "success": True,
            "vulnerability": "CORS_MISCONFIGURATION",
            "misconfiguration": finding.additional_info.get("misconfiguration", "") if hasattr(finding, "additional_info") else "",
            "test_origin": finding.additional_info.get("test_origin", "") if hasattr(finding, "additional_info") else "",
            "poc_html": finding.additional_info.get("poc_html", "") if hasattr(finding, "additional_info") else "",
            "evidence": finding.description if hasattr(finding, "description") else str(finding),
            "severity": finding.severity.name if hasattr(finding, "severity") else "MEDIUM",
            "tested_params": [],
            "vulnerable": True,
        }
    else:
        return {
            "findings_count": 0,
            "success": False,
            "vulnerable": False,
            "tested_params": [],
            "message": "No CORS misconfiguration found",
        }


# ── runner helpers ────────────────────────────────────────────────────


def _ensure_context_defaults(
    current_context: Dict[str, Any],
) -> None:
    if not isinstance(current_context, dict):
        return
    current_context.setdefault("findings", [])
    current_context.setdefault("auth_headers", {})
    current_context.setdefault("params", {})


def _extract_blind_correlation(
    findings: List[Any], specialist: Any, default: Dict[str, Any] | None = None
) -> Dict[str, Any]:
    bc: Dict[str, Any] = {}
    if findings and hasattr(findings[0], "additional_info"):
        bc = findings[0].additional_info.get("blind_correlation", {}) or {}
    if not bc:
        bc = getattr(specialist, "last_blind_correlation", {}) or {}
    if not bc and default is not None:
        bc = default
    return normalize_blind_correlation(bc)


def _extract_tested_params_or_fallback(
    findings: List[Any], specialist: Any
) -> List[str]:
    if findings and hasattr(findings[0], "additional_info"):
        tp = findings[0].additional_info.get("tested_params", []) or []
    else:
        tp = []
    if not tp:
        tp = getattr(specialist, "last_tested_params", []) or []
    return tp


def _make_auth_dict(
    kwargs: Dict[str, Any],
    current_context: Dict[str, Any],
) -> Dict[str, Any]:
    cookies_str = kwargs.get("cookies") or current_context.get("params", {}).get("cookies", "")
    return {
        "auth_headers": kwargs.get("auth_headers", current_context.get("auth_headers", {})),
        "cookies": cookies_str,
    }


# ── blind-correlation hunter runner (SQLi / XSS / CmdSSRF) ────────────


async def run_sqli_hunter_runner(
    *,
    deps: Dict[str, Any],
    url: str,
    params: Optional[Dict[str, Any]],
    quick_mode: bool = False,
    **_kwargs: Any,
) -> Dict[str, Any]:
    specialists = deps["specialists"]
    if "sqli" not in specialists:
        return {"error": "SQLi Specialist not available"}
    logger.info("[%s] Delegating SQLi check to SmartSQLiHunter (quick_mode=%s)", deps["agent_name"], quick_mode)
    target_task, detection_mode = build_hunter_task(
        url=url, specialist_key="sqli", task_name="SQLi Check", tags=["sqli"],
        params=params, kwargs=_kwargs,
        current_context=deps["current_context"],
        phase2_detection_mode=deps["phase2_detection_mode"],
        normalize_tool_supplied_params=deps["normalize_tool_supplied_params"],
        resolve_detection_mode=deps["resolve_detection_mode"],
    )
    findings = await specialists["sqli"].execute_with_retry(target_task, quick_mode=quick_mode) or []
    deps["current_context"]["findings"].extend(findings)
    tested_params = _extract_tested_params_or_fallback(findings, specialists["sqli"])
    blind_correlation = _extract_blind_correlation(findings, specialists["sqli"])
    normalize_findings_additional_info(findings, tested_params, detection_mode, excluded_params=deps["excluded_params"])
    if findings:
        f = findings[0]
        return {
            "success": True, "findings_count": len(findings), "vulnerability": "SQL Injection",
            "method": f.evidence.request_method if hasattr(f, "evidence") and f.evidence else "GET",
            "parameter": f.additional_info.get("parameter", "") if hasattr(f, "additional_info") else "",
            "payload": f.additional_info.get("payload", "") if hasattr(f, "additional_info") else "",
            "tested_params": tested_params, "blind_correlation": blind_correlation,
            "evidence": f.description if hasattr(f, "description") else str(f),
            "severity": f.severity.name if hasattr(f, "severity") else "HIGH",
            "info": f"SQL Injection vulnerability confirmed in parameter '{f.additional_info.get('parameter', 'unknown')}'",
        }
    return {
        "success": False, "findings_count": 0, "tested_params": tested_params,
        "blind_correlation": blind_correlation,
        "message": "No SQL Injection vulnerabilities found after comprehensive testing",
    }


async def run_xss_hunter_runner(
    *,
    deps: Dict[str, Any],
    url: str,
    params: Optional[Dict[str, Any]],
    quick_mode: bool = False,
    **_kwargs: Any,
) -> Dict[str, Any]:
    specialists = deps["specialists"]
    if "xss" not in specialists:
        return {"error": "XSS Specialist not available"}
    logger.info("[%s] Delegating XSS check to SmartXSSHunter (quick_mode=%s)", deps["agent_name"], quick_mode)
    target_task, detection_mode = build_hunter_task(
        url=url, specialist_key="xss", task_name="XSS Check", tags=["xss"],
        params=params, kwargs=_kwargs,
        current_context=deps["current_context"],
        phase2_detection_mode=deps["phase2_detection_mode"],
        normalize_tool_supplied_params=deps["normalize_tool_supplied_params"],
        resolve_detection_mode=deps["resolve_detection_mode"],
    )
    findings = await specialists["xss"].execute_with_retry(target_task, quick_mode=quick_mode) or []
    deps["current_context"]["findings"].extend(findings)
    tested_params = _extract_tested_params_or_fallback(findings, specialists["xss"])
    normalize_findings_additional_info(findings, tested_params, detection_mode, excluded_params=deps["excluded_params"])
    if findings:
        f = findings[0]
        reflection_observed = False
        if hasattr(f, "additional_info") and isinstance(f.additional_info, dict):
            reflection_observed = bool(f.additional_info.get("reflection_observed", False))
        return {
            "success": True, "findings_count": len(findings), "vulnerability": "XSS",
            "method": f.evidence.request_method if hasattr(f, "evidence") and f.evidence else "GET",
            "parameter": f.additional_info.get("parameter", "") if hasattr(f, "additional_info") else "",
            "payload": f.additional_info.get("payload", "") if hasattr(f, "additional_info") else "",
            "tested_params": tested_params, "evidence": f.description if hasattr(f, "description") else str(f),
            "reflection_observed": reflection_observed,
            "severity": f.severity.name if hasattr(f, "severity") else "HIGH",
            "info": f"XSS vulnerability confirmed in parameter '{f.additional_info.get('parameter', 'unknown')}'",
        }
    specialist_reflection = bool(getattr(specialists["xss"], "reflection_observed", False))
    specialist_evidence = str(getattr(specialists["xss"], "evidence", "") or "")
    return {
        "success": False, "findings_count": 0, "tested_params": tested_params,
        "reflection_observed": specialist_reflection, "evidence": specialist_evidence,
        "message": "No XSS vulnerabilities found after comprehensive testing",
    }


async def run_cmd_ssrf_hunter_runner(
    *,
    deps: Dict[str, Any],
    url: str,
    params: Optional[Dict[str, Any]],
    quick_mode: bool = False,
    **_kwargs: Any,
) -> Dict[str, Any]:
    specialists = deps["specialists"]
    if "cmd_ssrf" not in specialists:
        return {"error": "CmdSSRF Specialist not available"}
    logger.info("[%s] Delegating Cmd/SSRF check to SmartCmdSSRFHunter (quick_mode=%s)", deps["agent_name"], quick_mode)
    target_task, detection_mode = build_hunter_task(
        url=url, specialist_key="cmd_ssrf", task_name="Cmd/SSRF Check", tags=["cmd_ssrf"],
        params=params, kwargs=_kwargs,
        current_context=deps["current_context"],
        phase2_detection_mode=deps["phase2_detection_mode"],
        normalize_tool_supplied_params=deps["normalize_tool_supplied_params"],
        resolve_detection_mode=deps["resolve_detection_mode"],
    )
    findings = await specialists["cmd_ssrf"].execute_with_retry(target_task, quick_mode=quick_mode) or []
    deps["current_context"]["findings"].extend(findings)
    tested_params = _extract_tested_params_or_fallback(findings, specialists["cmd_ssrf"])
    blind_correlation = _extract_blind_correlation(findings, specialists["cmd_ssrf"])
    normalize_findings_additional_info(findings, tested_params, detection_mode, excluded_params=deps["excluded_params"])
    if findings:
        f = findings[0]
        return {
            "success": True, "findings_count": len(findings), "vulnerability": "SSRF/Command Injection",
            "parameter": f.additional_info.get("parameter", "") if hasattr(f, "additional_info") else "",
            "payload": f.additional_info.get("payload", "") if hasattr(f, "additional_info") else "",
            "evidence": f.description if hasattr(f, "description") else str(f),
            "severity": f.severity.name if hasattr(f, "severity") else "CRITICAL",
            "tested_params": sanitize_tested_params(tested_params, excluded_params=deps["excluded_params"]),
            "blind_correlation": blind_correlation,
            "info": "SSRF/Command Injection vulnerability confirmed",
        }
    fallback = tested_params or sanitize_tested_params(
        list(parse_qs(urlparse(url).query).keys()), excluded_params=deps["excluded_params"]
    )
    return {
        "success": False, "findings_count": 0, "tested_params": fallback,
        "blind_correlation": {}, "message": "No SSRF/Command Injection vulnerabilities found",
    }


# ── simple retry hunter runner (LFI / OpenRedirect) ───────────────────


async def run_lfi_check_runner(
    *,
    deps: Dict[str, Any],
    url: str,
    params: Optional[Dict[str, Any]],
    quick_mode: bool = False,
    **_kwargs: Any,
) -> Dict[str, Any]:
    specialists = deps["specialists"]
    if "lfi" not in specialists:
        return {"error": "LFI Specialist not available"}
    logger.info("[%s] Delegating LFI check to SmartLFIHunter (quick_mode=%s)", deps["agent_name"], quick_mode)
    target_task, detection_mode = build_hunter_task(
        url=url, specialist_key="lfi", task_name="LFI/Traversal Check", tags=["lfi"],
        params=params, kwargs=_kwargs,
        current_context=deps["current_context"],
        phase2_detection_mode=deps["phase2_detection_mode"],
        normalize_tool_supplied_params=deps["normalize_tool_supplied_params"],
        resolve_detection_mode=deps["resolve_detection_mode"],
    )
    findings = await specialists["lfi"].execute_with_retry(target_task, quick_mode=quick_mode) or []
    deps["current_context"]["findings"].extend(findings)
    tested_params: List[str] = []
    if findings and hasattr(findings[0], "additional_info"):
        tested_params = findings[0].additional_info.get("tested_params", []) or []
    normalize_findings_additional_info(findings, tested_params, detection_mode, excluded_params=deps["excluded_params"])
    return format_simple_hunter_result(
        findings=findings, url=url, excluded_params=deps["excluded_params"],
        vuln_name="LFI/Path Traversal", severity="HIGH",
        not_found_message="No LFI vulnerabilities found",
    )


async def run_open_redirect_check_runner(
    *,
    deps: Dict[str, Any],
    url: str,
    params: Optional[Dict[str, Any]],
    quick_mode: bool = False,
    **_kwargs: Any,
) -> Dict[str, Any]:
    specialists = deps["specialists"]
    if "redirect" not in specialists:
        return {"error": "Redirect Specialist not available"}
    logger.info("[%s] Delegating Open Redirect check to specialist (quick_mode=%s)", deps["agent_name"], quick_mode)
    target_task, detection_mode = build_hunter_task(
        url=url, specialist_key="redirect", task_name="Open Redirect Check", tags=["redirect"],
        params=params, kwargs=_kwargs,
        current_context=deps["current_context"],
        phase2_detection_mode=deps["phase2_detection_mode"],
        normalize_tool_supplied_params=deps["normalize_tool_supplied_params"],
        resolve_detection_mode=deps["resolve_detection_mode"],
    )
    findings = await specialists["redirect"].execute_with_retry(target_task, quick_mode=quick_mode) or []
    deps["current_context"]["findings"].extend(findings)
    tested_params_from_url = sanitize_tested_params(
        list(parse_qs(urlparse(url).query).keys()), excluded_params=deps["excluded_params"]
    )
    normalize_findings_additional_info(findings, tested_params_from_url, detection_mode, excluded_params=deps["excluded_params"])
    return format_simple_hunter_result(
        findings=findings, url=url, excluded_params=deps["excluded_params"],
        vuln_name="Open Redirect", severity="MEDIUM",
        not_found_message="No Open Redirect vulnerabilities found",
    )


# ── custom hunters (SSTI / CORS / CRLF / GraphQL / SSRF) ─────────────


async def run_ssti_hunter_runner(
    *,
    deps: Dict[str, Any],
    url: str,
    params: Optional[Dict[str, Any]],
    quick_mode: bool = False,
    **_kwargs: Any,
) -> Dict[str, Any]:
    specialists = deps["specialists"]
    if "ssti" not in specialists:
        return {"error": "SSTI Specialist not available", "findings_count": 0, "tested_params": []}
    logger.info("[%s] Delegating SSTI check to SmartSSTIHunter", deps["agent_name"])
    target_task, _detection_mode = build_hunter_task(
        url=url, specialist_key="ssti", task_name="SSTI Check", tags=["ssti"],
        params=params, kwargs=_kwargs,
        current_context=deps["current_context"],
        phase2_detection_mode=deps["phase2_detection_mode"],
        normalize_tool_supplied_params=deps["normalize_tool_supplied_params"],
        resolve_detection_mode=deps["resolve_detection_mode"],
    )
    effective_params = target_task.params
    effective_params["use_encoding"] = _kwargs.get("use_encoding", False)
    tech_stack = (
        _kwargs.get("tech_stack")
        or deps["current_context"].get("tech_stack")
        or deps["current_context"].get("fingerprint", {}).get("tech_stack", [])
    )
    if tech_stack:
        effective_params["_context"] = {"tech_stack": list(tech_stack)}
    findings = await specialists["ssti"].execute(target_task, quick_mode=quick_mode) or []
    deps["current_context"]["findings"].extend(findings)
    tested_params: List[str] = []
    if findings and hasattr(findings[0], "additional_info"):
        tested_params = findings[0].additional_info.get("tested_params", []) or []
    if findings:
        f = findings[0]
        return {
            "findings_count": len(findings), "success": True, "vulnerability": "SSTI",
            "parameter": f.additional_info.get("parameter", "") if hasattr(f, "additional_info") else "",
            "engine": f.additional_info.get("engine", "unknown") if hasattr(f, "additional_info") else "",
            "payload": f.additional_info.get("payload", "") if hasattr(f, "additional_info") else "",
            "evidence": f.description if hasattr(f, "description") else str(f),
            "severity": f.severity.name if hasattr(f, "severity") else "CRITICAL",
            "tested_params": sanitize_tested_params(tested_params, excluded_params=deps["excluded_params"]),
            "vulnerable": True,
        }
    fallback = sanitize_tested_params(
        list(parse_qs(urlparse(url).query).keys()), excluded_params=deps["excluded_params"]
    )
    return {
        "findings_count": 0, "success": False, "vulnerable": False,
        "tested_params": fallback, "message": "No SSTI vulnerabilities found",
    }


async def run_cors_hunter_runner(
    *,
    deps: Dict[str, Any],
    url: str,
    params: Optional[Dict[str, Any]],
    quick_mode: bool = False,
    **_kwargs: Any,
) -> Dict[str, Any]:
    specialists = deps["specialists"]
    if "cors" not in specialists:
        return {"error": "CORS Specialist not available", "findings_count": 0, "tested_params": []}
    logger.info("[%s] Delegating CORS check to SmartCORSHunter", deps["agent_name"])
    _ensure_context_defaults(deps["current_context"])
    target_task, _detection_mode = build_hunter_task(
        url=url, specialist_key="cors", task_name="CORS Check", tags=["cors"],
        params=params, kwargs=_kwargs,
        current_context=deps["current_context"],
        phase2_detection_mode=deps["phase2_detection_mode"],
        normalize_tool_supplied_params=deps["normalize_tool_supplied_params"],
        resolve_detection_mode=deps["resolve_detection_mode"],
    )
    findings = await specialists["cors"].execute(target_task, quick_mode=quick_mode) or []
    deps["current_context"]["findings"].extend(findings)
    return format_cors_hunter_result(findings=findings)


async def run_crlf_hunter_runner(
    *,
    deps: Dict[str, Any],
    url: str,
    params: Optional[Dict[str, Any]],
    quick_mode: bool = False,
    **_kwargs: Any,
) -> Dict[str, Any]:
    specialists = deps["specialists"]
    if "crlf" not in specialists:
        return {"error": "CRLF Specialist not available", "findings_count": 0, "tested_params": []}
    logger.info("[%s] Delegating CRLF check to SmartCRLFHunter", deps["agent_name"])
    effective_params = deps["normalize_tool_supplied_params"](params, _kwargs)
    _ensure_context_defaults(deps["current_context"])
    effective_params["_auth"] = _make_auth_dict(_kwargs, deps["current_context"])
    target_task = Task(
        id=f"inj_crlf_{id(url)}", name="CRLF Check", target=url,
        params=effective_params, tags=["crlf"],
    )
    findings = await specialists["crlf"].execute(target_task, quick_mode=quick_mode) or []
    deps["current_context"]["findings"].extend(findings)
    if findings:
        f = findings[0]
        return {
            "findings_count": len(findings), "success": True, "vulnerable": True,
            "vulnerability": "CRLF_INJECTION",
            "injected_header": f.additional_info.get("injected_header", "") if hasattr(f, "additional_info") else "",
            "payload": f.additional_info.get("payload", "") if hasattr(f, "additional_info") else "",
            "poc_html": f.additional_info.get("poc_html", "") if hasattr(f, "additional_info") else "",
            "evidence": f.description if hasattr(f, "description") else str(f),
            "severity": f.severity.name if hasattr(f, "severity") else "MEDIUM",
            "tested_params": f.additional_info.get("tested_params", []) if hasattr(f, "additional_info") else [],
        }
    return {
        "findings_count": 0, "success": False, "vulnerable": False,
        "tested_params": [], "message": "No CRLF injection found",
    }


async def run_graphql_hunter_runner(
    *,
    deps: Dict[str, Any],
    url: str,
    params: Optional[Dict[str, Any]],
    quick_mode: bool = False,
    **_kwargs: Any,
) -> Dict[str, Any]:
    specialists = deps["specialists"]
    if "graphql" not in specialists:
        return {"error": "GraphQL Specialist not available", "findings_count": 0, "tested_params": []}
    logger.info("[%s] Delegating GraphQL check to SmartGraphQLHunter", deps["agent_name"])
    _ensure_context_defaults(deps["current_context"])
    effective_params = deps["normalize_tool_supplied_params"](params, _kwargs)
    effective_params["_auth"] = _make_auth_dict(_kwargs, deps["current_context"])
    target_task = Task(
        id=f"inj_graphql_{id(url)}", name="GraphQL Introspection Check", target=url,
        params=effective_params, tags=["graphql"],
    )
    findings = await specialists["graphql"].execute(target_task, quick_mode=quick_mode) or []
    deps["current_context"]["findings"].extend(findings)
    if findings:
        f = findings[0]
        return {
            "findings_count": len(findings), "success": True, "vulnerable": True,
            "vulnerability": "GRAPHQL_INTROSPECTION",
            "introspection_enabled": f.additional_info.get("introspection_enabled", False) if hasattr(f, "additional_info") else False,
            "graphiql_enabled": f.additional_info.get("graphiql_enabled", False) if hasattr(f, "additional_info") else False,
            "field_suggestions_enabled": f.additional_info.get("field_suggestions_enabled", False) if hasattr(f, "additional_info") else False,
            "sensitive_fields": f.additional_info.get("sensitive_fields", []) if hasattr(f, "additional_info") else [],
            "poc_html": f.additional_info.get("poc_html", "") if hasattr(f, "additional_info") else "",
            "poc_request": f.additional_info.get("poc_request", "") if hasattr(f, "additional_info") else "",
            "poc_response": f.additional_info.get("poc_response", "") if hasattr(f, "additional_info") else "",
            "evidence": f.description if hasattr(f, "description") else str(f),
            "severity": f.severity.name if hasattr(f, "severity") else "MEDIUM",
            "tested_params": f.additional_info.get("tested_params", []) if hasattr(f, "additional_info") else [],
        }
    return {
        "findings_count": 0, "success": False, "vulnerable": False,
        "tested_params": [], "message": "No GraphQL introspection enabled",
    }


async def run_ssrf_hunter_runner(
    *,
    deps: Dict[str, Any],
    url: str,
    params: Optional[Dict[str, Any]],
    quick_mode: bool = False,
    **_kwargs: Any,
) -> Dict[str, Any]:
    specialists = deps["specialists"]
    if "ssrf" not in specialists:
        return {"error": "SSRF Specialist not available"}
    logger.info("[%s] Delegating SSRF check to SmartSSRFHunter (quick_mode=%s)", deps["agent_name"], quick_mode)
    effective_params = deps["normalize_tool_supplied_params"](params, _kwargs)
    effective_params["_auth"] = {
        "auth_headers": _kwargs.get("auth_headers", deps["current_context"].get("auth_headers")),
        "cookies": _kwargs.get("cookies", deps["current_context"].get("params", {}).get("cookies")),
    }
    target_task = Task(
        id=f"inj_ssrf_{id(url)}", name="SSRF Check", target=url,
        params=effective_params, tags=["ssrf"],
    )
    findings = await specialists["ssrf"].execute_with_retry(target_task, quick_mode=quick_mode) or []
    deps["current_context"]["findings"].extend(findings)
    tested_params: List[str] = []
    if findings and hasattr(findings[0], "additional_info"):
        tested_params = findings[0].additional_info.get("tested_params", []) or []
    if not tested_params:
        tested_params = getattr(specialists["ssrf"], "last_tested_params", []) or []
    if findings:
        f = findings[0]
        info = f.additional_info if hasattr(f, "additional_info") else {}
        return {
            "findings_count": len(findings), "success": True, "vulnerable": True,
            "vulnerability": "SSRF",
            "payload_type": info.get("payload_type", ""),
            "payload": info.get("payload", ""),
            "evidence": info.get("evidence", "") or f.description,
            "response_code": getattr(getattr(f, "evidence", None), "response_status", 0),
            "matched_variant": info.get("matched_variant", ""),
            "matched_variant_source": info.get("matched_variant_source", ""),
            "severity": f.severity.name if hasattr(f, "severity") else "HIGH",
            "tested_params": sanitize_tested_params(tested_params, excluded_params=deps["excluded_params"]),
            "poc_request": info.get("poc_request", ""),
            "poc_response": info.get("poc_response", ""),
            "poc_html": info.get("poc_html", ""),
        }
    fallback = tested_params or sanitize_tested_params(
        list(parse_qs(urlparse(url).query).keys()), excluded_params=deps["excluded_params"]
    )
    return {
        "findings_count": 0, "success": False, "vulnerable": False,
        "tested_params": fallback,
        "message": "No SSRF vulnerabilities found",
    }
