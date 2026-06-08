"""run_*_hunter 系メソッドの共通 boilerplate 抽出。

各 hunter に共通する「パラメータ正規化→auth構築→Task生成」と
結果フォーマットロジックを集約する。
"""

from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.manager_internal.result_normalizer import (
    normalize_findings_additional_info,
    sanitize_tested_params,
)


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

    cookies_str = kwargs.get("cookies") or current_context.get("params", {}).get("cookies", "")
    effective_params["_auth"] = {
        "auth_headers": kwargs.get("auth_headers", current_context.get("auth_headers", {})),
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
