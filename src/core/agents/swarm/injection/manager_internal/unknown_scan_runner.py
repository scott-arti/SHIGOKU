"""_run_unknown_hypothesis_scans の実行本体。

仮説に沿って必要な Specialist を選択実行するループ。
merged tested_params, reflection_observed, xss_evidence,
blind_correlation, findings slice の互換を維持する。
"""

import logging
from typing import Any, Callable, Dict, List

from src.core.agents.swarm.injection.manager_internal.result_normalizer import (
    normalize_blind_correlation,
    sanitize_tested_params,
)
from src.core.agents.swarm.injection.manager_internal.unknown_hypotheses import (
    build_unknown_hypotheses,
)

logger = logging.getLogger(__name__)


async def run_unknown_hypothesis_scans(
    *,
    url: str,
    base_params: Dict[str, Any],
    quick_mode: bool,
    callables: Dict[str, Callable[..., Any]],
    specialists: Dict[str, Any],
    current_context: Dict[str, Any],
    excluded_params: frozenset,
    agent_name: str,
) -> Dict[str, Any]:
    profile = build_unknown_hypotheses(
        url, base_params, available_specialists=set(specialists.keys())
    )
    selected = profile.get("selected_specialists", [])

    logger.info(
        "[%s] unknown hypothesis routing: url=%s hypotheses=%s specialists=%s",
        agent_name, url,
        profile.get("hypotheses", []), selected,
    )

    unknown_results: List[Dict[str, Any]] = []
    reflection_observed = False
    xss_evidence = ""
    blind_correlation: Dict[str, Any] = {}

    for specialist in selected:
        if specialist == "sqli":
            sqli_result = await callables["sqli"](url=url, params=base_params, quick_mode=quick_mode)
            unknown_results.append(sqli_result)
            if not blind_correlation:
                blind_correlation = normalize_blind_correlation(sqli_result.get("blind_correlation", {}) or {})
        elif specialist == "xss":
            xss_result = await callables["xss"](url=url, params=base_params, quick_mode=quick_mode)
            unknown_results.append(xss_result)
            reflection_observed = bool(xss_result.get("reflection_observed", False))
            xss_evidence = str(xss_result.get("evidence", "") or "")
        elif specialist == "lfi":
            unknown_results.append(await callables["lfi"](url=url, params=base_params, quick_mode=quick_mode))
        elif specialist == "ssti":
            ssti_result = await callables["ssti"](url=url, params=base_params, quick_mode=quick_mode)
            unknown_results.append(ssti_result)
        elif specialist == "cors":
            cors_result = await callables["cors"](url=url, params=base_params, quick_mode=quick_mode)
            unknown_results.append(cors_result)
        elif specialist == "crlf":
            crlf_result = await callables["crlf"](url=url, params=base_params, quick_mode=quick_mode)
            unknown_results.append(crlf_result)
        elif specialist == "cmd_ssrf":
            cmd_result = await callables["cmd_ssrf"](url=url, params=base_params, quick_mode=quick_mode)
            unknown_results.append(cmd_result)
            if not blind_correlation:
                blind_correlation = normalize_blind_correlation(cmd_result.get("blind_correlation", {}) or {})
        elif specialist == "ssrf":
            ssrf_result = await callables["ssrf"](url=url, params=base_params, quick_mode=quick_mode)
            unknown_results.append(ssrf_result)
        elif specialist == "graphql":
            graphql_result = await callables["graphql"](url=url, params=base_params, quick_mode=quick_mode)
            unknown_results.append(graphql_result)

    merged_params: List[str] = []
    for partial in unknown_results:
        merged_params.extend(partial.get("tested_params", []) or [])

    findings_count = sum(int(partial.get("findings_count", 0) or 0) for partial in unknown_results)
    findings_list = current_context["findings"][-findings_count:] if findings_count > 0 else []

    return {
        "findings_count": findings_count,
        "findings": findings_list,
        "tested_params": sanitize_tested_params(merged_params, excluded_params=excluded_params),
        "reflection_observed": reflection_observed,
        "xss_evidence": xss_evidence,
        "blind_correlation": normalize_blind_correlation(blind_correlation),
        "unknown_profile": profile,
    }
