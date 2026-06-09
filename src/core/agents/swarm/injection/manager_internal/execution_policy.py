from typing import Any, Callable, Dict, List
from urllib.parse import parse_qs, urlparse


def resolve_per_url_timeout(
    task: Any,
    target_url: str,
    vuln_type: str,
    *,
    default_timeout_seconds: int,
    timeout_by_type: Dict[str, int],
    blind_sqli_timeout_seconds: int,
) -> int:
    """URL/脆弱性タイプ別のタイムアウト秒数を決定する。"""
    path = urlparse(target_url).path.lower()
    task_params = task.params if hasattr(task, "params") and isinstance(task.params, dict) else {}

    default_timeout = int(task_params.get("per_url_timeout_seconds") or default_timeout_seconds)
    resolved_timeout_by_type = dict(timeout_by_type)
    resolved_timeout_by_type.update(task_params.get("per_url_timeout_by_type", {}))

    resolved = int(resolved_timeout_by_type.get(vuln_type, default_timeout))

    if vuln_type == "sqli" and "blind" in path:
        blind_timeout = int(
            task_params.get("per_url_timeout_blind_sqli_seconds")
            or blind_sqli_timeout_seconds
        )
        resolved = max(resolved, blind_timeout)

    if vuln_type == "xss" and "xss_s" in path:
        xss_s_timeout = int(task_params.get("per_url_timeout_xss_stored_seconds") or 240)
        resolved = max(resolved, xss_s_timeout)

    if vuln_type == "xss" and ("xss_r" in path or "javascript" in path):
        xss_reflected_timeout = int(task_params.get("per_url_timeout_xss_reflected_seconds") or 240)
        resolved = max(resolved, xss_reflected_timeout)

    if vuln_type == "sqli" and "/vulnerabilities/sqli/" in path:
        sqli_standard_timeout = int(task_params.get("per_url_timeout_sqli_standard_seconds") or 240)
        resolved = max(resolved, sqli_standard_timeout)

    return max(10, resolved)


def is_lane2_score_eligible(ssrf_score: int, risk_override: bool, *, lane2_score_threshold: int) -> bool:
    """Lane-2 昇格のスコア条件を判定する。"""
    if bool(risk_override):
        return True
    return int(ssrf_score or 0) >= int(lane2_score_threshold)


def should_force_phase2_by_risk(
    *,
    phase1_findings: List[Any],
    phase1_signals: Dict[str, bool],
    high_risk_requires_phase2: bool,
) -> bool:
    return (
        not phase1_findings
        and not phase1_signals.get("tool_error", False)
        and not phase1_signals.get("weak_signal", False)
        and bool(high_risk_requires_phase2)
    )


def cap_phase2_budget(
    *,
    remaining_budget: int,
    phase2_forced_by_risk: bool,
    task_params: Dict[str, Any],
) -> int:
    capped = max(1, int(remaining_budget))
    if phase2_forced_by_risk:
        risk_forced_cap = int(task_params.get("phase2_max_seconds_risk_forced") or 120)
        return max(1, min(capped, risk_forced_cap))
    phase2_cap = int(task_params.get("phase2_max_seconds") or 240)
    return max(1, min(capped, phase2_cap))


def resolve_risk_force_allowlist(task: Any, scan_profile: str) -> set[str]:
    """
    高リスク endpoint でも Phase2 を強制する vuln_type の allowlist を返す。
    """
    task_params = task.params if hasattr(task, "params") and isinstance(task.params, dict) else {}
    raw = task_params.get("phase2_risk_force_vuln_types")
    if isinstance(raw, list):
        return {str(v or "").strip().lower() for v in raw if str(v or "").strip()}

    allow = {"sqli", "cmd_ssrf", "ssrf", "lfi", "csrf", "api", "redirect", "ssti", "cors", "crlf", "graphql"}
    if scan_profile == "ctf":
        allow.add("xss")
    return allow


def should_auto_early_return(
    task: Any,
    *,
    phase1_findings: List[Any],
    phase1_signals: Dict[str, bool],
    phase1_vuln_types: set[str],
    coerce_bool: Callable[[Any, bool], bool],
) -> bool:
    """
    deterministic 精度が比較的高いカテゴリは finding が出た時点で自動早期終了して
    Phase2 の長時間化を避ける。
    """
    if not phase1_findings:
        return False
    if phase1_signals.get("tool_error", False):
        return False

    task_params = task.params if hasattr(task, "params") and isinstance(task.params, dict) else {}
    enabled = coerce_bool(task_params.get("phase1_auto_early_return_on_findings"), default=True)
    if not enabled:
        return False
    if not phase1_vuln_types:
        return False

    fast_types = {"lfi", "redirect", "csrf", "api"}
    if phase1_vuln_types.issubset(fast_types):
        return True

    include_cmd = coerce_bool(task_params.get("phase1_auto_early_return_cmd"), default=False)
    if include_cmd and phase1_vuln_types.issubset({"cmd_ssrf"}):
        return True

    return False


def ssrf_reachability_gate(url: str, base_params: Dict[str, Any]) -> tuple:
    """
    SSRF が成立しうる注入ポイントがあるかを判定する。
    Wave B の即効改善: 到達性が低い対象を Lane-1 から除外。
    """
    parsed = urlparse(str(url or ""))
    query_keys = {k.lower() for k in parse_qs(parsed.query, keep_blank_values=True).keys()}
    forms = base_params.get("forms", []) if isinstance(base_params, dict) else []
    url_evidence = base_params.get("url_evidence", {}) if isinstance(base_params, dict) else {}
    if not isinstance(url_evidence, dict):
        url_evidence = {}

    url_like_keys = {
        "url", "uri", "endpoint", "host", "target", "dest", "destination",
        "src", "source", "fetch", "load", "remote", "request", "webhook", "callback",
    }
    if query_keys & url_like_keys:
        return True, "query_param"

    form_field_names: set[str] = set()
    for form in forms if isinstance(forms, list) else []:
        if not isinstance(form, dict):
            continue
        for bucket in ("fields", "inputs"):
            fields = form.get(bucket, [])
            if not isinstance(fields, list):
                continue
            for field in fields:
                name = ""
                if isinstance(field, dict):
                    name = str(field.get("name", "") or "").strip().lower()
                else:
                    name = str(field or "").strip().lower()
                if name:
                    form_field_names.add(name)
    if form_field_names & url_like_keys:
        return True, "form_field"

    score = int(url_evidence.get("ssrf_score", 0) or 0)
    if score >= 40:
        return True, "score_threshold"

    breakdown = url_evidence.get("score_breakdown", {})
    if isinstance(breakdown, dict) and int(breakdown.get("graphql_variables", 0) or 0) >= 10:
        return True, "graphql_variables"

    return False, "no_ssrf_injection_point"


def build_timeout_cause_key(url: str, vuln_type: str) -> str:
    import re
    parsed = urlparse(str(url or ""))
    path = str(parsed.path or "").lower()
    path = re.sub(r"/\d+(?=/|$)", "/:num", path)
    path = re.sub(r"/[0-9a-f]{8,}(?=/|$)", "/:hex", path)
    path = re.sub(r"/{2,}", "/", path)
    query_keys = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())[:3]
    return f"{str(vuln_type or '').lower()}:{path}?{','.join(query_keys)}"


def is_high_risk_endpoint(url: str) -> bool:
    if not url:
        return False

    parsed = urlparse(url)
    path = (parsed.path or "").lower()
    query_keys = [k.lower() for k in parse_qs(parsed.query).keys()]

    high_risk_tokens = (
        "exec", "cmd",
        "sqli", "sqli_blind", "blind",
        "fi", "file_inclusion", "inclusion", "page",
        "csrf",
        "api", "/api/", "graphql",
        "open_redirect", "redirect",
        "authbypass", "weak_id",
    )

    if any(token in path for token in high_risk_tokens):
        return True

    return any(any(token in key for token in high_risk_tokens) for key in query_keys)
