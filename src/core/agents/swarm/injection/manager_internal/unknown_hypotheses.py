"""unknown URL 仮説駆動処理。

_build_unknown_hypotheses: 証拠抽出と仮説生成（純粋変換）
_build_unknown_idor_candidate_finding: IDOR/BOLA 候補 finding 構築（純粋変換）

注意: _run_unknown_hypothesis_scans は全 hunter への dispatcher であり
オーケストレーション脊柱のため抽出対象外（CTO 判断）。
"""

from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse

from src.core.agents.swarm.injection.manager_internal.result_normalizer import (
    normalize_detection_class_token,
    sanitize_tested_params,
)
from src.core.agents.swarm.injection.manager_internal.specialist_router import (
    SPECIALIST_MAP,
    select_specialists,
)
from src.core.models.finding import Evidence, Finding, Severity, VulnType


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    deduped: List[str] = []
    for item in items:
        if item and item not in deduped:
            deduped.append(item)
    return deduped


def build_unknown_hypotheses(
    url: str,
    base_params: Dict[str, Any],
    *,
    available_specialists: Set[str],
) -> Dict[str, Any]:
    parsed = urlparse(url)
    path = parsed.path.lower()
    query_keys = {k.lower() for k in parse_qs(parsed.query).keys()}
    forms = base_params.get("forms", []) if isinstance(base_params, dict) else []
    url_evidence = base_params.get("url_evidence", {}) if isinstance(base_params, dict) else {}
    if not isinstance(url_evidence, dict):
        url_evidence = {}

    source = str(url_evidence.get("source", "") or "").strip().lower()
    response_status_raw = url_evidence.get("response_status", 0)
    try:
        response_status = int(response_status_raw or 0)
    except (TypeError, ValueError):
        response_status = 0

    response_headers_raw = url_evidence.get("response_headers", {})
    if not isinstance(response_headers_raw, dict):
        response_headers_raw = {}
    response_headers = {
        str(k).strip().lower(): str(v or "")
        for k, v in response_headers_raw.items()
    }
    content_type = response_headers.get("content-type", "").lower()
    csp_header = response_headers.get("content-security-policy", "")

    response_body_snippet = str(url_evidence.get("response_body_snippet", "") or "")
    response_body_lower = response_body_snippet.lower()
    has_form_tag = bool(url_evidence.get("has_form_tag", False))

    form_fields: Set[str] = set()
    for form in forms:
        if not isinstance(form, dict):
            continue
        inputs = form.get("inputs", [])
        if isinstance(inputs, list):
            for item in inputs:
                if isinstance(item, dict):
                    name = str(item.get("name", "")).strip().lower()
                    if name:
                        form_fields.add(name)

    all_param_keys = query_keys | form_fields
    hypotheses: List[str] = []
    signals: List[str] = []

    sqli_keys = {"id", "uid", "user", "query", "search", "filter", "sort", "order", "where", "db"}
    xss_keys = {"q", "s", "query", "search", "keyword", "comment", "message", "content", "title", "name"}
    lfi_keys = {"file", "path", "page", "include", "doc", "folder", "download"}
    ssti_keys = {"template", "tpl", "view_name", "layout", "theme", "engine"}
    ssrf_keys = {"url", "uri", "target", "dest", "destination", "fetch", "proxy", "callback", "webhook", "next", "return"}
    idor_keys = {"id", "user_id", "uid", "account_id", "order_id", "invoice_id", "profile_id", "object_id"}
    crlf_keys = {"url", "redirect", "return_url", "next", "location", "forward", "continue", "redir", "dest", "target", "goto", "lang", "charset", "header", "filename"}

    if any(k in path for k in ["/render", "/tpl", "template_engine", "/jinja", "freemarker", "thymeleaf"]) \
            or (all_param_keys & ssti_keys):
        hypotheses.append("ssti")
        signals.append("ssti_signal")

    if any(k in path for k in ["sql", "query", "search", "db", "report"]) or (all_param_keys & sqli_keys):
        hypotheses.append("sqli")
        signals.append("sqli_signal")

    if any(k in path for k in ["search", "comment", "feedback", "profile", "message", "chat"]) or (all_param_keys & xss_keys) or bool(form_fields):
        hypotheses.append("xss")
        signals.append("xss_signal")

    if "/fi/" in path or any(k in path for k in ["file", "download", "include", "template", "view", "export"]) or (all_param_keys & lfi_keys):
        hypotheses.append("lfi")
        signals.append("lfi_signal")

    if any(k in path for k in ["fetch", "proxy", "webhook", "callback", "import", "connect", "ping", "redirect"]) or (all_param_keys & ssrf_keys):
        hypotheses.append("ssrf")
        signals.append("ssrf_signal")

    if "csrf" in path or any(k in path for k in ["change_password", "password_change"]):
        hypotheses.append("csrf")
        signals.append("csrf_signal")

    if any(k in path for k in ["redirect", "location", "forward", "continue", "redir"]) \
            or (all_param_keys & crlf_keys):
        hypotheses.append("crlf")
        signals.append("crlf_signal")

    if "/graphql" in path or "/gql" in path or "/graph" in path:
        hypotheses.append("graphql")
        signals.append("graphql_signal")

    graphql_keys = {"query", "mutation", "operationname", "variables"}
    if all_param_keys & graphql_keys:
        hypotheses.append("graphql")
        signals.append("graphql_param_signal")

    if "/api/" in path or "graphql" in path:
        hypotheses.append("api")
        signals.append("api_signal")

    if "/api/" in path or any(k in path for k in ["/user", "/account", "/order", "/invoice", "/profile", "/admin"]) or (all_param_keys & idor_keys):
        hypotheses.append("idor")
        signals.append("idor_signal")

    if has_form_tag:
        signals.append("form_tag_in_response")
        if not form_fields:
            hypotheses.append("xss")

    if csp_header:
        signals.append("csp_present")
        if any(token in csp_header.lower() for token in ["script-src", "unsafe-inline", "nonce-"]):
            hypotheses.append("xss")

    if "application/json" in content_type and (
        "/api/" in path
        or "graphql" in path
        or "api" in path
    ):
        hypotheses.append("idor")
        signals.append("api_json_surface")

    if any(token in path for token in ["/admin", "/manage", "/console", "/internal", "/account"]) and response_status in {200, 204, 302, 401, 403}:
        hypotheses.append("idor")
        signals.append("authz_boundary_signal")

    if any(token in response_body_lower for token in ["api_key", "secret", "authorization", "bearer "]):
        signals.append("secret_like_response")

    if source:
        signals.append(f"source_{source}")

    hypotheses = _dedupe_preserve_order(hypotheses)

    selected_specialists = select_specialists(
        hypotheses,
        available_specialists=available_specialists,
    )
    if not any(h in SPECIALIST_MAP for h in hypotheses):
        signals.append("default_unknown_path")

    return {
        "path": parsed.path,
        "query_keys": sorted(query_keys),
        "form_fields": sorted(form_fields),
        "source": source,
        "response_status": response_status,
        "content_type": content_type,
        "csp_present": bool(csp_header),
        "has_form_tag": has_form_tag,
        "hypotheses": hypotheses,
        "signals": _dedupe_preserve_order(signals),
        "selected_specialists": selected_specialists,
    }


def build_unknown_idor_candidate_finding(
    *,
    url: str,
    tested_params: List[str],
    unknown_profile: Dict[str, Any],
    source_agent_name: str,
    excluded_params: Set[str],
) -> Optional[Finding]:
    hypotheses = {
        normalize_detection_class_token(token)
        for token in (unknown_profile.get("hypotheses", []) or [])
    }
    signals = {
        normalize_detection_class_token(token)
        for token in (unknown_profile.get("signals", []) or [])
    }
    if "idor" not in hypotheses or "idor_signal" not in signals:
        return None

    sanitized_params = sanitize_tested_params(
        tested_params,
        excluded_params=excluded_params,
    )

    return Finding(
        vuln_type=VulnType.BROKEN_ACCESS_CONTROL,
        severity=Severity.MEDIUM,
        title="Potential IDOR/BOLA Object Access Surface",
        description=(
            "Object-level authorization surface was inferred from identifier-bearing account path or parameter "
            "signals. Manual verification is required."
        ),
        target_url=url,
        evidence=Evidence(
            request_method="GET",
            request_url=url,
            request_headers={},
            response_status=int(unknown_profile.get("response_status", 0) or 0),
            response_body="",
        ),
        source_agent=source_agent_name,
        confidence=0.46,
        tags=["idor", "manual_verify"],
        additional_info={
            "detection_class": "idor_bola",
            "heuristic_candidate": True,
            "verification_required": True,
            "tested_params": sanitized_params,
            "detection_mode": "phase1",
            "unknown_profile": dict(unknown_profile),
        },
    )
