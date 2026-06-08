from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse


def extract_form_field_names(forms: Any) -> set[str]:
    """forms 構造から field/input 名を抽出する。"""
    names: set[str] = set()
    if not isinstance(forms, list):
        return names
    for form in forms:
        if not isinstance(form, dict):
            continue
        for bucket in ("fields", "inputs"):
            fields = form.get(bucket, [])
            if not isinstance(fields, list):
                continue
            for field in fields:
                if isinstance(field, dict):
                    raw_name = field.get("name", "")
                else:
                    raw_name = field
                name = str(raw_name or "").strip().lower()
                if name:
                    names.add(name)
    return names


def score_target_priority(
    url: str,
    *,
    category: str,
    form_fields: set[str],
    url_evidence: Dict[str, Any],
) -> Tuple[int, List[str]]:
    """
    Step6 用の優先度スコアを返す。
    スコアは高いほど先行実行する。
    """
    parsed = urlparse(str(url or "").strip())
    path = str(parsed.path or "").lower()
    query_keys = {k.lower() for k in parse_qs(parsed.query, keep_blank_values=True).keys()}
    category_key = str(category or "").strip().lower()
    method = str(url_evidence.get("method", "GET") or "GET").upper()
    response_headers = url_evidence.get("response_headers", {})
    if not isinstance(response_headers, dict):
        response_headers = {}
    content_type = str(
        response_headers.get("Content-Type")
        or response_headers.get("content-type")
        or ""
    ).lower()
    response_body = str(url_evidence.get("response_body_snippet", "") or "").strip().lower()
    all_param_keys = set(query_keys) | set(form_fields)

    score = 0
    signals: List[str] = []

    category_weights = {
        "api_candidate": 45,
        "csrf_candidate": 36,
        "auth": 34,
        "id_param": 30,
        "api_data": 24,
        "xss_candidate": 18,
    }
    score += int(category_weights.get(category_key, 12))
    signals.append(f"category:{category_key or 'unknown'}")

    if "/api/" in path or "/rest/" in path or "/graphql" in path:
        score += 14
        signals.append("api_surface")

    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        score += 34
        signals.append(f"method:{method}")

    is_json_surface = (
        "application/json" in content_type
        or response_body.startswith("{")
        or response_body.startswith("[")
    )
    if is_json_surface:
        score += 20
        signals.append("json_surface")

    high_signal_params = {
        "id",
        "uid",
        "user_id",
        "account_id",
        "order_id",
        "invoice_id",
        "role",
        "roles",
        "is_admin",
        "admin",
        "permission",
        "permissions",
        "scope",
        "scopes",
        "token",
        "jwt",
        "price",
        "amount",
        "balance",
        "coupon",
    }
    if all_param_keys & high_signal_params:
        score += 24
        signals.append("high_signal_param")

    auth_boundary_tokens = {
        "account",
        "profile",
        "security",
        "password",
        "admin",
        "auth",
        "login",
        "session",
        "token",
        "user",
    }
    path_tokens = {t for t in path.split("/") if t}
    if path_tokens & auth_boundary_tokens:
        score += 18
        signals.append("auth_boundary_surface")

    if form_fields:
        score += 8
        signals.append("form_surface")

    if path in {"", "/"} and not all_param_keys:
        score -= 60
        signals.append("root_penalty")

    return score, signals


def prioritize_targets(
    targets: List[str],
    *,
    forms_by_url: Optional[Dict[str, Any]] = None,
    url_evidence_by_url: Optional[Dict[str, Dict[str, Any]]] = None,
    category: str = "",
) -> List[Tuple[str, int, List[str]]]:
    """
    URL に Step6 用スコアを付ける。

    Returns:
        (url, priority_score, priority_signals) のタプリリスト（score 降順）
    """
    forms_by_url = forms_by_url or {}
    url_evidence_by_url = url_evidence_by_url or {}
    prioritized: List[Tuple[str, int, List[str]]] = []

    for url in targets:
        forms = forms_by_url.get(url, [])
        form_fields = extract_form_field_names(forms)
        url_evidence = url_evidence_by_url.get(url, {})
        if not isinstance(url_evidence, dict):
            url_evidence = {}
        score, signals = score_target_priority(
            url,
            category=category,
            form_fields=form_fields,
            url_evidence=url_evidence,
        )
        prioritized.append((url, int(score), signals))

    prioritized.sort(key=lambda item: item[1], reverse=True)
    return prioritized
