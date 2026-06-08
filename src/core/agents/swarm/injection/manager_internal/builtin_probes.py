import re
from typing import Any, Callable, Dict, List
from urllib.parse import urljoin

from src.core.models.finding import Evidence, Finding, Severity, VulnType


async def run_csrf_minimal_check(
    *,
    url: str,
    base_params: Dict[str, Any],
    request_client: Any,
    source_agent_name: str,
    findings_sink: List[Any],
    looks_like_login_page: Callable[[str], bool],
    resolve_detection_mode: Callable[[Dict[str, Any], str], str],
    coerce_bool: Callable[[Any, bool], bool],
) -> Dict[str, Any]:
    """軽量 CSRF チェック（トークン欠如 + 擬似 forged request 成立性）。"""
    from bs4 import BeautifulSoup

    auth = base_params.get("_auth", {}) if isinstance(base_params.get("_auth", {}), dict) else {}
    headers = dict(auth.get("auth_headers", {}) or {})
    cookies = str(auth.get("cookies", "") or base_params.get("cookies", "") or "")
    if cookies and "Cookie" not in headers:
        headers["Cookie"] = cookies
    response = await request_client.request(
        method="GET",
        url=url,
        headers=headers,
        timeout=30,
        use_cache=False,
        allow_redirects=True,
    )
    body = str(getattr(response, "body", "") or "")
    if looks_like_login_page(body):
        return {"findings_count": 0, "tested_params": ["username", "password"]}
    detection_mode = resolve_detection_mode(base_params, "phase1")
    soup = BeautifulSoup(body, "html.parser")
    token_name_pattern = re.compile(r"(csrf|xsrf|nonce|authenticity|token|user_token)", re.IGNORECASE)
    stateful_field_pattern = re.compile(r"(password|pass|change|update|transfer|delete|email|profile)", re.IGNORECASE)

    tokenless_forms: List[Dict[str, Any]] = []
    tested_params: List[str] = []

    for form in soup.find_all("form"):
        method = str(form.get("method", "GET") or "GET").upper()
        action = str(form.get("action", "") or "")
        fields: Dict[str, str] = {}
        has_stateful_field = False
        has_token_field = False

        for input_elem in form.find_all(["input", "textarea", "select"]):
            name = str(input_elem.get("name", "") or "").strip()
            if not name:
                continue
            value = str(input_elem.get("value", "") or "")
            fields[name] = value
            if name not in tested_params:
                tested_params.append(name)
            if stateful_field_pattern.search(name):
                has_stateful_field = True
            if token_name_pattern.search(name):
                has_token_field = True

        if not fields:
            continue
        if method not in {"GET", "POST"}:
            continue
        if not has_stateful_field and not stateful_field_pattern.search(body):
            continue
        if has_token_field:
            continue

        tokenless_forms.append({
            "method": method,
            "action": action,
            "fields": fields,
        })

    if not tokenless_forms:
        return {"findings_count": 0, "tested_params": tested_params}

    forged = tokenless_forms[0]
    forged_method = forged.get("method", "GET")
    forged_fields = dict(forged.get("fields", {}))
    forged_action = urljoin(url, str(forged.get("action", "") or "")) if forged.get("action") else url
    active_verify = coerce_bool(base_params.get("csrf_active_verify"), default=False)
    forged_headers = dict(headers)
    forged_headers.pop("Origin", None)
    forged_headers.pop("Referer", None)
    verify_status = int(getattr(response, "status", 0) or 0)
    verify_body = body
    forged_success = False

    if active_verify:
        verify_resp = await request_client.request(
            method=forged_method,
            url=forged_action,
            headers=forged_headers,
            params=forged_fields if forged_method == "GET" else None,
            data=forged_fields if forged_method == "POST" else None,
            timeout=30,
            use_cache=False,
            allow_redirects=True,
        )
        verify_body = str(getattr(verify_resp, "body", "") or "")
        verify_body_lower = verify_body.lower()
        verify_status = int(getattr(verify_resp, "status", 0) or 0)
        forged_success_markers = [
            "password has been changed",
            "password changed",
            "successfully",
            "changed.",
        ]
        forged_success = verify_status in {200, 302} and any(marker in verify_body_lower for marker in forged_success_markers)

    finding = Finding(
        vuln_type=VulnType.MISCONFIGURATION,
        severity=Severity.HIGH if forged_success else Severity.MEDIUM,
        title="CSRF Protection Missing (Tokenless Stateful Form)",
        description=(
            "State-changing form has no anti-CSRF token and forged-request replay appears to succeed."
            if forged_success
            else "State-changing form has no anti-CSRF token. Forged-request verification needs manual confirmation."
        ),
        target_url=url,
        evidence=Evidence(
            request_method=forged_method,
            request_url=forged_action,
            request_headers=forged_headers,
            request_body=str(forged_fields)[:500],
            response_status=verify_status,
            response_headers=dict(getattr(response, "headers", {}) or {}),
            response_body=verify_body[:500],
        ),
        source_agent=source_agent_name,
        confidence=0.8 if forged_success else 0.6,
        tags=["csrf_candidate", "manual_verify"],
        additional_info={
            "parameter": "",
            "payload": "",
            "payloads_used": [],
            "tested_params": tested_params,
            "detection_mode": detection_mode,
            "forged_request_succeeded": forged_success,
            "active_verify": active_verify,
        },
    )
    findings_sink.append(finding)
    return {"findings_count": 1, "tested_params": tested_params}
