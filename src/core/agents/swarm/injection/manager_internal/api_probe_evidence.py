import json
from typing import Any, Dict


def clip_http_text(raw: Any, limit: int = 1200) -> str:
    text = str(raw or "")
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n...[truncated]"


def render_http_request(
    *,
    method: str,
    request_url: str,
    request_headers: Dict[str, Any],
    request_payload: Any,
) -> str:
    lines = [f"{str(method or 'GET').upper()} {str(request_url or '').strip()} HTTP/1.1"]
    header_count = 0
    for key, value in (request_headers or {}).items():
        h_key = str(key or "").strip()
        h_val = str(value or "").strip()
        if not h_key or not h_val:
            continue
        lines.append(f"{h_key}: {h_val}")
        header_count += 1
        if header_count >= 12:
            break

    body = ""
    if isinstance(request_payload, (dict, list)):
        body = json.dumps(request_payload, ensure_ascii=False)
    elif request_payload is not None:
        body = str(request_payload)
    body = clip_http_text(body, limit=800).strip()
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines).strip()


def render_http_response(
    *,
    status_code: int,
    response_headers: Dict[str, Any],
    response_body: Any,
) -> str:
    lines = [f"HTTP/1.1 {int(status_code or 0)}"]
    header_count = 0
    for key, value in (response_headers or {}).items():
        h_key = str(key or "").strip()
        h_val = str(value or "").strip()
        if not h_key or not h_val:
            continue
        lines.append(f"{h_key}: {h_val}")
        header_count += 1
        if header_count >= 12:
            break

    body = clip_http_text(response_body, limit=800).strip()
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines).strip()
