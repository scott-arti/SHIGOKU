"""SGK-2026-0449: mechanical impact/reproduction_steps + observed-request
evidence for error-based SQLi findings (Scope B, user-approved).

Pure helpers that fill Finding.impact / Finding.reproduction_steps and the
Evidence request identity from ALREADY-OBSERVED facts only (LLM-free, no
fabrication). The fill fires ONLY when a complete error-based SQLi
observation exists (sql_error_observed True + parameter/payload non-empty +
read-only method + valid http(s) URL + real status); otherwise the helpers
return (None, None) / {} and callers leave the finding as-is (fail-closed,
bar unchanged).

payout_grade.py and sealed_reproduction_checker.py are deliberately NOT
imported here and stay untouched.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

_READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_REQUEST_LINE_RE = re.compile(
    r"^\s*(GET|HEAD|OPTIONS)\s+(\S+)\s+HTTP/\d", re.IGNORECASE
)
_HOST_LINE_RE = re.compile(r"^Host:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_STATUS_LINE_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", re.MULTILINE)
_WS_RE = re.compile(r"\s+")


def parse_observed_request_url(poc_request: str, fallback_url: str) -> Optional[str]:
    """Actual request URL from a PoC request text (observed fact).

    ``GET /path?query HTTP/1.1`` + ``Host: host[:port]`` -> full
    ``scheme://host[:port]/path?query`` URL using the fallback URL's scheme.
    Returns None when the request line, the Host header, or the fallback
    scheme cannot be parsed (fail-closed).
    """
    line = _REQUEST_LINE_RE.match(str(poc_request or ""))
    if not line:
        return None
    path = line.group(2)
    host = _HOST_LINE_RE.search(str(poc_request or ""))
    if not host:
        return None
    try:
        parsed = urlsplit(str(fallback_url or ""))
    except ValueError:
        return None
    scheme = parsed.scheme or "http"
    if scheme not in {"http", "https"}:
        return None
    return f"{scheme}://{host.group(1)}{path}"


def parse_observed_status(poc_response: str, fallback_status: Any) -> Optional[int]:
    """Observed HTTP status: ``fallback_status`` when > 0 (e.g.
    response_differential.attack_status), else the PoC response status line.
    None when neither provides a real positive status."""
    try:
        fb = int(fallback_status or 0)
    except (TypeError, ValueError):
        fb = 0
    if fb > 0:
        return fb
    m = _STATUS_LINE_RE.search(str(poc_response or ""))
    if not m:
        return None
    status = int(m.group(1))
    return status if status > 0 else None


def build_sqli_observed_evidence(
    *,
    target_url: str,
    poc_request: str,
    poc_response: str,
    attack_status: Any,
    sql_error_observed: Any,
) -> Dict[str, Any]:
    """Evidence request identity from observed facts (Scope B).

    Returns ``{"request_method": <GET|HEAD|OPTIONS>, "request_url": <payload
    URL>, "response_status": <int>}`` when the error-based SQLi observation
    is complete and parseable; ``{}`` otherwise (fail-closed -> callers keep
    the current evidence).
    """
    if not bool(sql_error_observed):
        return {}
    line = _REQUEST_LINE_RE.match(str(poc_request or ""))
    if not line:
        return {}
    method = line.group(1).upper()
    if method not in _READ_ONLY_METHODS:
        return {}
    request_url = parse_observed_request_url(poc_request, target_url)
    if request_url is None:
        return {}
    status = parse_observed_status(poc_response, attack_status)
    if status is None:
        return {}
    return {
        "request_method": method,
        "request_url": request_url,
        "response_status": status,
    }


def build_sqli_impact_and_reproduction_steps(
    *,
    parameter: Any,
    payload: Any,
    method: Any,
    request_url: Any,
    response_status: Any,
    sql_error_observed: Any,
    marker_excerpt: Any = "",
) -> Tuple[Optional[str], Optional[list]]:
    """Mechanical impact + reproduction_steps for an error-based SQLi
    observation (observed facts only).

    Fires ONLY when ``sql_error_observed`` is True AND parameter/payload are
    non-empty AND the method is read-only (GET/HEAD/OPTIONS — GET-only
    boundary) AND the URL is a valid http(s) URL AND the status is a real
    positive int. Otherwise ``(None, None)`` (fail-closed, bar unchanged).

    The impact states only what was observed: parameter, payload, URL, HTTP
    status and the sql_error marker. It explicitly labels the marker as an
    error-based injection indicator — NOT proof of data extraction.
    """
    if not bool(sql_error_observed):
        return None, None
    param = str(parameter or "").strip()
    pay = str(payload or "").strip()
    m = str(method or "").strip().upper()
    if not param or not pay or m not in _READ_ONLY_METHODS:
        return None, None
    try:
        parsed = urlsplit(str(request_url or ""))
    except ValueError:
        return None, None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None, None
    status = int(response_status or 0)
    if isinstance(status, bool) or status <= 0:
        return None, None

    excerpt = _WS_RE.sub(" ", str(marker_excerpt or "")).strip()
    if excerpt:
        excerpt = excerpt[:120]
    marker_note = f" (response excerpt: '{excerpt}')" if excerpt else ""
    impact = (
        f"Error-based SQL injection indicator on GET parameter '{param}': "
        f"the payload '{pay}' sent to {request_url} returned HTTP {status} "
        f"with a SQL error marker observed in the response body{marker_note}. "
        "The sql_error marker is an indicator of error-based injection, "
        "not proof of data extraction."
    )
    steps = [
        f"Send GET {request_url} with parameter '{param}' set to the payload '{pay}'.",
        f"Observed HTTP status {status} in the response.",
        f"The response body contains a SQL error marker (sql_error firing marker){marker_note}.",
    ]
    return impact, steps
