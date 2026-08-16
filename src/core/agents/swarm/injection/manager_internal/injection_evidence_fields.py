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
    evidence_request_url: Optional[str] = None,
    evidence_status: Optional[Any] = None,
) -> Dict[str, Any]:
    """Evidence request identity from observed facts (Scope B).

    Returns ``{"request_method": <GET|HEAD|OPTIONS>, "request_url": <payload
    URL>, "response_status": <int>}`` when the error-based SQLi observation
    is complete and parseable; ``{}`` otherwise (fail-closed -> callers keep
    the current evidence).

    SGK-2026-0452 additive: when ``evidence_request_url`` / ``evidence_status``
    are non-None they are used verbatim instead of deriving the URL/status
    (caller pins them to the error-observation probe); None keeps the legacy
    derivation. Explicit values are still validated fail-closed (http(s) URL
    with host, positive non-bool int status).
    """
    if not bool(sql_error_observed):
        return {}
    line = _REQUEST_LINE_RE.match(str(poc_request or ""))
    if not line:
        return {}
    method = line.group(1).upper()
    if method not in _READ_ONLY_METHODS:
        return {}
    if evidence_request_url is not None:
        request_url = str(evidence_request_url)
        try:
            parsed = urlsplit(request_url)
        except ValueError:
            return {}
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return {}
    else:
        request_url = parse_observed_request_url(poc_request, target_url)
        if request_url is None:
            return {}
    if evidence_status is not None:
        try:
            raw_status = int(evidence_status)
        except (TypeError, ValueError):
            raw_status = 0
        status = (
            raw_status
            if (not isinstance(raw_status, bool) and raw_status > 0)
            else None
        )
    else:
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
    impact_probe_records: Optional[Dict[str, Any]] = None,
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

    SGK-2026-0452 additive: ``impact_probe_records`` (None or observed=False
    for both boolean_differential and extraction -> byte-identical 0449
    wording below) carries ALREADY-OBSERVED probe facts:
    ``{"boolean_differential": {"observed", "true_probe", "true_result",
    "false_probe", "false_result"}, "extraction": {"observed", "expr",
    "value", "probe", "response_excerpt"}, "error_probe": {"payload",
    "status", "marker_excerpt"}}``. When a probe is observed, the impact and
    reproduction_steps are composed from those observed facts only; unobserved
    clauses are omitted. Marker vocabulary stays ``sql_error``.
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

    records = impact_probe_records if isinstance(impact_probe_records, dict) else {}
    boolean = records.get("boolean_differential")
    boolean = boolean if isinstance(boolean, dict) else {}
    extraction = records.get("extraction")
    extraction = extraction if isinstance(extraction, dict) else {}
    error_probe = records.get("error_probe")
    error_probe = error_probe if isinstance(error_probe, dict) else {}
    boolean_observed = bool(boolean.get("observed"))
    extraction_observed = bool(extraction.get("observed"))

    if not (boolean_observed or extraction_observed):
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

    # ---- SGK-2026-0452 additive branch: observed probe facts only ----
    error_payload = str(error_probe.get("payload") or "").strip() or pay
    try:
        error_status_candidate = int(error_probe.get("status", 0))
    except (TypeError, ValueError):
        error_status_candidate = 0
    error_status = (
        error_status_candidate
        if (not isinstance(error_status_candidate, bool) and error_status_candidate > 0)
        else status
    )
    error_excerpt = _WS_RE.sub(" ", str(error_probe.get("marker_excerpt") or "")).strip()
    if error_excerpt:
        error_excerpt = error_excerpt[:120]
    elif excerpt:
        error_excerpt = excerpt
    error_excerpt_note = f" (response excerpt: '{error_excerpt}')" if error_excerpt else ""

    impact_parts = [
        f"Error-based SQL injection indicator on GET parameter '{param}': "
        f"the payload '{error_payload}' sent to {request_url} returned HTTP {error_status} "
        "with a SQL error marker observed in the response body."
    ]
    steps = [
        f"Send GET {request_url} with parameter '{param}' set to '{error_payload}'; "
        f"observed HTTP {error_status} with a SQL error marker in the response body"
        f"{error_excerpt_note}."
    ]

    if boolean_observed:
        true_probe = str(boolean.get("true_probe") or "").strip()
        true_result = str(boolean.get("true_result") or "").strip()
        false_probe = str(boolean.get("false_probe") or "").strip()
        false_result = str(boolean.get("false_result") or "").strip()
        if true_probe and true_result and false_probe and false_result:
            impact_parts.append(
                f"Boolean differential oracle: '{true_probe}' returned {true_result} "
                f"while '{false_probe}' returned {false_result}, a deterministic "
                "differential demonstrating the injected condition controls the "
                "query logic."
            )
            steps.append(
                f"Send GET {request_url} with parameter '{param}' set to '{true_probe}'; "
                f"observed {true_result}."
            )
            steps.append(
                f"Send GET {request_url} with parameter '{param}' set to '{false_probe}'; "
                f"observed {false_result}."
            )

    if extraction_observed:
        expr = str(extraction.get("expr") or "").strip()
        value = str(extraction.get("value") or "").strip()
        probe = str(extraction.get("probe") or "").strip()
        response_excerpt = _WS_RE.sub(
            " ", str(extraction.get("response_excerpt") or "")
        ).strip()
        if response_excerpt:
            response_excerpt = response_excerpt[:120]
        if expr and value:
            impact_parts.append(
                f"Non-sensitive token extraction: {expr} evaluated to '{value}' "
                "and was observed in the response body, demonstrating information "
                "disclosure of server metadata."
            )
            if probe:
                step = (
                    f"Send GET {request_url} with parameter '{param}' set to '{probe}'; "
                    f"observed '{expr}' evaluated to '{value}' in the response body"
                )
            else:
                step = f"Observed '{expr}' evaluated to '{value}' in the response body"
            if response_excerpt:
                step += f" (response excerpt: '{response_excerpt}')"
            steps.append(step + ".")

    impact = " ".join(impact_parts)
    return impact, steps
