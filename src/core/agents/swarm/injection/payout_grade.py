"""
SGK-2026-0441 Lane A — payout-grade PoC gate (deterministic, fail-closed).

The validation loop is modernized so candidates confirm ONLY with a
"payout-grade PoC": a reproducible request/response pair plus a firing
marker plus an impact statement. This module is the shared contract
between Lane A (manager gate / specialist stop wiring) and Lane B
(time-budget + poc_judge role):

- ``PayoutGradeResult``: deterministic verdict payload.
- ``evaluate_payout_grade(finding: dict)``: the ONLY public evaluation
  entry. Raise-only, deterministic, NO LLM calls, NEVER raises on
  malformed input (fail-closed -> ``payout_grade=False`` with a reason
  code: ``missing_evidence`` / ``not_reproducible`` /
  ``no_firing_marker`` / ``unknown_category`` / ``missing_impact``).
- ``payout_grade_stage(finding_id, result)``: returns ``"F4"`` when the
  result is payout-grade else ``None`` — used by the funnel emitters in
  ``manager.py`` (this module never emits funnel events itself).
- ``finding_payload(finding)``: guarded projection of a Finding-like
  object to the dict shape ``evaluate_payout_grade`` consumes.
- ``has_explicit_refute_signal(finding)``: fail-closed refute-signal
  detector used by the Phase-2 merge (candidates are NEVER marked
  refuted speculatively).
- ``assert_read_only_probe(method, url)``: Phase-2 verification probes
  are GET-only (approved design). The re-send loop itself is wired by
  Lane B; the guard is implemented here and unit-tested so Lane B calls
  it at the send boundary (the existing specialist send path stays
  untouched).

Marker helpers mirror the existing per-specialist deterministic helpers
so the payout-grade marker vocabulary stays in sync with the detectors:

- sql_error          -> smart_sqli ``sql_errors`` (smart_sqli.py:1097-1107),
                        ``_classify_sql_error`` patterns
                        (smart_sqli.py:1261-1355) and the ExploitVerifier
                        SQL-error regexes (exploit_verifier.py:207-215)
- reflected_payload  -> smart_xss ``suspicious_markers``
                        (smart_xss.py:202-212) + ``diff=="reflected"``
                        analog (finding-level ``reflection_observed``)
- file_content_leak  -> smart_lfi ``lfi_patterns`` (smart_lfi.py:524-534)
                        + ``additional_info.file_marker_excerpt``
- command_execution  -> smart_cmd_ssrf ``cmd_indicators``
                        (smart_cmd_ssrf.py:1186-1195) +
                        ``additional_info.command_execution_evidence``
- ssrf_callback      -> smart_cmd_ssrf ``ssrf_indicators``
                        (smart_cmd_ssrf.py:1196) + OOB/DNS blind
                        correlation confirmations
- authz_diff         -> ``additional_info.authz_differential`` proving
                        unauthenticated success vs authenticated success
                        (manager.py api probes)

Nothing here lowers any existing evidence threshold: the gate is purely
additive and every missing piece fails the candidate closed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Marker vocabulary (mirrors the specialist helpers cited above)
# ---------------------------------------------------------------------------

# smart_sqli.py:1097-1107 (sql_errors) + :1261-1355 (_classify_sql_error) +
# exploit_verifier.py:207-215 (error_patterns).
_SQL_ERROR_PATTERNS: tuple = (
    r"SQL syntax",
    r"mysql_fetch",
    r"ORA-\d+",
    r"PostgreSQL",
    r"SQLite",
    r"ODBC",
    r"JDBC",
    r"unclosed quotation mark",
    r"syntax error",
    r"mariadb",
    r"mysqli?_sql_exception",
    r"you have an error in your sql syntax",
    r"unexpected token",
    r"unexpected end of statement",
    r"parse error",
    r"invalid syntax",
    r"near.*syntax error",
    r"missing.*in expression",
    r"missing.*at or near",
    r"table.*doesn'?t exist",
    r"no such table",
    r"no such column",
    r"unknown column",
    r"invalid object name",
    r"SQLSTATE",
    r"access denied",
    r"permission denied",
)

# smart_xss.py:202-212 (suspicious_markers).
_XSS_MARKERS: tuple = (
    "<script",
    "&lt;script",
    "onerror",
    "onload",
    "javascript:",
    "alert(",
    "<img",
    "<svg",
)

# smart_lfi.py:524-534 (lfi_patterns).
_LFI_PATTERNS: tuple = (
    r"root:[^\n]*:0:0:",
    r"daemon:[^\n]*:[0-9]+:[0-9]+:",
    r"bin:[^\n]*:1:1:",
    r"www-data:[^\n]*:[0-9]+:[0-9]+:",
    r"\[extensions\]",
    r"\[fonts\]",
    r"\[boot loader\]",
    r"\[mci extensions\]",
    r"PD9waH[A-Za-z0-9+/=]{8,}",
)

# smart_cmd_ssrf.py:1186-1195 (cmd_indicators).
_CMD_INDICATORS: tuple = (
    "uid=",
    "gid=",
    "groups=",
    "root:",
    "daemon:",
    "www-data:",
    "www-data",
    "/bin/bash",
)

# smart_cmd_ssrf.py:1196 (ssrf_indicators).
_SSRF_INDICATORS: tuple = (
    "aws",
    "metadata",
    "169.254",
    "localhost",
    "127.0.0.1",
)

# Cloud-metadata response patterns (exploit_verifier.py:248-254,
# ``_verify_ssrf`` metadata_patterns).
_SSRF_METADATA_PATTERNS: tuple = (
    r"ami-[a-z0-9]+",
    r"instance-id",
    r"iam/security-credentials",
    r"metadata\.google",
    r"computeMetadata",
)

# Authz differential signals that prove unauthenticated success against an
# authenticated baseline (manager.py api probes, api_probe_analysis.py).
_AUTHZ_PROOF_SIGNALS: frozenset = frozenset(
    {"auth_success", "unauth_success", "status_improved_with_auth"}
)

# VDP-style impact markers (vdp_evidence_validator.py:64-74,
# ``_REQUIREMENT_MARKERS`` values): explicit structured proof tokens. Their
# presence in additional_info satisfies the impact/reproducibility condition
# for VDP findings that do not carry free-text impact/reproduction_steps.
_VDP_IMPACT_MARKERS: tuple = (
    "authz_impact_proven",
    "semantic_diff_observed",
    "second_account_compared",
    "request_fingerprint_matched",
    "state_change_verified",
    "state_change_readback_observed",
    "ssrf_proof_established",
    "unique_oob_callback_received",
    "timing_difference_observed",
)

# Explicit refute signals (never speculative; candidates stay candidates
# unless one of these is present).
_REFUTE_SIGNAL_KEYS: tuple = (
    "falsification",
    "falsified",
    "refuted",
    "false_positive",
)

# vuln_type -> expected marker vocabulary (known categories).
_MARKER_CATEGORIES: Dict[str, str] = {
    "sqli": "sql_error",
    "xss": "reflected_payload",
    "lfi": "file_content_leak",
    "cmd_ssrf": "command_execution",
    "os_command_injection": "command_execution",
    "rce": "command_execution",
    "ssrf": "ssrf_callback",
    "api": "authz_diff",
    "broken_access_control": "authz_diff",
    "idor": "authz_diff",
    "mass_assignment": "authz_diff",
}

# Read-only methods allowed for Phase-2 verification probes (GET-only
# design; HEAD/OPTIONS are accepted as read-only companions).
_READ_ONLY_METHODS: frozenset = frozenset({"GET", "HEAD", "OPTIONS"})

_REASON_PAYOUT_GRADE_SATISFIED = "payout_grade_satisfied"
_REASON_MISSING_EVIDENCE = "missing_evidence"
_REASON_NOT_REPRODUCIBLE = "not_reproducible"
_REASON_NO_FIRING_MARKER = "no_firing_marker"
_REASON_UNKNOWN_CATEGORY = "unknown_category"
_REASON_MISSING_IMPACT = "missing_impact"

_METHOD_TOKEN_RE = re.compile(r"^\s*(?:GET|POST|HEAD|OPTIONS|PUT|DELETE|PATCH|TRACE|CONNECT)\s+\S+", re.IGNORECASE)
_STATUS_LINE_RE = re.compile(r"^\s*HTTP/\d(?:\.\d)?\s+\d{3}")


@dataclass
class PayoutGradeResult:
    """Deterministic payout-grade verdict for one candidate finding.

    ``payout_grade`` True only when ALL evidence conditions hold;
    ``reason`` is a stable code (``payout_grade_satisfied`` on success);
    ``evidence_refs`` lists the field names that satisfied the
    reproducibility condition; ``marker`` is the matched firing marker
    vocabulary token (or None when no marker matched).
    """

    payout_grade: bool
    reason: str
    evidence_refs: list
    marker: Optional[str]


def finding_payload(finding: Any) -> dict:
    """Guarded projection of a Finding-like object to the dict shape that
    ``evaluate_payout_grade`` consumes (fail-closed: malformed input -> {}).

    Finding objects are converted via ``to_dict()`` (the canonical
    serialization); plain dicts pass through unchanged.
    """
    if isinstance(finding, dict):
        return finding
    try:
        if hasattr(finding, "to_dict") and callable(finding.to_dict):
            payload = finding.to_dict()
            if isinstance(payload, dict):
                return payload
    except Exception:  # noqa: BLE001 — boundary guard, fail closed
        pass
    return {}


def _poc_request_complete(poc_request: str) -> bool:
    """A PoC request is complete when it starts with a method + target
    (the format the specialist ``_build_poc_request`` helpers produce)."""
    return bool(_METHOD_TOKEN_RE.match(str(poc_request or "")))


def _poc_response_complete(poc_response: str) -> bool:
    """A PoC response is complete when it starts with an HTTP status line
    (the format the specialist ``_build_poc_response`` helpers produce)."""
    return bool(_STATUS_LINE_RE.match(str(poc_response or "")))


def _response_status_ok(status: Any) -> bool:
    """Fail-closed status check: a real captured HTTP status (> 0)."""
    return isinstance(status, int) and not isinstance(status, bool) and status > 0


def _response_text(*, evidence_body: str, poc_response: str) -> str:
    """The deterministic marker search text: response body + PoC response."""
    return "\n".join(
        text for text in (str(evidence_body or ""), str(poc_response or "")) if text
    )


def _match_firing_marker(
    vuln_type: str, evidence: Dict[str, Any], info: Dict[str, Any]
) -> Optional[str]:
    """Category-specific deterministic firing-marker match.

    Returns the marker vocabulary token, or None when the category is
    known but nothing fired (fail-closed).
    """
    body = _response_text(
        evidence_body=evidence.get("response_body", ""),
        poc_response=info.get("poc_response", ""),
    )
    body_lower = body.lower()

    if vuln_type == "sqli":
        if any(re.search(p, body, re.IGNORECASE) for p in _SQL_ERROR_PATTERNS):
            return "sql_error"
        return None

    if vuln_type == "xss":
        if any(marker in body_lower for marker in _XSS_MARKERS):
            return "reflected_payload"
        # finding-level analog of the specialist's diff == "reflected"
        # (smart_xss.py:199-200): reflection_observed is only ever set
        # together with vulnerable + a captured reflection.
        if bool(info.get("reflection_observed")):
            return "reflected_payload"
        return None

    if vuln_type == "lfi":
        if any(re.search(p, body, re.IGNORECASE | re.MULTILINE) for p in _LFI_PATTERNS):
            return "file_content_leak"
        if str(info.get("file_marker_excerpt") or "").strip():
            return "file_content_leak"
        return None

    if vuln_type in {"cmd_ssrf", "os_command_injection", "rce"}:
        if any(marker in body_lower for marker in _CMD_INDICATORS):
            return "command_execution"
        if info.get("command_execution_evidence"):
            return "command_execution"
        return None

    if vuln_type == "ssrf":
        if any(marker in body_lower for marker in _SSRF_INDICATORS):
            return "ssrf_callback"
        if any(re.search(p, body, re.IGNORECASE) for p in _SSRF_METADATA_PATTERNS):
            return "ssrf_callback"
        blind = info.get("blind_correlation")
        if isinstance(blind, dict):
            oob = blind.get("oob")
            dns = blind.get("dns")
            if not isinstance(oob, dict):
                oob = {}
            if not isinstance(dns, dict):
                dns = {}
            if oob.get("confirmed") or dns.get("confirmed"):
                return "ssrf_callback"
        return None

    if vuln_type in {"api", "broken_access_control", "idor", "mass_assignment"}:
        differential = info.get("authz_differential")
        if isinstance(differential, dict) and str(differential.get("scenario") or "").strip():
            signals = differential.get("signals")
            if isinstance(signals, list) and (
                ("auth_success" in signals and "unauth_success" in signals)
                or "status_improved_with_auth" in signals
            ):
                return "authz_diff"
        return None

    return None  # unknown category


def _has_vdp_impact_markers(info: Dict[str, Any]) -> bool:
    """VDP-style structured impact/repro markers (fail-closed: unknown
    markers are ignored)."""
    for key in _VDP_IMPACT_MARKERS:
        if bool(info.get(key)):
            return True
    return False


def evaluate_payout_grade(finding: dict) -> PayoutGradeResult:
    """The ONLY public payout-grade evaluation entry (SGK-2026-0441).

    Fail-closed: any missing evidence, missing impact, unknown category,
    or non-matching marker -> ``payout_grade=False`` with a stable reason
    code. Deterministic, raise-only, NO LLM calls. Accepts the dict shape
    produced by ``Finding.to_dict()`` (use ``finding_payload()`` to
    project Finding-like objects).
    """
    if not isinstance(finding, dict):
        return PayoutGradeResult(
            payout_grade=False,
            reason=_REASON_MISSING_EVIDENCE,
            evidence_refs=[],
            marker=None,
        )

    vuln_type = str(finding.get("vuln_type") or "").strip().lower()
    evidence = finding.get("evidence")
    info = finding.get("additional_info")
    if not isinstance(evidence, dict):
        evidence = {}
    if not isinstance(info, dict):
        info = {}

    # 1) Reproducibility — structured Evidence-style fields OR complete
    #    additional_info PoC pair.
    ev_method = str(evidence.get("request_method") or "").strip()
    ev_url = str(evidence.get("request_url") or "").strip()
    ev_status_ok = _response_status_ok(evidence.get("response_status"))
    ev_body = str(evidence.get("response_body") or "")
    refs: List[str] = []
    if ev_method and ev_url and ev_status_ok and ev_body:
        refs = [
            "evidence.request_method",
            "evidence.request_url",
            "evidence.response_status",
            "evidence.response_body",
        ]
    else:
        poc_request = str(info.get("poc_request") or "")
        poc_response = str(info.get("poc_response") or "")
        if _poc_request_complete(poc_request) and _poc_response_complete(poc_response):
            refs = ["additional_info.poc_request", "additional_info.poc_response"]
        else:
            partial_refs: List[str] = []
            if ev_method:
                partial_refs.append("evidence.request_method")
            if ev_url:
                partial_refs.append("evidence.request_url")
            if ev_status_ok:
                partial_refs.append("evidence.response_status")
            if ev_body:
                partial_refs.append("evidence.response_body")
            if poc_request or poc_response:
                return PayoutGradeResult(
                    payout_grade=False,
                    reason=_REASON_NOT_REPRODUCIBLE,
                    evidence_refs=partial_refs,
                    marker=None,
                )
            return PayoutGradeResult(
                payout_grade=False,
                reason=_REASON_MISSING_EVIDENCE,
                evidence_refs=partial_refs,
                marker=None,
            )

    # 2) Firing marker (category-specific, deterministic).
    expected_marker = _MARKER_CATEGORIES.get(vuln_type)
    if expected_marker is None:
        return PayoutGradeResult(
            payout_grade=False,
            reason=_REASON_UNKNOWN_CATEGORY,
            evidence_refs=refs,
            marker=None,
        )
    marker = _match_firing_marker(vuln_type, evidence, info)
    if marker is None:
        return PayoutGradeResult(
            payout_grade=False,
            reason=_REASON_NO_FIRING_MARKER,
            evidence_refs=refs,
            marker=None,
        )

    # 3) Impact: non-empty impact + non-empty reproduction steps (or
    #    VDP-style structured markers).
    impact = str(finding.get("impact") or "").strip()
    steps = finding.get("reproduction_steps")
    if not isinstance(steps, list):
        steps = [steps] if isinstance(steps, str) and steps.strip() else []
    steps_ok = bool(steps) and all(str(step).strip() for step in steps)
    if not (impact and steps_ok) and not _has_vdp_impact_markers(info):
        return PayoutGradeResult(
            payout_grade=False,
            reason=_REASON_MISSING_IMPACT,
            evidence_refs=refs,
            marker=marker,
        )

    return PayoutGradeResult(
        payout_grade=True,
        reason=_REASON_PAYOUT_GRADE_SATISFIED,
        evidence_refs=refs,
        marker=marker,
    )


def payout_grade_stage(finding_id: str, result: PayoutGradeResult) -> Optional[str]:
    """Stage token for funnel emitters: ``"F4"`` when the result is
    payout-grade, else ``None``. Pure value return — this module never
    emits funnel events (the emitters live in ``manager.py``)."""
    if getattr(result, "payout_grade", False):
        return "F4"
    return None


def has_explicit_refute_signal(finding: Any) -> bool:
    """Fail-closed refute-signal detector (Phase-2 merge).

    True ONLY when the finding carries an explicit refutation marker
    (falsification/refuted keys, or a delivery payload explicitly
    marked undelivered). Absence of evidence is NEVER a refutation.
    """
    payload = finding_payload(finding)
    info = payload.get("additional_info")
    if not isinstance(info, dict):
        return False
    if any(bool(info.get(key)) for key in _REFUTE_SIGNAL_KEYS):
        return True
    delivery = info.get("payload_delivery")
    if isinstance(delivery, dict) and delivery.get("delivered") is False:
        return True
    return False


def assert_read_only_probe(method: str, url: str) -> bool:
    """Phase-2 verification probes are GET-only (approved design).

    Returns True only for GET/HEAD/OPTIONS against a well-formed
    http(s) URL; anything else -> False (fail-closed: callers must NOT
    send the probe when False). The Phase-2 payout-grade re-send loop is
    wired by Lane B — this guard is the send boundary check it calls
    (the existing specialist send path stays untouched).
    """
    m = str(method or "").strip().upper()
    if m not in _READ_ONLY_METHODS:
        return False
    try:
        parsed = urlparse(str(url or ""))
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    except Exception:  # noqa: BLE001 — boundary guard, fail closed
        return False
