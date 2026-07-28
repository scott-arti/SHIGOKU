"""
HaddixEvidenceQualityValidator: evidence quality gate with shadow/enforce modes.

Implements SGK-2026-0345 P1 and SGK-2026-0347 P0/P1 — classify each finding
against vulnerability-specific proof requirements and return a verdict. Two
operating modes are supported:

* ``mode="shadow"`` (default): Returns ``EvidenceVerdict`` rows with
  ``shadow_status`` reflecting what the evidence would require. The
  ``effective_status`` mirrors ``current_status`` — no mutation occurs.
  The formatter renders the diff in the Internal Review Notes section.

* ``mode="enforce"``: The validator takes authority to reclassify findings.
  ``effective_status`` is set to ``shadow_status`` so callers (formatters)
  can use it as the authoritative confirmed/candidate split. This is the
  Bug Bounty submission-quality enforcement mode (SGK-2026-0347).

Design constraints (per plan sections 4.2-4.3, 8.5):

* Payload presence in the raw HTTP request is a *necessary* condition for
  confirmed status, never sufficient. Vuln-specific proof requirements
  (browser execution, timing samples, state change, sensitive fields, ...)
  compose the final verdict.

* ``HTTP/1.1 0`` responses are treated as ``synthetic_detector_note`` evidence
  and never count as a real HTTP response for submission purposes.

* Redaction helpers strip Cookie/Authorization/Set-Cookie/PHPSESSID/security
  tokens from raw request/response strings so the submission copy scope never
  leaks secret material.
"""
from __future__ import annotations

import hashlib
import re
import statistics
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from urllib.parse import unquote

from src.reporting.haddix_formatter import HaddixFinding


# ---------------------------------------------------------------------------
# CORS classification types (plan section 7)
# ---------------------------------------------------------------------------

CORS_WILDCARD_NO_CREDENTIALS = "wildcard_no_credentials"
CORS_WILDCARD_WITH_CREDENTIALS = "wildcard_with_credentials_invalid_combination"
CORS_ARBITRARY_ORIGIN_NO_CREDENTIALS = "arbitrary_origin_reflection_no_credentials"
CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS = "arbitrary_origin_reflection_with_credentials"
CORS_NULL_ORIGIN = "null_origin_allowed"
CORS_SUFFIX_BYPASS = "trusted_origin_suffix_bypass"
CORS_PREFIX_BYPASS = "trusted_origin_prefix_bypass"
CORS_PARSER_BYPASS = "origin_parser_bypass"
CORS_INTRANET_EXPOSURE = "intranet_resource_exposure"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class EvidenceVerdict:
    """Per-finding evidence quality verdict produced by the validator."""

    finding_id: str
    vuln_type: str
    current_status: str  # "confirmed" | "candidate"
    shadow_status: str   # "confirmed" | "candidate"
    reason_codes: List[str] = field(default_factory=list)
    payload_in_request: bool = False
    response_kind: str = "none"  # real_http | browser_evidence | synthetic_detector_note | none | timing_measurement | out_of_band_callback | transport_error | model_inference | auth_context_lost
    notes: List[str] = field(default_factory=list)
    _enforce_mode: bool = field(default=False, repr=False)
    potential_severity: str = ""  # Maximum potential severity based on vuln class (unverified)
    validated_severity: str = ""  # Confirmed severity based on attack evidence

    @property
    def effective_status(self) -> str:
        """The authoritative status after considering enforcement mode.

        In shadow mode this mirrors ``current_status`` (no mutation).
        In enforce mode this returns ``shadow_status`` (validator takes
        authority to reclassify).
        """
        if self._enforce_mode:
            return self.shadow_status
        return self.current_status

    @property
    def would_demote(self) -> bool:
        return self.current_status == "confirmed" and self.shadow_status == "candidate"

    @property
    def would_promote(self) -> bool:
        return self.current_status == "candidate" and self.shadow_status == "confirmed"


# ---------------------------------------------------------------------------
# Severity mapping (P5-1)
# ---------------------------------------------------------------------------


def determine_potential_severity(vuln_type: str) -> str:
    """Map a vulnerability class to its maximum potential severity.

    Returns the highest severity level the vulnerability class could
    potentially achieve with full attack evidence (unverified).
    Callers should distinguish this from ``validated_severity`` which
    reflects actual confirmed attack evidence.
    """
    _vuln_type = str(vuln_type or "").strip().lower().replace("-", "_").replace(" ", "_")
    # Direct matches (highest priority)
    _critical = {"command_injection", "rce", "os_command_injection"}
    _high = {"sqli", "sql_injection"}
    _medium = {
        "xss",
        "csrf",
        "broken_access_control",
        "idor",
        "cors",
        "cors_misconfiguration",
        "stored_xss",
        "reflected_xss",
        "authorization_bypass",
        "unauthenticated_api_access",
        "mass_assignment",
        "ssrf",
        "nosql_injection",
        "ssti",
        "graphql",
        "crlf_injection",
        "host_header_injection",
        "deserialization",
        "prototype_pollution",
    }
    _low = {"open_redirect", "lfi"}
    if _vuln_type in _critical:
        return "critical"
    if _vuln_type in _high:
        return "high"
    if _vuln_type in _medium:
        return "medium"
    if _vuln_type in _low:
        return "low"
    return "medium"


# ---------------------------------------------------------------------------
# Reason-code constants (plan section 7.2)
# ---------------------------------------------------------------------------

REASON_PAYLOAD_REQUEST_MISMATCH = "payload_request_mismatch"
REASON_SYNTHETIC_RESPONSE = "synthetic_response_evidence"
REASON_INSUFFICIENT_TIMING = "insufficient_timing_validation"
REASON_BROWSER_EXECUTION_MISSING = "browser_execution_missing"
REASON_STORED_REVISIT_MISSING = "stored_revisit_missing"
REASON_STATE_CHANGE_NOT_VERIFIED = "state_change_not_verified"
REASON_AUTHZ_IMPACT_NOT_PROVEN = "authz_impact_not_proven"
REASON_INSUFFICIENT_RESPONSE_DIFFERENCE = "insufficient_response_difference"
REASON_COMMAND_EXECUTION_NOT_VERIFIED = "command_execution_not_verified"
REASON_REDIRECT_TARGET_NOT_EXTERNAL = "redirect_target_not_external"
REASON_WEAK_SESSION_NOT_STATISTICALLY_VERIFIED = "weak_session_not_statistically_verified"
REASON_UNTESTED_NO_SECOND_ACCOUNT = "untested_no_second_account"
REASON_FILE_UPLOAD_IMPACT_NOT_PROVEN = "file_upload_impact_not_proven"
REASON_PUBLIC_DOCUMENTATION_NOT_AUTHZ_IMPACT = "public_documentation_not_authorization_impact"
REASON_SESSION_TAKEOVER_NOT_VERIFIED = "session_takeover_not_verified"


# ---------------------------------------------------------------------------
# Evidence type constants (P1-1)
# ---------------------------------------------------------------------------

EVIDENCE_TYPE_REAL_HTTP = "real_http_transaction"
EVIDENCE_TYPE_TIMING = "timing_measurement"
EVIDENCE_TYPE_BROWSER = "browser_execution"
EVIDENCE_TYPE_OOB = "out_of_band_callback"
EVIDENCE_TYPE_DETECTOR = "detector_observation"
EVIDENCE_TYPE_INFERENCE = "model_inference"
EVIDENCE_TYPE_MANUAL = "manual_observation"
EVIDENCE_TYPE_TRANSPORT_ERROR = "transport_error"

_SYNTHETIC_EVIDENCE_TYPES: frozenset = frozenset({
    EVIDENCE_TYPE_DETECTOR,
    EVIDENCE_TYPE_INFERENCE,
    EVIDENCE_TYPE_MANUAL,
})


# ---------------------------------------------------------------------------
# EvidenceRecord dataclass (P1-1)
# ---------------------------------------------------------------------------

@dataclass
class EvidenceRecord:
    """Structured evidence record for a finding.

    Supports multiple evidence types: real HTTP transactions, timing
    measurements, browser execution, out-of-band callbacks, detector
    observations, model inference, manual observations, and transport errors.
    """

    evidence_id: str
    evidence_type: str  # one of EVIDENCE_TYPE_* constants

    finding_id: str = ""
    detector_id: str = ""
    session_id: str = ""

    # HTTP transaction fields (for real_http_transaction type)
    request_method: str = ""
    request_scheme: str = ""
    request_host: str = ""
    request_port: int = 0
    request_path: str = ""
    request_query: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_cookies: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    request_content_type: str = ""
    request_timestamp: str = ""
    request_payload: str = ""
    request_payload_parameter: str = ""
    payload_location: str = ""

    # Response fields
    response_status_code: int = 0
    response_reason: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_elapsed_ms: float = 0.0
    response_redirect_history: List[str] = field(default_factory=list)
    response_timestamp: str = ""
    response_transport_error: str = ""

    # Timing fields (for timing_measurement type)
    timing_baseline_samples: List[float] = field(default_factory=list)
    timing_positive_samples: List[float] = field(default_factory=list)
    timing_negative_control_samples: List[float] = field(default_factory=list)
    timing_baseline_median: float = 0.0
    timing_positive_median: float = 0.0
    timing_negative_control_median: float = 0.0

    # Browser fields (for browser_execution type)
    browser_page_url: str = ""
    browser_navigation_url: str = ""
    browser_payload: str = ""
    browser_execution_token: str = ""
    browser_execution_event: str = ""
    browser_execution_timestamp: str = ""
    browser_trace_id: str = ""
    browser_dom_snapshot: str = ""
    browser_console_log: str = ""
    browser_screenshot: str = ""
    browser_auth_context: str = ""

    # Reference IDs
    baseline_request_id: str = ""
    attack_request_id: str = ""
    negative_control_request_id: str = ""

    # Metadata
    created_at: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence record to dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "finding_id": self.finding_id,
            "detector_id": self.detector_id,
            "session_id": self.session_id,
            "request_method": self.request_method,
            "request_scheme": self.request_scheme,
            "request_host": self.request_host,
            "request_port": self.request_port,
            "request_path": self.request_path,
            "request_query": self.request_query,
            "request_headers": dict(self.request_headers),
            "request_cookies": dict(self.request_cookies),
            "request_body": self.request_body,
            "request_content_type": self.request_content_type,
            "request_timestamp": self.request_timestamp,
            "request_payload": self.request_payload,
            "request_payload_parameter": self.request_payload_parameter,
            "payload_location": self.payload_location,
            "response_status_code": self.response_status_code,
            "response_reason": self.response_reason,
            "response_headers": dict(self.response_headers),
            "response_body": self.response_body,
            "response_elapsed_ms": self.response_elapsed_ms,
            "response_redirect_history": list(self.response_redirect_history),
            "response_timestamp": self.response_timestamp,
            "response_transport_error": self.response_transport_error,
            "timing_baseline_samples": list(self.timing_baseline_samples),
            "timing_positive_samples": list(self.timing_positive_samples),
            "timing_negative_control_samples": list(self.timing_negative_control_samples),
            "timing_baseline_median": self.timing_baseline_median,
            "timing_positive_median": self.timing_positive_median,
            "timing_negative_control_median": self.timing_negative_control_median,
            "browser_page_url": self.browser_page_url,
            "browser_navigation_url": self.browser_navigation_url,
            "browser_payload": self.browser_payload,
            "browser_execution_token": self.browser_execution_token,
            "browser_execution_event": self.browser_execution_event,
            "browser_execution_timestamp": self.browser_execution_timestamp,
            "browser_trace_id": self.browser_trace_id,
            "browser_dom_snapshot": self.browser_dom_snapshot,
            "browser_console_log": self.browser_console_log,
            "browser_screenshot": self.browser_screenshot,
            "browser_auth_context": self.browser_auth_context,
            "baseline_request_id": self.baseline_request_id,
            "attack_request_id": self.attack_request_id,
            "negative_control_request_id": self.negative_control_request_id,
            "created_at": self.created_at,
            "notes": list(self.notes),
        }

    def is_synthetic(self) -> bool:
        """Return True if the evidence type represents synthetic/inferred
        evidence rather than real observational data."""
        return self.evidence_type in _SYNTHETIC_EVIDENCE_TYPES


# ---------------------------------------------------------------------------
# classify_evidence_type (P1-1)
# ---------------------------------------------------------------------------

def classify_evidence_type(finding: HaddixFinding) -> str:
    """Classify a finding's evidence into one of the EVIDENCE_TYPE_* constants.

    Classification order (first match wins):
    1. Browser execution evidence → EVIDENCE_TYPE_BROWSER
    2. Timing measurement evidence → EVIDENCE_TYPE_TIMING
    3. Out-of-band callback evidence → EVIDENCE_TYPE_OOB
    4. Transport error → EVIDENCE_TYPE_TRANSPORT_ERROR
    5. HTTP/1.1 0 synthetic response → EVIDENCE_TYPE_DETECTOR
    6. Real HTTP transaction → EVIDENCE_TYPE_REAL_HTTP
    7. Fallback → EVIDENCE_TYPE_DETECTOR
    """
    info: Dict[str, Any] = finding.additional_info if isinstance(finding.additional_info, dict) else {}

    # Browser execution evidence
    browser_exec: Dict[str, Any] = info.get("browser_execution", {}) if isinstance(info.get("browser_execution"), dict) else {}
    if browser_exec and (
        bool(browser_exec.get("dialog_observed"))
        or bool(browser_exec.get("dom_mutation_observed"))
    ):
        return EVIDENCE_TYPE_BROWSER

    # Timing measurement evidence
    blind_corr: Dict[str, Any] = info.get("blind_correlation", {}) if isinstance(info.get("blind_correlation"), dict) else {}
    timing_samples: Dict[str, Any] = blind_corr.get("timing_samples", {}) if isinstance(blind_corr.get("timing_samples"), dict) else {}
    if not timing_samples:
        time_based: Dict[str, Any] = blind_corr.get("time_based", {}) if isinstance(blind_corr.get("time_based"), dict) else {}
        timing_samples = time_based.get("timing_samples", {}) if isinstance(time_based.get("timing_samples"), dict) else {}
    if timing_samples and (
        isinstance(timing_samples.get("baseline"), list) and len(timing_samples["baseline"]) >= 3
    ):
        return EVIDENCE_TYPE_TIMING

    # Out-of-band callback evidence
    if info.get("oob_evidence"):
        return EVIDENCE_TYPE_OOB

    # Transport error
    if info.get("transport_error"):
        return EVIDENCE_TYPE_TRANSPORT_ERROR

    # Check raw HTTP response
    raw_response = str(finding.poc_response or "").strip()
    if raw_response:
        if re.match(r"^HTTP/[\d.]+\s+0\b", raw_response):
            return EVIDENCE_TYPE_DETECTOR
        if re.match(r"^HTTP/[\d.]+\s+[1-9]\d*\b", raw_response):
            return EVIDENCE_TYPE_REAL_HTTP

    return EVIDENCE_TYPE_DETECTOR


# ---------------------------------------------------------------------------
# Shadow Validator Record (P5-5)
# ---------------------------------------------------------------------------

SHADOW_POLICY_VERSION = "2026-07-14"
SHADOW_VALIDATOR_VERSION = "1.0.0"


@dataclass
class ShadowValidatorRecord:
    """Per-session shadow validation audit record.

    Tracks the validator's invocation count, evaluation results for each
    evidence item, and the relationship between the current (source) verdict
    and the shadow (computed) verdict.
    """

    policy_version: str = SHADOW_POLICY_VERSION
    validator_version: str = SHADOW_VALIDATOR_VERSION
    evaluated_evidence_ids: List[str] = field(default_factory=list)
    current_verdict: str = ""  # "confirmed" or "candidate"
    shadow_verdict: str = ""   # "confirmed" or "candidate"
    rule_results: List[Dict[str, Any]] = field(default_factory=list)
    invocation_count: int = 0
    evaluation_error: Optional[str] = None


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class HaddixEvidenceQualityValidator:
    """Evidence quality validator with shadow and enforce modes.

    In shadow mode (default), the validator does not mutate the existing
    confirmed/candidate split — it returns ``EvidenceVerdict`` rows with
    ``effective_status`` equal to ``current_status``. Callers render the diff
    in the Internal Review Notes section.

    In enforce mode (``mode="enforce"``), ``effective_status`` reflects the
    evidence quality verdict, giving the validator authority to reclassify
    findings. This is the Bug Bounty submission-quality enforcement mode
    (SGK-2026-0347 P1).
    """

    def __init__(self, mode: str = "shadow") -> None:
        if mode not in ("shadow", "enforce"):
            raise ValueError(f"Invalid mode {mode!r}; expected 'shadow' or 'enforce'")
        self._mode = mode
        self._enforce = mode == "enforce"
        self._shadow_records: List[ShadowValidatorRecord] = []
        self._invocation_counter: int = 0

    # Headers / tokens that must never appear verbatim in submission evidence.
    _SENSITIVE_HEADER_RE = re.compile(
        r"^(?P<name>Cookie|Authorization|Set-Cookie|X-Api-Key|X-Auth-Token|Proxy-Authorization)"
        r"\s*:\s*(?P<value>.*)$",
        re.IGNORECASE | re.MULTILINE,
    )
    _SECRET_TOKEN_RE = re.compile(
        r"(?P<key>PHPSESSID|sessionid|session|csrf_token|csrftoken|access_token|api_key|apikey|secret|token|password|passwd)"
        r"\s*[=:]\s*(?P<value>[^;\s&\"'<>]+)",
        re.IGNORECASE,
    )
    _HTTP_ZERO_STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+0\s*$", re.MULTILINE)

    # ------------------------------------------------------------------
    # Internal helpers for safe dict access (also keeps the type checker
    # honest about None-safety without runtime cost).
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_dict(value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _safe_list(value: Any) -> List[Any]:
        return value if isinstance(value, list) else []

    @staticmethod
    def _validate_timing_samples(timing_data: dict) -> List[str]:
        """Validate timing evidence requirements for blind/time-based
        vulnerabilities.

        Requires:
        * baseline: >= 3 samples
        * positive: >= 3 samples
        * negative_control: >= 1 sample

        Returns ``[REASON_INSUFFICIENT_TIMING]`` if any requirement is not met.
        Returns an empty list when timing evidence is sufficient.
        """
        baseline = HaddixEvidenceQualityValidator._safe_list(timing_data.get("baseline"))
        positive = (
            HaddixEvidenceQualityValidator._safe_list(timing_data.get("sleep"))
            or HaddixEvidenceQualityValidator._safe_list(timing_data.get("positive"))
        )
        negative_control = (
            HaddixEvidenceQualityValidator._safe_list(timing_data.get("inverse_condition"))
            or HaddixEvidenceQualityValidator._safe_list(timing_data.get("negative_control"))
        )
        if len(baseline) < 3 or len(positive) < 3 or len(negative_control) < 1:
            return [REASON_INSUFFICIENT_TIMING]
        return []

    # ------------------------------------------------------------------
    # Single-finding evaluation
    # ------------------------------------------------------------------

    def evaluate_finding(
        self,
        finding: HaddixFinding,
        *,
        current_status: str,
    ) -> EvidenceVerdict:
        vuln_type = self._normalize_vuln_type(finding.vuln_type)
        verdict = EvidenceVerdict(
            finding_id=str(finding.title or vuln_type or "unknown"),
            vuln_type=vuln_type,
            current_status=self._normalize_status(current_status),
            shadow_status="confirmed",
            reason_codes=[],
            payload_in_request=False,
            response_kind=self._classify_response_kind(finding),
            notes=[],
            _enforce_mode=self._enforce,
        )
        # P5-1: Set potential severity based on vulnerability class
        verdict.potential_severity = determine_potential_severity(vuln_type)

        # Necessary condition #1: payload must be in the raw request
        verdict.payload_in_request = self._payload_in_raw_request(finding)
        if finding.payloads_used and not verdict.payload_in_request:
            verdict.reason_codes.append(REASON_PAYLOAD_REQUEST_MISMATCH)

        # Necessary condition #2: response evidence must not be synthetic
        if verdict.response_kind == "synthetic_detector_note":
            verdict.reason_codes.append(REASON_SYNTHETIC_RESPONSE)
        elif verdict.response_kind == "none" and not self._has_alt_real_evidence(finding):
            verdict.reason_codes.append(REASON_SYNTHETIC_RESPONSE)

        # Necessary condition #3: vuln-specific proof matrix
        verdict.reason_codes.extend(self._vuln_specific_gaps(finding, vuln_type))

        # Compose final shadow status
        if verdict.reason_codes:
            verdict.shadow_status = "candidate"
        else:
            verdict.shadow_status = "confirmed"

        # Set validated_severity when confirmed with actual evidence
        if verdict.shadow_status == "confirmed" and verdict.potential_severity:
            verdict.validated_severity = verdict.potential_severity

        # P5-5: Record shadow evaluation
        self._invocation_counter += 1
        try:
            shadow_record = ShadowValidatorRecord(
                policy_version=SHADOW_POLICY_VERSION,
                validator_version=SHADOW_VALIDATOR_VERSION,
                evaluated_evidence_ids=[verdict.finding_id],
                current_verdict=verdict.current_status,
                shadow_verdict=verdict.shadow_status,
                rule_results=[{"reason_codes": list(verdict.reason_codes)}],
                invocation_count=self._invocation_counter,
            )
            self._shadow_records.append(shadow_record)
        except Exception as exc:
            shadow_record = ShadowValidatorRecord(
                policy_version=SHADOW_POLICY_VERSION,
                validator_version=SHADOW_VALIDATOR_VERSION,
                evaluated_evidence_ids=[verdict.finding_id],
                current_verdict=verdict.current_status,
                shadow_verdict=verdict.shadow_status,
                rule_results=[],
                invocation_count=self._invocation_counter,
                evaluation_error=str(exc),
            )
            self._shadow_records.append(shadow_record)

        return verdict

    # ------------------------------------------------------------------
    # Batch evaluation
    # ------------------------------------------------------------------

    def evaluate_findings(
        self,
        *,
        findings: List[HaddixFinding],
        current_statuses: List[str],
    ) -> List[EvidenceVerdict]:
        if len(findings) != len(current_statuses):
            raise ValueError(
                f"findings and current_statuses length mismatch: "
                f"{len(findings)} != {len(current_statuses)}"
            )
        return [
            self.evaluate_finding(finding, current_status=status)
            for finding, status in zip(findings, current_statuses)
        ]

    def summarize_diff(self, verdicts: List[EvidenceVerdict]) -> Dict[str, int]:
        would_demote = sum(1 for v in verdicts if v.would_demote)
        would_promote = sum(1 for v in verdicts if v.would_promote)
        match = sum(
            1 for v in verdicts
            if v.shadow_status == v.current_status
        )
        return {
            "total": len(verdicts),
            "would_demote": would_demote,
            "would_promote": would_promote,
            "match": match,
        }

    def get_shadow_records(self) -> List[ShadowValidatorRecord]:
        """Return all shadow validator records collected during evaluations."""
        return list(self._shadow_records)

    # ------------------------------------------------------------------
    # Vuln-type-specific proof requirements (plan section 7.2)
    # ------------------------------------------------------------------

    def _vuln_specific_gaps(self, finding: HaddixFinding, vuln_type: str) -> List[str]:
        gaps: List[str] = []
        info = self._safe_dict(finding.additional_info)

        if vuln_type in {"sqli", "sql_injection", "nosql_injection"}:
            gaps.extend(self._sqli_gaps(finding, info, vuln_type))
        elif vuln_type in {"xss", "reflected_xss"}:
            gaps.extend(self._reflected_xss_gaps(info))
        elif vuln_type in {"stored_xss"}:
            gaps.extend(self._stored_xss_gaps(info))
        elif vuln_type in {"lfi"}:
            gaps.extend(self._lfi_gaps(info))
        elif vuln_type in {"csrf"}:
            gaps.extend(self._csrf_gaps(info))
        elif vuln_type in {
            "broken_access_control",
            "idor",
            "unauthenticated_api_access",
            "authorization_bypass",
        }:
            gaps.extend(self._authz_gaps(finding, info))
        elif vuln_type in {"session_fixation"}:
            gaps.extend(self._session_fixation_gaps(info))
        elif vuln_type in {"command_injection", "os_command_injection", "rce", "command_injection/ssrf"}:
            # command_injection/ssrf is split: both command_injection and ssrf
            # gaps are evaluated independently.
            gaps.extend(self._command_injection_gaps(info))
        elif vuln_type in {"ssrf", "server_side_request_forgery"}:
            gaps.extend(self._ssrf_gaps(info))
        elif vuln_type in {"open_redirect"}:
            gaps.extend(self._open_redirect_gaps(info))
        elif vuln_type in {"weak_session"}:
            gaps.extend(self._weak_session_gaps(info))
        elif vuln_type in {"file_upload", "unrestricted_file_upload"}:
            gaps.extend(self._file_upload_gaps(info))
        elif vuln_type in {"cors", "cors_misconfiguration", "misconfiguration"}:
            gaps.extend(self._cors_gaps(finding, info))

        # De-dup while preserving order
        seen: set[str] = set()
        ordered: List[str] = []
        for gap in gaps:
            if gap not in seen:
                seen.add(gap)
                ordered.append(gap)
        return ordered

    def _sqli_gaps(
        self,
        finding: HaddixFinding,
        info: Dict[str, Any],
        vuln_type: str,
    ) -> List[str]:
        gaps: List[str] = []
        blind = self._safe_dict(info.get("blind_correlation"))
        time_based = self._safe_dict(blind.get("time_based"))
        # If the finding relies on blind/time-based evidence, require timing samples.
        relies_on_timing = bool(time_based.get("confirmed")) or bool(blind.get("correlated"))
        if relies_on_timing:
            # Accept timing_samples at either blind_correlation.timing_samples
            # (canonical location in session evidence) or
            # blind_correlation.time_based.timing_samples (legacy/inline).
            timing_samples = self._safe_dict(blind.get("timing_samples")) or self._safe_dict(
                time_based.get("timing_samples")
            )
            gaps.extend(self._validate_timing_samples(timing_samples))
        else:
            # Non-blind SQLi: require control/attack differential or SQL error marker
            authz = self._safe_dict(info.get("authz_differential"))
            has_differential = bool(authz) or bool(info.get("boolean_differential")) or bool(info.get("response_differential"))
            has_sql_error = bool(info.get("sql_error_observed"))
            if not has_differential and not has_sql_error:
                gaps.append(REASON_INSUFFICIENT_RESPONSE_DIFFERENCE)
        return gaps

    def _validate_browser_execution(self, finding: Optional[HaddixFinding], info: Dict[str, Any]) -> List[str]:
        """Validate browser execution evidence for XSS findings.

        Returns ``[REASON_BROWSER_EXECUTION_MISSING]`` if no browser execution
        evidence is present or if contradictory markers exist.
        Returns an empty list when evidence is sufficient.
        """
        browser_exec = self._safe_dict(info.get("browser_execution"))
        dialog_observed = bool(browser_exec.get("dialog_observed"))
        dom_mutation = bool(browser_exec.get("dom_mutation_observed"))
        execution_token = str(browser_exec.get("execution_token", "") or "").strip()
        if not (dialog_observed or dom_mutation or execution_token):
            return [REASON_BROWSER_EXECUTION_MISSING]
        # Check for contradictory markers: the detector says execution was
        # observed but also reports browser execution is missing.
        if info.get("runtime_execution_observed") and info.get("browser_execution_missing"):
            return [REASON_BROWSER_EXECUTION_MISSING]
        return []

    def _reflected_xss_gaps(self, info: Dict[str, Any]) -> List[str]:
        return self._validate_browser_execution(None, info)

    def _stored_xss_gaps(self, info: Dict[str, Any]) -> List[str]:
        gaps: List[str] = []
        browser_exec = self._safe_dict(info.get("browser_execution"))
        revisit = self._safe_dict(info.get("stored_xss_revisit"))
        if not (bool(browser_exec.get("dialog_observed")) or bool(browser_exec.get("dom_mutation_observed"))):
            gaps.append(REASON_BROWSER_EXECUTION_MISSING)
        if not revisit or not (revisit.get("revisit_request_id") or revisit.get("save_request_id")):
            gaps.append(REASON_STORED_REVISIT_MISSING)
        return gaps

    def _lfi_gaps(self, info: Dict[str, Any]) -> List[str]:
        """LFI needs a file marker excerpt as evidence of successful file
        inclusion. A marker (e.g. 'root:x:0:0:') confirms the targeted file
        was actually read by the server."""
        marker = str(info.get("file_marker_excerpt", "") or "").strip()
        if not marker:
            return [REASON_INSUFFICIENT_RESPONSE_DIFFERENCE]
        return []

    def _csrf_gaps(self, info: Dict[str, Any]) -> List[str]:
        state_change = self._safe_dict(info.get("csrf_state_change"))
        if not state_change or not (
            state_change.get("before_state") is not None
            and state_change.get("after_state") is not None
        ):
            return [REASON_STATE_CHANGE_NOT_VERIFIED]
        return []

    def _authz_gaps(self, finding: HaddixFinding, info: Dict[str, Any]) -> List[str]:
        if self._is_public_api_documentation(finding):
            return [REASON_PUBLIC_DOCUMENTATION_NOT_AUTHZ_IMPACT]
        differential = self._safe_dict(info.get("authz_differential"))
        precondition_status = str(differential.get("precondition_status", "") or "").lower()
        reason = str(differential.get("reason", "") or "").lower()
        if (
            differential.get("requires_second_account")
            or precondition_status == "second_account_not_available"
            or reason == "second_account_not_available"
        ):
            return [REASON_UNTESTED_NO_SECOND_ACCOUNT]
        scenario = str(differential.get("scenario", "") or "").lower()
        cookie_name = str(differential.get("cookie_name", "") or "").lower()
        second_account_verified = bool(
            differential.get("second_account_verified")
            or differential.get("victim_account_verified")
            or differential.get("cross_account_verified")
        )
        session_cookie_names = {"phpsessid", "sessionid", "sid", "session"}
        session_cookie_probe = bool(cookie_name in session_cookie_names or "session" in cookie_name)
        if not second_account_verified and (
            scenario in {"cookie_privilege_escalation", "session_privilege_escalation"}
            or (session_cookie_probe and "privilege" in scenario)
        ):
            return [REASON_UNTESTED_NO_SECOND_ACCOUNT]
        weak_session = self._safe_dict(info.get("weak_session_id"))
        if weak_session and not second_account_verified and not differential:
            return [REASON_UNTESTED_NO_SECOND_ACCOUNT]
        signals = self._safe_list(differential.get("signals"))
        sensitive_signal_tokens = {
            "email_exposed",
            "api_key_exposed",
            "token_exposed",
            "secret_exposed",
            "balance_exposed",
            "pii_exposed",
            "credential_exposed",
        }
        has_sensitive_signal = any(
            str(s).lower() in sensitive_signal_tokens
            for s in self._flatten_signal_names(signals)
        )
        # Also accept a body-excerpt hint that contains known sensitive fields.
        has_sensitive_in_body = self._response_body_has_sensitive_field(finding)

        baseline_status = differential.get("baseline_status")
        test_status = differential.get("test_status")
        differential_status = (
            str(baseline_status) != str(test_status)
            and baseline_status is not None
            and test_status is not None
        )

        if not has_sensitive_signal and not has_sensitive_in_body and not differential_status:
            return [REASON_AUTHZ_IMPACT_NOT_PROVEN]
        if not has_sensitive_signal and not has_sensitive_in_body:
            # 200->200 alone is insufficient; need a sensitive-field root cause.
            return [REASON_AUTHZ_IMPACT_NOT_PROVEN]
        return []

    @staticmethod
    def _is_public_api_documentation(finding: HaddixFinding) -> bool:
        """Recognise API-description documents without relying on endpoint names.

        A public OpenAPI/Swagger/AsyncAPI document can contain contact email
        addresses and API-like paths, but that alone does not prove an
        authorization failure or exposure of a protected resource.
        """
        response = str(finding.poc_response or "")
        _, _, body = response.partition("\n\n")
        normalized = body.strip().lower()
        if not normalized:
            return False
        return (
            normalized.startswith("openapi:")
            or normalized.startswith("swagger:")
            or normalized.startswith("asyncapi:")
        )

    def _command_injection_gaps(self, info: Dict[str, Any]) -> List[str]:
        evidence = self._safe_dict(info.get("command_execution_evidence"))
        if not evidence or not (evidence.get("output_observed") or evidence.get("timing_confirmed")):
            return [REASON_COMMAND_EXECUTION_NOT_VERIFIED]
        # When confirmed via timing (not output), validate timing samples if present.
        if evidence.get("timing_confirmed") and not evidence.get("output_observed"):
            blind_corr = self._safe_dict(info.get("blind_correlation"))
            timing_samples = self._safe_dict(blind_corr.get("timing_samples"))
            if not timing_samples:
                time_based = self._safe_dict(blind_corr.get("time_based"))
                timing_samples = self._safe_dict(time_based.get("timing_samples"))
            # Only validate when timing samples are present; if absent, trust the
            # timing_confirmed flag from the detector.
            if timing_samples:
                timing_gaps = self._validate_timing_samples(timing_samples)
                if timing_gaps:
                    return timing_gaps
        # Check for negative control timing — if negative control also shows
        # significant delay, the finding does NOT confirm.
        blind_corr = self._safe_dict(info.get("blind_correlation"))
        timing_samples = self._safe_dict(blind_corr.get("timing_samples"))
        if not timing_samples:
            time_based = self._safe_dict(blind_corr.get("time_based"))
            timing_samples = self._safe_dict(time_based.get("timing_samples"))
        if timing_samples:
            negative = self._safe_list(timing_samples.get("inverse_condition")) or self._safe_list(timing_samples.get("negative_control"))
            baseline = self._safe_list(timing_samples.get("baseline"))
            positive = self._safe_list(timing_samples.get("sleep")) or self._safe_list(timing_samples.get("positive"))
            if negative and baseline and positive:
                neg_median = statistics.median(negative) if negative else 0
                base_median = statistics.median(baseline) if baseline else 0
                pos_median = statistics.median(positive) if positive else 0
                # If negative control delay is closer to positive than baseline,
                # the timing is unreliable.
                if pos_median > base_median and (neg_median - base_median) > (pos_median - base_median) * 0.5:
                    return [REASON_INSUFFICIENT_TIMING]
        return []

    def _ssrf_gaps(self, info: Dict[str, Any]) -> List[str]:
        """SSRF requires evidence of server-side request to an internal or
        attacker-controlled endpoint, not just a URL parameter that happens
        to be reflected."""
        ssrf_evidence = self._safe_dict(info.get("ssrf_evidence"))
        if not ssrf_evidence or not (
            ssrf_evidence.get("internal_host_reached")
            or ssrf_evidence.get("callback_received")
            or ssrf_evidence.get("metadata_fetched")
        ):
            return [REASON_COMMAND_EXECUTION_NOT_VERIFIED]
        return []

    def _open_redirect_gaps(self, info: Dict[str, Any]) -> List[str]:
        evidence = self._safe_dict(info.get("open_redirect_evidence"))
        if not evidence or not evidence.get("location_header_external") and not evidence.get("navigation_observed"):
            return [REASON_REDIRECT_TARGET_NOT_EXTERNAL]
        return []

    def _weak_session_gaps(self, info: Dict[str, Any]) -> List[str]:
        evidence = self._safe_dict(info.get("weak_session_evidence"))
        if not evidence or not evidence.get("sample_set") or not evidence.get("predictability_evidence"):
            return [REASON_WEAK_SESSION_NOT_STATISTICALLY_VERIFIED]
        return []

    def _session_fixation_gaps(self, info: Dict[str, Any]) -> List[str]:
        """Require a verified attacker reuse path, not only stable cookies."""
        evidence = self._safe_dict(info.get("session_fixation_evidence"))
        required = (
            "attacker_controlled_session_id",
            "victim_login_completed",
            "attacker_authenticated_reuse_verified",
        )
        if not all(bool(evidence.get(key)) for key in required):
            return [REASON_SESSION_TAKEOVER_NOT_VERIFIED]
        return []

    def _file_upload_gaps(self, info: Dict[str, Any]) -> List[str]:
        evidence = self._safe_dict(info.get("file_upload_evidence"))
        upload_allowed = bool(evidence.get("upload_allowed"))
        impact_observed = bool(evidence.get("retrieved")) or bool(evidence.get("execution_observed"))
        if not upload_allowed or not impact_observed:
            return [REASON_FILE_UPLOAD_IMPACT_NOT_PROVEN]
        return []

    # ------------------------------------------------------------------
    # CORS classification and gap detection (P2-1)
    # ------------------------------------------------------------------

    def classify_cors(self, finding: HaddixFinding) -> str:
        """Classify CORS misconfiguration from real response headers.

        Classification MUST come from actual response headers, not from
        detector descriptions. Returns one of CORS_* constants or empty
        string if not classifiable.
        """
        # Parse Access-Control-Allow-Origin from response
        acao = self._parse_response_header(finding, "Access-Control-Allow-Origin")
        # Parse Access-Control-Allow-Credentials from response
        acac = self._parse_response_header(finding, "Access-Control-Allow-Credentials")
        # Check request Origin header
        request_origin = self._parse_request_header(finding, "Origin")

        # wildcard_no_credentials: ACAO:* AND ACAC:false/absent
        if acao == "*":
            if acac and acac.lower() == "true":
                return CORS_WILDCARD_WITH_CREDENTIALS
            return CORS_WILDCARD_NO_CREDENTIALS

        # null_origin_allowed: ACAO:null
        if acao == "null":
            return CORS_NULL_ORIGIN

        # arbitrary_origin_reflection: ACAO echoes request Origin AND Origin is present
        if request_origin and acao and acao == request_origin:
            if acac and acac.lower() == "true":
                return CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS
            return CORS_ARBITRARY_ORIGIN_NO_CREDENTIALS

        return ""

    def cors_severity(self, finding: HaddixFinding, cors_classification: str) -> str:
        """Determine CORS severity based on classification and impact evidence.

        Severity levels consider:
        1. Specific readable data
        2. Data confidentiality
        3. Credential requirement
        4. Whether attacker can directly get same data
        """
        if cors_classification == CORS_WILDCARD_NO_CREDENTIALS:
            if not self._has_credential_sensitive_data(finding):
                return "info"
            return "low"
        if cors_classification == CORS_WILDCARD_WITH_CREDENTIALS:
            return "high"
        if cors_classification in (CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS,):
            return "high"
        if cors_classification == CORS_ARBITRARY_ORIGIN_NO_CREDENTIALS:
            return "medium"
        if cors_classification == CORS_NULL_ORIGIN:
            return "medium"
        if cors_classification in (CORS_SUFFIX_BYPASS, CORS_PREFIX_BYPASS, CORS_PARSER_BYPASS):
            return "high"
        if cors_classification == CORS_INTRANET_EXPOSURE:
            return "critical"
        return "medium"

    def _cors_gaps(self, finding: HaddixFinding, info: Dict[str, Any]) -> List[str]:
        """CORS-specific evidence gaps."""
        gaps: List[str] = []
        cors_class = self.classify_cors(finding)
        if not cors_class:
            return ["cors_classification_failed"]

        # wildcard_no_credentials on public-only data → informational, not confirmed
        if cors_class == CORS_WILDCARD_NO_CREDENTIALS:
            if not self._has_credential_sensitive_data(finding):
                return ["public_data_cross_origin_read"]

        return gaps

    def _has_credential_sensitive_data(self, finding: HaddixFinding) -> bool:
        """Check if CORS vulnerability exposes credential-protected sensitive data.

        Returns True if:
        - Access-Control-Allow-Credentials: true is set (credentials required)
        - OR response body contains known sensitive fields
        """
        # Check if credentials are required (ACAC:true)
        acac = self._parse_response_header(finding, "Access-Control-Allow-Credentials")
        if acac and acac.lower() == "true":
            return True
        # Check response body for sensitive fields
        body = str(finding.poc_response or "").lower()
        sensitive_tokens = (
            "email",
            "token",
            "secret",
            "password",
            "api_key",
            "apikey",
            "ssn",
            "credit_card",
            "balance",
            "user",
            "account",
        )
        return any(token in body for token in sensitive_tokens)

    # ------------------------------------------------------------------
    # HTTP header parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_response_header(finding: HaddixFinding, header_name: str) -> str:
        """Parse a specific header value from the raw HTTP response string.

        Parses only the header section (after status line, before the
        first blank line). Returns empty string if header is not found.
        """
        raw_response = str(finding.poc_response or "")
        if not raw_response:
            return ""
        lines = raw_response.split("\n")
        # Skip the status line (first line), then parse headers until blank line
        for line in lines[1:]:
            stripped = line.strip()
            if not stripped:
                break  # end of header section
            if stripped.lower().startswith(header_name.lower() + ":"):
                return stripped.split(":", 1)[1].strip()
        return ""

    @staticmethod
    def _parse_request_header(finding: HaddixFinding, header_name: str) -> str:
        """Parse a specific header value from the raw HTTP request string.

        Parses only the header section (after the request line, before the
        first blank line). Returns empty string if header is not found.
        """
        raw_request = str(finding.poc_request or "")
        if not raw_request:
            return ""
        lines = raw_request.split("\n")
        # Skip the request line (first line), then parse headers until blank line
        for line in lines[1:]:
            stripped = line.strip()
            if not stripped:
                break  # end of header section
            if stripped.lower().startswith(header_name.lower() + ":"):
                return stripped.split(":", 1)[1].strip()
        return ""

    # ------------------------------------------------------------------
    # Payload-in-request detection
    # ------------------------------------------------------------------

    def _payload_in_raw_request(self, finding: HaddixFinding) -> bool:
        payloads = [str(p).strip() for p in (finding.payloads_used or []) if str(p).strip()]
        if not payloads:
            # No payloads to verify against; treat as "no payload requirement"
            return True
        # DOM XSS: payloads in URL fragments are not sent in HTTP requests.
        info = self._safe_dict(finding.additional_info)
        if str(info.get("payload_location", "") or "").lower() == "fragment":
            return True
        raw_request = str(finding.poc_request or "")
        if not raw_request.strip():
            return False
        haystack = raw_request
        haystack_decoded = unquote(raw_request)
        for payload in payloads:
            if self._payload_present(payload, haystack, haystack_decoded):
                return True
        return False

    @staticmethod
    def _payload_present(payload: str, raw: str, decoded: str) -> bool:
        if not payload:
            return False
        if payload in raw or payload in decoded:
            return True
        # Tolerate simple obfuscations: whitespace/quote variants in SQLi payloads.
        compact_payload = re.sub(r"\s+", " ", payload).strip()
        if compact_payload and (compact_payload in raw or compact_payload in decoded):
            return True
        # URL-encoded form
        encoded = re.sub(r"\s", "+", compact_payload)
        if encoded and (encoded in raw or encoded in decoded):
            return True
        return False

    # ------------------------------------------------------------------
    # Response classification
    # ------------------------------------------------------------------

    def _classify_response_kind(self, finding: HaddixFinding) -> str:
        info = self._safe_dict(finding.additional_info)
        browser_exec = self._safe_dict(info.get("browser_execution"))
        if browser_exec and (
            bool(browser_exec.get("dialog_observed"))
            or bool(browser_exec.get("dom_mutation_observed"))
        ):
            return "browser_evidence"

        # Auth context lost (distinct from evidence missing)
        if browser_exec and bool(browser_exec.get("auth_context_lost")):
            return "auth_context_lost"

        # Timing measurement evidence
        blind_corr = self._safe_dict(info.get("blind_correlation"))
        timing_samples = self._safe_dict(blind_corr.get("timing_samples"))
        if not timing_samples:
            time_based = self._safe_dict(blind_corr.get("time_based"))
            timing_samples = self._safe_dict(time_based.get("timing_samples"))
        if timing_samples:
            baseline = self._safe_list(timing_samples.get("baseline"))
            if len(baseline) >= 3:
                return "timing_measurement"

        # Out-of-band callback evidence
        if info.get("oob_evidence"):
            return "out_of_band_callback"

        # Transport error (before raw response to avoid fake status codes)
        if info.get("transport_error"):
            return "transport_error"

        # Model inference evidence
        if info.get("model_inference"):
            return "model_inference"

        raw_response = str(finding.poc_response or "")
        if not raw_response.strip():
            return "none"
        if self._HTTP_ZERO_STATUS_RE.search(raw_response):
            return "synthetic_detector_note"
        if re.match(r"^HTTP/[\d.]+\s+[1-9]\d*\b", raw_response):
            return "real_http"
        # Fallback: body-only response with non-synthetic content
        return "real_http"

    @staticmethod
    def _has_alt_real_evidence(finding: HaddixFinding) -> bool:
        """Return True if there is a non-synthetic alternate evidence artifact
        (browser/state-change/differential) that substitutes for a real HTTP
        response."""
        info = HaddixEvidenceQualityValidator._safe_dict_static(finding.additional_info)
        browser_exec = HaddixEvidenceQualityValidator._safe_dict_static(info.get("browser_execution"))
        if browser_exec and (
            bool(browser_exec.get("dialog_observed"))
            or bool(browser_exec.get("dom_mutation_observed"))
        ):
            return True
        if HaddixEvidenceQualityValidator._safe_dict_static(info.get("csrf_state_change")):
            return True
        if HaddixEvidenceQualityValidator._safe_dict_static(info.get("authz_differential")):
            return True
        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_dict_static(value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_vuln_type(value: Any) -> str:
        token = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
        return token

    @staticmethod
    def _normalize_status(value: str) -> str:
        token = str(value or "").strip().lower()
        if token in {"confirmed", "candidate"}:
            return token
        return "candidate"

    @staticmethod
    def _flatten_signal_names(signals: Any) -> List[str]:
        out: List[str] = []
        if not isinstance(signals, list):
            return out
        for signal in signals:
            if isinstance(signal, str):
                out.append(signal.strip())
            elif isinstance(signal, dict):
                name = str(signal.get("name", "") or "").strip()
                if name:
                    out.append(name)
        return out

    @staticmethod
    def _response_body_has_sensitive_field(finding: HaddixFinding) -> bool:
        body = str(finding.poc_response or "").lower()
        if not body:
            return False
        sensitive_tokens = (
            "email",
            "balance",
            "api_key",
            "apikey",
            "token",
            "secret",
            "password",
            "ssn",
            "credit_card",
        )
        return any(token in body for token in sensitive_tokens)


# ---------------------------------------------------------------------------
# Redaction helpers
# ---------------------------------------------------------------------------

_REDACTED_PLACEHOLDER = "[REDACTED]"

# Sensitive key names for deep redaction (case-insensitive matching).
_SENSITIVE_KEY_NAMES: frozenset = frozenset({
    "cookie",
    "authorization",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
    "phpsessid",
    "sessionid",
    "session",
    "csrf_token",
    "csrftoken",
    "access_token",
    "api_key",
    "apikey",
    "secret",
    "token",
    "password",
    "passwd",
})


def _is_sensitive_key(key: str) -> bool:
    """Return True if *key* (case-insensitive) is a known sensitive key name."""
    if not key:
        return False
    return key.strip().lower() in _SENSITIVE_KEY_NAMES


def _redact_string(raw: str) -> str:
    """Apply regex-based redaction to a plain string value."""
    if not raw:
        return raw

    def _replace_header(match: re.Match) -> str:
        name = match.group("name")
        return f"{name}: {_REDACTED_PLACEHOLDER}"

    redacted = HaddixEvidenceQualityValidator._SENSITIVE_HEADER_RE.sub(
        _replace_header, raw,
    )

    def _replace_token(match: re.Match) -> str:
        key = match.group("key")
        return f"{key}={_REDACTED_PLACEHOLDER}"

    redacted = HaddixEvidenceQualityValidator._SECRET_TOKEN_RE.sub(_replace_token, redacted)
    return redacted


def _redact_value(value: Any) -> Any:
    """Recursively redact sensitive data from any value (str / dict / list).

    - Plain strings go through ``_redact_string`` (regex-based).
    - Dicts are scanned for sensitive key names (values redacted) and
      also for the ``{"name": "<header>", "value": "..."}`` header-container
      pattern (the ``value`` sibling is redacted when ``name`` is sensitive).
    - Lists are traversed recursively.
    """
    if isinstance(value, str):
        return _redact_string(value)
    if isinstance(value, dict):
        # Header-container pattern: {"name": "<SensitiveHeader>", "value": "..."}
        name_val = str(value.get("name", "") or "").strip().lower()
        if name_val and _is_sensitive_key(name_val) and "value" in value:
            result: Dict[str, Any] = {}
            for k, v in value.items():
                if k == "value":
                    result[k] = _REDACTED_PLACEHOLDER
                else:
                    result[k] = _redact_value(v)
            return result
        # Standard dict: redact values at sensitive keys, recurse otherwise
        result = {}
        for k, v in value.items():
            if _is_sensitive_key(k):
                result[k] = _REDACTED_PLACEHOLDER
            else:
                result[k] = _redact_value(v)
        return result
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


def redact_raw_request(raw: Any) -> Any:
    """Redact Cookie/Authorization/Set-Cookie and known secret tokens from a
    raw HTTP request string, nested dict, or list.

    Header names are preserved; values are replaced.  Nested structures
    are traversed recursively so that secrets at any depth are caught.
    """
    if not raw:
        return raw
    if isinstance(raw, str):
        return _redact_string(raw)
    return _redact_value(raw)


def redact_raw_response(raw: Any) -> Any:
    """Redact sensitive headers and secret tokens from a raw HTTP response
    string, nested dict, or list.

    Response-side redaction mirrors request-side: Set-Cookie values,
    Authorization challenges, and known secret tokens are stripped.
    Nested structures are traversed recursively.
    """
    if not raw:
        return raw
    return redact_raw_request(raw)


# ---------------------------------------------------------------------------
# Dedup key computation (P4-7)
# ---------------------------------------------------------------------------

def _normalize_http_method(method: str) -> str:
    """Normalize the HTTP method string to uppercase."""
    return str(method or "").strip().upper()


def _normalize_endpoint_for_dedup(endpoint: str) -> str:
    """Normalize an endpoint path by removing numeric IDs.

    Replaces path segments that are purely numeric with ``:id`` so that
    ``/api/users/1`` and ``/api/users/2`` produce the same key.
    """
    if not endpoint:
        return ""
    # Parse out path from URL
    path = endpoint
    if "://" in path:
        path = path.split("://", 1)[1]
        if "/" in path:
            path = "/" + path.split("/", 1)[1]
    # Strip query string and fragment
    path = path.split("?")[0].split("#")[0]
    # Normalize numeric segments
    segments = path.split("/")
    normalized: List[str] = []
    for seg in segments:
        if seg and re.fullmatch(r"\d+", seg):
            normalized.append(":id")
        else:
            normalized.append(seg)
    return "/".join(normalized).rstrip("/") or "/"


def _normalize_json_values(text: str) -> str:
    """Normalize JSON response body so structurally identical responses
    with different data produce the same string.

    Replaces JSON string values with ``"..."`` and numeric values with ``0``.
    If *text* is not valid JSON, returns it unchanged (trimmed).
    """
    import json as _json
    try:
        obj = _json.loads(text)
    except (ValueError, _json.JSONDecodeError):
        return text
    normalized = _json_value_normalizer(obj)
    return _json.dumps(normalized, sort_keys=True)


def _json_value_normalizer(obj: Any) -> Any:
    """Replace all JSON string/number values with placeholders."""
    if isinstance(obj, str):
        return "..."
    if isinstance(obj, (int, float)):
        return 0
    if isinstance(obj, bool):
        return False
    if isinstance(obj, list):
        return ["..."]  # Normalize list length to 1
    if isinstance(obj, dict):
        return {k: _json_value_normalizer(v) for k, v in obj.items()}
    return "..."


def compute_dedup_key(finding: Union[dict, HaddixFinding, Any]) -> str:
    """Compute a stable deduplication key for a finding.

    The key is computed from:
    * normalized endpoint (numeric IDs replaced with ``:id``)
    * HTTP method (uppercase)
    * vulnerability class (lowercase, normalized)
    * affected parameter (or empty string)
    * authorization boundary (from authz_differential or empty)
    * root cause signature (from additional_info or empty)
    * response signature (first 200 chars of body, stripped)

    Returns a 16-character hex digest. Two findings that represent the same
    vulnerability should produce the same key.
    """
    endpoint = ""
    method = "GET"
    vuln_class = ""
    param = ""
    auth_boundary = ""
    root_cause = ""
    resp_sig = ""

    if isinstance(finding, dict):
        f = finding
        endpoint = str(f.get("target_url", "") or "")
        method = _normalize_http_method(str(f.get("http_method", "") or f.get("request_method", "") or ""))
        vuln_class = str(f.get("vuln_type", "") or f.get("vulnerability_class", "") or "").strip().lower()
        payloads = f.get("payloads_used", [])
        if payloads and isinstance(payloads, list) and payloads:
            # Extract param name from first payload pattern or target URL
            param = str(f.get("affected_parameter", "") or "")
            if not param:
                url = str(f.get("target_url", "") or "")
                if "=" in url:
                    param = url.split("=")[0].split("?")[-1]
        # Auth boundary
        info = f.get("additional_info", {}) if isinstance(f.get("additional_info"), dict) else {}
        authz = info.get("authz_differential", {}) if isinstance(info.get("authz_differential"), dict) else {}
        auth_boundary = str(authz.get("boundary", "") or info.get("authorization_boundary", "") or "")
        # Root cause signature
        root_cause = str(info.get("root_cause_signature", "") or f.get("root_cause_signature", "") or "")
        # Response signature
        resp = str(f.get("poc_response", "") or "")
        if resp:
            # Extract body (after double newline)
            body_match = resp.split("\n\n", 1)
            if len(body_match) > 1:
                resp_sig = body_match[1].strip()[:200]
            else:
                resp_sig = resp.strip()[:200]

    elif hasattr(finding, "target_url"):
        f = finding
        endpoint = str(getattr(f, "target_url", "") or "")
        method = _normalize_http_method(str(getattr(f, "request_method", "") or getattr(f, "http_method", "") or "GET"))
        vuln_class = str(getattr(f, "vuln_type", "") or "").strip().lower()
        payloads = getattr(f, "payloads_used", []) or []
        if payloads and isinstance(payloads, list) and payloads:
            param = str(getattr(f, "affected_parameter", "") or "")
            if not param:
                url = str(getattr(f, "target_url", "") or "")
                if "=" in url:
                    param = url.split("=")[0].split("?")[-1]
        info = getattr(f, "additional_info", {})
        info = info if isinstance(info, dict) else {}
        authz = info.get("authz_differential", {}) if isinstance(info.get("authz_differential"), dict) else {}
        auth_boundary = str(authz.get("boundary", "") or info.get("authorization_boundary", "") or "")
        root_cause = str(info.get("root_cause_signature", "") or "")
        resp = str(getattr(f, "poc_response", "") or "")
        if resp:
            body_match = resp.split("\n\n", 1)
            if len(body_match) > 1:
                resp_sig = body_match[1].strip()[:200]
            else:
                resp_sig = resp.strip()[:200]

        # Normalize JSON values in response body so structurally identical
        # responses with different data produce the same signature.
        if resp_sig:
            resp_sig = _normalize_json_values(resp_sig)

    norm_endpoint = _normalize_endpoint_for_dedup(endpoint)
    method = method or "GET"
    vuln_class = vuln_class or "unknown"

    combined = (
        f"{norm_endpoint}|{method}|{vuln_class}|{param}"
        f"|{auth_boundary}|{root_cause}|{resp_sig}"
    )
    return hashlib.sha256(combined.encode()).hexdigest()[:16]
