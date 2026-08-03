"""
VDP Canonical Data Contracts — SGK-2026-0419 (M0 Contract foundation).

Versioned, additive schema for the VDP evidence pipeline.
All records carry ``schema_version``. Old-session compatible readers
ignore unknown fields and fill missing fields with safe defaults.

Design principles (from parent plan SGK-2026-0418):
- Additive schema changes only; never rename/remove/repurpose existing fields.
- Fail-closed for unknown scope, missing HITL, budget exhaustion.
- Evidence Validator is the sole authority for confirmed verdicts.
- No active communication is introduced here — pure data contracts.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
from dataclasses import dataclass, field
import dataclasses as _dc
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Schema version constant for all VDP contracts
# ---------------------------------------------------------------------------
VDP_CONTRACT_SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
# Confirmation proof — tamper-evident validation token for confirmed verdicts
# ---------------------------------------------------------------------------
# EvidenceVerdictV1.confirmed verdicts carry a `validation_proof` field: an
# HMAC-SHA256 tag over (verdict_id, hypothesis_id, evidence_ids,
# validator_version) keyed with a STABLE key so proofs survive process
# restarts. The key comes from (in priority order):
#   1. SHIGOKU_VDP_CONFIRMATION_KEY environment variable (hex, 64 chars)
#   2. ~/.shigoku/vdp_confirmation.key file (hex, 64 chars)
# If neither is available, key resolution returns None → fail-closed:
# confirmed verdicts cannot be created or restored.
#
# The proof detects file tampering (integrity) and is bound to the key held
# by the Evidence Validator boundary. Signing/verifying functions are
# module-private; a structural test enforces that no other module imports
# them. The Evidence Validator (haddix_evidence_quality.py) is the only
# authorized consumer and its runtime integration lands in SGK-2026-0422.
_CONFIRMATION_KEY_ENV = "SHIGOKU_VDP_CONFIRMATION_KEY"
_CONFIRMATION_KEY_FILE = Path.home() / ".shigoku" / "vdp_confirmation.key"


def _resolve_confirmation_key() -> Optional[bytes]:
    """Resolve the stable HMAC key. Returns None if unavailable (fail-closed)."""
    env_val = os.environ.get(_CONFIRMATION_KEY_ENV)
    if env_val:
        try:
            raw = env_val.strip()
            if len(raw) != 64:
                return None
            return bytes.fromhex(raw)
        except ValueError:
            return None  # malformed env value → fail-closed

    try:
        if _CONFIRMATION_KEY_FILE.exists():
            raw = _CONFIRMATION_KEY_FILE.read_text(encoding="utf-8").strip()
            if len(raw) != 64:
                return None
            return bytes.fromhex(raw)
    except (OSError, ValueError):
        return None  # unreadable/corrupt key file → fail-closed

    return None  # no stable key source → fail-closed


def _current_key_id() -> str:
    """Short identifier of the current key for rotation detection."""
    key = _resolve_confirmation_key()
    if key is None:
        return "unavailable"
    return hashlib.sha256(key).hexdigest()[:8]


def _compute_validation_proof(
    verdict_id: str,
    hypothesis_id: str,
    evidence_ids: List[str],
    validator_version: str,
) -> str:
    """Compute an HMAC-SHA256 proof tag over the verdict's confirming fields.

    Raises ValueError if no stable key is available (fail-closed).
    """
    key = _resolve_confirmation_key()
    if key is None:
        raise ValueError(
            "confirmation key unavailable: set SHIGOKU_VDP_CONFIRMATION_KEY "
            "or create ~/.shigoku/vdp_confirmation.key to enable confirmed verdicts"
        )
    payload = "|".join(
        [
            verdict_id,
            hypothesis_id,
            ",".join(sorted(evidence_ids)),
            validator_version,
        ]
    )
    tag = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{_current_key_id()}:{tag}"


def _verify_validation_proof(
    verdict_id: str,
    hypothesis_id: str,
    evidence_ids: List[str],
    validator_version: str,
    proof: str,
) -> bool:
    """Return True if the proof tag matches the given fields (tamper-evident).

    Returns False when: proof missing, key unavailable, key_id mismatch
    (key rotated/changed), or tag mismatch.
    """
    if not proof:
        return False
    parts = proof.split(":")
    if len(parts) != 3 or parts[0] != "hmac-sha256":
        return False
    key = _resolve_confirmation_key()
    if key is None:
        return False  # key unavailable → fail-closed
    if parts[1] != _current_key_id():
        return False  # key changed → fail-closed (no silent old-key fallback at M0)
    expected = _compute_validation_proof(
        verdict_id, hypothesis_id, evidence_ids, validator_version
    )
    return hmac.compare_digest(expected, proof)


# ---------------------------------------------------------------------------
# Canonical JSON helpers — deterministic hashing for idempotent IDs
# ---------------------------------------------------------------------------


def canonical_json_bytes(payload: dict) -> bytes:
    """Serialize a dict to canonical JSON bytes: sorted keys, no whitespace."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def deterministic_id(prefix: str, payload: dict, length: int = 16) -> str:
    """Deterministic ID: sha256 over canonical JSON bytes, prefixed."""
    digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return f"{prefix}-{digest[:length]}"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RunTerminationState(Enum):
    """Termination state of a VDP run — exit classification."""
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    DEGRADED = "degraded"
    SAFETY_BLOCKED = "safety_blocked"
    FAILED = "failed"


class CapabilityLevel(Enum):
    """VDP capability permission level for ProgramCapabilityMatrix."""
    ALLOWED = "allowed"
    CONFIRMATION_REQUIRED = "confirmation_required"
    PROHIBITED = "prohibited"
    UNAVAILABLE = "unavailable"


class VerdictAuthority(Enum):
    """Authority that can set a verdict status.
    
    - EVIDENCE_VALIDATOR: Sole authority for ``confirmed`` status.
    - DETECTOR: Can set ``candidate`` only.
    """
    EVIDENCE_VALIDATOR = "evidence_validator"
    DETECTOR = "detector"

# ---------------------------------------------------------------------------
# Budget / admission reason codes (structured, additive)
# ---------------------------------------------------------------------------

class BudgetReasonCodeV1:
    """Structured reason codes for budget exhaustion decisions."""
    REQUESTS_EXHAUSTED = "requests_exhausted"
    FOLLOW_UPS_EXHAUSTED = "follow_ups_exhausted"
    RETRIES_EXHAUSTED = "retries_exhausted"
    CONCURRENCY_EXCEEDED = "concurrency_exceeded"
    RUNTIME_EXCEEDED = "runtime_exceeded"
    ARTIFACT_BYTES_EXCEEDED = "artifact_bytes_exceeded"
    CIRCUIT_OPEN_429 = "circuit_open_429"
    CIRCUIT_OPEN_5XX = "circuit_open_5xx"
    CIRCUIT_OPEN_TIMEOUT = "circuit_open_timeout"
    CIRCUIT_OPEN_LATENCY = "circuit_open_latency"

    # Combined exhaustion
    ASSET_BUDGET_EXHAUSTED = "asset_budget_exhausted"
    ACTOR_BUDGET_EXHAUSTED = "actor_budget_exhausted"
    HYPOTHESIS_BUDGET_EXHAUSTED = "hypothesis_budget_exhausted"


class AdmissionReasonCode:
    """Structured reason codes for admission gate decisions."""
    SCOPE_REVALIDATION_BLOCKED = "scope_revalidation_blocked"
    OUT_OF_SCOPE = "out_of_scope"
    REDIRECT_OUT_OF_SCOPE = "redirect_out_of_scope"
    HITL_REQUIRED = "hitl_required"
    CAPABILITY_PROHIBITED = "capability_prohibited"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    BUDGET_EXHAUSTED = "budget_exhausted"


# ---------------------------------------------------------------------------
# Secret key patterns — matched recursively at any depth
# ---------------------------------------------------------------------------

_SECRET_KEY_PATTERNS_LOWER: set[str] = {
    "authorization", "cookie", "set-cookie", "set_cookie", "token", "api_key", "apikey",
    "secret", "password", "passwd", "access_token", "refresh_token",
    "auth_token", "bearer", "jwt",
    "x-api-key", "x-auth-token", "x_api_key", "x_auth_token",
    "proxy-authorization", "proxy_authorization",
    "credential", "credentials",
    "private_key", "ssh_key", "aws_access_key_id", "aws_secret_access_key",
}
# NOTE: "session_id" and "session" are deliberately excluded from the redaction set.
# Sessions need session_id for resume; redacting it would break checkpoint recovery.

_SECRET_VALUE_PATTERNS: list[Tuple[re.Pattern, str]] = [
    (re.compile(r"Bearer\s+[a-zA-Z0-9._\-+/=]{10,}", re.IGNORECASE), "[REDACTED:bearer_token]"),
    (re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"), "[REDACTED:jwt]"),
    (re.compile(r"sk-(?:live|test|proj|svcacct|admin)-?[a-zA-Z0-9_-]{20,}"), "[REDACTED:api_key]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:aws_key]"),
    (re.compile(r"session(?:id)?[=:]\s*[a-zA-Z0-9_-]{8,}", re.IGNORECASE), "[REDACTED:cookie]"),
    (re.compile(r"(?:password|passwd|pass)[=:]\s*\S+", re.IGNORECASE), "[REDACTED:password]"),
    # HTTP header value patterns: X-API-Key, X-Api-Key, Api-Key in header-style strings
    (re.compile(r"(?:X-API-Key|X-Api-Key|Api-Key|X-Auth-Token):\s*\S+", re.IGNORECASE), "[REDACTED:api_key_header]"),
    # Set-Cookie header with secret value
    (re.compile(r"(?:Set-Cookie):\s*\S+", re.IGNORECASE), "[REDACTED:cookie_header]"),
    # Proxy-Authorization header
    (re.compile(r"(?:Proxy-Authorization):\s*\S+", re.IGNORECASE), "[REDACTED:proxy_auth_header]"),
]

_REDACTED_MARKER = "[REDACTED]"


def _is_secret_key(key: str) -> bool:
    """Check whether a key name indicates it carries secret material."""
    key_lower = key.lower().replace("-", "_").replace(" ", "_")
    return key_lower in _SECRET_KEY_PATTERNS_LOWER


def _redact_string_value(value: str) -> str:
    """Apply regex-based redaction patterns to a string value."""
    result = value
    for pattern, replacement in _SECRET_VALUE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_secrets_deep(obj: Any, _depth: int = 0) -> Any:
    """Recursively redact secrets from nested dicts/lists at any depth.

    Keys matching secret patterns have their values replaced with ``[REDACTED]``.
    String values in non-secret-key positions are scanned for regex patterns.

    Args:
        obj: The object to redact (dict, list, str, or other).
        _depth: Internal recursion depth counter.

    Returns:
        A deep copy with secrets redacted. Does not mutate the input.
    """
    if isinstance(obj, dict):
        result: dict[str, Any] = {}
        for k, v in obj.items():
            if _is_secret_key(k):
                result[k] = _REDACTED_MARKER
            elif isinstance(v, (dict, list)):
                result[k] = redact_secrets_deep(v, _depth + 1)
            elif isinstance(v, str):
                result[k] = _redact_string_value(v)
            else:
                result[k] = copy.deepcopy(v)
        return result
    elif isinstance(obj, list):
        return [redact_secrets_deep(item, _depth + 1) for item in obj]
    elif isinstance(obj, str):
        return _redact_string_value(obj)
    else:
        return copy.deepcopy(obj)


# ---------------------------------------------------------------------------
# HTTP header redaction
# ---------------------------------------------------------------------------

_SENSITIVE_HEADER_NAMES_LOWER: set[str] = {
    "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
    "proxy-authorization", "www-authenticate",
}


def redact_http_headers(headers: dict) -> dict:
    """Redact sensitive HTTP headers while keeping non-sensitive headers intact.

    Redacts the value to ``[REDACTED]`` for these header names (case-insensitive):
    Authorization, Cookie, Set-Cookie, X-API-Key, X-Auth-Token,
    Proxy-Authorization, WWW-Authenticate.

    All other headers are preserved as-is.

    Args:
        headers: Dict of header name → header value.

    Returns:
        New dict with sensitive header values replaced by ``[REDACTED]``.
        Does not mutate the input.
    """
    result: dict[str, Any] = {}
    for name, value in headers.items():
        if name.lower() in _SENSITIVE_HEADER_NAMES_LOWER:
            result[name] = _REDACTED_MARKER
        else:
            result[name] = value
    return result


# ---------------------------------------------------------------------------
# Evidence truncation
# ---------------------------------------------------------------------------

def truncate_evidence_body(body: str, max_bytes: int) -> Dict[str, Any]:
    """Truncate large evidence body and return metadata.

    Args:
        body: Raw evidence body string.
        max_bytes: Maximum allowed bytes for the truncated version.

    Returns:
        Dict with keys: truncated_body, original_size, truncated,
        original_hash (sha256:hex), truncation_reason (if truncated).
    """
    original_bytes = body.encode("utf-8")
    original_hash = "sha256:" + hashlib.sha256(original_bytes).hexdigest()
    original_size = len(original_bytes)

    if original_size <= max_bytes:
        return {
            "truncated_body": body,
            "original_size": original_size,
            "original_hash": original_hash,
            "truncated": False,
        }

    # Find a safe truncation point at a UTF-8 character boundary
    truncated_bytes = original_bytes[:max_bytes]
    # Decode back, ignoring any trailing incomplete multi-byte sequence
    truncated_body = truncated_bytes.decode("utf-8", errors="ignore")

    return {
        "truncated_body": truncated_body,
        "original_size": original_size,
        "original_hash": original_hash,
        "truncated": True,
        "truncation_reason": f"evidence_body_exceeded_max_bytes ({original_size} > {max_bytes})",
        "max_bytes": max_bytes,
    }


# ---------------------------------------------------------------------------
# Scope revalidation result
# ---------------------------------------------------------------------------

@dataclass
class ScopeRevalidationResult:
    """Result of pre-communication scope re-evaluation."""
    verdict: str  # allowed | out_of_scope | redirect_out_of_scope | scope_revalidation_blocked
    allowed: bool
    reason: str = ""
    original_target: str = ""
    redirected_to: str = ""

    @classmethod
    def allow(cls) -> "ScopeRevalidationResult":
        return cls(verdict="allowed", allowed=True, reason="target in scope")

    @classmethod
    def out_of_scope(cls, reason: str) -> "ScopeRevalidationResult":
        return cls(verdict="out_of_scope", allowed=False, reason=reason)

    @classmethod
    def redirect_to_out_of_scope(cls, original: str, redirected_to: str) -> "ScopeRevalidationResult":
        return cls(
            verdict="redirect_out_of_scope",
            allowed=False,
            reason=f"Redirect from {original} to {redirected_to} is out of scope",
            original_target=original,
            redirected_to=redirected_to,
        )

    @classmethod
    def indeterminate(cls, reason: str) -> "ScopeRevalidationResult":
        """Scope could not be determined — fail-closed."""
        return cls(verdict="scope_revalidation_blocked", allowed=False, reason=reason)


# ---------------------------------------------------------------------------
# Evidence queue backpressure error
# ---------------------------------------------------------------------------

class EvidenceQueueBackpressureError(Exception):
    """Raised when the evidence queue is full; evidence must not be silently discarded."""

    def __init__(self, evidence_id: str, queue_size: int, max_size: int):
        self.evidence_id = evidence_id
        self.queue_size = queue_size
        self.max_size = max_size
        super().__init__(
            f"Evidence queue full: cannot enqueue evidence_id={evidence_id} "
            f"(queue_size={queue_size}, max_size={max_size})"
        )


# ---------------------------------------------------------------------------
# Idempotency guard
# ---------------------------------------------------------------------------

@dataclass
class IdempotencyGuard:
    """Prevent duplicate registration of the same attempt/evidence ID."""
    _registered: set[str] = field(default_factory=set)

    def register(self, id_: str) -> bool:
        """Register an ID. Returns True if new, False if already registered."""
        if id_ in self._registered:
            return False
        self._registered.add(id_)
        return True

    def is_registered(self, id_: str) -> bool:
        return id_ in self._registered

    def clear(self) -> None:
        self._registered.clear()

    def to_dict(self) -> Dict[str, Any]:
        return {"registered_ids": sorted(self._registered)}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "IdempotencyGuard":
        guard = cls()
        guard._registered = set(d.get("registered_ids", []))
        return guard


# ---------------------------------------------------------------------------
# State change guard (prevent double-send of sent-but-not-saved state changes)
# ---------------------------------------------------------------------------

@dataclass
class StateChangeGuard:
    """Guard against re-sending state changes that were sent but not confirmed saved.

    When a state change (e.g., mutable request) has been transmitted but the
    session save failed before confirmation, we must NOT auto-retry on resume.
    """
    _sent_but_not_confirmed: set[str] = field(default_factory=set)
    _confirmed_saved: set[str] = field(default_factory=set)

    def mark_sent(self, id_: str) -> None:
        """Mark a state change as having been sent."""
        self._sent_but_not_confirmed.add(id_)

    def confirm_saved(self, id_: str) -> None:
        """Confirm the state change has been saved to persistent storage."""
        self._sent_but_not_confirmed.discard(id_)
        self._confirmed_saved.add(id_)

    def prevent_double_send(self, id_: str) -> None:
        """Raise ValueError if this ID was sent but not confirmed saved.

        Call this before re-sending any state-change operation on resume.
        """
        if id_ in self._sent_but_not_confirmed:
            raise ValueError(
                f"State change '{id_}' was sent but not confirmed saved. "
                f"Will not auto-retry to avoid double state change."
            )

    def is_safe_to_send(self, id_: str) -> bool:
        """Return True if this ID can be safely sent (not in sent-but-not-confirmed)."""
        return id_ not in self._sent_but_not_confirmed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sent_but_not_confirmed": sorted(self._sent_but_not_confirmed),
            "confirmed_saved": sorted(self._confirmed_saved),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "StateChangeGuard":
        guard = cls()
        guard._sent_but_not_confirmed = set(d.get("sent_but_not_confirmed", []))
        guard._confirmed_saved = set(d.get("confirmed_saved", []))
        return guard


# ---------------------------------------------------------------------------
# Admission check
# ---------------------------------------------------------------------------

@dataclass
class AdmissionResult:
    """Result of the admission gate check."""
    admitted: bool
    reason_code: str = ""
    detail: str = ""


def check_admission(
    capability: str,
    capability_matrix: "ProgramCapabilityMatrix",
    scope_verdict: str,
    hitl_ticket_id: Optional[str] = None,
) -> AdmissionResult:
    """Check whether a capability action can be admitted.

    Checks in order:
    1. Scope verdict must be 'allowed'
    2. Capability level must allow execution
    3. HITL ticket required if capability is confirmation_required

    Args:
        capability: The capability name (e.g. "idor_detector").
        capability_matrix: The ProgramCapabilityMatrix instance.
        scope_verdict: Pre-communication scope revalidation result.
        hitl_ticket_id: Optional HITL approval ticket ID.

    Returns:
        AdmissionResult with admitted=True/False and reason code.
    """
    if scope_verdict != "allowed":
        return AdmissionResult(
            admitted=False,
            reason_code=AdmissionReasonCode.OUT_OF_SCOPE,
            detail=f"Scope verdict is '{scope_verdict}', not 'allowed'",
        )

    level = capability_matrix.get_level(capability)

    if level == CapabilityLevel.PROHIBITED:
        return AdmissionResult(
            admitted=False,
            reason_code=AdmissionReasonCode.CAPABILITY_PROHIBITED,
            detail=f"Capability '{capability}' is prohibited by VDP policy",
        )

    if level == CapabilityLevel.UNAVAILABLE:
        return AdmissionResult(
            admitted=False,
            reason_code=AdmissionReasonCode.CAPABILITY_UNAVAILABLE,
            detail=f"Capability '{capability}' is unavailable (not implemented or disabled)",
        )

    if level == CapabilityLevel.CONFIRMATION_REQUIRED:
        if not hitl_ticket_id:
            return AdmissionResult(
                admitted=False,
                reason_code=AdmissionReasonCode.HITL_REQUIRED,
                detail=f"Capability '{capability}' requires HITL approval ticket",
            )
        # HITL ticket present — allowed
        return AdmissionResult(admitted=True)

    # CapabilityLevel.ALLOWED
    return AdmissionResult(admitted=True)


# ---------------------------------------------------------------------------
# Boundary validation functions (Item 4)
# ---------------------------------------------------------------------------

_VALID_HYPOTHESIS_STATES = {"hypothesized", "admitted", "attempted", "candidate", "confirmed", "refuted", "untested"}
_VALID_ATTEMPT_STATES = {"attempted", "failed", "retried"}
_VALID_EVIDENCE_TYPES = {"real_http_response", "timing_measurement", "browser_execution", "dns_lookup", "tls_observation", "api_observation"}
_VALID_VERDICT_STATUSES = {"candidate", "confirmed", "refuted", "untested"}
_VALID_ACTION_CLASSES = {"follow_up_probe", "re_evaluate", "manual_review", "terminal"}
_VALID_RISK_CLASSES = {"read_only", "state_changing", "out_of_band"}


def validate_hypothesis_record(rec: "HypothesisRecord") -> List[str]:
    """Validate a HypothesisRecord — returns list of validation errors.
    
    Checks:
    - Mandatory fields: hypothesis_id, observation_id, asset, capability, hypothesis_text
    - Valid state
    - schema_version present and positive
    """
    errors: List[str] = []
    if not rec.hypothesis_id or not rec.hypothesis_id.strip():
        errors.append("Missing mandatory field: hypothesis_id")
    if not rec.observation_id or not rec.observation_id.strip():
        errors.append("Missing mandatory field: observation_id")
    if not rec.asset or not rec.asset.strip():
        errors.append("Missing mandatory field: asset")
    if not rec.capability or not rec.capability.strip():
        errors.append("Missing mandatory field: capability")
    if not rec.hypothesis_text or not rec.hypothesis_text.strip():
        errors.append("Missing mandatory field: hypothesis_text")
    if not rec.trust_boundary or not rec.trust_boundary.strip():
        errors.append("Missing mandatory field: trust_boundary")
    if rec.state not in _VALID_HYPOTHESIS_STATES:
        errors.append(f"Invalid state '{rec.state}'. Valid states: {sorted(_VALID_HYPOTHESIS_STATES)}")
    if rec.schema_version == 0:
        errors.append("schema_version_missing")
    elif rec.schema_version < 1:
        errors.append(f"Invalid schema_version: {rec.schema_version}")
    return errors


_VALID_SCOPE_VERDICTS_V0420 = {"allowed", "out_of_scope", "redirect_out_of_scope", "scope_revalidation_blocked"}


def validate_hypothesis_record_v0420(rec: "HypothesisRecord") -> List[str]:
    """Validate a HypothesisRecord produced by the v0420 generator.

    Calls the existing v1 validator first, then enforces v0420 additive
    fields: resource_owner, dedup_key, generator_version, risk_class,
    scope_verdict, budget_estimate, observation_ids.

    Returns:
        List of validation error strings (empty = valid).
    """
    errors = validate_hypothesis_record(rec)

    if not rec.resource_owner or not rec.resource_owner.strip():
        errors.append("v0420: resource_owner is required for generator output")
    if not rec.dedup_key or not rec.dedup_key.strip():
        errors.append("v0420: dedup_key is required for generator output")
    if not rec.generator_version or not rec.generator_version.strip():
        errors.append("v0420: generator_version is required for generator output")
    if not rec.risk_class or not rec.risk_class.strip():
        errors.append("v0420: risk_class is required for generator output")
    elif rec.risk_class not in _VALID_RISK_CLASSES:
        errors.append(
            f"v0420: invalid risk_class '{rec.risk_class}'. "
            f"Valid: {sorted(_VALID_RISK_CLASSES)}"
        )
    if not rec.scope_verdict or not rec.scope_verdict.strip():
        errors.append("v0420: scope_verdict is required for generator output")
    elif rec.scope_verdict not in _VALID_SCOPE_VERDICTS_V0420:
        errors.append(
            f"v0420: invalid scope_verdict '{rec.scope_verdict}'. "
            f"Valid: {sorted(_VALID_SCOPE_VERDICTS_V0420)}"
        )
    # ── SGK-2026-0420 I-06: mandatory-field validation ────────────────────────
    if not rec.controls:
        errors.append("controls_missing: controls must be a non-empty list")
    else:
        controls_lower = [c.lower() for c in rec.controls]
        if not any(c.startswith("baseline:") for c in controls_lower):
            errors.append("controls_missing_baseline: controls must include a 'baseline:' entry")
        if not any(c.startswith("attack:") for c in controls_lower):
            errors.append("controls_missing_attack: controls must include an 'attack:' entry")
        if not any(c.startswith("inverse:") for c in controls_lower):
            errors.append("controls_missing_inverse: controls must include an 'inverse:' entry")

    if not rec.success_condition or not rec.success_condition.strip():
        errors.append("success_condition_missing: success_condition is required")
    if not rec.falsification_condition or not rec.falsification_condition.strip():
        errors.append("falsification_condition_missing: falsification_condition is required")
    if not rec.required_evidence:
        errors.append("required_evidence_missing: required_evidence must be a non-empty list")
    if not rec.actors:
        errors.append("actors_missing: actors must be a non-empty list")
    if not rec.priority_trace:
        errors.append("priority_trace_missing: priority_trace must be a non-empty list")

    if not rec.budget_estimate:
        errors.append("v0420: budget_estimate must be a non-empty dict")
    if not rec.observation_ids:
        errors.append("v0420: observation_ids must be a non-empty list")
    elif rec.observation_ids[0] != rec.observation_id:
        errors.append(
            f"v0420: observation_ids[0] ({rec.observation_ids[0]!r}) "
            f"must equal observation_id ({rec.observation_id!r})"
        )
    return errors


def validate_attempt_record(rec: "AttemptRecord") -> List[str]:
    """Validate an AttemptRecord — returns list of validation errors.
    
    Checks:
    - Mandatory fields: attempt_id, hypothesis_id, actor, request_fingerprint, scope_verdict
    - Valid state
    - schema_version present and positive
    """
    errors: List[str] = []
    if not rec.attempt_id or not rec.attempt_id.strip():
        errors.append("Missing mandatory field: attempt_id")
    if not rec.hypothesis_id or not rec.hypothesis_id.strip():
        errors.append("Missing mandatory field: hypothesis_id")
    if not rec.actor or not rec.actor.strip():
        errors.append("Missing mandatory field: actor")
    if not rec.request_fingerprint or not rec.request_fingerprint.strip():
        errors.append("Missing mandatory field: request_fingerprint")
    if not rec.scope_verdict or not rec.scope_verdict.strip():
        errors.append("Missing mandatory field: scope_verdict")
    if rec.state not in _VALID_ATTEMPT_STATES:
        errors.append(f"Invalid state '{rec.state}'. Valid states: {sorted(_VALID_ATTEMPT_STATES)}")
    if rec.schema_version == 0:
        errors.append("schema_version_missing")
    elif rec.schema_version < 1:
        errors.append(f"Invalid schema_version: {rec.schema_version}")
    return errors


def validate_evidence_record(rec: "EvidenceRecordV1") -> List[str]:
    """Validate an EvidenceRecordV1 — returns list of validation errors.
    
    Checks:
    - Mandatory fields: evidence_id, attempt_id, evidence_type
    - Valid evidence_type enum value
    - schema_version present and positive
    """
    errors: List[str] = []
    if not rec.evidence_id or not rec.evidence_id.strip():
        errors.append("Missing mandatory field: evidence_id")
    if not rec.attempt_id or not rec.attempt_id.strip():
        errors.append("Missing mandatory field: attempt_id")
    if not rec.evidence_type or not rec.evidence_type.strip():
        errors.append("Missing mandatory field: evidence_type")
    elif rec.evidence_type not in _VALID_EVIDENCE_TYPES:
        errors.append(f"Invalid evidence_type '{rec.evidence_type}'. Valid types: {sorted(_VALID_EVIDENCE_TYPES)}")
    if rec.schema_version == 0:
        errors.append("schema_version_missing")
    elif rec.schema_version < 1:
        errors.append(f"Invalid schema_version: {rec.schema_version}")
    return errors


def validate_verdict_record(rec: "EvidenceVerdictV1") -> List[str]:
    """Validate an EvidenceVerdictV1 — returns list of validation errors.
    
    Checks:
    - Mandatory fields: verdict_id, hypothesis_id, status
    - Valid status enum value
    - schema_version present and positive
    """
    errors: List[str] = []
    if not rec.verdict_id or not rec.verdict_id.strip():
        errors.append("Missing mandatory field: verdict_id")
    if not rec.hypothesis_id or not rec.hypothesis_id.strip():
        errors.append("Missing mandatory field: hypothesis_id")
    if not rec.status or not rec.status.strip():
        errors.append("Missing mandatory field: status")
    elif rec.status not in _VALID_VERDICT_STATUSES:
        errors.append(f"Invalid status '{rec.status}'. Valid statuses: {sorted(_VALID_VERDICT_STATUSES)}")
    if rec.schema_version == 0:
        errors.append("schema_version_missing")
    elif rec.schema_version < 1:
        errors.append(f"Invalid schema_version: {rec.schema_version}")
    return errors


def validate_next_action_record(rec: "NextActionRecord") -> List[str]:
    """Validate a NextActionRecord — returns list of validation errors.
    
    Checks:
    - Mandatory fields: next_action_id, verdict_id
    - Valid action_class and risk_class enums (if non-empty)
    - schema_version present and positive
    """
    errors: List[str] = []
    if not rec.next_action_id or not rec.next_action_id.strip():
        errors.append("Missing mandatory field: next_action_id")
    if not rec.verdict_id or not rec.verdict_id.strip():
        errors.append("Missing mandatory field: verdict_id")
    if rec.action_class and rec.action_class not in _VALID_ACTION_CLASSES:
        errors.append(f"Invalid action_class '{rec.action_class}'. Valid: {sorted(_VALID_ACTION_CLASSES)}")
    if rec.risk_class and rec.risk_class not in _VALID_RISK_CLASSES:
        errors.append(f"Invalid risk_class '{rec.risk_class}'. Valid: {sorted(_VALID_RISK_CLASSES)}")
    if rec.schema_version == 0:
        errors.append("schema_version_missing")
    elif rec.schema_version < 1:
        errors.append(f"Invalid schema_version: {rec.schema_version}")
    return errors


# ============================================================================
# Canonical data contracts (v1)
# ============================================================================


# Valid state transitions for HypothesisRecord
_VALID_HYPOTHESIS_TRANSITIONS: dict[str, set[str]] = {
    "hypothesized": {"admitted", "candidate"},
    "admitted": {"attempted", "hypothesized"},
    "attempted": {"candidate", "confirmed", "refuted", "untested"},
    "candidate": {"confirmed", "refuted", "untested"},
    "confirmed": set(),  # terminal
    "refuted": set(),    # terminal
    "untested": {"hypothesized"},  # can restart hypothesis
}


@dataclass
class HypothesisRecord:
    """v1 canonical hypothesis record.

    ID series: observation_id -> hypothesis_id (this record)
    """
    hypothesis_id: str
    observation_id: str
    asset: str
    capability: str
    hypothesis_text: str
    trust_boundary: str
    actors: List[str] = field(default_factory=list)
    preconditions: Dict[str, Any] = field(default_factory=dict)
    controls: List[str] = field(default_factory=list)
    success_condition: str = ""
    falsification_condition: str = ""
    required_evidence: List[str] = field(default_factory=list)
    priority_trace: List[str] = field(default_factory=list)
    state: str = "hypothesized"
    schema_version: int = VDP_CONTRACT_SCHEMA_VERSION
    created_at: str = ""
    updated_at: str = ""
    # SGK-2026-0420 additive fields (hypothesis generation)
    resource_owner: str = ""
    dedup_key: str = ""
    generator_version: str = ""
    risk_class: str = ""
    scope_verdict: str = ""
    budget_estimate: Dict[str, Any] = field(default_factory=dict)
    observation_ids: List[str] = field(default_factory=list)

    def transition_to(self, new_state: str) -> None:
        valid_next = _VALID_HYPOTHESIS_TRANSITIONS.get(self.state, set())
        if new_state not in valid_next:
            raise ValueError(
                f"Invalid state transition: {self.state} -> {new_state}. "
                f"Valid next states: {sorted(valid_next)}"
            )
        # Evidence Validator exclusivity (Item 5):
        # Only EvidenceVerdictV1.set_confirmed() may transition to "confirmed".
        # Direct calls to transition_to("confirmed") are always rejected.
        if new_state == "confirmed":
            raise ValueError(
                "Direct transition to 'confirmed' is forbidden. "
                "Use EvidenceVerdictV1.set_confirmed() — the Evidence Validator "
                "is the sole authority for confirmed verdicts."
            )
        self.state = new_state

    def _set_confirmed_by_verdict(self) -> None:
        """Internal: transition hypothesis to 'confirmed'.

        Only callable from within this module's _create_confirmed_verdict() factory.
        """
        valid_next = _VALID_HYPOTHESIS_TRANSITIONS.get(self.state, set())
        if "confirmed" not in valid_next:
            raise ValueError(
                f"Invalid state transition: {self.state} -> confirmed. "
                f"Valid next states: {sorted(valid_next)}"
            )
        object.__setattr__(self, 'state', 'confirmed')

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "hypothesis_id": self.hypothesis_id,
            "observation_id": self.observation_id,
            "asset": self.asset,
            "capability": self.capability,
            "hypothesis_text": self.hypothesis_text,
            "trust_boundary": self.trust_boundary,
            "actors": list(self.actors),
            "preconditions": dict(self.preconditions),
            "controls": list(self.controls),
            "success_condition": self.success_condition,
            "falsification_condition": self.falsification_condition,
            "required_evidence": list(self.required_evidence),
            "priority_trace": list(self.priority_trace),
            "state": self.state,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            # SGK-2026-0420 additive fields
            "resource_owner": self.resource_owner,
            "dedup_key": self.dedup_key,
            "generator_version": self.generator_version,
            "risk_class": self.risk_class,
            "scope_verdict": self.scope_verdict,
            "budget_estimate": dict(self.budget_estimate),
            "observation_ids": list(self.observation_ids),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "HypothesisRecord":
        return cls(
            schema_version=d.get("schema_version", 0),
            hypothesis_id=d.get("hypothesis_id", ""),
            observation_id=d.get("observation_id", ""),
            asset=d.get("asset", ""),
            capability=d.get("capability", ""),
            hypothesis_text=d.get("hypothesis_text", ""),
            trust_boundary=d.get("trust_boundary", ""),
            actors=list(d.get("actors", [])),
            preconditions=dict(d.get("preconditions", {})),
            controls=list(d.get("controls", [])),
            success_condition=d.get("success_condition", ""),
            falsification_condition=d.get("falsification_condition", ""),
            required_evidence=list(d.get("required_evidence", [])),
            priority_trace=list(d.get("priority_trace", [])),
            state=d.get("state", "hypothesized"),
            created_at=d.get("created_at", ""),
            updated_at=d.get("updated_at", ""),
            # SGK-2026-0420 additive fields (defaults for old session compat)
            resource_owner=d.get("resource_owner", ""),
            dedup_key=d.get("dedup_key", ""),
            generator_version=d.get("generator_version", ""),
            risk_class=d.get("risk_class", ""),
            scope_verdict=d.get("scope_verdict", ""),
            budget_estimate=dict(d.get("budget_estimate", {})),
            observation_ids=list(d.get("observation_ids", [])),
        )


@dataclass
class AttemptRecord:
    """v1 canonical attempt record.

    ID series: hypothesis_id -> attempt_id (this record)
    """
    attempt_id: str
    hypothesis_id: str
    actor: str
    request_fingerprint: str
    scope_verdict: str  # allowed | out_of_scope | scope_revalidation_blocked
    budget_snapshot: Dict[str, Any] = field(default_factory=dict)
    started_at: str = ""
    ended_at: str = ""
    execution_result: Dict[str, Any] = field(default_factory=dict)
    state: str = "attempted"
    schema_version: int = VDP_CONTRACT_SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "attempt_id": self.attempt_id,
            "hypothesis_id": self.hypothesis_id,
            "actor": self.actor,
            "request_fingerprint": self.request_fingerprint,
            "scope_verdict": self.scope_verdict,
            "budget_snapshot": dict(self.budget_snapshot),
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "execution_result": dict(self.execution_result),
            "state": self.state,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AttemptRecord":
        return cls(
            schema_version=d.get("schema_version", 0),
            attempt_id=d.get("attempt_id", ""),
            hypothesis_id=d.get("hypothesis_id", ""),
            actor=d.get("actor", ""),
            request_fingerprint=d.get("request_fingerprint", ""),
            scope_verdict=d.get("scope_verdict", "unknown"),
            budget_snapshot=dict(d.get("budget_snapshot", {})),
            started_at=d.get("started_at", ""),
            ended_at=d.get("ended_at", ""),
            execution_result=dict(d.get("execution_result", {})),
            state=d.get("state", "attempted"),
        )


@dataclass
class EvidenceRecordV1:
    """v1 canonical evidence record.

    ID series: attempt_id -> evidence_id (this record)
    """
    evidence_id: str
    attempt_id: str
    evidence_type: str  # real_http_response, timing_measurement, browser_execution, etc.
    raw_hash: str = ""
    redacted_excerpt: str = ""
    normalization_rule_version: str = ""
    auth_context_version: str = ""
    captured_at: str = ""
    original_size: int = 0
    truncated: bool = False
    truncation_reason: str = ""
    schema_version: int = VDP_CONTRACT_SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "evidence_id": self.evidence_id,
            "attempt_id": self.attempt_id,
            "evidence_type": self.evidence_type,
            "raw_hash": self.raw_hash,
            "redacted_excerpt": self.redacted_excerpt,
            "normalization_rule_version": self.normalization_rule_version,
            "auth_context_version": self.auth_context_version,
            "captured_at": self.captured_at,
            "original_size": self.original_size,
            "truncated": self.truncated,
            "truncation_reason": self.truncation_reason,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EvidenceRecordV1":
        return cls(
            schema_version=d.get("schema_version", 0),
            evidence_id=d.get("evidence_id", ""),
            attempt_id=d.get("attempt_id", ""),
            evidence_type=d.get("evidence_type", ""),
            raw_hash=d.get("raw_hash", ""),
            redacted_excerpt=d.get("redacted_excerpt", ""),
            normalization_rule_version=d.get("normalization_rule_version", ""),
            auth_context_version=d.get("auth_context_version", ""),
            captured_at=d.get("captured_at", ""),
            original_size=d.get("original_size", 0),
            truncated=d.get("truncated", False),
            truncation_reason=d.get("truncation_reason", ""),
        )


@dataclass(frozen=True)
class EvidenceVerdictV1:
    """v1 canonical evidence verdict — sole authority for confirmed status.

    ID series: hypothesis_id -> verdict_id (this record, via hypothesis_id)

    This dataclass is **frozen** — no attribute assignment after construction.
    The only path to ``status == "confirmed"`` is the module-level
    ``_create_confirmed_verdict()`` factory function, which uses
    ``object.__setattr__`` to bypass the frozen restriction internally.
    All external callers (detectors, reporters) must use ``untested``,
    ``candidate``, or ``refuted`` via normal construction or ``from_dict``.
    """
    verdict_id: str
    hypothesis_id: str
    _status: str = field(default="untested")
    reason_codes: List[str] = field(default_factory=list)
    evaluated_evidence_ids: List[str] = field(default_factory=list)
    validator_version: str = ""
    validation_proof: str = ""
    schema_version: int = VDP_CONTRACT_SCHEMA_VERSION
    notes: List[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        """Read-only verdict status. Cannot be set directly (frozen dataclass)."""
        return self._status

    def __post_init__(self):
        """Reject construction with _status='confirmed'."""
        if self._status == "confirmed":
            raise ValueError(
                "confirmed status cannot be set via constructor. "
                "Use _create_confirmed_verdict() factory function. "
                "Initialize with 'candidate' or 'untested' instead."
            )

    def set_refuted(self, hypothesis: "HypothesisRecord") -> "EvidenceVerdictV1":
        """Return a NEW frozen verdict with status='refuted'.

        The original instance is not mutated (frozen dataclass).
        """
        new_verdict = _dc.replace(self, _status="refuted")
        hypothesis.transition_to("refuted")
        return new_verdict

    def set_untested(self, hypothesis: "HypothesisRecord") -> "EvidenceVerdictV1":
        """Return a NEW frozen verdict with status='untested'."""
        new_verdict = _dc.replace(self, _status="untested")
        hypothesis.transition_to("untested")
        return new_verdict

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "verdict_id": self.verdict_id,
            "hypothesis_id": self.hypothesis_id,
            "status": self._status,
            "reason_codes": list(self.reason_codes),
            "evaluated_evidence_ids": list(self.evaluated_evidence_ids),
            "validator_version": self.validator_version,
            "validation_proof": self.validation_proof,
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EvidenceVerdictV1":
        """Load verdict from dict. REJECTS confirmed unconditionally.

        Confirmed verdicts can only be restored via the internal
        ``_restore_confirmed_from_dict()`` which verifies the tamper-evident
        validation proof. There is no public ``trusted`` parameter.
        """
        raw_status = d.get("status", "untested")
        if raw_status == "confirmed":
            raise ValueError(
                "Cannot load confirmed verdict from serialized data. "
                "Confirmed verdicts require proof verification via the internal "
                "restore path. Use _restore_confirmed_from_dict()."
            )
        return cls(
            schema_version=d.get("schema_version", 0),
            verdict_id=d.get("verdict_id", ""),
            hypothesis_id=d.get("hypothesis_id", ""),
            _status=raw_status,
            reason_codes=list(d.get("reason_codes", [])),
            evaluated_evidence_ids=list(d.get("evaluated_evidence_ids", [])),
            validator_version=d.get("validator_version", ""),
            validation_proof=d.get("validation_proof", ""),
            notes=list(d.get("notes", [])),
        )


def _restore_confirmed_from_dict(d: Dict[str, Any]) -> EvidenceVerdictV1:
    """Internal: restore a confirmed verdict from persisted data.

    Verifies the tamper-evident ``validation_proof`` (HMAC-SHA256 over
    verdict_id, hypothesis_id, evidence_ids, validator_version keyed with the
    module-private key). Raises ValueError if the proof is missing, malformed,
    or does not match the verdict fields — i.e., if the data was not produced
    by ``_create_confirmed_verdict()`` (the Evidence Validator path).

    This is the ONLY path that may produce a verdict with
    ``status == "confirmed"`` from serialized data.
    """
    raw_status = d.get("status", "untested")
    if raw_status != "confirmed":
        return EvidenceVerdictV1.from_dict(d)

    evidence_ids = list(d.get("evaluated_evidence_ids", []))
    validator_version = d.get("validator_version", "")
    proof = d.get("validation_proof", "")

    if not evidence_ids:
        raise ValueError("confirmed verdict requires non-empty evaluated_evidence_ids")
    if not validator_version or not validator_version.strip():
        raise ValueError("confirmed verdict requires non-empty validator_version")

    key = _resolve_confirmation_key()
    if key is None:
        raise ValueError(
            f"confirmed verdict {d.get('verdict_id', 'unknown')} cannot be restored: "
            "confirmation key unavailable (set SHIGOKU_VDP_CONFIRMATION_KEY or "
            "create ~/.shigoku/vdp_confirmation.key)"
        )
    parts = proof.split(":") if proof else []
    if len(parts) != 3 or parts[0] != "hmac-sha256":
        raise ValueError(
            f"confirmed verdict {d.get('verdict_id', 'unknown')} has malformed validation_proof"
        )
    if parts[1] != _current_key_id():
        raise ValueError(
            f"confirmed verdict {d.get('verdict_id', 'unknown')} validation_proof "
            "key_id mismatch: confirmation key changed since signing"
        )
    expected = _compute_validation_proof(
        d.get("verdict_id", ""),
        d.get("hypothesis_id", ""),
        evidence_ids,
        validator_version,
    )
    if not hmac.compare_digest(expected, proof):
        raise ValueError(
            f"validation_proof verification failed for confirmed verdict "
            f"{d.get('verdict_id', 'unknown')} — data was not produced by "
            "the Evidence Validator path."
        )

    instance = EvidenceVerdictV1(
        schema_version=d.get("schema_version", 0),
        verdict_id=d.get("verdict_id", ""),
        hypothesis_id=d.get("hypothesis_id", ""),
        _status="candidate",
        reason_codes=list(d.get("reason_codes", [])),
        evaluated_evidence_ids=evidence_ids,
        validator_version=validator_version,
        validation_proof=proof,
        notes=list(d.get("notes", [])),
    )
    object.__setattr__(instance, '_status', 'confirmed')
    return instance


def _create_confirmed_verdict(
    verdict_id: str,
    hypothesis_id: str,
    evidence_ids: List[str],
    validator_version: str,
    reason_codes: List[str] | None = None,
    hypothesis: "HypothesisRecord | None" = None,
    **kwargs,
) -> EvidenceVerdictV1:
    """Factory: create a confirmed verdict. The ONLY function that can produce
    verdicts with ``status == "confirmed"``.

    Uses ``object.__setattr__`` to bypass the frozen-dataclass restriction.
    This function is intentionally NOT exported — callers outside this module
    must go through the EvidenceValidator (haddix_evidence_quality.py) which
    imports and calls this function explicitly.

    Args:
        verdict_id: Unique verdict identifier.
        hypothesis_id: Parent hypothesis ID.
        evidence_ids: Non-empty list of evidence IDs that justify confirmation.
        validator_version: Non-empty validator version string.
        reason_codes: Optional reason codes.
        hypothesis: Optional hypothesis to transition to confirmed state.
        **kwargs: Additional fields passed to the verdict constructor.

    Returns:
        A frozen EvidenceVerdictV1 with status='confirmed'.

    Raises:
        ValueError: If evidence_ids is empty or validator_version is blank.
    """
    if not evidence_ids:
        raise ValueError("evidence_ids must be non-empty for confirmed status")
    if not validator_version or not validator_version.strip():
        raise ValueError("validator_version must be non-empty for confirmed status")

    verdict = EvidenceVerdictV1(
        verdict_id=verdict_id,
        hypothesis_id=hypothesis_id,
        _status="candidate",  # start as candidate, bypass post_init
        reason_codes=list(reason_codes or []),
        **kwargs,
    )
    proof = _compute_validation_proof(
        verdict_id, hypothesis_id, list(evidence_ids), validator_version
    )
    object.__setattr__(verdict, '_status', 'confirmed')
    object.__setattr__(verdict, 'evaluated_evidence_ids', list(evidence_ids))
    object.__setattr__(verdict, 'validator_version', validator_version)
    object.__setattr__(verdict, 'validation_proof', proof)

    if hypothesis is not None:
        hypothesis._set_confirmed_by_verdict()

    return verdict


@dataclass
class NextActionRecord:
    """v1 canonical next-action record.

    ID series: verdict_id -> next_action_id (this record)
    """
    next_action_id: str
    verdict_id: str
    evidence_gap: str = ""
    required_preconditions: Dict[str, Any] = field(default_factory=dict)
    action_class: str = ""         # follow_up_probe, re_evaluate, manual_review, terminal
    risk_class: str = ""           # read_only, state_changing, out_of_band
    expected_information_gain: str = ""
    stop_condition: str = ""
    schema_version: int = VDP_CONTRACT_SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "next_action_id": self.next_action_id,
            "verdict_id": self.verdict_id,
            "evidence_gap": self.evidence_gap,
            "required_preconditions": dict(self.required_preconditions),
            "action_class": self.action_class,
            "risk_class": self.risk_class,
            "expected_information_gain": self.expected_information_gain,
            "stop_condition": self.stop_condition,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "NextActionRecord":
        return cls(
            schema_version=d.get("schema_version", 0),
            next_action_id=d.get("next_action_id", ""),
            verdict_id=d.get("verdict_id", ""),
            evidence_gap=d.get("evidence_gap", ""),
            required_preconditions=dict(d.get("required_preconditions", {})),
            action_class=d.get("action_class", ""),
            risk_class=d.get("risk_class", ""),
            expected_information_gain=d.get("expected_information_gain", ""),
            stop_condition=d.get("stop_condition", ""),
        )


@dataclass
class ProgramCapabilityMatrix:
    """v1 program capability matrix — defines what capabilities are permitted.

    Levels:
    - allowed: May execute without HITL.
    - confirmation_required: Requires HITL ticket before execution.
    - prohibited: Never execute under this VDP.
    - unavailable: Capability is not implemented or not configured.
    """
    matrix_version: int = 1
    rules: Dict[str, CapabilityLevel] = field(default_factory=dict)
    schema_version: int = VDP_CONTRACT_SCHEMA_VERSION
    program_name: str = ""

    def get_level(self, capability: str) -> CapabilityLevel:
        """Get the capability level. Unknown capabilities default to PROHIBITED (fail-closed)."""
        return self.rules.get(capability, CapabilityLevel.PROHIBITED)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "matrix_version": self.matrix_version,
            "program_name": self.program_name,
            "rules": {k: v.value for k, v in self.rules.items()},
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ProgramCapabilityMatrix":
        raw_rules = d.get("rules", {})
        rules: Dict[str, CapabilityLevel] = {}
        for k, v in raw_rules.items():
            if isinstance(v, CapabilityLevel):
                rules[k] = v
            elif isinstance(v, str):
                try:
                    rules[k] = CapabilityLevel(v)
                except ValueError:
                    # Unknown level → PROHIBITED (fail-closed)
                    rules[k] = CapabilityLevel.PROHIBITED
            else:
                rules[k] = CapabilityLevel.PROHIBITED

        return cls(
            schema_version=d.get("schema_version", VDP_CONTRACT_SCHEMA_VERSION),
            matrix_version=d.get("matrix_version", 1),
            program_name=d.get("program_name", ""),
            rules=rules,
        )


@dataclass
class ExecutionBudgetV1:
    """v1 execution budget — limits per asset/actor/hypothesis.

    Budgets are enforced at multiple granularity levels.
    The stricter of VDP policy and local config is used.
    """
    max_requests: int = 1000
    max_follow_ups: int = 50
    max_retries: int = 3
    max_concurrency: int = 10
    max_runtime_seconds: int = 3600
    max_artifact_bytes: int = 100 * 1024 * 1024  # 100MB
    per_asset_burst: int = 50
    per_asset_cooldown_seconds: float = 60.0
    per_actor_burst: int = 30
    per_actor_cooldown_seconds: float = 60.0
    per_hypothesis_burst: int = 20
    per_hypothesis_cooldown_seconds: float = 60.0
    circuit_breaker_429_threshold: int = 5
    circuit_breaker_5xx_threshold: int = 10
    circuit_breaker_timeout_threshold: int = 5
    circuit_breaker_latency_ms_threshold: int = 5000
    schema_version: int = VDP_CONTRACT_SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "max_requests": self.max_requests,
            "max_follow_ups": self.max_follow_ups,
            "max_retries": self.max_retries,
            "max_concurrency": self.max_concurrency,
            "max_runtime_seconds": self.max_runtime_seconds,
            "max_artifact_bytes": self.max_artifact_bytes,
            "per_asset_burst": self.per_asset_burst,
            "per_asset_cooldown_seconds": self.per_asset_cooldown_seconds,
            "per_actor_burst": self.per_actor_burst,
            "per_actor_cooldown_seconds": self.per_actor_cooldown_seconds,
            "per_hypothesis_burst": self.per_hypothesis_burst,
            "per_hypothesis_cooldown_seconds": self.per_hypothesis_cooldown_seconds,
            "circuit_breaker_429_threshold": self.circuit_breaker_429_threshold,
            "circuit_breaker_5xx_threshold": self.circuit_breaker_5xx_threshold,
            "circuit_breaker_timeout_threshold": self.circuit_breaker_timeout_threshold,
            "circuit_breaker_latency_ms_threshold": self.circuit_breaker_latency_ms_threshold,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ExecutionBudgetV1":
        return cls(
            schema_version=d.get("schema_version", VDP_CONTRACT_SCHEMA_VERSION),
            max_requests=d.get("max_requests", 1000),
            max_follow_ups=d.get("max_follow_ups", 50),
            max_retries=d.get("max_retries", 3),
            max_concurrency=d.get("max_concurrency", 10),
            max_runtime_seconds=d.get("max_runtime_seconds", 3600),
            max_artifact_bytes=d.get("max_artifact_bytes", 100 * 1024 * 1024),
            per_asset_burst=d.get("per_asset_burst", 50),
            per_asset_cooldown_seconds=d.get("per_asset_cooldown_seconds", 60.0),
            per_actor_burst=d.get("per_actor_burst", 30),
            per_actor_cooldown_seconds=d.get("per_actor_cooldown_seconds", 60.0),
            per_hypothesis_burst=d.get("per_hypothesis_burst", 20),
            per_hypothesis_cooldown_seconds=d.get("per_hypothesis_cooldown_seconds", 60.0),
            circuit_breaker_429_threshold=d.get("circuit_breaker_429_threshold", 5),
            circuit_breaker_5xx_threshold=d.get("circuit_breaker_5xx_threshold", 10),
            circuit_breaker_timeout_threshold=d.get("circuit_breaker_timeout_threshold", 5),
            circuit_breaker_latency_ms_threshold=d.get("circuit_breaker_latency_ms_threshold", 5000),
        )

    @classmethod
    def strictest(cls, *budgets: "ExecutionBudgetV1") -> "ExecutionBudgetV1":
        """Combine multiple budgets, taking the strictest (lowest) value for each field."""
        if not budgets:
            return cls()
        result = cls()
        for budget in budgets:
            result.max_requests = min(result.max_requests, budget.max_requests)
            result.max_follow_ups = min(result.max_follow_ups, budget.max_follow_ups)
            result.max_retries = min(result.max_retries, budget.max_retries)
            result.max_concurrency = min(result.max_concurrency, budget.max_concurrency)
            result.max_runtime_seconds = min(result.max_runtime_seconds, budget.max_runtime_seconds)
            result.max_artifact_bytes = min(result.max_artifact_bytes, budget.max_artifact_bytes)
            result.per_asset_burst = min(result.per_asset_burst, budget.per_asset_burst)
            result.per_actor_burst = min(result.per_actor_burst, budget.per_actor_burst)
            result.per_hypothesis_burst = min(result.per_hypothesis_burst, budget.per_hypothesis_burst)
            result.circuit_breaker_429_threshold = min(result.circuit_breaker_429_threshold, budget.circuit_breaker_429_threshold)
            result.circuit_breaker_5xx_threshold = min(result.circuit_breaker_5xx_threshold, budget.circuit_breaker_5xx_threshold)
            result.circuit_breaker_timeout_threshold = min(result.circuit_breaker_timeout_threshold, budget.circuit_breaker_timeout_threshold)
            result.circuit_breaker_latency_ms_threshold = min(result.circuit_breaker_latency_ms_threshold, budget.circuit_breaker_latency_ms_threshold)
        return result


@dataclass
class RunHealthRecord:
    """v1 run health record — terminal state classification for a VDP run."""
    health_id: str
    run_state: RunTerminationState
    reason: str = ""
    budget_exhaustions: List[str] = field(default_factory=list)
    scope_blocks: List[str] = field(default_factory=list)
    dependency_failures: List[str] = field(default_factory=list)
    circuit_breaker_events: List[str] = field(default_factory=list)
    schema_version: int = VDP_CONTRACT_SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "health_id": self.health_id,
            "run_state": self.run_state.value,
            "reason": self.reason,
            "budget_exhaustions": list(self.budget_exhaustions),
            "scope_blocks": list(self.scope_blocks),
            "dependency_failures": list(self.dependency_failures),
            "circuit_breaker_events": list(self.circuit_breaker_events),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RunHealthRecord":
        raw_state = d.get("run_state", "failed")
        if isinstance(raw_state, RunTerminationState):
            state = raw_state
        else:
            try:
                state = RunTerminationState(raw_state)
            except ValueError:
                state = RunTerminationState.FAILED

        return cls(
            schema_version=d.get("schema_version", VDP_CONTRACT_SCHEMA_VERSION),
            health_id=d.get("health_id", ""),
            run_state=state,
            reason=d.get("reason", ""),
            budget_exhaustions=list(d.get("budget_exhaustions", [])),
            scope_blocks=list(d.get("scope_blocks", [])),
            dependency_failures=list(d.get("dependency_failures", [])),
            circuit_breaker_events=list(d.get("circuit_breaker_events", [])),
        )


# ---------------------------------------------------------------------------
# VDP Checkpoint
# ---------------------------------------------------------------------------

@dataclass
class VdpCheckpoint:
    """Checkpoint for hypothesis/attempt-level recovery."""
    checkpoint_id: str
    hypothesis_id: str
    last_completed_attempt_id: str = ""
    budget_snapshot: Dict[str, Any] = field(default_factory=dict)
    state: str = "partial"
    vdp_contract_version: int = VDP_CONTRACT_SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "hypothesis_id": self.hypothesis_id,
            "last_completed_attempt_id": self.last_completed_attempt_id,
            "budget_snapshot": dict(self.budget_snapshot),
            "state": self.state,
            "vdp_contract_version": self.vdp_contract_version,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "VdpCheckpoint":
        return cls(
            checkpoint_id=d.get("checkpoint_id", ""),
            hypothesis_id=d.get("hypothesis_id", ""),
            last_completed_attempt_id=d.get("last_completed_attempt_id", ""),
            budget_snapshot=dict(d.get("budget_snapshot", {})),
            state=d.get("state", "partial"),
            vdp_contract_version=d.get("vdp_contract_version", VDP_CONTRACT_SCHEMA_VERSION),
        )


def atomic_write_checkpoint(data: Dict[str, Any], path: Path) -> None:
    """Atomically write a checkpoint dict to a file using temp-file + rename.

    Args:
        data: Checkpoint data to write.
        path: Target file path.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        suffix=".tmp",
        prefix=".vdp_ck_",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, str(path))
    except Exception:
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def read_checkpoint(path: Path) -> Optional[Dict[str, Any]]:
    """Read a checkpoint file. Returns None if missing or corrupt.

    Args:
        path: Checkpoint file path.

    Returns:
        Parsed checkpoint dict, or None.
    """
    path = Path(path)
    if not path.exists():
        return None
    try:
        raw = path.read_text(encoding="utf-8")
        return json.loads(raw)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None
