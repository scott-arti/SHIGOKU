"""
Reauth Event Payload Contracts

Defines strict schemas for SESSION_EXPIRED, REAUTH_SUCCESS, REAUTH_FAILED
event payloads. These dataclasses serve as the single source of truth
for mandatory and optional fields across NetworkClient, AutoReauthSpecialist,
and MasterConductor.

Spec: docs/shigoku/subtasks/2026-06-20_sgk-2026-0280_reauth_subtask_plan.md
  Section 3.1: イベント契約とコンテキスト契約
  Section 3.6: Reason Code taxonomy
"""

from __future__ import annotations

import uuid
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Reason Code Taxonomy (Section 3.6)
# ---------------------------------------------------------------------------

class ReauthReasonCode(str):
    """Base type for reauth reason codes.

    The minimum set defined in the spec:
      missing_refresh_url
      missing_login_request
      network_client_unavailable
      csrf_token_missing
      token_extraction_failed
      login_replay_non_200
      reauth_storm_suppressed
      unsupported_auth_scheme
    """


# Canonical reason codes as module-level constants
REASON_CODES: set[str] = {
    "missing_refresh_url",
    "missing_login_request",
    "network_client_unavailable",
    "csrf_token_missing",
    "token_extraction_failed",
    "login_replay_non_200",
    "reauth_storm_suppressed",
    "unsupported_auth_scheme",
}


def is_valid_reason_code(code: str) -> bool:
    """Return True if *code* is a recognised reason code."""
    return code in REASON_CODES


# ---------------------------------------------------------------------------
# Auth Context (Section 3.1)
# ---------------------------------------------------------------------------

@dataclass
class AuthContext:
    """Structured auth context stored by MasterConductor."""

    login_request: Optional[dict[str, Any]] = None
    refresh_url: Optional[str] = None
    cookie_jar_snapshot: dict[str, str] = field(default_factory=dict)
    last_auth_error: Optional[str] = None
    last_auth_status: Optional[str] = None  # e.g. "restored", "degraded"
    reauth_triggered_at: Optional[float] = None
    reauth_completed_at: Optional[float] = None

    # Auth context version — monotonically increasing counter
    auth_context_version: int = 0

    def bump_version(self) -> int:
        """Increment the auth context version and return the new value."""
        self.auth_context_version += 1
        return self.auth_context_version

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AuthContext":
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in valid_keys})


# ---------------------------------------------------------------------------
# SESSION_EXPIRED Payload (Section 3.1)
# ---------------------------------------------------------------------------

@dataclass
class SessionExpiredPayload:
    """
    Emitted by NetworkClient when a 401 response is detected.

    Mandatory fields:
      url, method, request_headers, origin_task_id, reauth_attempt_id,
      auth_context_version
    """

    url: str
    method: str
    request_headers: dict[str, Any]
    origin_task_id: str
    reauth_attempt_id: str
    auth_context_version: int
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def validate(self) -> list[str]:
        """Return a list of missing mandatory field names (empty = valid)."""
        missing: list[str] = []
        if not self.url:
            missing.append("url")
        if not self.method:
            missing.append("method")
        if not isinstance(self.request_headers, dict):
            missing.append("request_headers")
        if not self.origin_task_id:
            missing.append("origin_task_id")
        if not self.reauth_attempt_id:
            missing.append("reauth_attempt_id")
        return missing


# ---------------------------------------------------------------------------
# REAUTH_SUCCESS Payload (Section 3.1)
# ---------------------------------------------------------------------------

@dataclass
class ReauthSuccessPayload:
    """
    Emitted by AutoReauthSpecialist on successful re-authentication.

    Mandatory fields:
      target, reauth_attempt_id, method, new_tokens, updated_cookies,
      auth_context_version, success_evidence
    """

    target: str
    reauth_attempt_id: str
    method: str  # "token_refresh" | "login_replay" | "cookie_restore"
    new_tokens: dict[str, Any]
    updated_cookies: dict[str, str]
    auth_context_version: int
    success_evidence: dict[str, Any]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def validate(self) -> list[str]:
        missing: list[str] = []
        if not self.target:
            missing.append("target")
        if not self.reauth_attempt_id:
            missing.append("reauth_attempt_id")
        if not self.method:
            missing.append("method")
        if not isinstance(self.new_tokens, dict):
            missing.append("new_tokens")
        if not isinstance(self.updated_cookies, dict):
            missing.append("updated_cookies")
        if not isinstance(self.success_evidence, dict):
            missing.append("success_evidence")
        return missing


# ---------------------------------------------------------------------------
# REAUTH_FAILED Payload (Section 3.1)
# ---------------------------------------------------------------------------

@dataclass
class ReauthFailedPayload:
    """
    Emitted by AutoReauthSpecialist when re-authentication fails.

    Mandatory fields:
      target, reauth_attempt_id, reason_code, reason_detail,
      attempted_strategies, cooldown_until
    """

    target: str
    reauth_attempt_id: str
    reason_code: str
    reason_detail: str
    attempted_strategies: list[str]
    cooldown_until: float  # Unix timestamp after which retry is allowed
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def validate(self) -> list[str]:
        missing: list[str] = []
        if not self.target:
            missing.append("target")
        if not self.reauth_attempt_id:
            missing.append("reauth_attempt_id")
        if not self.reason_code:
            missing.append("reason_code")
        if not self.reason_detail:
            missing.append("reason_detail")
        if not isinstance(self.attempted_strategies, list):
            missing.append("attempted_strategies")
        if not isinstance(self.cooldown_until, (int, float)):
            missing.append("cooldown_until")
        if not is_valid_reason_code(self.reason_code):
            missing.append(f"reason_code(invalid:{self.reason_code})")
        return missing


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def generate_reauth_attempt_id() -> str:
    """Generate a unique reauth attempt identifier."""
    short_uuid = uuid.uuid4().hex[:12]
    return f"reauth_{int(time.time() * 1000)}_{short_uuid}"


def default_cooldown_until(seconds: float = 60.0) -> float:
    """Return a cooldown timestamp *seconds* from now."""
    return time.time() + seconds
