"""
Preflight data models for the strict entry gate.

Defines the structured types used across all preflight checkers:
- PreflightResult / PreflightFailure: gate outcome and failure details
- ToolRequirement: per-tool metadata for the tool matrix
- AuthProbeResult: authenticated reachability assessment
- ResponseClassificationInput/Result: AI classifier I/O
- PreflightContext / PreflightSnapshot: context and trace
- ReasonCodeNamespace / GatePhase / GatePolicy: enums
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PreflightStatus(Enum):
    """Overall gate outcome."""
    PASS = "pass"
    FAIL = "fail"


class ToolStatus(Enum):
    """Per-tool check outcome."""
    OK = "ok"
    MISSING = "missing"
    OUTDATED = "outdated"
    UNMANAGED = "unmanaged"
    UPDATE_FAILED = "update_failed"
    TEMPLATES_MISSING = "templates_missing"
    ERROR = "error"


class ToolCategory(Enum):
    """Grouping for tool requirements."""
    NETWORK = "network"
    RECON = "recon"
    FUZZING = "fuzzing"
    SCANNING = "scanning"
    DAST = "dast"
    ENUMERATION = "enumeration"
    PROXY = "proxy"


class AuthClassification(Enum):
    """Deterministic / AI classification of auth probe result."""
    AUTHENTICATED = "authenticated"
    LOGIN_PAGE = "login_page"
    SESSION_EXPIRED = "session_expired"
    WAF_CHALLENGE = "waf_challenge"
    RATE_LIMITED = "rate_limited"
    APP_FORBIDDEN = "app_forbidden"
    DNS_FAILURE = "dns_failure"
    CONNECTION_FAILURE = "connection_failure"
    UNKNOWN = "unknown"


class ReasonCodeNamespace(Enum):
    """Namespace prefix for structured reason codes."""
    CAIDO = "CAIDO"
    TOOL = "TOOL"
    AUTH = "AUTH"
    BLOCK = "BLOCK"
    APP = "APP"
    TARGET = "TARGET"
    SYSTEM = "SYSTEM"
    AI = "AI"


class GatePhase(Enum):
    """Rollout phase for feature-flag gating."""
    PHASE_1_DETERMINISTIC = 1   # deterministic gate only
    PHASE_2_TOOL_UPDATE = 2     # + tool update checks
    PHASE_3_AI_CLASSIFIER = 3   # + AI classifier
    PHASE_4_RESUME_HARDENING = 4  # + resume path hardening


class GatePolicy(Enum):
    """Gate strictness policy."""
    STRICT_PROD = "strict-prod"  # full fail-close, auto-update enabled
    STRICT_DEV = "strict-dev"    # fail-close, auto-update disabled, verbose trace


# ---------------------------------------------------------------------------
# Failure model
# ---------------------------------------------------------------------------

@dataclass
class PreflightFailure:
    """Single failure reason with structured diagnostics.

    Attributes:
        reason_code: Namespaced code, e.g. CAIDO_TCP_UNREACHABLE.
        severity: 'critical' means execution must stop.
        category: Short human label.
        remediation: Human-readable fix instruction.
        evidence: Supporting data (url, status, tool_path, etc.).
        checked_at: Unix timestamp of the check.
    """
    reason_code: str
    severity: str = "critical"
    category: str = ""
    remediation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    checked_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Tool requirement
# ---------------------------------------------------------------------------

@dataclass
class ToolRequirement:
    """Metadata for one tool in the required-tool matrix.

    Attributes:
        name: Tool binary name (e.g. 'nuclei', 'katana').
        category: Functional group.
        required_for_goals: List of goal names that require this tool.
        required_for_profiles: List of profile names that require this tool.
        managed: Whether BinaryManager handles install/update.
        minimum_version: Minimum acceptable semver string (None = any).
        needs_templates: Whether template directory is required (nuclei).
        timeout_seconds: Max probe time.
    """
    name: str
    category: ToolCategory = ToolCategory.SCANNING
    required_for_goals: List[str] = field(default_factory=lambda: ["*"])
    required_for_profiles: List[str] = field(default_factory=lambda: ["*"])
    managed: bool = False
    minimum_version: Optional[str] = None
    needs_templates: bool = False
    timeout_seconds: float = 3.0


# ---------------------------------------------------------------------------
# Auth probe result
# ---------------------------------------------------------------------------

@dataclass
class AuthProbeResult:
    """Result of a single authenticated reachability probe.

    Attributes:
        classification: Deterministic or AI-refined classification.
        status_code: HTTP status (0 if connection failed).
        redirect_chain: List of (status, url) tuples.
        title: Extracted <title> text.
        body_markers: Key phrases found in the body.
        is_login_page: Heuristic boolean.
        has_challenge: WAF/challenge detected.
        probed_url: The URL that was tested.
        elapsed_ms: Probe duration.
        ai_used: Whether AI classifier was invoked.
        ai_confidence: 0.0-1.0 if AI was used, else 1.0.
        ai_label: Raw AI output label when used.
    """
    classification: AuthClassification = AuthClassification.UNKNOWN
    status_code: int = 0
    redirect_chain: List[Dict[str, Any]] = field(default_factory=list)
    title: str = ""
    body_markers: List[str] = field(default_factory=list)
    is_login_page: bool = False
    has_challenge: bool = False
    probed_url: str = ""
    elapsed_ms: float = 0.0
    ai_used: bool = False
    ai_confidence: float = 0.0
    ai_label: str = ""


# ---------------------------------------------------------------------------
# AI classifier I/O
# ---------------------------------------------------------------------------

@dataclass
class ResponseClassificationInput:
    """Input fed to the lightweight AI classifier.

    Stripped-down version of AuthProbeResult for cost control.
    """
    title: str = ""
    redirect_summary: str = ""
    top_markers: List[str] = field(default_factory=list)
    status_code: int = 0
    response_fragment: str = ""


@dataclass
class ResponseClassificationResult:
    """Output from the AI classifier.

    Attributes:
        label: One of the fixed label set.
        confidence: 0.0-1.0.
        model_used: Which lightweight model was invoked.
        elapsed_ms: AI call duration.
    """
    label: str = "unknown"
    confidence: float = 0.0
    model_used: str = ""
    elapsed_ms: float = 0.0


# ---------------------------------------------------------------------------
# Preflight context and snapshot
# ---------------------------------------------------------------------------

@dataclass
class PreflightContext:
    """Context passed into the entry gate.

    Aggregates everything needed for all checkers.
    """
    mode: str = "bugbounty"
    goal: str = ""
    target: str = ""
    profile: str = ""
    scope_file: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    bearer_token: str = ""
    auth_headers: Dict[str, str] = field(default_factory=dict)
    resume_session_id: str = ""
    previous_preflight_snapshot: Optional[PreflightSnapshot] = None
    gate_policy: GatePolicy = GatePolicy.STRICT_PROD
    active_phases: List[GatePhase] = field(default_factory=lambda: [
        GatePhase.PHASE_1_DETERMINISTIC,
        GatePhase.PHASE_2_TOOL_UPDATE,
        GatePhase.PHASE_3_AI_CLASSIFIER,
        GatePhase.PHASE_4_RESUME_HARDENING,
    ])
    caido_url: str = "http://127.0.0.1:8080"
    caido_token: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PreflightSnapshot:
    """Full trace of a preflight run for observability/debugging.

    Attributes:
        status: Overall pass/fail.
        failures: List of failures (empty on pass).
        caido_tcp_ok: Caido TCP reachability.
        caido_http_ok: Caido HTTP/GraphQL response.
        tool_results: Per-tool status map.
        auth_result: AuthProbeResult if auth probe ran.
        ai_traces: Classification traces from AI classifier.
        elapsed_ms: Total gate duration.
        checked_at: Unix timestamp.
        context_summary: Subset of context (secrets masked).
    """
    status: PreflightStatus = PreflightStatus.PASS
    failures: List[PreflightFailure] = field(default_factory=list)
    caido_tcp_ok: bool = False
    caido_http_ok: bool = False
    tool_results: Dict[str, ToolStatus] = field(default_factory=dict)
    auth_result: Optional[AuthProbeResult] = None
    ai_traces: List[Dict[str, Any]] = field(default_factory=list)
    elapsed_ms: float = 0.0
    checked_at: float = field(default_factory=time.time)
    context_summary: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Top-level result
# ---------------------------------------------------------------------------

@dataclass
class PreflightResult:
    """Returned by EntryGateFacade.run_once().

    Attributes:
        status: PASS or FAIL.
        failures: Structured failure list (empty on pass).
        snapshot: Full trace for observability.
        resume_allowed: Whether resume can be attempted after failure.
    """
    status: PreflightStatus = PreflightStatus.PASS
    failures: List[PreflightFailure] = field(default_factory=list)
    snapshot: Optional[PreflightSnapshot] = None
    resume_allowed: bool = True

    @property
    def passed(self) -> bool:
        return self.status == PreflightStatus.PASS

    @property
    def failed(self) -> bool:
        return self.status == PreflightStatus.FAIL
