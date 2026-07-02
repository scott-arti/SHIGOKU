"""
Shared Execution Safeguard Service

Unified entry point for injection request safety decisions.
Combines HTTP method risk policy and payload risk policy into one
fail-closed facade. Bug Bounty mode is the fail-closed default.

Architecture:
    ExecutionSafeguardService (facade)
    ├── MethodRiskPolicy      -- decides allow/require_hitl based on HTTP method + mode
    ├── PayloadRiskPolicy     -- detects destructive SQL payloads
    └── RequestGuard          -- HTTP/HITL endpoint-approval adapter (normalization, cache, callback)
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Decision DTO
# ---------------------------------------------------------------------------

@dataclass
class SafeguardDecision:
    """Unified decision object returned by the shared safeguard service.

    Attributes:
        allowed: Whether the request may proceed.
        requires_hitl: Whether human-in-the-loop approval is needed.
        reason_code: Machine-readable reason (e.g. 'destructive_sql_payload_blocked').
        matched_rules: List of rule names that matched.
        message: Human-readable explanation.
    """
    allowed: bool = True
    requires_hitl: bool = False
    reason_code: str = ""
    matched_rules: List[str] = field(default_factory=list)
    message: str = ""

    @classmethod
    def allow(cls, reason_code: str = "approved", message: str = "") -> "SafeguardDecision":
        return cls(allowed=True, reason_code=reason_code, message=message)

    @classmethod
    def deny(cls, reason_code: str, matched_rules: Optional[List[str]] = None,
             message: str = "", requires_hitl: bool = False) -> "SafeguardDecision":
        return cls(
            allowed=False,
            requires_hitl=requires_hitl,
            reason_code=reason_code,
            matched_rules=matched_rules or [],
            message=message,
        )

    @classmethod
    def hitl_required(cls, reason_code: str = "hitl_required", message: str = "") -> "SafeguardDecision":
        return cls(allowed=False, requires_hitl=True, reason_code=reason_code, message=message)


# ---------------------------------------------------------------------------
# PayloadRiskPolicy
# ---------------------------------------------------------------------------

class PayloadRiskPolicy:
    """Payload-level risk assessment for SQL injection payloads.

    Detects destructive SQL operations and applies mode-based policy.
    Bug Bounty mode blocks destructive payloads; CTF mode allows them.
    Includes a time-based payload governance hook for future centralized control.
    """

    # Destructive SQL patterns -> rule name
    DESTRUCTIVE_SQL_RULES: List[tuple] = [
        (r"\bDELETE\s+FROM\b", "sql_delete_from"),
        (r"\bUPDATE\s+\w+\s+SET\b", "sql_update_set"),
        (r"\bINSERT\s+INTO\b", "sql_insert_into"),
        (r"\bDROP\s+TABLE\b", "sql_drop_table"),
        (r"\bDROP\s+DATABASE\b", "sql_drop_database"),
        (r"\bTRUNCATE\b", "sql_truncate"),
        (r"\bALTER\s+(TABLE|DATABASE|SCHEMA)\b", "sql_alter"),
    ]

    # Time-based payload markers (for future centralised governance)
    TIME_BASED_MARKERS: List[str] = [
        "sleep(", "pg_sleep", "waitfor delay", "benchmark(", "dbms_lock.sleep",
    ]

    def __init__(self, mode: str = "bugbounty"):
        self.mode = mode.lower() if mode else "bugbounty"
        # Future: configurable time-based policy
        self._time_based_block_enabled: bool = False

    # -- time-based governance hook (placeholder for future policy) ----------

    def is_time_based_payload(self, payload: str) -> bool:
        """Check whether *payload* contains a time-based blind injection marker.

        This is a read-only hook. The policy does NOT block time-based payloads
        by default. Future policy centralization can gate here.
        """
        payload_lower = str(payload or "").lower()
        return any(marker in payload_lower for marker in self.TIME_BASED_MARKERS)

    def set_time_based_block(self, enabled: bool) -> None:
        """Enable/disable blocking of time-based payloads (future)."""
        self._time_based_block_enabled = enabled
        logger.info("PayloadRiskPolicy time_based_block=%s", enabled)

    # -- main evaluation ----------------------------------------------------

    def evaluate(self, payload: Optional[Any]) -> SafeguardDecision:
        """Evaluate payload risk and return a decision.

        Args:
            payload: The request payload (str, dict, or None). Dicts are
                     serialised to a string for pattern matching.

        Returns:
            SafeguardDecision with allowed/matched_rules/reason_code.
        """
        if not payload:
            return SafeguardDecision.allow(reason_code="payload_none", message="No payload to inspect")

        # Normalise to string
        payload_str = self._normalise_payload(payload)

        # CTF mode is permissive
        if self.mode == "ctf":
            return SafeguardDecision.allow(
                reason_code="ctf_mode_payload_permissive",
                message="CTF mode allows all payloads",
            )

        # Check destructive SQL patterns
        matched = []
        for pattern, rule_name in self.DESTRUCTIVE_SQL_RULES:
            if re.search(pattern, payload_str, re.IGNORECASE):
                matched.append(rule_name)

        if matched:
            msg = f"Destructive SQL payload blocked in {self.mode} mode: {', '.join(matched)}"
            logger.warning(
                "PayloadRiskPolicy: BLOCKED reason_code=destructive_sql_payload_blocked "
                "mode=%s matched_rules=%s",
                self.mode, matched,
            )
            return SafeguardDecision.deny(
                reason_code="destructive_sql_payload_blocked",
                matched_rules=matched,
                message=msg,
            )

        # Future: time-based blocking (currently always passes)
        if self._time_based_block_enabled and self.is_time_based_payload(payload_str):
            return SafeguardDecision.deny(
                reason_code="time_based_payload_blocked",
                matched_rules=["time_based_policy"],
                message="Time-based payload blocked by policy",
            )

        return SafeguardDecision.allow(reason_code="payload_clean", message="Payload passed risk check")

    @staticmethod
    def _normalise_payload(payload: Any) -> str:
        """Convert payload to a string for pattern matching."""
        if isinstance(payload, str):
            return payload
        if isinstance(payload, dict):
            return " ".join(str(v) for v in payload.values())
        return str(payload)


# ---------------------------------------------------------------------------
# MethodRiskPolicy
# ---------------------------------------------------------------------------

class MethodRiskPolicy:
    """HTTP method-level risk policy.

    Decides whether a given HTTP method requires HITL approval based on
    the current operational mode.
    """

    AGGRESSIVE_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

    def __init__(self, mode: str = "bugbounty"):
        self.mode = mode.lower() if mode else "bugbounty"

    def is_aggressive(self, method: str) -> bool:
        return method.upper() in self.AGGRESSIVE_METHODS

    def evaluate(self, method: str) -> SafeguardDecision:
        """Evaluate method risk.

        - GET / HEAD / OPTIONS: always allowed.
        - CTF mode: all methods allowed.
        - Bug Bounty / other modes: aggressive methods require HITL approval.
        """
        method_upper = method.upper()

        if not self.is_aggressive(method_upper):
            return SafeguardDecision.allow(
                reason_code="safe_method",
                message=f"Method {method_upper} is safe",
            )

        if self.mode == "ctf":
            return SafeguardDecision.allow(
                reason_code="ctf_mode_method_permissive",
                message=f"CTF mode allows {method_upper}",
            )

        # Bug Bounty or other modes: require HITL
        return SafeguardDecision.hitl_required(
            reason_code="aggressive_method_requires_hitl",
            message=f"Method {method_upper} requires HITL approval in {self.mode} mode",
        )


# ---------------------------------------------------------------------------
# ExecutionSafeguardService
# ---------------------------------------------------------------------------

class ExecutionSafeguardService:
    """Shared safeguard facade for injection request execution.

    Evaluates both method risk and payload risk before network send.
    Fail-closed in Bug Bounty mode.
    """

    def __init__(
        self,
        mode: str = "bugbounty",
        request_guard: Optional[Any] = None,  # RequestGuard instance
        method_policy: Optional[MethodRiskPolicy] = None,
        payload_policy: Optional[PayloadRiskPolicy] = None,
    ):
        self.mode = mode.lower() if mode else "bugbounty"
        self._request_guard = request_guard
        self._method_policy = method_policy or MethodRiskPolicy(mode=self.mode)
        self._payload_policy = payload_policy or PayloadRiskPolicy(mode=self.mode)

    @property
    def request_guard(self) -> Optional[Any]:
        return self._request_guard

    async def evaluate(
        self,
        method: str,
        url: str,
        payload: Optional[Any] = None,
        source_agent: str = "",
    ) -> SafeguardDecision:
        """Evaluate a request before network send.

        Args:
            method: HTTP method (GET, POST, etc.).
            url: Target URL.
            payload: Request body/payload (str, dict, or None).
            source_agent: Name of the calling agent for logging.

        Returns:
            SafeguardDecision indicating allow/deny/require_hitl.
        """
        method_upper = method.upper()

        try:
            # ---- 1. Method risk policy ------------------------------------
            method_decision = self._method_policy.evaluate(method_upper)

            if method_decision.requires_hitl and not method_decision.allowed:
                # Aggressive method in non-CTF mode: requires endpoint approval
                if self._request_guard is not None:
                    logger.debug(
                        "ExecutionSafeguard: requesting HITL for method=%s url=%s agent=%s",
                        method_upper, url, source_agent,
                    )
                    try:
                        approved = await self._request_guard.check(
                            method_upper, url, source_agent=source_agent,
                        )
                    except Exception as exc:
                        logger.error(
                            "ExecutionSafeguard: RequestGuard.check() raised %s. "
                            "Failing closed (mode=%s).",
                            exc, self.mode,
                        )
                        return SafeguardDecision.deny(
                            reason_code="safeguard_hitl_exception",
                            matched_rules=[],
                            message=f"HITL check failed: {exc}",
                            requires_hitl=True,
                        )

                    if not approved:
                        logger.warning(
                            "ExecutionSafeguard: HITL DENIED method=%s url=%s agent=%s",
                            method_upper, url, source_agent,
                        )
                        return SafeguardDecision.deny(
                            reason_code="hitl_endpoint_denied",
                            matched_rules=[],
                            message=f"Endpoint approval denied for {method_upper} {url}",
                            requires_hitl=True,
                        )
                    logger.info(
                        "ExecutionSafeguard: HITL APPROVED method=%s url=%s",
                        method_upper, url,
                    )
                else:
                    # No HITL callback available -> fail-closed in bugbounty
                    if self.mode == "bugbounty":
                        logger.error(
                            "ExecutionSafeguard: no HITL callback configured, "
                            "blocking aggressive request method=%s url=%s (mode=%s)",
                            method_upper, url, self.mode,
                        )
                        return SafeguardDecision.deny(
                            reason_code="no_hitl_callback_bugbounty",
                            matched_rules=[],
                            message=f"No HITL callback available for {method_upper} {url} in {self.mode} mode",
                            requires_hitl=True,
                        )
                    # Non-bugbounty without callback: allow (backward compat)
                    logger.debug(
                        "ExecutionSafeguard: no HITL callback but mode=%s, allowing %s %s",
                        self.mode, method_upper, url,
                    )

            # ---- 2. Payload risk policy -----------------------------------
            if payload is not None:
                payload_decision = self._payload_policy.evaluate(payload)
                if not payload_decision.allowed:
                    return payload_decision

            # All checks passed
            return SafeguardDecision.allow(
                reason_code="all_checks_passed",
                message="Request passed all safeguard checks",
            )

        except Exception as exc:
            logger.error(
                "ExecutionSafeguard: unhandled exception during evaluate(): %s. "
                "Failing closed (mode=%s).",
                exc, self.mode,
                exc_info=True,
            )
            if self.mode == "bugbounty":
                return SafeguardDecision.deny(
                    reason_code="safeguard_evaluate_exception",
                    matched_rules=[],
                    message=f"Safeguard evaluation failed: {exc}",
                )
            raise


# ---------------------------------------------------------------------------
# Singleton / factory helpers
# ---------------------------------------------------------------------------

_safeguard_instance: Optional[ExecutionSafeguardService] = None


def get_execution_safeguard(
    mode: str = "bugbounty",
    hitl_callback: Optional[Any] = None,
) -> ExecutionSafeguardService:
    """Get or create the singleton ExecutionSafeguardService.

    Reuses the existing RequestGuard singleton via get_request_guard()
    when available.  When a mode change is requested, a separate
    RequestGuard is created to avoid mutating the global singleton
    and breaking previously-created safeguard instances.
    """
    global _safeguard_instance
    normalized_mode = (mode or "bugbounty").lower()

    if _safeguard_instance is None:
        # First creation: use the singleton getter normally
        from src.core.security.request_guard import get_request_guard
        request_guard = get_request_guard(mode=normalized_mode, hitl_callback=hitl_callback)
        _safeguard_instance = ExecutionSafeguardService(
            mode=normalized_mode,
            request_guard=request_guard,
        )
    elif _safeguard_instance.mode != normalized_mode:
        # Mode change: create a fresh RequestGuard directly to avoid
        # mutating the global singleton.  Previously-created safeguard
        # instances hold a reference to the old RequestGuard and must
        # not see their mode silently flipped to ctf.
        from src.core.security.request_guard import RequestGuard
        old_mode = _safeguard_instance.mode
        request_guard = RequestGuard(mode=normalized_mode)
        if hitl_callback is not None:
            request_guard.hitl_callback = hitl_callback
        elif _safeguard_instance._request_guard is not None:
            request_guard.hitl_callback = _safeguard_instance._request_guard.hitl_callback
        _safeguard_instance = ExecutionSafeguardService(
            mode=normalized_mode,
            request_guard=request_guard,
        )
        logger.info(
            "ExecutionSafeguard mode changed %s -> %s (new independent guard created)",
            old_mode, normalized_mode,
        )
    else:
        # Same mode: reuse the singleton normally
        from src.core.security.request_guard import get_request_guard
        request_guard = get_request_guard(mode=normalized_mode, hitl_callback=hitl_callback)
        if hitl_callback is not None:
            if _safeguard_instance._request_guard is not None:
                _safeguard_instance._request_guard.hitl_callback = hitl_callback

    return _safeguard_instance


def reset_execution_safeguard() -> None:
    """Reset the singleton (for tests)."""
    global _safeguard_instance
    _safeguard_instance = None
    # Also reset the RequestGuard singleton
    from src.core.security.request_guard import reset_request_guard
    reset_request_guard()
