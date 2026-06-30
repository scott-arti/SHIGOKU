"""
Action Admission Policy — Phase 2 (SGK-2026-0311).

Pre-execution admission gate that checks:
  - scope verdict (unknown / out_of_scope → reject for non-read_only lanes)
  - origin_key presence (missing → reject for non-read_only lanes)
  - mutating / aggressive lane checks (disabled flag + allowlist)

Designed as a NEW independent module; ethics_guard.py is NOT modified.
"""

from dataclasses import dataclass


class ReasonCode:
    """Structured reason codes for admission decisions."""
    SCOPE_UNKNOWN: str = "scope_unknown"
    OUT_OF_SCOPE: str = "out_of_scope"
    ORIGIN_KEY_MISSING: str = "origin_key_missing"
    MUTATING_NOT_ALLOWLISTED: str = "mutating_not_allowlisted"
    AGGRESSIVE_NOT_ALLOWLISTED: str = "aggressive_not_allowlisted"
    MUTATING_DISABLED: str = "mutating_disabled"
    AGGRESSIVE_DISABLED: str = "aggressive_disabled"
    STATE_ASSERTION_MISSING: str = "state_assertion_missing"
    AGGRESSIVE_EXPLICIT_FLAG_MISSING: str = "aggressive_explicit_flag_missing"
    AGGRESSIVE_LOW_NOISE_MISSING: str = "aggressive_low_noise_missing"


@dataclass
class AdmissionDecision:
    """Result of an admission check."""
    allowed: bool
    reason_code: str = ""
    message: str = ""

    @classmethod
    def allow(cls) -> "AdmissionDecision":
        return cls(allowed=True)

    @classmethod
    def reject(cls, reason_code: str, message: str = "") -> "AdmissionDecision":
        return cls(allowed=False, reason_code=reason_code, message=message)


# Lanes that are considered "safe" and can run with scope unknown / origin_key missing.
_SAFE_LANES: set[str] = {"read_only"}


class ActionAdmissionPolicy:
    """
    Pre-execution admission policy.

    Checks a task's lane, scope, and origin before allowing execution.
    Read-only lanes are always admitted; all other lanes require scope confidence
    and a valid origin_key.

    Mutating and aggressive lanes additionally require:
      - The global enabled flag
      - The origin being in the allowlist
    """

    def __init__(
        self,
        *,
        require_state_assertion: bool = False,
        require_explicit_aggressive_flag: bool = False,
    ):
        # Defaults are fail-safe (all mutating/aggressive disabled).
        self.mutating_enabled: bool = False
        self.aggressive_exclusive_enabled: bool = False
        self.mutating_allowlist: set[str] = set()
        self.aggressive_allowlist: set[str] = set()
        self.require_state_assertion = require_state_assertion
        self.require_explicit_aggressive_flag = require_explicit_aggressive_flag

    def apply_parallelism_settings(self, parallelism_settings) -> None:
        """Wire settings.parallelism lane flags into this admission policy."""
        mutating = getattr(parallelism_settings, "mutating", None)
        aggressive = getattr(parallelism_settings, "aggressive_exclusive", None)

        self.mutating_enabled = bool(getattr(mutating, "enabled", False))
        self.aggressive_exclusive_enabled = bool(getattr(aggressive, "enabled", False))
        self.mutating_allowlist = set(getattr(mutating, "allowlist", []) or [])
        self.aggressive_allowlist = set(getattr(aggressive, "allowlist", []) or [])

    def check(
        self,
        origin_key: str | None,
        target_key: str | None,
        lane: str | None,
        scope_verdict: str,
        state_assertion: dict | None = None,
        explicit_aggressive_approval: bool = False,
        low_noise_profile: bool = False,
    ) -> AdmissionDecision:
        """Evaluate admission for a task.

        Args:
            origin_key: Normalized origin key (may be None).
            target_key: Target key (may be None).
            lane: The resolved lane for this task.
            scope_verdict: "in_scope", "out_of_scope", or "unknown".

        Returns:
            AdmissionDecision with allowed/reject and reason code.
        """
        lane = lane or "read_only"

        # — scope / origin checks (non-read_only lanes) —
        if lane not in _SAFE_LANES:
            if scope_verdict == "out_of_scope":
                return AdmissionDecision.reject(
                    ReasonCode.OUT_OF_SCOPE,
                    f"Target is out of scope for lane '{lane}'",
                )
            if scope_verdict == "unknown":
                return AdmissionDecision.reject(
                    ReasonCode.SCOPE_UNKNOWN,
                    f"Scope is unknown for lane '{lane}'",
                )
            if origin_key is None:
                return AdmissionDecision.reject(
                    ReasonCode.ORIGIN_KEY_MISSING,
                    f"origin_key is missing for lane '{lane}'",
                )

        # — mutating lane checks —
        if lane == "mutating":
            if not self.mutating_enabled:
                return AdmissionDecision.reject(
                    ReasonCode.MUTATING_DISABLED,
                    "Mutating lane is globally disabled",
                )
            if origin_key not in self.mutating_allowlist:
                return AdmissionDecision.reject(
                    ReasonCode.MUTATING_NOT_ALLOWLISTED,
                    f"Origin '{origin_key}' is not in mutating allowlist",
                )
            if self.require_state_assertion:
                assertion = state_assertion or {}
                if not assertion.get("precondition") or not assertion.get("postcondition"):
                    return AdmissionDecision.reject(
                        ReasonCode.STATE_ASSERTION_MISSING,
                        "Mutating lane requires precondition and postcondition assertions",
                    )

        # — aggressive_exclusive lane checks —
        if lane == "aggressive_exclusive":
            if not self.aggressive_exclusive_enabled:
                return AdmissionDecision.reject(
                    ReasonCode.AGGRESSIVE_DISABLED,
                    "Aggressive exclusive lane is globally disabled",
                )
            if origin_key not in self.aggressive_allowlist:
                return AdmissionDecision.reject(
                    ReasonCode.AGGRESSIVE_NOT_ALLOWLISTED,
                    f"Origin '{origin_key}' is not in aggressive allowlist",
                )
            if self.require_explicit_aggressive_flag and not explicit_aggressive_approval:
                return AdmissionDecision.reject(
                    ReasonCode.AGGRESSIVE_EXPLICIT_FLAG_MISSING,
                    "Aggressive exclusive lane requires explicit approval",
                )
            if self.require_explicit_aggressive_flag and not low_noise_profile:
                return AdmissionDecision.reject(
                    ReasonCode.AGGRESSIVE_LOW_NOISE_MISSING,
                    "Aggressive exclusive lane requires a low-noise profile",
                )

        return AdmissionDecision.allow()
