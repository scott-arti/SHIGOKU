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

    def __init__(self):
        # Defaults are fail-safe (all mutating/aggressive disabled).
        self.mutating_enabled: bool = False
        self.aggressive_exclusive_enabled: bool = False
        self.mutating_allowlist: set[str] = set()
        self.aggressive_allowlist: set[str] = set()

    def check(
        self,
        origin_key: str | None,
        target_key: str | None,
        lane: str | None,
        scope_verdict: str,
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

        return AdmissionDecision.allow()
