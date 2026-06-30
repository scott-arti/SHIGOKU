"""
T-2.1 to T-2.8: ActionAdmissionPolicy tests.

Tests admission decisions based on lane, scope_verdict, origin_key, and allowlists.
"""
import pytest
from types import SimpleNamespace

from src.core.engine.admission_policy import (
    AdmissionDecision,
    ActionAdmissionPolicy,
    ReasonCode,
)


class TestAdmissionDecision:
    def test_allowed_decision(self):
        d = AdmissionDecision(allowed=True)
        assert d.allowed is True
        assert d.reason_code == ""
        assert d.message == ""

    def test_rejected_with_reason(self):
        d = AdmissionDecision(
            allowed=False,
            reason_code=ReasonCode.SCOPE_UNKNOWN,
            message="Scope is unknown for mutating lane",
        )
        assert d.allowed is False
        assert d.reason_code == "scope_unknown"
        assert d.message == "Scope is unknown for mutating lane"


class TestActionAdmissionPolicy:
    """T-2.1 to T-2.8: Lane-based admission policy."""

    # -- T-2.1: scope_unknown + mutating → rejected -----------------------
    def test_scope_unknown_fail_closed_mutating(self):
        """T-2.1: lane=mutating, scope=unknown → rejected."""
        policy = ActionAdmissionPolicy()
        decision = policy.check(
            origin_key="https://example.com",
            target_key="https://example.com/api",
            lane="mutating",
            scope_verdict="unknown",
        )
        assert decision.allowed is False
        assert decision.reason_code == ReasonCode.SCOPE_UNKNOWN

    # -- T-2.2: scope_unknown + aggressive → rejected ---------------------
    def test_scope_unknown_fail_closed_aggressive(self):
        """T-2.2: lane=aggressive_exclusive, scope=unknown → rejected."""
        policy = ActionAdmissionPolicy()
        decision = policy.check(
            origin_key="https://example.com",
            target_key="https://example.com/api",
            lane="aggressive_exclusive",
            scope_verdict="unknown",
        )
        assert decision.allowed is False

    # -- T-2.3: scope_unknown + read_only → allowed ----------------------
    def test_scope_unknown_allowed_read_only(self):
        """T-2.3: lane=read_only, scope=unknown → allowed."""
        policy = ActionAdmissionPolicy()
        decision = policy.check(
            origin_key="https://example.com",
            target_key="https://example.com/api",
            lane="read_only",
            scope_verdict="unknown",
        )
        assert decision.allowed is True

    # -- T-2.4: origin_key missing + mutating → rejected ------------------
    def test_origin_key_missing_fail_closed(self):
        """T-2.4: origin_key=None, lane=mutating → rejected."""
        policy = ActionAdmissionPolicy()
        decision = policy.check(
            origin_key=None,
            target_key=None,
            lane="mutating",
            scope_verdict="in_scope",
        )
        assert decision.allowed is False
        assert decision.reason_code == ReasonCode.ORIGIN_KEY_MISSING

    # -- T-2.5: origin_key missing + read_only → allowed ------------------
    def test_origin_key_missing_safe_fallback_read_only(self):
        """T-2.5: origin_key=None, lane=read_only → allowed."""
        policy = ActionAdmissionPolicy()
        decision = policy.check(
            origin_key=None,
            target_key=None,
            lane="read_only",
            scope_verdict="unknown",
        )
        assert decision.allowed is True

    # -- T-2.6: mutating without allowlist → rejected ---------------------
    def test_mutating_without_allowlist_rejected(self):
        """T-2.6: lane=mutating, origin not in allowlist → rejected."""
        policy = ActionAdmissionPolicy()
        policy.mutating_enabled = True
        decision = policy.check(
            origin_key="https://evil.com",
            target_key="https://evil.com/login",
            lane="mutating",
            scope_verdict="in_scope",
        )
        assert decision.allowed is False
        assert decision.reason_code == ReasonCode.MUTATING_NOT_ALLOWLISTED

    # -- T-2.7: mutating with allowlist → allowed -------------------------
    def test_mutating_with_allowlist_allowed(self):
        """T-2.7: lane=mutating, origin in allowlist + scope=in_scope → allowed."""
        policy = ActionAdmissionPolicy()
        policy.mutating_enabled = True
        policy.mutating_allowlist = {"https://example.com"}
        decision = policy.check(
            origin_key="https://example.com",
            target_key="https://example.com/login",
            lane="mutating",
            scope_verdict="in_scope",
        )
        assert decision.allowed is True

    # -- T-2.8: out_of_scope → rejected -----------------------------------
    def test_out_of_scope_rejection(self):
        """T-2.8: target out-of-scope, lane=mutating → rejected."""
        policy = ActionAdmissionPolicy()
        decision = policy.check(
            origin_key="https://evil.com",
            target_key="https://evil.com/api",
            lane="mutating",
            scope_verdict="out_of_scope",
        )
        assert decision.allowed is False
        assert decision.reason_code == ReasonCode.OUT_OF_SCOPE

    # -- Additional edge cases --------------------------------------------
    def test_stateful_read_scope_unknown_rejected(self):
        """stateful_read with scope unknown → rejected (non-read_only lanes)."""
        policy = ActionAdmissionPolicy()
        decision = policy.check(
            origin_key="https://example.com",
            target_key="https://example.com/api",
            lane="stateful_read",
            scope_verdict="unknown",
        )
        assert decision.allowed is False
        assert decision.reason_code == ReasonCode.SCOPE_UNKNOWN

    def test_mutating_disabled_by_default_rejects(self):
        """When mutating_enabled=False (default), mutating tasks are rejected."""
        policy = ActionAdmissionPolicy()  # mutating_enabled defaults to False
        policy.mutating_allowlist = {"https://example.com"}
        decision = policy.check(
            origin_key="https://example.com",
            target_key="https://example.com/login",
            lane="mutating",
            scope_verdict="in_scope",
        )
        assert decision.allowed is False
        assert decision.reason_code == ReasonCode.MUTATING_DISABLED

    def test_aggressive_disabled_by_default_rejects(self):
        """When aggressive_exclusive_enabled=False (default), aggressive tasks are rejected."""
        policy = ActionAdmissionPolicy()
        policy.aggressive_allowlist = {"https://example.com"}
        decision = policy.check(
            origin_key="https://example.com",
            target_key="https://example.com/api",
            lane="aggressive_exclusive",
            scope_verdict="in_scope",
        )
        assert decision.allowed is False
        assert decision.reason_code == ReasonCode.AGGRESSIVE_DISABLED

    def test_parallelism_settings_wire_mutating_and_aggressive_flags(self):
        """T-7.2: settings.parallelism mutating/aggressive flags feed admission policy."""
        policy = ActionAdmissionPolicy()
        policy.apply_parallelism_settings(SimpleNamespace(
            mutating=SimpleNamespace(enabled=True, allowlist=["https://example.com"]),
            aggressive_exclusive=SimpleNamespace(enabled=True, allowlist=["https://example.com"]),
        ))

        assert policy.mutating_enabled is True
        assert policy.aggressive_exclusive_enabled is True
        assert policy.mutating_allowlist == {"https://example.com"}
        assert policy.aggressive_allowlist == {"https://example.com"}

    def test_strict_mutating_requires_state_assertion_contract(self):
        """T-7.3: strict mutating admission requires pre/post state assertion."""
        policy = ActionAdmissionPolicy(require_state_assertion=True)
        policy.mutating_enabled = True
        policy.mutating_allowlist = {"https://example.com"}

        decision = policy.check(
            origin_key="https://example.com",
            target_key="https://example.com/login",
            lane="mutating",
            scope_verdict="in_scope",
        )
        assert decision.allowed is False
        assert decision.reason_code == ReasonCode.STATE_ASSERTION_MISSING

        allowed = policy.check(
            origin_key="https://example.com",
            target_key="https://example.com/login",
            lane="mutating",
            scope_verdict="in_scope",
            state_assertion={
                "precondition": "fresh_auth_context",
                "postcondition": "no_persistent_side_effect",
            },
        )
        assert allowed.allowed is True

    def test_strict_aggressive_requires_explicit_flag_and_low_noise_profile(self):
        """T-7.4: aggressive_exclusive requires explicit operator flag + low-noise profile."""
        policy = ActionAdmissionPolicy(require_explicit_aggressive_flag=True)
        policy.aggressive_exclusive_enabled = True
        policy.aggressive_allowlist = {"https://example.com"}

        decision = policy.check(
            origin_key="https://example.com",
            target_key="https://example.com/fuzz",
            lane="aggressive_exclusive",
            scope_verdict="in_scope",
        )
        assert decision.allowed is False
        assert decision.reason_code == ReasonCode.AGGRESSIVE_EXPLICIT_FLAG_MISSING

        decision = policy.check(
            origin_key="https://example.com",
            target_key="https://example.com/fuzz",
            lane="aggressive_exclusive",
            scope_verdict="in_scope",
            explicit_aggressive_approval=True,
        )
        assert decision.allowed is False
        assert decision.reason_code == ReasonCode.AGGRESSIVE_LOW_NOISE_MISSING

        allowed = policy.check(
            origin_key="https://example.com",
            target_key="https://example.com/fuzz",
            lane="aggressive_exclusive",
            scope_verdict="in_scope",
            explicit_aggressive_approval=True,
            low_noise_profile=True,
        )
        assert allowed.allowed is True
