"""
SGK-2026-0419 Step 3: VDP Admission Gate tests.

Tests cover:
- Scope revalidation fail-closed (indeterminate, out_of_scope, redirect_out_of_scope)
- Capability level checks (allowed, confirmation_required, prohibited, unavailable)
- HITL ticket enforcement (confirmation_required requires HITL; prohibited blocks even with HITL)
- Budget integration (budget exhausted = not admitted)
- Integration with ProgramCapabilityMatrix
- Integration with ScopeRevalidationResult
- Integration with VdpExecutionBudget
"""
from __future__ import annotations

import pytest

from src.core.models.vdp_contract import (
    AdmissionReasonCode,
    CapabilityLevel,
    HypothesisRecord,
    ProgramCapabilityMatrix,
    ScopeRevalidationResult,
)
from src.core.engine.vdp_budget import VdpExecutionBudget


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_hypothesis(capability: str = "read_asset", **kwargs) -> HypothesisRecord:
    defaults = {
        "hypothesis_id": "hyp-001",
        "observation_id": "obs-001",
        "asset": "https://api.example.com",
        "capability": capability,
        "hypothesis_text": "Test hypothesis",
        "trust_boundary": "public",
        "actors": ["unauthenticated"],
    }
    defaults.update(kwargs)
    return HypothesisRecord(**defaults)


def _make_capability_matrix(**rules) -> ProgramCapabilityMatrix:
    return ProgramCapabilityMatrix(rules=rules, program_name="test-program")


def _approved_vdp_ticket(ticket_id: str, hypothesis: HypothesisRecord) -> dict:
    """Build an approved, bound VDP HITL ticket for a hypothesis.

    SGK-2026-0421 (design constraint G): a ticket ID alone is never
    approval — the ticket must exist, be approved, and bind the same
    action/hypothesis/actor/risk_class.
    """
    from src.core.engine.vdp_hitl_guard import build_vdp_hitl_ticket

    ticket = build_vdp_hitl_ticket(
        ticket_id,
        action="follow_up_probe",
        hypothesis_id=hypothesis.hypothesis_id,
        actor=hypothesis.actors[0] if hypothesis.actors else "",
        risk_class=hypothesis.risk_class,
        evidence_gap="payload_request_mismatch",
    )
    ticket["status"] = "approved"
    return ticket


# ============================================================================
# T-0419-A01: Scope revalidation — fail-closed
# ============================================================================

class TestScopeRevalidation:
    """Scope verdict must be 'allowed'; everything else is rejected with specific reason codes."""

    def test_indeterminate_scope_fails_closed(self):
        """scope_revalidation_blocked must reject admission."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            read_asset=CapabilityLevel.ALLOWED,
        ))
        hyp = _make_hypothesis(capability="read_asset")

        result = gate.evaluate(hyp, scope_verdict="scope_revalidation_blocked")

        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.SCOPE_REVALIDATION_BLOCKED

    def test_out_of_scope_rejected(self):
        """out_of_scope verdict must reject with OUT_OF_SCOPE reason."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            read_asset=CapabilityLevel.ALLOWED,
        ))
        hyp = _make_hypothesis(capability="read_asset")

        result = gate.evaluate(hyp, scope_verdict="out_of_scope")

        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.OUT_OF_SCOPE

    def test_redirect_out_of_scope_rejected(self):
        """redirect_out_of_scope verdict must reject with REDIRECT_OUT_OF_SCOPE reason."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            read_asset=CapabilityLevel.ALLOWED,
        ))
        hyp = _make_hypothesis(capability="read_asset")

        result = gate.evaluate(hyp, scope_verdict="redirect_out_of_scope")

        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.REDIRECT_OUT_OF_SCOPE

    def test_scope_allowed_passes(self):
        """Scope 'allowed' must pass the scope check."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            read_asset=CapabilityLevel.ALLOWED,
        ))
        hyp = _make_hypothesis(capability="read_asset")

        result = gate.evaluate(hyp, scope_verdict="allowed")

        assert result.admitted is True

    def test_unknown_scope_verdict_fails_closed(self):
        """Any unexpected scope verdict must fail-closed as scope_revalidation_blocked."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            read_asset=CapabilityLevel.ALLOWED,
        ))
        hyp = _make_hypothesis(capability="read_asset")

        result = gate.evaluate(hyp, scope_verdict="unknown_value")

        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.SCOPE_REVALIDATION_BLOCKED


# ============================================================================
# T-0419-A02: Capability level checks
# ============================================================================

class TestCapabilityLevelChecks:
    """Capability level from ProgramCapabilityMatrix determines admission."""

    def test_allowed_capability_passes_admission(self):
        """ALLOWED capability must be admitted without HITL."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            read_asset=CapabilityLevel.ALLOWED,
        ))
        hyp = _make_hypothesis(capability="read_asset")

        result = gate.evaluate(hyp, scope_verdict="allowed")

        assert result.admitted is True

    def test_confirmation_required_rejected_without_hitl(self):
        """CONFIRMATION_REQUIRED must be rejected when no HITL ticket is provided."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            idor_detector=CapabilityLevel.CONFIRMATION_REQUIRED,
        ))
        hyp = _make_hypothesis(capability="idor_detector")

        result = gate.evaluate(hyp, scope_verdict="allowed")

        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.HITL_REQUIRED

    def test_confirmation_required_passes_with_hitl(self):
        """CONFIRMATION_REQUIRED must be admitted only with a VERIFIED HITL
        ticket (exists in the store, approved, bound to the hypothesis)."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            idor_detector=CapabilityLevel.CONFIRMATION_REQUIRED,
        ))
        hyp = _make_hypothesis(capability="idor_detector")

        tickets = [_approved_vdp_ticket("HITL-123", hyp)]

        result = gate.evaluate(
            hyp, scope_verdict="allowed", hitl_ticket_id="HITL-123",
            hitl_tickets=tickets, action="follow_up_probe",
        )

        assert result.admitted is True

    def test_confirmation_required_rejects_arbitrary_ticket_id(self):
        """An arbitrary ticket ID with no verifiable store entry must NOT pass
        (SGK-2026-0421: 任意ticket IDによるHITL通過禁止)."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            idor_detector=CapabilityLevel.CONFIRMATION_REQUIRED,
        ))
        hyp = _make_hypothesis(capability="idor_detector")

        result = gate.evaluate(
            hyp, scope_verdict="allowed", hitl_ticket_id="ARBITRARY-999",
        )

        assert result.admitted is False
        assert result.reason_code == "hitl_ticket_not_found"

    def test_prohibited_capability_rejected(self):
        """PROHIBITED capability must always be rejected."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            sql_injection=CapabilityLevel.PROHIBITED,
        ))
        hyp = _make_hypothesis(capability="sql_injection")

        result = gate.evaluate(hyp, scope_verdict="allowed")

        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.CAPABILITY_PROHIBITED

    def test_prohibited_capability_rejected_even_with_hitl(self):
        """PROHIBITED must be rejected even when HITL ticket is present."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            sql_injection=CapabilityLevel.PROHIBITED,
        ))
        hyp = _make_hypothesis(capability="sql_injection")

        result = gate.evaluate(
            hyp, scope_verdict="allowed", hitl_ticket_id="HITL-456",
        )

        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.CAPABILITY_PROHIBITED

    def test_unavailable_capability_rejected(self):
        """UNAVAILABLE capability must be rejected."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            browser_render=CapabilityLevel.UNAVAILABLE,
        ))
        hyp = _make_hypothesis(capability="browser_render")

        result = gate.evaluate(hyp, scope_verdict="allowed")

        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.CAPABILITY_UNAVAILABLE

    def test_unknown_capability_defaults_to_prohibited(self):
        """Capabilities not in the matrix must default to PROHIBITED (fail-closed)."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            # "unknown_cap" is NOT in the rules
        ))
        hyp = _make_hypothesis(capability="unknown_cap")

        result = gate.evaluate(hyp, scope_verdict="allowed")

        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.CAPABILITY_PROHIBITED


# ============================================================================
# T-0419-A03: Budget integration
# ============================================================================

class TestBudgetIntegration:
    """Admission gate must check budget before evaluating capability."""

    def test_budget_exhausted_rejects_admission(self):
        """When budget is exhausted, admission must be rejected regardless of capability."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        budget = VdpExecutionBudget(
            max_requests=1,
            per_asset_burst=100,
        )
        # Exhaust the budget
        budget.consume(asset_key="https://api.example.com")

        gate = VdpAdmissionGate(
            capability_matrix=_make_capability_matrix(
                read_asset=CapabilityLevel.ALLOWED,
            ),
            budget=budget,
        )
        hyp = _make_hypothesis(capability="read_asset")

        result = gate.evaluate(hyp, scope_verdict="allowed")

        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.BUDGET_EXHAUSTED

    def test_budget_consumed_on_admission(self):
        """A successful admission must consume from the budget."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        budget = VdpExecutionBudget(
            max_requests=10,
            per_asset_burst=100,
        )
        gate = VdpAdmissionGate(
            capability_matrix=_make_capability_matrix(
                read_asset=CapabilityLevel.ALLOWED,
            ),
            budget=budget,
        )
        hyp = _make_hypothesis(capability="read_asset")

        snapshot_before = budget.snapshot()
        result = gate.evaluate(hyp, scope_verdict="allowed")
        snapshot_after = budget.snapshot()

        assert result.admitted is True
        assert snapshot_after["requests_used"] == snapshot_before["requests_used"] + 1

    def test_no_budget_provided_admission_works(self):
        """When no budget is provided, admission should still work normally."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            read_asset=CapabilityLevel.ALLOWED,
        ))
        hyp = _make_hypothesis(capability="read_asset")

        result = gate.evaluate(hyp, scope_verdict="allowed")

        assert result.admitted is True

    def test_budget_check_happens_before_capability_check(self):
        """Budget exhaustion must block before reaching capability prohibitions."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        budget = VdpExecutionBudget(
            max_requests=0,  # fully exhausted
            per_asset_burst=100,
        )
        gate = VdpAdmissionGate(
            capability_matrix=_make_capability_matrix(
                sql_injection=CapabilityLevel.PROHIBITED,
            ),
            budget=budget,
        )
        hyp = _make_hypothesis(capability="sql_injection")

        result = gate.evaluate(hyp, scope_verdict="allowed")

        # Budget exhaustion takes priority over capability check
        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.BUDGET_EXHAUSTED

    def test_per_asset_budget_exhausted_uses_hypothesis_asset(self):
        """Budget consumption must use the hypothesis asset as the asset key."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        budget = VdpExecutionBudget(
            per_asset_burst=2,
            per_asset_cooldown_seconds=60.0,
            max_requests=100,
        )
        gate = VdpAdmissionGate(
            capability_matrix=_make_capability_matrix(
                read_asset=CapabilityLevel.ALLOWED,
            ),
            budget=budget,
        )
        hyp = _make_hypothesis(
            capability="read_asset",
            asset="https://target.example.com",
        )

        # Consume first two via gate
        assert gate.evaluate(hyp, scope_verdict="allowed").admitted is True
        assert gate.evaluate(hyp, scope_verdict="allowed").admitted is True

        # Third should be rejected by per-asset burst
        result = gate.evaluate(hyp, scope_verdict="allowed")
        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.BUDGET_EXHAUSTED


# ============================================================================
# T-0419-A04: Integration with existing contracts
# ============================================================================

class TestIntegrationWithContracts:
    """VdpAdmissionGate must integrate with ScopeRevalidationResult, check_admission()."""

    def test_integrates_with_scope_revalidation_result_allow(self):
        """Gate must accept verdict from ScopeRevalidationResult.allow()."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            read_asset=CapabilityLevel.ALLOWED,
        ))
        hyp = _make_hypothesis(capability="read_asset")
        sv = ScopeRevalidationResult.allow()

        result = gate.evaluate(hyp, scope_verdict=sv.verdict)

        assert result.admitted is True

    def test_integrates_with_scope_revalidation_result_out_of_scope(self):
        """Gate must accept verdict from ScopeRevalidationResult.out_of_scope()."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            read_asset=CapabilityLevel.ALLOWED,
        ))
        hyp = _make_hypothesis(capability="read_asset")
        sv = ScopeRevalidationResult.out_of_scope("domain not in scope")

        result = gate.evaluate(hyp, scope_verdict=sv.verdict)

        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.OUT_OF_SCOPE

    def test_integrates_with_scope_revalidation_result_redirect(self):
        """Gate must accept verdict from ScopeRevalidationResult.redirect_to_out_of_scope()."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            read_asset=CapabilityLevel.ALLOWED,
        ))
        hyp = _make_hypothesis(capability="read_asset")
        sv = ScopeRevalidationResult.redirect_to_out_of_scope(
            original="https://in-scope.com", redirected_to="https://out-of-scope.com",
        )

        result = gate.evaluate(hyp, scope_verdict=sv.verdict)

        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.REDIRECT_OUT_OF_SCOPE

    def test_integrates_with_scope_revalidation_result_indeterminate(self):
        """Gate must accept verdict from ScopeRevalidationResult.indeterminate()."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            read_asset=CapabilityLevel.ALLOWED,
        ))
        hyp = _make_hypothesis(capability="read_asset")
        sv = ScopeRevalidationResult.indeterminate("DNS resolution failed")

        result = gate.evaluate(hyp, scope_verdict=sv.verdict)

        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.SCOPE_REVALIDATION_BLOCKED

    def test_integrates_with_program_capability_matrix(self):
        """ProgramCapabilityMatrix.get_level() must be used for capability checks."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        matrix = ProgramCapabilityMatrix(
            rules={
                "recon": CapabilityLevel.ALLOWED,
                "fuzzing": CapabilityLevel.CONFIRMATION_REQUIRED,
                "exploit": CapabilityLevel.PROHIBITED,
            },
            program_name="acme-vdp",
        )
        gate = VdpAdmissionGate(capability_matrix=matrix)

        # ALLOWED passes
        hyp_allowed = _make_hypothesis(capability="recon")
        assert gate.evaluate(hyp_allowed, scope_verdict="allowed").admitted is True

        # CONFIRMATION_REQUIRED fails without HITL
        hyp_hitl = _make_hypothesis(capability="fuzzing")
        assert gate.evaluate(hyp_hitl, scope_verdict="allowed").admitted is False

        # CONFIRMATION_REQUIRED passes only with a verified, bound ticket
        tickets = [_approved_vdp_ticket("T-001", hyp_hitl)]
        assert gate.evaluate(
            hyp_hitl, scope_verdict="allowed", hitl_ticket_id="T-001",
            hitl_tickets=tickets, action="follow_up_probe",
        ).admitted is True
        # Arbitrary ID (not in the store) must be rejected
        assert gate.evaluate(
            hyp_hitl, scope_verdict="allowed", hitl_ticket_id="T-999",
        ).admitted is False

        # PROHIBITED always fails
        hyp_proh = _make_hypothesis(capability="exploit")
        assert gate.evaluate(hyp_proh, scope_verdict="allowed").admitted is False

    def test_integrates_with_vdp_execution_budget(self):
        """VdpExecutionBudget must be integrated for pre-capability budget checks."""
        from src.core.engine.vdp_admission import VdpAdmissionGate
        from src.core.models.vdp_contract import ExecutionBudgetV1

        model = ExecutionBudgetV1(
            max_requests=5,
            per_asset_burst=3,
            per_actor_burst=2,
        )
        budget = VdpExecutionBudget.from_model(model)
        gate = VdpAdmissionGate(
            capability_matrix=_make_capability_matrix(
                read_asset=CapabilityLevel.ALLOWED,
            ),
            budget=budget,
        )
        hyp = _make_hypothesis(
            capability="read_asset",
            actors=["actor-1"],
            asset="https://api.example.com",
        )

        # Should be able to admit up to actor burst (2)
        assert gate.evaluate(hyp, scope_verdict="allowed").admitted is True
        assert gate.evaluate(hyp, scope_verdict="allowed").admitted is True

        # Third attempt should hit actor budget exhaustion
        result = gate.evaluate(hyp, scope_verdict="allowed")
        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.BUDGET_EXHAUSTED

    def test_scope_check_priority_over_capability(self):
        """Scope check must happen first, before capability evaluation."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            read_asset=CapabilityLevel.ALLOWED,
        ))
        hyp = _make_hypothesis(capability="read_asset")

        result = gate.evaluate(hyp, scope_verdict="out_of_scope")

        # Should fail with scope reason, not capability reason
        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.OUT_OF_SCOPE

    def test_budget_scope_capability_check_ordering(self):
        """Verify the check ordering: scope → budget → capability."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        # Out of scope + budget available + capability allowed
        budget = VdpExecutionBudget(max_requests=100, per_asset_burst=100)
        gate = VdpAdmissionGate(
            capability_matrix=_make_capability_matrix(
                read_asset=CapabilityLevel.ALLOWED,
            ),
            budget=budget,
        )
        hyp = _make_hypothesis(capability="read_asset")

        # Scope fails first
        result_scope = gate.evaluate(hyp, scope_verdict="out_of_scope")
        assert result_scope.admitted is False
        assert result_scope.reason_code == AdmissionReasonCode.OUT_OF_SCOPE

        # Scope passes, budget exhausted
        budget_exhausted = VdpExecutionBudget(max_requests=0, per_asset_burst=100)
        gate2 = VdpAdmissionGate(
            capability_matrix=_make_capability_matrix(
                read_asset=CapabilityLevel.ALLOWED,
            ),
            budget=budget_exhausted,
        )
        result_budget = gate2.evaluate(hyp, scope_verdict="allowed")
        assert result_budget.admitted is False
        assert result_budget.reason_code == AdmissionReasonCode.BUDGET_EXHAUSTED

        # Scope passes, budget passes, capability fails (PROHIBITED)
        gate3 = VdpAdmissionGate(
            capability_matrix=_make_capability_matrix(
                read_asset=CapabilityLevel.PROHIBITED,
            ),
        )
        hyp_prohibited = _make_hypothesis(capability="read_asset")
        result_cap = gate3.evaluate(hyp_prohibited, scope_verdict="allowed")
        assert result_cap.admitted is False
        assert result_cap.reason_code == AdmissionReasonCode.CAPABILITY_PROHIBITED


# ============================================================================
# T-0419-A05: Edge cases
# ============================================================================

class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_actors_list_does_not_crash(self):
        """Budget check must handle hypothesis with empty actors list."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        budget = VdpExecutionBudget(
            per_actor_burst=2,
            per_actor_cooldown_seconds=60.0,
            max_requests=100,
            per_asset_burst=100,
        )
        gate = VdpAdmissionGate(
            capability_matrix=_make_capability_matrix(
                read_asset=CapabilityLevel.ALLOWED,
            ),
            budget=budget,
        )
        hyp = _make_hypothesis(capability="read_asset", actors=[])

        # Should not crash, should still admit
        result = gate.evaluate(hyp, scope_verdict="allowed")
        assert result.admitted is True

    def test_empty_asset_does_not_crash(self):
        """Budget check must handle hypothesis with empty asset."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        budget = VdpExecutionBudget(
            per_asset_burst=2,
            per_asset_cooldown_seconds=60.0,
            max_requests=100,
        )
        gate = VdpAdmissionGate(
            capability_matrix=_make_capability_matrix(
                read_asset=CapabilityLevel.ALLOWED,
            ),
            budget=budget,
        )
        hyp = _make_hypothesis(capability="read_asset", asset="")

        # Should not crash, consume() with empty asset_key should be fine
        result = gate.evaluate(hyp, scope_verdict="allowed")
        assert result.admitted is True

    def test_empty_hypothesis_id_does_not_crash(self):
        """Budget check must handle hypothesis with empty hypothesis_id."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        budget = VdpExecutionBudget(
            per_hypothesis_burst=2,
            per_hypothesis_cooldown_seconds=60.0,
            max_requests=100,
            per_asset_burst=100,
        )
        gate = VdpAdmissionGate(
            capability_matrix=_make_capability_matrix(
                read_asset=CapabilityLevel.ALLOWED,
            ),
            budget=budget,
        )
        hyp = _make_hypothesis(capability="read_asset", hypothesis_id="")

        # Should not crash
        result = gate.evaluate(hyp, scope_verdict="allowed")
        assert result.admitted is True

    def test_scope_verdict_empty_string_fails_closed(self):
        """Empty scope_verdict must fail-closed."""
        from src.core.engine.vdp_admission import VdpAdmissionGate

        gate = VdpAdmissionGate(capability_matrix=_make_capability_matrix(
            read_asset=CapabilityLevel.ALLOWED,
        ))
        hyp = _make_hypothesis(capability="read_asset")

        result = gate.evaluate(hyp, scope_verdict="")

        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.SCOPE_REVALIDATION_BLOCKED
