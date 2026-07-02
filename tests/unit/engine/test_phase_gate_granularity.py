"""P2b: PhaseGate granularity tests – attack task creation gate checks.

Covers:
- Backward-compatible can_create_task (no context)
- can_create_attack_task granular gating: scope, budget, auth, stale import
- PhaseData new field initialization (P2b)
- get_summary gate_reasons inclusion
"""

import pytest
from src.core.engine.phase_gate import PhaseGate, Phase, PhaseData


class TestPhaseGateGranularity:
    """Granular attack task creation gating introduced in P2b."""

    @pytest.fixture
    def gate(self) -> PhaseGate:
        """Fresh PhaseGate with only INIT and RECON unlocked."""
        return PhaseGate()

    # ------------------------------------------------------------------
    # 1. Backward compat: no context, unlocked → (True, "OK")
    # ------------------------------------------------------------------
    def test_can_create_task_backward_compat_no_context(self, gate: PhaseGate) -> None:
        gate.unlock(Phase.ATTACK)
        allowed, reason = gate.can_create_task(Phase.ATTACK)
        assert allowed is True
        assert reason == "OK"

    # ------------------------------------------------------------------
    # 2. Backward compat: locked → (False, ...)
    # ------------------------------------------------------------------
    def test_can_create_task_backward_compat_locked(self, gate: PhaseGate) -> None:
        allowed, reason = gate.can_create_task(Phase.ATTACK)
        assert allowed is False
        assert "locked" in reason.lower()

    # ------------------------------------------------------------------
    # 3. can_create_attack_task: basic OK path (budget not explicitly constrained)
    # ------------------------------------------------------------------
    def test_can_create_attack_task_ok(self, gate: PhaseGate) -> None:
        gate.unlock(Phase.ATTACK)
        # Default budget 0.0 means "not set" → no constraint → accept
        allowed, reason = gate.can_create_attack_task("auth")
        assert allowed is True
        assert reason == "OK"

    # ------------------------------------------------------------------
    # 3b. budget explicitly passed and sufficient → accept
    # ------------------------------------------------------------------
    def test_can_create_attack_task_budget_ok_explicit(self, gate: PhaseGate) -> None:
        gate.unlock(Phase.ATTACK)
        allowed, reason = gate.can_create_attack_task(
            "auth", {"budget_remaining": 100.0}
        )
        assert allowed is True
        assert reason == "OK"

    # ------------------------------------------------------------------
    # 3c. budget not provided at all → accept (unlimited)
    # ------------------------------------------------------------------
    def test_can_create_attack_task_no_budget_constraint(self, gate: PhaseGate) -> None:
        gate.unlock(Phase.ATTACK)
        allowed, reason = gate.can_create_attack_task("id_param")
        assert allowed is True
        assert reason == "OK"

    # ------------------------------------------------------------------
    # 4. scope_status "out_of_scope" → reject
    # ------------------------------------------------------------------
    def test_can_create_attack_task_scope_rejected(self, gate: PhaseGate) -> None:
        gate.unlock(Phase.ATTACK)
        data = gate._phases[Phase.ATTACK]
        data.scope_status = "out_of_scope"
        data.budget_remaining = 100.0
        allowed, reason = gate.can_create_attack_task("any_category")
        assert allowed is False
        assert "out of scope" in reason.lower()

    # ------------------------------------------------------------------
    # 5. budget explicitly passed as 0 → reject with budget reason
    # ------------------------------------------------------------------
    def test_can_create_attack_task_budget_rejected(self, gate: PhaseGate) -> None:
        gate.unlock(Phase.ATTACK)
        allowed, reason = gate.can_create_attack_task(
            "any_category", {"budget_remaining": 0.0}
        )
        assert allowed is False
        assert "budget" in reason.lower()

    # ------------------------------------------------------------------
    # 6. auth_required endpoint, no credentials → reject
    # ------------------------------------------------------------------
    def test_can_create_attack_task_auth_required_rejected(
        self, gate: PhaseGate
    ) -> None:
        gate.unlock(Phase.ATTACK)
        data = gate._phases[Phase.ATTACK]
        data.auth_required_endpoints.append("auth")
        data.budget_remaining = 100.0
        allowed, reason = gate.can_create_attack_task(
            "auth", {"auth_required": True, "has_auth_credentials": False}
        )
        assert allowed is False
        assert "auth" in reason.lower()

    # ------------------------------------------------------------------
    # 7. auth_required endpoint with credentials → accept
    # ------------------------------------------------------------------
    def test_can_create_attack_task_auth_with_credentials_accepted(
        self, gate: PhaseGate
    ) -> None:
        gate.unlock(Phase.ATTACK)
        data = gate._phases[Phase.ATTACK]
        data.auth_required_endpoints.append("auth")
        data.budget_remaining = 100.0
        allowed, reason = gate.can_create_attack_task(
            "auth", {"auth_required": True, "has_auth_credentials": True}
        )
        assert allowed is True
        assert reason == "OK"

    # ------------------------------------------------------------------
    # 8. stale_artifact in import_provenance → reject
    # ------------------------------------------------------------------
    def test_can_create_attack_task_stale_import_rejected(
        self, gate: PhaseGate
    ) -> None:
        gate.unlock(Phase.ATTACK)
        data = gate._phases[Phase.ATTACK]
        data.budget_remaining = 100.0
        allowed, reason = gate.can_create_attack_task(
            "imported", {"import_provenance": {"stale_artifact": True}}
        )
        assert allowed is False
        assert "stale" in reason.lower()

    # ------------------------------------------------------------------
    # 9. PhaseData defaults include all P2b fields
    # ------------------------------------------------------------------
    def test_phase_data_new_fields_initialized(self) -> None:
        pd = PhaseData()
        assert pd.auth_required_endpoints == []
        assert pd.public_endpoints == []
        assert pd.scope_status == ""
        assert pd.budget_remaining == 0.0
        assert pd.critical_findings == []
        assert pd.import_provenance == {}
        assert pd.gate_reasons == []

    # ------------------------------------------------------------------
    # 10. get_summary includes gate_reason_count and gate_reasons
    # ------------------------------------------------------------------
    def test_get_summary_includes_gate_reasons(self, gate: PhaseGate) -> None:
        gate.unlock(Phase.ATTACK)
        data = gate._phases[Phase.ATTACK]
        data.gate_reasons.append("missing auth")
        data.gate_reasons.append("budget exhausted")
        summary = gate.get_summary()
        assert summary["gate_reason_count"] == 2
        assert summary["gate_reasons"] == ["missing auth", "budget exhausted"]

    # ------------------------------------------------------------------
    # Regression: multiple fresh categories accepted without explicit budget
    # (P2b: default budget 0.0 means "not set", not "exhausted")
    # ------------------------------------------------------------------
    @pytest.mark.parametrize("category", [
        "id_param", "auth", "admin", "xss_candidate", "api_endpoint",
        "redirect_param", "file_param", "basket_order", "csrf_candidate",
    ])
    def test_can_create_attack_task_fresh_categories_ok(
        self, gate: PhaseGate, category: str
    ) -> None:
        gate.unlock(Phase.ATTACK)
        allowed, reason = gate.can_create_attack_task(category)
        assert allowed is True, f"Category '{category}' rejected: {reason}"
        assert reason == "OK"
