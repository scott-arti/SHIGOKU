"""
VDP HITL ticket verification + admission ordering — SGK-2026-0421 Steps 6-7.

- HITL ticket must exist, be approved, and bind action/hypothesis/actor/risk.
- Admission rejection never consumes budget.
- Budget rejection never fixes the idempotency ID as registered.
"""
from __future__ import annotations

from src.core.engine.vdp_admission import VdpAdmissionGate
from src.core.engine.vdp_budget import VdpExecutionBudget
from src.core.engine.vdp_hitl_guard import (
    build_vdp_hitl_ticket,
    verify_hitl_ticket,
)
from src.core.models.vdp_contract import (
    AdmissionReasonCode,
    AttemptRecord,
    CapabilityLevel,
    HypothesisRecord,
    IdempotencyGuard,
    ProgramCapabilityMatrix,
)


def _hypothesis(**kwargs) -> HypothesisRecord:
    defaults = {
        "hypothesis_id": "hyp-hitl-1",
        "observation_id": "obs-hitl-1",
        "asset": "https://api.example.com",
        "capability": "read_asset",
        "hypothesis_text": "t",
        "trust_boundary": "public",
        "actors": ["authA"],
        "risk_class": "read_only",
    }
    defaults.update(kwargs)
    return HypothesisRecord(**defaults)


def _matrix(**rules) -> ProgramCapabilityMatrix:
    return ProgramCapabilityMatrix(rules=rules, program_name="t")


def _approved(ticket_id: str, hyp: HypothesisRecord, **binding) -> dict:
    ticket = build_vdp_hitl_ticket(
        ticket_id,
        action=binding.get("action", "follow_up_probe"),
        hypothesis_id=binding.get("hypothesis_id", hyp.hypothesis_id),
        actor=binding.get("actor", hyp.actors[0] if hyp.actors else ""),
        risk_class=binding.get("risk_class", hyp.risk_class),
        evidence_gap=binding.get("evidence_gap", "payload_request_mismatch"),
    )
    ticket["status"] = "approved"
    return ticket


class TestHitlTicketVerification:
    def test_no_ticket_id(self):
        r = verify_hitl_ticket("", tickets=[])
        assert r.verified is False
        assert r.reason_code == "hitl_ticket_not_found"

    def test_ticket_not_in_store(self):
        hyp = _hypothesis()
        r = verify_hitl_ticket("HITL-X", tickets=[_approved("HITL-A", hyp)])
        assert r.verified is False
        assert r.reason_code == "hitl_ticket_not_found"

    def test_pending_ticket_rejected(self):
        hyp = _hypothesis()
        ticket = build_vdp_hitl_ticket(
            "HITL-P", action="follow_up_probe",
            hypothesis_id=hyp.hypothesis_id, actor="authA", risk_class="read_only",
        )
        r = verify_hitl_ticket("HITL-P", tickets=[ticket])
        assert r.verified is False
        assert r.reason_code == "hitl_ticket_not_approved"

    def test_rejected_ticket_rejected(self):
        hyp = _hypothesis()
        ticket = _approved("HITL-R", hyp)
        ticket["status"] = "rejected"
        r = verify_hitl_ticket("HITL-R", tickets=[ticket])
        assert r.verified is False
        assert r.reason_code == "hitl_ticket_not_approved"

    def test_legacy_ticket_without_binding_rejected(self):
        hyp = _hypothesis()
        legacy = {"ticket_id": "LEGACY-1", "status": "approved", "task_id": "t1"}
        r = verify_hitl_ticket("LEGACY-1", tickets=[legacy], hypothesis_id=hyp.hypothesis_id)
        assert r.verified is False
        assert r.reason_code == "hitl_ticket_not_bound"

    def test_binding_mismatch_rejected(self):
        hyp = _hypothesis()
        wrong_actor = _approved("HITL-B", hyp, actor="authB")
        r = verify_hitl_ticket(
            "HITL-B", tickets=[wrong_actor],
            action="follow_up_probe", hypothesis_id=hyp.hypothesis_id,
            actor="authA", risk_class="read_only",
        )
        assert r.verified is False
        assert r.reason_code == "hitl_ticket_not_bound"

        wrong_hyp = _approved("HITL-C", hyp, hypothesis_id="hyp-other")
        r2 = verify_hitl_ticket(
            "HITL-C", tickets=[wrong_hyp],
            action="follow_up_probe", hypothesis_id=hyp.hypothesis_id,
            actor="authA", risk_class="read_only",
        )
        assert r2.verified is False
        assert r2.reason_code == "hitl_ticket_not_bound"

    def test_fully_bound_approved_ticket_passes(self):
        hyp = _hypothesis()
        ticket = _approved("HITL-OK", hyp)
        r = verify_hitl_ticket(
            "HITL-OK", tickets=[ticket],
            action="follow_up_probe", hypothesis_id=hyp.hypothesis_id,
            actor="authA", risk_class="read_only",
        )
        assert r.verified is True


class TestAdmissionBudgetNotConsumedOnRejection:
    def test_capability_rejection_does_not_consume_budget(self):
        budget = VdpExecutionBudget(max_requests=100, per_asset_burst=100)
        gate = VdpAdmissionGate(
            capability_matrix=_matrix(sql_injection=CapabilityLevel.PROHIBITED),
            budget=budget,
        )
        hyp = _hypothesis(capability="sql_injection")
        before = budget.snapshot()["requests_used"]
        result = gate.evaluate(hyp, scope_verdict="allowed")
        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.CAPABILITY_PROHIBITED
        assert budget.snapshot()["requests_used"] == before

    def test_hitl_rejection_does_not_consume_budget(self):
        budget = VdpExecutionBudget(max_requests=100, per_asset_burst=100)
        gate = VdpAdmissionGate(
            capability_matrix=_matrix(fuzzing=CapabilityLevel.CONFIRMATION_REQUIRED),
            budget=budget,
        )
        hyp = _hypothesis(capability="fuzzing")
        before = budget.snapshot()["requests_used"]
        result = gate.evaluate(hyp, scope_verdict="allowed", hitl_ticket_id="FAKE-1")
        assert result.admitted is False
        assert budget.snapshot()["requests_used"] == before

    def test_scope_rejection_does_not_consume_budget(self):
        budget = VdpExecutionBudget(max_requests=100, per_asset_burst=100)
        gate = VdpAdmissionGate(
            capability_matrix=_matrix(read_asset=CapabilityLevel.ALLOWED),
            budget=budget,
        )
        hyp = _hypothesis()
        before = budget.snapshot()["requests_used"]
        result = gate.evaluate(hyp, scope_verdict="out_of_scope")
        assert result.admitted is False
        assert budget.snapshot()["requests_used"] == before

    def test_successful_admission_consumes_once(self):
        budget = VdpExecutionBudget(max_requests=100, per_asset_burst=100)
        gate = VdpAdmissionGate(
            capability_matrix=_matrix(read_asset=CapabilityLevel.ALLOWED),
            budget=budget,
        )
        hyp = _hypothesis()
        before = budget.snapshot()["requests_used"]
        result = gate.evaluate(hyp, scope_verdict="allowed")
        assert result.admitted is True
        assert budget.snapshot()["requests_used"] == before + 1

    def test_budget_exhaustion_still_blocks_before_capability(self):
        # 0419 priority semantics preserved: BUDGET_EXHAUSTED takes priority.
        budget = VdpExecutionBudget(max_requests=0, per_asset_burst=100)
        gate = VdpAdmissionGate(
            capability_matrix=_matrix(sql_injection=CapabilityLevel.PROHIBITED),
            budget=budget,
        )
        hyp = _hypothesis(capability="sql_injection")
        result = gate.evaluate(hyp, scope_verdict="allowed")
        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.BUDGET_EXHAUSTED


class TestIdempotencyNotFixedOnBudgetRejection:
    def test_budget_rejection_does_not_register_attempt(self):
        budget = VdpExecutionBudget(max_requests=0, per_asset_burst=100)
        gate = VdpAdmissionGate(
            capability_matrix=_matrix(read_asset=CapabilityLevel.ALLOWED),
            budget=budget,
        )
        hyp = _hypothesis()
        guard = IdempotencyGuard()
        attempt = AttemptRecord(
            attempt_id="att-1",
            hypothesis_id=hyp.hypothesis_id,
            actor="authA",
            request_fingerprint="fp-1",
            scope_verdict="allowed",
        )
        result = gate.admit_attempt(attempt, hyp, budget=budget, idempotency_guard=guard)
        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.BUDGET_EXHAUSTED
        assert guard.is_registered("att-1") is False

    def test_successful_admit_registers_attempt(self):
        budget = VdpExecutionBudget(max_requests=10, per_asset_burst=100)
        gate = VdpAdmissionGate(
            capability_matrix=_matrix(read_asset=CapabilityLevel.ALLOWED),
            budget=budget,
        )
        hyp = _hypothesis()
        guard = IdempotencyGuard()
        attempt = AttemptRecord(
            attempt_id="att-2",
            hypothesis_id=hyp.hypothesis_id,
            actor="authA",
            request_fingerprint="fp-2",
            scope_verdict="allowed",
        )
        result = gate.admit_attempt(attempt, hyp, budget=budget, idempotency_guard=guard)
        assert result.admitted is True
        assert guard.is_registered("att-2") is True

    def test_duplicate_attempt_rejected_without_consuming(self):
        budget = VdpExecutionBudget(max_requests=10, per_asset_burst=100)
        gate = VdpAdmissionGate(
            capability_matrix=_matrix(read_asset=CapabilityLevel.ALLOWED),
            budget=budget,
        )
        hyp = _hypothesis()
        guard = IdempotencyGuard()
        attempt = AttemptRecord(
            attempt_id="att-3",
            hypothesis_id=hyp.hypothesis_id,
            actor="authA",
            request_fingerprint="fp-3",
            scope_verdict="allowed",
        )
        assert gate.admit_attempt(attempt, hyp, budget=budget, idempotency_guard=guard).admitted
        before = budget.snapshot()["requests_used"]
        result = gate.admit_attempt(attempt, hyp, budget=budget, idempotency_guard=guard)
        assert result.admitted is False
        assert result.reason_code == "idempotency_duplicate"
        assert budget.snapshot()["requests_used"] == before


class TestGateStateIsolation:
    def test_validate_and_admit_does_not_mutate_shared_gate(self):
        shared_matrix = _matrix(read_asset=CapabilityLevel.ALLOWED)
        shared_budget = VdpExecutionBudget(max_requests=10, per_asset_burst=100)
        gate = VdpAdmissionGate(capability_matrix=shared_matrix, budget=shared_budget)

        override_matrix = _matrix(sql_injection=CapabilityLevel.PROHIBITED)
        hyp = _hypothesis(capability="sql_injection")
        result = gate.validate_and_admit(
            hyp, override_matrix, "allowed", budget=shared_budget
        )
        assert result.admitted is False  # override matrix used

        # Shared gate state unchanged after the call
        assert gate.capability_matrix is shared_matrix
        assert gate.budget is shared_budget
        assert gate.evaluate(_hypothesis(capability="read_asset"), "allowed").admitted is True
