"""
VDP Admission Gate — SGK-2026-0419 Step 3.

Pre-execution admission gate that checks:
  - Scope revalidation (fail-closed for unknown)
  - Budget exhaustion
  - Capability matrix (allowed/confirmation_required/prohibited/unavailable)

Integrates with ProgramCapabilityMatrix, VdpExecutionBudget, and ScopeRevalidationResult.
Delegates capability/HITL checks to check_admission().

Design principles (from parent plan SGK-2026-0418):
  - Fail-closed for unknown scope, missing HITL, budget exhaustion.
  - Budget check happens before capability check.
  - Scope verdicts are routed to specific AdmissionReasonCode values.
"""
from __future__ import annotations

from typing import Optional

from src.core.engine.vdp_budget import VdpExecutionBudget
from src.core.models.vdp_contract import (
    AdmissionReasonCode,
    AdmissionResult,
    AttemptRecord,
    HypothesisRecord,
    ProgramCapabilityMatrix,
    check_admission,
    validate_hypothesis_record,
    validate_attempt_record,
)


class VdpAdmissionGate:
    """Pre-execution admission gate for VDP hypothesis evaluation.

    Checks in order:
    1. Scope verdict must be "allowed" — distinguishes out_of_scope,
       redirect_out_of_scope, and scope_revalidation_blocked with specific reason codes.
    2. Execution budget is not exhausted (when budget is configured).
    3. Capability is permitted via ProgramCapabilityMatrix and check_admission().

    Fail-closed: any unknown scope verdict, exhausted budget, missing HITL
    ticket, prohibited/unavailable capability all block admission.

    Usage::

        matrix = ProgramCapabilityMatrix(rules={"read_asset": CapabilityLevel.ALLOWED})
        budget = VdpExecutionBudget(max_requests=100, per_asset_burst=10)
        gate = VdpAdmissionGate(capability_matrix=matrix, budget=budget)
        result = gate.evaluate(hypothesis, scope_verdict="allowed")
        if result.admitted:
            # proceed with execution
    """

    def __init__(
        self,
        capability_matrix: ProgramCapabilityMatrix,
        budget: Optional[VdpExecutionBudget] = None,
    ):
        """Initialize the admission gate.

        Args:
            capability_matrix: Program capability matrix defining what capabilities
                are permitted and at what level.
            budget: Optional execution budget. When provided, each admission check
                consumes from the budget. Budget exhaustion blocks admission.
        """
        self.capability_matrix = capability_matrix
        self.budget = budget

    def evaluate(
        self,
        hypothesis: HypothesisRecord,
        scope_verdict: str,
        hitl_ticket_id: Optional[str] = None,
    ) -> AdmissionResult:
        """Evaluate whether a hypothesis can be admitted for execution.

        Args:
            hypothesis: The HypothesisRecord containing capability, asset,
                actor, and hypothesis identification.
            scope_verdict: Pre-communication scope revalidation verdict.
                Must be "allowed" to proceed. Other values are routed to
                specific reason codes (out_of_scope, redirect_out_of_scope,
                scope_revalidation_blocked).
            hitl_ticket_id: Optional HITL approval ticket ID. Required when
                the request's capability is at CONFIRMATION_REQUIRED level.

        Returns:
            AdmissionResult with admitted=True/False and structured reason code.
        """
        # 1. Scope verdict check — routing to specific reason codes
        if scope_verdict == "out_of_scope":
            return AdmissionResult(
                admitted=False,
                reason_code=AdmissionReasonCode.OUT_OF_SCOPE,
                detail="Target is out of scope",
            )
        if scope_verdict == "redirect_out_of_scope":
            return AdmissionResult(
                admitted=False,
                reason_code=AdmissionReasonCode.REDIRECT_OUT_OF_SCOPE,
                detail="Redirect target is out of scope",
            )
        if scope_verdict != "allowed":
            return AdmissionResult(
                admitted=False,
                reason_code=AdmissionReasonCode.SCOPE_REVALIDATION_BLOCKED,
                detail=f"Scope verdict is '{scope_verdict}', not 'allowed'",
            )

        # 2. Budget check — before capability check
        if self.budget is not None:
            asset = hypothesis.asset or ""
            actor = hypothesis.actors[0] if hypothesis.actors else ""
            hyp_id = hypothesis.hypothesis_id or ""

            budget_decision = self.budget.consume(
                asset_key=asset,
                actor_key=actor,
                hypothesis_key=hyp_id,
            )
            if not budget_decision.allowed:
                return AdmissionResult(
                    admitted=False,
                    reason_code=AdmissionReasonCode.BUDGET_EXHAUSTED,
                    detail=f"Budget exhausted: {budget_decision.reason_code}",
                )

        # 3. Capability/HITL check — delegate to check_admission
        #    Scope already passed above, so pass "allowed" to avoid double-check.
        return check_admission(
            capability=hypothesis.capability,
            capability_matrix=self.capability_matrix,
            scope_verdict="allowed",
            hitl_ticket_id=hitl_ticket_id,
        )

    def validate_and_admit(
        self,
        hypothesis: HypothesisRecord,
        capability_matrix: ProgramCapabilityMatrix,
        scope_verdict: str,
        hitl_ticket_id: Optional[str] = None,
        budget: Optional[VdpExecutionBudget] = None,
    ) -> AdmissionResult:
        """Validate hypothesis record, then evaluate admission.

        First runs ``validate_hypothesis_record(hypothesis)``. If validation
        errors exist, returns AdmissionResult with reason "validation_failed".
        Only after validation passes does it call ``evaluate()``.

        Args:
            hypothesis: The HypothesisRecord to validate and admit.
            capability_matrix: ProgramCapabilityMatrix for capability checks.
            scope_verdict: Pre-communication scope revalidation verdict.
            hitl_ticket_id: Optional HITL approval ticket ID.
            budget: Optional execution budget to consume from.

        Returns:
            AdmissionResult with admitted=True/False and structured reason code.
        """
        validation_errors = validate_hypothesis_record(hypothesis)
        if validation_errors:
            return AdmissionResult(
                admitted=False,
                reason_code="validation_failed",
                detail=f"Hypothesis validation failed: {'; '.join(validation_errors)}",
            )

        # Temporarily swap budget and capability_matrix for evaluate()
        saved_matrix = self.capability_matrix
        saved_budget = self.budget
        try:
            self.capability_matrix = capability_matrix
            self.budget = budget
            return self.evaluate(hypothesis, scope_verdict, hitl_ticket_id)
        finally:
            self.capability_matrix = saved_matrix
            self.budget = saved_budget

    def admit_attempt(
        self,
        attempt_record: AttemptRecord,
        hypothesis: HypothesisRecord,
        budget: Optional[VdpExecutionBudget] = None,
        idempotency_guard=None,
    ) -> AdmissionResult:
        """Validate attempt_record, check idempotency, consume budget.

        Args:
            attempt_record: The AttemptRecord to validate and admit.
            hypothesis: The parent HypothesisRecord for capability lookup.
            budget: Optional execution budget to consume from.
            idempotency_guard: Optional IdempotencyGuard to check for duplicates.

        Returns:
            AdmissionResult with admitted=True/False.
        """
        # Validate attempt record
        attempt_errors = validate_attempt_record(attempt_record)
        if attempt_errors:
            return AdmissionResult(
                admitted=False,
                reason_code="validation_failed",
                detail=f"Attempt validation failed: {'; '.join(attempt_errors)}",
            )

        # Check idempotency guard
        if idempotency_guard is not None:
            if not idempotency_guard.register(attempt_record.attempt_id):
                return AdmissionResult(
                    admitted=False,
                    reason_code="idempotency_duplicate",
                    detail=f"Attempt {attempt_record.attempt_id} already registered",
                )

        # Consume budget
        effective_budget = budget or self.budget
        if effective_budget is not None:
            asset = hypothesis.asset or ""
            actor = hypothesis.actors[0] if hypothesis.actors else ""
            hyp_id = hypothesis.hypothesis_id or ""
            budget_decision = effective_budget.consume(
                asset_key=asset,
                actor_key=actor,
                hypothesis_key=hyp_id,
            )
            if not budget_decision.allowed:
                return AdmissionResult(
                    admitted=False,
                    reason_code=AdmissionReasonCode.BUDGET_EXHAUSTED,
                    detail=f"Budget exhausted: {budget_decision.reason_code}",
                )

        return AdmissionResult(
            admitted=True,
            reason_code="attempt_admitted",
            detail="Attempt admitted successfully",
        )
