"""
VDP Admission Gate — SGK-2026-0419 Step 3 (amended by SGK-2026-0421).

Pre-execution admission gate that checks:
  - Scope revalidation (fail-closed for unknown)
  - Budget exhaustion (peek first — admission rejection never consumes)
  - Capability matrix (allowed/confirmation_required/prohibited/unavailable)
  - HITL ticket verification (SGK-2026-0421, design constraint G):
    a ticket ID alone is never approval — the ticket must exist in the
    pending store, be ``approved``, and bind the same action / hypothesis /
    actor / risk_class.

Order (preserving 0419 budget-priority semantics):
  1. Scope verdict routing (out_of_scope / redirect_out_of_scope /
     scope_revalidation_blocked).
  2. Budget PEEK (non-consuming) — exhausted → BUDGET_EXHAUSTED.
  3. Capability / HITL verification (no budget consumed on rejection).
  4. Budget CONSUME (atomic commit; may reject on a concurrent race).

The gate never mutates its own capability_matrix/budget for a call
(SGK-2026-0421: shared gate state must not be temporarily swapped).
"""
from __future__ import annotations

from typing import Any, List, Optional

from src.core.engine.vdp_budget import VdpExecutionBudget
from src.core.engine.vdp_hitl_guard import verify_hitl_ticket
from src.core.models.vdp_contract import (
    AdmissionReasonCode,
    AdmissionResult,
    AttemptRecord,
    CapabilityLevel,
    HypothesisRecord,
    ProgramCapabilityMatrix,
    check_admission,
    validate_hypothesis_record,
    validate_attempt_record,
)


class VdpAdmissionGate:
    """Pre-execution admission gate for VDP hypothesis evaluation."""

    def __init__(
        self,
        capability_matrix: ProgramCapabilityMatrix,
        budget: Optional[VdpExecutionBudget] = None,
    ):
        self.capability_matrix = capability_matrix
        self.budget = budget

    def evaluate(
        self,
        hypothesis: HypothesisRecord,
        scope_verdict: str,
        hitl_ticket_id: Optional[str] = None,
        hitl_tickets: Optional[List[Any]] = None,
        *,
        capability_matrix: Optional[ProgramCapabilityMatrix] = None,
        budget: Optional[VdpExecutionBudget] = None,
        action: str = "",
    ) -> AdmissionResult:
        """Evaluate whether a hypothesis can be admitted for execution.

        Args:
            hypothesis: The HypothesisRecord to admit.
            scope_verdict: Pre-communication scope revalidation verdict.
                Must be "allowed".
            hitl_ticket_id: Claimed HITL ticket ID (presence is NOT approval;
                the ticket must verify against ``hitl_tickets``).
            hitl_tickets: The pending HITL store entries used for
                verification of confirmation_required capabilities.
            capability_matrix: Optional per-call matrix override (the shared
                instance is never mutated).
            budget: Optional per-call budget override.
            action: Expected follow-up action class for HITL binding.

        Returns:
            AdmissionResult with admitted=True/False and structured reason code.
        """
        matrix = (
            capability_matrix
            if capability_matrix is not None
            else self.capability_matrix
        )
        effective_budget = budget if budget is not None else self.budget

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

        asset = hypothesis.asset or ""
        actor = hypothesis.actors[0] if hypothesis.actors else ""
        hyp_id = hypothesis.hypothesis_id or ""

        # 2. Budget PEEK — exhausted budget blocks before capability checks
        #    (0419 priority semantics) WITHOUT consuming anything.
        if effective_budget is not None:
            peek = effective_budget.peek(
                asset_key=asset,
                actor_key=actor,
                hypothesis_key=hyp_id,
            )
            if not peek.allowed:
                return AdmissionResult(
                    admitted=False,
                    reason_code=AdmissionReasonCode.BUDGET_EXHAUSTED,
                    detail=f"Budget exhausted: {peek.reason_code}",
                )

        # 3. Capability / HITL check — delegate to check_admission, but
        #    confirmation_required needs a VERIFIED ticket first.
        level = matrix.get_level(hypothesis.capability)
        if level == CapabilityLevel.CONFIRMATION_REQUIRED:
            if not hitl_ticket_id:
                return AdmissionResult(
                    admitted=False,
                    reason_code=AdmissionReasonCode.HITL_REQUIRED,
                    detail=f"Capability '{hypothesis.capability}' requires HITL approval ticket",
                )
            verification = verify_hitl_ticket(
                hitl_ticket_id,
                tickets=hitl_tickets,
                action=action,
                hypothesis_id=hyp_id,
                actor=actor,
                risk_class=hypothesis.risk_class,
            )
            if not verification.verified:
                return AdmissionResult(
                    admitted=False,
                    reason_code=verification.reason_code
                    or AdmissionReasonCode.HITL_REQUIRED,
                    detail=verification.detail,
                )

        capability_result = check_admission(
            capability=hypothesis.capability,
            capability_matrix=matrix,
            scope_verdict="allowed",
            hitl_ticket_id=hitl_ticket_id,
        )
        if not capability_result.admitted:
            return capability_result

        # 4. Budget CONSUME — atomic commit. Nothing was consumed on any
        #    rejection path above (design constraint G).
        if effective_budget is not None:
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
            reason_code="admitted",
            detail="Admission granted",
        )

    def validate_and_admit(
        self,
        hypothesis: HypothesisRecord,
        capability_matrix: ProgramCapabilityMatrix,
        scope_verdict: str,
        hitl_ticket_id: Optional[str] = None,
        hitl_tickets: Optional[List[Any]] = None,
        budget: Optional[VdpExecutionBudget] = None,
        action: str = "",
    ) -> AdmissionResult:
        """Validate hypothesis record, then evaluate admission.

        The shared gate instance is never mutated: matrix/budget are passed
        as per-call overrides (SGK-2026-0421 design constraint G).
        """
        validation_errors = validate_hypothesis_record(hypothesis)
        if validation_errors:
            return AdmissionResult(
                admitted=False,
                reason_code="validation_failed",
                detail=f"Hypothesis validation failed: {'; '.join(validation_errors)}",
            )

        return self.evaluate(
            hypothesis,
            scope_verdict,
            hitl_ticket_id,
            hitl_tickets,
            capability_matrix=capability_matrix,
            budget=budget,
            action=action,
        )

    def admit_attempt(
        self,
        attempt_record: AttemptRecord,
        hypothesis: HypothesisRecord,
        budget: Optional[VdpExecutionBudget] = None,
        idempotency_guard=None,
    ) -> AdmissionResult:
        """Validate attempt_record, check idempotency (without registering on
        rejection), consume budget, then register the attempt ID.

        Order (design constraint G):
        1. attempt validation
        2. idempotency duplicate check (read-only)
        3. budget consume (atomic)
        4. idempotency register — only after budget success, so a budget
           rejection never fixes the ID as registered.
        """
        attempt_errors = validate_attempt_record(attempt_record)
        if attempt_errors:
            return AdmissionResult(
                admitted=False,
                reason_code="validation_failed",
                detail=f"Attempt validation failed: {'; '.join(attempt_errors)}",
            )

        if idempotency_guard is not None:
            if idempotency_guard.is_registered(attempt_record.attempt_id):
                return AdmissionResult(
                    admitted=False,
                    reason_code="idempotency_duplicate",
                    detail=f"Attempt {attempt_record.attempt_id} already registered",
                )

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

        if idempotency_guard is not None:
            idempotency_guard.register(attempt_record.attempt_id)

        return AdmissionResult(
            admitted=True,
            reason_code="attempt_admitted",
            detail="Attempt admitted successfully",
        )
