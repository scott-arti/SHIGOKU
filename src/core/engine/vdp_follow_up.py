"""
VDP follow-up reason code mapping — SGK-2026-0421 Step 1.

Deterministically maps every known reason code (sets A-E of the subtask
plan §3) to a unique NextAction or manual review. Unknown codes stop at
manual review with the reason attached — they are NEVER routed to a
generic scan.

Contract rules (plan §3 / design constraint A):
- The public vocabulary (recipe_contracts) is the source of truth.
- No production engine import of the reporting package (covered by test).
- No private constants from other modules are imported here.
- Mapping is a pure function of (reason_code, evidence_gap).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from src.core.engine.recipe_contracts import (
    VDP_ACTION_CLASSES,
    VDP_EVIDENCE_GAP_CODES,
    VDP_INFRA_REASON_CODES,
    VDP_REASON_CODES,
)
from src.core.models.vdp_contract import (
    AdmissionReasonCode,
    BudgetReasonCodeV1,
    HypothesisRecord,
    NextActionRecord,
    deterministic_id,
)

# ---------------------------------------------------------------------------
# Follow-up plan
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FollowUpPlan:
    """Deterministic plan for one reason code.

    Attributes:
        reason_code: The exact reason code string this plan maps.
        category: follow_up | manual_review | terminal | re_evaluate |
            delegate_to_gap (generated_candidate only).
        action_class: One of VDP_ACTION_CLASSES.
        risk_class: read_only | state_changing | out_of_band | "".
        m3a_policy: M3a treatment:
            - execute: may run read-only follow-up (read-only guard still
              re-checks the actual request semantics).
            - manual_review: M3a keeps this at manual review.
            - oob_gated: runs only when OOB is explicitly permitted by the
              ProgramCapabilityMatrix and the destination is in scope.
            - m3b_gated: requires the explicit M3b gate (never enabled here).
            - none: no follow-up possible (terminal/manual).
        required_preconditions: Precondition keys the executor must satisfy.
        success_evidence: Expected success evidence (plan §3-1).
        stop_condition: Stop condition for the follow-up (public vocabulary).
        notes: Extra audit notes (unknown-code reason etc.).
    """

    reason_code: str
    category: str
    action_class: str
    risk_class: str
    m3a_policy: str
    required_preconditions: Tuple[str, ...] = ()
    success_evidence: str = ""
    stop_condition: str = "evidence_gap_resolved_or_budget_exhausted"
    notes: str = ""


# ---------------------------------------------------------------------------
# Mapping table (sets A-E per subtask plan §3-1 / §3-2)
# ---------------------------------------------------------------------------

_FOLLOW_UP_MAP: Dict[str, FollowUpPlan] = {}

# --- set A: evidence gaps (plan table 3-1) ---------------------------------

_FOLLOW_UP_MAP["payload_request_mismatch"] = FollowUpPlan(
    reason_code="payload_request_mismatch",
    category="follow_up",
    action_class="follow_up_probe",
    risk_class="read_only",
    m3a_policy="execute",
    required_preconditions=("scope", "budget"),
    success_evidence="実requestとHypothesis payloadのmethod/URL/body/header位置一致",
)
_FOLLOW_UP_MAP["untested_no_second_account"] = FollowUpPlan(
    reason_code="untested_no_second_account",
    category="follow_up",
    action_class="follow_up_probe",
    risk_class="read_only",
    m3a_policy="execute",
    required_preconditions=("authA_authB", "owned_resources"),
    success_evidence="actor/owner交差による越権差分",
)
_FOLLOW_UP_MAP["authz_impact_not_proven"] = FollowUpPlan(
    reason_code="authz_impact_not_proven",
    category="follow_up",
    action_class="follow_up_probe",
    risk_class="read_only",
    m3a_policy="execute",
    required_preconditions=("protected_resource",),
    success_evidence="owner、permission、sensitive field差分",
)
_FOLLOW_UP_MAP["semantic_diff_owner_permission_sensitive_field"] = FollowUpPlan(
    reason_code="semantic_diff_owner_permission_sensitive_field",
    category="follow_up",
    action_class="follow_up_probe",
    risk_class="read_only",
    m3a_policy="execute",
    required_preconditions=("protected_resource",),
    success_evidence="owner、permission、sensitive field差分",
)
_FOLLOW_UP_MAP["state_change_not_verified"] = FollowUpPlan(
    reason_code="state_change_not_verified",
    category="follow_up",
    action_class="follow_up_probe",
    risk_class="state_changing",
    m3a_policy="m3b_gated",
    required_preconditions=("state_change_permission", "hitl"),
    success_evidence="独立再取得で状態差",
)
_FOLLOW_UP_MAP["state_change_readback"] = FollowUpPlan(
    reason_code="state_change_readback",
    category="follow_up",
    action_class="follow_up_probe",
    risk_class="state_changing",
    m3a_policy="m3b_gated",
    required_preconditions=("state_change_permission", "hitl"),
    success_evidence="独立再取得で状態差",
)
_FOLLOW_UP_MAP["browser_execution_missing"] = FollowUpPlan(
    reason_code="browser_execution_missing",
    category="follow_up",
    action_class="follow_up_probe",
    risk_class="read_only",
    m3a_policy="execute",
    required_preconditions=("browser", "auth_continuity"),
    success_evidence="execution token、DOM変化、再訪問",
)
_FOLLOW_UP_MAP["stored_revisit_missing"] = FollowUpPlan(
    reason_code="stored_revisit_missing",
    category="follow_up",
    action_class="follow_up_probe",
    risk_class="read_only",
    m3a_policy="execute",
    required_preconditions=("browser",),
    success_evidence="stored revisit再現",
)
_FOLLOW_UP_MAP["insufficient_timing_validation"] = FollowUpPlan(
    reason_code="insufficient_timing_validation",
    category="follow_up",
    action_class="follow_up_probe",
    risk_class="read_only",
    m3a_policy="execute",
    required_preconditions=("request_budget",),
    success_evidence="baseline/attack/inverseの統計差",
)
_FOLLOW_UP_MAP["command_execution_not_verified"] = FollowUpPlan(
    reason_code="command_execution_not_verified",
    category="follow_up",
    action_class="follow_up_probe",
    risk_class="read_only",
    m3a_policy="execute",
    required_preconditions=("action_permission",),
    success_evidence="安全markerまたは統計的timing",
)
_FOLLOW_UP_MAP["ssrf_proof_missing"] = FollowUpPlan(
    reason_code="ssrf_proof_missing",
    category="follow_up",
    action_class="follow_up_probe",
    risk_class="out_of_band",
    m3a_policy="oob_gated",
    required_preconditions=("oob_permission", "destination_scope"),
    success_evidence="attempt固有token callback",
)
_FOLLOW_UP_MAP["unique_oob_callback"] = FollowUpPlan(
    reason_code="unique_oob_callback",
    category="follow_up",
    action_class="follow_up_probe",
    risk_class="out_of_band",
    m3a_policy="oob_gated",
    required_preconditions=("oob_permission", "destination_scope"),
    success_evidence="attempt固有token callback",
)
_FOLLOW_UP_MAP["insufficient_response_difference"] = FollowUpPlan(
    reason_code="insufficient_response_difference",
    category="follow_up",
    action_class="follow_up_probe",
    risk_class="read_only",
    m3a_policy="execute",
    required_preconditions=("budget",),
    success_evidence="正規化後差分",
)
_FOLLOW_UP_MAP["weak_session_not_statistically_verified"] = FollowUpPlan(
    reason_code="weak_session_not_statistically_verified",
    category="follow_up",
    action_class="follow_up_probe",
    risk_class="read_only",
    m3a_policy="execute",
    required_preconditions=("budget",),
    success_evidence="統計差",
)
_FOLLOW_UP_MAP["file_upload_impact_not_proven"] = FollowUpPlan(
    reason_code="file_upload_impact_not_proven",
    category="follow_up",
    action_class="follow_up_probe",
    risk_class="state_changing",
    m3a_policy="m3b_gated",
    required_preconditions=("state_change_permission", "hitl"),
    success_evidence="transform/publish差分",
)
_FOLLOW_UP_MAP["public_documentation_not_authorization_impact"] = FollowUpPlan(
    reason_code="public_documentation_not_authorization_impact",
    category="manual_review",
    action_class="manual_review",
    risk_class="",
    m3a_policy="none",
)
_FOLLOW_UP_MAP["session_takeover_not_verified"] = FollowUpPlan(
    reason_code="session_takeover_not_verified",
    category="manual_review",
    action_class="manual_review",
    risk_class="",
    m3a_policy="none",
)
_FOLLOW_UP_MAP["redirect_target_not_external"] = FollowUpPlan(
    reason_code="redirect_target_not_external",
    category="manual_review",
    action_class="manual_review",
    risk_class="",
    m3a_policy="none",
)
_FOLLOW_UP_MAP["synthetic_response_evidence"] = FollowUpPlan(
    reason_code="synthetic_response_evidence",
    category="manual_review",
    action_class="manual_review",
    risk_class="",
    m3a_policy="none",
    notes="証拠完全性問題",
)
_FOLLOW_UP_MAP["evidence_channel_lost"] = FollowUpPlan(
    reason_code="evidence_channel_lost",
    category="re_evaluate",
    action_class="re_evaluate",
    risk_class="",
    m3a_policy="none",
    required_preconditions=("health_recovery",),
    success_evidence="同じattempt lineageの証拠",
    stop_condition="evidence_gap_resolved_or_budget_exhausted",
)
_FOLLOW_UP_MAP["scope_revalidation_blocked"] = FollowUpPlan(
    reason_code="scope_revalidation_blocked",
    category="manual_review",
    action_class="manual_review",
    risk_class="",
    m3a_policy="none",
    required_preconditions=("scope_explicit",),
    success_evidence="新しいscope verdict",
    stop_condition="scope_revalidation_blocked",
)

# --- set B: generator reason codes (plan table 3-2) -------------------------

_FOLLOW_UP_MAP["label_leakage_detected"] = FollowUpPlan(
    reason_code="label_leakage_detected",
    category="terminal",
    action_class="terminal",
    risk_class="",
    m3a_policy="none",
    notes="rejection理由として保存（監査可能）",
)
_FOLLOW_UP_MAP["duplicate_dedup_key"] = FollowUpPlan(
    reason_code="duplicate_dedup_key",
    category="terminal",
    action_class="terminal",
    risk_class="",
    m3a_policy="none",
    notes="suppression理由として保存",
)
_FOLLOW_UP_MAP["diversity_budget_exceeded"] = FollowUpPlan(
    reason_code="diversity_budget_exceeded",
    category="terminal",
    action_class="terminal",
    risk_class="",
    m3a_policy="none",
    notes="suppression理由として保存",
)
_FOLLOW_UP_MAP["no_observations"] = FollowUpPlan(
    reason_code="no_observations",
    category="terminal",
    action_class="terminal",
    risk_class="",
    m3a_policy="none",
    notes="degraded理由として保存",
)
_FOLLOW_UP_MAP["generator_exception"] = FollowUpPlan(
    reason_code="generator_exception",
    category="terminal",
    action_class="terminal",
    risk_class="",
    m3a_policy="none",
    notes="degraded理由として保存",
)
_FOLLOW_UP_MAP["budget_estimate_missing"] = FollowUpPlan(
    reason_code="budget_estimate_missing",
    category="manual_review",
    action_class="manual_review",
    risk_class="",
    m3a_policy="none",
    notes="予算根拠の欠落",
)
_FOLLOW_UP_MAP["generated_candidate"] = FollowUpPlan(
    reason_code="generated_candidate",
    category="delegate_to_gap",
    action_class="follow_up_probe",
    risk_class="read_only",
    m3a_policy="execute",
    notes="生成元のrequired_evidence先頭gapの写像先に従う",
)

# --- set C: admission reason codes (plan table 3-2) -------------------------

_FOLLOW_UP_MAP[AdmissionReasonCode.OUT_OF_SCOPE] = FollowUpPlan(
    reason_code=AdmissionReasonCode.OUT_OF_SCOPE,
    category="terminal",
    action_class="terminal",
    risk_class="",
    m3a_policy="none",
    notes="untested相当・理由コード保存",
)
_FOLLOW_UP_MAP[AdmissionReasonCode.REDIRECT_OUT_OF_SCOPE] = FollowUpPlan(
    reason_code=AdmissionReasonCode.REDIRECT_OUT_OF_SCOPE,
    category="terminal",
    action_class="terminal",
    risk_class="",
    m3a_policy="none",
    notes="untested相当・理由コード保存",
)
_FOLLOW_UP_MAP[AdmissionReasonCode.HITL_REQUIRED] = FollowUpPlan(
    reason_code=AdmissionReasonCode.HITL_REQUIRED,
    category="manual_review",
    action_class="manual_review",
    risk_class="",
    m3a_policy="none",
    notes="HITL承認待ち（M3b gateで再評価）",
)
_FOLLOW_UP_MAP[AdmissionReasonCode.CAPABILITY_PROHIBITED] = FollowUpPlan(
    reason_code=AdmissionReasonCode.CAPABILITY_PROHIBITED,
    category="terminal",
    action_class="terminal",
    risk_class="",
    m3a_policy="none",
    notes="untested相当・理由コード保存",
)
_FOLLOW_UP_MAP[AdmissionReasonCode.CAPABILITY_UNAVAILABLE] = FollowUpPlan(
    reason_code=AdmissionReasonCode.CAPABILITY_UNAVAILABLE,
    category="terminal",
    action_class="terminal",
    risk_class="",
    m3a_policy="none",
    notes="untested相当・理由コード保存",
)
_FOLLOW_UP_MAP[AdmissionReasonCode.BUDGET_EXHAUSTED] = FollowUpPlan(
    reason_code=AdmissionReasonCode.BUDGET_EXHAUSTED,
    category="terminal",
    action_class="terminal",
    risk_class="",
    m3a_policy="none",
    notes="untested_budget_exhausted相当",
)

# --- set D: budget / circuit breaker reason codes (plan table 3-2) ----------

_TERMINAL_BUDGET_CODES = {
    BudgetReasonCodeV1.REQUESTS_EXHAUSTED,
    BudgetReasonCodeV1.FOLLOW_UPS_EXHAUSTED,
    BudgetReasonCodeV1.RETRIES_EXHAUSTED,
    BudgetReasonCodeV1.CONCURRENCY_EXCEEDED,
    BudgetReasonCodeV1.RUNTIME_EXCEEDED,
    BudgetReasonCodeV1.ARTIFACT_BYTES_EXCEEDED,
    BudgetReasonCodeV1.ASSET_BUDGET_EXHAUSTED,
    BudgetReasonCodeV1.ACTOR_BUDGET_EXHAUSTED,
    BudgetReasonCodeV1.HYPOTHESIS_BUDGET_EXHAUSTED,
}
for _code in _TERMINAL_BUDGET_CODES:
    _FOLLOW_UP_MAP[_code] = FollowUpPlan(
        reason_code=_code,
        category="terminal",
        action_class="terminal",
        risk_class="",
        m3a_policy="none",
        notes="untested_budget_exhausted・理由コード保存",
    )
del _TERMINAL_BUDGET_CODES

for _code in (
    BudgetReasonCodeV1.CIRCUIT_OPEN_429,
    BudgetReasonCodeV1.CIRCUIT_OPEN_5XX,
    BudgetReasonCodeV1.CIRCUIT_OPEN_TIMEOUT,
    BudgetReasonCodeV1.CIRCUIT_OPEN_LATENCY,
):
    _FOLLOW_UP_MAP[_code] = FollowUpPlan(
        reason_code=_code,
        category="re_evaluate",
        action_class="re_evaluate",
        risk_class="",
        m3a_policy="none",
        notes="冷却後に再評価可（同一attemptは自動再送しない）",
        stop_condition="max_retries_exceeded",
    )
del _code

# --- set E: infrastructure reason codes (plan table 3-2) --------------------

_FOLLOW_UP_MAP["follow_up_enqueue_failed"] = FollowUpPlan(
    reason_code="follow_up_enqueue_failed",
    category="re_evaluate",
    action_class="re_evaluate",
    risk_class="",
    m3a_policy="none",
    notes="NextAction喪失なし・degraded",
    stop_condition="evidence_gap_resolved_or_budget_exhausted",
)
_FOLLOW_UP_MAP["dependency_unavailable"] = FollowUpPlan(
    reason_code="dependency_unavailable",
    category="re_evaluate",
    action_class="re_evaluate",
    risk_class="",
    m3a_policy="none",
    required_preconditions=("health_recovery",),
    notes="health回復後（refutedへ変換しない）",
    stop_condition="evidence_gap_resolved_or_budget_exhausted",
)
_FOLLOW_UP_MAP["unknown_reason_code"] = FollowUpPlan(
    reason_code="unknown_reason_code",
    category="manual_review",
    action_class="manual_review",
    risk_class="",
    m3a_policy="none",
    notes="reason付きで停止（generic scanへ送らない）",
)

# The shared contract sets are fully covered by the table above.
_KNOWN_CODES: frozenset = frozenset(_FOLLOW_UP_MAP)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_known_reason_code(reason_code: str) -> bool:
    """Return True when the code has an explicit mapping (sets A-E)."""
    return str(reason_code or "") in _KNOWN_CODES


def classify_reason_code(
    reason_code: str,
    *,
    evidence_gap: str = "",
) -> FollowUpPlan:
    """Deterministically classify a reason code.

    Unknown codes map to ``manual_review`` with the original code recorded
    in ``notes`` (fail-closed; never routed to a generic scan).
    """
    code = str(reason_code or "")
    plan = _FOLLOW_UP_MAP.get(code)
    if plan is not None:
        return plan
    return FollowUpPlan(
        reason_code=code,
        category="manual_review",
        action_class="manual_review",
        risk_class="",
        m3a_policy="none",
        notes=f"unknown_reason_code={code}",
        stop_condition="no_follow_up_needed",
    )


def build_next_action_record(
    verdict_id: str,
    hypothesis: HypothesisRecord,
    reason_code: str,
    *,
    evidence_gap: str = "",
) -> NextActionRecord:
    """Build a deterministic NextActionRecord from a reason code.

    ``generated_candidate`` delegates to ``evidence_gap`` (the candidate's
    first required evidence gap); an unknown gap then stops at manual review.
    """
    gap = str(evidence_gap or "")
    if reason_code == "generated_candidate":
        plan = classify_reason_code(gap) if gap else classify_reason_code("unknown_reason_code")
        effective_gap = gap
        if plan.category == "manual_review" and not is_known_reason_code(gap):
            plan = FollowUpPlan(
                reason_code=gap,
                category="manual_review",
                action_class="manual_review",
                risk_class="",
                m3a_policy="none",
                notes=f"unknown_reason_code={gap}",
                stop_condition="no_follow_up_needed",
            )
    else:
        plan = classify_reason_code(reason_code)
        effective_gap = reason_code

    next_action_id = deterministic_id(
        "nxt",
        {
            "verdict_id": verdict_id,
            "action_class": plan.action_class,
            "evidence_gap": effective_gap,
        },
    )
    preconditions: Dict[str, Any] = {}
    for key in plan.required_preconditions:
        preconditions[key] = False  # executor must satisfy and flip each
    if plan.notes:
        preconditions["_notes"] = plan.notes

    return NextActionRecord(
        next_action_id=next_action_id,
        verdict_id=verdict_id,
        evidence_gap=effective_gap,
        required_preconditions=preconditions,
        action_class=plan.action_class,
        risk_class=plan.risk_class,
        expected_information_gain=plan.success_evidence,
        stop_condition=plan.stop_condition,
    )


def is_follow_up_executable(plan: FollowUpPlan) -> bool:
    """Whether M3a may enqueue this plan (read-only follow-up only).

    manual_review / terminal / re_evaluate / m3b_gated plans never enqueue.
    ``oob_gated`` plans require explicit OOB permission checked at admission.
    """
    if plan.category != "follow_up":
        return False
    if plan.m3a_policy in {"execute", "oob_gated"}:
        return True
    return False
