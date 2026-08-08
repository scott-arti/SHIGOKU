"""
VDP follow-up executor — SGK-2026-0421 Steps 8-12 (M3a read-only enforce).

Deterministic follow-up execution for evidence gaps that M3a may run:
read-equivalent GET probes (exact replay, repeated controls / timing,
response-difference). Everything else stops at manual review — the executor
NEVER falls back to a generic scan, never sends state-changing requests,
and never creates confirmed verdicts.

Safety contract:
- kill switch checked before any work.
- Preconditions (scope/budget/authA_authB/OOB/browser/...) must be
  satisfiable; missing preconditions → manual_review, no send.
- Read-only guard re-checks the ACTUAL request semantics (method alone is
  never enough; GraphQL mutation / form-submit semantics are rejected).
- Scope revalidated with an explicit snapshot; redirects are NOT followed
  (each hop would need its own scope+budget re-evaluation).
- Budget consumed per actual network request — request count and budget
  consumption always match.
- Idempotency: attempt_id is registered only after all checks pass; the
  same NextAction re-processed never duplicates Attempt/Evidence.
- Attempt/Evidence IDs are deterministic (canonical JSON -> SHA-256).
- Evidence records keep raw hash + redacted excerpt + size + truncation
  reason; raw response bodies are never stored.
- State changes are sent ONLY through the M3b authorized path
  (``m3b_authorized`` spec flag + non-empty HITL ticket): exactly ONE
  mutation per attempt, the sent fact is persisted in the StateChangeGuard
  at the send boundary (``mark_sent``), and no-auto-resend holds even when
  the session save fails afterwards.
- SGK-2026-0423 Lane P-1 (cross-account comparison observation layer): for
  the comparison-capable read-only gaps the executor performs TWO
  authenticated GETs (account A then account B) when the spec carries
  ``auth_a_id``/``auth_b_id`` and both secrets resolve from the injected
  ``account_credentials`` store, and records ONLY TRUTHFUL structured
  markers (owner-attribution observed, comparison completed). The canonical
  Evidence Validator may then confirm from those markers — the executor
  itself never creates verdicts.
- Secret boundary: specs/session/evidence carry account IDs ONLY; secrets
  resolve from ``account_credentials`` at send time and are passed only to
  the network client — never logged or recorded.
- No confirmed verdict is produced here.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlparse

from src.core.engine.vdp_admission import VdpAdmissionGate
from src.core.engine.vdp_diagnostic_trace import DiagnosticCollector
from src.core.engine.vdp_follow_up import (
    FollowUpPlan,
    classify_reason_code,
    is_follow_up_executable,
)
from src.core.engine.vdp_readonly_guard import evaluate_readonly_request
from src.core.models.vdp_contract import (
    AttemptRecord,
    EvidenceRecordV1,
    EvidenceVerdictV1,
    HypothesisRecord,
    IdempotencyGuard,
    ProgramCapabilityMatrix,
    StateChangeGuard,
    deterministic_id,
    redact_secrets_deep,
    truncate_evidence_body,
)
from src.core.domain.scope.vdp_scope_validator import revalidate_scope_for_request
from src.core.security.ethics_guard import ScopeDefinition

# Execution statuses
EXECUTED = "executed"
MANUAL_REVIEW = "manual_review"
BLOCKED = "blocked"
DEGRADED = "degraded"
ERROR = "error"

# SGK-2026-0423 Lane F: state-changing plans are gated by the M3b policy.
# The executor sends them ONLY when the spec carries BOTH ``m3b_authorized``
# and a non-empty ``hitl_ticket`` (authorization is decided by the caller at
# queue/dispatch time against the rollout gate).
STATE_CHANGING_POLICY = "m3b_gated"

# Plans that send exactly one read GET.
_SINGLE_REQUEST_GAPS = {
    "payload_request_mismatch",
    "insufficient_response_difference",
}
# Plans that send repeated baseline/attack/inverse GETs (A/B/A).
_REPEATED_CONTROL_GAPS = {
    "insufficient_timing_validation",
    "weak_session_not_statistically_verified",
}

# 0421 only executes a gap when the current Observation contract contains
# enough request metadata to produce the evidence promised by the plan.
# Comparative/timing/auth/browser/OOB gaps stay pending until their explicit
# runtime controls/providers are available; they must never be mislabeled as
# successful evidence after a generic GET.
# SGK-2026-0423 Lane P-1: the comparison-capable gaps run the cross-account
# observation layer (two authenticated GETs, account A then account B) when
# the spec carries auth_a_id/auth_b_id and the secrets resolve; WITHOUT
# account ids they keep the existing single-request neutral-fact path.
_COMPARISON_GAPS = frozenset({
    "authz_impact_not_proven",
    "semantic_diff_owner_permission_sensitive_field",
    "untested_no_second_account",
})
_SUPPORTED_M3A_GAPS = (
    frozenset({"payload_request_mismatch", "insufficient_timing_validation"})
    | _COMPARISON_GAPS
)


def is_m3a_executor_supported_gap(evidence_gap: str) -> bool:
    return str(evidence_gap or "") in _SUPPORTED_M3A_GAPS


# ---------------------------------------------------------------------------
# SGK-2026-0433 timing foundation (m3a read-only, GET only)
# ---------------------------------------------------------------------------

# Sample counts of the timing control sequence. The positive control is a
# CLIENT-SIDE calibration: a short sleep before each positive request, inside
# the measured wall-clock window, proving the pipeline can detect a latency
# offset of the magnitude a delay-based condition would produce. It is NOT a
# server-side condition delta — ``timing_difference_observed`` never derives
# from it (the record labels it as client-side control).
_TIMING_BASELINE_SAMPLES = 3
_TIMING_POSITIVE_SAMPLES = 3
_TIMING_NEGATIVE_SAMPLES = 2
_TIMING_VARIANT_SAMPLES = 3
_TIMING_METHOD = "GET"
_TIMING_POSITIVE_CONTROL_SLEEP_SECONDS = 0.2  # 200ms client-side hold
# Detection threshold for the calibration: 100ms or 50% of the inserted
# client-side delay, whichever is smaller (deliberately NOT relaxed).
_TIMING_DETECTION_THRESHOLD_MS = 100.0
# Delta-vs-jitter criteria for a REAL read-only condition delta: the median
# delta must be >= 50ms AND >= 3x the baseline median absolute deviation,
# with non-overlapping [Q1, Q3] intervals.
_TIMING_MIN_DELTA_MS = 50.0
_TIMING_JITTER_MULTIPLIER = 3.0
# Honest reason vocabulary for the timing record.
_TIMING_REASON_INSENSITIVE = "timing_pipeline_insensitive"
_TIMING_REASON_NO_VARIANT = "no_alternate_condition_in_readonly_scope"
_TIMING_REASON_NO_DELTA = "no_timing_difference_beyond_jitter"
_TIMING_REASON_DELTA = "variant_timing_difference_observed"


def _timing_median_or_zero(values: List[float]) -> float:
    """Median of a latency sample group; 0.0 for an empty group."""
    return statistics.median(values) if values else 0.0


def _quantile_bounds(values: List[float]) -> Tuple[float, float]:
    """(Q1, Q3) bounds of a latency sample group (deterministic)."""
    if not values:
        return 0.0, 0.0
    if len(values) == 1:
        sample = float(values[0])
        return sample, sample
    quartiles = statistics.quantiles(values, n=4)
    return float(quartiles[0]), float(quartiles[2])


def build_follow_up_task_id(
    next_action_id: str,
    hypothesis_id: str,
    actor: str,
) -> str:
    """Deterministic task ID from the NextAction/Attempt lineage (constraint H)."""
    return deterministic_id(
        "vfu",
        {
            "next_action_id": next_action_id,
            "hypothesis_id": hypothesis_id,
            "actor": actor,
        },
    )


def build_attempt_id(hypothesis_id: str, evidence_gap: str, actor: str) -> str:
    """Deterministic attempt ID (constraint I: attempt_id and idempotency key)."""
    return deterministic_id(
        "att",
        {
            "hypothesis_id": hypothesis_id,
            "evidence_gap": evidence_gap,
            "actor": actor,
        },
        length=20,
    )


def build_request_fingerprint(
    method: str,
    url: str,
    param_names: Tuple[str, ...],
    header_positions: Tuple[str, ...] = (),
    param_locations: Tuple[str, ...] = (),
) -> str:
    """Deterministic request fingerprint: method, URL, body, header positions.

    Constraint J: secret VALUES are never part of the fingerprint — only
    canonical names/positions are hashed.
    """
    return deterministic_id(
        "fp",
        {
            "method": str(method or "").upper(),
            "url": url,
            "body": None,
            "param_names": sorted(param_names),
            "param_locations": sorted(param_locations),
            "header_positions": sorted(header_positions),
        },
        length=24,
    )


def build_follow_up_spec(
    next_action_id: str,
    hypothesis: HypothesisRecord,
    *,
    url: str,
    method: str,
    param_names: Tuple[str, ...],
    actor: str,
    plan: FollowUpPlan,
    param_locations: Tuple[str, ...] = (),
    header_positions: Tuple[str, ...] = (),
) -> Dict[str, Any]:
    """Serializable, secret-free follow-up spec (stored in _vdp_state)."""
    return {
        "task_id": build_follow_up_task_id(
            next_action_id, hypothesis.hypothesis_id, actor
        ),
        "hypothesis_id": hypothesis.hypothesis_id,
        "verdict_id": "",
        "next_action_id": next_action_id,
        "evidence_gap": plan.reason_code,
        "url": url,
        "method": str(method or "GET").upper(),
        "param_names": list(param_names),
        "param_locations": list(param_locations),
        "header_positions": list(header_positions),
        "expected_request_fingerprint": build_request_fingerprint(
            method,
            url,
            param_names,
            header_positions,
            param_locations,
        ),
        "actor": actor,
        "risk_class": plan.risk_class,
        "action_class": plan.action_class,
        "plan_category": plan.category,
        "plan_m3a_policy": plan.m3a_policy,
        "required_preconditions": list(plan.required_preconditions),
        "success_evidence": plan.success_evidence,
        "stop_condition": plan.stop_condition,
    }


@dataclass
class FollowUpExecutionResult:
    """Result of one follow-up execution.

    ``state_change_sent`` (SGK-2026-0423 Lane L-2): True exactly when a
    state-changing send happened AND ``StateChangeGuard.mark_sent`` was
    called (the EXECUTED path and the evidence_write_backpressure DEGRADED
    path — the HTTP send precedes evidence persistence). False on network
    failure, all blocked/manual paths, and read-only executions. The WAL
    transition in the dispatcher keys off this fact, never off status.
    """

    status: str
    reason: str = ""
    attempt_id: str = ""
    evidence_id: str = ""
    requests_made: int = 0
    verdict_status: str = ""  # candidate only — never confirmed here
    budget_snapshot: Dict[str, Any] = field(default_factory=dict)
    attempt: Optional[Dict[str, Any]] = None  # AttemptRecord.to_dict() when executed
    evidence: Optional[Dict[str, Any]] = None  # EvidenceRecordV1.to_dict() when executed
    state_change_sent: bool = False  # mark_sent was called (send happened)


def _redact_body_text(body: str) -> str:
    """Redact a response body for the evidence excerpt.

    JSON payloads are parsed and redacted recursively (key-based); non-JSON
    text goes through the regex-based redaction. Raw values never survive.
    """
    try:
        import json as _json

        parsed = _json.loads(body)
        if isinstance(parsed, (dict, list)):
            return _json.dumps(
                redact_secrets_deep(parsed), ensure_ascii=False
            )
    except Exception:
        pass
    return redact_secrets_deep(body)


class VdpFollowUpExecutor:
    """Executes one M3a follow-up spec with full pre-communication admission."""

    def __init__(
        self,
        *,
        scope_definition: Optional[ScopeDefinition],
        capability_matrix: ProgramCapabilityMatrix,
        budget: Any,
        network_client: Any,
        evidence_writer: Any,
        idempotency_guard: Optional[IdempotencyGuard] = None,
        state_change_guard: Optional[StateChangeGuard] = None,
        kill_switch_provider: Optional[Callable[[], bool]] = None,
        available_preconditions: Optional[Dict[str, bool]] = None,
        hitl_ticket_validator: Optional[Callable[[str], bool]] = None,
        account_credentials: Optional[Mapping[str, str]] = None,
        timeout: float = 15.0,
        hypothesis: Optional[HypothesisRecord] = None,
        gate: Optional[VdpAdmissionGate] = None,
        diagnostic_collector: Optional[DiagnosticCollector] = None,
    ):
        """Executes one M3a/M3b follow-up spec.

        ``hitl_ticket_validator`` (SGK-2026-0423 Lane J-2): checks a HITL
        ticket string against the REAL HITL ledger — approved, target-
        matching, and within validity. None = no ledger available =
        fail-closed (a state-changing spec is then refused; an arbitrary
        string is NEVER approval on its own).

        ``account_credentials`` (SGK-2026-0423 Lane P-1): mapping of
        account_id -> secret for the cross-account comparison layer. The
        SPEC carries account IDs only; secrets are resolved here at send
        time and passed solely to the network client — they never appear
        in specs, attempts, evidence, or results.

        ``diagnostic_collector`` (SGK-2026-0425 M1): optional bounded
        diagnostic telemetry collector (None when diagnostics disabled →
        every emission is a no-op). When the collector is ``required`` and
        a hook failure was recorded, ``execute`` stops with a blocked
        ``diagnostic_telemetry_hook_failure`` result BEFORE the first
        network send (fail-closed telemetry kill switch).
        """
        self.scope_definition = scope_definition
        self.capability_matrix = capability_matrix
        self.budget = budget
        self.network_client = network_client  # injected by MasterConductor
        self.evidence_writer = evidence_writer
        self.idempotency_guard = idempotency_guard or IdempotencyGuard()
        self.state_change_guard = state_change_guard or StateChangeGuard()
        self.kill_switch_provider = kill_switch_provider
        self.available_preconditions = dict(available_preconditions or {})
        self.hitl_ticket_validator = hitl_ticket_validator
        self.account_credentials = dict(account_credentials or {})
        self.timeout = float(timeout)
        self.hypothesis = hypothesis
        self.gate = gate or VdpAdmissionGate(
            capability_matrix=capability_matrix, budget=None
        )
        self.diagnostic_collector = diagnostic_collector
        # SGK-2026-0433 followup: exception class name of the last transport
        # failure ("" when the last send succeeded) so the timing sequence can
        # distinguish real TimeoutError from other transport errors.
        self._last_transport_error_type = ""

    # ------------------------------------------------------------------
    # Diagnostic telemetry (SGK-2026-0425 M1, additive)
    # ------------------------------------------------------------------

    def _diag_emit(
        self,
        *,
        stage_id: str,
        outcome: str,
        reason_codes: Tuple[str, ...] = (),
        source_refs: Tuple[str, ...] = (),
    ) -> None:
        """Emit one diagnostic event AFTER the corresponding side effect.

        No-op when no collector is injected (flag-off invariance). Hook
        exceptions NEVER break the existing path: the failure is recorded
        on the collector so a ``required`` run stops before the next
        network send (the required-run guard in ``execute``); a non-required
        run simply continues. Events carry no secrets — only vocabulary
        codes and source references.
        """
        collector = self.diagnostic_collector
        if collector is None:
            return
        try:
            collector.emit(
                stage_id=stage_id,
                outcome=outcome,
                reason_codes=tuple(reason_codes or ()),
                source_refs=tuple(source_refs or ()),
                producer_id="vdp_follow_up_executor",
            )
        except Exception as exc:
            collector.mark_hook_failed(f"{type(exc).__name__}: {exc}"[:200])

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def execute(self, spec: Dict[str, Any]) -> FollowUpExecutionResult:
        """Execute one follow-up spec (async; network via injected client)."""
        # 1. kill switch
        if self.kill_switch_provider is not None and self.kill_switch_provider():
            self._diag_emit(
                stage_id="S08", outcome="blocked",
                source_refs=("kill_switch_active",),
            )
            return FollowUpExecutionResult(BLOCKED, "kill_switch_active")

        plan = classify_reason_code(str(spec.get("evidence_gap", "") or ""))

        # 2a. M3b authorization gate (SGK-2026-0423 Lane F / Lane J-2): a
        # state-changing plan requires the spec-level authorization flag AND
        # a HITL ticket that the REAL ledger validator approves. An
        # arbitrary non-empty string is NEVER approval on its own — without
        # a validator (no ledger available) the gate fails closed; with a
        # validator that rejects the ticket the gate stops at
        # hitl_ticket_invalid. Everything else stops at manual review
        # BEFORE any network activity.
        m3b_authorized = bool(spec.get("m3b_authorized"))
        is_state_changing = (
            plan.risk_class == "state_changing"
            or plan.m3a_policy == STATE_CHANGING_POLICY
        )
        if is_state_changing:
            if not m3b_authorized:
                self._diag_emit(
                    stage_id="S07", outcome="blocked",
                    reason_codes=("hitl_missing",),
                    source_refs=("m3b_not_authorized",),
                )
                return FollowUpExecutionResult(MANUAL_REVIEW, "m3b_not_authorized")
            ticket = str(spec.get("hitl_ticket") or "")
            ticket_ok = (
                self.hitl_ticket_validator is not None
                and bool(ticket.strip())
                and self.hitl_ticket_validator(ticket)
            )
            if not ticket_ok:
                if self.hitl_ticket_validator is None:
                    self._diag_emit(
                        stage_id="S07", outcome="blocked",
                        reason_codes=("hitl_missing",),
                        source_refs=("m3b_not_authorized",),
                    )
                    return FollowUpExecutionResult(MANUAL_REVIEW, "m3b_not_authorized")
                self._diag_emit(
                    stage_id="S07", outcome="blocked",
                    reason_codes=("hitl_missing",),
                    source_refs=("hitl_ticket_invalid",),
                )
                return FollowUpExecutionResult(MANUAL_REVIEW, "hitl_ticket_invalid")

        # 2. M3a executability (manual_review / terminal / m3b_gated / oob);
        # the authorized M3b path passes through.
        if not is_follow_up_executable(plan):
            if not (is_state_changing and m3b_authorized):
                self._diag_emit(
                    stage_id="S07", outcome="blocked",
                    source_refs=("not_executable",),
                )
                return FollowUpExecutionResult(
                    MANUAL_REVIEW,
                    f"not_executable_in_m3a:{plan.category}:{plan.m3a_policy}",
                )
        if not (is_state_changing and m3b_authorized) and not is_m3a_executor_supported_gap(
            plan.reason_code
        ):
            self._diag_emit(
                stage_id="S07", outcome="skipped",
                source_refs=(f"unsupported_gap:{plan.reason_code}",),
            )
            return FollowUpExecutionResult(
                MANUAL_REVIEW,
                f"executor_contract_unavailable:{plan.reason_code}",
            )

        # Observation deliberately discards parameter values, request bodies,
        # and credential material.  Exact replay is therefore truthful only
        # for a request that needs none of them; all other shapes remain
        # pending/manual instead of sending a fabricated generic request.
        if plan.reason_code == "payload_request_mismatch" and (
            spec.get("param_names")
            or spec.get("param_locations")
            or spec.get("header_positions")
            or urlparse(str(spec.get("url", "") or "")).query
        ):
            self._diag_emit(
                stage_id="S07", outcome="blocked",
                source_refs=("exact_request_material_unavailable",),
            )
            return FollowUpExecutionResult(
                MANUAL_REVIEW, "exact_request_material_unavailable"
            )

        # 3. Preconditions must be satisfiable (constraint G / plan §3)
        missing = [
            key
            for key in plan.required_preconditions
            if not self.available_preconditions.get(key, False)
        ]
        if missing:
            if "hitl" in missing:
                self._diag_emit(
                    stage_id="S07", outcome="blocked",
                    reason_codes=("hitl_missing",),
                    source_refs=("precondition_missing:hitl",),
                )
            else:
                self._diag_emit(
                    stage_id="S07", outcome="blocked",
                    source_refs=("preconditions_unsatisfied",),
                )
            return FollowUpExecutionResult(
                MANUAL_REVIEW,
                "precondition_missing:" + ",".join(sorted(missing)),
            )

        # 4. Read-only guard on the ACTUAL request (constraint E). The M3b
        # authorized path is the ONLY state-changing exception: the send is
        # authorized by the M3b gate + HITL ticket; every other request
        # stays read-only guarded (method alone is never enough).
        if not (is_state_changing and m3b_authorized):
            readonly = evaluate_readonly_request(
                str(spec.get("method", "GET") or "GET"),
                action_semantics=str(spec.get("action_semantics", "") or ""),
                body=None,
                url=str(spec.get("url", "") or ""),
            )
            if not readonly.allowed:
                self._diag_emit(
                    stage_id="S07", outcome="blocked",
                    source_refs=("readonly_enforce_guard",),
                )
                return FollowUpExecutionResult(
                    MANUAL_REVIEW, f"readonly_guard:{readonly.reason}"
                )

        # 5. Scope revalidation (explicit snapshot, fail-closed)
        url = str(spec.get("url", "") or "")
        scope_result = revalidate_scope_for_request(
            url, scope_definition=self.scope_definition
        )
        if not scope_result.allowed:
            self._diag_emit(
                stage_id="S07", outcome="blocked",
                reason_codes=("scope_block_incorrect",),
                source_refs=(f"scope:{scope_result.verdict}",),
            )
            return FollowUpExecutionResult(
                BLOCKED, f"scope:{scope_result.verdict}"
            )

        method = str(spec.get("method", "GET") or "GET").upper()
        fp = build_request_fingerprint(
            method,
            url,
            tuple(spec.get("param_names", []) or []),
            tuple(spec.get("header_positions", []) or []),
            tuple(spec.get("param_locations", []) or []),
        )
        expected_fp = str(spec.get("expected_request_fingerprint", "") or "")
        if expected_fp and expected_fp != fp:
            self._diag_emit(
                stage_id="S08", outcome="blocked",
                reason_codes=("request_fingerprint_mismatch",),
                source_refs=("request_fingerprint_mismatch",),
            )
            return FollowUpExecutionResult(BLOCKED, "request_fingerprint_mismatch")

        hypothesis = self.hypothesis
        if hypothesis is None:
            hypothesis = HypothesisRecord(
                hypothesis_id=str(spec.get("hypothesis_id", "") or "hyp-unknown"),
                observation_id="obs-followup",
                asset=url,
                capability="follow_up_probe",
                hypothesis_text="follow-up",
                trust_boundary="unauthenticated",
                actors=[str(spec.get("actor", "") or "unauth")],
            )

        # 6. Admission: capability/HITL (no budget consumed here)
        admission = self.gate.evaluate(
            hypothesis,
            scope_verdict=scope_result.verdict,
            capability_matrix=self.capability_matrix,
            budget=None,
        )
        if not admission.admitted:
            self._diag_emit(
                stage_id="S05", outcome="blocked",
                source_refs=("admission_rejected",),
            )
            return FollowUpExecutionResult(
                MANUAL_REVIEW, f"admission:{admission.reason_code}"
            )

        # 7. Attempt record + idempotency (register only after checks pass)
        spec_actor = str(spec.get("actor", "") or "").strip()
        actor = spec_actor or (hypothesis.actors[0] if hypothesis.actors else "unauth")
        attempt_id = build_attempt_id(
            hypothesis.hypothesis_id,
            str(spec.get("evidence_gap", "") or ""),
            actor,
        )
        attempt = AttemptRecord(
            attempt_id=attempt_id,
            hypothesis_id=hypothesis.hypothesis_id,
            actor=actor,
            request_fingerprint=fp,
            scope_verdict=scope_result.verdict,
            budget_snapshot=self.budget.snapshot() if self.budget is not None else {},
            state="queued",
            # SGK-2026-0422 additive: keep the originating NextAction in the
            # Attempt so the ID series NextAction -> Attempt -> Evidence ->
            # Verdict is traceable from the session records.
            trigger_next_action_id=str(spec.get("next_action_id", "") or ""),
        )
        attempt_result = self.gate.admit_attempt(
            attempt,
            hypothesis,
            budget=None,
            idempotency_guard=None,
        )
        if not attempt_result.admitted:
            return FollowUpExecutionResult(
                MANUAL_REVIEW, f"attempt:{attempt_result.reason_code}"
            )
        # SGK-2026-0425: the attempt was admitted (side effect complete).
        self._diag_emit(
            stage_id="S08", outcome="reached",
            source_refs=("admit_attempt",),
        )

        # Reserve the deterministic attempt ID first so concurrent duplicate
        # dispatches cannot both consume budget.  Any later admission failure
        # rolls the provisional registration back.
        if not self.idempotency_guard.register(attempt_id):
            self._diag_emit(
                stage_id="S08", outcome="blocked",
                source_refs=("idempotency_duplicate",),
            )
            return FollowUpExecutionResult(
                MANUAL_REVIEW, "attempt:idempotency_duplicate"
            )

        concurrency_acquired = False
        if self.budget is not None:
            concurrency_acquired = self.budget.acquire_concurrency()
            if not concurrency_acquired:
                self.idempotency_guard.unregister(attempt_id)
                self._diag_emit(
                    stage_id="S08", outcome="blocked",
                    source_refs=("concurrency_limit",),
                )
                return FollowUpExecutionResult(
                    BLOCKED, "concurrency_limit_exceeded"
                )
            budget_decision = self.budget.consume_follow_up_request(
                asset_key=url,
                actor_key=actor,
                hypothesis_key=hypothesis.hypothesis_id,
            )
            if not budget_decision.allowed:
                self.budget.release_concurrency()
                self.idempotency_guard.unregister(attempt_id)
                self._diag_emit(
                    stage_id="S08", outcome="blocked",
                    reason_codes=("queue_backpressure",),
                    source_refs=(f"budget:{budget_decision.reason_code}",),
                )
                return FollowUpExecutionResult(
                    BLOCKED, f"budget:{budget_decision.reason_code}"
                )

        # 8. StateChangeGuard: a state change that was already sent but not
        # confirmed saved must NEVER be re-sent (no auto-resend on resume).
        # The ValueError is caught here so a LOST idempotency checkpoint
        # cannot turn a sent-but-unsaved state change into a second
        # transmission: the attempt is rolled back and the dispatch blocked.
        if self.state_change_guard is not None:
            try:
                self.state_change_guard.prevent_double_send(attempt_id)
            except ValueError:
                if concurrency_acquired and self.budget is not None:
                    self.budget.release_concurrency()
                self.idempotency_guard.unregister(attempt_id)
                self._diag_emit(
                    stage_id="S08", outcome="blocked",
                    source_refs=("double_send_prevented",),
                )
                return FollowUpExecutionResult(
                    BLOCKED, "state_change_already_sent"
                )

        gap = str(spec.get("evidence_gap", "") or "")
        # SGK-2026-0423 Lane P-1: cross-account comparison readiness. The
        # spec carries account IDs ONLY; secrets must resolve from the
        # credential store for BOTH accounts. Without ids or secrets the
        # gap keeps the existing single-request neutral-fact behavior.
        auth_a_id = str(spec.get("auth_a_id", "") or "").strip()
        auth_b_id = str(spec.get("auth_b_id", "") or "").strip()
        comparison_ready = (
            gap in _COMPARISON_GAPS
            and bool(auth_a_id)
            and bool(auth_b_id)
            and auth_a_id in self.account_credentials
            and auth_b_id in self.account_credentials
        )
        # SGK-2026-0425: cross-account comparison readiness evaluated.
        if comparison_ready:
            self._diag_emit(
                stage_id="S09", outcome="reached",
                source_refs=("comparison_ready",),
            )
        request_count = (
            2
            if comparison_ready
            else (
                1
                if is_state_changing
                else (3 if gap in _REPEATED_CONTROL_GAPS else 1)
            )
        )  # comparison = A then B; state changes = SINGLE mutation; A/B/A = read-only controls

        # SGK-2026-0433 timing foundation: the timing gap runs the full
        # baseline / positive-control / negative-control sequence (plus an
        # optional in-scope read-only input variant) instead of the A/B/A
        # triple. Every request goes through the same guards and budget
        # accounting as the other gaps; the optional variant URL is
        # re-guarded (read-only + scope) BEFORE the first network send.
        timing_plan: Optional[List[Dict[str, Any]]] = None
        if gap == "insufficient_timing_validation":
            timing_plan = self._build_timing_plan(spec)
            blocked = self._timing_variant_block_result(spec)
            if blocked is not None:
                return blocked

        # SGK-2026-0425 M1: required-run kill switch — a diagnostic hook
        # failure stops BEFORE the first network send (fail-closed
        # telemetry). The provisional idempotency registration and the
        # concurrency slot are rolled back exactly like the other
        # post-acquisition blocked paths.
        if (
            self.diagnostic_collector is not None
            and self.diagnostic_collector.required
            and self.diagnostic_collector.hook_failed
        ):
            if concurrency_acquired and self.budget is not None:
                self.budget.release_concurrency()
            self.idempotency_guard.unregister(attempt_id)
            return FollowUpExecutionResult(BLOCKED, "diagnostic_telemetry_hook_failure")

        # 9. Send phase: budget consume per request == actual network count
        bodies: List[str] = []
        statuses: List[int] = []
        request_fingerprints: List[str] = []
        comparison_facts: Optional[Dict[str, Any]] = None
        timing_result: Optional[Dict[str, Any]] = None
        timing_transport_failed = False
        try:
            attempt.state = "sending"
            if timing_plan is not None:
                # SGK-2026-0433: timing control sequence (baseline /
                # positive-control / negative-control / optional variant).
                timing_result = await self._run_timing_sequence(
                    timing_plan,
                    actor=actor,
                    hypothesis=hypothesis,
                )
                if timing_result.get("blocked_reason"):
                    return FollowUpExecutionResult(
                        BLOCKED, timing_result["blocked_reason"]
                    )
                bodies = list(timing_result.get("bodies") or [])
                statuses = list(timing_result.get("statuses") or [])
                request_fingerprints = [fp] * len(bodies)
                timing_transport_failed = bool(
                    timing_result.get("transport_failed")
                )
                if timing_transport_failed:
                    attempt.state = "failed"
                    attempt.execution_result = {
                        "status": "dependency_failure",
                        "reason": "network_error",
                        "requests_attempted": int(
                            timing_result.get("requests_attempted", len(bodies))
                        ),
                    }
                    attempt.budget_snapshot = (
                        self.budget.snapshot() if self.budget is not None else {}
                    )
                    # SGK-2026-0433: the transport failure is recorded as a
                    # fact; the honest timing evidence (``<group>_timeout`` /
                    # ``<group>_transport_error:<ExceptionClass>`` reason,
                    # ``timing_measurement_valid`` "false") is still
                    # built and enqueued below — the failure is never
                    # swallowed and the gap stays open.
                    self._diag_emit(
                        stage_id="S08", outcome="failed",
                        reason_codes=("transport_timeout",),
                        source_refs=("network_error",),
                    )
            else:
                for i in range(request_count):
                    # The first request was atomically reserved together with the
                    # follow-up token above.  Any repeated control request must
                    # independently consume budget before transmission.
                    if self.budget is not None and i > 0:
                        decision = self.budget.consume(
                            asset_key=url,
                            actor_key=actor,
                            hypothesis_key=hypothesis.hypothesis_id,
                        )
                        if not decision.allowed:
                            return FollowUpExecutionResult(
                                BLOCKED, f"budget:{decision.reason_code}"
                            )
                    if comparison_ready:
                        # authenticated GET for the i-th account (A then B)
                        body, status = await self._send_with_auth(
                            method, url, (auth_a_id, auth_b_id)[i]
                        )
                    else:
                        body, status = await self._send_read_request(method, url)
                    if body is None:
                        attempt.state = "failed"
                        attempt.execution_result = {
                            "status": "dependency_failure",
                            "reason": "network_error",
                            "requests_attempted": i + 1,
                        }
                        attempt.budget_snapshot = (
                            self.budget.snapshot() if self.budget is not None else {}
                        )
                        # SGK-2026-0425: transport failure recorded as a fact
                        # after the attempt state was persisted.
                        self._diag_emit(
                            stage_id="S08", outcome="failed",
                            reason_codes=("transport_timeout",),
                            source_refs=("network_error",),
                        )
                        return FollowUpExecutionResult(
                            DEGRADED,
                            "network_error",
                            attempt_id=attempt_id,
                            requests_made=i + 1,
                            budget_snapshot=dict(attempt.budget_snapshot),
                            attempt=attempt.to_dict(),
                        )
                    bodies.append(body)
                    statuses.append(status)
                    request_fingerprints.append(fp)
                if comparison_ready:
                    # Truthful observation: evaluate the A/B comparison AFTER
                    # both authenticated responses were received.
                    comparison_facts = self._evaluate_cross_account_comparison(
                        bodies, statuses
                    )
            if not timing_transport_failed:
                attempt.state = "sent"
            # M3b production send boundary (SGK-2026-0423 Lane F): persist
            # the sent fact in the StateChangeGuard IMMEDIATELY after the
            # send loop completes, BEFORE evidence build/writer — the
            # no-auto-resend property holds even when the session/checkpoint
            # save fails afterwards. The network-error path (body None)
            # returned above and never reaches this point, so a failed
            # transmission is never marked sent.
            if (
                is_state_changing
                and m3b_authorized
                and self.state_change_guard is not None
            ):
                self.state_change_guard.mark_sent(attempt_id)
            # SGK-2026-0425: the send loop completed (side effect done).
            self._diag_emit(
                stage_id="S08", outcome="reached",
                source_refs=("send_completed",),
            )
        finally:
            if concurrency_acquired and self.budget is not None:
                self.budget.release_concurrency()

        # 10. Evidence record (raw hash + redacted excerpt + truncation)
        # SGK-2026-0422 (audit I-07): the executor records NEUTRAL facts
        # only — response received, HTTP status, request count. It NEVER
        # asserts the hypothesis success condition; the canonical Evidence
        # Validator judges privilege-difference / state-change / account
        # comparison proofs from structured results instead.
        raw_body = "\n".join(bodies)
        raw_hash = "sha256:" + hashlib.sha256(raw_body.encode("utf-8")).hexdigest()
        truncated = truncate_evidence_body(raw_body, max_bytes=64 * 1024)
        # The M3b path records NEUTRAL facts + the sent fact only
        # (state_change_sent). It NEVER records the canonical validator's
        # ``state_change_verified`` success marker — proof of the state
        # change itself is judged by the validator from structured results.
        # The Lane P-1 comparison path records the TRUTHFUL cross-account
        # facts + markers (owner attribution / comparison completed).
        if comparison_facts is not None:
            execution_result = dict(comparison_facts)
        elif timing_result is not None:
            execution_result = dict(timing_result["execution_result"])
        elif (is_state_changing and m3b_authorized):
            execution_result = {
                "state_change_sent": True,
                "response_received": True,
                "http_status": statuses[-1] if statuses else 0,
                "request_count": 1,
            }
        else:
            execution_result = {
                "response_received": True,
                "http_status": statuses[-1] if statuses else 0,
                "request_count": len(bodies),
            }
        evidence = EvidenceRecordV1(
            evidence_id=deterministic_id(
                "ev",
                {"attempt_id": attempt_id, "evidence_type": self._evidence_type(gap)},
            ),
            attempt_id=attempt_id,
            evidence_type=self._evidence_type(gap),
            raw_hash=raw_hash,
            redacted_excerpt=_redact_body_text(truncated["truncated_body"]),
            normalization_rule_version="v1",
            auth_context_version="none",  # 0421: no credential material
            captured_at="",
            original_size=truncated["original_size"],
            truncated=truncated["truncated"],
            truncation_reason=truncated.get("truncation_reason", ""),
            execution_result=execution_result,
        )
        # SGK-2026-0425: neutral-fact evidence record built (side effect done).
        self._diag_emit(
            stage_id="S10", outcome="reached",
            source_refs=("evidence_built",),
        )
        if not timing_transport_failed:
            attempt.state = "evidence_saved"
        try:
            if self.evidence_writer is not None:
                await self.evidence_writer.enqueue_evidence(evidence.to_dict())
        except Exception:
            # Backpressure or writer failure must NOT silently discard:
            # report degraded; the evidence dict is still returned for the
            # caller to checkpoint. The HTTP send already happened and
            # mark_sent was already called — the send fact must survive.
            self._diag_emit(
                stage_id="S10", outcome="blocked",
                reason_codes=("queue_backpressure",),
                source_refs=("evidence_write_backpressure",),
            )
            return FollowUpExecutionResult(
                DEGRADED,
                "evidence_write_backpressure",
                attempt_id=attempt_id,
                evidence_id=evidence.evidence_id,
                requests_made=len(bodies),
                verdict_status="candidate",
                budget_snapshot=self.budget.snapshot() if self.budget is not None else {},
                attempt=attempt.to_dict(),
                evidence=evidence.to_dict(),
                state_change_sent=(is_state_changing and m3b_authorized),
            )

        if timing_transport_failed:
            # SGK-2026-0433: transport failure stays DEGRADED (same as the
            # A/B/A path) but the honest timing evidence record is attached
            # (``timing_measurement_valid`` "false" + the explicit timeout /
            # transport-error reason); the failure is recorded, never
            # swallowed.
            return FollowUpExecutionResult(
                DEGRADED,
                "network_error",
                attempt_id=attempt_id,
                evidence_id=evidence.evidence_id,
                requests_made=int(
                    timing_result.get("requests_attempted", len(bodies))
                    if timing_result is not None
                    else len(bodies)
                ),
                verdict_status="candidate",  # never confirmed in 0421
                budget_snapshot=self.budget.snapshot() if self.budget is not None else {},
                attempt=attempt.to_dict(),
                evidence=evidence.to_dict(),
                state_change_sent=False,
            )
        return FollowUpExecutionResult(
            EXECUTED,
            "executed",
            attempt_id=attempt_id,
            evidence_id=evidence.evidence_id,
            requests_made=len(bodies),
            verdict_status="candidate",  # never confirmed in 0421
            budget_snapshot=self.budget.snapshot() if self.budget is not None else {},
            attempt=attempt.to_dict(),
            evidence=evidence.to_dict(),
            state_change_sent=(is_state_changing and m3b_authorized),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evidence_type(self, gap: str) -> str:
        if gap in _REPEATED_CONTROL_GAPS:
            return "timing_measurement"
        return "real_http_response"

    async def _send_read_request(
        self,
        method: str,
        url: str,
        *,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[Optional[str], int]:
        """Send ONE admitted request with hidden communication disabled.

        Constraint D: use_cache=False, retries=0, auto_waf_bypass=False,
        allow_redirects=False, explicit timeout. Redirects are recorded but
        never followed — a hop would need its own scope+budget re-evaluation.

        The method is parameterized and this helper is reused for the M3b
        mutation send (the name is historical). For the M3b path the send is
        authorized by the executor's M3b authorization gate + the HITL
        ticket recorded in the spec — this helper performs no additional
        admission. ``extra_headers`` (Lane P-1) is attached to the request
        when given (the cross-account Authorization header); the default
        call shape is unchanged for all existing callers.

        Returns ``(body, http_status)``; ``body`` is None on transport
        failure (status 0). The status is a NEUTRAL fact about the response
        — the executor never asserts success conditions (audit I-07).
        """
        if self.network_client is None:
            return None, 0
        try:
            self._last_transport_error_type = ""
            request_kwargs: Dict[str, Any] = dict(
                use_cache=False,
                retries=0,
                auto_waf_bypass=False,
                allow_redirects=False,
                timeout=int(self.timeout),
                use_proxy=True,
            )
            if extra_headers:
                request_kwargs["headers"] = dict(extra_headers)
            resp = await self.network_client.request(method, url, **request_kwargs)
            status = int(getattr(resp, "status", 0) or 0)
            if self.budget is not None:
                latency = float(getattr(resp, "elapsed", 0.0) or 0.0) * 1000.0
                self.budget.record_response(url, status, latency_ms=latency)
            body = getattr(resp, "body", "") or ""
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")
            return str(body), status
        except Exception as exc:
            # SGK-2026-0433 followup: keep the exception class name so the
            # timing sequence can label the honest failure reason (a
            # connection-refused/DNS/TLS error is NOT a timeout).
            self._last_transport_error_type = type(exc).__name__
            if self.budget is not None:
                self.budget.record_timeout(url)
            return None, 0

    async def _send_with_auth(
        self, method: str, url: str, account_id: str
    ) -> Tuple[Optional[str], int]:
        """Send ONE authenticated GET for the given account (Lane P-1).

        The secret resolves from ``self.account_credentials`` at send time
        (the spec carries the account ID only) and is attached as an
        ``Authorization`` header passed solely to the network client — it
        is never logged, stored in the attempt/evidence, or returned.
        """
        secret = str(self.account_credentials.get(str(account_id or ""), "") or "")
        if not secret:
            return None, 0
        return await self._send_read_request(
            method,
            url,
            extra_headers={"Authorization": f"Bearer {secret}"},
        )

    def _evaluate_cross_account_comparison(
        self, bodies: List[str], statuses: List[int]
    ) -> Dict[str, Any]:
        """Evaluate the A/B comparison into TRUTHFUL structured facts +
        markers (SGK-2026-0423 Lane P-1).

        Marker truth-table (observation-driven, never gap-driven):
        - ``authz_impact_proven`` / ``semantic_diff_observed``: ONLY when
          the B (non-owner) response is 200 AND the A response is a JSON
          object carrying the generic ``owner`` key AND the normalized
          (key-sort only) B body equals the normalized A body — the
          non-owner received the owner's record — AND the shared record
          carries fields beyond ``owner``/``id`` (generic sensitive-field
          signal). ``owner`` is a generic JSON field name (owner-
          attribution signal), never a route/holdout secret; no URL or
          route is hardcoded.
        - ``second_account_compared``: whenever the comparison completed
          (both requests returned; B got 200 or 403).
        - Never set on: public endpoints (no owner key), denied (403/401)
          non-owner access, transport failures, or when the comparison did
          not run.
        """
        a_body = bodies[0] if bodies else ""
        b_body = bodies[1] if len(bodies) > 1 else ""
        a_status = statuses[0] if statuses else 0
        b_status = statuses[1] if len(statuses) > 1 else 0
        facts: Dict[str, Any] = {
            "cross_account_compared": True,
            "account_a_status": a_status,
            "account_b_status": b_status,
            "owner_record_accessible_to_non_owner": False,
            "sensitive_fields_shared_with_non_owner": False,
            "request_count": 2,
        }
        granted = self._owner_record_granted(a_body, b_body, b_status)
        facts["owner_record_accessible_to_non_owner"] = granted
        sensitive_shared = granted and bool(self._shared_sensitive_fields(a_body))
        facts["sensitive_fields_shared_with_non_owner"] = sensitive_shared
        if granted and sensitive_shared:
            facts["authz_impact_proven"] = "true"
            facts["semantic_diff_observed"] = "true"
        if a_status > 0 and b_status in (200, 403):
            facts["second_account_compared"] = "true"
        return facts

    # ------------------------------------------------------------------
    # SGK-2026-0433 timing foundation (read-only, GET-only)
    # ------------------------------------------------------------------

    def _build_timing_plan(self, spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build the timing control sequence for the timing gap.

        All requests are read-only GETs (``_TIMING_METHOD``). Baseline /
        positive-control / negative-control target the spec URL; the
        positive control adds a short CLIENT-SIDE sleep inside the measured
        wall-clock window (calibration only — it never drives
        ``timing_difference_observed``). When the spec carries an optional
        in-scope ``timing_variant_url``, a variant group samples that URL —
        the only real read-only condition delta the executor can observe
        (parameter values are deliberately discarded elsewhere). The account
        A session is used when ``auth_a_id`` resolves from the credential
        store, else anonymous.
        """
        url = str(spec.get("url", "") or "")
        auth_a_id = str(spec.get("auth_a_id", "") or "").strip()
        auth_a_id = auth_a_id if auth_a_id in self.account_credentials else ""
        variant_url = str(spec.get("timing_variant_url", "") or "").strip()
        plan: List[Dict[str, Any]] = []
        for _ in range(_TIMING_BASELINE_SAMPLES):
            plan.append({
                "group": "baseline", "url": url,
                "sleep_seconds": 0.0, "auth_id": auth_a_id,
            })
        for _ in range(_TIMING_POSITIVE_SAMPLES):
            plan.append({
                "group": "positive", "url": url,
                "sleep_seconds": _TIMING_POSITIVE_CONTROL_SLEEP_SECONDS,
                "auth_id": auth_a_id,
            })
        for _ in range(_TIMING_NEGATIVE_SAMPLES):
            plan.append({
                "group": "negative", "url": url,
                "sleep_seconds": 0.0, "auth_id": auth_a_id,
            })
        if variant_url:
            for _ in range(_TIMING_VARIANT_SAMPLES):
                plan.append({
                    "group": "variant", "url": variant_url,
                    "sleep_seconds": 0.0, "auth_id": auth_a_id,
                })
        return plan

    def _timing_variant_block_result(
        self, spec: Dict[str, Any]
    ) -> Optional[FollowUpExecutionResult]:
        """Fail-closed guard checks for the optional timing variant URL.

        The variant is a read-only GET only: it must pass the read-only
        guard (state-changing semantics rejected) and scope revalidation
        (explicit snapshot, same as the main request). Any violation blocks
        BEFORE the first network send.
        """
        variant_url = str(spec.get("timing_variant_url", "") or "").strip()
        if not variant_url:
            return None
        readonly = evaluate_readonly_request(
            _TIMING_METHOD,
            action_semantics="",
            body=None,
            url=variant_url,
        )
        if not readonly.allowed:
            self._diag_emit(
                stage_id="S07", outcome="blocked",
                source_refs=("readonly_enforce_guard",),
            )
            return FollowUpExecutionResult(
                MANUAL_REVIEW, f"readonly_guard:{readonly.reason}"
            )
        scope_result = revalidate_scope_for_request(
            variant_url, scope_definition=self.scope_definition
        )
        if not scope_result.allowed:
            self._diag_emit(
                stage_id="S07", outcome="blocked",
                reason_codes=("scope_block_incorrect",),
                source_refs=(f"scope:{scope_result.verdict}",),
            )
            return FollowUpExecutionResult(BLOCKED, f"scope:{scope_result.verdict}")
        return None

    async def _run_timing_sequence(
        self,
        plan: List[Dict[str, Any]],
        *,
        actor: str,
        hypothesis: HypothesisRecord,
    ) -> Dict[str, Any]:
        """Run the timing control sequence and build the honest timing result.

        Budget accounting mirrors the A/B/A path exactly: the first request
        was atomically reserved by ``consume_follow_up_request``; every
        subsequent request consumes budget independently before transmission.
        Every response is recorded via ``budget.record_response`` inside the
        shared send helper (the existing send pattern).

        Latency for the record is measured as wall-clock around the whole
        step (including the client-side control sleep for positive controls;
        the record labels that explicitly). Failures are NEVER swallowed: a
        non-2xx or transport failure stops the sequence and is recorded as
        ``failed_requests`` plus an explicit ``reason`` —
        ``<group>_failed_status_<status>`` for non-2xx, ``<group>_timeout``
        for TimeoutError/asyncio timeouts, and
        ``<group>_transport_error:<ExceptionClass>`` for other transport
        exceptions (connection-refused/DNS/TLS are never labeled as
        timeouts) — with ``timing_measurement_valid`` "false", keeping the
        gap open.
        """
        samples: Dict[str, List[float]] = {
            "baseline": [], "positive": [], "negative": [], "variant": [],
        }
        bodies: List[str] = []
        statuses: List[int] = []
        failed_requests: List[Dict[str, Any]] = []
        failure_reason = ""
        transport_failed = False
        variant_present = any(
            str(step.get("group") or "") == "variant" for step in plan
        )
        for i, step in enumerate(plan):
            step_url = str(step.get("url") or "")
            if self.budget is not None and i > 0:
                decision = self.budget.consume(
                    asset_key=step_url,
                    actor_key=actor,
                    hypothesis_key=hypothesis.hypothesis_id,
                )
                if not decision.allowed:
                    return {"blocked_reason": f"budget:{decision.reason_code}"}
            group = str(step.get("group") or "baseline")
            sleep_seconds = float(step.get("sleep_seconds") or 0.0)
            auth_id = str(step.get("auth_id") or "")
            t0 = time.monotonic()
            if sleep_seconds > 0.0:
                await asyncio.sleep(sleep_seconds)
            if auth_id:
                body, status = await self._send_with_auth(
                    _TIMING_METHOD, step_url, auth_id
                )
            else:
                body, status = await self._send_read_request(
                    _TIMING_METHOD, step_url
                )
            latency_ms = (time.monotonic() - t0) * 1000.0
            if body is None:
                transport_failed = True
                error_type = str(
                    getattr(self, "_last_transport_error_type", "") or ""
                )
                if error_type in ("", "TimeoutError"):
                    # actual TimeoutError / asyncio timeout (or unknown):
                    # keep the existing ``<group>_timeout`` label
                    failure_reason = f"{group}_timeout"
                    failed_requests.append(
                        {"group": group, "status": 0, "timeout": True}
                    )
                else:
                    # connection-refused / DNS / TLS / ... — record the
                    # exception class name honestly (never a fake timeout)
                    failure_reason = f"{group}_transport_error:{error_type}"
                    failed_requests.append(
                        {
                            "group": group,
                            "status": 0,
                            "timeout": False,
                            "error": error_type,
                        }
                    )
                break
            bodies.append(body)
            statuses.append(status)
            if 200 <= status < 300:
                samples[group].append(latency_ms)
            else:
                failure_reason = f"{group}_failed_status_{status}"
                failed_requests.append(
                    {"group": group, "status": status, "timeout": False}
                )
                break
        execution_result = self._build_timing_execution_result(
            samples=samples,
            statuses=statuses,
            failed_requests=failed_requests,
            failure_reason=failure_reason,
            variant_present=variant_present,
        )
        return {
            "blocked_reason": "",
            "bodies": bodies,
            "statuses": statuses,
            "execution_result": execution_result,
            "transport_failed": transport_failed,
            "requests_attempted": len(bodies) + len(failed_requests),
        }

    def _build_timing_execution_result(
        self,
        *,
        samples: Dict[str, List[float]],
        statuses: List[int],
        failed_requests: List[Dict[str, Any]],
        failure_reason: str,
        variant_present: bool,
    ) -> Dict[str, Any]:
        """Compute medians + the honest marker vocabulary for the record.

        - ``timing_measurement_valid`` "true" only when the calibration
          offset (median(positive) - median(baseline)) is at least the
          detection threshold (100ms or 50% of the inserted client-side
          delay, whichever is smaller); otherwise "false" with
          ``timing_pipeline_insensitive``.
        - ``timing_difference_observed`` "true" ONLY for a REAL read-only
          condition delta: the optional variant group's median differs from
          baseline beyond jitter (delta >= max(3x baseline MAD, 50ms) with
          non-overlapping [Q1, Q3] intervals). Without a variant condition
          the honest default is "false" with
          ``no_alternate_condition_in_readonly_scope``.
        - Any group failure (non-2xx or transport) → "false" with the
          explicit failure reason; the gap stays open.
        """
        baseline = list(samples.get("baseline") or [])
        positive = list(samples.get("positive") or [])
        negative = list(samples.get("negative") or [])
        variant = list(samples.get("variant") or [])
        base_median = _timing_median_or_zero(baseline)
        pos_median = _timing_median_or_zero(positive)
        neg_median = _timing_median_or_zero(negative)
        var_median = _timing_median_or_zero(variant) if variant else None
        medians: Dict[str, float] = {
            "baseline": base_median,
            "positive": pos_median,
            "negative": neg_median,
        }
        if var_median is not None:
            medians["variant"] = var_median

        valid = "true"
        observed = "false"
        reason = ""
        if failure_reason:
            valid = "false"
            reason = failure_reason
        else:
            inserted_delay_ms = _TIMING_POSITIVE_CONTROL_SLEEP_SECONDS * 1000.0
            detection_threshold = min(
                _TIMING_DETECTION_THRESHOLD_MS, inserted_delay_ms * 0.5
            )
            calibration_delta = pos_median - base_median
            if calibration_delta < detection_threshold:
                valid = "false"
                reason = _TIMING_REASON_INSENSITIVE
            elif not variant_present:
                reason = _TIMING_REASON_NO_VARIANT
            else:
                observed, reason = self._evaluate_timing_variant_delta(
                    baseline, variant, base_median
                )

        execution_result: Dict[str, Any] = {
            "timing_baseline_samples": baseline,
            "timing_positive_samples": positive,
            "timing_negative_control_samples": negative,
            "positive_control_samples": positive,
            "negative_control_samples": negative,
            "medians": medians,
            "timing_baseline_median": base_median,
            "timing_positive_median": pos_median,
            "timing_negative_control_median": neg_median,
            "timing_measurement_valid": valid,
            "timing_difference_observed": observed,
            "reason": reason,
            "positive_control_is_client_side": True,
            "positive_control_client_side_sleep_ms": round(
                _TIMING_POSITIVE_CONTROL_SLEEP_SECONDS * 1000.0, 3
            ),
            "positive_control_latency_includes_client_sleep": True,
            "timing_method": _TIMING_METHOD,
            "timing_variant_condition_present": bool(variant_present),
            "response_received": True,
            "http_status": statuses[-1] if statuses else 0,
            # SGK-2026-0433 followup: each request is counted exactly once.
            # A failed-status response is in ``statuses`` (received) and its
            # failure detail lives in ``failed_requests`` (informational) —
            # never summed together.
            "request_count": len(statuses),
            "failed_requests": failed_requests,
        }
        if var_median is not None:
            execution_result["timing_variant_median"] = var_median
        return execution_result

    @staticmethod
    def _evaluate_timing_variant_delta(
        baseline: List[float],
        variant: List[float],
        base_median: float,
    ) -> Tuple[str, str]:
        """Delta-vs-jitter check for the real read-only variant condition.

        Observed "true" only when the variant median differs from the
        baseline median beyond jitter: absolute delta >= 50ms AND >= 3x the
        baseline median absolute deviation, with non-overlapping [Q1, Q3]
        intervals. Returns (marker, reason).
        """
        var_median = statistics.median(variant)
        delta = abs(var_median - base_median)
        mad = (
            statistics.median([abs(sample - base_median) for sample in baseline])
            if baseline
            else 0.0
        )
        if delta < max(_TIMING_JITTER_MULTIPLIER * mad, _TIMING_MIN_DELTA_MS):
            return "false", _TIMING_REASON_NO_DELTA
        base_q1, base_q3 = _quantile_bounds(baseline)
        var_q1, var_q3 = _quantile_bounds(variant)
        if not (var_q1 > base_q3 or var_q3 < base_q1):
            return "false", _TIMING_REASON_NO_DELTA
        return "true", _TIMING_REASON_DELTA

    @staticmethod
    def _owner_record_granted(a_body: str, b_body: str, b_status: int) -> bool:
        """Generic owner-attribution grant signal: B (non-owner) received
        the owner's record — B is 200, A's response is a JSON object with
        an ``owner`` key, and the key-sorted normalized bodies are equal
        (the fixture's records are static synthetic data; normalization is
        key-sort only). ``owner`` is a generic JSON field name, not a
        route/holdout secret."""
        if b_status != 200:
            return False
        try:
            a_parsed = json.loads(a_body)
            b_parsed = json.loads(b_body)
        except (ValueError, TypeError):
            return False
        if not isinstance(a_parsed, dict) or not isinstance(b_parsed, dict):
            return False
        if "owner" not in a_parsed:
            return False
        return json.dumps(a_parsed, sort_keys=True) == json.dumps(
            b_parsed, sort_keys=True
        )

    @staticmethod
    def _shared_sensitive_fields(a_body: str) -> set:
        """Generic sensitive-field signal: the owner record's keys beyond
        ``owner``/``id``. ``owner`` and ``id`` are generic JSON field names
        of the fixture's record schema — the ``owner`` key is an owner-
        attribution signal, never a route/holdout secret, and no URL or
        route is hardcoded."""
        try:
            parsed = json.loads(a_body or "")
        except (ValueError, TypeError):
            return set()
        if not isinstance(parsed, dict):
            return set()
        return set(parsed.keys()) - {"owner", "id"}
