"""
SGK-2026-0425 M1 part 2: diagnostic telemetry hooks in VdpFollowUpExecutor.

- collector=None (default) → bit-identical existing behavior, no events.
- collector enabled → S05/S07/S08/S09/S10 events on the instrumented
  early-return paths with vocabulary-valid reason codes and secret-free
  source_refs.
- required=True + hook_failed → execute() returns blocked
  'diagnostic_telemetry_hook_failure' BEFORE any network send.

Events carry NO secrets: only stage/outcome/reason_codes/source_refs are
recorded (no URLs, no bodies, no credentials).
"""
from __future__ import annotations

from src.core.engine.vdp_budget import VdpExecutionBudget
from src.core.engine.vdp_diagnostic_trace import DiagnosticCollector
from src.core.engine.vdp_follow_up_executor import (
    BLOCKED,
    EXECUTED,
    MANUAL_REVIEW,
    VdpFollowUpExecutor,
    build_attempt_id,
)
from src.core.models.vdp_contract import (
    CapabilityLevel,
    IdempotencyGuard,
    ProgramCapabilityMatrix,
    StateChangeGuard,
)

from tests.unit.engine.test_vdp_follow_up_resilience import (
    _Net,
    _Resp,
    _W,
    _run,
    _scope,
    _spec,
)


def _collector(**kwargs) -> DiagnosticCollector:
    kwargs.setdefault("enabled", True)
    kwargs.setdefault("run_id", "test")
    return DiagnosticCollector(**kwargs)


def _ex(**kw):
    """Executor builder like ``resilience._ex`` but with the diagnostic
    collector + m3b preconditions supported (all other kwargs pass through)."""
    collector = kw.pop("diagnostic_collector", None)
    net = kw.pop("network_client", None) or _Net()
    budget = kw.pop("budget", None) or VdpExecutionBudget(
        max_requests=100, per_asset_burst=100, per_hypothesis_burst=100
    )
    writer = kw.pop("evidence_writer", None) or _W()
    idem = kw.pop("idem", None) or IdempotencyGuard()
    scg = kw.pop("scg", None) or StateChangeGuard()
    matrix = kw.pop("matrix", None) or ProgramCapabilityMatrix(
        rules={"follow_up_probe": CapabilityLevel.ALLOWED}
    )
    preconditions = kw.pop("available_preconditions", None)
    if preconditions is None:
        preconditions = {
            "scope": True, "budget": True, "request_budget": True,
            "action_permission": True, "protected_resource": True,
            "state_change_permission": True, "hitl": True,
        }
    ex = VdpFollowUpExecutor(
        scope_definition=_scope(),
        capability_matrix=matrix,
        budget=budget,
        network_client=net,
        evidence_writer=writer,
        idempotency_guard=idem,
        state_change_guard=scg,
        available_preconditions=preconditions,
        diagnostic_collector=collector,
        **kw,
    )
    return ex, net, writer, budget


def _m3b_spec(**overrides) -> dict:
    """An authorized state-changing spec (POST mutation, Lane F)."""
    spec = _spec(
        gap="state_change_not_verified",
        risk_class="state_changing",
        method="POST",
        m3b_authorized=True,
        hitl_ticket="T-1",
    )
    spec.update(overrides)
    return spec


class _FailingNet:
    """Transport that fails the first N requests (body None path)."""

    def __init__(self, fail_times: int = 1):
        self.fail_times = fail_times
        self.failures = 0
        self.calls: list = []

    async def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.failures < self.fail_times:
            self.failures += 1
            raise TimeoutError("simulated timeout")
        return _Resp(200, "ok")


class _FailingWriter:
    def __init__(self):
        self.evidence: list = []

    async def enqueue_evidence(self, evidence: dict):
        raise RuntimeError("queue full")


class _ExplodingNet:
    """Network that must NEVER be reached (asserts when invoked)."""

    def __init__(self):
        self.calls: list = []

    async def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("network must never be called")


# ---------------------------------------------------------------------------
# Event helpers
# ---------------------------------------------------------------------------


def _events(collector: DiagnosticCollector) -> list:
    section = collector.to_section()
    assert section is not None, "collector disabled?"
    return section["events"]


def _find(collector, stage_id: str, outcome: str, source_ref=None):
    for ev in _events(collector):
        if ev["stage_id"] == stage_id and ev["outcome"] == outcome:
            if source_ref is None or source_ref in ev["source_refs"]:
                return ev
    return None


def _assert_event(collector, stage_id, outcome, *, reason_codes=None, source_refs=None):
    ref = source_refs[0] if source_refs else None
    ev = _find(collector, stage_id, outcome, ref)
    assert ev is not None, (
        f"expected event {stage_id}/{outcome} {source_refs!r}; got {_events(collector)}"
    )
    if reason_codes is not None:
        assert ev["reason_codes"] == list(reason_codes), ev
    if source_refs is not None:
        assert ev["source_refs"] == list(source_refs), ev
    return ev


class TestNoneCollectorNoOp:
    """(a) collector=None → no events, existing result shapes unchanged."""

    def test_none_collector_executed_path_unchanged(self):
        (ex, net, writer, _b) = _ex(diagnostic_collector=None)
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        assert result.attempt_id != ""
        assert result.evidence_id != ""
        assert result.requests_made == 1
        assert len(net.calls) == 1
        assert len(writer.evidence) == 1
        assert result.verdict_status == "candidate"

    def test_none_collector_blocked_path_unchanged(self):
        (ex, _n, _w, _b) = _ex(diagnostic_collector=None, kill_switch_provider=lambda: True)
        result = _run(ex.execute(_spec()))
        assert result.status == BLOCKED
        assert result.reason == "kill_switch_active"


class TestEarlyReturnHooks:
    """(b) with collector: early-return paths emit the mapped events."""

    def test_kill_switch_emits_s08_blocked(self):
        col = _collector()
        (ex, net, _w, _b) = _ex(diagnostic_collector=col, kill_switch_provider=lambda: True)
        result = _run(ex.execute(_spec()))
        assert result.status == BLOCKED
        assert result.reason == "kill_switch_active"
        assert net.count == 0
        _assert_event(col, "S08", "blocked", source_refs=["kill_switch_active"])

    def test_m3b_unauthorized_emits_s07_hitl_missing(self):
        col = _collector()
        (ex, net, _w, _b) = _ex(diagnostic_collector=col)
        spec = _spec(gap="state_change_not_verified", risk_class="state_changing", method="POST")
        result = _run(ex.execute(spec))
        assert result.status == MANUAL_REVIEW
        assert result.reason == "m3b_not_authorized"
        assert net.count == 0
        _assert_event(col, "S07", "blocked", reason_codes=["hitl_missing"], source_refs=["m3b_not_authorized"])

    def test_m3b_invalid_ticket_emits_s07_hitl_missing(self):
        col = _collector()
        (ex, net, _w, _b) = _ex(
            diagnostic_collector=col,
            hitl_ticket_validator=lambda t: t == "T-1",
        )
        spec = _m3b_spec(hitl_ticket="wrong-ticket")
        result = _run(ex.execute(spec))
        assert result.status == MANUAL_REVIEW
        assert result.reason == "hitl_ticket_invalid"
        assert net.count == 0
        _assert_event(col, "S07", "blocked", reason_codes=["hitl_missing"], source_refs=["hitl_ticket_invalid"])

    def test_not_executable_emits_s07_blocked(self):
        col = _collector()
        (ex, net, _w, _b) = _ex(diagnostic_collector=col)
        result = _run(ex.execute(_spec(gap="unknown_reason_code")))
        assert result.status == MANUAL_REVIEW
        assert "not_executable_in_m3a" in result.reason
        assert net.count == 0
        _assert_event(col, "S07", "blocked", source_refs=["not_executable"])

    def test_unsupported_gap_emits_s07_skipped(self):
        col = _collector()
        (ex, net, _w, _b) = _ex(diagnostic_collector=col)
        # SGK-2026-0433: insufficient_timing_validation is now M3a-executable;
        # weak-session stays a still-unsupported repeated-control gap.
        result = _run(ex.execute(_spec(gap="weak_session_not_statistically_verified")))
        assert result.status == MANUAL_REVIEW
        assert result.reason == "executor_contract_unavailable:weak_session_not_statistically_verified"
        assert net.count == 0
        _assert_event(
            col,
            "S07",
            "skipped",
            source_refs=["unsupported_gap:weak_session_not_statistically_verified"],
        )

    def test_exact_request_material_unavailable_emits_s07_blocked(self):
        col = _collector()
        (ex, net, _w, _b) = _ex(diagnostic_collector=col)
        result = _run(ex.execute(_spec(param_names=["id"], param_locations=["query"])))
        assert result.status == MANUAL_REVIEW
        assert result.reason == "exact_request_material_unavailable"
        assert net.count == 0
        _assert_event(col, "S07", "blocked", source_refs=["exact_request_material_unavailable"])

    def test_preconditions_unsatisfied_emits_s07_blocked(self):
        col = _collector()
        (ex, net, _w, _b) = _ex(diagnostic_collector=col, available_preconditions={})
        result = _run(ex.execute(_spec()))
        assert result.status == MANUAL_REVIEW
        assert "precondition_missing" in result.reason
        assert net.count == 0
        _assert_event(col, "S07", "blocked", source_refs=["preconditions_unsatisfied"])

    def test_hitl_missing_precondition_emits_s07_hitl_missing(self):
        col = _collector()
        (ex, net, _w, _b) = _ex(
            diagnostic_collector=col,
            hitl_ticket_validator=lambda t: t == "T-1",
            available_preconditions={"state_change_permission": True},
        )
        result = _run(ex.execute(_m3b_spec()))
        assert result.status == MANUAL_REVIEW
        assert result.reason == "precondition_missing:hitl"
        assert net.count == 0
        _assert_event(col, "S07", "blocked", reason_codes=["hitl_missing"], source_refs=["precondition_missing:hitl"])

    def test_readonly_guard_emits_s07_blocked(self):
        col = _collector()
        (ex, net, _w, _b) = _ex(diagnostic_collector=col)
        result = _run(ex.execute(_spec(method="POST")))
        assert result.status == MANUAL_REVIEW
        assert "readonly_guard" in result.reason
        assert net.count == 0
        _assert_event(col, "S07", "blocked", source_refs=["readonly_enforce_guard"])

    def test_scope_block_emits_s07_blocked(self):
        col = _collector()
        (ex, net, _w, _b) = _ex(diagnostic_collector=col)
        result = _run(ex.execute(_spec(url="https://outside.example.com/x")))
        assert result.status == BLOCKED
        assert result.reason.startswith("scope:")
        assert net.count == 0
        _assert_event(col, "S07", "blocked", reason_codes=["scope_block_incorrect"])

    def test_fingerprint_mismatch_emits_s08_blocked(self):
        expected = __import__(
            "src.core.engine.vdp_follow_up_executor", fromlist=["build_request_fingerprint"]
        ).build_request_fingerprint("GET", "https://api.example.com/items", ())
        col = _collector()
        (ex, net, _w, _b) = _ex(diagnostic_collector=col)
        result = _run(ex.execute(_spec(method="HEAD", expected_request_fingerprint=expected)))
        assert result.status == BLOCKED
        assert result.reason == "request_fingerprint_mismatch"
        assert net.count == 0
        _assert_event(
            col, "S08", "blocked",
            reason_codes=["request_fingerprint_mismatch"],
            source_refs=["request_fingerprint_mismatch"],
        )

    def test_admission_rejected_emits_s05_blocked(self):
        col = _collector()
        (ex, net, _w, _b) = _ex(
            diagnostic_collector=col,
            matrix=ProgramCapabilityMatrix(
                rules={"follow_up_probe": CapabilityLevel.PROHIBITED}
            ),
        )
        result = _run(ex.execute(_spec()))
        assert result.status == MANUAL_REVIEW
        assert result.reason.startswith("admission:")
        assert net.count == 0
        _assert_event(col, "S05", "blocked", source_refs=["admission_rejected"])


class TestSendPathHooks:
    """(b) with collector: send-path events (facts after side effects)."""

    def test_executed_path_emits_s08_and_s10(self):
        col = _collector()
        (ex, net, _w, _b) = _ex(diagnostic_collector=col)
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        assert len(net.calls) == 1
        _assert_event(col, "S08", "reached", source_refs=["admit_attempt"])
        _assert_event(col, "S08", "reached", source_refs=["send_completed"])
        _assert_event(col, "S10", "reached", source_refs=["evidence_built"])
        # No S09 (no comparison), no S11 (validator-owned), no failed events.
        assert _find(col, "S09", "reached") is None
        assert _find(col, "S11", "reached") is None
        assert _find(col, "S08", "failed") is None
        assert _find(col, "S08", "blocked") is None
        assert _find(col, "S10", "blocked") is None

    def test_comparison_ready_emits_s09_reached(self):
        col = _collector()
        (ex, net, _w, _b) = _ex(
            diagnostic_collector=col,
            account_credentials={"acct-a": "secret-a", "acct-b": "secret-b"},
        )
        spec = _spec(
            gap="authz_impact_not_proven",
            auth_a_id="acct-a",
            auth_b_id="acct-b",
        )
        result = _run(ex.execute(spec))
        assert result.status == EXECUTED
        assert result.requests_made == 2
        assert len(net.calls) == 2
        _assert_event(col, "S09", "reached", source_refs=["comparison_ready"])
        # No secret value may ever reach the diagnostic section.
        dumped = str(_events(col))
        assert "secret-a" not in dumped and "secret-b" not in dumped

    def test_idempotency_duplicate_emits_s08_blocked(self):
        col = _collector()
        (ex, net, _w, _b) = _ex(diagnostic_collector=col)
        attempt_id = build_attempt_id("hyp-res-1", "payload_request_mismatch", "unauth")
        assert ex.idempotency_guard.register(attempt_id)
        result = _run(ex.execute(_spec()))
        assert result.status == MANUAL_REVIEW
        assert result.reason == "attempt:idempotency_duplicate"
        assert net.count == 0
        _assert_event(col, "S08", "blocked", source_refs=["idempotency_duplicate"])

    def test_concurrency_limit_emits_s08_blocked(self):
        col = _collector()
        budget = VdpExecutionBudget(
            max_requests=100, max_follow_ups=100, max_concurrency=0,
            per_asset_burst=100, per_hypothesis_burst=100,
        )
        (ex, net, _w, _b) = _ex(diagnostic_collector=col, budget=budget)
        result = _run(ex.execute(_spec()))
        assert result.status == BLOCKED
        assert result.reason == "concurrency_limit_exceeded"
        assert net.count == 0
        _assert_event(col, "S08", "blocked", source_refs=["concurrency_limit"])

    def test_budget_limited_emits_s08_blocked_queue_backpressure(self):
        col = _collector()
        budget = VdpExecutionBudget(
            max_requests=100, max_follow_ups=0,
            per_asset_burst=100, per_hypothesis_burst=100,
        )
        (ex, net, _w, _b) = _ex(diagnostic_collector=col, budget=budget)
        result = _run(ex.execute(_spec()))
        assert result.status == BLOCKED
        assert result.reason == "budget:follow_ups_exhausted"
        assert net.count == 0
        _assert_event(
            col, "S08", "blocked",
            reason_codes=["queue_backpressure"],
            source_refs=["budget:follow_ups_exhausted"],
        )

    def test_double_send_prevented_emits_s08_blocked(self):
        col = _collector()
        idem = IdempotencyGuard()
        scg = StateChangeGuard()
        validator = lambda t: t == "T-1"  # noqa: E731
        (ex1, net1, _w, _b) = _ex(
            diagnostic_collector=col, idem=idem, scg=scg,
            hitl_ticket_validator=validator,
        )
        r1 = _run(ex1.execute(_m3b_spec()))
        assert r1.status == EXECUTED
        assert len(net1.calls) == 1
        assert ex1.state_change_guard.is_safe_to_send(r1.attempt_id) is False
        # Release ONLY the idempotency registration; the sent fact stays.
        ex1.idempotency_guard.unregister(r1.attempt_id)
        (ex2, net2, _w, _b) = _ex(
            diagnostic_collector=col, idem=idem, scg=scg,
            hitl_ticket_validator=validator,
        )
        r2 = _run(ex2.execute(_m3b_spec()))
        assert r2.status == BLOCKED
        assert r2.reason == "state_change_already_sent"
        assert net2.count == 0
        _assert_event(col, "S08", "blocked", source_refs=["double_send_prevented"])

    def test_network_error_emits_s08_failed_transport_timeout(self):
        col = _collector()
        net = _FailingNet(fail_times=1)
        (ex, _n, _w, _b) = _ex(diagnostic_collector=col, network_client=net)
        result = _run(ex.execute(_spec()))
        assert result.status == "degraded"
        assert result.reason == "network_error"
        _assert_event(
            col, "S08", "failed",
            reason_codes=["transport_timeout"],
            source_refs=["network_error"],
        )
        # The send never completed and no evidence was built.
        assert _find(col, "S08", "reached", "send_completed") is None
        assert _find(col, "S10", "reached") is None

    def test_writer_backpressure_emits_s10_blocked_queue_backpressure(self):
        col = _collector()
        writer = _FailingWriter()
        (ex, net, _w, _b) = _ex(diagnostic_collector=col, evidence_writer=writer)
        result = _run(ex.execute(_spec()))
        assert result.status == "degraded"
        assert result.reason == "evidence_write_backpressure"
        assert len(net.calls) == 1
        _assert_event(col, "S08", "reached", source_refs=["send_completed"])
        _assert_event(col, "S10", "reached", source_refs=["evidence_built"])
        _assert_event(
            col, "S10", "blocked",
            reason_codes=["queue_backpressure"],
            source_refs=["evidence_write_backpressure"],
        )


class TestRequiredRunGuard:
    """(c) required=True + hook failure → blocked BEFORE any network send."""

    def test_required_hook_failure_blocks_before_network(self):
        col = _collector(required=True)
        col.mark_hook_failed("boom")
        net = _ExplodingNet()
        (ex, _n, _w, budget) = _ex(diagnostic_collector=col, network_client=net)
        result = _run(ex.execute(_spec()))
        assert result.status == BLOCKED
        assert result.reason == "diagnostic_telemetry_hook_failure"
        assert net.calls == []
        attempt_id = build_attempt_id("hyp-res-1", "payload_request_mismatch", "unauth")
        assert not ex.idempotency_guard.is_registered(attempt_id)
        # No send-completion event may exist (the send loop never ran).
        assert _find(col, "S08", "reached", "send_completed") is None
        assert _find(col, "S08", "failed") is None

    def test_required_without_hook_failure_executes(self):
        col = _collector(required=True)
        (ex, net, _w, _b) = _ex(diagnostic_collector=col)
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        assert len(net.calls) == 1
        _assert_event(col, "S08", "reached", source_refs=["send_completed"])

    def test_non_required_hook_failure_does_not_break_execution(self):
        col = _collector(required=False)
        col.mark_hook_failed("boom")
        (ex, net, _w, _b) = _ex(diagnostic_collector=col)
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        assert len(net.calls) == 1

    def test_hook_exception_marks_hook_failed_and_continues(self):
        """A raising emit hook never breaks execute(); with required=False
        the run continues, and the failure is recorded for the kill switch."""
        col = _collector(required=False)

        def _exploding_emit(**kwargs):
            raise RuntimeError("telemetry down")

        col.emit = _exploding_emit
        (ex, net, _w, _b) = _ex(diagnostic_collector=col)
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        assert len(net.calls) == 1
        assert col.hook_failed is True
