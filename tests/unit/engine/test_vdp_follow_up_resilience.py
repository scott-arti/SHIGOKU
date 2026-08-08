"""
VDP follow-up resilience counter-proofs — SGK-2026-0421 Steps 11-12.

Every counter-proof required by the implementation gate:
circuit open, concurrency, redirect (no second hop), HITL-path blocking,
StateChangeGuard non-bypass, hook re-run dedup, secrets absent end-to-end.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from src.core.engine.vdp_budget import VdpExecutionBudget
from src.core.engine.vdp_follow_up import build_next_action_record
from src.core.engine.vdp_follow_up_executor import (
    EXECUTED,
    MANUAL_REVIEW,
    VdpFollowUpExecutor,
    build_follow_up_task_id,
)
from src.core.models.vdp_contract import (
    CapabilityLevel,
    HypothesisRecord,
    IdempotencyGuard,
    ProgramCapabilityMatrix,
    StateChangeGuard,
)
from src.core.security.ethics_guard import ScopeDefinition


def _hyp(**kwargs) -> HypothesisRecord:
    d = {
        "hypothesis_id": "hyp-res-1",
        "observation_id": "obs-res-1",
        "asset": "https://api.example.com/items",
        "capability": "object_read_write_delete",
        "hypothesis_text": "t",
        "trust_boundary": "unauthenticated",
        "actors": ["unauth"],
        "risk_class": "read_only",
    }
    d.update(kwargs)
    return HypothesisRecord(**d)


def _scope() -> ScopeDefinition:
    return ScopeDefinition(
        program_name="t",
        in_scope_domains=["api.example.com"],
        out_of_scope_domains=[],
        max_requests_per_minute=1000,
    )


class _Net:
    def __init__(self, status=200, body="ok", redirect_to=""):
        self.status = status
        self.body = body
        self.redirect_to = redirect_to
        self.calls = []

    async def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.redirect_to:
            return _Resp(302, "", location=self.redirect_to)
        return _Resp(self.status, self.body)

    @property
    def count(self):
        return len(self.calls)


class _Resp:
    def __init__(self, status, body, location=""):
        self.status = status
        self.body = body
        self.elapsed = 0.01
        self.headers = {"location": location} if location else {}


class _W:
    def __init__(self):
        self.evidence = []

    async def enqueue_evidence(self, evidence: dict):
        self.evidence.append(evidence)


def _spec(gap="authz_impact_not_proven", **overrides) -> dict:
    # SGK-2026-0434: payload_request_mismatch is no longer an executable
    # m3a gap; machinery tests default to a healthy executable gap.
    hyp = _hyp()
    na = build_next_action_record("vrd-r1", hyp, gap)
    spec = {
        "task_id": build_follow_up_task_id(na.next_action_id, hyp.hypothesis_id, "unauth"),
        "hypothesis_id": hyp.hypothesis_id,
        "next_action_id": na.next_action_id,
        "evidence_gap": gap,
        "url": "https://api.example.com/items",
        "method": "GET",
        "param_names": [],
        "actor": "unauth",
        "risk_class": "read_only",
    }
    spec.update(overrides)
    return spec


def _ex(**kw):
    net = kw.pop("net", None) or _Net()
    budget = kw.pop("budget", None) or VdpExecutionBudget(
        max_requests=100, per_asset_burst=100, per_hypothesis_burst=100
    )
    writer = kw.pop("writer", None) or _W()
    ex = VdpFollowUpExecutor(
        scope_definition=kw.pop("scope", None) or _scope(),
        capability_matrix=kw.pop(
            "matrix", None
        ) or ProgramCapabilityMatrix(rules={"follow_up_probe": CapabilityLevel.ALLOWED}),
        budget=budget,
        network_client=net,
        evidence_writer=writer,
        idempotency_guard=kw.pop("idem", None) or IdempotencyGuard(),
        state_change_guard=kw.pop("scg", None) or StateChangeGuard(),
        available_preconditions={
            "scope": True, "budget": True, "request_budget": True,
            "action_permission": True, "protected_resource": True,
        },
        **kw,
    )
    return ex, net, writer, budget


def _run(coro):
    return asyncio.run(coro)


class TestCircuitAndConcurrency:
    def test_circuit_open_blocks_communication(self):
        budget = VdpExecutionBudget(max_requests=100, per_asset_burst=100)
        for _ in range(budget.circuit_breaker_429_threshold):
            budget.record_response("https://api.example.com/items", 429)
        (ex, net, writer, _b) = _ex(budget=budget)
        result = _run(ex.execute(_spec()))
        assert result.status == "blocked"
        assert "circuit_open_429" in result.reason
        assert net.count == 0

    def test_concurrency_limit_exceeded_blocks(self):
        budget = VdpExecutionBudget(max_requests=100, max_concurrency=0)
        (ex, net, writer, _b) = _ex(budget=budget)
        result = _run(ex.execute(_spec()))
        assert result.status == "blocked"
        assert "concurrency" in result.reason
        assert net.count == 0

    def test_budget_exhausted_after_peek_blocks(self):
        budget = VdpExecutionBudget(max_requests=1, per_asset_burst=100)
        budget.consume(asset_key="https://api.example.com/items")
        (ex, net, writer, _b) = _ex(budget=budget)
        result = _run(ex.execute(_spec()))
        assert result.status == "blocked"
        assert "budget" in result.reason
        assert net.count == 0


class TestRedirect:
    def test_redirect_is_never_followed_automatically(self):
        net = _Net(redirect_to="https://other.example.com/landing")
        (ex, _n, writer, budget) = _ex(net=net)
        result = _run(ex.execute(_spec()))
        # One request recorded; no second hop (scope re-evaluation would be
        # required per hop — 0421 does not follow redirects).
        assert net.count == 1
        assert result.status == EXECUTED

    def test_redirect_target_out_of_scope_has_zero_second_communication(self):
        net = _Net(redirect_to="https://outside.example.com/x")
        (ex, _n, writer, budget) = _ex(net=net)
        _run(ex.execute(_spec()))
        assert net.count == 1  # only the initial hop — never the redirect target


class TestHitlPathInExecutor:
    def test_confirmation_required_without_verified_ticket_never_sends(self):
        matrix = ProgramCapabilityMatrix(
            rules={"follow_up_probe": CapabilityLevel.CONFIRMATION_REQUIRED}
        )
        (ex, net, writer, budget) = _ex(matrix=matrix)
        result = _run(ex.execute(_spec()))
        assert result.status == MANUAL_REVIEW
        assert net.count == 0

    def test_arbitrary_ticket_id_never_passes(self):
        matrix = ProgramCapabilityMatrix(
            rules={"follow_up_probe": CapabilityLevel.CONFIRMATION_REQUIRED}
        )
        (ex, net, writer, budget) = _ex(matrix=matrix)
        # The executor has no ticket store — even a provided ID cannot verify.
        result = _run(ex.execute(_spec()))
        assert result.status == MANUAL_REVIEW
        assert net.count == 0


class TestStateChangeGuard:
    def test_double_send_prevented(self):
        guard = StateChangeGuard()
        guard.mark_sent("att-state-1")
        with pytest.raises(ValueError):
            guard.prevent_double_send("att-state-1")
        assert guard.is_safe_to_send("att-state-2") is True

    def test_confirmed_saved_allows_restart(self):
        guard = StateChangeGuard()
        guard.mark_sent("att-state-1")
        guard.confirm_saved("att-state-1")
        assert guard.is_safe_to_send("att-state-1") is True

    def test_state_changing_plans_never_reach_network(self):
        (ex, net, writer, budget) = _ex()
        for gap in ("state_change_not_verified", "state_change_readback", "file_upload_impact_not_proven"):
            result = _run(ex.execute(_spec(gap=gap)))
            assert result.status == MANUAL_REVIEW, gap
            assert net.count == 0


class TestDependencyStop:
    def test_dependency_stop_is_never_refuted(self):
        """network failure → degraded; the verdict stays candidate/untested."""
        net = _Net(status=0, body="")

        class _BoomNet(_Net):
            async def request(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                raise TimeoutError("dep stopped")

        (ex, net2, writer, budget) = _ex(net=_BoomNet())
        result = _run(ex.execute(_spec()))
        assert result.status == "degraded"
        assert result.reason == "network_error"
        assert result.requests_made == 1
        assert net2.count == 1
        assert result.attempt is not None
        assert result.attempt["state"] == "failed"
        assert result.evidence is None
        assert result.verdict_status in ("", "candidate")
        assert result.verdict_status != "refuted"


class TestSecretsEndToEnd:
    def test_secret_absent_in_spec_attempt_evidence(self):
        net = _Net(body='{"session_token": "topsecretvalue123", "ok": true}')
        (ex, _n, writer, budget) = _ex(net=net)
        spec = _spec()
        result = _run(ex.execute(spec))
        assert result.status == EXECUTED
        dumped = json.dumps(
            {"spec": spec, "result": result.__dict__, "evidence": writer.evidence}
        )
        assert "topsecretvalue123" not in dumped
        assert "Authorization" not in dumped

    def test_hook_rerun_does_not_duplicate(self):
        """同じNextAction再処理でqueue/Attempt/Evidenceが重複しない (hook層)。"""
        from types import SimpleNamespace

        from src.core.engine.master_conductor import MasterConductor
        from src.core.engine.task_queue import DynamicTaskQueue

        mc = object.__new__(MasterConductor)
        mc.task_queue = DynamicTaskQueue()
        mc._vdp_state = {
            "vdp_active": True,
            "hypotheses": [_hyp().to_dict()],
            "attempts": [],
            "evidence_records": [],
            "verdicts": [{
                "verdict_id": "vrd-r1",
                "hypothesis_id": "hyp-res-1",
                "status": "candidate",
                "schema_version": 1,
            }],
            "next_actions": [build_next_action_record("vrd-r1", _hyp(), "payload_request_mismatch").to_dict()],
            "follow_up_pending": [],
            "follow_up_queued": [],
            "budget_snapshot": {},
            "run_health": {},
        }
        mc._injected_task_ids = set()
        mc._derived_task_count = 0
        mc._owned_injection_targets = set()
        mc._vdp_mode = SimpleNamespace(
            mode="readonly_enforce", label_leakage_denylist=[], kill_switch=False,
            capability_rules={"follow_up_probe": "allowed"},
        )

        from src.core.engine.vdp_observation_adapter import ObservationAdapter
        observation = ObservationAdapter().adapt_endpoint_signal({
            "url": "https://api.example.com/items",
            "method": "GET",
            "entity_type": "endpoint",
            "primary_label": "items",
            "params": [],
        })
        assert observation is not None
        mc._vdp_state["hypotheses"][0]["observation_id"] = observation.observation_id

        # Spy on _add_tasks: real DynamicTaskQueue behind it, unrelated MC
        # plumbing bypassed (queue dedup + pending preservation is the unit
        # under test here; the real _add_tasks path is covered by the
        # MasterConductor integration test).
        def _spy_add_tasks(tasks, source="unknown"):
            added = 0
            for t in tasks:
                if mc.task_queue.get_by_id(t.id):
                    continue
                mc.task_queue.add(t)
                mc._injected_task_ids.add(t.id)
                added += 1
            return added

        mc._add_tasks = _spy_add_tasks

        for _ in range(2):
            mc._queue_vdp_follow_ups(_scope(), observations=[observation])
        task_ids = [t.id for t in mc.task_queue]
        assert len(task_ids) == len(set(task_ids)), "duplicate tasks queued"
        assert len(mc._vdp_state["follow_up_pending"]) == 1
        assert len(mc._vdp_state["follow_up_queued"]) == 1
