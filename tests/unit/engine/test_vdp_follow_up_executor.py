"""
VDP follow-up executor tests — SGK-2026-0421 Steps 8-12.

Deterministic Task/Attempt/Evidence IDs, request fingerprint, exact replay /
PoC mismatch, budget-consumption == network-count, hidden-communication
disabled, and M3a blocking behavior.
"""
from __future__ import annotations

import asyncio

import pytest

from src.core.domain.scope.vdp_scope_validator import revalidate_scope_for_request
from src.core.engine.vdp_budget import VdpExecutionBudget
from src.core.engine.vdp_follow_up import build_next_action_record
from src.core.engine.vdp_follow_up_executor import (
    EXECUTED,
    MANUAL_REVIEW,
    VdpFollowUpExecutor,
    build_attempt_id,
    build_follow_up_task_id,
    build_request_fingerprint,
)
from src.core.models.vdp_contract import (
    CapabilityLevel,
    EvidenceVerdictV1,
    HypothesisRecord,
    IdempotencyGuard,
    ProgramCapabilityMatrix,
    StateChangeGuard,
)
from src.core.security.ethics_guard import ScopeDefinition


def _hypothesis(**kwargs) -> HypothesisRecord:
    defaults = {
        "hypothesis_id": "hyp-exec-1",
        "observation_id": "obs-exec-1",
        "asset": "https://api.example.com/items",
        "capability": "object_read_write_delete",
        "hypothesis_text": "t",
        "trust_boundary": "unauthenticated",
        "actors": ["unauth"],
        "risk_class": "read_only",
        "scope_verdict": "allowed",
    }
    defaults.update(kwargs)
    return HypothesisRecord(**defaults)


def _scope() -> ScopeDefinition:
    return ScopeDefinition(
        program_name="t",
        in_scope_domains=["api.example.com"],
        out_of_scope_domains=[],
        max_requests_per_minute=1000,
    )


def _matrix(**rules) -> ProgramCapabilityMatrix:
    return ProgramCapabilityMatrix(rules=rules, program_name="t")


class _FakeNetwork:
    """Injected fake transport. Records call kwargs; returns canned responses."""

    def __init__(self, status: int = 200, body: str = "ok", fail_times: int = 0):
        self.status = status
        self.body = body
        self.calls: list[dict] = []
        self.fail_times = fail_times
        self.failures = 0

    async def request(self, *args, **kwargs):
        call = dict(kwargs)
        if args:
            call.setdefault("method", args[0])
        if len(args) > 1:
            call.setdefault("url", args[1])
        self.calls.append(call)
        if self.failures < self.fail_times:
            self.failures += 1
            raise TimeoutError("simulated timeout")
        return _FakeResponse(self.status, self.body)

    @property
    def last(self) -> dict:
        return self.calls[-1]


class _FakeResponse:
    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        self.elapsed = 0.05


class _FakeWriter:
    def __init__(self, fail: bool = False):
        self.evidence: list[dict] = []
        self.fail = fail

    async def enqueue_evidence(self, evidence: dict):
        if self.fail:
            raise RuntimeError("queue full")
        self.evidence.append(evidence)


def _spec(gap: str = "payload_request_mismatch", **overrides) -> dict:
    hyp = _hypothesis()
    na = build_next_action_record("vrd-1", hyp, gap)
    data = {
        "task_id": build_follow_up_task_id(na.next_action_id, hyp.hypothesis_id, "unauth"),
        "hypothesis_id": hyp.hypothesis_id,
        "next_action_id": na.next_action_id,
        "evidence_gap": gap,
        "url": "https://api.example.com/items",
        "method": "GET",
        "param_names": [],
        "actor": "unauth",
        "risk_class": "read_only",
        "action_class": na.action_class,
    }
    data.update(overrides)
    return data


def _executor(**kwargs):
    net = kwargs.pop("network_client", None) or _FakeNetwork()
    budget = kwargs.pop("budget", None) or VdpExecutionBudget(
        max_requests=100, per_asset_burst=100, per_hypothesis_burst=100
    )
    writer = kwargs.pop("evidence_writer", None) or _FakeWriter()
    return (
        VdpFollowUpExecutor(
            scope_definition=_scope(),
            capability_matrix=_matrix(follow_up_probe=CapabilityLevel.ALLOWED),
            budget=budget,
            network_client=net,
            evidence_writer=writer,
            idempotency_guard=IdempotencyGuard(),
            state_change_guard=StateChangeGuard(),
            available_preconditions={
                "scope": True,
                "budget": True,
                "request_budget": True,
                "action_permission": True,
                "protected_resource": True,
            },
            **kwargs,
        ),
        net,
        writer,
        budget,
    )


def _run(coro):
    return asyncio.run(coro)


def _evidence_of(result) -> dict:
    """Narrow the optional evidence dict of an execution result."""
    evidence = result.evidence
    assert evidence is not None, result.reason
    return evidence


class TestDeterministicIds:
    def test_task_id_deterministic(self):
        a = build_follow_up_task_id("nxt-1", "hyp-1", "unauth")
        b = build_follow_up_task_id("nxt-1", "hyp-1", "unauth")
        assert a == b
        c = build_follow_up_task_id("nxt-2", "hyp-1", "unauth")
        assert a != c

    def test_attempt_id_deterministic(self):
        a = build_attempt_id("hyp-1", "payload_request_mismatch", "unauth")
        b = build_attempt_id("hyp-1", "payload_request_mismatch", "unauth")
        assert a == b
        assert a != build_attempt_id("hyp-1", "state_change_not_verified", "unauth")

    def test_request_fingerprint_deterministic_and_secret_free(self):
        fp = build_request_fingerprint(
            "GET", "https://api.example.com/items", ("id", "csrf")
        )
        fp2 = build_request_fingerprint(
            "get", "https://api.example.com/items", ("csrf", "id")
        )
        assert fp == fp2  # case/order normalized
        assert "csrf" not in fp.split("-")[1:]  # only the digest survives

    def test_same_next_action_reprocessing_has_same_attempt(self):
        spec = _spec()
        (ex, net, writer, budget) = _executor()
        r1 = _run(ex.execute(spec))
        assert r1.attempt_id != ""
        r2 = _run(ex.execute(spec))
        # Second processing of the same NextAction is rejected as duplicate
        # and produces NO additional network traffic / evidence.
        assert r2.status == MANUAL_REVIEW
        assert "idempotency_duplicate" in r2.reason
        assert len(net.calls) == 1
        assert len(writer.evidence) == 1
        snapshot = budget.snapshot()
        assert snapshot["requests_used"] == 1
        assert snapshot["follow_ups_used"] == 1


class TestExactReplayAndFingerprint:
    def test_replay_uses_hidden_communication_disabled(self):
        spec = _spec()
        (ex, net, writer, budget) = _executor()
        result = _run(ex.execute(spec))
        assert result.status == EXECUTED
        call = net.last
        assert call["use_cache"] is False
        assert call["retries"] == 0
        assert call["auto_waf_bypass"] is False
        assert call["allow_redirects"] is False
        assert call["timeout"] == 15

    def test_request_count_matches_budget_consumption(self):
        spec = _spec()
        (ex, net, writer, budget) = _executor()
        before = budget.snapshot()["requests_used"]
        result = _run(ex.execute(spec))
        assert result.status == EXECUTED
        assert result.requests_made == 1
        assert len(net.calls) == 1
        assert budget.snapshot()["requests_used"] == before + 1

    def test_single_request_plan_consumes_once(self):
        spec = _spec()
        (ex, net, writer, budget) = _executor()
        before = budget.snapshot()["requests_used"]
        result = _run(ex.execute(spec))
        assert result.status == EXECUTED
        assert result.requests_made == 1
        assert budget.snapshot()["requests_used"] == before + 1

    def test_poc_mismatch_detected(self):
        """The production executor must stop a mismatched replay before I/O."""
        expected = build_request_fingerprint(
            "GET", "https://api.example.com/items", ()
        )
        spec = _spec(method="HEAD", expected_request_fingerprint=expected)
        (ex, net, writer, budget) = _executor()
        result = _run(ex.execute(spec))
        assert result.status == "blocked"
        assert result.reason == "request_fingerprint_mismatch"
        assert len(net.calls) == 0

    def test_exact_replay_sends_the_admitted_method(self):
        expected = build_request_fingerprint(
            "HEAD", "https://api.example.com/items", ()
        )
        spec = _spec(method="HEAD", expected_request_fingerprint=expected)
        (ex, net, writer, budget) = _executor()
        result = _run(ex.execute(spec))
        assert result.status == EXECUTED
        assert net.last["method"] == "HEAD"

    def test_exact_replay_without_discarded_parameter_values_only(self):
        spec = _spec(param_names=["id"], param_locations=["query"])
        (ex, net, writer, budget) = _executor()
        result = _run(ex.execute(spec))
        assert result.status == MANUAL_REVIEW
        assert result.reason == "exact_request_material_unavailable"
        assert len(net.calls) == 0

    def test_evidence_record_has_raw_hash_and_redacted_excerpt(self):
        spec = _spec()
        (ex, net, writer, budget) = _executor()
        result = _run(ex.execute(spec))
        assert result.status == EXECUTED
        evidence = writer.evidence[0]
        assert evidence["raw_hash"].startswith("sha256:")
        assert evidence["original_size"] > 0
        assert "redacted_excerpt" in evidence
        assert evidence["evidence_type"] == "real_http_response"

    def test_timing_evidence_type(self):
        spec = _spec(gap="insufficient_timing_validation")
        (ex, net, writer, budget) = _executor()
        result = _run(ex.execute(spec))
        assert result.status == MANUAL_REVIEW
        assert result.reason == "executor_contract_unavailable:insufficient_timing_validation"
        assert len(net.calls) == 0
        assert writer.evidence == []

    def test_failed_negative_control_never_confirms(self):
        spec = _spec(
            gap="insufficient_timing_validation",
            control_results={
                "baseline": [0.1],
                "attack": [4.8],
                "inverse": [4.7],
            },
        )
        (ex, net, writer, budget) = _executor()
        result = _run(ex.execute(spec))
        assert result.status == MANUAL_REVIEW
        assert result.verdict_status != "confirmed"
        assert len(net.calls) == 0
        assert writer.evidence == []


class TestM3aBlocking:
    def test_state_changing_gap_is_manual_review(self):
        spec = _spec(gap="state_change_not_verified")
        (ex, net, writer, budget) = _executor()
        result = _run(ex.execute(spec))
        assert result.status == MANUAL_REVIEW
        assert len(net.calls) == 0

    def test_oob_gap_is_manual_review_without_oob_channel(self):
        spec = _spec(gap="ssrf_proof_missing")
        (ex, net, writer, budget) = _executor()
        result = _run(ex.execute(spec))
        assert result.status == MANUAL_REVIEW
        assert len(net.calls) == 0

    def test_missing_precondition_is_manual_review(self):
        spec = _spec()
        (ex, net, writer, budget) = _executor()
        ex.available_preconditions = {}
        result = _run(ex.execute(spec))
        assert result.status == MANUAL_REVIEW
        assert "precondition_missing" in result.reason
        assert len(net.calls) == 0

    def test_kill_switch_blocks_before_network(self):
        spec = _spec()
        (ex, net, writer, budget) = _executor(kill_switch_provider=lambda: True)
        result = _run(ex.execute(spec))
        assert result.status == "blocked"
        assert len(net.calls) == 0

    def test_scope_unknown_blocks(self):
        spec = _spec(url="https://outside.example.com/x")
        (ex, net, writer, budget) = _executor()
        result = _run(ex.execute(spec))
        assert result.status == "blocked"
        assert len(net.calls) == 0

    def test_budget_exhausted_blocks_after_admission_checks(self):
        budget = VdpExecutionBudget(max_requests=0, per_asset_burst=100)
        spec = _spec()
        (ex, net, writer, _b) = _executor(budget=budget)
        result = _run(ex.execute(spec))
        assert result.status == "blocked"
        assert "budget" in result.reason
        assert len(net.calls) == 0
        attempt_id = build_attempt_id(
            "hyp-exec-1", "payload_request_mismatch", "unauth"
        )
        assert not ex.idempotency_guard.is_registered(attempt_id)
        assert budget.snapshot()["follow_ups_used"] == 0

    def test_follow_up_budget_exhausted_blocks_before_network(self):
        budget = VdpExecutionBudget(
            max_requests=100,
            max_follow_ups=0,
            per_asset_burst=100,
            per_hypothesis_burst=100,
        )
        (ex, net, writer, _b) = _executor(budget=budget)
        result = _run(ex.execute(_spec()))
        assert result.status == "blocked"
        assert result.reason == "budget:follow_ups_exhausted"
        assert len(net.calls) == 0
        assert budget.snapshot()["requests_used"] == 0

    def test_concurrency_rejection_consumes_no_budget_or_idempotency(self):
        budget = VdpExecutionBudget(
            max_requests=100,
            max_follow_ups=100,
            max_concurrency=0,
            per_asset_burst=100,
            per_hypothesis_burst=100,
        )
        (ex, net, writer, _b) = _executor(budget=budget)
        result = _run(ex.execute(_spec()))
        assert result.status == "blocked"
        assert result.reason == "concurrency_limit_exceeded"
        assert len(net.calls) == 0
        snapshot = budget.snapshot()
        assert snapshot["requests_used"] == 0
        assert snapshot["follow_ups_used"] == 0
        attempt_id = build_attempt_id(
            "hyp-exec-1", "payload_request_mismatch", "unauth"
        )
        assert not ex.idempotency_guard.is_registered(attempt_id)

    def test_network_error_is_degraded_not_refuted(self):
        spec = _spec()
        net = _FakeNetwork(fail_times=1)
        (ex, _n, writer, budget) = _executor(network_client=net)
        result = _run(ex.execute(spec))
        assert result.status == "degraded"
        assert result.reason == "network_error"
        assert result.requests_made == 1
        assert len(net.calls) == 1
        assert result.attempt is not None
        assert result.attempt["state"] == "failed"
        assert result.evidence is None

    def test_evidence_write_backpressure_is_degraded_not_silent(self):
        spec = _spec()
        writer = _FakeWriter(fail=True)
        (ex, net, _w, budget) = _executor(evidence_writer=writer)
        result = _run(ex.execute(spec))
        assert result.status == "degraded"
        assert result.evidence_id  # evidence is not silently discarded
        assert result.attempt is not None
        assert result.evidence is not None

    def test_never_confirmed(self):
        spec = _spec()
        (ex, net, writer, budget) = _executor()
        result = _run(ex.execute(spec))
        assert result.verdict_status in ("", "candidate")
        assert result.verdict_status != "confirmed"


class TestM3aSupportedGapExpansion:
    """SGK-2026-0423 Lane P-1: comparison-capable gaps are now M3a-
    executable, but WITHOUT auth account ids they keep the existing
    single-request neutral-fact behavior (no comparison markers)."""

    def test_comparison_gap_without_account_ids_single_request_unchanged(self):
        for gap in (
            "authz_impact_not_proven",
            "semantic_diff_owner_permission_sensitive_field",
        ):
            (ex, net, writer, budget) = _executor()
            result = _run(ex.execute(_spec(gap=gap)))
            assert result.status == EXECUTED, gap
            assert result.requests_made == 1, gap
            assert len(net.calls) == 1, gap
            er = writer.evidence[0]["execution_result"]
            assert "cross_account_compared" not in er, gap
            assert "authz_impact_proven" not in er, gap
            assert "semantic_diff_observed" not in er, gap
            assert "second_account_compared" not in er, gap
            assert er["response_received"] is True
            assert er["request_count"] == 1


class TestNoSecrets:
    def test_spec_and_result_never_contain_secret_values(self):
        spec = _spec()
        (ex, net, writer, budget) = _executor()
        result = _run(ex.execute(spec))
        dumped = str(spec) + str(result) + str(writer.evidence)
        for secret in ("Bearer", "Authorization", "password=value", "token-abc"):
            assert secret not in dumped

    def test_evidence_excerpt_is_redacted(self):
        spec = _spec()
        net = _FakeNetwork(body='{"session_token": "abc123def456", "ok": true}')
        (ex, _n, writer, budget) = _executor(network_client=net)
        _run(ex.execute(spec))
        excerpt = writer.evidence[0]["redacted_excerpt"]
        assert "abc123def456" not in excerpt
        assert "[REDACTED]" in excerpt


class TestComparisonGapFallback:
    """Lane P-1 additive: the comparison-capable gaps WITHOUT account ids
    keep the existing single-request neutral-fact behavior — executed with
    ONE request, NO comparison facts, NO markers (existing tests stay
    green)."""

    def test_authz_gap_without_accounts_falls_back_to_single_request(self):
        spec = _spec(gap="authz_impact_not_proven")
        (ex, net, writer, budget) = _executor()
        result = _run(ex.execute(spec))
        assert result.status == EXECUTED
        assert result.requests_made == 1
        assert len(net.calls) == 1
        er = _evidence_of(result)["execution_result"]
        assert er["response_received"] is True
        assert er["request_count"] == 1
        assert "cross_account_compared" not in er
        assert "authz_impact_proven" not in er
        assert "second_account_compared" not in er
        # no credential header was attached (no account credentials)
        assert "headers" not in net.last

    def test_semantic_gap_without_accounts_falls_back_to_single_request(self):
        spec = _spec(gap="semantic_diff_owner_permission_sensitive_field")
        (ex, net, writer, budget) = _executor()
        result = _run(ex.execute(spec))
        assert result.status == EXECUTED
        assert result.requests_made == 1
        er = _evidence_of(result)["execution_result"]
        assert er["request_count"] == 1
        assert "cross_account_compared" not in er
        assert "semantic_diff_observed" not in er
