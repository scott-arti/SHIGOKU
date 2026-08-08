"""
SGK-2026-0433 — timing-difference foundation tests (m3a read-only).

The executor now measures timing differences for the
``insufficient_timing_validation`` gap with proper controls and records a
``timing_measurement`` evidence record whose execution_result carries the
``timing_difference_observed`` marker ("true"/"false"). Honest outcome is the
goal: without a real read-only condition delta the marker is "false" and the
gap stays open (hold) — that is success per the plan. The marker is NEVER
fabricated.

The fake transport pattern follows tests/unit/engine/test_vdp_cross_account.py
(``_AuthNet``): per-URL deterministic latency + captured calls.
"""
from __future__ import annotations

import asyncio

from src.core.engine.vdp_budget import VdpExecutionBudget
from src.core.engine.vdp_evidence_validator import (
    REASON_EVIDENCE_CONTRACT_SATISFIED,
    REASON_SUCCESS_CONDITION_NOT_PROVEN,
    Ed25519EvidenceSigner,
    VdpEvidenceValidator,
)
from src.core.engine.vdp_follow_up import build_next_action_record
from src.core.engine.vdp_follow_up_executor import (
    BLOCKED,
    DEGRADED,
    EXECUTED,
    MANUAL_REVIEW,
    VdpFollowUpExecutor,
    build_follow_up_task_id,
    is_m3a_executor_supported_gap,
)
from src.core.models.vdp_contract import (
    AttemptRecord,
    CapabilityLevel,
    EvidenceRecordV1,
    HypothesisRecord,
    IdempotencyGuard,
    ProgramCapabilityMatrix,
    StateChangeGuard,
)
from src.core.security.ethics_guard import ScopeDefinition


def _hyp(**kwargs) -> HypothesisRecord:
    d = {
        "hypothesis_id": "hyp-tm-1",
        "observation_id": "obs-tm-1",
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


class _TimingNet:
    """Fake transport with deterministic per-URL wall-clock latency.

    ``latency_by_url`` maps URL -> seconds the transport sleeps before
    answering (simulates a server-side condition delta). Calls are captured
    so the tests can assert request counts and headers.
    """

    def __init__(self, status: int = 200, body: str = "ok", latency_by_url=None):
        self.status = status
        self.body = body
        self.latency_by_url = dict(latency_by_url or {})
        self.calls: list = []

    async def request(self, *args, **kwargs):
        url = args[1] if len(args) > 1 else kwargs.get("url", "")
        self.calls.append((args, kwargs))
        delay = float(self.latency_by_url.get(url, 0.0) or 0.0)
        if delay > 0.0:
            await asyncio.sleep(delay)
        return _Resp(self.status, self.body)

    @property
    def count(self) -> int:
        return len(self.calls)

    def auth_for_call(self, index: int) -> str:
        headers = self.calls[index][1].get("headers") or {}
        return (headers.get("Authorization", "") or "").replace("Bearer ", "")


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


class _RefusingNet:
    """Transport that raises a NON-timeout transport exception (body None
    path with an honest error class: connection-refused, not a timeout)."""

    def __init__(self):
        self.calls: list = []

    async def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise ConnectionRefusedError("simulated connection refused")


class _StatusSequenceNet:
    """Transport serving a per-call status sequence, then 200 forever."""

    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.calls: list = []

    async def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        index = len(self.calls) - 1
        status = (
            self.statuses[index] if index < len(self.statuses) else 200
        )
        return _Resp(status, "ok")


class _Resp:
    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        self.elapsed = 0.05


class _W:
    def __init__(self):
        self.evidence: list = []

    async def enqueue_evidence(self, evidence: dict):
        self.evidence.append(evidence)


def _spec(gap: str = "insufficient_timing_validation", **overrides) -> dict:
    hyp = _hyp()
    na = build_next_action_record("vrd-tm-1", hyp, gap)
    spec = {
        "task_id": build_follow_up_task_id(
            na.next_action_id, hyp.hypothesis_id, "unauth"
        ),
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
    net = kw.pop("net", None) or _TimingNet()
    budget = kw.pop("budget", None) or VdpExecutionBudget(
        max_requests=100, per_asset_burst=100, per_hypothesis_burst=100
    )
    writer = kw.pop("writer", None) or _W()
    creds = kw.pop("account_credentials", None) or {
        "acct-a": "secret-a",
        "acct-b": "secret-b",
    }
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
        account_credentials=creds,
        available_preconditions={
            "scope": True,
            "budget": True,
            "request_budget": True,
            "action_permission": True,
            "protected_resource": True,
        },
        **kw,
    )
    return ex, net, writer, budget


def _run(coro):
    return asyncio.run(coro)


def _evidence_of(result) -> dict:
    """Narrow the optional evidence dict of an execution result."""
    evidence = result.evidence
    assert evidence is not None, result.reason
    return evidence


def _attempt_of(result) -> dict:
    """Narrow the optional attempt dict of an execution result."""
    attempt = result.attempt
    assert attempt is not None, result.reason
    return attempt


def _signer() -> Ed25519EvidenceSigner:
    return Ed25519EvidenceSigner(private_key=bytes.fromhex("22" * 32))


def _validator_hypothesis(**kwargs) -> HypothesisRecord:
    """Full-contract hypothesis for the canonical validator path."""
    d = {
        "hypothesis_id": "hyp-tm-1",
        "observation_id": "obs-tm-1",
        "asset": "https://api.example.com/items",
        "capability": "object_read_write_delete",
        "hypothesis_text": "endpoint latency depends on a server-side condition",
        "trust_boundary": "api_endpoint",
        "actors": ["unauth"],
        "risk_class": "read_only",
        "success_condition": "measurable latency delta for a real condition",
        "falsification_condition": "no latency delta beyond jitter",
        "required_evidence": ["insufficient_timing_validation"],
        "state": "attempted",
    }
    d.update(kwargs)
    return HypothesisRecord(**d)


class TestSupportedGap:
    def test_timing_gap_supported_in_m3a(self):
        assert is_m3a_executor_supported_gap("insufficient_timing_validation") is True
        # weak-session stays unsupported (out of scope for the timing foundation)
        assert is_m3a_executor_supported_gap("weak_session_not_statistically_verified") is False


class TestTimingEvidenceRecord:
    def test_execution_produces_timing_measurement_record(self):
        (ex, net, writer, budget) = _ex()
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        assert result.requests_made == 8
        assert len(net.calls) == 8
        evidence = _evidence_of(result)
        assert evidence["evidence_type"] == "timing_measurement"
        er = evidence["execution_result"]
        # baseline >= 3, positive/negative controls present, medians computed
        assert len(er["timing_baseline_samples"]) == 3
        assert len(er["positive_control_samples"]) == 3
        assert len(er["negative_control_samples"]) == 2
        assert er["medians"]["baseline"] >= 0
        assert er["medians"]["positive"] > er["medians"]["baseline"]
        # calibration is honest: client-side control, never a server delta
        assert er["positive_control_is_client_side"] is True
        assert er["positive_control_latency_includes_client_sleep"] is True
        assert er["timing_method"] == "GET"
        assert er["timing_measurement_valid"] == "true"
        assert er["timing_difference_observed"] == "false"
        assert er["reason"] == "no_alternate_condition_in_readonly_scope"

    def test_uniform_latency_keeps_gap_open_via_validator(self):
        """No observable delta → marker false → the canonical validator does
        NOT satisfy the gap's required evidence (candidate/hold stays)."""
        (ex, net, writer, budget) = _ex()
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        assert result.verdict_status == "candidate"
        er = _evidence_of(result)["execution_result"]
        assert er["timing_difference_observed"] == "false"
        validator = VdpEvidenceValidator(signer=_signer())
        verdict = validator.evaluate(
            _validator_hypothesis(),
            [AttemptRecord.from_dict(_attempt_of(result))],
            [EvidenceRecordV1.from_dict(_evidence_of(result))],
        )
        assert verdict.status == "candidate"
        assert REASON_SUCCESS_CONDITION_NOT_PROVEN in verdict.reason_codes

    def test_variant_delta_observed_true_and_validator_confirms(self):
        """A real read-only condition delta (variant URL slower beyond
        jitter) → marker "true" and the validator sees it satisfied."""
        net = _TimingNet(latency_by_url={"https://api.example.com/variant": 0.15})
        (ex, net, writer, budget) = _ex(net=net)
        spec = _spec(timing_variant_url="https://api.example.com/variant")
        result = _run(ex.execute(spec))
        assert result.status == EXECUTED
        assert result.requests_made == 11
        er = _evidence_of(result)["execution_result"]
        assert er["timing_measurement_valid"] == "true"
        assert er["timing_difference_observed"] == "true"
        assert er["reason"] == "variant_timing_difference_observed"
        assert er["timing_variant_condition_present"] is True
        validator = VdpEvidenceValidator(signer=_signer())
        verdict = validator.evaluate(
            _validator_hypothesis(),
            [AttemptRecord.from_dict(_attempt_of(result))],
            [EvidenceRecordV1.from_dict(_evidence_of(result))],
        )
        assert verdict.status == "confirmed"
        assert REASON_EVIDENCE_CONTRACT_SATISFIED in verdict.reason_codes

    def test_variant_present_but_no_delta_stays_false(self):
        (ex, net, writer, budget) = _ex()
        er = ex._build_timing_execution_result(
            samples={
                "baseline": [100.0, 101.0, 99.0],
                "positive": [300.0, 301.0, 299.0],
                "negative": [100.0, 101.0],
                "variant": [100.5, 101.5, 99.5],
            },
            statuses=[200] * 11,
            failed_requests=[],
            failure_reason="",
            variant_present=True,
        )
        assert er["timing_measurement_valid"] == "true"
        assert er["timing_difference_observed"] == "false"
        assert er["reason"] == "no_timing_difference_beyond_jitter"

    def test_variant_delta_with_overlapping_quartiles_stays_false(self):
        """A large median delta alone is not enough: overlapping [Q1, Q3]
        intervals mean the difference is not beyond jitter."""
        (ex, net, writer, budget) = _ex()
        er = ex._build_timing_execution_result(
            samples={
                "baseline": [100.0, 101.0, 99.0],
                "positive": [300.0, 301.0, 299.0],
                "negative": [100.0, 101.0],
                "variant": [99.0, 160.0, 161.0],
            },
            statuses=[200] * 11,
            failed_requests=[],
            failure_reason="",
            variant_present=True,
        )
        assert er["timing_measurement_valid"] == "true"
        assert er["timing_difference_observed"] == "false"
        assert er["reason"] == "no_timing_difference_beyond_jitter"

    def test_insensitive_pipeline_reason(self):
        """Calibration offset missing → valid "false" + explicit reason."""
        (ex, net, writer, budget) = _ex()
        er = ex._build_timing_execution_result(
            samples={
                "baseline": [100.0, 101.0, 99.0],
                "positive": [100.5, 101.5, 99.5],
                "negative": [100.0, 101.0],
                "variant": [],
            },
            statuses=[200] * 8,
            failed_requests=[],
            failure_reason="",
            variant_present=False,
        )
        assert er["timing_measurement_valid"] == "false"
        assert er["reason"] == "timing_pipeline_insensitive"
        assert er["timing_difference_observed"] == "false"


class TestBudgetAccounting:
    def test_request_count_matches_budget_consumption(self):
        (ex, net, writer, budget) = _ex()
        before = budget.snapshot()["requests_used"]
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        assert result.requests_made == 8
        assert len(net.calls) == 8
        assert budget.snapshot()["requests_used"] == before + 8
        assert budget.snapshot()["follow_ups_used"] == 1

    def test_variant_sequence_consumes_its_requests(self):
        (ex, net, writer, budget) = _ex()
        spec = _spec(timing_variant_url="https://api.example.com/variant")
        result = _run(ex.execute(spec))
        assert result.status == EXECUTED
        assert result.requests_made == 11
        assert budget.snapshot()["requests_used"] == 11

    def test_budget_limits_are_respected(self):
        budget = VdpExecutionBudget(
            max_requests=5, per_asset_burst=100, per_hypothesis_burst=100
        )
        (ex, net, writer, _b) = _ex(budget=budget)
        result = _run(ex.execute(_spec()))
        # the sequence consumes budget per request and stops when exhausted
        assert result.status == BLOCKED
        assert "budget" in result.reason
        assert len(net.calls) == 5


class TestAuthAndGuards:
    def test_account_a_session_used_when_credentials_resolve(self):
        (ex, net, writer, budget) = _ex()
        spec = _spec(auth_a_id="acct-a")
        result = _run(ex.execute(spec))
        assert result.status == EXECUTED
        assert len(net.calls) == 8
        for i in range(8):
            assert net.auth_for_call(i) == "secret-a", i
        er = _evidence_of(result)["execution_result"]
        assert er["timing_difference_observed"] == "false"

    def test_anonymous_when_no_auth_ids(self):
        (ex, net, writer, budget) = _ex()
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        for i in range(8):
            assert "headers" not in net.calls[i][1], i

    def test_non_get_spec_still_blocked_by_readonly_guard(self):
        """No regression: a state-changing spec for this gap is still
        rejected by the readonly guard before any network activity."""
        (ex, net, writer, budget) = _ex()
        result = _run(ex.execute(_spec(method="POST")))
        assert result.status == MANUAL_REVIEW
        assert "readonly_guard" in result.reason
        assert len(net.calls) == 0
        assert writer.evidence == []

    def test_variant_out_of_scope_blocks_before_network(self):
        (ex, net, writer, budget) = _ex()
        result = _run(
            ex.execute(_spec(timing_variant_url="https://outside.example.com/x"))
        )
        assert result.status == BLOCKED
        assert result.reason.startswith("scope:")
        assert len(net.calls) == 0


class TestFailureHonesty:
    def test_baseline_non_2xx_recorded_honestly(self):
        net = _TimingNet(status=500)
        (ex, net, writer, budget) = _ex(net=net)
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        er = _evidence_of(result)["execution_result"]
        assert er["timing_measurement_valid"] == "false"
        assert er["timing_difference_observed"] == "false"
        assert er["reason"] == "baseline_failed_status_500"
        assert er["failed_requests"] == [
            {"group": "baseline", "status": 500, "timeout": False}
        ]
        # SGK-2026-0433 followup: the failed response is counted exactly
        # once (1 actual request sent, not 1 status + 1 failure = 2).
        assert er["request_count"] == 1
        assert len(net.calls) == 1
        assert result.verdict_status == "candidate"

    def test_baseline_failure_after_successes_counts_requests_once(self):
        """3 baseline requests with the last one failing → 3 requests sent,
        each counted exactly once (2xx are in ``statuses``, the failed one
        is recorded once with its status)."""
        net = _StatusSequenceNet([200, 200, 500])
        (ex, net, writer, budget) = _ex(net=net)
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        er = _evidence_of(result)["execution_result"]
        assert len(net.calls) == 3
        assert er["request_count"] == 3
        assert er["reason"] == "baseline_failed_status_500"
        assert er["failed_requests"] == [
            {"group": "baseline", "status": 500, "timeout": False}
        ]
        assert er["timing_measurement_valid"] == "false"
        assert er["timing_difference_observed"] == "false"

    def test_baseline_timeout_recorded_honestly(self):
        net = _FailingNet(fail_times=1)
        (ex, net, writer, budget) = _ex(net=net)
        result = _run(ex.execute(_spec()))
        assert result.status == DEGRADED
        assert result.reason == "network_error"
        er = _evidence_of(result)["execution_result"]
        assert er["timing_measurement_valid"] == "false"
        assert er["timing_difference_observed"] == "false"
        assert er["reason"] == "baseline_timeout"
        assert er["failed_requests"] == [
            {"group": "baseline", "status": 0, "timeout": True}
        ]
        assert er["request_count"] == 0  # nothing was received (transport)
        assert _attempt_of(result)["state"] == "failed"
        assert result.verdict_status == "candidate"

    def test_non_timeout_transport_error_never_labeled_timeout(self):
        """A connection-refused (non-timeout) transport exception is
        recorded with its exception class name, never as a fake timeout."""
        net = _RefusingNet()
        (ex, net, writer, budget) = _ex(net=net)
        result = _run(ex.execute(_spec()))
        assert result.status == DEGRADED
        assert result.reason == "network_error"
        er = _evidence_of(result)["execution_result"]
        assert er["timing_measurement_valid"] == "false"
        assert er["timing_difference_observed"] == "false"
        assert er["reason"] == "baseline_transport_error:ConnectionRefusedError"
        assert er["failed_requests"] == [
            {
                "group": "baseline",
                "status": 0,
                "timeout": False,
                "error": "ConnectionRefusedError",
            }
        ]
        assert result.verdict_status == "candidate"


class TestQualityGateSchema:
    def test_record_matches_haddix_timing_schema(self):
        from src.reporting.haddix_evidence_quality import (
            EVIDENCE_TYPE_TIMING,
            HaddixEvidenceQualityValidator,
        )

        (ex, net, writer, budget) = _ex()
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        evidence = _evidence_of(result)
        assert evidence["evidence_type"] == EVIDENCE_TYPE_TIMING
        er = evidence["execution_result"]
        # the timing_samples structure the quality gate validates
        timing_samples = {
            "baseline": er["timing_baseline_samples"],
            "sleep": er["timing_positive_samples"],
            "negative_control": er["timing_negative_control_samples"],
        }
        gaps = HaddixEvidenceQualityValidator._validate_timing_samples(
            timing_samples
        )
        assert gaps == [], gaps
        # dataclass field-name alignment is preserved on the record
        for key in (
            "timing_baseline_samples",
            "timing_positive_samples",
            "timing_negative_control_samples",
            "timing_baseline_median",
            "timing_positive_median",
            "timing_negative_control_median",
        ):
            assert key in er, key
