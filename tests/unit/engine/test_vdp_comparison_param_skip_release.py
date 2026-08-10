"""
SGK-2026-0438 (D) — queue-time exact-replay skip release for comparison gaps.

Sealed-run evidence (session_20260810_012214): 5 attack candidates, 1 fired.
The funnel constraint was the queue-time exact-replay skip in
``_queue_vdp_follow_ups``: 3 candidates were dropped because their
observations carried ``param_names`` (param VALUES are deliberately
discarded at the observation boundary), including two comparison-capable
candidates — hyp-084aab96187f3079 (``authz_impact_not_proven``, ``?name``)
and hyp-ab68264db521553f (``semantic_diff_owner_permission_sensitive_field``,
``?q``).

Release (this task): comparison-type gaps may queue even when param values
were discarded, because the cross-account A/B comparison sends the IDENTICAL
(possibly redacted) URL for both accounts and records truthful
response-difference facts — exact param VALUES are not needed for
truthfulness (the Evidence Validator / marker vocabulary is untouched, so
false confirmed is structurally impossible). Non-comparison gaps keep the
strict skip (payload fidelity required), and the auth-header / cookie skip
stays fail-closed for EVERY gap.

Counterfactual proof: ``test_comparison_gap_with_param_names_is_queued_with_auth_ids``
FAILS on the pre-fix code (candidate skipped, never queued) and PASSES after
the release (candidate queued with ``auth_a_id``/``auth_b_id`` injected and
recorded enforced / matched_shadow).
"""
from __future__ import annotations

import threading
from unittest.mock import MagicMock

import pytest

from src.core.engine.master_conductor import MasterConductor
from src.core.security.ethics_guard import ScopeDefinition


class _StubObservation:
    def __init__(
        self,
        observation_id="obs-1",
        method="GET",
        param_names=(),
        param_locations=(),
        has_auth_header=False,
        has_cookie=False,
    ):
        self.observation_id = observation_id
        self.method = method
        self.param_names = param_names
        self.param_locations = param_locations
        self.has_auth_header = has_auth_header
        self.has_cookie = has_cookie
        self.asset = "https://opaque-target.test/resource"


class _StubGate:
    def effective_stage(self):
        return "m3a"

    def cap_reasons(self):
        return []


def _vdp_state(evidence_gap: str, asset: str) -> dict:
    return {
        "vdp_active": True,
        "hypotheses": [
            {
                "hypothesis_id": "hyp-1",
                "observation_id": "obs-1",
                "asset": asset,
                "capability": "follow_up_probe",
                "actors": ["unauth"],
            }
        ],
        "verdicts": [
            {
                "verdict_id": "vrd-1",
                "hypothesis_id": "hyp-1",
                "status": "candidate",
                "reason_codes": ["generated_candidate"],
            }
        ],
        "next_actions": [
            {
                "next_action_id": "nxt-1",
                "verdict_id": "vrd-1",
                "evidence_gap": evidence_gap,
            }
        ],
        "follow_up_pending": [],
        "follow_up_queued": [],
        "follow_up_failures": [],
        "run_health": {},
    }


def _minimal_mc(
    monkeypatch,
    *,
    evidence_gap: str,
    asset: str = "https://opaque-target.test/resource?name=x",
    param_names=(),
    param_locations=(),
    has_auth_header=False,
    has_cookie=False,
):
    """Minimal MC wired for the REAL ``_queue_vdp_follow_ups`` + REAL
    ``task_queue`` + REAL buffer/drain (same construction pattern as
    ``test_vdp_followup_thread_confinement.py``)."""
    from src.core.engine.task_queue import DynamicTaskQueue

    mc = MasterConductor.__new__(MasterConductor)
    mc.task_queue = DynamicTaskQueue()
    mc._vdp_state = _vdp_state(evidence_gap, asset)
    mc._vdp_mode = MagicMock(mode="readonly_enforce", kill_switch=False)
    mc._vdp_rollout_gate = MagicMock(return_value=_StubGate())
    mc._vdp_diagnostics = None

    def _real_add_tasks(tasks, source="vdp_follow_up"):
        for task in tasks:
            mc.task_queue.add(task)
        return len(tasks)

    mc._add_tasks = _real_add_tasks
    mc._record_vdp_degraded = MagicMock()
    mc._ensure_shadow_decisions = MagicMock(
        side_effect=lambda: mc._vdp_state.setdefault("shadow_decisions", [])
    )
    mc._set_vdp_run_health_degraded = MagicMock()
    mc._vdp_diagnostic_emit = MagicMock()
    mc._ensure_vdp_diagnostics = MagicMock(return_value=None)

    obs = _StubObservation(
        param_names=param_names,
        param_locations=param_locations,
        has_auth_header=has_auth_header,
        has_cookie=has_cookie,
    )
    scope = ScopeDefinition(
        program_name="vdp-follow-up",
        in_scope_domains=["opaque-target.test"],
        out_of_scope_domains=[],
        max_requests_per_minute=60,
    )
    return mc, obs, scope


def _queue_and_drain(mc, obs, scope):
    """Run the production queue path on a WORKER thread (the MC task body —
    incl. ``_queue_vdp_follow_ups`` — runs off-main via ``_run_async_safe``),
    then drain on the MAIN thread (W2 drain point) and return the drained
    count. Mirrors ``test_vdp_followup_thread_confinement.py``."""
    outcome: dict = {}

    def _run():
        try:
            mc._queue_vdp_follow_ups(
                scope_definition=scope,
                checkpoint_path=None,
                observations=[obs],
            )
            outcome["raised"] = None
        except BaseException as exc:  # noqa: BLE001 — capture for assertion
            outcome["raised"] = exc

    worker = threading.Thread(target=_run)
    worker.start()
    worker.join(timeout=30)
    assert not worker.is_alive(), "worker thread hung"
    assert outcome["raised"] is None, f"queue path raised: {outcome['raised']!r}"
    return mc._drain_vdp_pending_follow_up_injections()


class TestComparisonParamSkipRelease:
    def test_comparison_gap_with_param_names_is_queued_with_auth_ids(self, monkeypatch):
        """COUNTERFACTUAL PROOF: a comparison-capable gap (authz_impact_not_proven)
        with discarded param VALUES (param_names non-empty) is queued AFTER the
        release — spec present, auth_a_id/auth_b_id injected, task in the real
        queue, shadow diff enforced/matched_shadow. FAILS on the pre-fix code
        (the exact-replay skip drops the candidate)."""
        monkeypatch.setenv("VDP_ACCOUNT_A_ID", "acct-a")
        monkeypatch.setenv("VDP_ACCOUNT_B_ID", "acct-b")
        mc, obs, scope = _minimal_mc(
            monkeypatch,
            evidence_gap="authz_impact_not_proven",
            param_names=("name",),
            param_locations=("query",),
        )

        drained = _queue_and_drain(mc, obs, scope)

        assert drained >= 1
        pending = mc._vdp_state["follow_up_pending"]
        assert len(pending) == 1
        spec = pending[0]
        assert spec["evidence_gap"] == "authz_impact_not_proven"
        # the URL travels as-is, param fragment included (values discarded)
        assert spec["url"] == "https://opaque-target.test/resource?name=x"
        # Lane P-2: account ids injected for comparison-capable gaps
        assert spec["auth_a_id"] == "acct-a"
        assert spec["auth_b_id"] == "acct-b"
        # enqueued into the REAL queue via the main-thread drain
        assert mc.task_queue.get_by_id(spec["task_id"]) is not None
        assert spec["task_id"] in mc._vdp_state.get("follow_up_queued", [])
        # shadow diff: enforced / matched_shadow
        enforced = [
            e
            for e in mc._vdp_state.get("shadow_diff", [])
            if e.get("next_action_id") == "nxt-1"
        ]
        assert enforced and enforced[-1]["decision"] == "enforced"
        assert enforced[-1]["diff_type"] == "matched_shadow"
        assert mc._vdp_state.get("run_outcome") is None  # no fail-closed marker

    def test_non_comparison_gap_with_param_names_still_skipped(self, monkeypatch):
        """payload_request_mismatch (non-comparison) with discarded param
        VALUES stays skipped — exact replay fidelity still required there."""
        mc, obs, scope = _minimal_mc(
            monkeypatch,
            evidence_gap="payload_request_mismatch",
            param_names=("name",),
            param_locations=("query",),
        )

        drained = _queue_and_drain(mc, obs, scope)

        assert drained == 0
        assert mc._vdp_state["follow_up_pending"] == []
        assert mc._vdp_state["follow_up_queued"] == []
        enforced = [
            e
            for e in mc._vdp_state.get("shadow_diff", [])
            if e.get("decision") == "enforced"
        ]
        assert enforced == []

    def test_comparison_gap_with_cookie_still_skipped(self, monkeypatch):
        """auth context discarded → replay unsafe for EVERY gap: a comparison
        gap with has_cookie=True stays fail-closed (never queued)."""
        mc, obs, scope = _minimal_mc(
            monkeypatch,
            evidence_gap="authz_impact_not_proven",
            param_names=("name",),
            has_cookie=True,
        )

        drained = _queue_and_drain(mc, obs, scope)

        assert drained == 0
        assert mc._vdp_state["follow_up_pending"] == []
        assert mc._vdp_state["follow_up_queued"] == []

    def test_comparison_gap_without_params_still_queued(self, monkeypatch):
        """Regression: the root-URL case (no params, no cookie — the sealed-run
        fired candidate shape) still queues after the release."""
        monkeypatch.setenv("VDP_ACCOUNT_A_ID", "acct-a")
        monkeypatch.setenv("VDP_ACCOUNT_B_ID", "acct-b")
        mc, obs, scope = _minimal_mc(
            monkeypatch,
            evidence_gap="authz_impact_not_proven",
            asset="https://opaque-target.test/resource",
        )

        drained = _queue_and_drain(mc, obs, scope)

        assert drained >= 1
        spec = mc._vdp_state["follow_up_pending"][0]
        assert spec["url"] == "https://opaque-target.test/resource"
        assert mc.task_queue.get_by_id(spec["task_id"]) is not None

    def test_comparison_spec_on_param_bearing_url_sends_two_requests(self):
        """Executor-level proof: a queued comparison spec on a param-bearing
        URL produces a cross-account comparison — 2 authenticated requests,
        the URL sent AS-IS (param fragment intact), truthful facts recorded.
        Reuses the transport-injection pattern from test_vdp_cross_account.py."""
        from tests.unit.engine.test_vdp_cross_account import (
            _AuthNet,
            _ex,
            _run,
            _spec,
        )
        from src.core.engine.vdp_follow_up_executor import EXECUTED

        spec = _spec(
            gap="authz_impact_not_proven",
            url="https://api.example.com/records/42?name=x",
            param_names=["name"],
        )
        net = _AuthNet(
            account_table={
                "secret-a": {"status": 200, "body": '{"owner":"acct-a","sensitive":"X"}'},
                "secret-b": {"status": 200, "body": '{"owner":"acct-a","sensitive":"X"}'},
            }
        )
        (ex, net, writer, budget) = _ex(net=net)
        result = _run(ex.execute(spec))

        assert result.status == EXECUTED
        assert result.requests_made == 2
        assert net.count == 2
        # the URL is sent as-is, param fragment included, for BOTH accounts
        assert net.calls[0][0][1] == "https://api.example.com/records/42?name=x"
        assert net.calls[1][0][1] == "https://api.example.com/records/42?name=x"
        assert result.evidence is not None
        er = result.evidence["execution_result"]
        assert er["cross_account_compared"] is True
        assert er["request_count"] == 2
