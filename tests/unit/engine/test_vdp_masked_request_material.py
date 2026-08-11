"""
SGK-2026-0439 — masked request material (mask at ingest / restore at send).

The VDP attack path previously dropped param-dependent follow-ups
(payload_request_mismatch, injection-style gaps) because param VALUES were
discarded at the observation boundary and never recoverable. This task
routes the path through PIIMasker: the RAW request URL is masked at ingest
(``masked_request_url`` on the Observation — values preserved inside
tokens), the follow-up spec carries only the MASKED url, and the executor
restores the exact values at the send boundary (fail-closed when a token
cannot be resolved).

Invariants covered here:
- observation_id is UNCHANGED by the additive masked_request_url field
  (determinism invariant — the canonical payload excludes it).
- The queue-time skip releases ONLY when material is preserved.
- S07 blocks only genuinely material-less payload_request_mismatch specs.
- The executor sends the RESTORED url; the fingerprint keeps the normalized
  (values-free) spec url.
- Unresolvable tokens fail closed with ZERO network calls.
- 0438 comparison release / auth-cookie skip regressions stay green.
"""
from __future__ import annotations

import threading
from unittest.mock import MagicMock

import pytest

from src.core.engine.master_conductor import MasterConductor
from src.core.security.ethics_guard import ScopeDefinition
from src.core.security.pii_masker import PIIMasker


class _StubObservation:
    def __init__(
        self,
        observation_id="obs-1",
        method="GET",
        param_names=(),
        param_locations=(),
        has_auth_header=False,
        has_cookie=False,
        masked_request_url=None,
    ):
        self.observation_id = observation_id
        self.method = method
        self.param_names = param_names
        self.param_locations = param_locations
        self.has_auth_header = has_auth_header
        self.has_cookie = has_cookie
        self.masked_request_url = masked_request_url


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


def _minimal_mc(monkeypatch, *, evidence_gap, observation):
    """Minimal MC wired for the REAL ``_queue_vdp_follow_ups`` + REAL
    ``task_queue`` + REAL buffer/drain (same construction pattern as
    test_vdp_followup_thread_confinement.py / test_vdp_comparison_param_skip_release.py)."""
    from src.core.engine.task_queue import DynamicTaskQueue

    mc = MasterConductor.__new__(MasterConductor)
    mc.task_queue = DynamicTaskQueue()
    mc._vdp_state = _vdp_state(evidence_gap, "https://opaque-target.test/resource?name=x")
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
    scope = ScopeDefinition(
        program_name="vdp-follow-up",
        in_scope_domains=["opaque-target.test"],
        out_of_scope_domains=[],
        max_requests_per_minute=60,
    )
    return mc, scope


def _queue_and_drain(mc, obs, scope):
    """Run the queue path on a WORKER thread (production topology), then
    drain on the MAIN thread and return the drained count."""
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


class TestObservationDeterminism:
    def test_observation_id_unchanged_by_masked_request_url(self):
        """The additive masked_request_url field MUST NOT change the
        observation_id (excluded from the canonical payload)."""
        from src.core.engine.vdp_observation_adapter import ObservationAdapter

        signal = {
            "url": "http://x/search?q=test&id=12345",
            "method": "GET",
            "entity_type": "endpoint",
            "primary_label": "search",
            "params": [
                {"name": "q", "location": "query"},
                {"name": "id", "location": "query"},
            ],
        }
        plain = ObservationAdapter().adapt_endpoint_signal(signal)
        masked = ObservationAdapter(masker=PIIMasker()).adapt_endpoint_signal(signal)

        assert plain is not None and masked is not None
        assert plain.observation_id == masked.observation_id
        assert plain.masked_request_url is None  # fail-closed default
        assert masked.masked_request_url is not None
        assert "q=test" not in masked.masked_request_url
        # normalized url (values-free) is identical for both
        assert plain.url == masked.url


class TestQueueRelease:
    def test_payload_request_mismatch_with_material_queued_without_skipped(self):
        """payload_request_mismatch + param_names: queued WHEN the observation
        carries masked_request_url; still skipped when it does not."""
        from src.core.security.pii_masker import PIIMasker

        masker = PIIMasker()
        masked = masker.mask_url_query_values(
            "https://opaque-target.test/resource?name=x"
        )

        # WITH material → queued
        obs = _StubObservation(
            param_names=("name",),
            param_locations=("query",),
            masked_request_url=masked,
        )
        mc, scope = _minimal_mc(
            pytest.MonkeyPatch(),
            evidence_gap="payload_request_mismatch",
            observation=obs,
        )
        drained = _queue_and_drain(mc, obs, scope)
        assert drained >= 1
        spec = mc._vdp_state["follow_up_pending"][0]
        assert spec["masked_request_url"] == masked
        assert mc.task_queue.get_by_id(spec["task_id"]) is not None

        # WITHOUT material → still skipped (regression: 0434 behavior)
        obs2 = _StubObservation(param_names=("name",), param_locations=("query",))
        mc2, scope2 = _minimal_mc(
            pytest.MonkeyPatch(),
            evidence_gap="payload_request_mismatch",
            observation=obs2,
        )
        drained2 = _queue_and_drain(mc2, obs2, scope2)
        assert drained2 == 0
        assert mc2._vdp_state["follow_up_pending"] == []

    def test_auth_cookie_skip_applies_even_with_material(self):
        """has_cookie=True stays fail-closed for EVERY gap even when the
        observation carries masked_request_url (auth context discarded)."""
        masker = PIIMasker()
        masked = masker.mask_url_query_values(
            "https://opaque-target.test/resource?name=x"
        )
        obs = _StubObservation(
            param_names=("name",),
            has_cookie=True,
            masked_request_url=masked,
        )
        mc, scope = _minimal_mc(
            pytest.MonkeyPatch(),
            evidence_gap="payload_request_mismatch",
            observation=obs,
        )
        drained = _queue_and_drain(mc, obs, scope)
        assert drained == 0
        assert mc._vdp_state["follow_up_pending"] == []

    def test_comparison_gap_release_still_queues_with_and_without_material(self):
        """0438 release regression: comparison gaps with params queue both
        with and without masked material; the spec carries the masked url
        when present."""
        masker = PIIMasker()
        masked = masker.mask_url_query_values(
            "https://opaque-target.test/resource?name=x"
        )
        for obs in (
            _StubObservation(
                param_names=("name",), masked_request_url=masked
            ),
            _StubObservation(param_names=("name",)),  # no material (0438 case)
        ):
            mc, scope = _minimal_mc(
                pytest.MonkeyPatch(),
                evidence_gap="authz_impact_not_proven",
                observation=obs,
            )
            drained = _queue_and_drain(mc, obs, scope)
            assert drained >= 1, "comparison gap must still queue"
            spec = mc._vdp_state["follow_up_pending"][0]
            assert spec.get("masked_request_url") == (
                masked if obs.masked_request_url else None
            )


class TestExecutorSendBoundary:
    def test_s07_blocks_material_less_payload_spec(self):
        """Regression: a payload_request_mismatch spec WITHOUT masked material
        is blocked at S07 (exact_request_material_unavailable)."""
        import asyncio

        from src.core.engine.vdp_follow_up_executor import MANUAL_REVIEW
        from tests.unit.engine.test_vdp_cross_account import _ex, _run, _spec

        spec = _spec(gap="payload_request_mismatch")
        (ex, net, writer, budget) = _ex()
        result = _run(ex.execute(spec))
        assert result.status == MANUAL_REVIEW
        assert result.reason == "exact_request_material_unavailable"
        assert net.count == 0

    def test_executor_sends_restored_url_with_original_values(self):
        """A payload_request_mismatch spec WITH masked material passes S07,
        the fingerprint check (normalized url, values-free), and the send
        boundary sends the RESTORED url with the original query values."""
        from src.core.engine.vdp_follow_up_executor import (
            EXECUTED,
            build_request_fingerprint,
        )
        from tests.unit.engine.test_vdp_cross_account import _AuthNet, _ex, _run, _spec

        masker = PIIMasker()
        masked = masker.mask_url_query_values(
            "https://api.example.com/records/42?name=x"
        )
        spec = _spec(
            gap="payload_request_mismatch",
            url="https://api.example.com/records/42",  # normalized (values-free)
            param_names=["name"],
            masked_request_url=masked,
            # the fingerprint is built from the NORMALIZED url — values never
            # enter it (Constraint J)
            expected_request_fingerprint=build_request_fingerprint(
                "GET",
                "https://api.example.com/records/42",
                ("name",),
            ),
        )
        net = _AuthNet()
        (ex, net, writer, budget) = _ex(net=net, pii_masker=masker)
        result = _run(ex.execute(spec))

        assert result.status == EXECUTED
        assert net.count == 1
        # the RESTORED url (original values) reached the transport
        assert net.calls[0][0][1] == "https://api.example.com/records/42?name=x"
        # SGK-2026-0439: the restored url is the request TARGET only — the
        # network client receives the MASKED url for every log line
        # (log_safe_url), never the restored values.
        assert net.calls[0][1].get("log_safe_url") == masked
        assert net.calls[0][1].get("log_safe_url") != "https://api.example.com/records/42?name=x"
        # the fingerprint stays the NORMALIZED (values-free) spec url —
        # values never enter the fingerprint (Constraint J)
        assert result.attempt is not None
        assert result.attempt["request_fingerprint"] == spec["expected_request_fingerprint"]

    def test_executor_passes_values_free_url_as_log_safe_url_without_material(self):
        """Without masked material the send boundary passes the NORMALIZED
        (values-free) spec url as log_safe_url — never a restored url."""
        from src.core.engine.vdp_follow_up_executor import EXECUTED
        from tests.unit.engine.test_vdp_cross_account import _AuthNet, _ex, _run, _spec

        spec = _spec(gap="authz_impact_not_proven")
        net = _AuthNet()
        (ex, net, writer, budget) = _ex(net=net)
        result = _run(ex.execute(spec))

        assert result.status == EXECUTED
        assert net.count == 2  # comparison path: A then B
        for call in net.calls:
            # the request target stays the normalized values-free url
            assert call[0][1] == "https://api.example.com/records/42"
            # ... and so does the log_safe_url (no material to restore)
            assert call[1].get("log_safe_url") == "https://api.example.com/records/42"

    def test_executor_fail_closed_on_unresolved_token(self):
        """Unresolvable token (e.g. resumed spec whose run-scoped token map
        is gone): NO network call, MANUAL_REVIEW."""
        from src.core.engine.vdp_follow_up_executor import MANUAL_REVIEW
        from tests.unit.engine.test_vdp_cross_account import _AuthNet, _ex, _run, _spec

        masker_a = PIIMasker()
        masked = masker_a.mask_url_query_values(
            "https://api.example.com/records/42?name=x"
        )
        masker_b = PIIMasker()  # empty token map — cannot resolve
        spec = _spec(
            gap="payload_request_mismatch",
            url="https://api.example.com/records/42",
            masked_request_url=masked,
        )
        net = _AuthNet()
        (ex, net, writer, budget) = _ex(net=net, pii_masker=masker_b)
        result = _run(ex.execute(spec))

        assert result.status == MANUAL_REVIEW
        assert "masked_request_material_unresolvable" in result.reason
        assert net.count == 0
