"""
SGK-2026-0426 W2 — generic reproduction of the PCR-P1 thread-confinement
crash (follow-up enqueue from a worker thread) and its fix (deferred
injection buffer + main-thread drain).

Reproduction (product-independent):
- The MC executes task bodies (incl. ``_generate_vdp_hypotheses`` ->
  ``_queue_vdp_follow_ups``) on the SharedLoopManager background thread.
- ``_queue_vdp_follow_ups`` mutates the task_queue from that thread ->
  ``task_queue.add`` PCR-P1 assert fires -> S05 failed
  (``follow_up_enqueue_failed``) and attempts stay 0 (0427 session evidence).

Fix contract (approved §3.1 W2):
- The worker part only builds specs and buffers them; the queue mutation
  happens in ``_drain_vdp_pending_follow_up_injections()`` on the MAIN
  thread (drain points: ``_apply_post_batch_feedback`` /
  ``execute_single_task`` / resume path). The drain carries a PCR-P1-style
  main-thread assert (fail-closed; task_queue asserts untouched).

This test fails BEFORE the fix (crash reproduced: S05 failed, tasks not
queued) and passes AFTER (S04/S05 reached, tasks queued via main-thread
drain). It also self-verifies: if the drain ever runs off the main thread,
its own assert turns the test red.
"""
from __future__ import annotations

import threading
from unittest.mock import MagicMock

import pytest

from src.core.engine.master_conductor import MasterConductor
from src.core.models.vdp_contract import ExecutionBudgetV1


class _StubObservation:
    def __init__(self, observation_id="obs-1", method="GET"):
        self.observation_id = observation_id
        self.method = method
        self.param_names = ()
        self.param_locations = ()
        self.has_auth_header = False
        self.has_cookie = False
        self.asset = "https://opaque-target.test/resource"


class _StubGate:
    def effective_stage(self):
        return "m3a"

    def cap_reasons(self):
        return []


def _minimal_mc(monkeypatch):
    """Minimal MC wired for the real ``_queue_vdp_follow_ups`` + real
    ``task_queue`` (PCR-P1 is enforced by the REAL queue object)."""
    from src.core.engine.task_queue import DynamicTaskQueue
    from src.core.security.ethics_guard import ScopeDefinition

    mc = MasterConductor.__new__(MasterConductor)
    mc.task_queue = DynamicTaskQueue()
    mc._vdp_state = {
        "vdp_active": True,
        "hypotheses": [
            {
                "hypothesis_id": "hyp-1",
                "observation_id": "obs-1",
                "asset": "https://opaque-target.test/resource",
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
                "evidence_gap": "payload_request_mismatch",
            }
        ],
        "follow_up_pending": [],
        "follow_up_queued": [],
        "follow_up_failures": [],
        "run_health": {},
    }
    mc._vdp_mode = MagicMock(mode="readonly_enforce", kill_switch=False)
    mc._vdp_rollout_gate = MagicMock(return_value=_StubGate())
    mc._vdp_diagnostics = None
    # The ONLY queue mutation used by this path is task_queue.add; patch
    # _add_tasks to the real PCR-P1-critical line so the test stays fast
    # without dragging the whole priority/strategy machinery.
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


def _enqueue_from_thread(mc, scope):
    """Drive the production topology: the follow-up enqueue runs on a
    NON-main thread (SharedLoopManager equivalent)."""
    outcome: dict = {}

    def _run():
        try:
            mc._queue_vdp_follow_ups(
                scope_definition=scope,
                checkpoint_path=None,
                observations=[_StubObservation()],
            )
            outcome["raised"] = None
        except BaseException as exc:  # noqa: BLE001 — capture for assertion
            outcome["raised"] = exc

    worker = threading.Thread(target=_run)
    worker.start()
    worker.join(timeout=30)
    assert not worker.is_alive(), "worker thread hung"
    return outcome


class TestThreadConfinementReproduction:
    def test_follow_up_enqueue_via_worker_thread_queues_tasks(self):
        """FIXED behavior: the worker thread only buffers the injection; the
        main-thread drain (batch-feedback phase) performs the queue mutation
        (S04/S05 reached, tasks actually queued). FAILS before the fix
        (PCR-P1 crash -> S05 failed, 0 tasks queued)."""
        mc, scope = _minimal_mc(pytest.MonkeyPatch())
        outcome = _enqueue_from_thread(mc, scope)
        assert outcome["raised"] is None
        # production-equivalent main-thread phase (batch feedback drain)
        drained = mc._drain_vdp_pending_follow_up_injections()
        assert drained >= 1
        # tasks landed in the real queue via the main-thread drain
        assert any(
            mc.task_queue.get_by_id(s["task_id"]) is not None
            for s in mc._vdp_state.get("follow_up_pending", [])
        )
        assert mc._vdp_state.get("run_outcome") is None  # no fail-closed marker

    def test_drain_asserts_main_thread(self):
        """The drain itself carries the PCR-P1-style main-thread assert —
        calling it from a worker thread fails closed (self-checking)."""
        mc, _scope = _minimal_mc(pytest.MonkeyPatch())
        from src.core.security.ethics_guard import ScopeDefinition

        scope = ScopeDefinition(
            program_name="vdp-follow-up",
            in_scope_domains=["opaque-target.test"],
            out_of_scope_domains=[],
            max_requests_per_minute=60,
        )
        _enqueue_from_thread(mc, scope)
        # buffer holds the deferred injection
        buffer = mc._ensure_vdp_follow_up_inject_buffer()
        assert len(buffer["items"]) >= 1

        error: list[BaseException] = []

        def _drain_off_main():
            try:
                mc._drain_vdp_pending_follow_up_injections()
            except BaseException as exc:  # noqa: BLE001 — test capture
                error.append(exc)

        worker = threading.Thread(target=_drain_off_main)
        worker.start()
        worker.join(timeout=30)
        assert len(error) == 1
        assert isinstance(error[0], AssertionError)
        assert "main thread" in str(error[0])
