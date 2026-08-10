"""
SGK-2026-0431 — off-main VDP follow-up drain delegation guard.

Problem (0437 sealed run evidence): ``_execute_single_task_full_flow`` ran on
a ParallelOrchestrator ThreadPoolExecutor worker thread (via
``create_parallel_task`` -> ``loop.run_in_executor``) and its UNGUARDED
``_drain_vdp_pending_follow_up_injections()`` call fired the PCR-P1-style
main-thread assert (``recon_master`` task critical failure -> recon
truncation).

Fix (SGK-2026-0431): the drain call in ``_execute_single_task_full_flow`` is
now guarded with the SAME main-thread pattern as the W2 producer guard in
``_queue_vdp_follow_ups`` (L11692-11695):

- on the MAIN thread (serial dispatch / timeout-recovery paths): drain
  synchronously — pre-0431 behavior, regression 0;
- off-main (parallel executor worker): do NOT drain — the buffered
  injections stay in ``_vdp_pending_follow_up_injections`` and are delegated
  to the main-thread drain inside ``_apply_post_batch_feedback``
  (``execute_with_replan`` batch join, L6702), which runs after every batch
  (including parallel batches) on the main thread.

The drain itself (``_drain_vdp_pending_follow_up_injections``) keeps its
PCR-P1 assert (L11724) UNTOUCHED — this test suite is self-checking: if the
guard regresses, the off-main flow re-fires the assert and the tests turn
red.

Construction pattern reuses ``test_vdp_followup_thread_confinement.py``
(real ``DynamicTaskQueue`` + real buffer + real drain, ``__new__``-based MC)
and ``test_mc_vdp_drain_main_thread.py`` (``safe_run_async`` /
SharedLoopManager off-main premise).
"""
from __future__ import annotations

import threading
from unittest.mock import MagicMock

import pytest

from src.core.engine.master_conductor import MasterConductor
from src.core.domain.model.task import Task


class _StubGate:
    def effective_stage(self):
        return "m3a"

    def cap_reasons(self):
        return []


def _minimal_mc(monkeypatch):
    """Minimal MC that can run the REAL ``_execute_single_task_full_flow``
    (with a stubbed ``_dispatch_with_timeout_retry``) plus the REAL
    VDP injection buffer + REAL main-thread drain + REAL ``task_queue``.

    The ONLY queue mutation used by the stubbed flow is the drain's
    ``_add_tasks`` -> ``task_queue.add`` (PCR-P1 enforced by the REAL queue
    object), mirroring ``test_vdp_followup_thread_confinement.py``."""
    from src.core.engine.task_queue import DynamicTaskQueue
    from src.core.security.ethics_guard import ScopeDefinition

    mc = MasterConductor.__new__(MasterConductor)
    mc._state_lock = threading.RLock()
    mc.task_queue = DynamicTaskQueue()
    mc.workspace = MagicMock()
    mc.accumulated_context = MagicMock()
    mc.accumulated_context.is_empty.return_value = True
    mc.context_designer = MagicMock(
        side_effect=lambda task, context, accumulated, workspace=None: task
    )
    mc.context = MagicMock()
    mc.context.target_info = {}
    mc.execution_log = MagicMock()
    mc.risk_predictor = MagicMock()
    mc.risk_predictor.assess.return_value = MagicMock(
        should_proceed=True, recommended_delay=0, risk_level="low", risk_score=0.1,
        to_dict=lambda: {},
    )
    mc.diff_analyzer = MagicMock()
    mc.graph = MagicMock()

    # Early gates: pass through to the drain site.
    mc._reject_invalid_task_snapshot_at_start = MagicMock(return_value=None)
    mc._evaluate_phase7_state_assertion_before_start = MagicMock(return_value=None)
    mc._run_intervention_precheck = MagicMock(return_value=None)
    # The task body itself is NOT part of this test — stub dispatch so the
    # flow reaches the drain guard at L7667.
    mc._dispatch_with_timeout_retry = MagicMock(
        return_value={
            "success": True,
            "task_id": "t1",
            "message": "ok",
            "data": {},
            "findings": [],
        }
    )

    # Post-drain bookkeeping (success path).
    mc._emit_task_state_event = MagicMock()
    mc._update_flaky_quarantine = MagicMock(return_value={})
    mc.decision_enhancer = MagicMock()
    mc.critical_path_analyzer = MagicMock()
    mc.critical_path_analyzer.analyze.return_value = []
    mc.priority_booster = MagicMock()
    mc.priority_booster.auto_detect_boost.return_value = None
    mc._observe_and_rethink = MagicMock(return_value=[])
    mc.context_propagator = MagicMock()
    mc.check_hitl_required = MagicMock(return_value=None)
    mc._mark_pending_hitl_done = MagicMock()
    mc._record_task_prioritizer_outcome = MagicMock()

    # VDP state + the ONLY queue mutation used by this path is
    # task_queue.add via the drain; patch _add_tasks to the real
    # PCR-P1-critical line so the test stays fast.
    mc._vdp_state = {
        "follow_up_pending": [],
        "follow_up_queued": [],
        "follow_up_failures": [],
        "run_health": {},
    }
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
    # The task body emits TASK_STARTED via the event bus singleton; patch it
    # so the flow is hermetic and runs off-main without shared state.
    monkeypatch.setattr(
        "src.core.infra.event_bus.get_event_bus",
        MagicMock(return_value=MagicMock()),
    )

    scope = ScopeDefinition(
        program_name="vdp-follow-up",
        in_scope_domains=["opaque-target.test"],
        out_of_scope_domains=[],
        max_requests_per_minute=60,
    )
    return mc, scope


def _buffer_follow_up_batch(mc, task_id="fu-1"):
    """Append one (tasks, pending) batch to the real W2 injection buffer,
    exactly as the off-main producer (``_queue_vdp_follow_ups``) does."""
    spec = {
        "task_id": task_id,
        "next_action_id": "nxt-1",
        "evidence_gap": "payload_request_mismatch",
    }
    follow_up_task = Task(
        id=task_id,
        name=f"vdp_follow_up:{spec['evidence_gap']}",
        agent_type="vdp_follow_up",
        action="run",
        params={"vdp_follow_up_spec": spec},
    )
    buffer = mc._ensure_vdp_follow_up_inject_buffer()
    with buffer["lock"]:
        buffer["items"].append({"tasks": [follow_up_task], "pending": [spec]})
    return spec


def _run_full_flow_off_main(mc, task):
    """Drive the production parallel topology: the task body
    (``_execute_single_task_full_flow``) runs on a NON-main thread
    (ThreadPoolExecutor worker equivalent), capturing the outcome."""
    outcome: dict = {}

    def _run():
        try:
            result = mc._execute_single_task_full_flow(task)
            outcome["result"] = result
            outcome["raised"] = None
        except BaseException as exc:  # noqa: BLE001 — capture for assertion
            outcome["raised"] = exc

    worker = threading.Thread(target=_run)
    worker.start()
    worker.join(timeout=30)
    assert not worker.is_alive(), "worker thread hung"
    return outcome


def _make_flow_task(task_id="t1"):
    from tests.core.engine.test_master_conductor_phase5_parallelism import _make_task

    return _make_task(task_id, "scanner")


class TestOffMainDrainDelegation:
    def test_off_main_full_flow_does_not_assert_and_buffers(self, monkeypatch):
        """FIXED behavior: the drain in ``_execute_single_task_full_flow``
        is skipped off-main (parallel executor worker), so the PCR-P1 assert
        inside the drain is never fired and the buffered injection batch is
        preserved. FAILS before the fix (drain assert -> flow raises)."""
        mc, _scope = _minimal_mc(monkeypatch)
        spec = _buffer_follow_up_batch(mc)
        # Spy on the REAL drain: records every invocation thread.
        drain_calls: list = []
        orig_drain = MasterConductor._drain_vdp_pending_follow_up_injections

        def _spy(self):
            drain_calls.append(threading.current_thread())
            return orig_drain(self)

        monkeypatch.setattr(
            MasterConductor, "_drain_vdp_pending_follow_up_injections", _spy
        )

        outcome = _run_full_flow_off_main(mc, _make_flow_task())

        assert outcome["raised"] is None, f"off-main flow raised: {outcome['raised']!r}"
        assert outcome["result"].get("success") is True
        # The drain must NOT have run off-main (guard active) -> no assert.
        assert drain_calls == [], "drain was invoked off-main"
        # Buffer preserved: the batch is still pending, nothing queued.
        buffer = mc._ensure_vdp_follow_up_inject_buffer()
        with buffer["lock"]:
            assert len(buffer["items"]) == 1
        assert mc.task_queue.get_by_id(spec["task_id"]) is None

    def test_main_thread_batch_feedback_drains_buffered_items(self, monkeypatch):
        """After the off-main flow buffered the injection, the main-thread
        ``_apply_post_batch_feedback`` drain (L6702, execute_with_replan
        batch join) drains it: S04/S05 reached and the follow-up task lands
        in the real queue (mirrors
        test_vdp_followup_thread_confinement.py L155-161)."""
        mc, _scope = _minimal_mc(monkeypatch)
        spec = _buffer_follow_up_batch(mc)
        # Off-main flow first (guard active, nothing drained).
        outcome = _run_full_flow_off_main(mc, _make_flow_task())
        assert outcome["raised"] is None

        # Main-thread batch-join feedback phase (execute_with_replan L7391).
        mc._apply_post_batch_feedback([], [])

        # tasks landed in the real queue via the main-thread drain
        assert mc.task_queue.get_by_id(spec["task_id"]) is not None
        assert spec["task_id"] in mc._vdp_state.get("follow_up_queued", [])
        assert mc._vdp_state.get("run_outcome") is None  # no fail-closed marker

    def test_recon_body_via_safe_run_async_does_not_critical_fail(self, monkeypatch):
        """The recon/_dispatch task body runs via ``_run_async_safe`` on the
        ShigokuSharedLoop background thread (safe_run_async). A task body
        exercising the drain call must NOT raise when run off-main there
        (premise mirrored from test_mc_vdp_drain_main_thread.py)."""
        mc, _scope = _minimal_mc(monkeypatch)
        spec = _buffer_follow_up_batch(mc)
        task = _make_flow_task()
        main_ident = threading.get_ident()
        body_ident: list[int] = []

        async def _task_body():
            body_ident.append(threading.get_ident())
            return mc._execute_single_task_full_flow(task)

        # Production-equivalent off-main execution on the shared loop.
        result = mc._run_async_safe(_task_body(), timeout_override=60)

        assert body_ident and body_ident[0] != main_ident, "body must run off-main"
        assert result.get("success") is True
        # Buffer preserved — nothing drained off-main by the shared-loop body.
        buffer = mc._ensure_vdp_follow_up_inject_buffer()
        with buffer["lock"]:
            assert len(buffer["items"]) == 1
        assert mc.task_queue.get_by_id(spec["task_id"]) is None
        # Main-thread drain still completes the delegation.
        mc._apply_post_batch_feedback([], [])
        assert mc.task_queue.get_by_id(spec["task_id"]) is not None


# =====================================================================
# Gap #3 — exception-path drain confluence (plan completion condition 3:
# "injection 滞留・喪失を作らない"). The execute_with_replan batch-exception
# handler must drain buffered VDP follow-up injections + off-main task
# batches on the main thread BEFORE `continue`, regardless of the exception
# type / recovery outcome.
# =====================================================================


def _minimal_execute_mc(monkeypatch):
    """Minimal MC that can run the REAL ``execute_with_replan`` loop with a
    stubbed ``_dispatch_batch`` that RAISES a non-timeout exception, plus the
    REAL VDP injection buffer + REAL off-main task buffer + REAL drains +
    REAL ``task_queue`` (same construction pattern as ``_minimal_mc``)."""
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from src.core.engine.task_queue import DynamicTaskQueue

    async def _noop():
        return None

    class _StubGateFacade:
        async def run_once(self, ctx):
            return SimpleNamespace(failed=False, failures=[])

    mc = MasterConductor.__new__(MasterConductor)
    mc._state_lock = threading.RLock()
    mc.task_queue = DynamicTaskQueue()
    mc.completed_tasks = []
    mc._shutdown_requested = False
    mc._auto_checkpoint = False
    mc.context = MagicMock()
    mc.context.metrics = {"start_time": None}
    mc.context.target_info = {}
    mc.writer = MagicMock()
    mc.writer.start.return_value = _noop()
    mc.resource_manager = MagicMock()
    mc.resource_manager.get_suggested_concurrency.return_value = 5
    mc.optimizer = MagicMock()
    mc.optimizer.should_review.return_value = False

    # VDP + off-main task buffers are REAL (that is what the exception path
    # must drain); the ONLY queue mutation used here is _add_tasks ->
    # task_queue.add via the drains (PCR-P1 enforced by the REAL queue).
    mc._vdp_state = {
        "follow_up_pending": [],
        "follow_up_queued": [],
        "follow_up_failures": [],
        "run_health": {},
    }

    def _real_add_tasks(tasks, source="vdp_follow_up"):
        for task in tasks:
            mc.task_queue.add(task)
        return len(tasks)

    mc._add_tasks = _real_add_tasks
    mc._vdp_diagnostic_emit = MagicMock()
    mc._record_vdp_follow_up_enqueue_failure = MagicMock()
    mc._set_vdp_run_health_degraded = MagicMock()
    mc._ensure_shadow_decisions = MagicMock(
        side_effect=lambda: mc._vdp_state.setdefault("shadow_decisions", [])
    )

    # Loop machinery: stubs that keep the single-iteration exception path.
    mc._build_preflight_context = MagicMock(return_value={})
    monkeypatch.setattr(
        "src.core.engine.master_conductor.EntryGateFacade",
        lambda: _StubGateFacade(),
    )
    mc._sync_task_queue_snapshot_versions = MagicMock()
    mc._terminalize_dependency_deadlock = MagicMock(return_value=False)
    mc._record_failure_context = MagicMock()
    mc._generate_summary = MagicMock(
        return_value={
            "outcome_status": "succeeded",
            "total_tasks": 1,
            "success": 0,
            "failed": 1,
            "skipped": 0,
            "replanned": 0,
            "success_rate": 0.0,
            "discovered_assets": [],
            "estimated_cost": 0.0,
            "coverage_gate_passed": True,
            "coverage_gate_covered": 0,
            "coverage_gate_required": 0,
            "coverage_gate_missing": [],
            "scenario_covered": 0,
            "scenario_required": 0,
            "scenario_missing": [],
            "pending_hitl_count": 0,
            "failed_reason_codes": {},
            "skipped_reason_codes": {},
        }
    )
    mc.save_session = MagicMock()
    # Avoid rich console output from the loop.
    monkeypatch.setattr("src.core.logger.logger", MagicMock())
    return mc


class TestExceptionPathDrainConfluence:
    def test_exception_path_drains_buffered_injections_before_continue(self, monkeypatch):
        """Gap #3: a non-timeout batch exception (``_dispatch_batch`` raises)
        must STILL drain the buffered VDP follow-up injections and the
        buffered off-main task batches on the main thread before the loop
        continues — FAILS before the fix (buffer left stranded past loop
        end: tasks never appear in the queue)."""
        from tests.core.engine.test_master_conductor_phase5_parallelism import _make_task

        mc = _minimal_execute_mc(monkeypatch)
        spec = _buffer_follow_up_batch(mc)  # VDP follow-up batch (fu-1)
        # Off-main generic task batch (aux-1) produced from a worker thread.
        aux_task = _make_task("aux-1", "scanner")
        worker_outcome: dict = {}

        def _produce_off_main():
            try:
                worker_outcome["added"] = mc._add_tasks_main_safe(
                    [aux_task], source="recon.permutation"
                )
                worker_outcome["raised"] = None
            except BaseException as exc:  # noqa: BLE001 — capture for assertion
                worker_outcome["raised"] = exc

        worker = threading.Thread(target=_produce_off_main)
        worker.start()
        worker.join(timeout=30)
        assert worker_outcome.get("raised") is None
        assert worker_outcome.get("added") == 0  # buffered, not enqueued

        # The batch execution raises a NON-timeout exception. The batch task
        # must be IN the queue so the loop proceeds past the empty-queue break.
        mc.task_queue.add(_make_task("t1", "scanner"))
        mc._dispatch_batch = MagicMock(side_effect=RuntimeError("boom"))
        mc._select_next_task_from_queue = MagicMock(
            side_effect=[_make_task("t1", "scanner")] + [None] * 10
        )

        summary = mc.execute_with_replan()

        # Exception path taken, loop completed without propagating.
        assert mc._dispatch_batch.called
        assert summary.get("outcome_status") == "succeeded"
        # Buffered VDP follow-up drained on main before `continue`.
        assert mc.task_queue.get_by_id(spec["task_id"]) is not None
        assert spec["task_id"] in mc._vdp_state.get("follow_up_queued", [])
        assert mc._vdp_state.get("run_outcome") is None  # no fail-closed marker
        # Buffered off-main task drained at the same confluence.
        assert mc.task_queue.get_by_id("aux-1") is not None


# =====================================================================
# Gap #4 — uniform off-main task_queue mutation delegation: the safe entry
# ``_add_tasks_main_safe`` buffers off-main and enqueues at the main-thread
# confluence ``_apply_post_batch_feedback``; main-thread callers behave
# exactly as before (regression 0).
# =====================================================================


class TestOffMainTaskBufferDelegation:
    def test_main_thread_safe_entry_enqueues_immediately_and_off_main_buffers(self, monkeypatch):
        """Gap #4a: on the MAIN thread ``_add_tasks_main_safe`` enqueues
        immediately (regression 0, real added count). Off-main (worker
        thread) it does NOT assert, does NOT mutate the queue, and buffers;
        the subsequent main-thread ``_apply_post_batch_feedback`` enqueues
        the buffered tasks."""
        from tests.core.engine.test_master_conductor_phase5_parallelism import _make_task

        mc, _scope = _minimal_mc(monkeypatch)
        task_main = _make_task("m-1", "scanner")
        task_off = _make_task("w-1", "scanner")

        # Main thread: immediate enqueue (regression 0).
        added = mc._add_tasks_main_safe([task_main], source="test_main")
        assert added == 1
        assert mc.task_queue.get_by_id("m-1") is not None

        # Off-main: no assert, buffered, NOT in the queue.
        outcome: dict = {}

        def _produce():
            try:
                outcome["added"] = mc._add_tasks_main_safe(
                    [task_off], source="recon.permutation"
                )
                outcome["raised"] = None
            except BaseException as exc:  # noqa: BLE001 — capture for assertion
                outcome["raised"] = exc

        worker = threading.Thread(target=_produce)
        worker.start()
        worker.join(timeout=30)
        assert outcome.get("raised") is None, f"off-main safe entry raised: {outcome['raised']!r}"
        assert outcome.get("added") == 0  # buffered, not enqueued
        assert mc.task_queue.get_by_id("w-1") is None
        buffer = mc._ensure_off_main_task_buffer()
        with buffer["lock"]:
            assert len(buffer["items"]) == 1
            assert buffer["items"][0]["source"] == "recon.permutation"

        # Main-thread confluence enqueues the buffered batch.
        mc._apply_post_batch_feedback([], [])
        assert mc.task_queue.get_by_id("w-1") is not None
        with buffer["lock"]:
            assert buffer["items"] == []

    def test_recon_pipeline_add_tasks_via_shared_loop_buffers_and_confluences(self, monkeypatch):
        """Gap #4b: the recon chain calls ``mc._add_tasks_main_safe`` from
        non-main threads (pipeline.run() via asyncio.to_thread /
        SharedLoopManager). Such a call must NOT critical-fail and the
        buffered tasks must be enqueued at the main confluence."""
        from tests.core.engine.test_master_conductor_phase5_parallelism import _make_task

        mc, _scope = _minimal_mc(monkeypatch)
        task = _make_task("recon-1", "vuln_scanner")
        main_ident = threading.get_ident()
        body_ident: list[int] = []
        out: dict = {}

        async def _recon_producer_body():
            body_ident.append(threading.get_ident())
            try:
                out["added"] = mc._add_tasks_main_safe(
                    [task], source="recon.permutation"
                )
                out["raised"] = None
            except BaseException as exc:  # noqa: BLE001 — capture for assertion
                out["raised"] = exc

        # Production-equivalent off-main execution on the shared loop.
        mc._run_async_safe(_recon_producer_body(), timeout_override=60)

        assert body_ident and body_ident[0] != main_ident, "producer must run off-main"
        assert out.get("raised") is None, f"recon producer raised: {out['raised']!r}"
        assert out.get("added") == 0  # buffered, not enqueued
        assert mc.task_queue.get_by_id("recon-1") is None
        buffer = mc._ensure_off_main_task_buffer()
        with buffer["lock"]:
            assert len(buffer["items"]) == 1

        # Main-thread confluence (batch join) enqueues the buffered task.
        mc._apply_post_batch_feedback([], [])
        assert mc.task_queue.get_by_id("recon-1") is not None
        with buffer["lock"]:
            assert buffer["items"] == []

    def test_off_main_task_buffer_drain_asserts_main_thread(self):
        """The new buffer drain carries the PCR-P1-style main-thread assert —
        calling it from a worker thread fails closed (self-checking)."""
        from tests.core.engine.test_master_conductor_phase5_parallelism import _make_task

        mc, _scope = _minimal_mc(pytest.MonkeyPatch())
        outcome: dict = {}

        def _produce():
            try:
                outcome["added"] = mc._add_tasks_main_safe(
                    [_make_task("aux-1", "scanner")], source="test"
                )
                outcome["raised"] = None
            except BaseException as exc:  # noqa: BLE001 — capture for assertion
                outcome["raised"] = exc

        worker = threading.Thread(target=_produce)
        worker.start()
        worker.join(timeout=30)
        assert outcome.get("raised") is None
        assert outcome.get("added") == 0

        error: list[BaseException] = []

        def _drain_off_main():
            try:
                mc._drain_pending_off_main_tasks()
            except BaseException as exc:  # noqa: BLE001 — test capture
                error.append(exc)

        worker = threading.Thread(target=_drain_off_main)
        worker.start()
        worker.join(timeout=30)
        assert len(error) == 1
        assert isinstance(error[0], AssertionError)
        assert "main thread" in str(error[0])
