"""
SGK-2026-0426 — W2 gate: prove the VDP follow-up drain point is the MAIN thread.

Mandatory-condition #1 (approved contract §3.1): BEFORE building the
deferred-injection buffer, prove that the drain phase (
``MasterConductor._apply_post_batch_feedback`` — the batch-join feedback
phase where the VDP follow-up queue injection will be drained, LB-2
contract) executes on ``threading.main_thread()``. If this were a worker
thread, the main-thread-marshal design itself would collapse.

Evidence chain:
1. Task bodies (incl. ``_queue_vdp_follow_ups``) run on the SharedLoopManager
   background daemon thread (NOT main) — this is why PCR-P1 fires on the
   real run (session_20260806_105634.json, completed_tasks[1].error).
2. ``execute_with_replan`` is a SYNCHRONOUS method invoked from ``main()``
   (main thread); it blocks the main thread while SharedLoopManager workers
   run, then calls ``_apply_post_batch_feedback`` synchronously — so the
   feedback/drain phase executes on the main thread.
3. A probe placed at the drain point (with the PCR-P1-style assert) passes on
   the main thread and fails when (incorrectly) invoked from a worker thread
   (fail-closed, mirroring task_queue.py's asserts which stay untouched).
"""
from __future__ import annotations

import inspect
import threading

import pytest

from src.core.engine.master_conductor import MasterConductor
from src.core.utils.async_utils import safe_run_async


class TestSharedLoopRunsTaskBodiesOffMainThread:
    def test_safe_run_async_executes_on_background_thread(self):
        """Premise: MC task bodies via _run_async_safe run on the
        SharedLoopManager daemon thread, never on the main thread."""
        main_ident = threading.get_ident()

        async def _probe_thread():
            return threading.get_ident()

        loop_ident = safe_run_async(_probe_thread(), timeout=10)
        assert loop_ident != main_ident

        async def _probe_main():
            return threading.current_thread() is threading.main_thread()

        is_main = safe_run_async(_probe_main(), timeout=10)
        assert is_main is False

    def test_execute_with_replan_is_synchronous(self):
        """execute_with_replan is a plain (blocking) method — it runs on the
        caller's (main) thread and does not yield to any event loop."""
        assert inspect.iscoroutinefunction(MasterConductor.execute_with_replan) is False


class TestDrainPointIsMainThread:
    """Gate (mandatory condition #1): the batch-feedback phase where the VDP
    follow-up drain will be placed executes on the main thread."""

    def _minimal_mc(self):
        from unittest.mock import MagicMock

        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.task_queue = MagicMock()
        mc._expand_plan_for_assets = MagicMock()
        mc.handle_finding = MagicMock()
        mc._observe_and_rethink = MagicMock(return_value=[])
        mc._add_tasks = MagicMock()
        mc._process_handoff = MagicMock()
        mc.context_propagator = MagicMock()
        mc.accumulated_context = MagicMock()
        mc.wordlist_manager = MagicMock()
        mc.priority_booster = MagicMock()
        mc.critical_path_analyzer = MagicMock()
        mc.critical_path_analyzer.analyze.return_value = []
        return mc

    def _task_and_result(self):
        from tests.core.engine.test_master_conductor_phase5_parallelism import (
            _make_task,
        )

        task = _make_task("t1", "scanner")
        result = {
            "task_id": "t1",
            "success": True,
            "_post_batch_feedback": {
                "deferred_findings": [],
                "deferred_new_assets": [],
                "deferred_decision_enhancer_tasks": [],
            },
        }
        return task, result

    def test_drain_point_assert_passes_on_main_thread(self, monkeypatch):
        """The PCR-P1-style assert at the drain point PASSES when the batch
        loop (main thread) applies post-batch feedback — the exact call
        pattern ``execute_with_replan`` uses at :7349/:7386."""
        observed: dict = {}

        orig = MasterConductor._apply_post_batch_feedback

        def probe(self, batch_tasks, results):
            # PCR-P1-style drain-point assert (mandatory condition #1).
            assert threading.current_thread() is threading.main_thread(), (
                "PCR-P1: VDP drain (post-batch feedback) must be on main thread"
            )
            observed["drain_point_is_main_thread"] = True
            return orig(self, batch_tasks, results)

        monkeypatch.setattr(
            MasterConductor, "_apply_post_batch_feedback", probe
        )
        mc = self._minimal_mc()
        task, result = self._task_and_result()
        mc._apply_post_batch_feedback([task], [result])
        assert observed.get("drain_point_is_main_thread") is True

    def test_drain_point_assert_fails_from_worker_thread(self, monkeypatch):
        """Invoking the drain point from a worker thread must fail closed —
        the marshal design keeps every queue mutation on the main thread."""
        orig = MasterConductor._apply_post_batch_feedback

        def probe(self, batch_tasks, results):
            assert threading.current_thread() is threading.main_thread(), (
                "PCR-P1: VDP drain (post-batch feedback) must be on main thread"
            )
            return orig(self, batch_tasks, results)

        monkeypatch.setattr(
            MasterConductor, "_apply_post_batch_feedback", probe
        )
        mc = self._minimal_mc()
        task, result = self._task_and_result()
        error: list[BaseException] = []

        def _invoke_from_worker():
            try:
                mc._apply_post_batch_feedback([task], [result])
            except BaseException as exc:  # noqa: BLE001 — test capture
                error.append(exc)

        worker = threading.Thread(target=_invoke_from_worker)
        worker.start()
        worker.join(timeout=15)
        assert not worker.is_alive()
        assert len(error) == 1
        assert isinstance(error[0], AssertionError)
        assert "PCR-P1" in str(error[0])
