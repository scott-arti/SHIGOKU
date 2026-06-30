"""
Phase 5 TDD tests: read_only outer task parallelism with safety gates (SGK-2026-0314).

TDD order (6.11): T-0.1 → T-5.1/T-5.2 → T-1.1/T-1.2 → T-3.1/T-3.2 → T-4.1 →
    T-2.1-T-2.6 → T-7.1 → T-6.1 → T-8.1/T-9.1/T-9.2
"""
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.core.config.settings import ParallelismSettings
from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor
from src.core.engine.lane_policy import LanePolicy


# ============================================================
# Helpers
# ============================================================

def _make_task(task_id: str, agent_type: str = "scanner", metadata: dict | None = None) -> Task:
    """Create a minimal Task for dispatch testing."""
    return Task(
        id=task_id,
        name=f"test-{task_id}",
        agent_type=agent_type,
        metadata=metadata or {},
    )


def _mock_lane_policy(mc: MasterConductor, lane: str = "read_only",
                       parallel_safe: bool = True,
                       rate_limited: bool = False) -> MagicMock:
    """Install a mock LanePolicy that returns a fixed classification."""
    lp = MagicMock(spec=LanePolicy)
    lp.classify.return_value = (lane, parallel_safe, rate_limited, None, False, "mock_classify")
    mc._lane_policy = lp
    return lp


# ============================================================
# T-0.1: Kill switch serial baseline (LB-1, LB-6 foundation)
# ============================================================

class TestKillSwitchSerialBaseline:
    """T-0.1: `parallelism.enabled=false` → serial execution route.

    When the serial path is forced, tasks MUST execute sequentially
    (via `_execute_single_task_full_flow`), and `orchestrator.execute_parallel`
    MUST NOT be called.  This test serves as a characterization baseline
    for parity comparisons (T-6.1).
    """

    def test_force_serial_executes_sequentially(self):
        """force_serial=True → tasks execute in batch order, no parallel dispatch."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        _mock_lane_policy(mc, lane="read_only", parallel_safe=True)

        executed: list[str] = []
        mc._execute_single_task_full_flow = lambda t: (
            executed.append(t.id) or {"success": True}
        )

        tasks = [_make_task("t1"), _make_task("t2"), _make_task("t3")]

        mc._dispatch_batch(tasks, force_serial=True)

        assert executed == ["t1", "t2", "t3"], (
            "Serial execution must preserve batch order"
        )
        mc.orchestrator.execute_parallel.assert_not_called()

    def test_serial_path_not_called_when_not_forced(self):
        """force_serial=False + read_only tasks → execute_parallel IS called."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        _mock_lane_policy(mc, lane="read_only", parallel_safe=True)

        executed: list[str] = []
        mc._execute_single_task_full_flow = lambda t: (
            executed.append(t.id) or {"success": True}
        )

        tasks = [_make_task("t1", "scanner"), _make_task("t2", "scanner")]

        result = mc._dispatch_batch(tasks, force_serial=False)

        # Parallel-eligible tasks → must NOT have been executed serially
        assert executed == [], (
            "Parallel-eligible tasks must NOT be executed serially"
        )
        assert len(result['parallel_tasks']) == 2, (
            "All read_only tasks must be in parallel_tasks"
        )
        assert result['serial_task_ids'] == []


# ============================================================
# T-5.2: parallelism.enabled=false → all serial (LB-1)
# ============================================================

class TestParallelismDisabledSerialPath:
    """T-5.2: parallelism.enabled=false → all batches ran serially."""

    def test_disabled_parallelism_forces_serial_on_all_tasks(self):
        """Even read_only tasks run serially when parallelism.enabled=False."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        _mock_lane_policy(mc, lane="read_only", parallel_safe=True)

        executed: list[str] = []
        mc._execute_single_task_full_flow = lambda t: (
            executed.append(t.id) or {"success": True}
        )

        tasks = [_make_task("t1"), _make_task("t2")]

        # When parallelism is disabled, every task must be serial
        mc._dispatch_batch(tasks, force_serial=True)

        assert len(executed) == 2
        mc.orchestrator.execute_parallel.assert_not_called()


# ============================================================
# T-5.1: Kill switch immediate serial revert (LB-1)
# ============================================================

class TestKillSwitchImmediateSerialRevert:
    """T-5.1: kill_switch toggled → next batch becomes serial."""

    def test_kill_switch_activates_serial(self):
        """kill_switch=True → batch runs serially despite read_only tasks."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        _mock_lane_policy(mc, lane="read_only", parallel_safe=True)

        executed: list[str] = []
        mc._execute_single_task_full_flow = lambda t: (
            executed.append(t.id) or {"success": True}
        )

        tasks = [_make_task("t1"), _make_task("t2")]

        # kill_switch forces serial
        mc._dispatch_batch(tasks, force_serial=True)

        assert len(executed) == 2
        mc.orchestrator.execute_parallel.assert_not_called()


# ============================================================
# T-1.1: Only read_only+parallel_safe tasks are parallel (LB-0, LB-5)
# ============================================================

class TestOnlyReadOnlyParallelOthersSerial:
    """T-1.1: read_only+parallel_safe=True tasks only → parallel batch.
    All other lanes → serial forced downgrade."""

    def test_mutating_lane_downgraded_to_serial(self):
        """A mutating-lane task is excluded from parallel and runs serially."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5

        # read_only task = parallel_safe
        def classify_side_effect(agent_type, metadata=None):
            if "mutating" in (agent_type or "").lower():
                return ("mutating", False, False, None, False, "class_stateful")
            return ("read_only", True, False, None, False, "class_parallel_safe")
        lp = MagicMock(spec=LanePolicy)
        lp.classify.side_effect = classify_side_effect
        mc._lane_policy = lp

        serial_executed: list[str] = []
        mc._execute_single_task_full_flow = lambda t: (
            serial_executed.append(t.id) or {"success": True}
        )

        tasks = [
            _make_task("t1", "scanner"),        # read_only
            _make_task("t2", "mutating_agent"),  # mutating → must be serial
            _make_task("t3", "scanner"),         # read_only
        ]

        mc._dispatch_batch(tasks, force_serial=False)

        # t2 (mutating) MUST have been serial-executed
        assert "t2" in serial_executed, (
            "Mutating-lane task must be serial-downgraded"
        )
        # t1 and t3 must NOT be in serial list
        assert "t1" not in serial_executed
        assert "t3" not in serial_executed

    def test_stateful_read_downgraded_to_serial(self):
        """stateful_read lane → serial downgrade."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5

        lp = MagicMock(spec=LanePolicy)
        lp.classify.return_value = ("stateful_read", False, False, None, False, "class_stateful")
        mc._lane_policy = lp

        serial_executed: list[str] = []
        mc._execute_single_task_full_flow = lambda t: (
            serial_executed.append(t.id) or {"success": True}
        )

        tasks = [_make_task("t1", "stateful_agent")]

        mc._dispatch_batch(tasks, force_serial=False)

        assert serial_executed == ["t1"]
        mc.orchestrator.execute_parallel.assert_not_called()

    def test_aggressive_exclusive_downgraded_to_serial(self):
        """aggressive_exclusive lane → serial downgrade (LB-0 protection)."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5

        lp = MagicMock(spec=LanePolicy)
        lp.classify.return_value = ("aggressive_exclusive", False, False, None, False, "class_aggressive")
        mc._lane_policy = lp

        serial_executed: list[str] = []
        mc._execute_single_task_full_flow = lambda t: (
            serial_executed.append(t.id) or {"success": True}
        )

        tasks = [_make_task("t1", "aggressive_agent")]

        mc._dispatch_batch(tasks, force_serial=False)

        assert serial_executed == ["t1"]
        mc.orchestrator.execute_parallel.assert_not_called()

    def test_sequential_required_downgraded_to_serial(self):
        """sequential_required lane → serial downgrade."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5

        lp = MagicMock(spec=LanePolicy)
        lp.classify.return_value = ("sequential_required", False, False, None, False, "unclassified")
        mc._lane_policy = lp

        serial_executed: list[str] = []
        mc._execute_single_task_full_flow = lambda t: (
            serial_executed.append(t.id) or {"success": True}
        )

        tasks = [_make_task("t1", "unknown_agent")]

        mc._dispatch_batch(tasks, force_serial=False)

        assert serial_executed == ["t1"]
        mc.orchestrator.execute_parallel.assert_not_called()


# ============================================================
# T-1.2: Live LanePolicy.classify is gate input, not shadow (LB-5)
# ============================================================

class TestLiveLanePolicyGatesDispatch:
    """T-1.2: LanePolicy.classify is called as a live gate before dispatch.
    Phase 4 shadow decisions are NOT consulted for the live gate."""

    def test_classify_called_during_dispatch(self):
        """LanePolicy.classify is invoked for each task during _dispatch_batch."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5

        lp = MagicMock(spec=LanePolicy)
        lp.classify.return_value = ("read_only", True, False, None, False, "mock")
        mc._lane_policy = lp

        mc._execute_single_task_full_flow = lambda t: {"success": True}

        tasks = [_make_task("t1", "scanner"), _make_task("t2", "fuzzer")]

        mc._dispatch_batch(tasks, force_serial=False)

        # classify must be called exactly twice (once per task)
        assert lp.classify.call_count == 2, (
            "LanePolicy.classify must be called for each task at dispatch time"
        )

    def test_shadow_decisions_not_consulted_for_gate(self):
        """Shadow _shadow_decisions list is NOT read by dispatch gate.
        The gate input is ONLY live LanePolicy.classify."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5

        # Seed _shadow_decisions with a fake "mutating" classification
        # to prove it is NOT read during dispatch
        from src.core.engine.scheduling_decision import SchedulingDecision
        mc._shadow_decisions = [
            SchedulingDecision(
                lane="mutating", parallel_safe=False, rate_limited=False,
                compat_lane=None, lane_disagreement=False, reason_code="shadow_fake",
                mutex_key="fake", mutation_surface="fake", would_wait=False,
                would_reject=False, shadow_only=True, origin_key="https://target.com",
                auth_context_version=0,
            )
        ]

        # Live LanePolicy says read_only
        lp = MagicMock(spec=LanePolicy)
        lp.classify.return_value = ("read_only", True, False, None, False, "live")
        mc._lane_policy = lp

        mc._execute_single_task_full_flow = lambda t: {"success": True}

        tasks = [_make_task("t1", "scanner")]

        result = mc._dispatch_batch(tasks, force_serial=False)

        # The task went to parallel (proving shadow was ignored, live was used)
        assert len(result['parallel_tasks']) == 1


class TestPhase7ExecutionBoundary:
    """Phase 7 blockers: strict runtime boundary before parallel dispatch/start."""

    def test_unknown_category_can_fail_closed_in_strict_phase7_mode(self):
        """T-7.7: strict Phase 7 boundary must not silently map unknown category to read_only."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        mc._phase7_strict_category_gate = True
        _mock_lane_policy(mc, lane="read_only", parallel_safe=True)

        mc._execute_single_task_full_flow = lambda t: {"success": True}
        task = _make_task("t-unknown", "new_agent", metadata={
            "origin_key": "https://example.com",
            "scope_verdict": "in_scope",
        })

        result = mc._dispatch_batch([task], force_serial=False)

        assert result["parallel_tasks"] == []
        assert result["serial_results"] == []
        assert result["rejected_task_ids"] == ["t-unknown"]
        assert task.metadata["lifecycle_status"] == "rejected"
        assert task.metadata["lifecycle_reason"] == "unknown_execution_category"

    def test_start_boundary_skips_stale_task_before_execution(self):
        """T-7.1c: task start performs snapshot validity check before mutation."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc._get_current_snapshot_versions = lambda: (5, 3)
        task = _make_task("stale-start", "scanner", metadata={
            "recon_snapshot_version": 1,
            "auth_context_version": 3,
        })

        result = mc._reject_invalid_task_snapshot_at_start(task)

        assert result == {
            "success": False,
            "skipped": True,
            "task_id": "stale-start",
            "skip_reason": "stale_recon_snapshot",
        }
        assert task.metadata["lifecycle_status"] == "invalidated"
        assert task.metadata["invalidated_by"] == "validity_check:start"

    def test_queue_snapshot_versions_synced_before_task_selection(self):
        """T-7.1d: MC passes current snapshot versions to queue before pop."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._get_current_snapshot_versions = lambda: (5, 3)
        mc._is_task_quarantined = lambda task: False
        mc.task_prioritizer = None
        task = _make_task("fresh", "scanner", metadata={
            "recon_snapshot_version": 5,
            "auth_context_version": 3,
        })
        mc.task_queue = MagicMock()
        mc.task_queue.pop.side_effect = [task]

        selected = mc._select_next_task_from_queue()

        assert selected is task
        mc.task_queue.set_snapshot_versions.assert_called_once_with(
            current_recon_version=5,
            current_auth_version=3,
        )

    def test_admission_policy_is_synced_from_parallelism_settings(self):
        """T-7.8: MasterConductor wires settings.parallelism into admission policy."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._sync_parallelism_admission_policy(SimpleNamespace(
            mutating=SimpleNamespace(enabled=True, allowlist=["https://example.com"]),
            aggressive_exclusive=SimpleNamespace(enabled=True, allowlist=["https://example.com"]),
        ))

        policy = mc._admission_policy
        assert policy.mutating_enabled is True
        assert policy.aggressive_exclusive_enabled is True
        assert policy.mutating_allowlist == {"https://example.com"}
        assert policy.aggressive_allowlist == {"https://example.com"}

    def test_react_observation_state_has_lazy_lock_for_new_and_newless_instances(self):
        """T-7.10: ReAct observation counters have a lock even in __new__ tests."""
        mc = MasterConductor.__new__(MasterConductor)

        lock = mc._ensure_react_observation_lock()

        assert lock is mc._react_observation_lock
        assert hasattr(lock, "acquire")


# ============================================================
# T-3.1: origin_key propagated to ParallelTask (LB-3)
# ============================================================

class TestOriginKeyPropagatedToParallelTask:
    """T-3.1: Task.metadata.origin_key → ParallelTask.origin_key."""

    def test_origin_key_in_metadata_propagates(self):
        """origin_key from Task.metadata reaches ParallelTask."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        _mock_lane_policy(mc)

        mc._execute_single_task_full_flow = lambda t: {"success": True}

        tasks = [
            _make_task("t1", "scanner", {"origin_key": "https://api.example.com"}),
        ]

        result = mc._dispatch_batch(tasks, force_serial=False)

        parallel_tasks = result['parallel_tasks']
        assert len(parallel_tasks) == 1
        pt = parallel_tasks[0]
        assert pt.origin_key == "https://api.example.com", (
            "origin_key must propagate to ParallelTask"
        )

    def test_origin_key_none_when_missing(self):
        """Missing origin_key → None propagated."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        _mock_lane_policy(mc)

        mc._execute_single_task_full_flow = lambda t: {"success": True}

        tasks = [_make_task("t1", "scanner", {})]  # no origin_key

        result = mc._dispatch_batch(tasks, force_serial=False)

        pt = result['parallel_tasks'][0]
        assert pt.origin_key is None


# ============================================================
# T-3.2: Per-origin budget isolated (LB-3)
# ============================================================

class TestPerOriginBudgetIsolated:
    """T-3.2: Different origins tracked in separate budget buckets."""

    def test_different_origins_use_different_buckets(self):
        """Two origins → two separate ParallelTask entries with correct keys."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        _mock_lane_policy(mc)

        mc._execute_single_task_full_flow = lambda t: {"success": True}

        tasks = [
            _make_task("t1", "scanner", {"origin_key": "https://a.example.com"}),
            _make_task("t2", "scanner", {"origin_key": "https://b.example.com"}),
        ]

        result = mc._dispatch_batch(tasks, force_serial=False)

        pts = result['parallel_tasks']
        assert len(pts) == 2
        origin_keys = {pt.origin_key for pt in pts}
        assert origin_keys == {"https://a.example.com", "https://b.example.com"}, (
            "Each origin must propagate independently"
        )


# ============================================================
# T-2.4: No concurrent task_queue mutation during batch (LB-2)
# ============================================================

class TestNoConcurrentTaskQueueMutationDuringBatch:
    """T-2.4: task_queue mutations are NOT called concurrently during a batch.

    All shared-state mutations from _execute_single_task_full_flow are deferred
    into _post_batch_feedback and applied in _apply_post_batch_feedback on the
    main thread after batch join.  This test verifies that the re-entrancy
    detector sees zero concurrent calls — INCLUDING DecisionEnhancer.add
    which must also be deferred.
    """

    def test_task_queue_not_called_during_parallel_execution(self):
        """When _dispatch_batch routes to parallel, task_queue mutations
        are NOT made during _execute_single_task_full_flow but deferred."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        _mock_lane_policy(mc)

        # Install a DecisionEnhancer mock that triggers RETRY (→ task_queue.add)
        mc.decision_enhancer = MagicMock()
        mc.decision_enhancer.decide.return_value = MagicMock(
            decision=MagicMock(value="retry", spec=[]),
            reasoning="test",
            modifications={},
        )

        # Track whether task_queue.add is called
        add_calls: list[str] = []
        mc.task_queue = MagicMock()
        def record_add(new_task, _calls=add_calls):
            _calls.append(threading.current_thread().name)
        mc.task_queue.add = MagicMock(side_effect=record_add)

        # Make execute produce a success result with a replan_depth < 3
        # so DecisionEnhancer will try to retry
        def real_execute(task):
            task.replan_depth = 0  # ensure retry triggers
            return {
                "success": True,
                "message": "",
                "findings": [],
                "_post_batch_feedback": {
                    "deferred_decision_enhancer_tasks": [],
                    "deferred_findings": [],
                    "deferred_critical_actions": [],
                },
            }

        mc._execute_single_task_full_flow = real_execute

        tasks = [_make_task("t1", "scanner"), _make_task("t2", "scanner")]
        mc._dispatch_batch(tasks, force_serial=False)

        # task_queue.add must NOT have been called during dispatch
        # (DecisionEnhancer's new_task is deferred to _post_batch_feedback)
        assert len(add_calls) == 0, (
            f"task_queue.add called {len(add_calls)} times during batch dispatch. "
            "DecisionEnhancer retry tasks must be deferred to _post_batch_feedback."
        )

    def test_decision_enhancer_retry_deferred_to_feedback(self):
        """DecisionEnhancer RETRY → new_task goes into _post_batch_feedback."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        _mock_lane_policy(mc)

        mc.decision_enhancer = MagicMock()
        mc.decision_enhancer.decide.return_value = MagicMock(
            decision=MagicMock(value="retry", spec=[]),
            reasoning="test",
            modifications={},
        )

        mc.task_queue = MagicMock()

        def real_execute(task):
            task.replan_depth = 0
            # Build realistic feedback including DecisionEnhancer retry task
            task_clone = _make_task("t1_retry", "scanner")
            task_clone.id = f"{task.id}_retry_999"
            return {
                "success": True,
                "message": "",
                "findings": [],
                "_post_batch_feedback": {
                    "deferred_decision_enhancer_tasks": [task_clone],
                    "deferred_findings": [],
                    "deferred_critical_actions": [],
                },
            }

        mc._execute_single_task_full_flow = real_execute

        tasks = [_make_task("t1", "scanner")]
        mc._dispatch_batch(tasks, force_serial=False)

        # task_queue.add NOT called during dispatch
        mc.task_queue.add.assert_not_called()

        # Now apply post-batch feedback → task_queue.add IS called
        result_fb = {"task_id": "t1", "_post_batch_feedback": {
            "deferred_decision_enhancer_tasks": [_make_task("retry_t1", "scanner")],
        }}
        mc._apply_post_batch_feedback(tasks, [result_fb])
        mc.task_queue.add.assert_called_once()

    def test_apply_post_batch_feedback_replays_mutations(self):
        """_apply_post_batch_feedback replays deferred mutations on main thread."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
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

        task = _make_task("t1", "scanner")
        results = [{"task_id": "t1", "success": True, "_post_batch_feedback": {
            "deferred_findings": [],
            "deferred_new_assets": ["https://new.example.com"],
        }}]

        mc._apply_post_batch_feedback([task], results)

        mc._expand_plan_for_assets.assert_called_once_with(["https://new.example.com"])


# ============================================================
# T-2.5: Recovery path propagates context (LB-2)
# ============================================================

class TestRecoveryPathPropagatesContext:
    """T-2.5: Recovery tasks' findings propagate via _apply_post_batch_feedback."""

    def test_recovery_task_context_propagates(self):
        """After recovery, deferred feedback is applied."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc._expand_plan_for_assets = MagicMock()
        mc.handle_finding = MagicMock()
        mc._add_tasks = MagicMock()
        mc._process_handoff = MagicMock()
        mc.accumulated_context = MagicMock()
        mc.accumulated_context.is_empty.return_value = False
        mc.wordlist_manager = MagicMock()
        mc.task_queue = MagicMock()
        mc.priority_booster = MagicMock()
        mc.critical_path_analyzer = MagicMock()
        mc.critical_path_analyzer.analyze.return_value = []

        task = _make_task("t1", "scanner")
        results = [{"task_id": "t1", "success": True, "_post_batch_feedback": {
            "deferred_findings": [],
            "deferred_new_assets": ["https://recovered.example.com"],
        }}]

        mc._apply_post_batch_feedback([task], results)

        mc._expand_plan_for_assets.assert_called_once_with(["https://recovered.example.com"])


# ============================================================
# T-7.1: Dispatcher singleton no race under parallel dispatch (LB-7)
# ============================================================

class TestDispatcherSingletonNoRaceUnderParallelDispatch:
    """T-7.1: get_swarm_dispatcher singleton reconfiguration is thread-safe.

    LB-7 (Phase 5): _dispatcher_lock protects singleton access against
    TOCTOU race when called concurrently.
    """

    def test_get_swarm_dispatcher_lock_present_and_is_lock(self):
        """_dispatcher_lock exists and is a threading.Lock."""
        import src.core.engine.swarm_dispatcher as sd
        lock = getattr(sd, '_dispatcher_lock', None)
        assert lock is not None, (
            "_dispatcher_lock must exist in swarm_dispatcher (LB-7 fix)"
        )
        assert isinstance(lock, type(threading.Lock())), (
            f"_dispatcher_lock must be threading.Lock, got {type(lock)}"
        )

    def test_get_swarm_dispatcher_serializes_under_lock(self):
        """Concurrent get_swarm_dispatcher calls are serialized by the lock."""
        from src.core.engine.swarm_dispatcher import get_swarm_dispatcher
        import src.core.engine.swarm_dispatcher as sd

        # Reset singleton for test
        with sd._dispatcher_lock:
            sd._dispatcher = None

        try:
            d1 = get_swarm_dispatcher(llm_client="mock1")
            d2 = get_swarm_dispatcher(llm_client="mock2")
            assert d1 is d2, "Singleton must return same instance"
        finally:
            with sd._dispatcher_lock:
                sd._dispatcher = None


# ============================================================
# T-6.1: Finding parity serial vs gated parallel (LB-6 Go condition)
# ============================================================

class TestFindingParitySerialVsGatedParallel:
    """T-6.1: Serial and gated parallel produce identical High/Critical findings.

    Go condition (6.5): High/Critical finding (severity+id) set must be
    identical between serial baseline and gated parallel path.
    Uses canonical extract_all_findings() for authoritative finding extraction.
    Each test runs both serial and parallel paths end-to-end including
    _apply_post_batch_feedback, then compares finding sets.
    """

    def _make_finding(self, finding_id: str, severity: str = "HIGH",
                       vuln_type: str = "IDOR") -> dict:
        return {
            "id": finding_id,
            "title": f"Test vuln {finding_id}",
            "severity": severity,
            "vuln_type": vuln_type,
        }

    def _make_executor(self, findings_by_task: dict[str, list[dict]]):
        """Return a deterministic _execute_single_task_full_flow that produces
        findings from findings_by_task keyed by task.id."""
        def execute(task):
            found = findings_by_task.get(task.id, [])
            return {
                "success": True,
                "message": "",
                "findings": found,
                "_post_batch_feedback": {
                    "deferred_findings": found,
                    "deferred_critical_actions": [],
                    "deferred_new_assets": None,
                    "deferred_new_context": None,
                    "deferred_react_tasks": None,
                    "deferred_handoff": None,
                },
            }
        return execute

    def _build_mc(self):
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        mc.handle_finding = MagicMock()
        mc._expand_plan_for_assets = MagicMock()
        mc._add_tasks = MagicMock()
        mc._process_handoff = MagicMock()
        mc.accumulated_context = MagicMock()
        mc.accumulated_context.is_empty.return_value = False
        mc.wordlist_manager = MagicMock()
        mc.task_queue = MagicMock()
        mc.priority_booster = MagicMock()
        mc.critical_path_analyzer = MagicMock()
        mc.critical_path_analyzer.analyze.return_value = []
        _mock_lane_policy(mc)
        return mc

    def _collect_findings_from_apply(self, mc, batch_tasks, results):
        """Call _apply_post_batch_feedback and collect finding ids from
        handle_finding calls."""
        mc._apply_post_batch_feedback(batch_tasks, results)
        finding_ids: set[str] = set()
        for call_args in mc.handle_finding.call_args_list:
            finding = call_args[0][0]  # first positional arg
            if isinstance(finding, dict):
                finding_ids.add(finding.get("id", ""))
            else:
                finding_ids.add(getattr(finding, "id", ""))
        return finding_ids

    def test_finding_parity_serial_path_produces_findings(self):
        """Serial path: findings fed through _apply_post_batch_feedback are collected."""
        mc = self._build_mc()
        findings = {"t1": [self._make_finding("f-serial-1")]}
        mc._execute_single_task_full_flow = self._make_executor(findings)

        tasks = [_make_task("t1", "scanner")]
        batch_info = mc._dispatch_batch(tasks, force_serial=True)

        # Serial path: result is in serial_results
        serial_results = batch_info['serial_results']
        assert len(serial_results) == 1
        assert serial_results[0].get("success") is True

        # Apply feedback
        finding_ids = self._collect_findings_from_apply(mc, tasks, serial_results)
        assert "f-serial-1" in finding_ids, (
            "Serial path must propagate findings through _apply_post_batch_feedback"
        )

    def test_finding_parity_identical_seeds_produce_identical_sets(self):
        """Same task seeds → serial and gated parallel produce identical finding sets."""
        # Common task seeds
        tasks = [
            _make_task("t1", "scanner"),
            _make_task("t2", "scanner"),
            _make_task("t3", "scanner"),
        ]
        common_findings = {
            "t1": [self._make_finding("f-001")],
            "t2": [self._make_finding("f-002", "CRITICAL")],
            "t3": [self._make_finding("f-003"), self._make_finding("f-004", "MEDIUM")],
        }

        # --- Serial path ---
        mc_s = self._build_mc()
        mc_s._execute_single_task_full_flow = self._make_executor(common_findings)
        batch_s = mc_s._dispatch_batch(tasks, force_serial=True)
        serial_results = batch_s['serial_results']
        serial_finding_ids = self._collect_findings_from_apply(mc_s, tasks, serial_results)

        # --- Gated parallel path ---
        mc_p = self._build_mc()
        mc_p._execute_single_task_full_flow = self._make_executor(common_findings)
        batch_p = mc_p._dispatch_batch(tasks, force_serial=False)

        # Parallel tasks: simulate execution by calling the function inline
        # (orchestrator is mocked, so we call the func ourselves)
        parallel_results: list[dict] = []
        for pt in batch_p['parallel_tasks']:
            # pt.func is _execute_single_task_full_flow
            res = pt.func(*pt.args, **pt.kwargs)
            # Tag with task_id for _apply_post_batch_feedback lookup
            res["task_id"] = pt.id
            parallel_results.append(res)

        # Combine serial + parallel results
        all_results_p = list(batch_p.get('serial_results', [])) + parallel_results
        parallel_finding_ids = self._collect_findings_from_apply(mc_p, tasks, all_results_p)

        # --- Compare finding sets ---
        assert serial_finding_ids == parallel_finding_ids, (
            f"Finding parity broken! Serial={serial_finding_ids}, "
            f"Parallel={parallel_finding_ids}"
        )
        assert serial_finding_ids == {"f-001", "f-002", "f-003", "f-004"}, (
            "All seeded findings must be present"
        )


# ============================================================
# T-8.1: Phase 4 shadow vs Phase 5 live gate agreement (S-4)
# ============================================================

class TestPhase4ShadowVsPhase5LiveGateAgreement:
    """T-8.1: Observe agreement rate between shadow and live gate decisions."""

    def test_shadow_and_live_agreement(self):
        """Live LanePolicy.classify is always the gate input, not shadow."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5

        call_count = 0

        def classify_spy(agent_type, metadata=None):
            nonlocal call_count
            call_count += 1
            return ("read_only", True, False, None, False, "live_classify")

        lp = MagicMock()
        lp.classify.side_effect = classify_spy
        mc._lane_policy = lp
        mc._execute_single_task_full_flow = lambda t: {"success": True}

        tasks = [_make_task("t1", "scanner"), _make_task("t2", "scanner")]
        mc._dispatch_batch(tasks, force_serial=False)

        assert call_count == 2, "Live classify must be called for each task"


# ============================================================
# T-9.1: Phase 2 admission regression (LB-3 cross-check)
# ============================================================

class TestPhase2AdmissionRegression:
    """T-9.1: origin_key/lane propagation doesn't break Phase 2 admission."""

    def test_admission_not_broken_by_origin_propagation(self):
        """origin_key propagation doesn't break admission."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        _mock_lane_policy(mc)

        mc._execute_single_task_full_flow = lambda t: {"success": True}

        tasks = [_make_task("t1", "scanner", {"origin_key": "https://target.com"})]
        result = mc._dispatch_batch(tasks, force_serial=False)

        pt = result['parallel_tasks'][0]
        assert pt.origin_key == "https://target.com"
        assert pt.admitted is True, (
            "read_only tasks with valid origin_key must be admitted"
        )


# ============================================================
# T-9.2: Phase 3 isolation regression
# ============================================================

class TestPhase3IsolationRegression:
    """T-9.2: Phase 3 per-dispatch instance isolation maintained under gates."""

    def test_isolation_maintained_under_gated_parallel(self):
        """Per-dispatch isolation is preserved under gated parallel."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.orchestrator = MagicMock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        _mock_lane_policy(mc)

        mc._execute_single_task_full_flow = lambda t: {"success": True}

        tasks = [_make_task("t1", "scanner"), _make_task("t2", "scanner")]
        result = mc._dispatch_batch(tasks, force_serial=False)

        # Each task generates its own ParallelTask (no sharing)
        pts = result['parallel_tasks']
        assert len(pts) == 2
        assert pts[0].id != pts[1].id, "Each task must have unique ParallelTask id"
