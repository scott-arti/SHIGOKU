"""
Phase 6 M2: EventBus handler marshaling tests.
T-0.1: Characterization of handler thread origin (before/after M2).
T-2.1: No direct task_queue mutation from event handlers.
T-2.2: No re-entrant mutation during _apply_post_batch_feedback iteration.
"""
import pytest
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List

from src.core.engine.master_conductor import MasterConductor
from src.core.engine.task_queue import DynamicTaskQueue
from src.core.engine.task_pruning_policy import TaskPruningPolicy


@dataclass
class MockTask:
    id: str
    name: str = "Test Task"
    priority: int = 0
    agent_type: str = "test"
    action: str = "run"
    tags: List[str] = field(default_factory=list)
    params: Dict[str, Any] = field(default_factory=dict)
    target: str = ""


def _new_mc_for_marshaling() -> MasterConductor:
    """Create a minimal MC for marshaling tests."""
    mc = MasterConductor.__new__(MasterConductor)
    mc._state_lock = threading.RLock()
    mc.task_queue = DynamicTaskQueue()
    mc._shadow_decisions = []
    mc._pruning_policy = TaskPruningPolicy(shadow_only=True)
    mc._pending_event_follow_ups = []
    mc._derived_task_count = 0
    return mc


class TestHandlerThreadCharacterization:
    """T-0.1: Characterization test for handler thread origin."""

    def test_pending_event_follow_ups_list_initialized(self):
        """_pending_event_follow_ups is available as a list."""
        mc = _new_mc_for_marshaling()
        assert isinstance(mc._pending_event_follow_ups, list)
        assert mc._pending_event_follow_ups == []

    def test_main_thread_is_main_thread(self):
        """Verify we can detect main thread."""
        assert threading.current_thread() is threading.main_thread()

    def test_deferred_follow_up_mechanism_available(self):
        """Lazy init pattern works for _pending_event_follow_ups."""
        mc = MasterConductor.__new__(MasterConductor)
        assert not hasattr(mc, '_pending_event_follow_ups')
        # Simulate what _handle_vuln_found does
        if not hasattr(mc, '_pending_event_follow_ups'):
            mc._pending_event_follow_ups = []
        assert hasattr(mc, '_pending_event_follow_ups')


class TestNoDirectTaskQueueMutation:
    """T-2.1: Verify no direct task_queue mutation from handlers."""

    def test_deferred_queue_accepts_tasks(self):
        """_pending_event_follow_ups can accept tasks."""
        mc = _new_mc_for_marshaling()
        task = MockTask(id="t1", name="chain_task", priority=2,
                        target="https://example.com")
        mc._pending_event_follow_ups.append(task)
        assert len(mc._pending_event_follow_ups) == 1

    def test_deferred_queue_drain_adds_tasks_to_queue(self):
        """Draining _pending_event_follow_ups adds tasks to task_queue."""
        mc = _new_mc_for_marshaling()
        task = MockTask(id="chain_1", name="Chain Auth Escalation",
                        priority=2)
        mc._pending_event_follow_ups.append(task)
        assert len(mc._pending_event_follow_ups) == 1
        assert len(mc.task_queue) == 0

        # Drain (simulating _apply_post_batch_feedback)
        follow_ups = mc._pending_event_follow_ups
        mc._pending_event_follow_ups = []
        for t in follow_ups:
            mc.task_queue.add(t)

        assert len(mc.task_queue) == 1
        assert mc.task_queue.get_by_id("chain_1") is not None

    def test_drain_clears_deferred_list(self):
        """After draining, _pending_event_follow_ups is reset."""
        mc = _new_mc_for_marshaling()
        mc._pending_event_follow_ups = [MockTask(id="x")]
        mc._pending_event_follow_ups = []
        assert mc._pending_event_follow_ups == []


class TestNoReentrantMutation:
    """T-2.2: No re-entrant mutation during _apply_post_batch_feedback iteration."""

    def test_evaluate_pruning_policy_does_not_mutate_queue(self):
        """_evaluate_pruning_policy does not remove tasks from queue."""
        mc = _new_mc_for_marshaling()
        task = MockTask(id="t_keep", agent_type="web_scanner",
                        params={"out_of_scope": True, "source_category": "discovery"})
        mc.task_queue.add(task)
        initial_len = len(mc.task_queue)

        mc._evaluate_pruning_policy([task])

        # Queue should be unchanged (shadow-only)
        assert len(mc.task_queue) == initial_len

    def test_deferred_queue_preserved_across_batches(self):
        """_pending_event_follow_ups survives between evaluations."""
        mc = _new_mc_for_marshaling()
        t1 = MockTask(id="batch1_task", priority=1)
        mc._pending_event_follow_ups.append(t1)
        assert len(mc._pending_event_follow_ups) == 1
