"""
Integration tests for MasterConductor + TaskPruningPolicy connection.
SGK-2026-0287 Step 6: Verify pruning decisions are recorded in _shadow_decisions.
"""
import pytest
import threading
from dataclasses import dataclass, field
from typing import Dict, Any, List

from src.core.engine.master_conductor import MasterConductor
from src.core.engine.task_queue import DynamicTaskQueue
from src.core.engine.task_pruning_policy import TaskPruningPolicy, TaskPruningDecision


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


def _new_minimal_conductor() -> MasterConductor:
    """Create a minimal MasterConductor instance for pruning tests."""
    mc = MasterConductor.__new__(MasterConductor)
    mc._state_lock = threading.RLock()
    mc.task_queue = DynamicTaskQueue()
    mc._shadow_decisions = []
    mc._pruning_policy = TaskPruningPolicy(shadow_only=True)
    return mc


class TestMasterConductorPruningIntegration:
    """Test that pruning policy integrates with MasterConductor correctly."""

    def test_pruning_policy_initialized_lazily(self):
        """_pruning_policy is created on first evaluate call."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.task_queue = DynamicTaskQueue()

        assert not hasattr(mc, '_pruning_policy')

        # Call evaluate - should lazily initialize
        mc._evaluate_pruning_policy([])

        assert hasattr(mc, '_pruning_policy')
        assert isinstance(mc._pruning_policy, TaskPruningPolicy)
        assert mc._pruning_policy.shadow_only is True

    def test_shadow_decisions_initialized_lazily(self):
        """_shadow_decisions is created if missing."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.task_queue = DynamicTaskQueue()
        mc._pruning_policy = TaskPruningPolicy(shadow_only=True)

        assert not hasattr(mc, '_shadow_decisions')

        mc._evaluate_pruning_policy([])

        assert hasattr(mc, '_shadow_decisions')
        assert mc._shadow_decisions == []

    def test_decisions_recorded_in_shadow_decisions(self):
        """Out-of-scope tasks generate decisions recorded in _shadow_decisions."""
        mc = _new_minimal_conductor()

        # Add an out-of-scope task
        task = MockTask(
            id="task_oos",
            agent_type="web_scanner",
            params={"out_of_scope": True, "source_category": "discovery"},
        )
        mc.task_queue.add(task)

        initial_count = len(mc._shadow_decisions)
        mc._evaluate_pruning_policy([task])

        # Should have at least one new decision
        assert len(mc._shadow_decisions) > initial_count
        # The decision should have the right format
        last = mc._shadow_decisions[-1]
        assert isinstance(last, dict)
        assert last["task_id"] == "task_oos"
        assert last["lifecycle_status"] == "retired"
        assert last["reason_code"] == "out_of_scope"
        assert last["shadow_only"] is True

    def test_duplicate_tasks_generate_superseded_decision(self):
        """Duplicate tasks generate superseded decisions."""
        mc = _new_minimal_conductor()

        t1 = MockTask(id="task_high", agent_type="web_scanner",
                      target="https://example.com", action="scan", priority=100)
        t2 = MockTask(id="task_low", agent_type="web_scanner",
                      target="https://example.com", action="scan", priority=10)

        mc.task_queue.add(t1)
        mc.task_queue.add(t2)

        mc._evaluate_pruning_policy([t1])

        # Should find the duplicate lower-priority task
        dup_decisions = [d for d in mc._shadow_decisions
                         if d.get("reason_code") == "duplicate"]
        assert len(dup_decisions) >= 1
        dup = dup_decisions[0]
        assert dup["task_id"] == "task_low"
        assert dup["lifecycle_status"] == "superseded"

    def test_protected_tasks_not_in_decisions(self):
        """Protected tasks never appear in pruning decisions."""
        mc = _new_minimal_conductor()

        task = MockTask(id="task_protected", agent_type="scope_parser",
                        params={"out_of_scope": True})  # even if out of scope
        mc.task_queue.add(task)

        initial_count = len(mc._shadow_decisions)
        mc._evaluate_pruning_policy([task])

        # No new decisions for protected tasks
        assert len(mc._shadow_decisions) == initial_count

    def test_empty_queue_produces_no_decisions(self):
        """Empty queue evaluation does not crash and produces no decisions."""
        mc = _new_minimal_conductor()
        initial_count = len(mc._shadow_decisions)
        mc._evaluate_pruning_policy([])
        assert len(mc._shadow_decisions) == initial_count

    def test_decision_to_dict_format_compatible_with_decision_traces(self):
        """Decisions stored have the format expected by decision_traces sink."""
        mc = _new_minimal_conductor()

        task = MockTask(id="task_format", agent_type="web_scanner",
                        params={"out_of_scope": True, "source_category": "discovery"})
        mc.task_queue.add(task)
        mc._evaluate_pruning_policy([task])

        decision = mc._shadow_decisions[-1]
        # Check all required fields for decision_traces compatibility
        assert "decision_type" in decision
        assert decision["decision_type"] in (
            "task_retired", "task_superseded", "task_invalidated"
        )
        assert "task_id" in decision
        assert "lifecycle_status" in decision
        assert "reason_code" in decision
        assert "timestamp" in decision
        assert "shadow_only" in decision
        assert "protected" in decision

    def test_multiple_rules_can_fire_together(self):
        """A single queue can produce multiple types of decisions."""
        mc = _new_minimal_conductor()

        # Duplicate pair
        t1 = MockTask(id="t_high", agent_type="web_scanner",
                      target="https://x.com", action="scan", priority=100)
        t2 = MockTask(id="t_low", agent_type="web_scanner",
                      target="https://x.com", action="scan", priority=5)
        # Out of scope
        t3 = MockTask(id="t_oos", agent_type="fuzzer",
                      params={"out_of_scope": True, "source_category": "discovery"})
        # Chain low-value follow-up
        t4 = MockTask(id="t_chain", agent_type="auth", priority=2,
                      params={"generation_reason": "vulnerability_chaining",
                               "parent_vuln_type": "idor"})
        # Protected task (should not appear)
        t5 = MockTask(id="t_protected", agent_type="coverage_guard")

        for t in [t1, t2, t3, t4, t5]:
            mc.task_queue.add(t)

        mc._evaluate_pruning_policy([t1])

        decisions = mc._shadow_decisions
        reason_codes = {d["reason_code"] for d in decisions}
        # Should contain duplicate and out_of_scope
        assert "duplicate" in reason_codes
        assert "out_of_scope" in reason_codes
        # Protected tasks should NOT be in decisions
        protected_ids = {d["task_id"] for d in decisions if d.get("protected")}
        assert "t_protected" not in protected_ids
        assert "t_protected" not in {d["task_id"] for d in decisions}
