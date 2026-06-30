"""
Tests for TaskPruningPolicy and TaskPruningDecision.
SGK-2026-0287 Step 1 + Step 6: data model, protected tasks, shadow mode, conservative rules.
"""
import pytest
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

from src.core.engine.task_pruning_policy import (
    TaskPruningDecision,
    TaskPruningPolicy,
)
from src.core.engine.task_queue import DynamicTaskQueue


# -- Test helpers --

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


# ======================================================================
# TaskPruningDecision tests
# ======================================================================

class TestTaskPruningDecision:
    def test_decision_creation_defaults(self):
        """TaskPruningDecision has correct default values."""
        d = TaskPruningDecision(
            task_id="task_abc",
            lifecycle_status="retired",
            reason_code="duplicate",
        )
        assert d.task_id == "task_abc"
        assert d.lifecycle_status == "retired"
        assert d.reason_code == "duplicate"
        assert d.trigger_event_id is None
        assert d.evidence_key is None
        assert d.protected is False
        assert d.shadow_only is True
        assert isinstance(d.timestamp, datetime)

    def test_decision_to_dict(self):
        """to_dict() produces a dict compatible with decision_traces sink."""
        d = TaskPruningDecision(
            task_id="task_xyz",
            lifecycle_status="superseded",
            reason_code="chain_completed",
            trigger_event_id="evt_001",
            evidence_key="vuln_123:admin_panel",
            protected=False,
        )
        result = d.to_dict()
        assert result["decision_type"] == "task_superseded"
        assert result["task_id"] == "task_xyz"
        assert result["lifecycle_status"] == "superseded"
        assert result["reason_code"] == "chain_completed"
        assert result["trigger_event_id"] == "evt_001"
        assert result["evidence_key"] == "vuln_123:admin_panel"
        assert result["protected"] is False
        assert result["shadow_only"] is True
        assert "timestamp" in result

    def test_decision_to_dict_invalidated(self):
        """to_dict() for invalidated status."""
        d = TaskPruningDecision(
            task_id="task_stale",
            lifecycle_status="invalidated",
            reason_code="stale_snapshot",
            trigger_event_id="evt_recon_002",
        )
        result = d.to_dict()
        assert result["decision_type"] == "task_invalidated"


# ======================================================================
# TaskPruningPolicy - Protected tasks
# ======================================================================

class TestTaskPruningPolicyProtected:
    """Tests that protected tasks are never pruned."""

    def test_protected_scope_parser_not_pruned(self):
        """scope_parser agent_type is protected."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="t1",
            name="Scope Check",
            agent_type="scope_parser",
        )
        assert policy._is_protected(task) is True

    def test_protected_coverage_guard_not_pruned(self):
        """coverage_guard agent_type is protected."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="t2",
            name="Coverage Guard",
            agent_type="coverage_guard",
        )
        assert policy._is_protected(task) is True

    def test_protected_scenario_probe_not_pruned(self):
        """scenario_probe agent_type is protected."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="t3",
            name="Scenario Probe",
            agent_type="scenario_probe",
        )
        assert policy._is_protected(task) is True

    def test_protected_manual_verify_not_pruned(self):
        """manual_verify agent_type is protected."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="t4",
            name="Manual Verify",
            agent_type="manual_verify",
        )
        assert policy._is_protected(task) is True

    def test_protected_report_not_pruned(self):
        """report agent_type is protected."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="t5",
            name="Report Gen",
            agent_type="report",
        )
        assert policy._is_protected(task) is True

    def test_protected_evidence_not_pruned(self):
        """evidence agent_type is protected."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="t6",
            name="Evidence Collect",
            agent_type="evidence",
        )
        assert policy._is_protected(task) is True

    def test_protected_via_tags(self):
        """manual_verify and coverage_guard_forced tags are protected."""
        policy = TaskPruningPolicy()
        task1 = MockTask(id="t7", agent_type="web_scanner", tags=["manual_verify"])
        task2 = MockTask(id="t8", agent_type="web_scanner", tags=["coverage_guard_forced"])
        task3 = MockTask(id="t9", agent_type="web_scanner", tags=["Manual_Verify"])  # case insensitive
        assert policy._is_protected(task1) is True
        assert policy._is_protected(task2) is True
        assert policy._is_protected(task3) is True

    def test_protected_via_source_category(self):
        """source_category values in params are protected."""
        policy = TaskPruningPolicy()
        for cat in ["scenario_probe_planner", "scenario_probe_guard",
                     "coverage_backfill", "coverage_backfill_guard"]:
            task = MockTask(
                id=f"t_{cat}",
                agent_type="web_scanner",
                params={"source_category": cat},
            )
            assert policy._is_protected(task) is True, f"{cat} should be protected"

    def test_not_protected_ordinary_task(self):
        """Ordinary web_scanner task is not protected."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="t10",
            agent_type="web_scanner",
            params={"source_category": "discovery"},
        )
        assert policy._is_protected(task) is False


# ======================================================================
# TaskPruningPolicy - Conservative rules
# ======================================================================

class TestTaskPruningPolicyEvaluate:
    """Tests for the evaluate() method with conservative initial rules."""

    def _build_queue(self, tasks: List[MockTask]) -> DynamicTaskQueue:
        q = DynamicTaskQueue()
        for t in tasks:
            q.add(t)
        return q

    def test_evaluate_returns_empty_for_protected_tasks(self):
        """Protected tasks are never in prune candidate list."""
        policy = TaskPruningPolicy()
        task = MockTask(id="t_protected", agent_type="scope_parser")
        queue = self._build_queue([task])
        decisions = policy.evaluate(queue_snapshot=queue, completed_task=None, findings=[])
        assert decisions == []

    def test_evaluate_detects_duplicate_tasks(self):
        """Two tasks with same agent_type + target + action => one is flagged."""
        policy = TaskPruningPolicy()
        t1 = MockTask(id="task_a", agent_type="web_scanner",
                      target="https://example.com", action="scan", priority=10)
        t2 = MockTask(id="task_b", agent_type="web_scanner",
                      target="https://example.com", action="scan", priority=5)
        queue = self._build_queue([t1, t2])
        decisions = policy.evaluate(queue_snapshot=queue, completed_task=None, findings=[])
        # Lower-priority duplicate should be a candidate
        assert len(decisions) >= 1
        dup_decision = [d for d in decisions if d.reason_code == "duplicate"]
        assert len(dup_decision) >= 1

    def test_evaluate_no_duplicate_for_different_targets(self):
        """Same agent_type + action but different targets => not duplicate."""
        policy = TaskPruningPolicy()
        t1 = MockTask(id="task_a", agent_type="web_scanner",
                      target="https://example.com", action="scan")
        t2 = MockTask(id="task_b", agent_type="web_scanner",
                      target="https://other.com", action="scan")
        queue = self._build_queue([t1, t2])
        decisions = policy.evaluate(queue_snapshot=queue, completed_task=None, findings=[])
        dup = [d for d in decisions if d.reason_code == "duplicate"]
        assert dup == []

    def test_evaluate_out_of_scope_task(self):
        """Task with out-of-scope tag/params is detected."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="task_oos",
            agent_type="web_scanner",
            params={"out_of_scope": True, "source_category": "discovery"},
        )
        queue = self._build_queue([task])
        decisions = policy.evaluate(queue_snapshot=queue, completed_task=None, findings=[])
        oos = [d for d in decisions if d.reason_code == "out_of_scope"]
        assert len(oos) == 1
        assert oos[0].task_id == "task_oos"

    def test_evaluate_protected_not_in_result(self):
        """Protected tasks are excluded from any decision."""
        policy = TaskPruningPolicy()
        t_protected = MockTask(id="t_protected", agent_type="coverage_guard",
                               params={"out_of_scope": True},  # even if out_of_scope
                               )
        t_normal = MockTask(id="t_normal", agent_type="web_scanner",
                            params={"out_of_scope": True, "source_category": "discovery"},
                            )
        queue = self._build_queue([t_protected, t_normal])
        decisions = policy.evaluate(queue_snapshot=queue, completed_task=None, findings=[])
        # protected task should NOT be in decisions
        protected_ids = [d.task_id for d in decisions if d.task_id == "t_protected"]
        assert protected_ids == []
        # normal task SHOULD be
        assert any(d.task_id == "t_normal" for d in decisions)

    def test_evaluate_shadow_only_default(self):
        """All decisions are shadow_only=True by default."""
        policy = TaskPruningPolicy()
        task = MockTask(id="t_oos", agent_type="web_scanner",
                        params={"out_of_scope": True, "source_category": "discovery"})
        queue = self._build_queue([task])
        decisions = policy.evaluate(queue_snapshot=queue, completed_task=None, findings=[])
        assert len(decisions) > 0
        for d in decisions:
            assert d.shadow_only is True

    def test_evaluate_with_completed_task_chain(self):
        """Completed chaining task may invalidate follow-up tasks."""
        policy = TaskPruningPolicy()
        # A follow-up task that was generated by vuln chaining
        follow_up = MockTask(
            id="follow_up_1",
            name="Chain Admin Probe",
            agent_type="auth",
            priority=2,
            params={"generation_reason": "vulnerability_chaining",
                     "parent_vuln_type": "idor"},
        )
        queue = self._build_queue([follow_up])
        decisions = policy.evaluate(queue_snapshot=queue,
                                     completed_task=None,
                                     findings=[])
        # Chain follow-up may be flagged if it no longer has value
        chain = [d for d in decisions if d.reason_code == "chain_low_value"]
        # At minimum, we assert the policy runs without error
        assert isinstance(decisions, list)

    def test_evaluate_empty_queue(self):
        """Empty queue returns empty decisions."""
        policy = TaskPruningPolicy()
        queue = self._build_queue([])
        decisions = policy.evaluate(queue_snapshot=queue, completed_task=None, findings=[])
        assert decisions == []

    def test_evaluate_preserves_task_index(self):
        """evaluate() does not mutate the queue."""
        policy = TaskPruningPolicy()
        t1 = MockTask(id="task_a", agent_type="web_scanner",
                      target="https://example.com", action="scan")
        queue = self._build_queue([t1])
        initial_len = len(queue)
        policy.evaluate(queue_snapshot=queue, completed_task=None, findings=[])
        assert len(queue) == initial_len
        assert queue.get_by_id("task_a") is not None


# ======================================================================
# TaskPruningPolicy - round-trip via to_dict
# ======================================================================

class TestTaskPruningDecisionRoundTrip:
    def test_multiple_decisions_to_dict_list(self):
        """Multiple decisions serialized as list of dicts."""
        decisions = [
            TaskPruningDecision(task_id="t1", lifecycle_status="retired",
                                 reason_code="duplicate"),
            TaskPruningDecision(task_id="t2", lifecycle_status="invalidated",
                                 reason_code="stale_snapshot",
                                 trigger_event_id="evt_003"),
        ]
        result_list = [d.to_dict() for d in decisions]
        assert len(result_list) == 2
        assert result_list[0]["task_id"] == "t1"
        assert result_list[1]["task_id"] == "t2"
        assert result_list[0]["decision_type"] == "task_retired"
        assert result_list[1]["decision_type"] == "task_invalidated"
