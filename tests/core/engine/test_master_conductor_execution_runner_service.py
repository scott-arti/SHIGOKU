"""master_conductor_execution_runner_service.py の pure unit tests.

Plan dataclass builder、timeout checker、dispatch timeout decision、
event payload builder、record init builder を直接検証する。

注: 本テストファイルは pure function の logic verification に限定し、
facade (MasterConductor) の state mutation / lock / event emission は含まない。
"""

from __future__ import annotations

import asyncio
from concurrent.futures import TimeoutError as FutureTimeoutError
from unittest.mock import MagicMock

import pytest

from src.core.domain.model.task import Task, TaskState
from src.core.engine.master_conductor_execution_runner_service import (
    build_execution_record_init,
    build_task_started_payload,
    build_task_state_event_payload,
    compute_batch_size,
    compute_batch_timeout_params,
)
from src.core.engine.master_conductor_execution_plan_service import (
    BatchExecutionPlan,
    BatchResultApplyPlan,
    FailureReplanDecision,
    TaskResultApplyPlan,
    TimeoutRecoveryPlan,
    build_batch_execution_plan,
    build_batch_result_apply_plan,
    build_dispatch_timeout_decision,
    build_failure_apply_plan,
    build_failure_replan_decision,
    build_success_apply_plan,
    build_timeout_recovery_plan,
    is_timeout_related,
)


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _make_task(
    task_id: str = "test-01",
    agent_type: str = "swarm",
    action: str = "scan",
    state: TaskState = TaskState.PENDING,
    params: dict | None = None,
    replan_depth: int = 0,
) -> Task:
    return Task(
        id=task_id,
        name=f"Test {task_id}",
        agent_type=agent_type,
        action=action,
        state=state,
        params=params or {"target": "http://example.com"},
        replan_depth=replan_depth,
    )


class _FakeQueue:
    def __init__(self, first_agent_type: str | None = None):
        self._first = _make_task(agent_type=first_agent_type) if first_agent_type else None

    def peek(self):
        return self._first

    def is_empty(self):
        return self._first is None

    def empty(self):
        return self.is_empty()


class _FakeResMgr:
    def get_suggested_concurrency(self):
        return 5


class _FakeResult:
    def __init__(self, task_id: str, success: bool, error: str = ""):
        self.task_id = task_id
        self.success = success
        self.error = error


# ═══════════════════════════════════════════════════════════════════════════
# is_timeout_related
# ═══════════════════════════════════════════════════════════════════════════

def test_is_timeout_related_none():
    assert is_timeout_related(None) is False


def test_is_timeout_related_future_timeout():
    assert is_timeout_related(FutureTimeoutError("timeout")) is True


def test_is_timeout_related_asyncio_timeout():
    assert is_timeout_related(asyncio.TimeoutError()) is True


def test_is_timeout_related_builtin_timeout():
    assert is_timeout_related(TimeoutError()) is True


def test_is_timeout_related_message_contains_timeout():
    assert is_timeout_related(Exception("connection timed out")) is True


def test_is_timeout_related_generic_error():
    assert is_timeout_related(ValueError("bad value")) is False


# ═══════════════════════════════════════════════════════════════════════════
# compute_batch_size
# ═══════════════════════════════════════════════════════════════════════════

def test_compute_batch_size_normal():
    queue = _FakeQueue(first_agent_type="swarm")
    mgr = _FakeResMgr()
    size, has_inj = compute_batch_size(queue, mgr)
    assert size == 5
    assert has_inj is False


def test_compute_batch_size_injection_sequential():
    queue = _FakeQueue(first_agent_type="injection_manager")
    mgr = _FakeResMgr()
    size, has_inj = compute_batch_size(queue, mgr)
    assert size == 1
    assert has_inj is True


def test_compute_batch_size_injection_parallel():
    queue = _FakeQueue(first_agent_type="injection_manager")
    mgr = _FakeResMgr()
    size, has_inj = compute_batch_size(
        queue, mgr,
        injection_full_parallel_dispatch=True,
        injection_batch_parallelism=4,
    )
    assert size == 4
    assert has_inj is True


def test_compute_batch_size_empty_queue():
    queue = _FakeQueue(first_agent_type=None)
    mgr = _FakeResMgr()
    size, has_inj = compute_batch_size(queue, mgr)
    assert size == 5
    assert has_inj is False


# ═══════════════════════════════════════════════════════════════════════════
# compute_batch_timeout_params
# ═══════════════════════════════════════════════════════════════════════════

def test_compute_batch_timeout_normal():
    tasks = [_make_task(task_id="t1")]
    timeout, chunk, has_recon, mixed = compute_batch_timeout_params(tasks, has_injection=False)
    assert timeout == 600
    assert chunk == 0
    assert has_recon is False
    assert mixed is False


def test_compute_batch_timeout_injection():
    tasks = [_make_task(task_id="t1", agent_type="injection_manager")]
    timeout, chunk, has_recon, mixed = compute_batch_timeout_params(
        tasks, has_injection=True, injection_manager_timeout=1800, injection_batch_parallelism=2,
    )
    assert timeout == 1800
    assert chunk == 2
    assert has_recon is False
    assert mixed is False


def test_compute_batch_timeout_mixed_injection():
    tasks = [
        _make_task(task_id="t1", agent_type="injection_manager"),
        _make_task(task_id="t2", agent_type="swarm"),
    ]
    timeout, chunk, has_recon, mixed = compute_batch_timeout_params(
        tasks, has_injection=True,
        injection_manager_timeout=1800, injection_batch_parallelism=2,
        parallel_batch_timeout=600,
    )
    assert mixed is True
    assert chunk == 1  # mixed + not full_parallel
    assert timeout >= 900


def test_compute_batch_timeout_recon_master():
    tasks = [_make_task(task_id="t1", agent_type="recon_master")]
    timeout, chunk, has_recon, mixed = compute_batch_timeout_params(tasks, has_injection=False)
    assert has_recon is True
    assert timeout == 900


# ═══════════════════════════════════════════════════════════════════════════
# build_dispatch_timeout_decision
# ═══════════════════════════════════════════════════════════════════════════

def test_dispatch_timeout_normal():
    task = _make_task(agent_type="swarm")
    timeout, reason = build_dispatch_timeout_decision(task)
    assert timeout is None
    assert reason == "default_timeout"


def test_dispatch_timeout_injection():
    task = _make_task(agent_type="InjectionManagerAgent")
    timeout, reason = build_dispatch_timeout_decision(task, injection_manager_timeout=1800)
    assert timeout == 1800
    assert "1800" in reason


def test_dispatch_timeout_injection_swarm():
    task = _make_task(agent_type="InjectionSwarm")
    timeout, reason = build_dispatch_timeout_decision(task)
    assert timeout == 1800


# ═══════════════════════════════════════════════════════════════════════════
# build_batch_execution_plan
# ═══════════════════════════════════════════════════════════════════════════

def test_build_batch_execution_plan_normal():
    tasks = [_make_task(task_id="t1"), _make_task(task_id="t2")]
    plan = build_batch_execution_plan(
        tasks, _make_task,
        has_injection=False,
        parallel_batch_timeout=600,
    )
    assert isinstance(plan, BatchExecutionPlan)
    assert len(plan.batch_tasks) == 2
    assert plan.has_injection is False
    assert plan.execution_mode == "parallel"
    assert plan.batch_timeout == 600
    assert plan.chunk_size == 0
    assert len(plan.affected_task_ids) == 2
    assert "t1" in plan.affected_task_ids


def test_build_batch_execution_plan_injection():
    tasks = [_make_task(task_id="t1", agent_type="injection_manager")]
    plan = build_batch_execution_plan(
        tasks, _make_task,
        has_injection=True,
        injection_manager_timeout=1800,
        injection_batch_parallelism=2,
    )
    assert plan.has_injection is True
    assert plan.execution_mode == "sequential_chunked"
    assert plan.batch_timeout == 1800
    assert plan.chunk_size == 2


def test_build_batch_execution_plan_trace_fields():
    tasks = [_make_task(task_id="trace-1")]
    plan = build_batch_execution_plan(tasks, _make_task, has_injection=False)
    assert plan.source_phase == "execute_with_replan"
    assert len(plan.decision_reason) > 0
    assert plan.skipped_task_ids == []


# ═══════════════════════════════════════════════════════════════════════════
# build_timeout_recovery_plan
# ═══════════════════════════════════════════════════════════════════════════

def test_timeout_recovery_plan_all_unfinished():
    tasks = [
        _make_task(task_id="t1", state=TaskState.PENDING),
        _make_task(task_id="t2", state=TaskState.RUNNING),
    ]
    exc = asyncio.TimeoutError("timeout")
    plan = build_timeout_recovery_plan(tasks, exc)
    assert plan.failure_reason == "timeout_batch"
    assert set(plan.recovery_task_ids) == {"t1", "t2"}
    assert plan.skipped_completed_task_ids == []


def test_timeout_recovery_plan_some_completed():
    tasks = [
        _make_task(task_id="t1", state=TaskState.SUCCESS),
        _make_task(task_id="t2", state=TaskState.FAILED),
        _make_task(task_id="t3", state=TaskState.PENDING),
    ]
    exc = Exception("generic error")
    plan = build_timeout_recovery_plan(tasks, exc)
    assert plan.failure_reason == "Exception"
    assert plan.recovery_task_ids == ["t3"]
    assert set(plan.skipped_completed_task_ids) == {"t1", "t2"}


def test_timeout_recovery_plan_skipped_state():
    tasks = [
        _make_task(task_id="t1", state=TaskState.SKIPPED),
        _make_task(task_id="t2", state=TaskState.PENDING),
    ]
    exc = FutureTimeoutError("future timeout")
    plan = build_timeout_recovery_plan(tasks, exc)
    assert plan.failure_reason == "timeout_batch"
    assert plan.recovery_task_ids == ["t2"]
    assert "t1" in plan.skipped_completed_task_ids


# ═══════════════════════════════════════════════════════════════════════════
# build_batch_result_apply_plan
# ═══════════════════════════════════════════════════════════════════════════

def test_batch_result_apply_plan_no_failures():
    tasks = [_make_task(task_id="t1"), _make_task(task_id="t2")]
    results = [_FakeResult("t1", success=True), _FakeResult("t2", success=True)]
    plan = build_batch_result_apply_plan(tasks, results)
    assert plan.failed_tasks == []
    assert plan.affected_task_ids == []


def test_batch_result_apply_plan_with_failure():
    tasks = [
        _make_task(task_id="t1", state=TaskState.PENDING),
        _make_task(task_id="t2", state=TaskState.PENDING),
    ]
    results = [_FakeResult("t1", success=False, error="timeout"), _FakeResult("t2", success=True)]
    plan = build_batch_result_apply_plan(tasks, results)
    assert len(plan.failed_tasks) == 1
    assert plan.failed_tasks[0]["task_id"] == "t1"
    assert "timeout" in plan.failed_tasks[0]["failure_reason"]


def test_batch_result_apply_plan_already_completed():
    tasks = [_make_task(task_id="t1", state=TaskState.SUCCESS)]
    results = [_FakeResult("t1", success=False, error="timeout")]
    plan = build_batch_result_apply_plan(tasks, results)
    assert plan.failed_tasks == []  # already SUCCESS, don't overwrite


# ═══════════════════════════════════════════════════════════════════════════
# build_success_apply_plan
# ═══════════════════════════════════════════════════════════════════════════

def test_success_apply_plan():
    task = _make_task(task_id="s1")
    result = {"success": True, "findings": [{"title": "XSS"}], "new_assets": ["/admin"]}
    plan = build_success_apply_plan(task, result)
    assert plan.intent == "success"
    assert plan.task_state == TaskState.SUCCESS
    assert len(plan.finding_intents) == 1
    assert plan.new_assets == ["/admin"]
    assert plan.react_intent is True
    assert plan.handoff_intent is True
    assert "s1" in plan.affected_task_ids


def test_success_apply_plan_no_findings():
    task = _make_task(task_id="s2")
    result = {"success": True}
    plan = build_success_apply_plan(task, result)
    assert plan.finding_intents == []
    assert plan.new_assets == []


# ═══════════════════════════════════════════════════════════════════════════
# build_failure_apply_plan
# ═══════════════════════════════════════════════════════════════════════════

def test_failure_apply_plan():
    task = _make_task(task_id="f1")
    result = {"success": False, "error": "connection refused", "phase": "dispatch_result"}
    plan = build_failure_apply_plan(task, result)
    assert plan.intent == "failure"
    assert plan.task_state == TaskState.FAILED
    assert plan.error_message == "connection refused"
    assert plan.failure_phase == "dispatch_result"


def test_failure_apply_plan_fallback_phase():
    task = _make_task(task_id="f2")
    result = {"success": False, "error": "timeout"}
    plan = build_failure_apply_plan(task, result)
    assert plan.failure_phase == "dispatch_result"  # default


# ═══════════════════════════════════════════════════════════════════════════
# build_failure_replan_decision
# ═══════════════════════════════════════════════════════════════════════════

def test_replan_decision_recommended():
    task = _make_task(task_id="r1", replan_depth=0)
    root_cause = MagicMock(retry_recommended=True, category="generic", wait_seconds=0.0)
    flaky = {"status": "ok"}
    decision = build_failure_replan_decision(task, root_cause, flaky, max_replan_depth=3)
    assert decision.should_replan is True
    assert decision.should_quarantine is False
    assert decision.wait_seconds == 0.0


def test_replan_decision_max_depth():
    task = _make_task(task_id="r2", replan_depth=3)
    root_cause = MagicMock(retry_recommended=True, category="generic", wait_seconds=0.0)
    flaky = {"status": "ok"}
    decision = build_failure_replan_decision(task, root_cause, flaky, max_replan_depth=3)
    assert decision.should_replan is False
    assert "max_depth" in decision.decision_reason


def test_replan_decision_flaky_quarantine():
    task = _make_task(task_id="r3", replan_depth=0)
    root_cause = MagicMock(retry_recommended=True, category="generic", wait_seconds=0.0)
    flaky = {"status": "quarantine", "window_size": 10, "failures": 5, "failure_rate": 0.5}
    decision = build_failure_replan_decision(task, root_cause, flaky, max_replan_depth=3)
    assert decision.should_replan is False
    assert decision.should_quarantine is True
    assert decision.quarantine_reason == "flaky_auto_quarantine"


def test_replan_decision_not_recommended():
    task = _make_task(task_id="r4", replan_depth=0)
    root_cause = MagicMock(retry_recommended=False, category="waf_blocked", wait_seconds=0.0)
    flaky = {"status": "ok"}
    decision = build_failure_replan_decision(task, root_cause, flaky, max_replan_depth=3)
    assert decision.should_replan is False
    assert decision.retry_recommended is False
    assert "retry_not_recommended" in decision.decision_reason


def test_replan_decision_wait_seconds():
    task = _make_task(task_id="r5", replan_depth=0)
    root_cause = MagicMock(retry_recommended=True, category="rate_limited", wait_seconds=5.0)
    flaky = {"status": "ok"}
    decision = build_failure_replan_decision(task, root_cause, flaky, max_replan_depth=3, max_wait_seconds=15.0)
    assert decision.should_replan is True
    assert decision.wait_seconds == 5.0


def test_replan_decision_wait_capped():
    task = _make_task(task_id="r6", replan_depth=0)
    root_cause = MagicMock(retry_recommended=True, category="generic", wait_seconds=100.0)
    flaky = {"status": "ok"}
    decision = build_failure_replan_decision(task, root_cause, flaky, max_replan_depth=3, max_wait_seconds=15.0)
    assert decision.wait_seconds == 15.0


def test_replan_decision_null_root_cause():
    task = _make_task(task_id="r7", replan_depth=0)
    flaky = {"status": "ok"}
    decision = build_failure_replan_decision(task, None, flaky, max_replan_depth=3)
    assert decision.should_replan is True
    assert decision.retry_recommended is True


# ═══════════════════════════════════════════════════════════════════════════
# build_task_started_payload
# ═══════════════════════════════════════════════════════════════════════════

def test_task_started_payload():
    task = _make_task(task_id="p1", agent_type="swarm", params={"target": "http://example.com", "timeout": 30})
    correlation = {"session": "test-session"}
    payload = build_task_started_payload(task, correlation=correlation)
    assert payload["task_id"] == "p1"
    assert payload["task_name"] == "Test p1"
    assert payload["agent"] == "swarm"


# ═══════════════════════════════════════════════════════════════════════════
# build_task_state_event_payload
# ═══════════════════════════════════════════════════════════════════════════

def test_task_completed_payload():
    task = _make_task(task_id="p2", agent_type="swarm", state=TaskState.SUCCESS)
    correlation = {"session": "test-session"}
    result = {"success": True, "phase": "attack"}
    payload = build_task_state_event_payload(task, result, correlation=correlation)
    assert payload["task_id"] == "p2"
    assert str(payload["state"]) in ("TaskState.SUCCESS", "success")
    assert payload["success"] is True


def test_task_failed_payload():
    task = _make_task(task_id="p3", agent_type="swarm", state=TaskState.FAILED)
    task.error = "timeout"
    correlation = {"session": "test-session"}
    result = {"success": False, "error": "timeout", "phase": "dispatch"}
    payload = build_task_state_event_payload(task, result, correlation=correlation)
    assert payload["task_id"] == "p3"
    assert payload["success"] is False


# ═══════════════════════════════════════════════════════════════════════════
# build_execution_record_init
# ═══════════════════════════════════════════════════════════════════════════

def test_execution_record_init():
    task = _make_task(task_id="e1", agent_type="swarm", action="scan",
                      params={"target": "http://example.com"})
    record = build_execution_record_init(task)
    assert record.task_id == "e1"
    assert record.task_name == "Test e1"
    assert record.agent_type == "swarm"


# ═══════════════════════════════════════════════════════════════════════════
# Edge cases
# ═══════════════════════════════════════════════════════════════════════════

def test_is_timeout_related_none_returns_false():
    assert is_timeout_related(None) is False


def test_batch_result_apply_plan_unknown_task_id():
    tasks = [_make_task(task_id="t1")]
    results = [_FakeResult("unknown-id", success=False)]
    plan = build_batch_result_apply_plan(tasks, results)
    assert plan.failed_tasks == []


def test_timeout_recovery_plan_all_skipped():
    tasks = [
        _make_task(task_id="t1", state=TaskState.SKIPPED),
        _make_task(task_id="t2", state=TaskState.SKIPPED),
    ]
    exc = asyncio.TimeoutError("timeout")
    plan = build_timeout_recovery_plan(tasks, exc)
    assert plan.recovery_task_ids == []
    assert len(plan.skipped_completed_task_ids) == 2


def test_dispatch_timeout_decision_unknown_agent():
    task = _make_task(agent_type="unrecognized_agent")
    timeout, _ = build_dispatch_timeout_decision(task)
    assert timeout is None
