from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from src.core.domain.model.task import Task, TaskState
from src.core.engine.master_conductor import MasterConductor


def _new_mc_with_min_context() -> MasterConductor:
    mc = MasterConductor.__new__(MasterConductor)
    mc.completed_tasks = []
    mc.task_queue = []
    mc.pending_hitl = []
    cast(Any, mc).context = SimpleNamespace(
        _total_attempts=0,
        _successful_attempts=0,
        discovered_assets=[],
        bypass_methods=[],
        metrics={"estimated_cost": 0.0, "total_duration": 0},
        target_info={"required_vuln_families": ["api"]},
    )
    return mc


def test_record_failure_context_sets_normalized_reason_code_and_meta() -> None:
    mc = _new_mc_with_min_context()
    task = Task(
        id="task_failure_reason_code_01",
        name="dependency failure",
        agent_type="test_agent",
        action="scan",
        params={},
    )
    task.error = "ModuleNotFoundError: No module named 'pydantic_core'"

    mc._record_failure_context(
        task,
        "dispatch_exception",
        "ModuleNotFoundError: No module named 'pydantic_core'",
    )

    assert getattr(task, "failure_phase") == "dispatch_exception"
    assert getattr(task, "failure_reason_code") == "DEPENDENCY_ERROR"
    assert isinstance(task.params.get("_failure"), dict)
    assert task.params["_failure"]["reason_code"] == "DEPENDENCY_ERROR"


def test_generate_summary_counts_failed_reason_codes() -> None:
    mc = _new_mc_with_min_context()
    task = Task(
        id="task_failure_reason_code_02",
        name="phase2 timeout",
        agent_type="InjectionSwarm",
        action="scan",
        params={"category": "api_candidate"},
    )
    task.state = TaskState.FAILED
    task.error = "Phase 2 timed out after 60s"
    setattr(task, "failure_phase", "dispatch_result")
    setattr(task, "failure_reason", "phase2_timeout")
    mc.completed_tasks = [task]

    summary = mc._generate_summary()

    assert summary["failed"] == 1
    assert summary["failed_reason_codes"].get("TIMEOUT_PHASE2") == 1


def test_generate_summary_counts_skipped_reason_codes() -> None:
    mc = _new_mc_with_min_context()

    skipped_snapshot = Task(
        id="task_skip_reason_code_01",
        name="stale snapshot",
        agent_type="InjectionSwarm",
        action="scan",
        params={"category": "api_candidate"},
    )
    skipped_snapshot.state = TaskState.SKIPPED
    setattr(skipped_snapshot, "failure_phase", "validity_check")
    setattr(skipped_snapshot, "failure_reason", "stale_snapshot")
    skipped_snapshot.error = "Task invalidated before execution"

    skipped_assertion = Task(
        id="task_skip_reason_code_02",
        name="state assertion rejected",
        agent_type="InjectionSwarm",
        action="scan",
        params={"category": "api_candidate"},
    )
    skipped_assertion.state = TaskState.SKIPPED
    setattr(skipped_assertion, "failure_phase", "state_assertion")
    setattr(skipped_assertion, "failure_reason", "state_assertion_precondition_missing")
    skipped_assertion.error = "Missing precondition"

    mc.completed_tasks = [skipped_snapshot, skipped_assertion]

    summary = mc._generate_summary()

    assert summary["skipped"] == 2
    assert summary["skipped_reason_codes"].get("STALE_SNAPSHOT") == 1
    assert summary["skipped_reason_codes"].get("STATE_ASSERTION_PRECONDITION_MISSING") == 1


@pytest.mark.asyncio
async def test_async_save_session_persists_normalized_skipped_reason_codes() -> None:
    mc = _new_mc_with_min_context()
    mc.task_queue = []
    mc.pending_hitl = []
    mc.project_manager = SimpleNamespace(
        project_dir="/tmp/shigoku-test-project",
        save_session=AsyncMock(),
    )
    cast(Any, mc).run_ledger_recorder = SimpleNamespace(prepare_for_session=lambda spool_dir=None: {})

    skipped_task = Task(
        id="task_skip_reason_code_03",
        name="stale auth snapshot",
        agent_type="InjectionSwarm",
        action="scan",
        params={"category": "api_candidate"},
    )
    skipped_task.state = TaskState.SKIPPED
    setattr(skipped_task, "failure_phase", "validity_check")
    setattr(skipped_task, "failure_reason", "stale_auth_context")
    skipped_task.error = "Task auth context is stale"
    mc.completed_tasks = [skipped_task]

    await mc.async_save_session("dummy.json")

    session_data = mc.project_manager.save_session.await_args.args[0]
    assert session_data["completed_tasks"][0]["failure_reason_code"] == "STALE_AUTH_CONTEXT"
