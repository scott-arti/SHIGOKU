from __future__ import annotations

import copy
from typing import Any, TYPE_CHECKING

from src.core.domain.model.task import Task, TaskState

if TYPE_CHECKING:
    from src.core.engine.master_conductor import ExecutionContext


def restore_pending_hitl_from_session_payload(session_data: dict[str, Any]) -> list[dict[str, Any]]:
    pending_hitl = session_data.get("pending_hitl")
    if not isinstance(pending_hitl, list):
        context_data = session_data.get("context", {})
        if isinstance(context_data, dict):
            pending_hitl = context_data.get("pending_hitl", [])
        else:
            pending_hitl = []
    return copy.deepcopy(pending_hitl) if isinstance(pending_hitl, list) else []


def restore_context_from_session_payload(session_data: dict[str, Any], context: "ExecutionContext") -> None:
    context_data = session_data.get("context", {})
    if not isinstance(context_data, dict):
        context_data = {}

    context._total_attempts = context_data.get("total_attempts", 0)
    context._successful_attempts = context_data.get("successful_attempts", 0)
    context.bypass_methods = context_data.get("bypass_methods", [])
    context.discovered_assets = context_data.get("discovered_assets", [])
    context.target_info = context_data.get("target_info", {})


def restore_completed_tasks_from_session_payload(
    session_data: dict[str, Any],
    normalize_failure_reason_code,
) -> list[Task]:
    restored_tasks: list[Task] = []
    for task_dict in session_data.get("completed_tasks", []):
        state_value = task_dict.get("state", "success")
        try:
            state = TaskState(state_value)
        except ValueError:
            state = TaskState.SUCCESS

        # Sanitize state for from_dict (may raise ValueError on invalid states)
        task_dict["state"] = state.value
        task = Task.from_dict(task_dict)
        # Override with already-parsed state to preserve existing behavior
        task.state = state
        task.error = task_dict.get("error")
        task.result = task_dict.get("result")
        task.failure_phase = task_dict.get("failure_phase")
        task.failure_reason = task_dict.get("failure_reason")
        task.failure_reason_code = task_dict.get("failure_reason_code")
        if not task.failure_reason_code and task.failure_reason:
            task.failure_reason_code = normalize_failure_reason_code(
                str(task.failure_phase or ""),
                task.failure_reason,
                task.error,
            )
        task.timeout_retry_count = int(task_dict.get("timeout_retry_count", 0) or 0)
        restored_tasks.append(task)

    return restored_tasks


def restore_task_queue_from_session_payload(
    session_data: dict[str, Any],
    should_rerun_running: bool,
    on_invalid_state=None,
) -> list[Task]:
    restored_tasks: list[Task] = []
    for task_dict in session_data.get("task_queue", []):
        state_str = task_dict.get("state", "pending")

        if state_str == "running":
            state = TaskState.PENDING if should_rerun_running else TaskState.SKIPPED
        else:
            try:
                state = TaskState(state_str)
            except ValueError:
                if on_invalid_state is not None:
                    on_invalid_state(state_str)
                state = TaskState.PENDING

        # Sanitize state for from_dict (may raise ValueError on invalid states)
        task_dict["state"] = state.value
        task = Task.from_dict(task_dict)
        # Override with already-resolved state to preserve existing behavior
        task.state = state
        restored_tasks.append(task)

    return restored_tasks
