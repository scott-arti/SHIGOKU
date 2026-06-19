"""
MasterConductor execution coordinator (SGK-2026-0293).

Handles single task + full flow + parallel execution orchestration.
Takes facade reference as parameter. Does NOT hold MasterConductor instance.

Success/failure handling is delegated to facade._handle_task_success /
facade._handle_task_failure (the canonical implementations in the facade).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from src.core.domain.model.task import Task, TaskState
from src.core.infra.event_bus import Event, EventType, get_event_bus
from src.config import settings

_log = logging.getLogger(__name__)


# ---- SGK-2026-0293: single task execution ----

def execute_task_coordinator(
    facade: Any, task: Task, enable_react: bool = False, enable_replan: bool = True,
) -> dict:
    """Execute a single task with full lifecycle. Extracted from facade.execute_single_task.

    Success/failure handling delegates to facade._handle_task_success / _handle_task_failure.
    """
    task.state = TaskState.RUNNING

    if getattr(facade, "_debug_logger", None):
        facade._debug_logger.log_action(
            agent="MasterConductor", action="single task execution",
            target=task.name, result="running",
            details={"task_id": task.id, "agent_type": task.agent_type},
        )

    try:
        intervention_block = facade._run_intervention_precheck(task)
        if intervention_block is not None:
            if not bool(intervention_block.get("pending_hitl", False)):
                facade.context.update_success_rate(False)
            return intervention_block

        timeout_override = None
        agent_type = str(getattr(task, "agent_type", ""))
        if "Injection" in agent_type or "injection" in agent_type.lower():
            timeout_override = getattr(settings, "injection_manager_timeout", 1800)

        result = facade._dispatch_with_timeout_retry(task, timeout_override=timeout_override)
        task.result = result

        if result.get("success", False):
            facade._handle_task_success(task, result)
        else:
            facade._handle_task_failure(task, result)
            if not enable_replan:
                task.state = TaskState.FAILED

        facade.completed_tasks.append(task)
        facade._mark_pending_hitl_done(task, success=bool(result.get("success", False)))

        if facade._auto_checkpoint:
            facade._checkpoint_counter += 1
            if facade._checkpoint_counter >= getattr(settings, "checkpoint_interval", 5):
                facade._checkpoint()
                facade._checkpoint_counter = 0

        facade._record_task_prioritizer_outcome(task, result)

        # ReAct observation (off by default in interactive mode)
        if enable_react and bool(facade._react_setting("enable_react_observation", False)) and facade.llm_client:
            react_tasks = facade._observe_and_rethink(task, result)
            facade._add_tasks(react_tasks, source="react")

        return result

    except Exception as e:
        task.state = TaskState.FAILED
        task.error = str(e)
        failure_reason = "timeout_exception" if facade._is_timeout_related(e) else type(e).__name__
        facade._record_failure_context(task, "dispatch_exception", failure_reason)
        facade.completed_tasks.append(task)
        facade._mark_pending_hitl_done(task, success=False)
        _log.error("Task execution error: %s", e)
        if facade._auto_checkpoint:
            facade._checkpoint()
        facade._record_task_prioritizer_outcome(task, {"success": False, "error": str(e)})
        return {"success": False, "task_id": task.id, "agent": task.agent_type, "error": str(e)}


# ---- SGK-2026-0293: full flow execution ----

def execute_full_flow_coordinator(facade: Any, task: Task) -> dict:
    """Execute single task full flow. Extracted from facade._execute_single_task_full_flow.

    Success/failure handling delegates to facade._handle_task_success / _handle_task_failure.
    """
    from src.core.engine.master_conductor_execution_runner_service import (
        build_task_started_payload, build_execution_record_init,
    )

    with facade._state_lock:
        task.state = TaskState.RUNNING
        if not facade.accumulated_context.is_empty():
            task.params["_context"] = facade.accumulated_context.to_dict()
        task = facade.context_designer.enrich_task(
            task, facade.context, facade.accumulated_context, workspace=facade.workspace,
        )

    event_bus = getattr(facade, "state", None)
    event_bus = event_bus.event_bus if event_bus else get_event_bus()
    correlation = facade.context.target_info.get("correlation", {})
    started_payload = build_task_started_payload(task, correlation=correlation)
    event_bus.emit_sync(Event(type=EventType.TASK_STARTED, payload=started_payload, source="master_conductor"))
    exec_record = build_execution_record_init(task)

    before_snap_id = facade._capture_task_before_snapshot(task)

    try:
        precheck_result = facade._assess_task_risk(task, exec_record)
        if precheck_result is not None:
            return precheck_result

        from src.core.engine.master_conductor_execution_plan_service import build_dispatch_timeout_decision
        timeout_override, _ = build_dispatch_timeout_decision(
            task, injection_manager_timeout=int(getattr(settings, "injection_manager_timeout", 1800)),
        )
        result = facade._dispatch_with_timeout_retry(task, timeout_override=timeout_override)
        task.result = result

        with facade._state_lock:
            facade._apply_post_dispatch_intelligence(task, result, before_snap_id)
            if result.get("success", False):
                facade._handle_task_success(task, result, exec_record)
            else:
                facade._handle_task_failure(task, result, exec_record)

        hitl_info = facade.check_hitl_required(task, result)
        if hitl_info:
            facade.request_human_approval(hitl_info)
        facade._mark_pending_hitl_done(task, success=bool(result.get("success", False)))
        facade._record_task_prioritizer_outcome(task, result)
        return result

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        error_msg = f"{type(e).__name__}: {str(e)}\n{tb}"
        _log.error("Task %s critical failure: %s", task.id, error_msg)
        failure_reason = "timeout_exception" if facade._is_timeout_related(e) else type(e).__name__
        with facade._state_lock:
            task.state = TaskState.FAILED
            task.error = error_msg
            facade._record_failure_context(task, "dispatch_exception", failure_reason)
            exec_record.mark_completed(success=False, error=error_msg)
            if getattr(facade, "execution_log", None) is not None:
                facade.execution_log.add_record(exec_record)
        facade._emit_task_state_event(
            event_type=EventType.TASK_FAILED, task=task,
            result={"success": False, "error": str(e), "phase": "dispatch_exception"},
        )
        facade._mark_pending_hitl_done(task, success=False)
        facade._record_task_prioritizer_outcome(task, {"success": False, "error": str(e)})
        return {"success": False, "error": str(e)}


# ---- SGK-2026-0293: parallel execution ----

async def execute_parallel_coordinator(facade: Any, max_workers: int = 5) -> dict:
    """Smart parallel execution with dependency awareness. Extracted from facade.execute_parallel."""
    from src.core.engine.smart_scheduler import SmartScheduler

    scheduler = SmartScheduler(max_workers=max_workers)
    while not facade.task_queue.is_empty() and not facade._shutdown_requested:
        task = facade._select_next_task_from_queue()
        if task is None:
            break
        dep_ids = getattr(task, "depends_on", None) or []
        deps = [facade.task_queue.get_by_id(did) for did in dep_ids if facade.task_queue.get_by_id(did)]
        decision_deps = facade._resolve_decision_dependencies(task)
        combined_deps = list(set(deps + decision_deps))
        try:
            scheduler.add_task(task, blocking_on=combined_deps)
        except Exception as e:
            _log.warning("Failed to schedule task %s: %s", task.id, e)

    start = time.time()
    try:
        results = await facade._run_async_safe(scheduler.execute())
    except Exception as e:
        _log.error("SmartScheduler execution failed: %s", e)
        return {"success": False, "error": str(e), "executed": 0, "results": []}

    elapsed = time.time() - start
    total = len(results)
    succeeded = sum(1 for r in results if r.success)
    failed = total - succeeded
    _log.info(
        "Parallel execution completed: %d/%d succeeded in %.1fs (max_workers=%d)",
        succeeded, total, elapsed, max_workers,
    )
    return {
        "success": failed == 0,
        "executed": total,
        "succeeded": succeeded,
        "failed": failed,
        "elapsed_seconds": round(elapsed, 2),
        "results": [{"task_id": r.task_id, "success": r.success, "result": r.result} for r in results],
    }
