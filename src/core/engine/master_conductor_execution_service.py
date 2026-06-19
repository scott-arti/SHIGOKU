"""
MasterConductor batch execution service (SGK-2026-0292).

Pure helper for single batch execution. No MasterConductor instance.
"""

from __future__ import annotations

import logging
from typing import Any

from src.core.domain.model.task import TaskState


def execute_single_batch(
    facade: Any,
    batch_tasks: list,
    executed: int,
    *,
    execute_task_fn: Any,
    orchestrator: Any,
    run_async_safe: Any,
    state_lock: Any,
    record_failure: Any,
    apply_failure: Any,
    apply_result: Any,
) -> tuple:
    """Execute one batch: build plan, run, recover on failure, apply results.

    Extracted from facade._execute_single_batch.
    Returns (results, should_continue). facade is passed for readonly access to settings/etc.
    """
    from src.core.engine.master_conductor_execution_plan_service import (
        build_batch_execution_plan, build_timeout_recovery_plan,
        build_batch_result_apply_plan,
    )
    from src.core.engine.master_conductor_execution_plan_service import (
        is_timeout_related as _svc_is_timeout_related,
    )
    from src.config import settings

    _logger = logging.getLogger(__name__)

    has_injection = any("injection" in (t.agent_type or "").lower() for t in batch_tasks)
    full_parallel_injection = bool(getattr(settings, "injection_full_parallel_dispatch", False))
    plan = build_batch_execution_plan(
        batch_tasks, execute_task_fn,
        has_injection=has_injection,
        injection_manager_timeout=int(getattr(settings, "injection_manager_timeout", 1800)),
        injection_batch_parallelism=int(getattr(settings, "injection_batch_parallelism", 2)),
        parallel_batch_timeout=int(getattr(settings, "parallel_batch_timeout", 600)),
        recon_master_timeout=int(getattr(settings, "recon_master_timeout", 900)),
        injection_full_parallel_dispatch=full_parallel_injection,
    )

    from src.core.logger import logger as rich_logger
    rich_logger.show_tree(
        {f"Task: {t.name}": {"agent": t.agent_type, "priority": t.priority} for t in batch_tasks},
        title=f"Executing Batch (Total executed: {executed})",
    )

    try:
        if plan.has_injection:
            results = []
            for i in range(0, len(plan.parallel_tasks), plan.chunk_size):
                chunk = plan.parallel_tasks[i:i + plan.chunk_size]
                result = run_async_safe(
                    orchestrator.execute_parallel(chunk, timeout=plan.batch_timeout),
                    timeout_override=plan.batch_timeout,
                )
                results.extend(result)
        else:
            results = run_async_safe(
                orchestrator.execute_parallel(plan.parallel_tasks, timeout=plan.batch_timeout),
                timeout_override=plan.batch_timeout,
            )
    except Exception as batch_exc:
        recovery_plan = build_timeout_recovery_plan(batch_tasks, batch_exc)
        _logger.error("Batch execution failed (%s): %r", recovery_plan.failure_reason, batch_exc)

        if _svc_is_timeout_related(batch_exc):
            _logger.warning(
                "Batch timeout detected. Retrying unfinished tasks sequentially (count=%d).",
                len(recovery_plan.recovery_task_ids),
            )
            recovery_map = {str(getattr(t, "id", "")): t for t in batch_tasks}
            for tid in recovery_plan.recovery_task_ids:
                task = recovery_map.get(tid)
                if task is None:
                    continue
                try:
                    execute_task_fn(task)
                except Exception as recovery_exc:
                    _logger.error("Sequential recovery failed for %s: %r", tid, recovery_exc)
                    with state_lock:
                        if task.state not in [TaskState.SUCCESS, TaskState.FAILED]:
                            task.state = TaskState.FAILED
                            task.error = repr(recovery_exc)
                            recovery_reason = (
                                "timeout_recovery"
                                if _svc_is_timeout_related(recovery_exc)
                                else type(recovery_exc).__name__
                            )
                            record_failure(task, "orchestrator_batch_recovery", recovery_reason)

        apply_failure(batch_tasks, recovery_plan.failure_reason)
        return None, True

    apply_plan = build_batch_result_apply_plan(batch_tasks, results)
    apply_result(batch_tasks, apply_plan)
    return results, False
