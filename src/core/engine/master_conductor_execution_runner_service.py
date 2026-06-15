"""
Execution Runner Service

execute_with_replan / _execute_single_task_full_flow から切り出す
pure helper 群。event payload builder、execution record 構築、
batch size/timeout 計算を担当する。

Plan/Apply/Decision 用 dataclass + builder は
master_conductor_execution_plan_service.py に分離。

状態変更（task_queue / execution_log / pending_hitl / event emission）は
facade 側の責務とする。本 service は副作用を持たない pure function として実装する。

依存方向: master_conductor.py -> master_conductor_execution_runner_service.py -> なし
本 service から master_conductor.py への import は禁止。
"""

from __future__ import annotations

from typing import Any

from src.core.domain.model.task import Task


# ── Event Payload Builders ────────────────────────────────────────────────


def build_task_started_payload(
    task: Task,
    *,
    correlation: dict[str, Any],
) -> dict[str, Any]:
    """TASK_STARTED イベント用 payload を構築する（pure function）。

    facade は本関数の戻り値を event_bus.emit_sync() に渡す。
    """
    from src.core.infra.event_bus import get_event_bus  # import 解決用
    from src.core.observability.phase1_contracts import ensure_observability_fields

    return ensure_observability_fields(
        {
            "task_id": task.id,
            "task_name": task.name,
            "agent": task.agent_type,
        },
        correlation=correlation,
        endpoint=str(task.params.get("target", "") or ""),
        error_type="none",
        timeout_ms=int(task.params.get("timeout", 0) or 0),
        retry_count=int(getattr(task, "timeout_retry_count", 0) or 0),
        test_case_id=str(task.id),
    )


def build_task_state_event_payload(
    task: Task,
    result: dict[str, Any],
    *,
    correlation: dict[str, Any],
) -> dict[str, Any]:
    """TASK_COMPLETED / TASK_FAILED 共用 payload を構築する（pure function）。

    result は dispatch の戻り値 dict または {"success": False, "error": ...}。
    """
    from src.core.observability.phase1_contracts import ensure_observability_fields
    from src.core.observability.phase2_classification import classify_failure_pattern

    reason_code = str(getattr(task, "failure_reason_code", "") or "")
    error_message = str(result.get("error", "") or getattr(task, "error", "") or "")
    return ensure_observability_fields(
        {
            "task_id": task.id,
            "task_name": task.name,
            "agent": task.agent_type,
            "state": str(getattr(task, "state", "")),
            "success": bool(result.get("success", False)),
            "phase": str(result.get("phase", "") or ""),
            "failure_reason_code": reason_code,
            "failure_category": classify_failure_pattern(
                reason_code=reason_code,
                error_message=error_message,
            ),
        },
        correlation=correlation,
        endpoint=str(task.params.get("target", "") or ""),
        error_type=error_message or "none",
        timeout_ms=int(task.params.get("timeout", 0) or 0),
        retry_count=int(getattr(task, "timeout_retry_count", 0) or 0),
        test_case_id=str(task.id),
    )


# ── Execution Record Builder ──────────────────────────────────────────────


def build_execution_record_init(task: Task) -> Any:
    """TaskExecutionRecord の初期構築（pure function）。

    facade 側で start_time や mark_completed の管理を行う。
    """
    from src.core.models.task_execution_log import TaskExecutionRecord

    return TaskExecutionRecord(
        task_id=task.id,
        task_name=task.name,
        agent_type=task.agent_type,
        action=task.action,
        target_url=task.params.get("target", ""),
        parameters=task.params.copy(),
        source=getattr(task, "source", "unknown"),
    )


# ── Batch Computation Helpers ───────────────────────────────────────────


def compute_batch_size(
    task_queue: Any,
    resource_manager: Any,
    *,
    injection_full_parallel_dispatch: bool = False,
    injection_batch_parallelism: int = 2,
) -> tuple[int, bool]:
    """execute_with_replan のバッチサイズ計算（pure function）。

    Returns:
        (suggested_batch_size, has_injection_in_queue)
    """
    suggested_batch = getattr(resource_manager, "get_suggested_concurrency", lambda: 5)()

    first_task = task_queue.peek() if task_queue is not None else None
    first_agent_type = (first_task.agent_type or "") if first_task else ""
    has_injection_in_queue = "injection" in first_agent_type.lower()

    if has_injection_in_queue:
        if injection_full_parallel_dispatch:
            injection_batch_limit = max(1, int(injection_batch_parallelism))
            suggested_batch = max(1, min(int(suggested_batch or 1), injection_batch_limit))
        else:
            suggested_batch = 1

    return suggested_batch, has_injection_in_queue


def build_parallel_tasks(
    batch_tasks: list[Any],
    execute_single_task_fn: Any,
) -> list[Any]:
    """batch_tasks から ParallelTask オブジェクトのリストを構築する（pure function）。

    create_parallel_task は facade から import するため、呼び出しは service 内で行う。
    """
    from src.core.engine.parallel_orchestrator import create_parallel_task

    return [
        create_parallel_task(
            t.id, execute_single_task_fn, t, category=t.agent_type or "default"
        )
        for t in batch_tasks
    ]


def compute_batch_timeout_params(
    batch_tasks: list[Any],
    has_injection: bool,
    *,
    injection_manager_timeout: int = 1800,
    injection_batch_parallelism: int = 2,
    parallel_batch_timeout: int = 600,
    recon_master_timeout: int = 900,
    injection_full_parallel_dispatch: bool = False,
) -> tuple[int, int, bool, bool]:
    """execute_with_replan の batch timeout / chunk size 計算（pure function）。

    Returns:
        (batch_timeout, chunk_size, has_recon_master, mixed_agents)
        - has_recon_master: batch 内に recon_master タスクが含まれる
        - mixed_agents: injection 系と非 injection 系が混在している
    """
    has_recon_master = any(
        "recon_master" in (t.agent_type or "").lower()
        for t in batch_tasks
    )

    if has_injection:
        batch_timeout = injection_manager_timeout
        chunk_size = max(1, int(injection_batch_parallelism))
        mixed_agents = any(
            "injection" not in (t.agent_type or "").lower()
            for t in batch_tasks
        )
        if mixed_agents and not injection_full_parallel_dispatch:
            chunk_size = 1
            batch_timeout = max(
                batch_timeout,
                int(parallel_batch_timeout),
                900,
            )
        return batch_timeout, chunk_size, has_recon_master, mixed_agents

    batch_timeout = int(parallel_batch_timeout)
    if has_recon_master:
        batch_timeout = max(batch_timeout, int(recon_master_timeout))
    return batch_timeout, 0, has_recon_master, False
