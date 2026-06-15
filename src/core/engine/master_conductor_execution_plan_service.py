"""
Execution Plan Service

execute_with_replan / _execute_single_task_full_flow から切り出す
Plan/Apply/Decision 用 dataclass + builder 群。

責務: バッチ実行計画、タイムアウトリカバリ計画、結果適用計画、
失敗リプラン判定、dispatch timeout 判定を pure function で提供する。

状態変更（task_queue / execution_log / pending_hitl / event emission）は
facade 側の責務とする。本 service は副作用を持たない pure function として実装する。

依存方向:
  master_conductor.py -> master_conductor_execution_plan_service.py
  master_conductor_execution_plan_service.py -> master_conductor_execution_runner_service.py
  (runner service の build_parallel_tasks / compute_batch_timeout_params を利用)

本 service から master_conductor.py への import は禁止。

責務分割 gate:
- 1 helper = 1 unit（batch plan / recovery / result apply / failure policy 混在禁止）
- 代表 test と利用箇所のない helper / dependency field は追加しない
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from src.core.engine.master_conductor_execution_runner_service import (
    build_parallel_tasks,
    compute_batch_timeout_params,
)


# ═══════════════════════════════════════════════════════════════════════════
# Plan Dataclasses
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class BatchExecutionPlan:
    """execute_with_replan のバッチ実行計画（pure plan）。

    facade は本 plan を受け取り、orchestrator 実行・task mutation・
    completed_tasks 追加を担当する。
    """
    batch_tasks: list[Any] = field(default_factory=list)
    parallel_tasks: list[Any] = field(default_factory=list)
    batch_timeout: int = 600
    chunk_size: int = 0
    has_injection: bool = False
    has_recon_master: bool = False
    mixed_agents: bool = False
    execution_mode: str = "parallel"
    source_phase: str = "execute_with_replan"
    decision_reason: str = ""
    affected_task_ids: list[str] = field(default_factory=list)
    skipped_task_ids: list[str] = field(default_factory=list)


@dataclass
class TimeoutRecoveryPlan:
    """batch timeout 時の逐次リカバリ計画（pure plan）。

    facade は未完了 task を _execute_single_task_full_flow で recovery し、
    skipped_completed_task_ids は再実行しない。
    """
    recovery_task_ids: list[str] = field(default_factory=list)
    skipped_completed_task_ids: list[str] = field(default_factory=list)
    decision_reason: str = ""
    failure_reason: str = ""
    source_phase: str = "batch_recovery"


@dataclass
class BatchResultApplyPlan:
    """orchestrator 結果から task state 反映計画（pure plan）。

    failed_tasks: orchestrator が失敗報告した task（未完了の場合のみ FAILED へ）
    既に SUCCESS/FAILED/SKIPPED の task は上書きしない。
    """
    failed_tasks: list[dict] = field(default_factory=list)
    failure_reason: str = ""
    decision_reason: str = ""
    affected_task_ids: list[str] = field(default_factory=list)
    source_phase: str = "orchestrator_batch"


@dataclass
class TaskResultApplyPlan:
    """_execute_single_task_full_flow の成功/失敗分岐計画（pure plan）。

    intent: "success" または "failure"
    本 plan は state/context/finding intent までに限定し、
    DecisionEnhancer / DiffAnalyzer / PriorityBooster / handoff / event emit は
    facade-only hook zone として残す。
    """
    intent: str = ""
    task_state: Any = None
    error_message: Optional[str] = None
    failure_reason: Optional[str] = None
    failure_phase: Optional[str] = None
    context_update: Optional[dict] = None
    finding_intents: list[Any] = field(default_factory=list)
    new_assets: list[Any] = field(default_factory=list)
    react_intent: bool = False
    handoff_intent: bool = False
    source_phase: str = "task_result"
    decision_reason: str = ""
    affected_task_ids: list[str] = field(default_factory=list)


@dataclass
class FailureReplanDecision:
    """失敗時のリプラン判定結果（pure plan）。

    facade は should_replan=True の場合のみ replan() / _add_tasks() を実行する。
    quarantine 判定は facade の flaky tracker に委譲する。
    """
    should_replan: bool = False
    should_quarantine: bool = False
    quarantine_reason: Optional[str] = None
    wait_seconds: float = 0.0
    retry_recommended: bool = True
    root_cause_category: Optional[str] = None
    source_phase: str = "failure_replan"
    decision_reason: str = ""
    affected_task_ids: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
# Timeout / Utility
# ═══════════════════════════════════════════════════════════════════════════


def is_timeout_related(error: Any) -> bool:
    """例外がタイムアウト関連かどうかを判定する（pure function）。"""
    if error is None:
        return False
    import asyncio
    from concurrent.futures import TimeoutError as FutureTimeoutError
    if isinstance(error, (FutureTimeoutError, asyncio.TimeoutError, TimeoutError)):
        return True
    message = str(error).lower()
    return "timeout" in message or "timed out" in message


# ═══════════════════════════════════════════════════════════════════════════
# Plan Builders (Phase A: execute_with_replan)
# ═══════════════════════════════════════════════════════════════════════════


def build_batch_execution_plan(
    batch_tasks: list[Any],
    execute_single_task_fn: Any,
    *,
    has_injection: bool,
    injection_manager_timeout: int = 1800,
    injection_batch_parallelism: int = 2,
    parallel_batch_timeout: int = 600,
    recon_master_timeout: int = 900,
    injection_full_parallel_dispatch: bool = False,
) -> BatchExecutionPlan:
    """execute_with_replan のバッチ実行計画を構築する（pure function）。"""
    p_tasks = build_parallel_tasks(batch_tasks, execute_single_task_fn)
    batch_timeout, chunk_size, has_recon_master, mixed_agents = compute_batch_timeout_params(
        batch_tasks,
        has_injection,
        injection_manager_timeout=injection_manager_timeout,
        injection_batch_parallelism=injection_batch_parallelism,
        parallel_batch_timeout=parallel_batch_timeout,
        recon_master_timeout=recon_master_timeout,
        injection_full_parallel_dispatch=injection_full_parallel_dispatch,
    )

    execution_mode = "sequential_chunked" if has_injection and chunk_size > 0 else "parallel"
    affected_ids = [str(getattr(t, "id", "")) for t in batch_tasks]

    return BatchExecutionPlan(
        batch_tasks=batch_tasks,
        parallel_tasks=p_tasks,
        batch_timeout=batch_timeout,
        chunk_size=chunk_size,
        has_injection=has_injection,
        has_recon_master=has_recon_master,
        mixed_agents=mixed_agents,
        execution_mode=execution_mode,
        decision_reason=(
            f"injection_batch_chunked(chunk={chunk_size})" if has_injection
            else f"parallel_batch(timeout={batch_timeout})"
        ),
        affected_task_ids=affected_ids,
    )


def build_timeout_recovery_plan(
    batch_tasks: list[Any],
    batch_exception: Any,
) -> TimeoutRecoveryPlan:
    """batch timeout 時の逐次リカバリ計画を構築する（pure function）。"""
    from src.core.domain.model.task import TaskState

    timeout_related = is_timeout_related(batch_exception)
    failure_reason = "timeout_batch" if timeout_related else type(batch_exception).__name__

    recovery_ids: list[str] = []
    skipped_ids: list[str] = []

    for task in batch_tasks:
        tid = str(getattr(task, "id", ""))
        task_state = getattr(task, "state", None)
        if task_state in [TaskState.SUCCESS, TaskState.FAILED, TaskState.SKIPPED]:
            skipped_ids.append(tid)
        else:
            recovery_ids.append(tid)

    return TimeoutRecoveryPlan(
        recovery_task_ids=recovery_ids,
        skipped_completed_task_ids=skipped_ids,
        decision_reason=f"batch_{failure_reason}_recovery",
        failure_reason=failure_reason,
    )


def build_batch_result_apply_plan(
    batch_tasks: list[Any],
    results: list[Any],
    is_timeout_checker: Any = None,
) -> BatchResultApplyPlan:
    """orchestrator 結果から task state 反映計画を構築する（pure function）。"""
    from src.core.domain.model.task import TaskState

    if is_timeout_checker is None:
        is_timeout_checker = is_timeout_related

    task_map: dict[str, Any] = {str(getattr(t, "id", "")): t for t in batch_tasks}
    failed: list[dict] = []
    affected_ids: list[str] = []

    for res in results:
        tid = str(getattr(res, "task_id", ""))
        task = task_map.get(tid)
        if not task:
            continue
        if getattr(res, "success", True):
            continue
        task_state = getattr(task, "state", None)
        if task_state in [TaskState.SUCCESS, TaskState.FAILED, TaskState.SKIPPED]:
            continue
        error_str = str(getattr(res, "error", ""))
        reason = (
            "timeout_orchestrator"
            if is_timeout_checker(error_str)
            else (error_str or "orchestrator_failed")
        )
        affected_ids.append(tid)
        failed.append({
            "task": task,
            "task_id": tid,
            "error": error_str,
            "failure_reason": reason,
        })

    return BatchResultApplyPlan(
        failed_tasks=failed,
        failure_reason="orchestrator_batch",
        decision_reason=f"orchestrator_result_apply(failed={len(failed)}/{len(results)})",
        affected_task_ids=affected_ids,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Plan Builders (Phase B: _execute_single_task_full_flow)
# ═══════════════════════════════════════════════════════════════════════════


def build_success_apply_plan(
    task: Any,
    result: dict[str, Any],
) -> TaskResultApplyPlan:
    """タスク成功時の apply plan を構築する（pure function）。"""
    from src.core.domain.model.task import TaskState

    findings = result.get("findings", []) if isinstance(result, dict) else []
    new_assets = result.get("new_assets", []) if isinstance(result, dict) else []

    return TaskResultApplyPlan(
        intent="success",
        task_state=TaskState.SUCCESS,
        finding_intents=list(findings),
        new_assets=list(new_assets) if isinstance(new_assets, list) else [],
        react_intent=True,
        handoff_intent=True,
        source_phase="task_result_success",
        decision_reason="dispatch_success",
        affected_task_ids=[str(getattr(task, "id", ""))],
    )


def build_failure_apply_plan(
    task: Any,
    result: dict[str, Any],
    *,
    failure_phase: str = "dispatch_result",
) -> TaskResultApplyPlan:
    """タスク失敗時の apply plan を構築する（pure function）。"""
    from src.core.domain.model.task import TaskState

    result = result if isinstance(result, dict) else {}
    error_msg = str(result.get("error", getattr(task, "error", "")) or "")
    phase = str(result.get("phase", failure_phase))

    return TaskResultApplyPlan(
        intent="failure",
        task_state=TaskState.FAILED,
        error_message=error_msg,
        failure_reason="unknown_error",
        failure_phase=phase,
        source_phase="task_result_failure",
        decision_reason="dispatch_failed",
        affected_task_ids=[str(getattr(task, "id", ""))],
    )


def build_failure_replan_decision(
    task: Any,
    root_cause: Any,
    flaky_verdict: dict[str, Any],
    *,
    max_replan_depth: int = 3,
    max_wait_seconds: float = 15.0,
) -> FailureReplanDecision:
    """失敗時のリプラン判定を構築する（pure function）。"""
    task_replan_depth = int(getattr(task, "replan_depth", 0) or 0)
    retry_recommended = getattr(root_cause, "retry_recommended", True) if root_cause else True
    root_cause_category = str(getattr(root_cause, "category", "") if root_cause else "")
    root_cause_wait = float(getattr(root_cause, "wait_seconds", 0.0) or 0.0) if root_cause else 0.0

    should_replan = task_replan_depth < max_replan_depth
    should_quarantine = False
    quarantine_reason = None

    flaky_status = str(flaky_verdict.get("status", "") or "")
    if flaky_status == "quarantine":
        should_replan = False
        should_quarantine = True
        quarantine_reason = "flaky_auto_quarantine"

    if should_replan and not retry_recommended:
        should_replan = False

    wait_seconds = min(root_cause_wait, max_wait_seconds) if should_replan else 0.0

    reasons: list[str] = []
    if not should_replan:
        if task_replan_depth >= max_replan_depth:
            reasons.append(f"max_depth_reached({task_replan_depth}>={max_replan_depth})")
        if should_quarantine:
            reasons.append(f"flaky_quarantine({flaky_status})")
        if not retry_recommended:
            reasons.append(f"retry_not_recommended(cat={root_cause_category})")
    else:
        reasons.append("retry_recommended")

    return FailureReplanDecision(
        should_replan=should_replan,
        should_quarantine=should_quarantine,
        quarantine_reason=quarantine_reason,
        wait_seconds=wait_seconds,
        retry_recommended=retry_recommended,
        root_cause_category=root_cause_category if root_cause_category else None,
        decision_reason="; ".join(reasons) if reasons else "default_allow",
        affected_task_ids=[str(getattr(task, "id", ""))],
    )


def build_dispatch_timeout_decision(
    task: Any,
    *,
    injection_manager_timeout: int = 1800,
) -> tuple[Optional[int], str]:
    """_execute_single_task_full_flow の dispatch timeout 判定（pure function）。

    Returns:
        (timeout_override, decision_reason)
        timeout_override が None の場合はデフォルトタイムアウトを使用。
    """
    agent_type = str(getattr(task, "agent_type", "") or "")
    injection_agents = {
        "InjectionManager", "InjectionManagerAgent", "injection_manager",
        "InjectionSwarm", "injection_manager_agent",
    }
    is_injection = agent_type in injection_agents or "Injection" in agent_type

    if is_injection:
        return injection_manager_timeout, f"injection_extended_timeout({injection_manager_timeout}s)"
    return None, "default_timeout"
