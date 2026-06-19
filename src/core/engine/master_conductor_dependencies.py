"""
MasterConductor 依存束ねモジュール

facade から各 service へ渡すための依存束ね用 dataclass / protocol 群。
service は self 全体を保持せず、必要な依存だけを本モジュール経由で受け取る。

所有権ルール:
- task_queue / context / phase_gate / event_bus / _state_lock / pending_hitl / project_manager
  は MasterConductor facade が所有し、service へは明示的に渡す。
- 依存方向: master_conductor.py -> master_conductor_* service/helper -> serializer/helper
  の一方向のみ。service 間の循環 import は禁止。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional, Callable

if TYPE_CHECKING:
    from src.core.engine.phase_gate import PhaseGate
    from src.core.infra.event_bus import EventBus
    from src.core.domain.model.task import Task
    from src.core.engine.master_conductor import ExecutionContext


@dataclass
class PlannerDependencies:
    """recon attack task planner へ渡す依存束ね

    planner は queue mutation を持たず list[Task] を返す。
    PhaseGate.can_create_task() / recon file resolve / history replay など
    既存 self 依存は本 dataclass 経由で明示的に渡す。
    """
    phase_gate: Any = None  # PhaseGate
    task_id_generator: Optional[Callable[[], str]] = None
    resolve_recon_file_path: Optional[Callable[..., Any]] = None
    resolve_project_tagged_dir: Optional[Callable[[], Any]] = None
    collect_history_replay_targets: Optional[Callable[..., Any]] = None
    collect_xss_seed_targets: Optional[Callable[..., Any]] = None
    collect_csrf_seed_targets: Optional[Callable[..., Any]] = None
    score_csrf_seed_candidate: Optional[Callable[..., Any]] = None
    score_xss_seed_candidate: Optional[Callable[..., Any]] = None
    is_low_value_backfill_target: Optional[Callable[..., Any]] = None
    refine_backfill_seed_targets: Optional[Callable[..., Any]] = None
    should_enable_phase2_on_empty_for_backfill: Optional[Callable[..., Any]] = None
    apply_phase2_on_empty_policy: Optional[Callable[..., Any]] = None
    collect_scenario_probe_seed_targets: Optional[Callable[..., Any]] = None
    select_targets_for_scenario_probe: Optional[Callable[..., Any]] = None
    context_target_info: Optional[dict[str, Any]] = None
    auth_cookies: Optional[dict[str, str]] = None
    _loaded_recipes: Optional[set[str]] = None
    _injected_task_ids: Optional[set[str]] = None
    _processed_techs: Optional[set[str]] = None
    # scenario catalog
    scn_catalog: tuple = ()


@dataclass
class HitlDependencies:
    """HITL service へ渡す依存束ね

    pending_hitl の所有は facade に残しつつ、
    ticket 構築・状態遷移・approved enqueue をサービス化する。
    """
    pending_hitl: list[dict[str, Any]] = field(default_factory=list)
    task_queue: Any = None  # DynamicTaskQueue
    intervention_policy: Any = None
    human_approval_callback: Optional[Callable[[dict], bool]] = None
    task_id_generator: Optional[Callable[[], str]] = None


@dataclass
class DispatchDependencies:
    """dispatch service へ渡す依存束ね

    scope guard / worker route / swarm fallback / recon duplicate skip /
    AgentFactory fallback / recipe dispatch を含む。
    """
    task_queue: Any = None  # DynamicTaskQueue
    phase_gate: Any = None  # PhaseGate
    event_bus: Any = None  # EventBus
    agent_factory: Any = None
    recipe_loader: Any = None
    network_client: Any = None
    settings: Any = None
    mode: str = "BUG_BOUNTY"
    _recon_executed: bool = False
    _loaded_recipes: Optional[set[str]] = None
    _injected_task_ids: Optional[set[str]] = None
    _processed_techs: Optional[set[str]] = None


@dataclass
class ReconExecutionDependencies:
    """recon execution service へ渡す依存束ね

    ReconPipeline 実行と PhaseGate 反映を担当する。
    facade 参照が不要になるよう、ReconPipeline(master_conductor=self) を
    直接生成しないための adapter 境界として使用する。
    """
    phase_gate: Any = None  # PhaseGate
    event_bus: Any = None  # EventBus
    task_queue: Any = None  # DynamicTaskQueue
    settings: Any = None
    mode: str = "BUG_BOUNTY"
    _recon_executed: bool = False
    attack_planner: Any = None
    network_client: Any = None
    # ReconPipeline 構築に必要な facade 依存
    project_manager: Any = None
    workspace_root: Optional[str] = None
    # recon 結果から attack task を生成して queue に追加する callable
    create_attack_tasks_from_recon: Optional[Callable[..., Any]] = None
    add_tasks: Optional[Callable[..., Any]] = None
    # recon 重複実行防止フラグの mutation（service からは参照のみ、set は facade）
    set_recon_executed: Optional[Callable[[], None]] = None
    # SGK-2026-0288: ReconPipeline adapter に必要な追加依存
    target_info: Optional[dict[str, Any]] = None
    llm_client: Any = None


# ---- SGK-2026-0287 Phase 2: Constructor decomposition helpers ----


def build_core_dependencies(
    graph: Any = None,
    recipe_loader: Any = None,
) -> dict[str, Any]:
    """Pure helper: construct core dependencies without side effects.

    Returns a dict of constructed objects. Caller assigns to self.* attributes.
    This avoids direct module-level symbol access in __init__ and enables
    testability via explicit dependency injection.
    """
    from src.core.infra.knowledge_graph import KnowledgeGraph
    from src.core.learning.findings_repository import get_findings_repository
    from src.core.infra.async_writer import AsyncDatabaseWriter
    from src.core.models.task_execution_log import get_execution_log

    _graph = graph or KnowledgeGraph()
    repo = get_findings_repository()
    writer = AsyncDatabaseWriter(kg=_graph, repo=repo)
    execution_log = get_execution_log()

    if recipe_loader is None:
        from src.core.engine.recipe_loader import RecipeLoader
        _recipe_loader = RecipeLoader()
    else:
        _recipe_loader = recipe_loader

    return {
        "graph": _graph,
        "repo": repo,
        "writer": writer,
        "execution_log": execution_log,
        "recipe_loader": _recipe_loader,
    }


def build_mode_config(settings: Any) -> dict[str, str]:
    """Pure helper: resolve mode, flag_format, and system_prompt.

    Returns a dict with 'mode', 'flag_format', 'system_prompt'.
    No side effects.
    """
    mode = str(getattr(settings, "environment", "BUG_BOUNTY") or "BUG_BOUNTY")
    if hasattr(settings, "ctf_target") and settings.ctf_target:
        mode = "CTF"

    flag_format = str(getattr(settings, "ctf_flag_format", "flag{.*}") or "flag{.*}")

    from src.core.engine.conductor_prompts import BB_PLANNING_PROMPT, CTF_PLANNING_PROMPT
    system_prompt = CTF_PLANNING_PROMPT.format(flag_format=flag_format) if mode == "CTF" else BB_PLANNING_PROMPT

    return {"mode": mode, "flag_format": flag_format, "system_prompt": system_prompt}


def build_intelligence_modules(llm_client: Any = None, settings: Any = None) -> dict[str, Any]:
    """Pure helper: initialize intelligence module singletons.

    Returns a dict of {attr_name: instance}. Caller assigns to self.*.
    Graceful fallback on initialization failures (logs warnings).
    """
    import logging
    _log = logging.getLogger(__name__)

    from src.core.intelligence import (
        get_risk_predictor, get_self_reflection,
        get_error_analyzer, get_priority_booster,
        get_decision_enhancer, get_diff_analyzer,
        get_task_prioritizer,
        get_chain_builder,
        get_strategy_selector,
    )

    modules: dict[str, Any] = {
        "risk_predictor": get_risk_predictor(),
        "self_reflection": get_self_reflection(),
        "error_analyzer": get_error_analyzer(),
        "priority_booster": get_priority_booster(),
        "decision_enhancer": get_decision_enhancer(),
        "diff_analyzer": get_diff_analyzer(),
    }

    try:
        modules["task_prioritizer"] = get_task_prioritizer()
    except Exception as e:
        _log.warning("TaskPrioritizer initialization failed, fallback to queue priority only: %s", e)
        modules["task_prioritizer"] = None

    try:
        modules["chain_builder"] = get_chain_builder(llm_client=llm_client)
    except Exception as e:
        _log.warning("AttackChainBuilder initialization failed, chain inference disabled: %s", e)
        modules["chain_builder"] = None

    try:
        modules["strategy_selector"] = get_strategy_selector()
    except Exception as e:
        _log.warning("StrategySelector initialization failed, default strategy fallback will be used: %s", e)
        modules["strategy_selector"] = None

    # StrategyOptimizer
    from src.core.engine.strategy_optimizer import StrategyOptimizer
    _mode = str(getattr(settings, "environment", "BUG_BOUNTY") or "BUG_BOUNTY") if settings else "BUG_BOUNTY"
    modules["optimizer"] = StrategyOptimizer(llm_client=llm_client, config={"mode": _mode})

    return modules


# ---- SGK-2026-0287 Phase 3: Runtime loop decision helpers ----


@dataclass
class RuntimeLoopDecision:
    """execute_with_replan のループ継続判断。

    Pure decision: facade が apply する前にサービスが返す。
    """
    action: str = "continue"  # "continue" | "break" | "wait"
    reason: str = ""


def should_checkpoint(
    executed: int,
    auto_checkpoint: bool = True,
    checkpoint_interval: int = 10,
) -> bool:
    """Pure function: checkpoint を保存すべきかを判断。

    Args:
        executed: 現在の実行済みタスク数
        auto_checkpoint: 自動チェックポイント有効フラグ
        checkpoint_interval: チェックポイント間隔
    """
    if not auto_checkpoint:
        return False
    if executed <= 0:
        return False
    if checkpoint_interval <= 0:
        return False
    return executed % checkpoint_interval == 0


def build_runtime_loop_decision(
    executed: int,
    max_tasks: int,
    task_queue_empty: bool,
    shutdown_requested: bool = False,
    has_active_background_workers: bool = False,
) -> RuntimeLoopDecision:
    """Pure function: 実行ループの継続/中断/待機を判断。

    Returns:
        RuntimeLoopDecision with action and reason.
    """
    if shutdown_requested:
        return RuntimeLoopDecision(action="break", reason="shutdown_requested")
    if executed >= max_tasks:
        return RuntimeLoopDecision(action="break", reason="max_tasks_reached")
    if task_queue_empty:
        if has_active_background_workers:
            return RuntimeLoopDecision(action="wait", reason="queue_empty_background_active")
        return RuntimeLoopDecision(action="break", reason="queue_empty_no_workers")
    return RuntimeLoopDecision(action="continue", reason="tasks_available")


def build_recon_dependencies_from_mc(mc: Any) -> ReconExecutionDependencies:
    """MasterConductor facade から ReconExecutionDependencies を構築する。

    抽出先 service は本 dataclass 経由で依存を受け取り、
    ReconPipeline(master_conductor=self) を直接生成しない。
    """
    return ReconExecutionDependencies(
        phase_gate=getattr(mc, "phase_gate", None),
        event_bus=getattr(mc, "event_bus", None),
        task_queue=getattr(mc, "task_queue", None),
        settings=getattr(mc, "settings", None),
        mode=str(getattr(mc, "mode", "BUG_BOUNTY") or "BUG_BOUNTY"),
        _recon_executed=bool(getattr(mc, "_recon_executed", False)),
        attack_planner=getattr(mc, "attack_planner", None),
        network_client=getattr(mc, "network_client", None),
        project_manager=getattr(mc, "project_manager", None),
        workspace_root=(
            str(mc.workspace.base) if getattr(mc, "workspace", None) else None
        ),
        create_attack_tasks_from_recon=getattr(mc, "_create_attack_tasks_from_recon", None),
        add_tasks=getattr(mc, "_add_tasks", None),
        set_recon_executed=lambda: setattr(mc, "_recon_executed", True),
        # SGK-2026-0288: context + llm for ReconPipeline/ParallelTasks adapter
        target_info=(
            dict(getattr(mc.context, "target_info", {}))
            if getattr(mc, "context", None) else None
        ),
        llm_client=getattr(mc, "llm_client", None),
    )
