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
    )
