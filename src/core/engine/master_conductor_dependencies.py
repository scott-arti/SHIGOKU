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
    """
    phase_gate: Any = None  # PhaseGate
    event_bus: Any = None  # EventBus
    task_queue: Any = None  # DynamicTaskQueue
    settings: Any = None
    mode: str = "BUG_BOUNTY"
    _recon_executed: bool = False
    attack_planner: Any = None
    network_client: Any = None
