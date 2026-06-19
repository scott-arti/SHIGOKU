"""
Recon Seed Target Service

master_conductor.py から抽出した seed/path/target helper 群。
MasterConductor instance への参照を持たず、必要な値（context snapshot /
workspace / project_manager / target / settings）をコンストラクタで受け取る。

内部境界:
- _UrlScopeResolver:  URL 正規化・scope 判定などの stateless helper
- _SeedTargetSelector: seed スコアリング・選別のロジック（settings 参照あり）
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from src.config import settings
from src.core.domain.model.task import Task
from src.core.engine.master_conductor_recon_url_scope import _UrlScopeResolver
from src.core.engine.master_conductor_recon_seed_selector import _SeedTargetSelector
from src.core.engine.master_conductor_recon_seed_collectors import _SeedCollectors
from src.core.engine.master_conductor_recon_seed_replay_probe import _SeedReplayProbe

logger = logging.getLogger(__name__)


class ReconSeedTargetService:
    """seed / path / target helper の統合サービス（coordinator facade）。

    MasterConductor instance を保持せず、必要な情報はコンストラクタで受け取る。
    facade 側の wrapper から遅延初期化で利用する前提のため、
    欠損し得る属性には ``getattr(... , None)`` で安全にアクセスする。

    内部委譲:
    - _UrlScopeResolver:  URL 正規化・scope 判定  (master_conductor_recon_url_scope)
    - _SeedTargetSelector: seed スコアリング・選別 (master_conductor_recon_seed_selector)
    - _SeedCollectors:   seed 収集 / refine           (master_conductor_recon_seed_collectors)
    - _SeedReplayProbe:  history replay / scenario probe (master_conductor_recon_seed_replay_probe)
    """

    def __init__(
        self,
        *,
        context: Any = None,
        workspace: Any = None,
        project_manager: Any = None,
        target: str = "",
        settings_: Any = None,
    ) -> None:
        self._context = context
        self._workspace = workspace
        self._project_manager = project_manager
        self._target = target
        self._settings = settings_ if settings_ is not None else settings

        self.scope = _UrlScopeResolver()
        self.seed = _SeedTargetSelector(context, target, self._settings)
        self._collectors = _SeedCollectors(
            context=context,
            workspace=workspace,
            project_manager=project_manager,
            target=target,
            settings_=self._settings,
            scope=self.scope,
            seed=self.seed,
        )
        self._replay_probe = _SeedReplayProbe(
            context=context,
            workspace=workspace,
            project_manager=project_manager,
            target=target,
            settings_=self._settings,
            scope=self.scope,
            collectors=self._collectors,
        )

    # ---- stateless URL/scope helpers (delegate to _UrlScopeResolver) ----

    def normalize_url_candidate(self, value: str) -> str:
        return self.scope.normalize_url_candidate(value)

    def extract_host_candidate(self, value: str) -> str:
        return self.scope.extract_host_candidate(value)

    def is_target_url_in_scope(self, url: str, scope_hosts: list[str]) -> bool:
        return self.scope.is_target_url_in_scope(url, scope_hosts)

    def resolve_task_target(self, task: Task) -> str:
        return self.scope.resolve_task_target(task)

    # ---- context/workspace 依存の helpers (delegate to _SeedCollectors) ----

    def get_context_auth_headers(self) -> dict[str, str]:
        return self._collectors.get_context_auth_headers()

    def get_context_cookie_string(self) -> str:
        return self._collectors.get_context_cookie_string()

    def resolve_recon_file_path(self, file_path: str) -> Optional[Path]:
        return self._collectors.resolve_recon_file_path(file_path)

    def resolve_project_tagged_dir(self) -> Optional[Path]:
        return self._collectors.resolve_project_tagged_dir()

    def resolve_in_scope_hosts(self) -> list[str]:
        return self._collectors.resolve_in_scope_hosts()

    # ---- seed scorers (delegate to _SeedTargetSelector) ----

    def score_csrf_seed_candidate(
        self, url: str, category: str, item: dict[str, Any]
    ) -> tuple[int, list[str]]:
        return self.seed.score_csrf_seed_candidate(url, category, item)

    def score_xss_seed_candidate(
        self, url: str, category: str, item: dict[str, Any]
    ) -> tuple[int, list[str]]:
        return self.seed.score_xss_seed_candidate(url, category, item)

    def is_low_value_backfill_target(self, url: str) -> bool:
        return self.seed.is_low_value_backfill_target(url)

    def should_enable_phase2_on_empty_for_backfill(
        self,
        targets: list[str],
        evidence_by_url: dict[str, dict[str, Any]],
    ) -> bool:
        return self.seed.should_enable_phase2_on_empty_for_backfill(targets, evidence_by_url)

    def apply_phase2_on_empty_policy(self, enabled: bool) -> bool:
        return self.seed.apply_phase2_on_empty_policy(enabled)

    # ---- history replay / scenario probe (delegate to _SeedReplayProbe) ----

    def collect_csrf_seed_targets(
        self,
        recon_results: dict[str, dict],
        budget: int,
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        return self._collectors.collect_csrf_seed_targets(recon_results, budget)

    def collect_xss_seed_targets(
        self,
        recon_results: dict[str, dict],
        budget: int,
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        return self._collectors.collect_xss_seed_targets(recon_results, budget)

    def collect_history_replay_targets(
        self,
        category: str,
        *,
        limit: int,
        file_window: int,
        exclude_urls: Optional[set[str]] = None,
    ) -> list[str]:
        return self._replay_probe.collect_history_replay_targets(
            category,
            limit=limit,
            file_window=file_window,
            exclude_urls=exclude_urls,
        )

    def refine_backfill_seed_targets(
        self,
        targets: list[str],
        evidence_by_url: dict[str, dict[str, Any]],
        budget: int,
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        return self._collectors.refine_backfill_seed_targets(targets, evidence_by_url, budget)

    def collect_scenario_probe_seed_targets(
        self,
        recon_results: dict[str, dict],
        budget: int = 2,
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        return self._replay_probe.collect_scenario_probe_seed_targets(recon_results, budget)

    def select_targets_for_scenario_probe(
        self,
        *,
        scenario_id: str,
        targets: list[str],
        evidence_by_url: dict[str, dict[str, Any]],
        budget: int,
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        return self._replay_probe.select_targets_for_scenario_probe(
            scenario_id=scenario_id,
            targets=targets,
            evidence_by_url=evidence_by_url,
            budget=budget,
        )
