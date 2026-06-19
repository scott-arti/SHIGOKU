# MasterConductor facade - canonical class definitions (SGK-2026-0287 Phase 1)
# Contains ExecutionContext and MasterConductor classes.
# master_conductor.py is the compatibility shim that re-exports from here.

"""
MasterConductor: 動的リプラン司令塔

再帰的計画ロジック:
1. 初期計画生成（Goal → SubGoals → Tasks）
2. タスク実行 → 結果評価
3. 失敗/新情報発見時 → 計画を動的に再構築
4. コンテキストを次エージェントへ引き継ぎ (Context-Aware Handoff 2.0)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any, Callable
import copy
import time
import json
import logging
import threading
import uuid
import hashlib
import asyncio
from collections import deque
from concurrent.futures import TimeoutError as FutureTimeoutError

logger = logging.getLogger(__name__)
from src.core.utils.async_utils import safe_run_async, safe_run_async_forget, SharedLoopManager
# DebugLogger統合（オプショナル）
try:
    from src.core.debug_logger import get_debug_logger
    HAS_DEBUG_LOGGER = True
except ImportError:
    HAS_DEBUG_LOGGER = False

from src.config import settings
from src.core.engine.smart_scheduler import SmartScheduler, ScheduledTask
from src.core.notifications.notifier import get_notifier, Notifier
from src.core.engine.phase_gate import get_phase_gate, Phase
from src.core.domain.model.task import Task, TaskState
from src.commands import print_step, print_result
from src.core.infra.event_bus import get_event_bus, Event, EventType
from src.core.models.task_execution_log import TaskExecutionRecord
from src.core.models.finding import Finding, VulnType
from src.core.infra.knowledge_graph import KnowledgeGraph
from src.core.intel.cartographer import SiteNode  # Added for type hinting
from src.core.learning.findings_repository import get_findings_repository
from src.core.infra.async_writer import AsyncDatabaseWriter
from src.core.factory import AgentFactory
from src.core.engine.attack_planner import AttackPlanner
from src.core.engine.intervention_policy import InterventionPolicy
from src.core.engine.recipe_contracts import validate_task_schema
from src.core.engine.master_conductor_hitl_snapshot import snapshot_task_for_hitl
from src.core.engine.master_conductor_hitl_ticket import build_pending_hitl_ticket
from src.core.engine.master_conductor_hitl_service import HitlService
from src.core.engine.master_conductor_session_service import (
    apply_restored_session_state,
    await_session_save_future,
    build_async_session_payload,
    build_checkpoint_session_state,
    build_start_session_payload,
    deserialize_legacy_session_task_queue,
    load_session_payload_from_path,
    resolve_running_task_resume_policy,
    restore_legacy_resume_session_state,
    serialize_legacy_session_task_queue,
)
from src.core.engine.master_conductor_state import ConductorState  # SGK-2026-0289 Step 1
from src.core.engine.master_conductor_lifecycle_coordinator import (
    shutdown_coordinator,
    finalize_summary_coordinator,
    checkpoint_coordinator,
    resume_session_coordinator,
)  # SGK-2026-0295
from src.core.engine.master_conductor_bootstrap_coordinator import (
    inject_heuristic_swarm_tasks_coordinator,
    run_pre_action_gate_coordinator,
    bootstrap_wiring,
)  # SGK-2026-0294 / 0299
from src.core.engine.master_conductor_finding_coordinator import (
    handle_finding_coordinator,
    observe_and_rethink_coordinator,
)  # SGK-2026-0297
from src.core.engine.master_conductor_intervention_coordinator import (
    apply_intervention_require_approval_coordinator,
    apply_intervention_defer_v1_coordinator,
)  # SGK-2026-0298
from src.core.engine.master_conductor_execution_coordinator import (
    execute_task_coordinator,
    execute_full_flow_coordinator,
    execute_parallel_coordinator,
)  # SGK-2026-0293
from src.core.engine.master_conductor_finding_service import (
    build_react_followup_tasks,
    emit_finding_vuln_payload,
    generate_react_suggestions,
)  # SGK-2026-0291 / 0292
from src.core.engine.master_conductor_enrichment_service import enrich_task_for_enqueue  # SGK-2026-0292
from src.core.engine.master_conductor_execution_service import execute_single_batch  # SGK-2026-0292
from src.core.engine.master_conductor_state_snapshot import (
    restore_completed_tasks_from_session_payload,
    restore_context_from_session_payload,
    restore_pending_hitl_from_session_payload,
    restore_task_queue_from_session_payload,
)
from src.core.engine.master_conductor_recon_seed_target_service import ReconSeedTargetService
from src.core.engine.master_conductor_hitl_precheck_service import (
    PrecheckDecision,
    build_intervention_hitl_info,
    build_scn07_12_notification_lines,
    evaluate_precheck_decision,
    is_manual_defer_target_v1 as _svc_is_manual_defer_target_v1,
    is_scn07_to_12 as _svc_is_scn07_to_12,
    normalize_intervention_gate_mode as _svc_normalize_intervention_gate_mode,
    requires_intervention_approval as _svc_requires_intervention_approval,
)
from src.core.engine.master_conductor_dispatch_service import (
    dispatch_scope_verification_fast_path as _svc_dispatch_scope_verification_fast_path,
    run_recon_pipeline_isolated,
    dispatch_post_exploit_guard as _svc_dispatch_post_exploit_guard,
    dispatch_ctf_filter as _svc_dispatch_ctf_filter,
    dispatch_worker as _svc_dispatch_worker,
    dispatch_swarm as _svc_dispatch_swarm,
    dispatch_cartographer as _svc_dispatch_cartographer,
    dispatch_fingerprinter as _svc_dispatch_fingerprinter,
    dispatch_recipe_check as _svc_dispatch_recipe_check,
    execute_agent_dispatch as _svc_execute_agent_dispatch,
)
from src.core.engine.master_conductor_summary_service import (
    compute_duration_percentile,
    compute_failure_aggregation,
)
from src.core.engine.master_conductor_execution_runner_service import (
    build_task_started_payload,
    build_task_state_event_payload,
    build_execution_record_init,
    compute_batch_size,
)
from src.core.engine.master_conductor_execution_plan_service import (
    build_batch_execution_plan,
    build_timeout_recovery_plan,
    build_batch_result_apply_plan,
    build_failure_replan_decision,
    build_dispatch_timeout_decision,
    is_timeout_related as _svc_is_timeout_related,
)
from src.core.engine.master_conductor_policy_service import (
    assess_missing_link_probe_rollout as _svc_assess_missing_link_probe_rollout,
    build_chain_audit_details,
    build_degradation_audit_details,
    build_degradation_component_contract as _svc_build_degradation_component_contract,
    build_probe_runtime_context_from_chain_finding as _svc_build_probe_runtime_context_from_chain_finding,
    build_race_profile as _svc_build_race_profile,
    build_safe_probe_variations as _svc_build_safe_probe_variations,
    evaluate_active_probe_policy as _svc_evaluate_active_probe_policy,
    evaluate_active_probe_runtime_guard as _svc_evaluate_active_probe_runtime_guard,
    evaluate_phase2_operational_mode as _svc_evaluate_phase2_operational_mode,
    normalize_workflow_template as _svc_normalize_workflow_template,
    rank_missing_link_targets_by_information_gain as _svc_rank_missing_link_targets_by_information_gain,
    resolve_active_probe_policy_default,
    resolve_active_probe_policy_for_program as _svc_resolve_active_probe_policy_for_program,
    resolve_component_degradation as _svc_resolve_component_degradation,
    sanitize_active_probe_policy as _svc_sanitize_active_probe_policy,
)

_SCN_CATALOG_DEFAULTS: tuple[tuple[str, str], ...] = (
    ("scn_01_idor_bola_object_access", "IDOR/BOLA Object Access"),
    ("scn_02_mass_assignment_object_update", "Mass Assignment Object Update"),
    ("scn_03_injection_input_tampering", "Injection Input Tampering"),
    ("scn_04_endpoint_enumeration_bfla", "Endpoint Enumeration / BFLA"),
    ("scn_05_rate_limit_resilience", "Rate Limit Resilience"),
    ("scn_06_data_exposure_diff", "Data Exposure / Response Diff"),
    ("scn_07_token_trust_boundary", "Token Trust Boundary"),
    ("scn_08_oob_external_channel_flow", "Out-of-Band External Channel"),
    ("scn_09_multi_step_state_machine", "Multi-step State Machine"),
    ("scn_10_semantic_business_logic", "Semantic Business Logic"),
    ("scn_11_multi_vector_chain", "Multi-Vector Chain"),
    ("scn_12_advanced_ssrf_internal_topology", "Advanced SSRF Internal Topology"),
)


@dataclass

class ExecutionContext:
    """
    Context-Aware Handoff 2.0: エージェント間で引き継ぐ文脈
    
    単なるデータではなく、成功確率、バイパス手法、
    トリアージャーの傾向を「文脈」として引き継ぐ。
    """
    # 実行履歴 (プライベート化してプロパティ経由でアクセス)
    _total_attempts: int = 0
    _successful_attempts: int = 0
    
    # バイパス手法（過去に成功したもの）
    bypass_methods: list[str] = field(default_factory=list)
    
    # 発見した資産
    discovered_assets: list[str] = field(default_factory=list)
    
    # 現在の攻撃チェーン
    current_attack_chain: list[str] = field(default_factory=list)
    
    # トリアージャー傾向（プログラム別）
    triager_preferences: dict[str, dict] = field(default_factory=dict)
    
    # ターゲット情報
    target_info: dict[str, Any] = field(default_factory=dict)
    
    # [NEW] 実行メトリクス
    metrics: dict[str, Any] = field(default_factory=lambda: {
        "start_time": None,
        "end_time": None,
        "total_duration": 0,
        "estimated_cost": 0.0,
        "phase_durations": {}, # phase_name -> duration
        "token_usage": {"input": 0, "output": 0}
    })
    
    @property
    def success_rate(self) -> float:
        """成功率を取得（ゼロ除算安全）"""
        return self._successful_attempts / self._total_attempts if self._total_attempts > 0 else 0.0
    
    @property
    def total_attempts(self) -> int:
        """総試行回数を取得"""
        return self._total_attempts
    
    @property
    def successful_attempts(self) -> int:
        """成功回数を取得"""
        return self._successful_attempts
    
    def update_success_rate(self, success: bool) -> None:
        """成功率を更新"""
        self._total_attempts += 1
        if success:
            self._successful_attempts += 1
    
    def add_bypass_method(self, method: str) -> None:
        """成功したバイパス手法を追加"""
        if method not in self.bypass_methods:
            self.bypass_methods.append(method)
    
    def to_handoff_dict(self) -> dict:
        """Handoff用の辞書形式に変換"""
        return {
            "success_rate": self.success_rate,
            "bypass_methods": self.bypass_methods,
            "discovered_assets": self.discovered_assets,
            "attack_chain": self.current_attack_chain,
            "target_info": self.target_info,
            "metrics": self.metrics,
        }


from src.core.workspace.shared_workspace import SharedWorkspace
from src.core.engine.task_expander import TaskExpander
from src.core.engine.observation_reason import ObservationReason
from src.core.engine.skip_reason_registry import normalize_skip_reason
from src.core.observability.phase1_contracts import generate_correlation_ids, ensure_observability_fields
from src.core.observability.phase2_classification import classify_failure_pattern
from src.core.observability.flaky_quarantine import (
    FlakyQuarantinePolicy,
    FlakyQuarantineTracker,
    resolve_flaky_policy_from_settings,
)
from src.core.engine.master_conductor_scenario_coverage_service import (
    create_missing_core_scenario_probe_tasks as _service_create_missing_core_scenario_probe_tasks,
    evaluate_intervention_scenario_coverage as _service_evaluate_intervention_scenario_coverage,
    has_scenario_in_queue_or_history as _service_has_scenario_in_queue_or_history,
    normalize_scenario_id_for_coverage as _service_normalize_scenario_id_for_coverage,
    resolve_intervention_scenario_catalog as _service_resolve_intervention_scenario_catalog,
    task_matches_scenario as _service_task_matches_scenario,
)
from src.core.engine.master_conductor_global_guard_task_service import (
    build_csrf_guard_payload,
    build_oob_guard_payload,
    build_xss_guard_payload,
    ensure_global_csrf_guard_decision,
    ensure_global_oob_guard_decision,
    ensure_global_xss_guard_decision,
    resolve_global_csrf_guard_target as _service_resolve_global_csrf_guard_target,
    resolve_global_oob_guard_target as _service_resolve_global_oob_guard_target,
)


class MasterConductor:
    """
    動的リプラン司令塔
    
    サブエージェントの成否に基づき次に召喚するエージェントを
    リアルタイムで変更（再帰的計画）。
    
    ROI（報奨金期待値）に基づくリソース配分も行う。
    """
    
    def __init__(
        self,
        graph = None,  # KnowledgeGraph
        pam = None,    # ProgramAwareMemory
        rag = None,    # KnowledgeIngester
        recipe_loader = None,  # RecipeLoader
        debug_enabled: bool = False,  # デバッグログ有効化
        human_approval_callback: Optional[Callable[[dict], bool]] = None,  # HITL
        llm_client = None,  # LLM連携用クライアント
        session_manager = None,  # SessionManager for persistence
        auto_checkpoint: bool = True,  # 自動チェックポイント有効化
        project_manager = None,  # ProjectManager for data persistence
    ):
        # ---- SGK-2026-0287 Phase 2: use pure construction helpers ----
        from src.core.engine.master_conductor_dependencies import (
            build_core_dependencies,
            build_mode_config,
            build_intelligence_modules,
        )

        self.pam = pam
        self.rag = rag
        self.llm_client = llm_client
        self._auto_checkpoint = auto_checkpoint
        self.settings = settings
        self.project_manager = project_manager

        # Core dependencies (graph, repo, writer, execution_log, recipe_loader)
        core = build_core_dependencies(graph=graph, recipe_loader=recipe_loader)
        for key, val in core.items():
            setattr(self, key, val)

        # Mode / flag / system_prompt
        mode_cfg = build_mode_config(settings)
        for key, val in mode_cfg.items():
            setattr(self, key, val)

        # Intelligence modules
        intel = build_intelligence_modules(llm_client=self.llm_client, settings=settings)
        for key, val in intel.items():
            setattr(self, key, val)

        # ---- SGK-2026-0299: bootstrap wiring → coordinator ----
        bootstrap_wiring(self, debug_enabled, human_approval_callback, session_manager)
        # ---- SGK-2026-0289 Step 1: ConductorState owner ----
        self.state = ConductorState(
            task_queue=self.task_queue,
            completed_tasks=self.completed_tasks,
            pending_hitl=self.pending_hitl,
            _state_lock=self._state_lock,
            context=self.context,
            event_bus=self.event_bus,
            execution_log=self.execution_log,
            shutdown_requested=self._shutdown_requested,
            _recon_executed=self._recon_executed,
            auto_checkpoint=self._auto_checkpoint,
            react_cache=self._react_cache,
            react_observation_executed_total=self._react_observation_executed_total,
            react_observation_executed_by_target=self._react_observation_executed_by_target,
            react_observation_metrics=self._react_observation_metrics,
            react_observation_retry_used=self._react_observation_retry_used,
            react_observation_cb_failures=self._react_observation_cb_failures,
            react_observation_cb_open_until=self._react_observation_cb_open_until,
            react_observation_inflight=self._react_observation_inflight,
            react_observation_pending_queue=self._react_observation_pending_queue,
        )

    @property
    def _seed_service(self) -> ReconSeedTargetService:
        return ReconSeedTargetService(
            context=getattr(self, 'context', None),
            workspace=getattr(self, 'workspace', None),
            project_manager=getattr(self, 'project_manager', None),
            target=getattr(self, 'target', ''),
        )

    async def _handle_vuln_found(self, event: Event) -> None:
        """
        脆弱性発見時に実行されるコールバック。
        発見された脆弱性を起点に、さらなる攻撃（チェイニング）を検討する。
        """
        payload = event.payload
        vuln_type = payload.get("vuln_type")
        target = payload.get("target")
        
        if not vuln_type or not target:
            return

        # 連鎖の無限ループ・暴走防止
        if self._derived_task_count >= 50:
            logger.warning("⚠️ [MasterConductor] Max derived tasks reached. Skipping chaining.")
            return
            
        logger.info("🔗 [MasterConductor] Analyzing chaining for %s (%s)", vuln_type, target)
        
        new_tasks = []
        
        # 連鎖ロジック (Tier 2 Phase 8.1)
        if vuln_type == "idor":
            # IDOR発見 -> 権限昇格の疑いのあるエンドポイントを深掘り
            new_tasks.append({
                "name": f"chain_auth_escalation_{int(time.time()) % 1000}",
                "tags": ["auth", "escalation"],
                "params": {"seed_vuln": "idor", "seed_target": target}
            })
        elif vuln_type == "secret_leak":
            # 秘密情報漏洩 -> 発見された情報を元に機微情報の偵察を強化
            new_tasks.append({
                "name": f"chain_intel_recon_{int(time.time()) % 1000}",
                "tags": ["discovery", "intel"],
                "params": {"seed_vuln": "secret_leak", "seed_target": target}
            })
        elif vuln_type == "auth_bypass":
            # 認証回避 -> 特権管理エンドポイントの探索
            new_tasks.append({
                "name": f"chain_admin_probe_{int(time.time()) % 1000}",
                "tags": ["logic", "priv_esc"],
                "params": {"seed_vuln": "auth_bypass", "seed_target": target}
            })

        # タスクをキューに追加
        tasks_to_add = []
        for t_info in new_tasks:
            from src.core.domain.model.task import Task
            tasks_to_add.append(Task(
                id=t_info["name"],
                name=t_info["name"],
                target=target,
                tags=t_info["tags"],
                params=t_info["params"],
                priority=2 # チェイニングタスクは少し優先度を上げる
            ))
            
        if tasks_to_add:
            self._add_tasks(tasks_to_add, source="vulnerability_chaining")
            for t in tasks_to_add:
                logger.info("➕ [MasterConductor] Triggered chaining task: %s", t.name)

    async def _handle_reauth_success(self, event: Event) -> None:
        """
        再認証成功時に実行されるコールバック。
        新しいトークンをコンテキストに反映し、停止していたタスクの再開を促す。
        """
        payload = event.payload
        new_tokens = payload.get("new_tokens", {})
        target = payload.get("target", "unknown")
        
        logger.info("✅ [MasterConductor] Re-authentication SUCCEEDED for %s. Updating context.", target)
        
        with self._state_lock:
            # トークンを更新
            for k, v in new_tokens.items():
                self.accumulated_context.auth_tokens[k] = v
            
            # ステータスを更新
            self.accumulated_context.auth_tokens["last_auth_status"] = "restored"
            self.accumulated_context.auth_tokens["reauth_completed_at"] = str(time.time())
            
        # TODO: 失敗して待機中のタスクがあれば再キックするロジック

    async def _handle_session_expired(self, event: Event) -> None:
        """
        401 Unauthorized検出時に実行されるコールバック。
        """
        payload = event.payload
        url = payload.get("url", "unknown")
        logger.warning("🚨 [MasterConductor] Session EXPIRED at %s. Dispatching re-auth task.", url)
        
        # 1. コンテキストにエラー情報を記録
        with self._state_lock:
            self.accumulated_context.auth_tokens["last_auth_error"] = "401_unauthorized"
            self.accumulated_context.auth_tokens["reauth_triggered_at"] = str(time.time())
        
        # 2. SwarmDispatcher を取得
        from src.core.engine.swarm_dispatcher import get_swarm_dispatcher
        dispatcher = get_swarm_dispatcher(
            config=self.project_manager.config if self.project_manager else {},
            network_client=self.network_client,
            llm_client=self.llm_client,
            loop=self._get_loop(),
            event_bus=self.event_bus
        )
        
        # 3. 再認証タスクをディスパッチ (AuthManagerAgent -> AutoReauthSpecialist)
        # AuthManagerAgent は 'auth' タグに反応する
        try:
            # 過去のログインリクエスト情報があればコンテキストから取得
            login_req = self.accumulated_context.auth_tokens.get("login_request")
            
            await dispatcher.dispatch(
                tags=["auth", "reauth"],
                target=url,
                task_name="autonomous_reauth",
                params={
                    "auth_tokens": self.accumulated_context.auth_tokens,
                    "login_request": login_req
                }
            )
            logger.info("✅ [MasterConductor] Re-auth task dispatched via Swarm.")
        except Exception as e:
            logger.error("❌ [MasterConductor] Failed to dispatch re-auth task: %s", e)

    def _get_loop(self):
        """共有イベントループを取得（必要に応じて開始）"""
        return SharedLoopManager.get_instance().get_loop()

    def _run_event_loop_forever(self, loop):
        """[DEPRECATED] SharedLoopManager に処理が移行されました"""
        pass

    def _on_flag_found(self, flag: str, source: str):
        """フラグ発見時のコールバック"""
        msg = f"🚩 [FLAG DETECTED] {flag} from {source}"
        logger.warning(msg)
        get_notifier().notify(f"🏆 **FLAG CAPTURED**: `{flag}`\nSource: {source}", bulk=False)

        # CTFモードなら即時停止フラグを立てる等の処理が可能
        if self.mode == "CTF":
            logger.info("Flag found in CTF mode. Recommending mission completion.")

    def _query_knowledge_graph(self, query_type: str, params: dict = None) -> list[dict]:
        """
        Knowledge Graph (Neo4j) からコンテキストを取得
        
        Args:
            query_type: クエリの種類 ("assets", "tech_stack", "pending_params", "vectors")
            params: クエリパラメータ
            
        Returns:
            結果のリスト
        """
        try:
            from src.core.knowledge.driver import get_db
            driver = get_db()
            if not driver:
                return []
            
            project_name = self.project_manager.project_name if self.project_manager else "default"
            
            queries = {
                "assets": """
                    MATCH (a:Asset {project: $project})
                    RETURN a.domain_name as domain, a.ip_address as ip
                    LIMIT 20
                """,
                "tech_stack": """
                    MATCH (e:Endpoint {project: $project})-[:BUILT_WITH]->(t:Technology)
                    RETURN DISTINCT t.name as technology, count(e) as usage_count
                    ORDER BY usage_count DESC
                """,
                "pending_params": """
                    MATCH (e:Endpoint {project: $project})-[:ACCEPTS]->(p:Parameter)
                    WHERE NOT (p)-[:TESTED_BY]->()
                    RETURN e.url as url, p.name as param, p.type as type
                    LIMIT 10
                """,
                 # 攻撃ベクトル提案用: 特定技術に関連する未テストのエンドポイント
                "vectors": """
                    MATCH (e:Endpoint {project: $project})-[:BUILT_WITH]->(t:Technology)
                    WHERE t.name IN $tech_list
                    RETURN e.url as url, t.name as tech
                    LIMIT 5
                """
            }
            
            cypher = queries.get(query_type)
            if not cypher:
                return []
                
            query_params = {"project": project_name}
            if params:
                query_params.update(params)
                
            with driver.session() as session:
                result = session.run(cypher, **query_params)
                return [record.data() for record in result]
                
        except ImportError:
            logger.warning("Knowledge Graph module not found. Skipping graph query.")
            return []
        except Exception as e:
            logger.warning(f"Knowledge Graph query failed: {e}")
            return []

    def shutdown(self):
        """同期および非同期からのシャットダウン・エントリーポイント"""
        import asyncio
        try:
            loop = self._get_loop()
            if loop.is_running():
                future = asyncio.run_coroutine_threadsafe(self._async_shutdown(), loop)
                return future.result(timeout=30)
            else:
                loop.run_until_complete(self._async_shutdown())
        except Exception as e:
            logger.error("Shutdown error: %r", e)
        finally:
            if self._loop_thread and self._loop_thread.is_alive():
                self._get_loop().call_soon_threadsafe(self._get_loop().stop)
                logger.debug("Signaled background loop to stop")

    async def _async_shutdown(self):
        """Thin wrapper → lifecycle_coordinator (SGK-2026-0295)."""
        await shutdown_coordinator(self)
    def close(self):
        """同期クローズ用ラッパー"""
        try:
            self.shutdown()
        except Exception as e:
            logger.error(f"Error during conductor close: {e}")

    def _resolve_async_timeout(
        self,
        coro,
        timeout_override: Optional[int] = None,
        use_batch_timeout: bool = False,
        agent_type: Optional[str] = None,
    ) -> int:
        """_run_async_safe 用のタイムアウト値を決定"""
        if timeout_override is not None:
            return int(timeout_override)
        if use_batch_timeout:
            return int(getattr(settings, "parallel_batch_timeout", 600))

        normalized_agent = (agent_type or "").strip().lower()
        if normalized_agent:
            if "scope_parser" in normalized_agent:
                timeout = int(getattr(settings, "scope_parser_timeout", 120))
                logger.debug("Using scope_parser timeout: %d seconds", timeout)
                return timeout
            if "recon_master" in normalized_agent:
                timeout = int(getattr(settings, "recon_master_timeout", 900))
                logger.debug("Using recon_master timeout: %d seconds", timeout)
                return timeout
            if "injection" in normalized_agent:
                timeout = int(getattr(settings, "injection_manager_timeout", 600))
                logger.debug("Using injection timeout: %d seconds", timeout)
                return timeout

        # 互換用: agent_type が無い呼び出しでは従来の coro 名判定も維持
        try:
            coro_name = getattr(coro, "__qualname__", "")
            if "InjectionManagerAgent" in coro_name and "dispatch" in coro_name:
                timeout = int(getattr(settings, "injection_manager_timeout", 600))
                logger.debug("Using InjectionManager timeout: %d seconds", timeout)
                return timeout
        except Exception:
            pass

        return int(getattr(settings, "single_task_timeout", 300))

    def _run_async_safe(
        self,
        coro,
        timeout_override: Optional[int] = None,
        use_batch_timeout: bool = False,
        agent_type: Optional[str] = None,
    ):
        """共有イベントループで安全に非同期関数（コルーチン）を実行"""
        from src.core.utils.async_utils import safe_run_async

        timeout = self._resolve_async_timeout(
            coro,
            timeout_override=timeout_override,
            use_batch_timeout=use_batch_timeout,
            agent_type=agent_type,
        )
        return safe_run_async(coro, timeout=timeout)

    def _is_timeout_related(self, error: Any) -> bool:
        if error is None:
            return False
        if isinstance(error, (FutureTimeoutError, asyncio.TimeoutError, TimeoutError)):
            return True
        message = str(error).lower()
        return "timeout" in message or "timed out" in message

    def _extract_failure_reason(self, result: Optional[dict], fallback: str = "unknown_error") -> str:
        if isinstance(result, dict):
            for key in ("reason", "error", "message", "status"):
                value = result.get(key)
                if value is not None and str(value).strip():
                    return str(value)
        return fallback

    def _normalize_failure_reason_code(self, phase: str, reason: Any, error: Any = None) -> str:
        phase_text = str(phase or "").strip().lower()
        reason_text = str(reason or "").strip().lower()
        error_text = str(error or "").strip().lower()
        combined = " ".join(part for part in (phase_text, reason_text, error_text) if part)

        if "intervention_gate_pending_hitl" in combined or "pending hitl" in combined:
            return "INTERVENTION_PENDING_HITL"

        if "phase2_timeout" in combined or ("phase2" in combined and "timeout" in combined):
            return "TIMEOUT_PHASE2"
        if any(token in combined for token in ("timeout", "timed out", "timeout_result", "timeout_exception", "timeout_batch")):
            return "TIMEOUT_PER_URL"

        parser_tokens = (
            "parser", "parse error", "parsing failed", "jsondecodeerror", "json parse",
            "yaml", "ast parsing failed", "invalid json",
        )
        if any(token in combined for token in parser_tokens):
            return "PARSER_ERROR"

        auth_tokens = (
            "auth_context_missing",
            "missing auth",
            "missing authorization",
            "missing bearer",
            "missing cookie",
            "missing jwt",
            "auth required but missing",
            "no auth headers",
        )
        if any(token in combined for token in auth_tokens):
            return "AUTH_CONTEXT_MISSING"

        dependency_tokens = (
            "modulenotfounderror",
            "importerror",
            "no module named",
            "dependency",
            "version mismatch",
            "pydantic-core",
            "pkg_resources",
        )
        if any(token in combined for token in dependency_tokens):
            return "DEPENDENCY_ERROR"

        transient_network_tokens = (
            "connection reset",
            "connection aborted",
            "connection refused",
            "name or service not known",
            "temporary failure",
            "network is unreachable",
            "dns",
            "ssl",
            "tls",
            "too many requests",
            "rate limit",
            "429",
            "503",
            "socket",
            "remoteprotocolerror",
            "connecterror",
            "readtimeout",
        )
        if any(token in combined for token in transient_network_tokens):
            return "NETWORK_TRANSIENT"

        return "UNEXPECTED_EXCEPTION"

    def _normalize_finding_entry(self, finding: Any) -> Optional[dict]:
        """Finding オブジェクト/辞書を辞書へ正規化"""
        if isinstance(finding, dict):
            return finding
        if hasattr(finding, "to_dict") and callable(getattr(finding, "to_dict")):
            try:
                converted = finding.to_dict()
                if isinstance(converted, dict):
                    return converted
            except Exception:
                return None
        return None

    def _extract_findings_from_result_payload(self, payload: Any) -> list[dict]:
        """
        result/data の多様な形から findings を抽出する。
        - findings: []
        - finding: {}
        - data.findings / data.finding
        - result.findings / result.finding
        """
        extracted: list[dict] = []
        seen_keys: set[str] = set()
        queue: list[Any] = [payload]
        visited_dict_ids: set[int] = set()

        def _add_finding(finding_obj: Any) -> None:
            finding_dict = self._normalize_finding_entry(finding_obj)
            if not finding_dict:
                return

            key = str(finding_dict.get("id") or "").strip()
            if not key:
                vuln_type = str(finding_dict.get("vuln_type") or finding_dict.get("type") or "").strip()
                title = str(finding_dict.get("title") or "").strip()
                target = str(
                    finding_dict.get("target_url")
                    or finding_dict.get("target")
                    or finding_dict.get("url")
                    or ""
                ).strip()
                key = f"{vuln_type}|{title}|{target}"

            if key in seen_keys:
                return

            seen_keys.add(key)
            extracted.append(finding_dict)

        while queue:
            current = queue.pop(0)
            if not isinstance(current, dict):
                continue

            current_id = id(current)
            if current_id in visited_dict_ids:
                continue
            visited_dict_ids.add(current_id)

            raw_findings = current.get("findings")
            if isinstance(raw_findings, list):
                for entry in raw_findings:
                    _add_finding(entry)

            if "finding" in current:
                _add_finding(current.get("finding"))

            nested_data = current.get("data")
            if isinstance(nested_data, dict):
                queue.append(nested_data)

            nested_result = current.get("result")
            if isinstance(nested_result, dict):
                queue.append(nested_result)

        return extracted

    def _augment_payload_with_findings(self, payload: Any) -> tuple[Any, list[dict]]:
        """payload から findings を抽出し、可能なら payload.findings に反映する。"""
        findings = self._extract_findings_from_result_payload(payload)
        if not findings or not isinstance(payload, dict):
            return payload, findings

        existing = payload.get("findings")
        if isinstance(existing, list):
            merged = self._extract_findings_from_result_payload({"findings": existing + findings})
            payload["findings"] = merged
        else:
            payload["findings"] = findings
        return payload, findings

    def _normalize_vuln_family_name(self, raw: Any) -> str:
        candidate = str(raw or "").strip().lower()
        if not candidate:
            return ""
        candidate = candidate.replace("-", "_").replace(" ", "_")
        aliases = {
            "accesscontrol": "access_control",
            "authz": "access_control",
            "bac": "access_control",
            "idor": "access_control",
            "injection": "injection",
            "sqli": "injection",
            "xss": "xss",
            "csrf": "csrf",
            "auth": "auth",
            "authentication": "auth",
            "business_logic": "business_logic",
            "bizlogic": "business_logic",
            "logic": "business_logic",
            "api": "api",
            "api_security": "api",
            "realtime": "realtime",
        }
        return aliases.get(candidate, candidate)

    def _resolve_required_vuln_families(self) -> list[str]:
        default_required = [
            "access_control",
            "injection",
            "xss",
            "csrf",
            "auth",
            "business_logic",
            "api",
        ]
        raw_required = []
        if isinstance(getattr(self.context, "target_info", {}), dict):
            raw_required = self.context.target_info.get("required_vuln_families", [])
        if not isinstance(raw_required, (list, tuple, set)):
            raw_required = []

        required: list[str] = []
        source = raw_required if raw_required else default_required
        for family in source:
            normalized = self._normalize_vuln_family_name(family)
            if normalized and normalized not in required:
                required.append(normalized)
        return required

    def _map_category_to_vuln_families(self, category: str) -> set[str]:
        mapping: dict[str, set[str]] = {
            "admin": {"access_control", "business_logic", "auth"},
            "auth": {"auth"},
            "id_param": {"injection", "xss", "access_control"},
            "redirect_param": {"injection", "api"},
            "file_param": {"injection", "api"},
            "upload": {"business_logic", "api"},
            "product_search": {"injection", "xss", "api"},
            "basket_order": {"business_logic", "access_control", "api"},
            "feedback_review": {"xss", "injection", "api"},
            "file_exposure_upload": {"access_control", "business_logic", "api"},
            "api_data": {"api", "injection"},
            "client_route_dom": {"xss", "injection"},
            "realtime": {"realtime", "api", "auth"},
            "meta_observability": {"api"},
            "api_candidate": {"api", "injection"},
            "csrf_candidate": {"csrf", "auth"},
            "xss_candidate": {"xss", "injection"},
            "command_injection": {"injection"},
        }
        return set(mapping.get(str(category or "").strip().lower(), set()))

    def _map_finding_type_to_vuln_families(self, finding_type: str) -> set[str]:
        normalized = str(finding_type or "").strip().lower().replace("-", "_").replace(" ", "_")
        if not normalized:
            return set()
        contains_map = [
            ("access", "access_control"),
            ("idor", "access_control"),
            ("authz", "access_control"),
            ("injection", "injection"),
            ("sqli", "injection"),
            ("ssrf", "injection"),
            ("ssti", "injection"),
            ("command", "injection"),
            ("xss", "xss"),
            ("csrf", "csrf"),
            ("auth", "auth"),
            ("session", "auth"),
            ("logic", "business_logic"),
            ("race", "business_logic"),
            ("price", "business_logic"),
            ("api", "api"),
            ("graphql", "api"),
            ("realtime", "realtime"),
            ("socket", "realtime"),
        ]
        families: set[str] = set()
        for needle, family in contains_map:
            if needle in normalized:
                families.add(family)
        return families

    def _evaluate_vuln_family_coverage(self) -> dict[str, Any]:
        required_families = self._resolve_required_vuln_families()
        reached_by_category: set[str] = set()
        reached_by_finding: set[str] = set()
        evidence_categories: dict[str, set[str]] = {}
        evidence_findings: dict[str, set[str]] = {}
        category_counts: dict[str, int] = {}

        for task in self.completed_tasks:
            params = task.params if isinstance(getattr(task, "params", None), dict) else {}
            category = str(params.get("category", "") or "").strip().lower()
            if category:
                category_counts[category] = category_counts.get(category, 0) + 1
                for family in self._map_category_to_vuln_families(category):
                    reached_by_category.add(family)
                    evidence_categories.setdefault(family, set()).add(category)

            for finding in self._extract_findings_from_result_payload(getattr(task, "result", None)):
                finding_type = str(finding.get("type") or finding.get("vuln_type") or "").strip().lower()
                if not finding_type:
                    continue
                for family in self._map_finding_type_to_vuln_families(finding_type):
                    reached_by_finding.add(family)
                    evidence_findings.setdefault(family, set()).add(finding_type)

        reached_families = sorted(reached_by_category | reached_by_finding)
        missing_families = [f for f in required_families if f not in reached_families]
        gate_passed = len(missing_families) == 0
        coverage_rate = (len(required_families) - len(missing_families)) / len(required_families) if required_families else 1.0

        coverage_items: list[dict[str, Any]] = []
        for family in required_families:
            coverage_items.append(
                {
                    "family": family,
                    "reached": family in reached_families,
                    "category_evidence": sorted(evidence_categories.get(family, set())),
                    "finding_evidence": sorted(evidence_findings.get(family, set())),
                }
            )

        return {
            "required_families": required_families,
            "reached_families": reached_families,
            "missing_families": missing_families,
            "gate_passed": gate_passed,
            "coverage_rate": coverage_rate,
            "coverage_items": coverage_items,
            "category_counts": dict(sorted(category_counts.items())),
        }

    def _extract_scn_number(self, scenario_id: str) -> int:
        sid = str(scenario_id or "").strip().lower().replace("-", "_")
        if not sid.startswith("scn_"):
            return 0
        tokens = sid.split("_")
        if len(tokens) < 2:
            return 0
        try:
            return int(tokens[1])
        except Exception:
            return 0

    def _normalize_scenario_id_for_coverage(
        self,
        task: Task,
        params: dict[str, Any],
        scenario_id: str,
        route: str,
    ) -> tuple[str, str, Optional[str]]:
        return _service_normalize_scenario_id_for_coverage(task, params, scenario_id, route)

    def _resolve_intervention_scenario_catalog(self) -> list[dict[str, Any]]:
        return _service_resolve_intervention_scenario_catalog(
            intervention_policy=getattr(self, "intervention_policy", None),
            extract_scn_number=self._extract_scn_number,
        )

    def _evaluate_intervention_scenario_coverage(
        self,
        tasks: Optional[list[Task]] = None,
        infer_if_missing: bool = True,
    ) -> dict[str, Any]:
        return _service_evaluate_intervention_scenario_coverage(
            tasks=tasks,
            infer_if_missing=infer_if_missing,
            completed_tasks=list(getattr(self, "completed_tasks", []) or []),
            get_intervention_decision=self._get_intervention_decision,
            extract_scn_number=self._extract_scn_number,
            intervention_policy=getattr(self, "intervention_policy", None),
        )

    def _collect_scenario_probe_seed_targets(
        self,
        recon_results: dict[str, dict],
        budget: int = 2,
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        return self._seed_service.collect_scenario_probe_seed_targets(recon_results, budget)

    def _select_targets_for_scenario_probe(
        self,
        *,
        scenario_id: str,
        targets: list[str],
        evidence_by_url: dict[str, dict[str, Any]],
        budget: int,
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        return self._seed_service.select_targets_for_scenario_probe(
            scenario_id=scenario_id,
            targets=targets,
            evidence_by_url=evidence_by_url,
            budget=budget,
        )

    def _create_missing_core_scenario_probe_tasks(
        self,
        existing_tasks: list[Task],
        recon_results: dict[str, dict],
    ) -> list[Task]:
        return _service_create_missing_core_scenario_probe_tasks(
            existing_tasks=existing_tasks,
            recon_results=recon_results,
            evaluate_scenario_coverage=self._evaluate_intervention_scenario_coverage,
            extract_scn_number=self._extract_scn_number,
            collect_seed_targets=self._collect_scenario_probe_seed_targets,
            get_context_cookie_string=self._get_context_cookie_string,
            get_context_auth_headers=self._get_context_auth_headers,
            resolve_active_probe_policy=self._resolve_active_probe_policy_for_program,
            select_targets_for_scenario_probe=self._select_targets_for_scenario_probe,
            apply_phase2_on_empty_policy=self._apply_phase2_on_empty_policy,
            evaluate_active_probe_policy=self.evaluate_active_probe_policy,
            target_info=getattr(self.context, "target_info", {}),
            discovered_assets=list(getattr(self.context, "discovered_assets", []) or []),
            scenario_probe_target_budget=int(getattr(settings, "scenario_probe_target_budget", 2) or 2),
        )

    def _resolve_recon_file_path(self, file_path: str) -> Optional[Any]:
        return self._seed_service.resolve_recon_file_path(file_path)

    def _resolve_project_tagged_dir(self) -> Optional[Any]:
        return self._seed_service.resolve_project_tagged_dir()

    def _collect_history_replay_targets(
        self,
        category: str,
        *,
        limit: int,
        file_window: int,
        exclude_urls: Optional[set[str]] = None,
    ) -> list[str]:
        return self._seed_service.collect_history_replay_targets(
            category, limit=limit, file_window=file_window, exclude_urls=exclude_urls,
        )

    def _score_csrf_seed_candidate(self, url: str, category: str, item: dict[str, Any]) -> tuple[int, list[str]]:
        return self._seed_service.score_csrf_seed_candidate(url, category, item)

    def _score_xss_seed_candidate(self, url: str, category: str, item: dict[str, Any]) -> tuple[int, list[str]]:
        return self._seed_service.score_xss_seed_candidate(url, category, item)

    def _collect_xss_seed_targets(
        self,
        recon_results: dict[str, dict],
        budget: int,
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        return self._seed_service.collect_xss_seed_targets(recon_results, budget)

    def _is_low_value_backfill_target(self, url: str) -> bool:
        return self._seed_service.is_low_value_backfill_target(url)

    def _refine_backfill_seed_targets(
        self,
        targets: list[str],
        evidence_by_url: dict[str, dict[str, Any]],
        budget: int,
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        return self._seed_service.refine_backfill_seed_targets(targets, evidence_by_url, budget)

    def _should_enable_phase2_on_empty_for_backfill(
        self,
        targets: list[str],
        evidence_by_url: dict[str, dict[str, Any]],
    ) -> bool:
        return self._seed_service.should_enable_phase2_on_empty_for_backfill(targets, evidence_by_url)

    def _apply_phase2_on_empty_policy(self, enabled: bool) -> bool:
        return self._seed_service.apply_phase2_on_empty_policy(enabled)

    def _collect_csrf_seed_targets(
        self,
        recon_results: dict[str, dict],
        budget: int,
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        return self._seed_service.collect_csrf_seed_targets(recon_results, budget)

    def _record_failure_context(self, task: Task, phase: str, reason: str) -> None:
        phase_text = str(phase or "").strip() or "unknown_phase"
        reason_text = str(reason or "").strip() or "unknown_error"
        reason_code = self._normalize_failure_reason_code(phase_text, reason_text, getattr(task, "error", None))

        task.failure_phase = phase_text
        task.failure_reason = reason_text
        task.failure_reason_code = reason_code

        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        task.params = params
        failure_meta = params.get("_failure")
        if not isinstance(failure_meta, dict):
            failure_meta = {}
        failure_meta["phase"] = phase_text
        failure_meta["reason"] = reason_text
        failure_meta["reason_code"] = reason_code
        failure_meta["recorded_at"] = int(time.time())
        params["_failure"] = failure_meta

    def _dispatch_with_timeout_retry(self, task: Task, timeout_override: Optional[int] = None) -> dict:
        """timeout 起因失敗の軽量リトライ（エージェント別上限あり）"""
        max_timeout_retry = self._resolve_timeout_retry_limit(task)
        timeout_retry_count = int(getattr(task, "timeout_retry_count", 0) or 0)

        while True:
            try:
                result = self._run_async_safe(
                    self._dispatch(task),
                    timeout_override=timeout_override,
                    agent_type=task.agent_type,
                )
            except Exception as exc:
                if self._is_timeout_related(exc) and timeout_retry_count < max_timeout_retry:
                    timeout_retry_count += 1
                    task.timeout_retry_count = timeout_retry_count
                    logger.warning(
                        "Timeout-origin failure on task %s (%s). Retrying once (%d/%d).",
                        task.id,
                        task.agent_type,
                        timeout_retry_count,
                        max_timeout_retry,
                    )
                    continue
                raise

            if (
                isinstance(result, dict)
                and not result.get("success", False)
                and self._is_timeout_related(result.get("error"))
                and timeout_retry_count < max_timeout_retry
            ):
                timeout_retry_count += 1
                task.timeout_retry_count = timeout_retry_count
                logger.warning(
                    "Timeout-origin failure result on task %s (%s). Retrying once (%d/%d).",
                    task.id,
                    task.agent_type,
                    timeout_retry_count,
                    max_timeout_retry,
                )
                continue

            task.timeout_retry_count = timeout_retry_count
            return result

    def _resolve_timeout_retry_limit(self, task: Task) -> int:
        """
        timeout リトライ回数をタスク種別ごとに決定する。

        recon_master は長時間タスクのため、timeout 後に同一処理を重ねると
        ループ化しやすい。既定では retry=0 とし、必要なら設定で上書きする。
        """
        default_retry = int(getattr(settings, "timeout_retry_max", 1) or 1)
        default_retry = max(0, default_retry)

        normalized_agent = str(getattr(task, "agent_type", "") or "").strip().lower()
        if "recon_master" in normalized_agent:
            recon_retry = int(getattr(settings, "recon_master_timeout_retry_max", 0) or 0)
            return max(0, recon_retry)

        return default_retry

    def _run_async_safe_forget(self, coro):
        """完了を待たずに非同期関数を投げっぱなしで実行 (Fire-and-forget)"""
        from src.core.utils.async_utils import safe_run_async_forget
        return safe_run_async_forget(coro)

    def _run_safe(self, func, *args, timeout_override: Optional[int] = None, **kwargs):
        """同期/非同期関数を共有ループで安全に呼び出し、結果を待機"""
        from src.core.utils.async_utils import safe_run
        timeout = timeout_override if timeout_override is not None else getattr(settings, "single_task_timeout", 300)
        return safe_run(func, *args, timeout=timeout, **kwargs)

    def _handle_signal_shutdown(self, signum, frame):
        """シグナル受信時のハンドラ"""
        if self._shutdown_requested:
            logger.warning("Force exiting...")
            import sys
            sys.exit(1)
            
        self._shutdown_requested = True
        logger.warning(f"Shutdown signal received ({signum}). Requesting graceful exit...")
        # メインループ (execute_with_replan) が self._shutdown_requested を検知して抜ける

    def _send_notification(self, finding) -> None:
        """Finding に関する通知を送信"""
        if not self.notify_tool:
            return
            
        message = (
            f"🚨 **{finding.severity.upper()} Vulnerability Found!**\n"
            f"Title: {finding.title}\n"
            f"Target: {finding.target}\n"
            "Action Required."
        )
        try:
            self.notify_tool.run(message=message, provider="all")
            logger.info(f"Notification sent for finding: {finding.title}")
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")

    def initialize_workspace(self, target: str):
        """
        ターゲットスコープに基づいてワークスペースを初期化
        """
        # ターゲットからワークスペースパスを生成
        workspace_name = target.replace("https://", "").replace("http://", "").replace("/", "_")[:50]
        workspace_path = f"./workspace/{workspace_name}"
        self.workspace = SharedWorkspace(workspace_root=workspace_path)
        logger.info(f"Initialized SharedWorkspace for target: {target} at {self.workspace.root}")
        
        # マルチセッション情報のロード
        workspace_settings = self.settings
        multi_session_settings = getattr(workspace_settings, "multi_session", None)
        if multi_session_settings is None:
            try:
                from src.core.config.settings import get_settings

                workspace_settings = get_settings()
                multi_session_settings = getattr(workspace_settings, "multi_session", None)
            except Exception:
                workspace_settings = self.settings
                multi_session_settings = None

        if getattr(multi_session_settings, "enabled", False):
            from src.core.utils.async_utils import safe_run_async
            # YAMLからのロード
            safe_run_async(SessionLoader.load_from_config(self.workspace, workspace_settings))
            
            # Caidoからの抽出
            if getattr(multi_session_settings, "auto_extract_from_caido", False):
                domain = target.replace("https://", "").replace("http://", "").split("/")[0]
                safe_run_async(SessionLoader.load_from_caido(self.workspace, domain=domain))
    

    # ---- SGK-2026-0287 Phase 5: queue helpers ----

    def _should_add_task(self, task: Task, max_derived: int) -> bool:
        """Check dedup and limit guards before adding a task to the queue."""
        if self._derived_task_count >= max_derived:
            return False
        if self.task_queue.get_by_id(task.id) or task.id in self._injected_task_ids:
            logger.debug("Task %s (%s) already in queue or processed, skipping.", task.id, task.name)
            return False
        return True



    # ---- SGK-2026-0289 Step 2: _add_tasks enrichment helper ----

    def _build_react_followup_tasks(self, task: Task, suggestions: dict) -> list:
        """Thin wrapper → master_conductor_finding_service (SGK-2026-0291)."""
        return build_react_followup_tasks(
            task, suggestions,
            max_additions=getattr(settings, "react_observation_max_additions", 5),
        )

    def _enrich_task_before_enqueue(self, task, source, aggressive_targets):
        """Thin wrapper → master_conductor_enrichment_service (SGK-2026-0292)."""
        enrich_task_for_enqueue(
            self, task, source, aggressive_targets,
            strategy_selector=getattr(self, "strategy_selector", None),
            priority_booster=getattr(self, "priority_booster", None),
            context=self.context,
            mode=self.mode,
            normalize_gate=self._normalize_intervention_gate_mode,
            get_decision=self._get_intervention_decision,
            requires_approval=self._requires_intervention_approval,
            calc_boost=self._calculate_dynamic_priority_boost,
            logger=logger,
        )
    def _add_tasks(self, tasks: list[Task], source: str = "unknown") -> int:
        """
        タスクを優先度順でキューに追加 (#7: ヘルパーメソッド)
        
        Args:
            tasks: 追加するタスクのリスト
            source: 追加元（ログ用）: "react", "replan", "recipe", etc.
        
        Returns:
            実際に追加されたタスク数
        """
        if not tasks:
            return 0
        
        # #4: 派生タスク上限チェック
        max_derived = settings.max_derived_tasks_per_session
        added_count = 0
        
        # aggressive ターゲット取得
        aggressive_targets = self.state.context.target_info.get("aggressive_targets", [])

        for task in tasks:
            if self._derived_task_count >= max_derived:
                logger.warning(
                    "Derived task limit (%d) reached. Skipping %d tasks from %s.",
                    max_derived, len(tasks) - added_count, source,
                )
                break
            
            # 7.1 IDベースの重複排除 (#9: 重複回避) — via helper
            if not self._should_add_task(task, max_derived):
                continue

            # P3-1 + N3 + HITL + PriorityBooster + aggressive → via helper
            self._enrich_task_before_enqueue(task, source, aggressive_targets)
            
            self.state.task_queue.add(task)
            self._injected_task_ids.add(task.id) # 履歴に記録
            self._derived_task_count += 1
            added_count += 1
        
        # 優先度順にソート (DynamicTaskQueue handles sorting automatically on add)
        if added_count > 0:
            logger.debug(f"Added {added_count} tasks from {source}, queue size: {len(self.task_queue)}")
        
        return added_count

    def _calculate_dynamic_priority_boost(self, task: Task, max_boost: float = 3.0) -> tuple[float, list[str]]:
        """
        タスク内容に含まれる高価値トリガーに応じて優先度ブースト倍率を計算。
        乗算合成し、max_boost を上限として適用する。
        """
        import re

        trigger_multipliers = {
            "admin": 1.6,
            "api": 1.3,
            "file_upload": 1.8,
            "debug": 1.4,
        }

        signal_parts: list[str] = [
            str(getattr(task, "name", "") or ""),
            str(getattr(task, "agent_type", "") or ""),
            str(getattr(task, "target", "") or ""),
        ]

        params = getattr(task, "params", {}) or {}
        for key in ("target", "url", "path", "endpoint", "route"):
            value = params.get(key)
            if value:
                signal_parts.append(str(value))

        tags = getattr(task, "tags", []) or []
        if isinstance(tags, list):
            signal_parts.extend(str(tag) for tag in tags)

        signal_text = " ".join(signal_parts).lower()

        reasons: list[str] = []
        factor = 1.0

        if "admin" in signal_text:
            factor *= trigger_multipliers["admin"]
            reasons.append("admin")

        if re.search(r"(^|[^a-z0-9])api([^a-z0-9]|$)", signal_text):
            factor *= trigger_multipliers["api"]
            reasons.append("api")

        if any(token in signal_text for token in ("file_upload", "file-upload", "upload")):
            factor *= trigger_multipliers["file_upload"]
            reasons.append("file_upload")

        if "debug" in signal_text:
            factor *= trigger_multipliers["debug"]
            reasons.append("debug")

        if not reasons:
            return 1.0, []

        return min(factor, max_boost), reasons

    def _mark_target_as_aggressive(self, target_url: str) -> None:
        """ターゲットを aggressive としてマーク（後続タスクに継承）"""
        if "aggressive_targets" not in self.context.target_info:
            self.context.target_info["aggressive_targets"] = []
            
        targets = self.context.target_info["aggressive_targets"]
        if target_url not in targets:
            targets.append(target_url)
            self.context.target_info["aggressive_targets"] = targets

    def _boost_related_tasks(self, target_url: str, priority_delta: int = 20) -> None:
        """関連ターゲットのタスク優先度をブースト"""
        with self._state_lock:
            self.task_queue.boost_by_delta(
                condition=lambda t: t.params.get("target", "") and t.params.get("target", "").startswith(target_url),
                delta=priority_delta
            )

    def _process_findings(self, findings: list, target_url: str) -> None:
        """Findings を処理（通知、is_aggressive継承、レポート生成トリガー）"""
        for finding_data in findings:
            # オブジェクトの場合は辞書に変換 (Phase 2.1 互換)
            if hasattr(finding_data, 'to_dict') and callable(finding_data.to_dict):
                finding_data = finding_data.to_dict()
            elif not isinstance(finding_data, dict):
                continue

            severity = finding_data.get("severity", "low").lower()
            is_aggressive = finding_data.get("is_aggressive", False)
            
            # 1. Critical/High 通知
            if severity in ["critical", "high"]:
                self._send_notification_from_dict(finding_data)
                # NOTE: レポート生成タスクの自動追加はここで行うか ReAct で行うか要検討
                # 現状は通知のみ
            
            # 2. is_aggressive 継承
            if is_aggressive:
                self._mark_target_as_aggressive(target_url)
                logger.info("Target marked as aggressive based on finding: %s", target_url)

    def _send_notification_from_dict(self, finding_data: dict) -> None:
        """辞書形式の Finding から通知を送信"""
        if not self.notify_tool:
            return
            
        severity = finding_data.get("severity", "unknown").upper()
        title = finding_data.get("title", "Unknown Vulnerability")
        target = finding_data.get("target", "unknown")
        
        message = (
            f"🚨 **{severity} Vulnerability Found!**\n"
            f"Title: {title}\n"
            f"Target: {target}\n"
            "Action Required."
        )
        try:
            self.notify_tool.run(message=message, provider="all")
            logger.info(f"Notification sent for finding: {title}")
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")
    
    def generate_clarifying_questions(self, target: str, mode: str) -> list[str]:
        """
        モードに応じた確認質問を生成
        
        Args:
            target: ターゲットURL/ドメイン
            mode: 動作モード (bugbounty/ctf/vulntest)
        
        Returns:
            質問のリスト
        """
        questions = []
        
        # 共通質問
        questions.append(f"ターゲット '{target}' で間違いありませんか？(Y/N)")
        
        if mode == "bugbounty":
            questions.extend([
                "Bug Bountyプログラム名は何ですか？",
                "スコープファイルはありますか？パスを入力 (なければEnter):",
                "特に注力したい脆弱性タイプは？(例: Auth, IDOR, XSS)",
                "過去に報告済みの脆弱性タイプはありますか？",
            ])
        elif mode == "ctf":
            questions.extend([
                "問題文を入力してください:",
                "ヒントはありますか？",
                "制限事項は何ですか？(時間、ツール等)",
            ])
        elif mode == "vulntest":
            questions.extend([
                "診断範囲（スコープ）を入力:",
                "認証情報は提供されていますか？",
                "除外すべきエンドポイントは？",
            ])
        
        return questions
    
    def update_context(self, question: str, answer: str):
        """
        Q&Aの回答をコンテキストに反映
        
        Args:
            question: 質問内容
            answer: ユーザーの回答
        """
        # スコープファイル
        if "スコープ" in question and answer and answer.endswith((".yaml", ".yml", ".txt")):
            self.context.target_info["scope_file"] = answer
        
        # プログラム名
        elif "プログラム名" in question:
            self.context.target_info["program_name"] = answer
        
        # 脆弱性タイプ
        elif "脆弱性タイプ" in question:
            vuln_types = [v.strip() for v in answer.split(",") if v.strip()]
            self.context.target_info["focus_vulns"] = vuln_types
        
        # 認証情報
        elif "認証情報" in question:
            self.context.target_info["has_credentials"] = answer.lower() in ["yes", "y", "はい"]
        
        # CTF問題文
        elif "問題文" in question:
            self.context.target_info["problem_statement"] = answer
        
        # ヒント
        elif "ヒント" in question:
            self.context.target_info["hints"] = answer
        
        # 制限事項
        elif "制限" in question:
            self.context.target_info["restrictions"] = answer
        
        # 一般的な質問（その他）
        else:
            if "qa_history" not in self.context.target_info:
                self.context.target_info["qa_history"] = []
            self.context.target_info["qa_history"].append({
                "question": question,
                "answer": answer
            })
    
    
    def set_project_manager(self, pm):
        """ProjectManagerを設定"""
        self.project_manager = pm

    async def async_save_session(self, filepath: str = "session_state.json") -> None:
        """
        セッション状態を非同期で保存
        """
        from pathlib import Path
        import time
        import json

        try:
            coverage_gate = self._evaluate_vuln_family_coverage()
            scenario_coverage = self._evaluate_intervention_scenario_coverage()
            # データの準備
            now = time.time()
            session_data = build_async_session_payload(
                task_queue=list(self.task_queue),
                completed_tasks=self.completed_tasks,
                context=self.context,
                pending_hitl=getattr(self, "pending_hitl", []),
                coverage_gate=coverage_gate,
                scenario_coverage=scenario_coverage,
                timestamp=now,
                default_start_time=now,
            )

            if self.project_manager:
                filename = None
                if filepath != "session_state.json":
                    filename = Path(filepath).name
                
                await self.project_manager.save_session(session_data, filename=filename)
            else:
                # レガシー保存 (Atomic)
                import asyncio
                import aiofiles
                
                path = Path(filepath)
                tmp_path = path.with_suffix(".tmp")
                try:
                    # CPUバウンドなJSONダンプをスレッドに逃がす
                    content = await asyncio.to_thread(json.dumps, session_data, indent=2, ensure_ascii=False)
                    async with aiofiles.open(tmp_path, "w", encoding="utf-8") as f:
                        await f.write(content)
                        await f.flush()
                        
                    # Rename
                    await asyncio.to_thread(tmp_path.replace, path)
                except Exception as e:
                    if tmp_path.exists():
                        await asyncio.to_thread(tmp_path.unlink)
                    raise e
                
        except Exception as e:
            logger.error(f"Failed to save session asynchronously: {e}")

    def save_session(self, filepath: str = "session_state.json") -> None:
        """
        セッション状態を保存 (同期ラッパー - 完了待機)
        """
        try:
            # Fire-and-forgetではなく、Futureを受け取って完了を待つ
            future = self._run_async_safe_forget(self.async_save_session(filepath=filepath))
            await_session_save_future(future, timeout=15)
        except Exception as e:
            logger.error(f"Failed to save session (sync wrapper): {e}")
    
    def load_session(self, filepath: str = "session_state.json") -> bool:
        """
        セッション状態を復元
        
        Args:
            filepath: 読み込み元ファイルパス
            
        Returns:
            復元に成功したか
        """
        try:
            session_data = load_session_payload_from_path(filepath)
            if session_data is None:
                logger.debug(f"No session file found at {filepath}")
                return False
            
            # RUNNING だったタスクの扱いを確認
            task_queue_data = session_data.get("task_queue", [])
            running_count = sum(1 for t in task_queue_data if t.get("state") == "running")
            should_rerun = True
            
            if running_count > 0:
                print(f"\n⚠️  Found {running_count} tasks that were interrupted (RUNNING state).")
                should_rerun = resolve_running_task_resume_policy(running_count, prompt_for_resume=input)
                if should_rerun:
                    logger.info("User chose to RESUME interrupted tasks.")
                else:
                    logger.info("User chose to SKIP interrupted tasks.")

            # タスクキューの復元
            self.task_queue.clear()
            restored_tasks = restore_task_queue_from_session_payload(
                session_data,
                should_rerun_running=should_rerun,
                on_invalid_state=lambda state_str: logger.warning(
                    "Invalid task state '%s', defaulting to PENDING",
                    state_str,
                ),
            )
            self.task_queue.add_batch(restored_tasks, source="load_session")
            
            # 完了タスクの復元
            self.completed_tasks = restore_completed_tasks_from_session_payload(
                session_data,
                normalize_failure_reason_code=self._normalize_failure_reason_code,
            )
            
            # コンテキストの復元
            restore_context_from_session_payload(session_data, self.context)
            self.pending_hitl = restore_pending_hitl_from_session_payload(session_data)
            
            logger.info(f"Session restored from {filepath}: {len(self.task_queue)} tasks in queue")
            return True
        except Exception as e:
            logger.error(f"Failed to load session: {e}")
            return False
    
    
    def process_user_answers(self, questions: list[str], answers: list[str]) -> dict:
        """
        ユーザーの回答を解析してコンテキストを更新 (update_contextのラッパー)
        """
        for q, a in zip(questions, answers):
            self.update_context(q, a)
        return self.context.target_info

    def is_context_sufficient(self) -> tuple[bool, list[str]]:
        """
        プランニングに十分なコンテキストが集まったか判定
        
        Returns:
            (充分か, 不足している情報のリスト)
        """
        # 最低限必要な情報
        required = ["target"]
        missing = [req for req in required if req not in self.context.target_info or not self.context.target_info[req]]
        
        # モード別の追加要件
        mode = self.context.target_info.get("mode", "")
        
        if mode == "bugbounty":
            if "program_name" not in self.context.target_info:
                missing.append("program_name")
        elif mode == "ctf":
            if "problem_statement" not in self.context.target_info:
                missing.append("problem_statement")
        
        return len(missing) == 0, missing

    def has_sufficient_context(self) -> bool:
        """既存互換用: 十分なコンテキストがあるか判定"""
        sufficient, _ = self.is_context_sufficient()
        return sufficient

    def update_tech_stack(self, technologies: list[str]) -> None:
        """
        技術スタック情報を更新し、マッチするRecipeを動的に注入
        
        Args:
            technologies: 検出された技術のリスト
        """
        if "tech_stack" not in self.context.target_info:
            self.context.target_info["tech_stack"] = []
        
        old_stack = set(self.context.target_info["tech_stack"])
        self.context.target_info["tech_stack"].extend(technologies)
        self.context.target_info["tech_stack"] = list(set(self.context.target_info["tech_stack"]))
        new_stack = set(self.context.target_info["tech_stack"])
        
        # 新しい技術が追加された場合のみRecipeをチェック
        new_techs = new_stack - old_stack
        if new_techs:
            # 処理済みとしてマークされていない技術のみを対象にレシピ注入
            unprocessed = [t for t in new_techs if t not in self._processed_techs]
            if unprocessed:
                self._inject_heuristic_swarm_tasks(new_techs=unprocessed)
                for t in unprocessed:
                    self._processed_techs.add(t)
    
    def _inject_heuristic_swarm_tasks(self, new_techs: list[str] = None) -> None:
        """Discovery-driven heuristic Swarm task injection (SGK-2026-0294).

        Creates Swarm tasks (NOT YAML Recipe tasks) based on URL-pattern
        heuristics from discovered URLs in the recon context.  This is the
        **direct swarm dispatch** path (Gate 5), distinct from the recipe-based
        path (Gate 9) in _load_recipe_tasks().

        The previous name `_inject_matching_recipes` was misleading: this method
        has never injected YAML Recipe tasks.  It generates heuristic Swarm
        workflow tasks (auth_ninja, api_spec_reconstruct) from URL patterns.
        """
        inject_heuristic_swarm_tasks_coordinator(self, new_techs)

    def _normalize_intervention_gate_mode(self) -> str:
        return _svc_normalize_intervention_gate_mode(settings)

    def evaluate_active_probe_policy(
        self,
        probe: dict[str, Any],
        policy: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Active Probing policy evaluator.

        Returns:
            {"allowed": bool, "reason": str}
        """
        return _svc_evaluate_active_probe_policy(probe, policy)

    def _rank_missing_link_targets_by_information_gain(
        self,
        candidates: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        return _svc_rank_missing_link_targets_by_information_gain(candidates)

    def _resolve_active_probe_policy_for_program(
        self,
        runtime_policy: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        return _svc_resolve_active_probe_policy_for_program(
            context_target_info=getattr(getattr(self, "context", None), "target_info", None),
            sanitize=self._sanitize_active_probe_policy,
            resolve_default=self._resolve_active_probe_policy,
            runtime_policy=runtime_policy,
        )

    def _sanitize_active_probe_policy(
        self,
        raw_policy: Optional[dict[str, Any]],
        *,
        source: str,
        include_source: bool,
    ) -> dict[str, Any]:
        return _svc_sanitize_active_probe_policy(raw_policy, source=source, include_source=include_source)

    def _normalize_workflow_template(self, raw_template: Optional[dict[str, Any]]) -> dict[str, Any]:
        return _svc_normalize_workflow_template(raw_template)

    def build_probe_runtime_context_from_chain_finding(
        self,
        finding_info: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        return _svc_build_probe_runtime_context_from_chain_finding(
            finding_info,
            sanitize=self._sanitize_active_probe_policy,
            normalize_template=self._normalize_workflow_template,
        )

    def assess_missing_link_probe_rollout(
        self,
        *,
        baseline_metrics: dict[str, Any],
        current_metrics: dict[str, Any],
        thresholds: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        return _svc_assess_missing_link_probe_rollout(
            baseline_metrics=baseline_metrics,
            current_metrics=current_metrics,
            thresholds=thresholds,
        )

    def evaluate_active_probe_runtime_guard(
        self,
        outcomes: list[dict[str, Any]],
        dependency_error: bool = False,
    ) -> dict[str, Any]:
        return _svc_evaluate_active_probe_runtime_guard(outcomes, dependency_error)

    def build_race_profile(self, mode: str = "interval") -> dict[str, Any]:
        return _svc_build_race_profile(mode)

    def build_safe_probe_variations(
        self,
        waf_name: Optional[str],
        *,
        dry_run: bool,
        allowlist: list[str],
        fail_closed: bool,
    ) -> list[dict[str, Any]]:
        return _svc_build_safe_probe_variations(
            waf_name,
            dry_run=dry_run,
            allowlist=allowlist,
            fail_closed=fail_closed,
        )

    def plan_missing_link_probes(
        self,
        existing_tasks: list[Task],
        recon_results: dict[str, dict],
        runtime_policy: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        runtime_policy = runtime_policy or {}
        budget_raw = runtime_policy.get("global_probe_budget")
        if budget_raw is not None and int(budget_raw or 0) <= 0:
            return {
                "tasks": [],
                "state": "defer",
                "reason": "global_probe_budget_exhausted",
            }

        tasks = self._create_missing_core_scenario_probe_tasks(
            existing_tasks=existing_tasks,
            recon_results=recon_results,
        )
        planned_task_count_before_override = len(tasks)
        race_mode = str(runtime_policy.get("race_mode", "interval") or "interval")
        dry_run = bool(runtime_policy.get("dry_run", False))
        allowlist = runtime_policy.get("allowlist", [])
        fail_closed = bool(runtime_policy.get("fail_closed", False))
        waf_name = runtime_policy.get("waf_name")
        race_profile = self.build_race_profile(mode=race_mode)
        safe_variations = self.build_safe_probe_variations(
            waf_name,
            dry_run=dry_run,
            allowlist=allowlist if isinstance(allowlist, list) else [],
            fail_closed=fail_closed,
        )
        for task in tasks:
            params = task.params if isinstance(getattr(task, "params", None), dict) else {}
            task.params = params
            params["race_profile"] = dict(race_profile)
            params["safe_variations"] = [dict(item) for item in safe_variations]
        if budget_raw is None:
            planned_tasks = tasks
        else:
            planned_tasks = tasks[: int(budget_raw or 0)]
        workflow_template = runtime_policy.get("workflow_template", {})
        if not isinstance(workflow_template, dict):
            workflow_template = {}
        qps_cap_target = ""
        per_asset_qps_cap = int(runtime_policy.get("per_asset_qps_cap", 0) or 0)
        if per_asset_qps_cap > 0:
            if recon_results:
                qps_cap_target = str(next(iter(recon_results.keys()), "") or "")
            if planned_tasks:
                first_params = planned_tasks[0].params if isinstance(getattr(planned_tasks[0], "params", None), dict) else {}
                qps_cap_target = qps_cap_target or str(first_params.get("target", "") or "")
            if not qps_cap_target and recon_results:
                qps_cap_target = str(next(iter(recon_results.keys()), "") or "")
        return {
            "tasks": planned_tasks,
            "state": "continue",
            "reason": "planned",
            "planned_task_count_before_override": planned_task_count_before_override,
            "planned_task_count_after_override": len(planned_tasks),
            "qps_cap_target": qps_cap_target,
            "workflow_template": dict(workflow_template),
            "workflow_template_applied": False,
        }

    def trigger_chain_evaluation(
        self,
        trigger: str,
        *,
        chain_key: Optional[str] = None,
        state_version: Optional[int] = None,
    ) -> str:
        normalized = str(trigger or "").strip().lower()
        trigger_map = {
            "finding_added": "draft_refresh",
            "batch_recheck": "confirmed_refresh",
            "pre_action_gate": "actionable_gate",
        }
        action = trigger_map.get(normalized, "draft_refresh")
        if not chain_key:
            return action

        ledger = getattr(self, "_chain_trigger_ledger", None)
        if not isinstance(ledger, dict):
            ledger = {}
            setattr(self, "_chain_trigger_ledger", ledger)
        latest_versions = getattr(self, "_chain_trigger_latest_versions", None)
        if not isinstance(latest_versions, dict):
            latest_versions = {}
            setattr(self, "_chain_trigger_latest_versions", latest_versions)

        version = int(state_version or 0)
        latest_key = f"{normalized}:{chain_key}"
        latest_version = int(latest_versions.get(latest_key, 0) or 0)
        if version and latest_version and version < latest_version:
            return "noop"
        ledger_key = f"{normalized}:{chain_key}:{version}"
        if ledger_key in ledger:
            return "noop"

        ledger[ledger_key] = action
        if version:
            latest_versions[latest_key] = max(latest_version, version)
        return action

    def emit_chain_audit_record(
        self,
        *,
        chain: dict[str, Any],
        audit_context: dict[str, Any],
    ) -> dict[str, Any]:
        from src.core.models.decision_trace import DecisionType
        from src.core.utils.audit_logger import AuditEvent, AuditEventType

        decision_trace = self.decision_tracer.trace(
            decision_type=DecisionType.PRIORITY_BOOST,
            input_context={
                "chain_key": str(chain.get("chain_key", "") or ""),
                "rule_id": str(chain.get("rule_id", "") or ""),
                "state": str(chain.get("state", "") or ""),
            },
            available_options=["actionable", "blocked", "defer"],
            selected_option=str(chain.get("state", "") or "unknown"),
            reasoning="Phase 2 actionable chain audit linkage",
            related_task_id=str(chain.get("chain_key", "") or "") or None,
            related_target=str(audit_context.get("scope_basis", "") or "") or None,
        )
        audit_event_id = f"audit-{uuid.uuid4().hex[:12]}"
        details = build_chain_audit_details(chain, audit_context)
        details["audit_event_id"] = audit_event_id
        details["decision_id"] = decision_trace.decision_id
        self.audit_logger.log(
            AuditEvent(
                event_type=AuditEventType.CONFIG_CHANGED,
                action="attack_chain_audit",
                result=str(chain.get("state", "") or "unknown"),
                details=details,
            )
        )
        return {
            "audit_event_id": audit_event_id,
            "decision_id": decision_trace.decision_id,
            "final_state": str(chain.get("state", "") or "unknown"),
        }

    def evaluate_phase2_operational_mode(
        self,
        *,
        failure_mode: str,
        policy: dict[str, str],
    ) -> dict[str, str]:
        return _svc_evaluate_phase2_operational_mode(failure_mode=failure_mode, policy=policy)

    def _build_degradation_component_contract(self) -> dict[str, dict[str, str]]:
        return _svc_build_degradation_component_contract()

    def emit_degradation_audit_record(
        self,
        *,
        component_status: dict[str, str],
        degradation_result: dict[str, Any],
        audit_context: dict[str, Any],
    ) -> dict[str, Any]:
        from src.core.models.decision_trace import DecisionType
        from src.core.utils.audit_logger import AuditEvent, AuditEventType

        normalized_status = {
            str(component).strip(): str(status).strip().lower()
            for component, status in dict(component_status or {}).items()
            if str(component).strip()
        }
        decision_trace = self.decision_tracer.trace(
            decision_type=DecisionType.FALLBACK,
            input_context={
                "component_status": normalized_status,
                "correlation_id": str(audit_context.get("correlation_id", "") or ""),
            },
            available_options=["continue", "defer", "blocked"],
            selected_option=str(degradation_result.get("state", "") or "unknown"),
            reasoning=str(degradation_result.get("reason", "") or "component_degradation"),
            related_task_id=str(audit_context.get("correlation_id", "") or "") or None,
            related_target="component_degradation",
        )
        audit_event_id = f"audit-{uuid.uuid4().hex[:12]}"
        details = build_degradation_audit_details(component_status, degradation_result, audit_context)
        details["audit_event_id"] = audit_event_id
        details["decision_id"] = decision_trace.decision_id
        self.audit_logger.log(
            AuditEvent(
                event_type=AuditEventType.CONFIG_CHANGED,
                action="component_degradation",
                result=str(degradation_result.get("state", "") or "unknown"),
                details=details,
            )
        )
        return {
            "audit_event_id": audit_event_id,
            "decision_id": decision_trace.decision_id,
            "final_state": str(degradation_result.get("state", "") or "unknown"),
            "submit_blocked": bool(degradation_result.get("submit_blocked", False)),
        }

    def resolve_component_degradation(self, component_status: dict[str, str]) -> dict[str, Any]:
        return _svc_resolve_component_degradation(
            component_status,
            component_contract=self._build_degradation_component_contract(),
        )

    def _run_pre_action_risk_gate(
        self,
        task: Task,
        result: dict,
        exec_record: Any = None,
    ) -> Optional[dict]:
        """Thin wrapper → bootstrap_coordinator (SGK-2026-0294)."""
        return run_pre_action_gate_coordinator(self, task, result, exec_record)

    def run_pre_action_gate_shadow(
        self,
        findings: list[Finding],
        *,
        benchmark_manifest: Optional[dict[str, Any]] = None,
        runtime_context: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        if not bool(getattr(settings, "chain_llm_shadow_mode", True)):
            return {"state": "skipped", "reason": "shadow_mode_disabled"}

        report: dict[str, Any] = {
            "state": "completed",
            "timestamp": time.time(),
            "findings_count": len(findings) if findings else 0,
            "findings": [],
        }
        if benchmark_manifest:
            report["benchmark"] = benchmark_manifest
        if runtime_context:
            report["runtime"] = runtime_context

        temporal_demotion_count = 0
        explainable_feasibility_diffs: list[dict[str, Any]] = []

        for idx, finding in enumerate((findings or [])[:20]):
            f_entry: dict[str, Any] = {
                "index": idx,
                "title": getattr(finding, "title", ""),
                "severity": str(getattr(finding, "severity", "")),
                "vuln_type": str(getattr(finding, "vuln_type", "")),
                "source_agent": str(getattr(finding, "source_agent", "")),
            }

            additional = getattr(finding, "additional_info", None) or {}
            if isinstance(additional, dict):
                schema_sev = str(additional.get("schema_severity", "none"))
                temporal_sev = str(additional.get("temporal_severity", ""))
                f_entry["schema_severity"] = schema_sev
                if temporal_sev and temporal_sev != schema_sev:
                    f_entry["temporal_severity"] = temporal_sev
                    temporal_demotion_count += 1
                    explainable_feasibility_diffs.append({
                        "finding_index": idx,
                        "schema": schema_sev,
                        "temporal": temporal_sev,
                        "reason": additional.get("temporal_reason", "temporal_adjustment"),
                        "feasibility": additional.get("exploit_feasibility", "unknown"),
                    })

            target_url = getattr(finding, "target_url", "")
            if not target_url and isinstance(getattr(finding, "params", None), dict):
                target_url = str(finding.params.get("target", ""))
            f_entry["target_url"] = target_url
            report["findings"].append(f_entry)

        report["temporal_demotion_count"] = temporal_demotion_count
        report["explainable_feasibility_diffs"] = explainable_feasibility_diffs
        report["explainable_feasibility_summary"] = {
            "total": len(explainable_feasibility_diffs),
            "by_reason": {},
        }
        for diff in explainable_feasibility_diffs:
            reason = diff["reason"]
            report["explainable_feasibility_summary"]["by_reason"][reason] = (
                report["explainable_feasibility_summary"]["by_reason"].get(reason, 0) + 1
            )

        event_bus = getattr(self, "state", None)
        event_bus = event_bus.event_bus if event_bus else get_event_bus()
        correlation = getattr(getattr(self, "context", None), "target_info", {}).get("correlation", {})
        payload = ensure_observability_fields(
            {"shadow_report": report},
            correlation=correlation, endpoint="chain_shadow",
            error_type="pre_action_gate_report", timeout_ms=0, retry_count=0,
            test_case_id="chain_shadow",
        )
        event_bus.emit_sync(
            Event(type=EventType.SHADOW_REPORT, payload=payload, source="master_conductor"),
        )

        ledger = getattr(self, "_chain_shadow_reports", None)
        if not isinstance(ledger, list):
            ledger = []
            setattr(self, "_chain_shadow_reports", ledger)
        ledger.append(report)
        return report

    def _resolve_active_probe_policy(self) -> dict[str, Any]:
        return resolve_active_probe_policy_default(settings)

    def _get_intervention_decision(self, task: Task) -> dict[str, Any]:
        decision: dict[str, Any] = {
            "route": "shigoku_only",
            "scenario_id": "default_route",
            "confidence": 0.0,
            "reasons": ["Intervention policy unavailable"],
            "matched_signals": [],
        }
        try:
            policy = getattr(self, "intervention_policy", None)
            if policy is None:
                policy = InterventionPolicy(settings.get_intervention_scenarios())
                self.intervention_policy = policy
            raw = policy.decide(task)
            if isinstance(raw, dict):
                decision.update(raw)
        except Exception as e:
            logger.warning("Intervention decision failed for task %s: %s", getattr(task, "id", "unknown"), e)

        route = str(decision.get("route", "shigoku_only") or "shigoku_only").strip().lower()
        if route not in {"shigoku_only", "shigoku_hitl", "human_preferred"}:
            route = "shigoku_only"
        decision["route"] = route
        decision["scenario_id"] = str(decision.get("scenario_id", "default_route") or "default_route")
        return decision

    def _annotate_task_intervention_decision(self, task: Task, decision: dict[str, Any], gate_mode: str) -> None:
        params = task.params if isinstance(task.params, dict) else {}
        task.params = params
        intervention = params.get("_intervention")
        if not isinstance(intervention, dict):
            intervention = {}
        intervention["decision"] = decision
        intervention["gate_mode"] = gate_mode
        intervention["evaluated_at"] = int(time.time())
        params["_intervention"] = intervention


    def _is_scn07_to_12(self, decision: dict[str, Any]) -> bool:
        return _svc_is_scn07_to_12(decision, self._extract_scn_number)

    def _run_intervention_precheck(
        self,
        task: Task,
        exec_record: Optional[TaskExecutionRecord] = None,
    ) -> Optional[dict]:
        from contextlib import nullcontext
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        intervention_meta = params.get("_intervention", {})
        if isinstance(intervention_meta, dict) and bool(intervention_meta.get("resumed_from_pending_hitl", False)):
            intervention_meta.setdefault(
                "approval",
                {"required": True, "approved": True, "mode": "hitl_resume", "status": "approved"},
            )
            params["_intervention"] = intervention_meta
            task.params = params
            return None

        decision = self._get_intervention_decision(task)
        gate_mode = self._normalize_intervention_gate_mode()
        self._annotate_task_intervention_decision(task, decision, gate_mode)
        self._notify_scn07_12_intervention(task, decision, gate_mode)

        has_callback = bool(getattr(self, "human_approval_callback", None))
        defer_v1 = bool(getattr(settings, "defer_scn07_12_hitl_v1", True))

        precheck = evaluate_precheck_decision(
            task_id=str(getattr(task, "id", "") or ""),
            decision=decision, gate_mode=gate_mode, is_hitl_resume=False,
            extract_scn_number=self._extract_scn_number,
            is_manual_defer_v1_enabled=defer_v1, has_callback=has_callback,
        )

        if precheck.action == "allow":
            return None

        if precheck.action == "defer_manual_v1":
            return self._apply_intervention_defer_v1(task, precheck, gate_mode)

        return self._apply_intervention_require_approval(
            task, decision, gate_mode, precheck, exec_record, has_callback,
        )


    def _get_hitl_service(self) -> HitlService:
        if not hasattr(self, "_hitl_service") or self._hitl_service is None:
            self._hitl_service = HitlService(
                pending_hitl=getattr(self, "pending_hitl", []),
                task_queue=getattr(self, "task_queue", None),
                extract_scn_number=getattr(self, "_extract_scn_number", lambda s: 0),
            )
        return self._hitl_service

    def _requires_intervention_approval(self, decision: dict[str, Any], gate_mode: str) -> bool:
        return HitlService.requires_intervention_approval(decision, gate_mode)

    def _build_intervention_hitl_info(self, task: Task, decision: dict[str, Any], gate_mode: str) -> dict[str, Any]:
        return HitlService.build_intervention_hitl_info(task, decision, gate_mode)

    def _ensure_pending_hitl_store(self) -> list[dict[str, Any]]:
        return self.pending_hitl

    def _snapshot_task_for_hitl(self, task: Task) -> dict[str, Any]:
        return snapshot_task_for_hitl(task)

    def _build_task_from_hitl_snapshot(self, ticket: dict[str, Any]) -> Optional[Task]:
        return HitlService.build_task_from_hitl_snapshot(ticket)

    def _register_pending_hitl_ticket(self, task: Task, decision: dict[str, Any], gate_mode: str) -> str:
        return self._get_hitl_service().register_pending_hitl_ticket(task, decision, gate_mode)

    def list_pending_hitl_tickets(self, statuses: Optional[set[str]] = None) -> list[dict[str, Any]]:
        return self._get_hitl_service().list_pending_hitl_tickets(statuses)

    def set_pending_hitl_status(self, ticket_id: str, status: str) -> bool:
        return self._get_hitl_service().set_pending_hitl_status(ticket_id, status)

    def enqueue_approved_hitl_tasks(self, max_tasks: Optional[int] = None) -> int:
        return self._get_hitl_service().enqueue_approved_hitl_tasks(max_tasks)

    def _mark_pending_hitl_done(self, task: Task, success: bool) -> None:
        self._get_hitl_service().mark_pending_hitl_done(task, success)


    # ---- SGK-2026-0287 Phase 5: intervention precheck helpers ----

    def _apply_intervention_defer_v1(self, task: Task, precheck: Any, gate_mode: str) -> dict:
        """Thin wrapper → intervention_coordinator (SGK-2026-0298)."""
        return apply_intervention_defer_v1_coordinator(self, task, precheck, gate_mode)
    def _apply_intervention_require_approval(
        self, task: Task, decision: dict, gate_mode: str,
        precheck: Any, exec_record: Any, has_callback: bool,
    ) -> Optional[dict]:
        """Thin wrapper → intervention_coordinator (SGK-2026-0298)."""
        return apply_intervention_require_approval_coordinator(
            self, task, decision, gate_mode, precheck, exec_record, has_callback,
        )
    def _is_manual_defer_target_v1(self, decision: dict[str, Any]) -> bool:
        """Ver.1 manual defer policy: keep SCN11 executable for autonomous chain probing."""
        return _svc_is_manual_defer_target_v1(decision, self._extract_scn_number)

    def _notify_scn07_12_intervention(self, task: Task, decision: dict[str, Any], gate_mode: str) -> None:
        """SCN07-12 は Ver.1 方針で通知を必ず送る（手動実行導線）。"""
        scenario_id = str(decision.get("scenario_id", "") or "").strip().lower().replace("-", "_")
        if not scenario_id.startswith("scn_"):
            return

        number = self._extract_scn_number(scenario_id)
        if number < 7 or number > 12:
            return

        task_id = str(getattr(task, "id", "") or "")
        dedupe_key = f"{task_id}:{scenario_id}"
        sent_keys = getattr(self, "_notified_scn07_12_keys", None)
        if not isinstance(sent_keys, set):
            sent_keys = set()
            self._notified_scn07_12_keys = sent_keys
        if dedupe_key in sent_keys:
            return
        sent_keys.add(dedupe_key)

        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        targets = params.get("targets", [])
        if not isinstance(targets, list):
            targets = []
        primary_target = str(params.get("target", "") or getattr(task, "target", "") or "").strip()
        target_summary = ", ".join(str(t) for t in targets[:3]) if targets else (primary_target or "-")

        message_lines = build_scn07_12_notification_lines(
            task_id=task_id,
            task_name=str(getattr(task, "name", "") or "-"),
            decision=decision,
            gate_mode=gate_mode,
            target_summary=target_summary,
        )
        message = "\n".join(message_lines)

        try:
            get_notifier().notify(message=message, bulk=True)
        except Exception as e:
            logger.debug("SCN07-12 notification failed (non-fatal): %s", e)

    def check_hitl_required(self, task: 'Task', result: dict) -> Optional[dict]:
        """
        タスク実行結果に対してHuman-in-the-loop確認が必要か判定
        
        Args:
            task: 実行したタスク
            result: 実行結果
        
        Returns:
            確認が必要な場合は確認情報のdict、不要ならNone
        """
        hitl_info = None
        
        # 1. HIGH/CRITICAL severity の発見
        data = result.get("data", {})
        if isinstance(data, dict):
            finding = data.get("finding") or data.get("result", {})
            if isinstance(finding, dict):
                severity = finding.get("severity", "").upper()
                if severity in ["HIGH", "CRITICAL"]:
                    hitl_info = {
                        "reason": f"{severity} severity 脆弱性を発見",
                        "severity": "critical",
                        "summary": f"タスク '{task.name}' で{severity}レベルの脆弱性が検出されました",
                        "data": finding,
                    }
        
        # 2. 攻撃的アクション
        attack_actions = ["exploit", "inject", "bypass", "bruteforce"]
        if any(action in task.action.lower() for action in attack_actions):
            hitl_info = {
                "reason": "攻撃的アクションの実行",
                "severity": "warning", 
                "summary": f"攻撃的アクション '{task.action}' を実行しました",
                "data": result,
            }
        
        # 3. 新しい資産の発見
        new_assets = result.get("new_assets", [])
        if new_assets and len(new_assets) >= 3:
            hitl_info = {
                "reason": "多数の新規資産を発見",
                "severity": "info",
                "summary": f"{len(new_assets)}個の新規資産を発見。スキャン対象に追加しますか？",
                "data": {"assets": new_assets},
            }
        
        return hitl_info
    
    def request_human_approval(self, hitl_info: dict) -> bool:
        """
        Human-in-the-loop確認を実行
        
        Args:
            hitl_info: 確認情報
        
        Returns:
            承認された場合True、拒否された場合False
        """
        if not self.human_approval_callback:
            logger.debug("No HITL callback, auto-approving")
            return True
        
        try:
            return self.human_approval_callback(hitl_info)
        except Exception as e:
            logger.critical(f"HITL callback crashed, DENYING action for safety: {e}")
            return False  # Fail-Closed: 安全側に倒す

    def _plan_with_llm(self, goal: str, target: Optional[str]) -> Optional[list[Task]]:
        """LLMを使用して動的プランを生成"""
        from src.core.conductor.conductor_prompts import get_planning_prompt

        if not self.llm_client:
            return None
            
        try:
            # プロンプトの準備
            # Knowledge Graph からリッチなコンテキストを取得
            assets = self._query_knowledge_graph("assets")
            tech_cols = self._query_knowledge_graph("tech_stack")
            pending_params = self._query_knowledge_graph("pending_params")
            
            # 🧠 HOOK: 自己省察結果をプロンプトに注入
            insights = self.self_reflection.reflect()
            
            # コンテキストデータの構築
            context_data = {
                "target_info": {"target": target if target else "unknown"},
                "discovered_assets": assets if assets else self.context.discovered_assets,
                "tech_stack": [t['technology'] for t in tech_cols],
                "interesting_vectors": pending_params, # パラメータがあるエンドポイントは優先度高い
                "history_summary": f"Success Rate: {self.context.success_rate:.2f}, Attempts: {self.context.total_attempts}",
            }
            
            prompt = get_planning_prompt(goal, context_data, insights=insights)
            
            # LLM呼び出し
            response = self.llm_client.generate(
                messages=[
                    {"role": "system", "content": "You are a smart security planner. Output JSON only."},
                    {"role": "user", "content": prompt}
                ],
                force_cloud=True,
                response_format={"type": "json_object"},
                temperature=0.3,
            )
            
            content = response.choices[0].message.content
            data = json.loads(content)
            
            tasks = []
            for t in data.get("tasks", []):
                # ID生成 (H-5: UUID使用で衝突防止)
                task_id = t.get("id") or f"task_{uuid.uuid4().hex[:12]}"
                
                
                
                task = Task(
                    id=task_id,
                    name=t.get("name", "Unnamed Task"),
                    agent_type=t.get("agent"),
                    action=t.get("action", "run"),
                    params=t.get("params", {}),
                    priority=int(t.get("priority", 50)),
                    parent_id=t.get("parent_id"),
                )
                
                # targetパラメータの補完
                if target and "target" not in task.params:
                    task.params["target"] = target
                    
                tasks.append(task)
            
            logger.info(f"LLM generated {len(tasks)} tasks")
            return tasks
            
        except Exception as e:
            logger.error(f"LLM planning failed: {e}")
            return None


    # ---- SGK-2026-0290 Step 2: plan helpers ----

    def _plan_pending_fuzz_tasks(self) -> list[Task]:
        """Build fuzzing tasks from pending fuzz URLs in KnowledgeGraph.

        Extracted from plan() pending_fuzz block.
        """
        try:
            from src.core.infra.knowledge_graph import KnowledgeGraph
            kg = KnowledgeGraph()
            pending_urls = kg.get_pending_tasks(category="fuzzing")
            scope_hosts = self._resolve_in_scope_hosts()
            if not scope_hosts:
                logger.warning("Pending fuzzing skipped: unable to resolve in-scope hosts from context.")
                return []

            tasks: list[Task] = []
            out_of_scope_count = 0
            for raw_url in pending_urls:
                url = self._normalize_url_candidate(str(raw_url or "").strip())
                if not url:
                    continue
                if not self._is_target_url_in_scope(url, scope_hosts):
                    out_of_scope_count += 1
                    continue
                task_id = f"fuzz-{hash(url)}"
                tasks.append(Task(
                    id=task_id,
                    name=f"Fuzzing: {url}",
                    agent_type="fuzzing",
                    action="execute",
                    priority=10,
                    target=url,
                    params={"target": url, "tags": ["force_fuzz", "api_endpoint"]},
                ))
            if out_of_scope_count > 0:
                logger.info("[MC] Pending fuzz scope filter removed %d out-of-scope URL(s).", out_of_scope_count)
            if not tasks:
                logger.warning("No pending fuzzing tasks found.")
            return tasks
        except Exception as e:
            logger.error("Failed to load pending tasks: %s", e)
            return []

    def _build_static_plan_tasks(self, target: str | None) -> list[Task]:
        """Build the static fallback plan task list.

        Extracted from plan() static fallback block.
        Includes recon step range normalization, scope verification,
        recon_master, and recipe tasks.
        """
        tasks: list[Task] = []

        if target:
            self.context.target_info["target"] = target

        recon_start_step = 1
        recon_end_step = 8
        try:
            target_info = self.context.target_info if isinstance(self.context.target_info, dict) else {}
            recon_start_step = int(target_info.get("recon_start_step", recon_start_step) or recon_start_step)
            recon_end_step = int(target_info.get("recon_end_step", recon_end_step) or recon_end_step)
        except Exception:
            recon_start_step = 1
            recon_end_step = 8

        recon_start_step = min(8, max(1, recon_start_step))
        recon_end_step = min(8, max(1, recon_end_step))
        if recon_start_step > recon_end_step:
            logger.warning(
                "Invalid recon step range requested (%s-%s). Falling back to 1-8.",
                recon_start_step, recon_end_step,
            )
            recon_start_step = 1
            recon_end_step = 8

        tasks.append(Task(
            id="task_001", name="Scope Verification",
            agent_type="scope_parser", action="verify_scope",
            params={"target": target}, priority=100,
        ))
        tasks.append(Task(
            id="task_002", name="Deep Reconnaissance (Parallel)",
            agent_type="recon_master", action="parallel_recon",
            params={"target": target, "start_step": recon_start_step, "end_step": recon_end_step},
            priority=90, parent_id="task_001",
        ))

        if self.recipe_loader:
            recipe_tasks = self._load_recipe_tasks()
            tasks.extend(recipe_tasks)

        return tasks


    def plan(self, goal: str, target: Optional[str] = None) -> list[Task]:
        """実行可能なタスクのリスト (SGK-2026-0290: thin orchestrator)."""
        # [Phase 3.2] Pending Fuzzing Trigger
        if target == "pending_fuzz":
            logger.info("Triggering Pending Fuzzing Tasks...")
            tasks = self._plan_pending_fuzz_tasks()
            if tasks:
                self._add_tasks(tasks, source="pending_fuzz")
            return tasks

        # Phase 3: LLM動的プランニング
        if settings.use_llm_planning and self.llm_client:
            logger.info("Attempting dynamic planning with LLM...")
            llm_tasks = self._plan_with_llm(goal, target)
            if llm_tasks:
                self.task_queue.clear()
                self.task_queue.add_batch(llm_tasks, source="llm_plan")
                return llm_tasks
            logger.warning("LLM planning returned no tasks, falling back to static plan")

        # Static fallback → via helper
        tasks = self._build_static_plan_tasks(target)
        self.task_queue.clear()
        self.task_queue.add_batch(tasks, source="plan_static")
        return tasks
    
    def _load_recipe_tasks(self) -> list[Task]:
        """RecipeLoaderからRecipeを取得し、OptimizedRecipeRunnerで実行"""
        if not self.recipe_loader:
            return []
        
        # コンテキスト情報を準備 (Step 3: auth surface / token / session metadata を追加)
        ti = self.context.target_info if isinstance(self.context.target_info, dict) else {}
        context_dict = {
            "target": str(ti.get("target", "") or ""),
            "tech_stack": list(ti.get("tech_stack", [])) if isinstance(ti.get("tech_stack"), list) else [],
            "bearer_token": str(ti.get("bearer_token", "") or ""),
            "cookies": str(ti.get("cookies", "") or ""),
            "discovered_urls": list(ti.get("discovered_urls", [])) if isinstance(ti.get("discovered_urls"), list) else [],
            "auth_headers": dict(ti.get("auth_headers", {})) if isinstance(ti.get("auth_headers"), dict) else {},
            "auth_surface_metadata": dict(ti.get("auth_surface_metadata", {})) if isinstance(ti.get("auth_surface_metadata"), dict) else {},
            "form_params": list(ti.get("form_params", [])) if isinstance(ti.get("form_params"), list) else [],
            "query_params": list(ti.get("query_params", [])) if isinstance(ti.get("query_params"), list) else [],
            "js_files": list(ti.get("js_files", [])) if isinstance(ti.get("js_files"), list) else [],
            "recon_findings": list(ti.get("recon_findings", [])) if isinstance(ti.get("recon_findings"), list) else [],
        }
        
        # マッチするRecipeを検索 (Step 3: now returns RecipeCandidate objects)
        candidates = self.recipe_loader.match_recipes_to_context(context_dict)
        
        tasks = []
        if candidates:
            target = str(ti.get("target", "") or "")
            for candidate in candidates:
                recipe = self.recipe_loader.recipes.get(candidate.recipe_name)
                if recipe is None:
                    logger.warning("RecipeCandidate %s has no loaded Recipe — skipping", candidate.recipe_name)
                    continue

                recipe_task = Task(
                    id=f"recipe_exec_{candidate.recipe_name}_{uuid.uuid4().hex[:8]}",
                    name=f"Optimized Recipe: {candidate.recipe_name}",
                    agent_type="swarm",
                    action="run_recipe",
                    params={
                        "recipe_name": candidate.recipe_name,
                        "target": target,
                        # Step 3: Attach selection reasons for decision trace
                        "selection_reasons": candidate.reasons,
                        "selection_score": candidate.score,
                    },
                    priority=100
                )
                task_contract = validate_task_schema(recipe_task)
                if not task_contract.get("ok", False):
                    logger.warning(
                        "Skip invalid recipe task contract for %s: %s",
                        candidate.recipe_name,
                        task_contract.get("errors", []),
                    )
                    continue
                tasks.append(recipe_task)
        
        if tasks:
            logger.info("Injected %d optimized recipe execution tasks", len(tasks))
        
        if tasks:
            logger.info("Injected %d optimized recipe execution tasks", len(tasks))
        
        return tasks

    async def _execute_recipe_task(self, task: Task) -> dict:
        from src.core.engine.optimized_runner import OptimizedRecipeRunner

        recipe_name = str(task.params.get("recipe_name", "") or "").strip()
        target = str(task.params.get("target", "") or "").strip()
        if not recipe_name:
            return {"success": False, "error": "CONTRACT_ERROR:missing_recipe_name"}
        if not target:
            return {"success": False, "error": "CONTRACT_ERROR:missing_target"}
        if not self.recipe_loader:
            return {"success": False, "error": "CONTRACT_ERROR:missing_recipe_loader"}

        recipe = self.recipe_loader.recipes.get(recipe_name)
        if not recipe:
            return {"success": False, "error": f"Recipe not found: {recipe_name}"}

        async def _step_executor(step, step_target):
            step_params = dict(step.params or {})
            step_tags = step_params.get("tags", [])
            if not isinstance(step_tags, list):
                step_tags = []
            step_task = Task(
                id=f"recipe_step_{step.id}",
                name=step.name or f"recipe_step_{step.id}",
                agent_type=str(step_params.get("agent_type", "swarm") or "swarm"),
                action=str(step.action or "run"),
                params={
                    **step_params,
                    "target": step_target,
                    "tags": step_tags,
                },
                priority=int(step_params.get("priority", 100) or 100),
                target=step_target,
            )
            dispatch_result = await self._dispatch(step_task)
            if dispatch_result.get("success"):
                return {
                    "status": "success",
                    "reason": "dispatch_success",
                    "retryable": False,
                    "data": dispatch_result.get("data", {}),
                }
            return {
                "status": "failed",
                "error_code": "TOOL_ERROR",
                "reason": str(dispatch_result.get("error", "dispatch_failed")),
                "retryable": True,
                "data": dispatch_result,
            }

        runner = OptimizedRecipeRunner(step_executor=_step_executor)
        result_bundle = await runner.run_recipe(recipe, target)
        summary = result_bundle.get("summary", {}) if isinstance(result_bundle, dict) else {}
        total_steps = int(summary.get("total_steps", 0) or 0)
        failed_steps = int(summary.get("failed_steps", 0) or 0)

        # Step 6: Process follow-up decisions generated by the runner
        follow_up_decisions = result_bundle.get("follow_up_decisions", []) if isinstance(result_bundle, dict) else []
        if follow_up_decisions:
            self._process_recipe_follow_up_decisions(follow_up_decisions, recipe_name, target)

        return {
            "success": bool(result_bundle.get("success", False)),
            "message": f"Recipe {recipe_name} executed: total={total_steps}, failed={failed_steps}",
            "data": result_bundle,
        }

    def _process_recipe_follow_up_decisions(
        self,
        follow_up_decisions: list,
        recipe_name: str,
        target: str,
    ) -> None:
        """Process follow-up decisions from recipe execution (Step 6: SGK-2026-0260).

        Creates swarm tasks for follow-up exploration when a recipe run
        produces evidence that warrants additional investigation.

        Each follow-up decision is deduplicated by its dedup_key before
        being converted to a swarm task and added to the task queue.
        """
        dedup_keys = set()
        for decision in follow_up_decisions:
            if not isinstance(decision, dict):
                continue
            dedup_key = str(decision.get("dedup_key", "") or "")
            if dedup_key and dedup_key in dedup_keys:
                logger.debug("Skipping duplicate follow-up: %s", dedup_key)
                continue
            if dedup_key:
                dedup_keys.add(dedup_key)

            follow_up_task = Task(
                id=f"recipe_follow_up_{recipe_name}_{uuid.uuid4().hex[:8]}",
                name=f"Recipe Follow-up: {decision.get('reason', 'unknown')} ({recipe_name})",
                agent_type="swarm",
                action=str(decision.get("suggested_action", "scan") or "scan"),
                params={
                    "target": target,
                    "tags": list(decision.get("suggested_tags", []) or []),
                    "follow_up_reason": decision.get("reason", ""),
                    "evidence_summary": decision.get("evidence_summary", ""),
                    "source_recipe": recipe_name,
                    "dedup_key": dedup_key,
                },
                priority=int(decision.get("priority", 50) or 50),
            )
            try:
                self._add_tasks([follow_up_task], source="recipe_follow_up")
            except Exception as e:
                logger.warning("Failed to enqueue recipe follow-up task: %s", e)
    
    def _run_pre_batch_intelligence(self, executed: int) -> None:
        """execute_with_replan の pre-batch intelligence phase（facade helper）。

        SelfReflection / strategy review / KG-based dynamic task inference を担当する。
        cadence と呼び出し順は本 helper で固定する。
        """
        REFLECTION_INTERVAL = getattr(settings, "reflection_interval", 20)
        if executed > 0 and executed % REFLECTION_INTERVAL == 0:
            try:
                insights = self.self_reflection.reflect()
                for insight in insights:
                    if insight.actionable:
                        logger.info("🧠 SelfReflection insight: %s → %s", insight.insight, insight.suggested_action)
                        if hasattr(self, "decision_tracer"):
                            self.decision_tracer.trace(
                                decision="reflection_insight",
                                reason=insight.insight,
                                context={"suggested_action": insight.suggested_action, "confidence": insight.confidence}
                            )
            except Exception as e:
                logger.warning(f"Intelligence: Self-reflection failed (non-critical): {e}")

        if self.optimizer.should_review(executed):
            logger.debug(f"🔑 MainThread attempting to acquire _state_lock for strategy review")
            with self._state_lock:
                logger.debug(f"🔓 MainThread acquired _state_lock for strategy review")
                self.optimizer.review_strategy(self.task_queue, self.graph, executed)

            if executed > 0 and executed % 10 == 0:
                logger.info("[MC] Triggering KG-based dynamic task inference with insights...")
                insights = self.self_reflection.reflect()
                new_tasks = self.attack_planner.infer_tasks(self.graph, self.context, insights=insights)
                for t in new_tasks:
                    if not self.task_queue.get_by_id(t.id):
                        self.task_queue.add(t)

    def _finalize_execution_summary(self, executed: int, *, normal_completion: bool = True) -> dict:
        """execute_with_replan の summary tail（facade helper）。

        final save_session / _generate_summary / rich_logger 表示を担当する。
        normal_completion=False の場合は shutdown 扱いとし、_finished_normally を立てない。
        """
        from src.core.logger import logger as rich_logger

        if normal_completion:
            self._finished_normally = True
            rich_logger.status("success", "ミッションが正常に完了しました。")
        else:
            logger.info("[MC] Execution loop terminated by shutdown request.")

        self.save_session()
        summary = self._generate_summary()

        total_duration = time.time() - self.context.metrics["start_time"]
        self.context.metrics["end_time"] = time.time()
        self.context.metrics["total_duration"] = total_duration

        rich_logger.summary_table(
            "Final Execution Summary",
            ["Metric", "Value"],
            [
                ["Total Tasks", summary["total_tasks"]],
                ["Success", summary["success"]],
                ["Failed", summary["failed"]],
                ["Replanned", summary["replanned"]],
                ["Success Rate", f"{summary['success_rate']:.1%}"],
                ["Discovered Assets", len(summary["discovered_assets"])],
                ["Total Duration", f"{total_duration:.2f}s"],
                ["Estimated Cost", f"${summary['estimated_cost']:.4f}"],
                ["Coverage Gate", "PASS" if summary.get("coverage_gate_passed", False) else "FAIL"],
                ["Coverage", f"{summary.get('coverage_gate_covered', 0)}/{summary.get('coverage_gate_required', 0)}"],
                ["Coverage Missing", ", ".join(summary.get("coverage_gate_missing", [])) or "-"],
                ["Scenario Coverage", f"{summary.get('scenario_covered', 0)}/{summary.get('scenario_required', 0)}"],
                ["Scenario Missing", ", ".join(summary.get("scenario_missing", [])) or "-"],
                ["Pending HITL", summary.get("pending_hitl_count", 0)],
                ["Failed Reasons",
                    (", ".join(f"{code}={count}" for code, count in summary.get("failed_reason_codes", {}).items())
                     if summary.get("failed_reason_codes") else "-"),
                ],
            ]
        )
        return summary

    # ---- SGK-2026-0287 Phase 3: Runtime loop helpers ----

    def _dequeue_batch_tasks(self, suggested_batch: int) -> list:
        """Lock-guarded batch dequeue from task_queue.

        Pure state-reading facade helper. Extracted from execute_with_replan
        to reduce method indentation and clarify lock scope.
        """
        batch_tasks: list = []
        with self._state_lock:
            while len(batch_tasks) < suggested_batch and not self.task_queue.is_empty():
                task = self._select_next_task_from_queue()
                if task is None:
                    break
                batch_tasks.append(task)
        return batch_tasks

    def _apply_batch_failure_state(self, batch_tasks: list, reason: str) -> None:
        """Mark all unfinished batch tasks as FAILED and record failure context.

        Extracted from execute_with_replan recovery path.
        """
        with self._state_lock:
            for task in batch_tasks:
                if task.state not in [TaskState.SUCCESS, TaskState.FAILED, TaskState.SKIPPED]:
                    task.state = TaskState.FAILED
                    task.error = f"batch_failure: {reason}"
                    self._record_failure_context(task, "orchestrator_batch_execute", reason)
            self.completed_tasks.extend(batch_tasks)

    def _apply_batch_result_state(self, batch_tasks: list, apply_plan: Any) -> None:
        """Apply batch orchestration results to task state.

        Extracted from execute_with_replan success path.
        """
        for entry in apply_plan.failed_tasks:
            task = entry["task"]
            task.state = TaskState.FAILED
            task.error = entry["error"]
            self._record_failure_context(task, "orchestrator_batch", str(entry["failure_reason"]))

        with self._state_lock:
            self.completed_tasks.extend(batch_tasks)

    def execute_with_replan(self, max_tasks: int = None) -> dict:
        """
        再帰的実行ループ (並列化対応版)
        SGK-2026-0287 Phase 3: Plan/Apply decomposed.
        """
        from src.core.engine.master_conductor_dependencies import should_checkpoint

        if max_tasks is None:
            max_tasks = getattr(settings, "max_session_tasks", 1000)
        executed = 0
        checkpoint_interval = int(getattr(settings, "checkpoint_interval", 10))

        # 実行開始時間を記録
        if self.context.metrics["start_time"] is None:
            self.context.metrics["start_time"] = time.time()

        # バックグラウンドワーカー起動
        self._run_async_safe(self.writer.start())

        from src.core.logger import logger as rich_logger
        rich_logger.status("info", "SHIGOKU 実行エンジンを起動しています...")

        # SystemResourceManager Start
        try:
            if hasattr(self, "resource_manager") and self.resource_manager:
                self.resource_manager.start()
        except Exception as e:
            logger.warning(f"Failed to start SystemResourceManager: {e}")

        while True:
            # ---- termination decision ----
            if self._shutdown_requested:
                break
            if executed >= max_tasks:
                break

            # 最終カバレッジガード（キューにタスクを追加する可能性あり）
            with self._state_lock:
                self._ensure_global_csrf_guard_task(trigger_source="execute_loop")
                self._ensure_global_xss_guard_task(trigger_source="execute_loop")
                self._ensure_global_oob_guard_task(trigger_source="execute_loop")

            if self.task_queue.empty():
                logger.info("[MC] Task queue is empty. Finishing execution loop.")
                break

            # Pre-batch intelligence
            self._run_pre_batch_intelligence(executed)

            # 1. バッチサイズ計算
            suggested_batch, has_injection_in_queue = compute_batch_size(
                self.task_queue,
                self.resource_manager,
                injection_full_parallel_dispatch=bool(getattr(settings, "injection_full_parallel_dispatch", False)),
                injection_batch_parallelism=int(getattr(settings, "injection_batch_parallelism", 2)),
            )
            if has_injection_in_queue:
                if bool(getattr(settings, "injection_full_parallel_dispatch", False)):
                    logger.info("Injection full parallel dispatch enabled (suggested_batch=%s)", suggested_batch)

            # 2. バッチタスクをデキュー
            batch_tasks = self._dequeue_batch_tasks(suggested_batch)

            if not batch_tasks:
                active_background = [t for t in threading.enumerate() if t.name.startswith("ReconWorker-")]
                if active_background:
                    time.sleep(2)
                    continue
                break

            # 3. バッチ実行 → via helper
            results, should_continue = self._execute_single_batch(batch_tasks, executed)
            if should_continue:
                executed += len(batch_tasks)
                continue

            executed += len(results)
            logger.info("Executed batch of %d tasks (Total: %d)", len(results), executed)

            # 5. チェックポイント判定
            if should_checkpoint(
                executed=executed,
                auto_checkpoint=self._auto_checkpoint,
                checkpoint_interval=checkpoint_interval,
            ):
                self.save_session()

        return self._finalize_execution_summary(executed, normal_completion=not self._shutdown_requested)


    # ---- SGK-2026-0290: batch execution helper ----

    def _execute_single_batch(self, batch_tasks: list, executed: int) -> tuple:
        """Thin wrapper → master_conductor_execution_service (SGK-2026-0292)."""
        return execute_single_batch(
            self, batch_tasks, executed,
            execute_task_fn=self._execute_single_task_full_flow,
            orchestrator=self.orchestrator,
            run_async_safe=self._run_async_safe,
            state_lock=self._state_lock,
            record_failure=self._record_failure_context,
            apply_failure=self._apply_batch_failure_state,
            apply_result=self._apply_batch_result_state,
        )
    def _assess_task_risk(self, task: Task, exec_record: Any) -> Optional[dict]:
        """タスク実行前のリスク評価と介入チェック（facade helper）。

        RiskPredictor block + intervention precheck を担当する。
        ブロック時は早期 return 用 dict を返し、通過時は None を返す。
        """
        # RiskPredictor block
        try:
            from src.core.intelligence import ActionRiskProfile
            action_type = self._map_agent_to_action_type(task.agent_type, task.action)
            profile = ActionRiskProfile(
                action_type=action_type,
                target_url=task.params.get("target", ""),
                has_waf="waf" in str(self.context.target_info).lower(),
                consecutive_failures=getattr(task, "replan_depth", 0),
                payload=str(task.params.get("payload", "")) if task.params.get("payload") else None
            )
            assessment = self.risk_predictor.assess(profile)

            if not assessment.should_proceed:
                logger.warning("🚫 RiskPredictor blocked task %s (risk level: %s)", task.id, assessment.risk_level)
                with self._state_lock:
                    task.state = TaskState.FAILED
                    task.error = f"Blocked by RiskPredictor: {assessment.risk_level}"
                    self._record_failure_context(task, "precheck", "risk_predictor_block")
                    exec_record.mark_completed(success=False, error=task.error)
                    self.execution_log.add_record(exec_record)
                self._mark_pending_hitl_done(task, success=False)
                self._record_task_prioritizer_outcome(task, {"success": False, "error": task.error})
                return {"success": False, "error": "Blocked by RiskPredictor", "risk": assessment.to_dict()}

            if assessment.recommended_delay > 0:
                delay_disabled = bool(getattr(settings, "risk_predictor_delay_disable", False))
                high_only = bool(getattr(settings, "risk_predictor_delay_high_only", False))
                min_score = float(getattr(settings, "risk_predictor_delay_min_score", 0.7) or 0.7)
                apply_delay = not delay_disabled
                risk_score = float(getattr(assessment, "risk_score", 0.0) or 0.0)
                risk_level = str(getattr(assessment, "risk_level", "") or "").strip().lower()
                is_high_risk_level = risk_level in {"high", "critical"}
                if apply_delay and high_only and not (is_high_risk_level or risk_score >= min_score):
                    apply_delay = False

                if apply_delay:
                    delay = min(assessment.recommended_delay, 10.0)
                    logger.info("⏳ RiskPredictor: applying recommended delay %.2fs for %s", delay, task.name)
                    time.sleep(delay)
                else:
                    if delay_disabled:
                        logger.info("RiskPredictor: delay disabled by settings for %s", task.name)
                    else:
                        logger.info(
                            "RiskPredictor: skipped delay for %s (risk_level=%s, risk_score=%.2f, min_score=%.2f)",
                            task.name, risk_level or "unknown", risk_score, min_score,
                        )
        except Exception as e:
            logger.warning(f"Intelligence: Risk assessment failed (non-critical): {e}")

        # Intervention precheck
        intervention_block = self._run_intervention_precheck(task, exec_record=exec_record)
        if intervention_block is not None:
            self._record_task_prioritizer_outcome(task, intervention_block)
            return intervention_block
        return None

    def _apply_post_dispatch_intelligence(
        self, task: Task, result: dict, before_snap_id: Optional[str]
    ) -> None:
        """Dispatch 後のインテリジェンスフック（facade helper）。

        DecisionEnhancer + DiffAnalyzer を担当する。
        """
        # DecisionEnhancer
        try:
            from src.core.intelligence import DecisionContext, Decision
            waf_detected = "waf" in str(result.get("message", "")).lower() or result.get("data", {}).get("waf_blocked", False)
            rate_limited = "rate limit" in str(result.get("message", "")).lower() or result.get("status") == 429

            d_ctx = DecisionContext(
                action_type=task.agent_type or "unknown",
                target_url=task.params.get("target", ""),
                previous_attempts=getattr(task, "replan_depth", 0),
                waf_detected=waf_detected,
                rate_limit_active=rate_limited
            )
            enhanced_decision = self.decision_enhancer.decide(d_ctx)

            if enhanced_decision.decision in [Decision.RETRY, Decision.MODIFY]:
                logger.info("💡 DecisionEnhancer: %s requested. Reason: %s",
                            enhanced_decision.decision.value, enhanced_decision.reasoning)
                if getattr(task, "replan_depth", 0) < 3:
                    new_task = task.clone()
                    new_task.id = f"{task.id}_retry_{int(time.time())}"
                    new_task.replan_depth = getattr(task, "replan_depth", 0) + 1
                    if enhanced_decision.modifications:
                        new_task.params["_modifications"] = enhanced_decision.modifications
                        logger.info("🔧 Applying modifications: %s", enhanced_decision.modifications)
                    self.task_queue.add(new_task)
        except Exception as e:
            logger.warning("DecisionEnhancer: Failed to enhance decision: %s", e)

        # DiffAnalyzer
        if before_snap_id:
            try:
                target = task.params.get("target", "default")
                current_data = {
                    "urls": [n.url for n in self.graph.get_nodes_by_type("Page") if hasattr(n, "url")],
                    "endpoints": [n.url for n in self.graph.get_nodes_by_type("Endpoint") if hasattr(n, "url")]
                }
                _, after_snap_id = self.diff_analyzer.take_snapshot(target, current_data, label=f"after_{task.id}")
                diffs = self.diff_analyzer.compare(
                    self.diff_analyzer.snapshots[after_snap_id],
                    self.diff_analyzer.snapshots[before_snap_id]
                )
                has_changes = any(d.has_changes() for d in diffs.values())
                if has_changes:
                    logger.info("🔍 State changes detected after %s!", task.id)
                    for cat, d in diffs.items():
                        if d.added:
                            logger.info("  [+] Added in %s: %s", cat, d.added[:5])
            except Exception as e:
                logger.warning("DiffAnalyzer: Failed to perform post-execution diff: %s", e)

    def _handle_task_success(self, task: Task, result: dict, exec_record: Any = None) -> None:
        """Handle successful task completion (SGK-2026-0293: kept in facade)."""
        task.state = TaskState.SUCCESS
        task.failure_phase = None
        task.failure_reason = None
        task.failure_reason_code = None
        if isinstance(task.params, dict):
            task.params.pop("_failure", None)
        self.context.update_success_rate(True)

        findings = result.get("findings", [])
        if not findings:
            findings = self._extract_findings_from_result_payload(result.get("data", {}))
        if findings:
            self._process_findings(findings, task.params.get("target", ""))

        if result.get("new_assets"):
            self._expand_plan_for_assets(result["new_assets"])
        if result.get("bypass_method"):
            self.context.add_bypass_method(result["bypass_method"])

        if isinstance(result, dict):
            for f in findings:
                if hasattr(f, 'title'):
                    self.handle_finding(f)

        self._process_handoff(task, result)

        if hasattr(self, "priority_booster") and self.priority_booster:
            try:
                self.priority_booster.boost_on_discovery(task, result)
                self.task_queue.boost_priority(task.id, 10)
            except Exception:
                pass

        if exec_record is not None:
            exec_record.mark_completed(
                success=True, summary=result.get("message", ""),
                output=result.get("output", ""), metadata=result.get("data", {}),
            )
            for f in findings:
                exec_record.add_vulnerability(f)
            if getattr(self, "execution_log", None) is not None:
                self.execution_log.add_record(exec_record)
    def _handle_task_failure(self, task: Task, result: dict, exec_record: Any) -> None:
        """タスク失敗時の状態更新と分析・リプラン（facade helper）。"""
        task.state = TaskState.FAILED
        task.error = result.get("error", task.error)
        failure_phase = str(result.get("phase", "dispatch_result")) if isinstance(result, dict) else "dispatch_result"
        failure_reason = self._extract_failure_reason(result)
        if self._is_timeout_related(failure_reason):
            failure_reason = "timeout_result"
        self._record_failure_context(task, failure_phase, failure_reason)
        self._emit_task_state_event(
            event_type=EventType.TASK_FAILED,
            task=task,
            result=result,
        )
        flaky_verdict = self._update_flaky_quarantine(task, success=False)

        # ErrorAnalyzer & SelfReflection
        root_cause = None
        try:
            from src.core.intelligence import ErrorRecord, ExecutionOutcome, ExecutionRecord
            error_record = ErrorRecord(
                error_message=result.get("error", "Unknown error"),
                status_code=result.get("data", {}).get("status_code"),
                target_url=task.params.get("target", ""),
                action_type=task.agent_type,
            )
            root_cause = self.error_analyzer.analyze(error_record)

            outcome = ExecutionOutcome.FAILURE
            if root_cause and root_cause.category.value in ["waf_blocked", "ip_blocked", "rate_limited"]:
                outcome = ExecutionOutcome.BLOCKED

            self.self_reflection.record(ExecutionRecord(
                task_id=task.id,
                action_type=task.agent_type or "unknown",
                target=task.params.get("target", ""),
                outcome=outcome,
                duration_seconds=exec_record.duration_seconds() or 0.0,
                error_message=result.get("error"),
                response_code=result.get("data", {}).get("status_code"),
            ))
        except Exception as e:
            logger.warning(f"Intelligence: Error analysis failed (non-critical): {e}")

        # Replan decision (service plan)
        replan_decision = build_failure_replan_decision(
            task, root_cause, flaky_verdict,
            max_replan_depth=self.max_replan_depth,
        )
        if replan_decision.should_quarantine:
            task.params["_quarantine"] = {
                "status": "quarantine",
                "window_size": flaky_verdict.get("window_size"),
                "failures": flaky_verdict.get("failures"),
                "failure_rate": flaky_verdict.get("failure_rate"),
                "reason": replan_decision.quarantine_reason or "flaky_auto_quarantine",
            }
        if replan_decision.should_replan:
            if replan_decision.wait_seconds > 0:
                logger.info(f"Intelligence: ErrorAnalyzer suggests waiting {replan_decision.wait_seconds}s before replan")
                time.sleep(replan_decision.wait_seconds)
            failure_replan = self.replan(task, result.get("error", "Unknown error"), root_cause=root_cause)
            for alt in failure_replan:
                alt.replan_depth = task.replan_depth + 1
                alt.parent_id = task.id
            self._add_tasks(failure_replan, source="failure_replan")
        elif not replan_decision.retry_recommended:
            logger.info(f"Intelligence: ErrorAnalyzer suggests NOT retrying task {task.id} (Category: {replan_decision.root_cause_category or 'unknown'})")


    # ---- SGK-2026-0287 Step 10: task execution helpers ----

    def _capture_task_before_snapshot(self, task: Task) -> Optional[str]:
        """Capture a 'before' snapshot via DiffAnalyzer for stateful mutations.

        Returns snapshot_id or None.
        """
        if task.action not in ("fuzz", "post", "put", "delete") and            task.params.get("method") not in ("POST", "PUT", "DELETE"):
            return None

        try:
            target = task.params.get("target", "default")
            current_data = {
                "urls": [n.url for n in self.graph.get_nodes_by_type("Page") if hasattr(n, "url")],
                "endpoints": [n.url for n in self.graph.get_nodes_by_type("Endpoint") if hasattr(n, "url")],
            }
            _, snap_id = self.diff_analyzer.take_snapshot(target, current_data, label=f"before_{task.id}")
            logger.info("Captured 'before' snapshot: %s", snap_id)
            return snap_id
        except Exception as e:
            logger.warning("DiffAnalyzer: Failed to take 'before' snapshot: %s", e)
            return None


    def _execute_single_task_full_flow(self, task: Task) -> dict:
        """Thin wrapper → execution_coordinator (SGK-2026-0293)."""
        return execute_full_flow_coordinator(self, task)











    
    def _emit_task_state_event(self, *, event_type: EventType, task: Task, result: dict | None = None) -> None:
        result = result or {}
        try:
            event_bus = get_event_bus()
            correlation = self.context.target_info.get("correlation", {})
            payload = build_task_state_event_payload(
                task,
                result,
                correlation=correlation,
            )
            event_bus.emit_sync(
                Event(
                    type=event_type,
                    payload=payload,
                    source="master_conductor",
                )
            )
        except Exception as e:
            logger.debug("Failed to emit task state event: %s", e)

    def _task_flaky_signature(self, task: Task) -> str:
        target = ""
        if isinstance(getattr(task, "params", None), dict):
            target = str(task.params.get("target", "") or "")
        return "|".join(
            [
                str(getattr(task, "agent_type", "") or ""),
                str(getattr(task, "action", "") or ""),
                target,
            ]
        )

    def _update_flaky_quarantine(self, task: Task, *, success: bool) -> dict[str, Any]:
        signature = self._task_flaky_signature(task)
        tracker = self._flaky_trackers.get(signature)
        if tracker is None:
            resolved_policy = resolve_flaky_policy_from_settings(settings)
            tracker = FlakyQuarantineTracker(
                policy=FlakyQuarantinePolicy(
                    window_size=resolved_policy.window_size,
                    min_failures=resolved_policy.min_failures,
                    release_success_streak=resolved_policy.release_success_streak,
                )
            )
            self._flaky_trackers[signature] = tracker
        tracker.record(success=success)
        verdict = tracker.evaluate()
        release_streak = int(getattr(tracker.policy, "release_success_streak", 3) or 3)
        if success:
            self._flaky_success_streaks[signature] = self._flaky_success_streaks.get(signature, 0) + 1
        else:
            self._flaky_success_streaks[signature] = 0
        if verdict.get("status") == "quarantine":
            self._quarantined_signatures[signature] = verdict
            if self._flaky_success_streaks.get(signature, 0) >= release_streak:
                self._quarantined_signatures.pop(signature, None)
                verdict = {
                    **verdict,
                    "status": "ok",
                    "released": True,
                    "release_success_streak": self._flaky_success_streaks.get(signature, 0),
                }
                try:
                    event_bus = get_event_bus()
                    correlation = self.context.target_info.get("correlation", {})
                    payload = ensure_observability_fields(
                        {
                            "event": "flaky_quarantine_released",
                            "who": "system_auto",
                            "when_epoch": int(time.time()),
                            "why": "success_streak_reached",
                            "basis": {
                                "signature": signature,
                                "release_success_streak": self._flaky_success_streaks.get(signature, 0),
                                "window_size": verdict.get("window_size"),
                                "min_failures": verdict.get("min_failures"),
                                "observed_total": verdict.get("observed_total"),
                                "observed_failures": verdict.get("observed_failures"),
                                "failure_rate": verdict.get("failure_rate"),
                            },
                        },
                        correlation=correlation,
                        endpoint=str(getattr(task, "params", {}).get("target", "") or ""),
                        error_type="flaky_quarantine_released",
                        timeout_ms=int(getattr(task, "params", {}).get("timeout", 0) or 0),
                        retry_count=int(getattr(task, "timeout_retry_count", 0) or 0),
                        test_case_id=str(getattr(task, "id", "") or "flaky_release"),
                    )
                    event_bus.emit_sync(
                        Event(
                            type=EventType.FLAKY_QUARANTINE_RELEASED,
                            payload=payload,
                            source="master_conductor",
                        )
                    )
                except Exception as e:
                    logger.debug("Failed to emit flaky quarantine release event: %s", e)
        else:
            self._quarantined_signatures.pop(signature, None)
        return verdict

    def _is_task_quarantined(self, task: Task) -> bool:
        signature = self._task_flaky_signature(task)
        return signature in self._quarantined_signatures


    # ---- SGK-2026-0289 Step 3: handle_finding helpers ----

    def _emit_finding_vuln_event(self, finding: Any, target_url: str) -> None:
        """Thin wrapper → master_conductor_finding_service (SGK-2026-0291)."""
        emit_finding_vuln_payload(
            finding, target_url,
            context_target_info=self.context.target_info,
            event_bus=self.state.event_bus if getattr(self, "state", None) else get_event_bus(),
            notifier=get_notifier(),
        )


    def handle_finding(self, finding: Finding) -> None:
        """Thin wrapper → finding_coordinator (SGK-2026-0297)."""
        handle_finding_coordinator(self, finding)
    def save_finding(self, finding: Finding) -> None:
        """Findingを非同期バッチで保存"""
        self._run_async_safe(self.writer.enqueue_finding(finding))
        
    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """キャッシュまたはDBからFindingを取得"""
        # 1. キャッシュ (L1)
        finding = self.writer.get_cached_finding(finding_id)
        if finding:
            return finding
            
        # 2. DB (FindingsRepo)
        return self.repo.get(finding_id)

    def save_sitemap(self, domain: str, node: SiteNode) -> None:
        """サイトマップノードを非同期バッチで保存"""
        self._run_async_safe(self.writer.enqueue_sitemap(domain, node))

    def _trigger_post_exploit(self, finding: Finding) -> None:
        """
        脆弱性の種類に応じて、Post-Exploitタスクを生成・割り込みさせる
        """
        # 交戦規定チェック (BBモードでの暴走防止)
        from src.core.security.ethics_guard import get_ethics_guard
        guard = get_ethics_guard()
        if guard.scope:
            allow_pe = guard.scope.allow_post_exploit
        else:
            allow_pe = getattr(settings, "allow_post_exploit", False)
            
        if self.mode.lower() == "bugbounty" and not allow_pe:
            logger.info("Post-Exploit skipped due to RoE config (mode=%s).", self.mode)
            return

        new_tasks = []
        
        # RCE系が見つかった場合 -> 内部偵察 / 機密探索
        if finding.vuln_type in [VulnType.OS_COMMAND_INJECTION, VulnType.SSTI, VulnType.DESERIALIZATION]:
            # exploit_payload が additional_info 等に含まれていることを想定
            access = finding.additional_info.get("exploit_payload") or finding.evidence.request_url
            
            new_tasks.append(Task(
                id=f"post_recon_{uuid.uuid4().hex[:8]}",
                name=f"Internal Reconnaissance (vial {finding.vuln_type.value})",
                agent_type="post_exploit",
                action="internal_recon",
                params={"access_method": access},
                priority=999
            ))
            new_tasks.append(Task(
                id=f"secret_loot_{uuid.uuid4().hex[:8]}",
                name="Secret Looting",
                agent_type="post_exploit",
                action="secret_looting",
                params={"access_method": access},
                priority=990
            ))
        
        # SSRFが見つかった場合 -> 内部スキャン
        elif finding.vuln_type == VulnType.SSRF:
            new_tasks.append(Task(
                id=f"pivot_scan_{uuid.uuid4().hex[:8]}",
                name="Internal Pivot Scan",
                agent_type="post_exploit",
                action="pivot_scan",
                params={"target": finding.target_url},
                priority=900
            ))

        if new_tasks:
            self._add_tasks(new_tasks, source="post_exploit_trigger")
            logger.warning("[!] Triggered Post-Exploit Sequence for finding: %s", finding.title)

    def _infer_and_emit_attack_chains(self, finding: Finding) -> None:
        """
        観測された Finding 群から攻撃チェーンを推論し、新規チェーンのみ Finding として発行する。
        """
        chain_builder = getattr(self, "chain_builder", None)
        if chain_builder is None:
            return

        with self._state_lock:
            self._chain_observation_buffer.append(finding)
            # メモリ肥大化抑制
            if len(self._chain_observation_buffer) > 60:
                self._chain_observation_buffer = self._chain_observation_buffer[-60:]
            snapshot = list(self._chain_observation_buffer)
            current_version = int(getattr(self, "_chain_state_version", 0) or 0) + 1
            self._chain_state_version = current_version

        chains = chain_builder.analyze(snapshot)
        if not chains:
            return

        try:
            self.run_pre_action_gate_shadow(
                snapshot,
                benchmark_manifest=None,
                runtime_context={
                    "trigger": "pre_action_gate",
                    "state_version": current_version,
                },
            )
        except Exception as e:
            logger.debug("Attack chain shadow proposal skipped due to runtime error: %s", e)

        for chain in chains:
            chain_key = getattr(chain, "chain_key", "")
            if not chain_key:
                continue

            evaluation_action = self.trigger_chain_evaluation(
                "finding_added",
                chain_key=chain_key,
                state_version=current_version,
            )
            if evaluation_action == "noop":
                continue

            with self._state_lock:
                if chain_key in self._emitted_attack_chain_keys:
                    continue
                self._emitted_attack_chain_keys.add(chain_key)

            chain_finding = chain.to_finding()
            logger.warning(
                "🔗 Attack chain inferred: %s (severity=%s, confidence=%.2f, key=%s)",
                chain_finding.title,
                chain_finding.severity.value if hasattr(chain_finding.severity, "value") else str(chain_finding.severity),
                getattr(chain_finding, "confidence", 0.0),
                chain_key,
            )
            # 既存の Finding フローを再利用（通知・優先度制御・永続化）
            self.handle_finding(chain_finding)
    
    def _process_handoff(self, task: Task, result: dict) -> None:
        """
        Context-Aware Handoff 処理 (Phase 2.7)
        
        エージェントが次のエージェントを指名した場合 (HandoffResult)、
        即座に次のタスクをスケジュールし、コンテキストを引き継ぐ。
        """
        data = result.get("data", {})
        if not isinstance(data, dict):
            return
            
        # HandoffResult の構造をチェック
        # AgentProtocol経由の場合、data直下にあるか、data["output"]にある可能性がある
        
        target_data = data
        next_agent = data.get("next_suggested_agent")
        
        # 直下になく、outputが辞書の場合は中身をチェック
        if not next_agent:
            output = data.get("output")
            if isinstance(output, dict):
                 next_agent = output.get("next_suggested_agent")
                 if next_agent:
                     target_data = output

        if not next_agent:
            return
            
        logger.info(f"🔄 Handoff requested: {task.agent_type} -> {next_agent}")
        
        handoff_context = target_data.get("handoff_context", {})
        handoff_reason = target_data.get("reason", "Handoff requested")
        
        # 新しいタスクを作成
        new_task_id = f"handoff_{uuid.uuid4().hex[:8]}"
        new_task = Task(
            id=new_task_id,
            name=f"Handoff: {next_agent} ({handoff_reason})",
            agent_type=next_agent,
            action="execute", # Handoff先は通常executeアクション
            params={
                "target": task.params.get("target"),
                "context": handoff_context, # マージされたコンテキスト
                **handoff_context # フラットにも展開しておく
            },
            priority=task.priority + 10, # 現在のタスクより優先して割り込み
            parent_id=task.id
        )
        

        
        # キューに追加 (priorityで自動ソートされるので、insert(0)の代わりにaddを使う)
        self.task_queue.add(new_task)
        logger.info(f"Handoff task scheduled: {new_task.name} (Priority: {new_task.priority})")
        
        # 通知
        if settings.notify_on_task_start:
             get_notifier().notify(f"🔄 **Handoff Initiated**: {task.agent_type} ➡️ {next_agent}", bulk=True)

    def _record_react_decision(self, reason: ObservationReason, allowed: bool) -> None:
        metrics = getattr(self, "_react_observation_metrics", None)
        if not isinstance(metrics, dict):
            return
        metrics["attempted"] = int(metrics.get("attempted", 0)) + 1
        if allowed:
            metrics["executed"] = int(metrics.get("executed", 0)) + 1
        else:
            metrics["skipped"] = int(metrics.get("skipped", 0)) + 1
            reasons = metrics.setdefault("skip_reasons", {})
            normalized_reason = normalize_skip_reason(reason.value)
            reasons[normalized_reason] = int(reasons.get(normalized_reason, 0)) + 1
        self._sync_react_observation_metrics_snapshot()
        self._emit_react_observation_decision(reason=reason, allowed=allowed)

    def _react_setting(self, name: str, default: Any) -> Any:
        # Prefer unified core settings if available, then fallback to legacy settings.
        try:
            from src.core.config.settings import get_settings
            core_settings = get_settings()
            if hasattr(core_settings, name):
                return getattr(core_settings, name)
        except Exception:
            pass
        return getattr(settings, name, default)

    def _sync_react_observation_metrics_snapshot(self) -> None:
        try:
            metrics = getattr(self, "_react_observation_metrics", {})
            self.context.metrics["react_observation"] = {
                "attempted": int(metrics.get("attempted", 0)),
                "executed": int(metrics.get("executed", 0)),
                "skipped": int(metrics.get("skipped", 0)),
                "skip_reasons": dict(metrics.get("skip_reasons", {})),
                "retry_used": int(getattr(self, "_react_observation_retry_used", 0)),
                "inflight": int(getattr(self, "_react_observation_inflight", 0)),
                "queue_depth": int(len(getattr(self, "_react_observation_pending_queue", []))),
                "circuit_open_until": float(getattr(self, "_react_observation_cb_open_until", 0.0)),
            }
        except Exception:
            pass

    def _emit_react_observation_decision(self, *, reason: ObservationReason, allowed: bool) -> None:
        try:
            sample_rate = float(self._react_setting("react_observation_decision_event_sample_rate", 0.2))
            always_emit = {
                ObservationReason.SKIP_CIRCUIT_OPEN,
                ObservationReason.SKIP_BUDGET_EXCEEDED,
                ObservationReason.SKIP_QUEUE_OVERFLOW,
            }
            if reason not in always_emit and sample_rate < 1.0:
                seed = f"{reason.value}:{int(time.time() // 60)}:{self._react_field("observation_metrics", {"attempted": 0, "executed": 0, "skipped": 0, "skip_reasons": {}}).get('attempted', 0)}"
                deterministic = int(hashlib.md5(seed.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
                if deterministic > max(0.0, sample_rate):
                    return
            event_bus = get_event_bus()
            snapshot = self.context.metrics.get("react_observation", {})
            event_bus.emit_sync(
                Event(
                    type=EventType.DECISION_MADE,
                    payload={
                        "decision_type": "react_observation",
                        "allowed": bool(allowed),
                        "reason_code": reason.value,
                        "metrics": snapshot,
                    },
                    source="master_conductor",
                )
            )
        except Exception as e:
            logger.debug("Failed to emit react observation decision: %s", e)


    # ---- SGK-2026-0289: react state compat accessor (__new__ test safe) ----

    def _react_field(self, name: str, default=None):
        """Read react state from self.state (preferred) or legacy self._react_*."""
        state = getattr(self, "state", None)
        if state is not None:
            return getattr(state, f"react_{name}", default)
        return getattr(self, f"_react_{name}", default)

    def _set_react_field(self, name: str, value) -> None:
        """Write react state to self.state (preferred) or legacy self._react_*."""
        state = getattr(self, "state", None)
        if state is not None:
            setattr(state, f"react_{name}", value)
        else:
            setattr(self, f"_react_{name}", value)


    def _should_observe(self, task: Task, result: dict) -> tuple[bool, ObservationReason]:
        if not bool(self._react_setting("enable_react_observation", False)):
            return False, ObservationReason.SKIP_DISABLED

        if not self.llm_client:
            return False, ObservationReason.SKIP_NO_LLM_CLIENT

        now = time.time()
        if now < float(self._react_field("observation_cb_open_until", 0.0)):
            return False, ObservationReason.SKIP_CIRCUIT_OPEN

        retry_budget = int(self._react_setting("react_observation_retry_budget_per_run", 20))
        if int(self._react_field("observation_retry_used", 0)) >= retry_budget:
            return False, ObservationReason.SKIP_BUDGET_EXCEEDED

        queue_maxsize = int(self._react_setting("react_observation_queue_maxsize", 100))
        pending_queue = self._react_field("observation_pending_queue", None)
        queue_depth = len(pending_queue) if pending_queue is not None else 0
        if queue_depth >= queue_maxsize:
            return False, ObservationReason.SKIP_QUEUE_OVERFLOW

        max_inflight = int(self._react_setting("max_inflight_react_requests_global", 8))
        if int(self._react_field("observation_inflight", 0)) >= max_inflight:
            return False, ObservationReason.SKIP_BUDGET_EXCEEDED

        if not bool(result.get("success", False)):
            return False, ObservationReason.SKIP_NOT_SUCCESS

        data = result.get("data", {}) if isinstance(result, dict) else {}
        findings = result.get("findings", []) if isinstance(result, dict) else []
        if not data and not findings:
            return False, ObservationReason.SKIP_NO_SIGNAL

        low_value_patterns = str(self._react_setting("react_observation_low_value_task_patterns", "read,list,fetch"))
        pattern_items = [p.strip().lower() for p in low_value_patterns.split(",") if p.strip()]
        task_text = f"{getattr(task, 'name', '')} {getattr(task, 'action', '')}".lower()
        if any(p in task_text for p in pattern_items):
            return False, ObservationReason.SKIP_LOW_VALUE_TASK

        max_calls_per_run = int(self._react_setting("react_observation_max_calls_per_run", 50))
        if self._react_field("observation_executed_total", 0) >= max_calls_per_run:
            return False, ObservationReason.SKIP_BUDGET_EXCEEDED

        target = ""
        if isinstance(getattr(task, "params", None), dict):
            target = str(task.params.get("target", "") or "")
        max_calls_per_target = int(self._react_setting("react_observation_max_calls_per_target", 10))
        if target and self._react_field("observation_executed_by_target", {}).get(target, 0) >= max_calls_per_target:
            return False, ObservationReason.SKIP_BUDGET_EXCEEDED

        serialized = json.dumps(data, sort_keys=True, ensure_ascii=False).lower()
        high_value_keywords = ("vulnerability", "error", "unexpected", "critical", "exploit")
        if findings or any(k in serialized for k in high_value_keywords):
            return True, ObservationReason.ALLOW_HIGH_VALUE_SIGNAL

        sampling_rate = float(self._react_setting("react_observation_sampling_rate", 1.0))
        if sampling_rate >= 1.0:
            return True, ObservationReason.ALLOW_SAMPLED
        if sampling_rate <= 0.0:
            return False, ObservationReason.SKIP_SAMPLING_POLICY

        sample_seed = f"{task.id}:{task.name}:{target}"
        deterministic = int(hashlib.md5(sample_seed.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
        if deterministic <= sampling_rate:
            return True, ObservationReason.ALLOW_SAMPLED
        return False, ObservationReason.SKIP_SAMPLING_POLICY
    

    def _generate_react_suggestions(self, task: Task, result: dict) -> list[dict]:
        """Thin wrapper → master_conductor_finding_service (SGK-2026-0292)."""
        return generate_react_suggestions(
            task, result, self.rag, self.llm_client,
            self.context.target_info,
            self._react_field, self._set_react_field, self._react_setting,
        )
    def _observe_and_rethink(self, task: Task, result: dict) -> list[Task]:
        """Thin wrapper → finding_coordinator (SGK-2026-0297)."""
        return observe_and_rethink_coordinator(self, task, result)
    def replan(self, failed_task: Task, error: str, root_cause: Optional["RootCauseAnalysis"] = None) -> list[Task]:
        """
        失敗原因を分析し代替計画を生成
        
        Args:
            failed_task: 失敗したタスク
            error: エラーメッセージ
        
        Returns:
            代替タスクのリスト
        """
        normalized_agent = str(getattr(failed_task, "agent_type", "") or "").strip().lower()
        timeout_like_error = "timeout" in str(error or "").lower() or (
            root_cause is not None and getattr(root_cause.category, "value", "") == "network_timeout"
        )
        if (
            "recon_master" in normalized_agent
            and timeout_like_error
            and not bool(getattr(settings, "recon_master_timeout_replan_enabled", False))
        ):
            logger.info(
                "Skipping recon_master timeout replan by policy "
                "(recon_master_timeout_replan_enabled=false)."
            )
            return []

        alternative_tasks = []
        hints = []  # Initialize default
        
        # NOTE: RAG クエリは Swarm 経由に移行済み (Implementation Plan Section 3.4)
        # 以下はフォールバック
        if self.rag:
            try:
                hints = self.rag.query(f"bypass {error}")
                logger.debug("RAG fallback used in replan (Swarm not available)")
            except Exception as e:
                logger.debug("RAG query failed (non-critical): %s", e)
        
        # 1.5 Error Handling & Replanning: ErrorReplanner に委譲
        if hasattr(self, 'error_replanner') and self.error_replanner:
             try:
                 alternative_tasks = self.error_replanner.analyze_error_and_replan(
                     failed_task=failed_task,
                     error_message=error,
                     context=self.context
                 )
                 # RAGヒントも考慮（ErrorReplanner内でもRAG統合されているが、念のためマージ）
                 # ただし、ErrorReplannerがメインになるべき
             except Exception as e:
                 logger.error(f"ErrorReplanner failed: {e}")
                 # フォールバックロジック（既存のもの）を使うか、空リストを返す
        
        # ErrorReplannerが未実装または失敗した場合の既存ロジック（後方互換性）
        if not alternative_tasks:
            dynamic_priority = failed_task.priority - 5
            if root_cause and root_cause.confidence > 0.8:
                if root_cause.category.value == "auth_failure":
                    dynamic_priority = failed_task.priority + 20

            alternative_tasks = self._build_replan_fallback_tasks(
                failed_task, error, hints, root_cause, dynamic_priority,
            )
        
        return alternative_tasks

    def _map_agent_to_action_type(self, agent_type: str, action: str = "") -> "ActionType":
        """エージェントタイプをリスク評価用のActionTypeにマッピング"""
        try:
            from src.core.intelligence import ActionType
        except ImportError:
            return "param_fuzzing" # fallback

        mapping = {
            "recon": ActionType.PASSIVE_RECON,
            "discovery": ActionType.READ_ONLY,
            "auth": ActionType.AUTH_TESTING,
            "idor": ActionType.PARAM_FUZZING,
            "injection": ActionType.INJECTION_TESTING,
            "scanner": ActionType.PARAM_FUZZING,
            "fuzzing": ActionType.PARAM_FUZZING,
            "file_upload": ActionType.FILE_UPLOAD,
            "exploit": ActionType.EXPLOIT_ATTEMPT,
        }
        for key, action_type in mapping.items():
            if key in (agent_type or "").lower():
                return action_type
        return ActionType.PARAM_FUZZING  # デフォルト
    
    def next_task(self) -> Optional[Task]:
        """
        キューから次のタスクを取得（対話モード用）
        
        InteractiveBridge から呼び出されることを想定。
        execute_with_replan() の代わりに、1タスクずつ制御したい場合に使用。
        
        Returns:
            次のタスク。キューが空の場合は None
        """
        task = self._select_next_task_from_queue()
        
        if task:
            self.current_task = task
            task.state = TaskState.PENDING
        
        return task

    def _select_next_task_from_queue(self) -> Optional[Task]:
        """TaskPrioritizer があれば選択に使い、失敗時は通常 pop にフォールバックする。"""
        def _pop_non_quarantined() -> Optional[Task]:
            while True:
                candidate = self.task_queue.pop()
                if candidate is None:
                    return None
                if self._is_task_quarantined(candidate):
                    logger.info("Skip quarantined task from queue: %s", getattr(candidate, "id", "unknown"))
                    continue
                return candidate

        prioritizer = getattr(self, "task_prioritizer", None)
        if prioritizer is None:
            return _pop_non_quarantined()

        try:
            candidates = self.task_queue.get_all()
            if not candidates:
                return None

            selected = prioritizer.select_task(candidates)
            if selected is None:
                return self.task_queue.pop()

            if hasattr(prioritizer, "get_last_selection_trace"):
                trace = prioritizer.get_last_selection_trace()
                logger.debug(
                    "TaskPrioritizer select trace: mode=%s selected=%s arm=%s candidates=%s score=%s",
                    trace.get("mode"),
                    trace.get("selected_task_id"),
                    trace.get("selected_arm"),
                    trace.get("candidates"),
                    trace.get("score"),
                )

            selected_id = getattr(selected, "id", None)
            if selected_id and self.task_queue.remove_by_id(selected_id):
                if self._is_task_quarantined(selected):
                    logger.info("Skip quarantined selected task: %s", selected_id)
                    return _pop_non_quarantined()
                return selected

            return _pop_non_quarantined()
        except Exception as e:
            logger.warning("TaskPrioritizer selection failed, fallback to queue priority only: %s", e)
            return _pop_non_quarantined()

    def _record_task_prioritizer_outcome(self, task: Optional[Task], result: Optional[dict]) -> None:
        prioritizer = getattr(self, "task_prioritizer", None)
        if prioritizer is None or task is None:
            return

        try:
            payload = result if isinstance(result, dict) else {}
            prioritizer.record_outcome(task, payload)
        except Exception as e:
            logger.warning("TaskPrioritizer outcome recording failed (non-critical): %s", e)
    
    def execute_single_task(
        self,
        task: Task,
        enable_react: bool = False,
        enable_replan: bool = True,
    ) -> dict:
        """Thin wrapper → execution_coordinator (SGK-2026-0293)."""
        return execute_task_coordinator(self, task, enable_react, enable_replan)
        
        
        
        
        

                
            
                
                

                
                

                
                    
                    
            
            

            
            
            

            

    def _dispatch_scope_verification_fast_path(self, task: Task) -> dict:
        """
        Scope Verification の軽量フォールバック。

        ScopeParser の LLM/外部依存を介さずに、最低限のスコープを確定して
        初期フェーズの timeout 連鎖を防ぐ。
        """
        result = _svc_dispatch_scope_verification_fast_path(
            task,
            context_target_info=self.context.target_info,
            allow_post_exploit=bool(getattr(settings, "allow_post_exploit", False)),
        )
        scope = result.pop("_scope_definition", None)
        if scope is not None:
            try:
                from src.core.security.ethics_guard import get_ethics_guard
                get_ethics_guard().set_scope(scope)
            except Exception as guard_exc:
                logger.warning("Failed to apply fast-path scope to EthicsGuard: %s", guard_exc)
        return result

    # ---- SGK-2026-0287 D02: _dispatch sub-block extractions ----

    async def _dispatch_recon_master(self, task: Task, workspace_root: str | None) -> dict:
        """ReconPipeline dispatch sub-block. Extracted from _dispatch Phase 3 branch.

        Args:
            task: recon_master task
            workspace_root: workspace root path string
        """
        if hasattr(self, "_recon_executed") and self._recon_executed:
            logger.warning("Recon already executed. Skipping duplicate recon_master task.")
            return {
                "success": True,
                "task_id": task.id,
                "agent": "recon_master",
                "skipped": True,
                "reason": "Recon already executed",
            }

        try:
            from src.recon.pipeline import ReconPipeline

            target = task.params.get("target", self.context.target_info.get("target"))
            if not target:
                return {"success": False, "task_id": task.id, "error": "Target not specified"}

            logger.info("Dispatching ReconPipeline for target: %s", target)

            from src.core.engine.master_conductor_dependencies import build_recon_dependencies_from_mc
            recon_deps = build_recon_dependencies_from_mc(self)
            pipeline = ReconPipeline(
                config=settings.model_dump() if hasattr(settings, "model_dump") else settings.dict(),
                workspace_root=recon_deps.workspace_root,
                project_manager=self.project_manager,
                deps=recon_deps,
            )

            start_step = int(task.params.get("start_step", 1))
            end_step = int(task.params.get("end_step", 8))

            state = await run_recon_pipeline_isolated(
                pipeline, target,
                start_step=start_step,
                end_step=end_step,
            )

            for asset in state.live_subs:
                self.phase_gate.add_asset(Phase.RECON, asset)
            for tech in state.tech_stack:
                self.phase_gate.add_tech(Phase.RECON, tech)

            if state.results:
                self.phase_gate.set_classified_files(Phase.RECON, state.results)
                if any(v.get("count", 0) > 0 for v in state.results.values()):
                    self.phase_gate.unlock(Phase.ATTACK)
                    logger.info("ATTACK phase unlocked due to recon results")
                    attack_tasks = self._create_attack_tasks_from_recon(state.results)
                    if attack_tasks:
                        self._add_tasks(attack_tasks, source="recon_result")
                        logger.info("Added %d attack tasks to queue", len(attack_tasks))

            self._recon_executed = True

            return {
                "success": True,
                "task_id": task.id,
                "agent": "recon_master",
                "data": {
                    "status": "completed",
                    "current_step": state.current_step,
                    "live_subs_count": len(state.live_subs),
                    "screens_count": state.screenshots_count,
                    "results": state.results,
                },
                "new_assets": state.live_subs,
            }
        except Exception as e:
            logger.error("ReconPipeline execution error: %s", e)
            return {"success": False, "task_id": task.id, "agent": "recon_master", "error": str(e)}

    async def _dispatch_agent_fallback(self, task: Task, workspace_root: str | None) -> dict:
        """AgentFactory fallback dispatch sub-block. Extracted from _dispatch.

        Handles agent creation, cookie/auth injection, execution, result assembly,
        and workspace persistence.
        """
        effective_model = task.params.get("model") or getattr(settings, "security_agent_model", settings.model)
        try:
            agent = AgentFactory.create_agent(
                task.agent_type,
                mode=self.context.target_info.get("mode", "security"),
                model=effective_model,
                tools=task.params.get("tools"),
                workspace_root=workspace_root,
                project_manager=self.project_manager,
                master_conductor=self,
            )

            logger.info("Dispatching task %s to agent %s", task.id, task.agent_type)

            token, resolved_target = self._inject_cookies_into_task(task)

            try:
                result_data = await _svc_execute_agent_dispatch(
                    agent, task,
                    resolved_target=resolved_target,
                )
            finally:
                await self._cleanup_agent_after_dispatch(agent, task, token)

            result_data, extracted_findings = self._augment_payload_with_findings(result_data)
            success_flag = True
            error_message = None
            if isinstance(result_data, dict):
                inner_success = result_data.get("success")
                if isinstance(inner_success, bool) and ("data" in result_data or "error" in result_data):
                    success_flag = inner_success
                    if not inner_success:
                        error_message = str(result_data.get("error") or "Agent reported failure")

            if self.workspace and result_data:
                self.workspace.save_task_result(task, result_data)

            response = {
                "success": success_flag,
                "task_id": task.id,
                "agent": task.agent_type,
                "data": result_data,
                "context": self.context.to_handoff_dict(),
                "findings": extracted_findings,
            }
            if error_message is not None:
                response["error"] = error_message
            return response

        except ImportError as e:
            logger.error("Failed to import agent %s: %s", task.agent_type, e)
            return {
                "success": False,
                "task_id": task.id,
                "agent": task.agent_type,
                "error": f"Agent not found: {str(e)}",
            }
        except Exception as e:
            import traceback
            logger.error("Task execution error in %s: %s\n%s", task.agent_type, e, traceback.format_exc())
            return {
                "success": False,
                "task_id": task.id,
                "agent": task.agent_type,
                "error": str(e),
            }

    async def _dispatch(self, task: Task) -> dict:
        """タスクを適切なエージェントにディスパッチ (SGK-2026-0287 D02: thin routing facade).

        # === Dispatch Routing: Two Main Paths ===
        #
        # SHIGOKU has two primary dispatch paths for attack tasks.  The choice is
        # deterministic based on the task's action field, NOT on agent_type alone.
        #
        # ## Gate 5: Direct Swarm Dispatch
        #   - Activated when `task.agent_type == "swarm"` OR tags are present
        #   - Used for: broad exploration, ambiguous signals, hypothesis generation
        #   - Tasks created by:
        #     * _inject_heuristic_swarm_tasks() — URL-pattern heuristics from discovery
        #       (auth_ninja, api_spec_reconstruct)
        #     * Recon pipeline — auth_attack, sqli_scan, xss_scan, etc.
        #   - Key characteristic: ONE swarm, ONE dispatch call
        #   - Dispatched via: SwarmDispatcher.dispatch(tags=...)
        #
        # ## Gate 9: Recipe Execution (run_recipe)
        #   - Activated when `task.action == "run_recipe"`
        #   - Used for: deterministic, high-confidence, repeatable deep-dive verification
        #   - Tasks created by:
        #     * _load_recipe_tasks() — signal-based RecipeLoader.match_recipes_to_context()
        #   - Key characteristic: MULTI-STEP DAG/stage execution via OptimizedRecipeRunner
        #   - Each step dispatches recursively back through _dispatch()
        #
        # ## Switching Conditions (deterministic)
        #   - Recipe が選ばれる条件:
        #     + trigger (required_signals) が揃っている
        #     + success / stop condition が定義できる
        #     + 同じ検証列を繰り返し再利用したい
        #   - Direct swarm が選ばれる条件:
        #     + signal が曖昧で branching が多い
        #     + LLM 探索で候補列挙したほうが価値が高い
        #     + Recipe の trigger 条件が満たされていない
        #   - Recipe 後に swarm が起動する条件 (follow-up):
        #     + Recipe が additional evidence や adjacent attack surface を発見した
        #     + 決定論的な確認は終わったが、次の横展開が必要
        #
        # ## Non-Attack Dispatch Gates (also in routing chain)
        #   - Gate 1: Scope verification fast path (scope_parser)
        #   - Gate 2: Post-exploit guard (EthicsGuard)
        #   - Gate 3: CTF filter
        #   - Gate 4: Worker dispatch
        #   - Gate 6: Cartographer
        #   - Gate 7: Fingerprinter
        #   - Gate 8: Recon Master → ReconPipeline
        #   - Gate 10: AgentFactory fallback
        """
        logger.debug("Entering _dispatch with task %s", task.agent_type)

        if task.agent_type == "scope_parser" and getattr(task, "action", "") == "verify_scope":
            return self._dispatch_scope_verification_fast_path(task)

        current_mode = self.context.target_info.get("mode", "bugbounty")

        # --- Scope-based Post Exploitation Control ---
        from src.core.security.ethics_guard import get_ethics_guard
        guard = get_ethics_guard()
        pe_guard = _svc_dispatch_post_exploit_guard(
            task, current_mode=current_mode,
            settings_allow_post_exploit=getattr(settings, "allow_post_exploit", False),
            scope_allow_post_exploit=guard.scope.allow_post_exploit if guard.scope else None,
        )
        if pe_guard is not None:
            return pe_guard

        # === Phase 1: CTF filter ===
        ctf_filter = _svc_dispatch_ctf_filter(task, current_mode=current_mode)
        if ctf_filter is not None:
            return ctf_filter

        workspace_root = str(self.workspace.base) if self.workspace else None

        # === Phase 1.2: Worker / Swarm / Specialized ===
        worker_result = await _svc_dispatch_worker(
            task, accumulated_context=self.accumulated_context,
            llm_client=self.llm_client, network_client=self.network_client,
        )
        if worker_result is not None:
            return worker_result

        # === Gate 5: Direct Swarm Dispatch ===
        # Swarm/LLM による広域探索・曖昧性解消・仮説列挙。
        # task.agent_type=="swarm" または tags が存在する場合に発火。
        # この経路は YAML Recipe を経由せず、SwarmDispatcher へ直接 dispatch する。
        swarm_result = await _svc_dispatch_swarm(
            task,
            project_manager_config=self.project_manager.config if self.project_manager else None,
            network_client=self.network_client, llm_client=self.llm_client,
            event_bus=self.event_bus, recipe_loader=self.recipe_loader,
            rag=self.rag, agentic_rag=self.agentic_rag,
        )
        if swarm_result is not None:
            return swarm_result

        if task.agent_type == "cartographer":
            return await _svc_dispatch_cartographer(
                task, network_client=self.network_client, workspace_root=workspace_root,
            )
        if task.agent_type == "fingerprinter":
            return await _svc_dispatch_fingerprinter(
                task, network_client=self.network_client, workspace_root=workspace_root,
            )

        # === Phase 3: Recon Master (D02 extracted helper) ===
        if task.agent_type == "recon_master":
            return await self._dispatch_recon_master(task, workspace_root)

        # === Gate 9: Recipe Execution (run_recipe) ===
        # YAML Recipe による決定論的・多段階の検証実行。
        # task.action == "run_recipe" の場合に発火。
        # OptimizedRecipeRunner 経由で DAG/Stage 実行し、各 step は再帰的に _dispatch() される。
        if _svc_dispatch_recipe_check(task):
            logger.info("Executing optimized recipe: %s", task.params.get("recipe_name"))
            try:
                return await self._execute_recipe_task(task)
            except Exception as e:
                logger.error("Recipe execution error: %s", e)
                return {"success": False, "error": str(e)}

        # === AgentFactory fallback (D02 extracted helper) ===
        return await self._dispatch_agent_fallback(task, workspace_root)

    def _get_context_auth_headers(self) -> dict[str, str]:
        return self._seed_service.get_context_auth_headers()

    def _get_context_cookie_string(self) -> str:
        return self._seed_service.get_context_cookie_string()

    # ---- SGK-2026-0287 Phase 4: dispatch helpers ----

    def _inject_cookies_into_task(self, task: Task) -> tuple[object | None, str | None]:
        """Inject context cookies and auth headers into task params.

        Returns:
            (cookie_token, resolved_target) tuple.
            cookie_token: for later reset via _cleanup_agent_after_dispatch.
            resolved_target: the resolved task target, or None.
        """
        from src.core.infra.network_client import current_scan_cookies

        context_auth_headers = self._get_context_auth_headers()
        raw_cookies = self._get_context_cookie_string()
        cookie_dict: dict[str, str] = {}
        if raw_cookies:
            try:
                from http.cookies import SimpleCookie
                cookie = SimpleCookie()
                cookie.load(raw_cookies)
                cookie_dict = {k: v.value for k, v in cookie.items()}
            except Exception as e:
                logger.warning("Failed to parse cookies: %s", e)

        token = current_scan_cookies.set(cookie_dict)

        if context_auth_headers:
            task_auth_headers = task.params.get("auth_headers", {})
            if not isinstance(task_auth_headers, dict):
                task_auth_headers = {}
            task_auth_headers.update(context_auth_headers)
            task.params["auth_headers"] = task_auth_headers

        # Resolve task target
        resolved_target = self._resolve_task_target(task)
        if resolved_target:
            task.target = resolved_target
            task.params["target"] = resolved_target

        return token, resolved_target

    @staticmethod
    async def _cleanup_agent_after_dispatch(agent: Any, task: Task, token: object | None) -> None:
        """Clean up agent resources and reset cookie contextvar.

        Extracted from _dispatch finally block.
        """
        from src.core.infra.network_client import current_scan_cookies

        if token:
            current_scan_cookies.reset(token)

        if agent and hasattr(agent, "close"):
            try:
                import inspect
                if inspect.iscoroutinefunction(agent.close):
                    await agent.close()
                else:
                    agent.close()
            except Exception as e:
                logger = __import__("logging").getLogger(__name__)
                logger.warning("Error closing agent %s: %s", getattr(task, "agent_type", "?"), e)

    def _normalize_url_candidate(self, value: str) -> str:
        return self._seed_service.normalize_url_candidate(value)

    def _extract_host_candidate(self, value: str) -> str:
        return self._seed_service.extract_host_candidate(value)

    def _resolve_in_scope_hosts(self) -> list[str]:
        return self._seed_service.resolve_in_scope_hosts()

    def _is_target_url_in_scope(self, url: str, scope_hosts: list[str]) -> bool:
        return self._seed_service.is_target_url_in_scope(url, scope_hosts)

    def _resolve_task_target(self, task: Task) -> str:
        return self._seed_service.resolve_task_target(task)

    def _task_has_csrf_candidate_category(self, task: Any) -> bool:
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        category = str(params.get("category", "") or "").strip().lower()
        return category == "csrf_candidate"

    def _has_csrf_candidate_in_queue_or_history(self) -> bool:
        for task in list(getattr(self, "completed_tasks", []) or []):
            if self._task_has_csrf_candidate_category(task):
                return True

        task_queue = getattr(self, "task_queue", None)
        if task_queue is not None:
            try:
                for queued_task in task_queue:
                    if self._task_has_csrf_candidate_category(queued_task):
                        return True
            except Exception:
                pass

        pending_hitl = getattr(self, "pending_hitl", [])
        if isinstance(pending_hitl, list):
            for ticket in pending_hitl:
                if not isinstance(ticket, dict):
                    continue
                task_snapshot = ticket.get("task")
                if not isinstance(task_snapshot, dict):
                    continue
                params = task_snapshot.get("params", {})
                if not isinstance(params, dict):
                    continue
                category = str(params.get("category", "") or "").strip().lower()
                if category == "csrf_candidate":
                    return True
        return False

    def _has_xss_candidate_in_queue_or_history(self) -> bool:
        for task in self.completed_tasks:
            params = task.params if isinstance(getattr(task, "params", None), dict) else {}
            category = str(params.get("category", "") or "").strip().lower()
            if category == "xss_candidate":
                return True

        task_queue = getattr(self, "task_queue", None)
        if task_queue is not None:
            try:
                for task in task_queue:
                    params = task.params if isinstance(getattr(task, "params", None), dict) else {}
                    category = str(params.get("category", "") or "").strip().lower()
                    if category == "xss_candidate":
                        return True
            except Exception:
                pass

        pending_hitl = getattr(self, "pending_hitl", [])
        if isinstance(pending_hitl, list):
            for ticket in pending_hitl:
                if not isinstance(ticket, dict):
                    continue
                task_snapshot = ticket.get("task")
                if not isinstance(task_snapshot, dict):
                    continue
                params = task_snapshot.get("params", {})
                if not isinstance(params, dict):
                    continue
                category = str(params.get("category", "") or "").strip().lower()
                if category == "xss_candidate":
                    return True
        return False

    def _task_matches_scenario(self, task: Any, scenario_id: str) -> bool:
        return _service_task_matches_scenario(task, scenario_id)

    def _task_has_auth_surface(self, task: Any) -> bool:
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        if not isinstance(params, dict):
            params = {}
        category = str(params.get("category", "") or "").strip().lower()
        tags = params.get("tags", [])
        normalized_tags = {
            str(tag or "").strip().lower()
            for tag in tags
            if str(tag or "").strip()
        } if isinstance(tags, list) else set()
        return category == "auth" or "auth_endpoint" in normalized_tags or "oob_candidate" in normalized_tags

    def _has_scenario_in_queue_or_history(self, scenario_id: str) -> bool:
        return _service_has_scenario_in_queue_or_history(
            scenario_id=scenario_id,
            completed_tasks=list(getattr(self, "completed_tasks", []) or []),
            task_queue=getattr(self, "task_queue", None),
            pending_hitl=getattr(self, "pending_hitl", []),
        )

    def _resolve_global_oob_guard_target(self) -> str:
        return _service_resolve_global_oob_guard_target(
            completed_tasks=list(getattr(self, "completed_tasks", []) or []),
            task_queue=getattr(self, "task_queue", None),
            discovered_assets=list(getattr(self.context, "discovered_assets", []) or []),
            resolve_task_target=self._resolve_task_target,
            normalize_url_candidate=self._normalize_url_candidate,
            resolve_in_scope_hosts=self._resolve_in_scope_hosts,
        )

    def _resolve_global_csrf_guard_target(self) -> str:
        return _service_resolve_global_csrf_guard_target(
            context_target_info=getattr(self.context, "target_info", {}),
            target_attr=str(getattr(self, "target", "") or ""),
            discovered_assets=list(getattr(self.context, "discovered_assets", []) or []),
            task_queue=getattr(self, "task_queue", None),
            resolve_task_target=self._resolve_task_target,
            normalize_url_candidate=self._normalize_url_candidate,
            resolve_in_scope_hosts=self._resolve_in_scope_hosts,
        )

    def _ensure_global_csrf_guard_task(self, trigger_source: str = "execute_loop") -> bool:
        if self._has_csrf_candidate_in_queue_or_history():
            return False
        should_inject, guard_task, guard_id = ensure_global_csrf_guard_decision(
            trigger_source=trigger_source,
            resolve_required_vuln_families=self._resolve_required_vuln_families,
            resolve_guard_target=self._resolve_global_csrf_guard_target,
            task_queue=getattr(self, "task_queue", None),
            get_context_cookie_string=self._get_context_cookie_string,
            get_context_auth_headers=self._get_context_auth_headers,
            discovered_assets=getattr(self.context, "discovered_assets", [])[:10] if hasattr(self.context, "discovered_assets") else [],
            target_info=getattr(self.context, "target_info", {}) if hasattr(self.context, "target_info") else {},
        )
        if not should_inject or guard_task is None:
            return False
        task_queue = getattr(self, "task_queue", None)
        if task_queue is None:
            return False
        task_queue.add(guard_task)
        self._injected_task_ids.add(guard_task.id)
        self._derived_task_count += 1
        logger.warning(
            "Global CSRF coverage guard injected (source=%s, target=%s, task_id=%s)",
            trigger_source, guard_task.target, guard_id,
        )
        return True

    def _ensure_global_xss_guard_task(self, trigger_source: str = "execute_loop") -> bool:
        if self._has_xss_candidate_in_queue_or_history():
            return False
        should_inject, guard_task, guard_id = ensure_global_xss_guard_decision(
            trigger_source=trigger_source,
            resolve_required_vuln_families=self._resolve_required_vuln_families,
            resolve_guard_target=self._resolve_global_csrf_guard_target,
            task_queue=getattr(self, "task_queue", None),
            get_context_cookie_string=self._get_context_cookie_string,
            get_context_auth_headers=self._get_context_auth_headers,
            discovered_assets=getattr(self.context, "discovered_assets", [])[:10] if hasattr(self.context, "discovered_assets") else [],
            target_info=getattr(self.context, "target_info", {}) if hasattr(self.context, "target_info") else {},
        )
        if not should_inject or guard_task is None:
            return False
        task_queue = getattr(self, "task_queue", None)
        if task_queue is None:
            return False
        task_queue.add(guard_task)
        self._injected_task_ids.add(guard_task.id)
        self._derived_task_count += 1
        logger.warning(
            "Global XSS coverage guard injected (source=%s, target=%s, task_id=%s)",
            trigger_source, guard_task.target, guard_id,
        )
        return True

    def _ensure_global_oob_guard_task(self, trigger_source: str = "execute_loop") -> bool:
        scenario_id = "scn_08_oob_external_channel_flow"
        if self._has_scenario_in_queue_or_history(scenario_id):
            return False
        should_inject, guard_task, guard_id = ensure_global_oob_guard_decision(
            trigger_source=trigger_source,
            resolve_guard_target=self._resolve_global_oob_guard_target,
            task_queue=getattr(self, "task_queue", None),
            get_context_cookie_string=self._get_context_cookie_string,
            get_context_auth_headers=self._get_context_auth_headers,
            discovered_assets=getattr(self.context, "discovered_assets", [])[:10] if hasattr(self.context, "discovered_assets") else [],
            target_info=getattr(self.context, "target_info", {}) if hasattr(self.context, "target_info") else {},
        )
        if not should_inject or guard_task is None:
            return False
        task_queue = getattr(self, "task_queue", None)
        if task_queue is None:
            return False
        task_queue.add(guard_task)
        self._injected_task_ids.add(guard_task.id)
        self._derived_task_count += 1
        logger.warning(
            "Global OOB coverage guard injected (source=%s, target=%s, task_id=%s)",
            trigger_source, guard_task.target, guard_id,
        )
        return True

    def _expand_plan_for_assets(self, new_assets: list[str]) -> None:
        """新発見の資産に対するタスクを追加"""
        for asset in new_assets:
            if asset not in self.context.discovered_assets:
                self.context.discovered_assets.append(asset)
                
                # 資産ごとにスキャンタスクを追加
                self.task_queue.add(Task(
                    id=f"scan_{asset}_{len(self.task_queue)}",
                    name=f"Scan {asset}",
                    agent_type="web_scanner",
                    action="scan",
                    params={"url": f"https://{asset}"},
                    priority=60,
                ))
    
    def _create_attack_tasks_from_recon(self, recon_results: dict[str, dict]) -> list[Task]:
        """
        Recon 結果から Attack タスクを生成 (thin wrapper)

        ReconAttackTaskPlanner へ delegation し、queue mutation を facade 側に残す。

        Returns:
            生成されたタスクのリスト
        """
        from src.core.engine.master_conductor_recon_attack_task_planner import ReconAttackTaskPlanner

        planner = ReconAttackTaskPlanner(
            phase_gate=self.phase_gate,
            resolve_recon_file_path=self._resolve_recon_file_path,
            collect_history_replay_targets=self._collect_history_replay_targets,
            get_context_cookie_string=self._get_context_cookie_string,
            get_context_auth_headers=self._get_context_auth_headers,
            apply_phase2_on_empty_policy=self._apply_phase2_on_empty_policy,
            normalize_url_candidate=self._normalize_url_candidate,
            resolve_required_vuln_families=self._resolve_required_vuln_families,
            collect_csrf_seed_targets=self._collect_csrf_seed_targets,
            refine_backfill_seed_targets=self._refine_backfill_seed_targets,
            should_enable_phase2_on_empty_for_backfill=self._should_enable_phase2_on_empty_for_backfill,
            resolve_task_target=self._resolve_task_target,
            resolve_in_scope_hosts=self._resolve_in_scope_hosts,
            map_category_to_vuln_families=self._map_category_to_vuln_families,
            collect_xss_seed_targets=self._collect_xss_seed_targets,
            resolve_global_csrf_guard_target=self._resolve_global_csrf_guard_target,
            plan_missing_link_probes=self.plan_missing_link_probes,
            context=self.context,
            target_url=getattr(self, "target", ""),
            workspace=self.workspace,
        )
        return planner.create_attack_tasks_from_recon(recon_results)
    
    async def execute_parallel(self, max_workers: int = 5) -> dict:
        """Thin wrapper → execution_coordinator (SGK-2026-0293)."""
        return await execute_parallel_coordinator(self, max_workers)
        
        
        
        
            
        
        
            
            
            
        
        
        
    
    def _create_decision_check_for_task(self, task: Task) -> Optional[Callable[[dict], bool]]:
        """タスク固有のDecision Check関数を生成"""
        if "login" in task.agent_type.lower() or "brute" in task.name.lower():
            def check_auth_required(context: dict) -> bool:
                return context.get("auth_required", True)
            return check_auth_required
        
        if task.agent_type == "wordpress_scanner":
            def check_wordpress(context: dict) -> bool:
                tech_stack = context.get("tech_stack", [])
                return "WordPress" in tech_stack or "wordpress" in [t.lower() for t in tech_stack]
            return check_wordpress
        
        return None
    
    def _generate_summary(self) -> dict:
        """実行結果サマリーを生成"""
        total = len(self.completed_tasks)
        success = len([t for t in self.completed_tasks if t.state == TaskState.SUCCESS])
        failed = len([t for t in self.completed_tasks if t.state == TaskState.FAILED])
        replanned = len([t for t in self.completed_tasks if t.state == TaskState.REPLANNED])

        failure_agg = compute_failure_aggregation(
            self.completed_tasks,
            normalize_failure_reason_code=self._normalize_failure_reason_code,
        )

        percentile_data = compute_duration_percentile(
            getattr(self, "execution_log", None),
        )

        coverage_gate = self._evaluate_vuln_family_coverage()
        scenario_coverage = self._evaluate_intervention_scenario_coverage()
        pending_hitl_items = self.list_pending_hitl_tickets(statuses={"pending", "approved", "queued"})
        if not coverage_gate.get("gate_passed", False):
            logger.warning(
                "Vulnerability-family coverage gate not reached. Missing: %s",
                ", ".join(coverage_gate.get("missing_families", [])),
            )
        
        return {
            "total_tasks": total,
            "success": success,
            "failed": failed,
            "replanned": replanned,
            "success_rate": success / total if total > 0 else 0,
            "discovered_assets": self.context.discovered_assets,
            "bypass_methods_learned": self.context.bypass_methods,
            "pending_tasks": len(self.task_queue),
            "estimated_cost": self.context.metrics.get("estimated_cost", 0.0),
            "total_duration": self.context.metrics.get("total_duration", 0),
            "vulnerability_family_coverage": coverage_gate,
            "coverage_gate_passed": coverage_gate.get("gate_passed", False),
            "coverage_gate_missing": coverage_gate.get("missing_families", []),
            "coverage_gate_required": len(coverage_gate.get("required_families", [])),
            "coverage_gate_covered": len(coverage_gate.get("required_families", []))
            - len(coverage_gate.get("missing_families", [])),
            "intervention_scenario_coverage": scenario_coverage,
            "scenario_coverage": scenario_coverage,
            "scenario_gate_passed": scenario_coverage.get("gate_passed", False),
            "scenario_missing": scenario_coverage.get("missing_scenarios", []),
            "scenario_required": int(scenario_coverage.get("required_count", 0) or 0),
            "scenario_covered": int(scenario_coverage.get("covered_count", 0) or 0),
            "pending_hitl_count": len(pending_hitl_items),
            "failed_reason_codes": failure_agg["failed_reason_codes"],
            "failed_failure_categories": failure_agg["failed_failure_categories"],
            "unknown_failure_count": failure_agg["unknown_failure_count"],
            "unknown_rate": failure_agg["unknown_rate"],
            "quarantined_signatures": len(getattr(self, "_quarantined_signatures", {})),
            "pr_execution_time_slo": percentile_data["pr_execution_time_slo"],
        }
    
    def get_context(self) -> ExecutionContext:
        """現在のコンテキストを取得"""
        return self.context
    
    def inject_context(self, context_dict: dict) -> None:
        """外部からコンテキストを注入（Handoff用）"""
        if context_dict.get("bypass_methods"):
            self.context.bypass_methods.extend(context_dict["bypass_methods"])
        if context_dict.get("discovered_assets"):
            self.context.discovered_assets.extend(context_dict["discovered_assets"])
        if context_dict.get("target_info"):
            self.context.target_info.update(context_dict["target_info"])

    # =========================================================================
    # Session Persistence Methods (クラッシュ回復・再開機能)
    # =========================================================================
    
    def start_session(self, target: str, mode: str) -> None:
        """
        新規セッションを開始
        
        Args:
            target: ターゲットURL/ドメイン
            mode: 動作モード (bugbounty/ctf/vulntest)
        """
        if not self._session_manager:
            logger.debug("SessionManager not configured, skipping session creation")
            return

        payload = build_start_session_payload(
            target=target,
            mode=mode,
            context_target_info=self.context.target_info,
        )
        self._current_session = self._session_manager.create_session(**payload)
        logger.info(f"Session started: {self._current_session.session_id}")
    
    def _checkpoint(self) -> None:
        """Thin wrapper → lifecycle_coordinator (SGK-2026-0295)."""
        checkpoint_coordinator(self)

    def resume_session(self, session_id: str) -> bool:
        """Thin wrapper → lifecycle_coordinator (SGK-2026-0295)."""
        return resume_session_coordinator(self, session_id)

    def _serialize_task_queue(self) -> list[str]:
        """タスクキューをJSON文字列リストにシリアライズ"""
        return serialize_legacy_session_task_queue(self.task_queue)
    
    def _deserialize_task_queue(self, serialized: list[str]) -> tuple[list[Task], list[str]]:
        """
        JSON文字列リストからタスクキューを復元
        
        Returns:
            (復元成功したタスクリスト, 失敗したタスクID/概要リスト)
        """
        tasks, failed_ids = deserialize_legacy_session_task_queue(serialized)
        for failed in failed_ids:
            logger.warning("Failed to deserialize task: %s", failed)
        return tasks, failed_ids
    
    def list_sessions(self) -> list:
        """保存されたセッション一覧を取得"""
        if not self._session_manager:
            return []
        return self._session_manager.list_sessions()
