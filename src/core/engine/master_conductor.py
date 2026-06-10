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
from src.core.engine.master_conductor_state_snapshot import (
    restore_completed_tasks_from_session_payload,
    restore_context_from_session_payload,
    restore_pending_hitl_from_session_payload,
    restore_task_queue_from_session_payload,
)
from src.core.waf.bypasser import WAFBypasser
from src.core.engine.master_conductor_recon_seed_target_service import ReconSeedTargetService

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
        self.graph = graph or KnowledgeGraph()
        self.pam = pam
        self.rag = rag
        self.llm_client = llm_client
        self._auto_checkpoint = auto_checkpoint
        self.settings = settings
        
        # 6.3 TaskExecutionLog for Dashboard Traceability
        from src.core.models.task_execution_log import get_execution_log
        self.execution_log = get_execution_log()
        
        # Database Writer (バッチ & 安全性強化)
        self.repo = get_findings_repository()
        self.writer = AsyncDatabaseWriter(kg=self.graph, repo=self.repo)
        
        # Self-initialize RecipeLoader if not provided
        if recipe_loader is None:
            from src.core.engine.recipe_loader import RecipeLoader
            self.recipe_loader = RecipeLoader()
        else:
            self.recipe_loader = recipe_loader
            
        self.project_manager = project_manager  # ProjectManager
        
        # Phase 2 Spec: モードの取得
        self.mode = getattr(settings, "environment", "BUG_BOUNTY") 
        if hasattr(settings, "ctf_target") and settings.ctf_target:
             self.mode = "CTF"
             
        self.flag_format = getattr(settings, "ctf_flag_format", "flag{.*}")
        
        # 🧠 Intelligence Modules
        from src.core.intelligence import (
            get_risk_predictor, get_self_reflection,
            get_error_analyzer, get_priority_booster,
            get_decision_enhancer, get_diff_analyzer,
            get_task_prioritizer,
            get_chain_builder,
            get_strategy_selector,
        )
        self.risk_predictor = get_risk_predictor()
        self.self_reflection = get_self_reflection()
        self.error_analyzer = get_error_analyzer()
        self.priority_booster = get_priority_booster()
        self.decision_enhancer = get_decision_enhancer()
        self.diff_analyzer = get_diff_analyzer()
        try:
            self.task_prioritizer = get_task_prioritizer()
        except Exception as e:
            logger.warning("TaskPrioritizer initialization failed, fallback to queue priority only: %s", e)
            self.task_prioritizer = None
        try:
            self.chain_builder = get_chain_builder(llm_client=self.llm_client)
        except Exception as e:
            logger.warning("AttackChainBuilder initialization failed, chain inference disabled: %s", e)
            self.chain_builder = None
        try:
            self.strategy_selector = get_strategy_selector()
        except Exception as e:
            logger.warning("StrategySelector initialization failed, default strategy fallback will be used: %s", e)
            self.strategy_selector = None
        
        # [Phase 5] Attack Planner (KG-based Dynamic Inference)
        self.attack_planner = AttackPlanner(kg=self.graph)

        # Personaの選択
        from src.core.engine.conductor_prompts import CTF_PLANNING_PROMPT, BB_PLANNING_PROMPT
        if self.mode == "CTF":
            self.system_prompt = CTF_PLANNING_PROMPT.format(flag_format=self.flag_format)
        else:
            self.system_prompt = BB_PLANNING_PROMPT

        # StrategyOptimizerの初期化
        from src.core.engine.strategy_optimizer import StrategyOptimizer
        self.optimizer = StrategyOptimizer(llm_client=llm_client, config={"mode": self.mode})

        # Agentic RAG Feedback Loop (Tier 4)
        self.agentic_rag = None
        if self.rag and self.llm_client:
            from src.core.intelligence.agentic_rag import AgenticRAGFeedbackLoop
            self.agentic_rag = AgenticRAGFeedbackLoop(
                rag_client=self.rag,
                llm_client=self.llm_client,
                threshold=getattr(settings, "rag_confidence_threshold", 0.7)
            )

        self.context = ExecutionContext()
        # Phase 1: correlation keys are initialized once and propagated via target_info.
        self.context.target_info.setdefault("correlation", generate_correlation_ids())
        
        # Phase 1.2: DynamicTaskQueue + ContextPropagator 統合
        from src.core.engine.task_queue import DynamicTaskQueue, TaskContext
        from src.core.engine.context_propagator import ContextPropagator
        
        # メモリ制限の設定を反映
        max_mem = getattr(settings, "task_queue_max_memory", 5000)
        self.task_queue = DynamicTaskQueue(max_memory_size=max_mem)
        self.context_propagator = ContextPropagator()
        self.accumulated_context = TaskContext()
        
        # Phase 2.8: Context Designer
        from src.core.engine.context_designer import ContextDesigner
        self.context_designer = ContextDesigner()
        
        # Phase 2.1: Critical Path Analyzer
        from src.core.engine.critical_path_analyzer import CriticalPathAnalyzer
        self.critical_path_analyzer = CriticalPathAnalyzer()
        
        # Phase 2.5: Dynamic Wordlist
        from src.core.wordlist.wordlist_manager import get_wordlist_manager
        self.wordlist_manager = get_wordlist_manager()
        
        self.completed_tasks: list[Task] = []
        self.current_task: Optional[Task] = None
        
        # 再帰深度制限（無限ループ防止）
        self.max_replan_depth = 5
        self._current_replan_depth = 0  # 非推奨: 互換性のため残す。Task.replan_depthを使用
        
        # #4: 派生タスク制御（暴走防止）
        self._derived_task_count = 0
        self._checkpoint_counter = 0  # #9: チェックポイント間隔カウンター
        
        # DebugLogger
        self._debug_enabled = debug_enabled and HAS_DEBUG_LOGGER
        self._debug_logger = get_debug_logger() if self._debug_enabled else None
        
        # Workspace (Phase 0で追加)
        self.workspace: Optional[SharedWorkspace] = None

        # Phase 4: FlagWatcher Initial Setup
        from src.core.engine.flag_watcher import FlagWatcher
        self.flag_watcher = FlagWatcher.get_instance()
        self.flag_watcher.register_pattern(self.flag_format)
        self.flag_watcher.register_callback(self._on_flag_found)

        # Human-in-the-lock コールバック
        self.human_approval_callback = human_approval_callback
        try:
            self.intervention_policy = InterventionPolicy(settings.get_intervention_scenarios())
        except Exception as e:
            logger.warning("Failed to initialize intervention policy. Falling back to defaults: %s", e)
            self.intervention_policy = InterventionPolicy({})

        # LLM クライアント（動的質問生成用）は既に初期化済み

        # Recipe動的注入用：既にロード済みのRecipe名を追跡
        self._loaded_recipes: set[str] = set()

        # Session persistence (クラッシュ回復用)
        self._session_manager = session_manager
        self._current_session = None
        self._recon_executed = False

        # TaskExecutionLog は既に初期化済み

        # 注入済みタスクおよび処理済み技術の重複防止用
        self._injected_task_ids: set[str] = set()
        self._processed_techs: set[str] = set()
        self.pending_hitl: list[dict[str, Any]] = []

        # HITL Service (pending ticket 状態遷移)
        self._hitl_service = HitlService(
            pending_hitl=self.pending_hitl,
            task_queue=self.task_queue,
            extract_scn_number=self._extract_scn_number,
        )

        # Shared Network Client (Connection Pooling)
        from src.core.infra.network_client import AsyncNetworkClient
        from src.core.infra.proxy_manager import get_proxy_manager
        self.network_client = AsyncNetworkClient(
            proxy_manager=get_proxy_manager(),
            mode=self.mode.lower()
        )

        # H-2: 並行アクセス用ロック（タスクキュー・コンテキスト保護）
        self._state_lock = threading.RLock()

        # PhaseGate: フェーズベースのタスク生成制御
        self.phase_gate = get_phase_gate()

        # 5.1 Notification Tool
        from src.tools.custom.notify import NotifyTool
        self.notify_tool = NotifyTool()
        
        # 5.3 SystemResourceManager (Dynamic Resource Scaling)
        from src.core.engine.resource_manager import SystemResourceManager
        from src.core.engine.parallel_orchestrator import ParallelOrchestrator
        
        self.orchestrator = ParallelOrchestrator()
        self.resource_manager = SystemResourceManager.get_instance()
        # Orchestrator を ResourceManager に紐付ける (動的スケール用)
        self.resource_manager.set_orchestrator(self.orchestrator) 
        self.resource_manager.start()

        # 5.2 Graceful Shutdown setup
        import signal
        signal.signal(signal.SIGINT, self._handle_signal_shutdown)
        signal.signal(signal.SIGTERM, self._handle_signal_shutdown)
        self._shutdown_requested = False
        self._react_cache = {}
        self._react_observation_executed_total = 0
        self._react_observation_executed_by_target: dict[str, int] = {}
        self._react_observation_metrics = {
            "attempted": 0,
            "executed": 0,
            "skipped": 0,
            "skip_reasons": {},
        }
        self._react_observation_retry_used = 0
        self._react_observation_cb_failures = 0
        self._react_observation_cb_open_until = 0.0
        self._react_observation_inflight = 0
        self._react_observation_pending_queue = deque()

        # 5.4 Unified Event Loop Management
        self._loop = None
        self._loop_thread = None

        # Phase 1.5: ErrorReplanner
        from src.core.engine.error_replanner import ErrorReplanner
        self.error_replanner = ErrorReplanner(
            rag_client=self.rag,
            llm_client=self.llm_client
        )

        # Phase 6.4: DecisionTracer for MasterConductor Decision Log
        from src.core.models.decision_trace import get_decision_tracer
        from src.core.utils.audit_logger import get_audit_logger
        self.decision_tracer = get_decision_tracer()
        self.audit_logger = get_audit_logger()

        self.context_enriched = False
        self._finished_normally = False
        self._chain_observation_buffer: list[Finding] = []
        self._emitted_attack_chain_keys: set[str] = set()
        self._chain_state_version: int = 0
        self._flaky_trackers: dict[str, FlakyQuarantineTracker] = {}
        self._quarantined_signatures: dict[str, dict[str, Any]] = {}
        self._flaky_success_streaks: dict[str, int] = {}

        # === Tier 2 Phase 4-5: EventBus Wiring ===
        self.event_bus = get_event_bus()
        self.event_bus.subscribe(EventType.SESSION_EXPIRED, self._handle_session_expired)
        self.event_bus.subscribe(EventType.REAUTH_SUCCESS, self._handle_reauth_success)
        self.event_bus.subscribe(EventType.VULN_FOUND, self._handle_vuln_found)
        self.event_bus.subscribe(EventType.VULN_FOUND, self._handle_vuln_found)
        # Start EventBus (Ensure it's running in background)
        # Use shared loop to support synchronous instantiation
        loop = self._get_loop()
        asyncio.run_coroutine_threadsafe(self.event_bus.start(), loop)

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
        """グレースフルシャットダウンの実体 (非同期)"""
        if self._shutdown_requested:
            # 二重呼び出し防止
            return

        self._shutdown_requested = True
        logger.warning("Graceful shutdown initiated...")

        # 0. リソースマネージャーを最初に停止（新規タスク生成防止）
        try:
            if hasattr(self, "resource_manager") and self.resource_manager:
                self.resource_manager.stop()
        except Exception as e:
            logger.error(f"Failed to stop ResourceManager: {e}")

        # 0.1 EventBus を停止（新規イベント発行防止）
        try:
            if hasattr(self, "event_bus") and self.event_bus:
                await self.event_bus.stop()
        except Exception as e:
            logger.error(f"Failed to stop EventBus: {e}")

        # 0.2 NotificationService を停止
        try:
            from src.core.notifications.notification_service import get_notification_service
            service = get_notification_service()
            await service.stop()
        except Exception as e:
            logger.error(f"Failed to stop NotificationService: {e}")

        # 0.3 OOB Listener を停止
        try:
            from src.core.utils.oob_listener import get_oob_listener
            listener = get_oob_listener()
            await listener.stop()
        except Exception as e:
            if hasattr(self, "network_client") and self.network_client:
                await self.network_client.close()
                logger.debug("Closed shared Network Client")
        except Exception as e:
            logger.error(f"Failed to close Network Client: {e}")

        # 0.5 AsyncWriter のクリーンアップ
        try:
            await self.writer.stop()
        except Exception as e:
            logger.error(f"Failed to stop AsyncWriter: {e}")

        # 1. セッション保存
        if not self._finished_normally:
            try:
                from datetime import datetime
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"session_interrupted_{ts}.json"
                await self.async_save_session(filepath=filename)
                logger.info(f"Session state saved to {filename}")
            except Exception as e:
                logger.error(f"Failed to save session during shutdown: {e}")
        else:
            logger.info("Shutdown initiated after normal completion. Skipping interrupted session save.")

        # 2. 通知
        try:
            from src.core.notifications.notifier import get_notifier
            get_notifier().notify("⚠️ **SHIGOKU Interrupted**: Conductor is shutting down.")
        except Exception:
            pass

        # 3. 共有ループの pending タスクを全てキャンセル（LiteLLM 等のサードパーティ製タスク含む）
        try:
            from src.core.utils.async_utils import SharedLoopManager
            loop_manager = SharedLoopManager.get_instance()
            
            # ループから直接タスクをキャンセル
            if loop_manager._loop:
                try:
                    pending = asyncio.all_tasks(loop_manager._loop)
                    for task in pending:
                        task.cancel()
                except Exception:
                    pass
            
            # SharedLoopManager を停止
            loop_manager.stop()
        except Exception as e:
            logger.error(f"Failed to stop SharedLoopManager: {e}")

        print_step("🛑", "MasterConductor shutdown complete.")

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
        aggressive_targets = self.context.target_info.get("aggressive_targets", [])

        max_boost = 3.0
        
        for task in tasks:
            if self._derived_task_count >= max_derived:
                logger.warning(
                    f"Derived task limit ({max_derived}) reached. "
                    f"Skipping {len(tasks) - added_count} tasks from {source}."
                )
                break
            
            # 7.1 IDベースの重複排除 (#9: 重複回避)
            if self.task_queue.get_by_id(task.id) or task.id in self._injected_task_ids:
                logger.debug(f"Task {task.id} ({task.name}) already in queue or processed, skipping.")
                continue

            # P3-1: 高価値トリガーに基づく動的優先度ブースト
            boost_factor, boost_reasons = self._calculate_dynamic_priority_boost(task, max_boost=max_boost)
            if boost_factor > 1.0:
                base_priority = int(getattr(task, "priority", 0) or 0)
                boosted_priority = int(round(base_priority * boost_factor))
                task.priority = max(base_priority, boosted_priority)
                logger.info(
                    "Dynamic priority boost applied: task_id=%s task_name=%s source=%s base=%d factor=%.2f boosted=%d max_boost=%.1f reasons=%s",
                    task.id,
                    task.name,
                    source,
                    base_priority,
                    boost_factor,
                    task.priority,
                    max_boost,
                    ",".join(boost_reasons),
                )

            # N3: Target characteristics -> strategy mapping
            strategy_selector = getattr(self, "strategy_selector", None)
            if strategy_selector is not None:
                try:
                    decision = strategy_selector.select(
                        task=task,
                        target_info=self.context.target_info,
                        mode=self.mode,
                    )

                    if decision.priority_delta:
                        task.priority = max(0, int(task.priority) + int(decision.priority_delta))

                    # Respect explicit task params while still applying defaults from strategy.
                    for k, v in (decision.param_overrides or {}).items():
                        task.params.setdefault(k, v)

                    existing_tags = set(getattr(task, "tags", []) or [])
                    for tag in (decision.tag_hints or []):
                        if tag not in existing_tags:
                            task.tags.append(tag)

                    task.params["_strategy"] = {
                        "id": decision.strategy_id,
                        "confidence": decision.confidence,
                        "rationale": decision.rationale,
                    }

                    if not decision.is_default:
                        logger.info(
                            "Strategy selected: task_id=%s strategy=%s confidence=%.2f priority=%s source=%s",
                            task.id,
                            decision.strategy_id,
                            decision.confidence,
                            task.priority,
                            source,
                        )
                except Exception as e:
                    logger.debug("StrategySelector failed for task %s: %s", task.id, e)

            # HITL運用時は、人手承認が必要なタスクを先に評価してチケット化しやすくする。
            try:
                gate_mode = self._normalize_intervention_gate_mode()
                if gate_mode in {"enforce_hitl", "enforce_human_preferred"}:
                    intervention_decision = self._get_intervention_decision(task)
                    if self._requires_intervention_approval(intervention_decision, gate_mode):
                        route = str(intervention_decision.get("route", "") or "")
                        current_priority = int(getattr(task, "priority", 0) or 0)
                        priority_floor = 1200 if route == "human_preferred" else 1000
                        if current_priority < priority_floor:
                            task.priority = priority_floor
                            logger.info(
                                "Intervention priority boost applied: task_id=%s route=%s gate_mode=%s base=%d boosted=%d",
                                task.id,
                                route or "unknown",
                                gate_mode,
                                current_priority,
                                task.priority,
                            )
            except Exception as e:
                logger.debug("Intervention priority boost skipped for task %s: %s", task.id, e)

            # Intelligence: PriorityBooster に登録
            # base_priority は 0-1.0 に正規化 (Task.priority を 0-100 と想定)
            if hasattr(self, "priority_booster"):
                norm_priority = max(0.01, min(task.priority / 100.0, 1.0))
                self.priority_booster.register_task(task.id, base_priority=norm_priority)

            # 5.1 is_aggressive の自動継承
            target = task.params.get("target", "")
            if target and target in aggressive_targets:
                task.params["is_aggressive"] = True
                logger.debug(f"Inherited is_aggressive=True for task: {task.name}")
            
            self.task_queue.add(task)
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
                self._inject_matching_recipes(new_techs=unprocessed)
                for t in unprocessed:
                    self._processed_techs.add(t)
    
    def _inject_matching_recipes(self, new_techs: list[str] = None) -> None:
        """
        tech_stackおよび検出されたアセットにマッチするRecipeをSwarm経由で実行するタスクを注入
        """
        import hashlib
        tasks_to_add = []
        
        tech_stack = new_techs if new_techs is not None else self.context.target_info.get("tech_stack", [])
        discovered_urls = self.context.target_info.get("discovered_urls", [])
        target_url = self.context.target_info.get("target", "")
        
        def gen_task_id(prefix: str, salt: str = "") -> str:
            """内容に基づいた決定論的なタスクIDを生成"""
            content = f"{prefix}:{target_url}:{salt}"
            return f"{prefix}_{hashlib.md5(content.encode()).hexdigest()[:8]}"

        # ====== Phase 6.1.2: 認証ページ検出 → AuthNinja 召喚 ======
        auth_patterns = ["login", "signin", "auth", "session", "oauth", "sso", "password"]
        auth_urls = []
        for url in discovered_urls:
            url_lower = url.lower()
            if any(pattern in url_lower for pattern in auth_patterns):
                auth_urls.append(url)
        
        if auth_urls:
            task_id = gen_task_id("auth_ninja", f"len:{len(auth_urls)}")
            auth_task = Task(
                id=task_id,
                name=f"AuthNinja: Login/Auth endpoints detected ({len(auth_urls)} URLs)",
                agent_type="swarm",
                action="auth_attack",
                params={
                    "target": target_url,
                    "auth_urls": auth_urls[:10],
                    "tags": ["auth_bypass", "brute_force", "session_hijack"],
                },
                priority=150,
            )
            tasks_to_add.append(auth_task)
            
            # Phase 6.4: 意思決定記録
            from src.core.models.decision_trace import DecisionType
            self.decision_tracer.trace(
                decision_type=DecisionType.VULN_HUNTER_DISPATCH,
                input_context={"auth_urls": auth_urls[:5]},
                selected_option="AuthNinja",
                reasoning=f"Detected auth endpoints: {auth_urls[:2]}...",
                related_task_id=auth_task.id,
                related_target=target_url,
            )
        
        # ====== フォームパラメータ検出 → SQLi Hunter 召喚 ======
        all_params = list(set(self.context.target_info.get("form_params", []) + self.context.target_info.get("query_params", [])))
        if all_params:
            sqli_task = Task(
                id=gen_task_id("sqli_hunter", f"params:{len(all_params)}"),
                name=f"SQLi Hunter: {len(all_params)} parameters detected",
                agent_type="swarm",
                action="sqli_scan",
                params={
                    "target": target_url,
                    "params": all_params[:20],
                    "tags": ["sqli_union", "sqli_blind", "sqli_error"],
                },
                priority=140,
            )
            tasks_to_add.append(sqli_task)
        
        # ====== JavaScript検出 → DOM XSS Hunter 召喚 ======
        js_files = self.context.target_info.get("js_files", [])
        if any("javascript" in str(t).lower() for t in tech_stack) or js_files:
            xss_task = Task(
                id=gen_task_id("dom_xss", f"js:{len(js_files)}"),
                name=f"DOM XSS Hunter: JavaScript analysis",
                agent_type="swarm",
                action="xss_scan",
                params={
                    "target": target_url,
                    "js_files": js_files[:10],
                    "tags": ["dom_xss", "reflected_xss", "stored_xss"],
                },
                priority=130,
            )
            tasks_to_add.append(xss_task)
        
        # ====== テックスタックベースのタスク生成 ======
        if tech_stack:
            for tech in tech_stack:
                tech_lower = tech.lower()
                tag = None
                if "jwt" in tech_lower: tag = "jwt_token"
                elif "oauth" in tech_lower: tag = "oauth_flow"
                elif any(x in tech_lower for x in ["graphql", "rest", "api"]): tag = "api_endpoint"
                
                if tag:
                    tasks_to_add.append(Task(
                        id=gen_task_id("tech_swarm", tech_lower),
                        name=f"Swarm attack for {tech}",
                        agent_type="swarm",
                        action="scan",
                        params={"target": target_url, "tags": [tag], "tech_stack": [tech]},
                        priority=100,
                    ))
        
        if tasks_to_add:
            self._add_tasks(tasks_to_add, source="dynamic_recipe")
    
    def generate_dynamic_questions(self, mode: str) -> list[str]:
        """
        LLMを使用して動的に追加質問を生成（ハイブリッド方式）
        
        固定質問で収集した情報を分析し、不足があれば追加質問を生成。
        LLMが利用できない場合は空リストを返す。
        
        Args:
            mode: 動作モード
        
        Returns:
            追加質問のリスト（0-2個）
        """
        if not self.llm_client:
            logger.debug("LLM client not available, skipping dynamic questions")
            return []
        
        try:
            from src.core.conductor.conductor_prompts import get_dynamic_question_prompt
            
            prompt = get_dynamic_question_prompt(mode, self.context.target_info)
            
            # LLM呼び出し
            llm_model = (
                getattr(settings, "model_lightweight", None)
                or getattr(settings, "model", None)
                or getattr(settings, "model_output", None)
                or "ollama/qwen3.5:latest"
            )
            response = self.llm_client.chat.completions.create(
                model=llm_model,  # コスト効率の良いモデル
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=500,
            )
            
            content = response.choices[0].message.content
            
            # JSONパース
            import re
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                questions = result.get("questions", [])
                if questions:
                    logger.info(f"Generated {len(questions)} dynamic questions")
                return questions[:2]  # 最大2問
            
            return []
            
        except Exception as e:
            logger.warning(f"Dynamic question generation failed: {e}")
            return []
    
    def _normalize_intervention_gate_mode(self) -> str:
        mode = str(getattr(settings, "intervention_gate_mode", "observe") or "observe").strip().lower()
        if mode not in {"observe", "enforce_human_preferred", "enforce_hitl"}:
            return "observe"
        return mode

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
        strategy = str(probe.get("strategy", "") or "").strip().lower()
        qps = float(probe.get("qps", 0) or 0)

        allow = {str(v).strip().lower() for v in (policy.get("allow") or []) if str(v).strip()}
        deny = {str(v).strip().lower() for v in (policy.get("deny") or []) if str(v).strip()}
        per_asset_qps_cap = float(policy.get("per_asset_qps_cap", 0) or 0)

        if strategy in deny:
            return {"allowed": False, "reason": "strategy_denied"}
        if allow and strategy not in allow:
            return {"allowed": False, "reason": "strategy_not_allowed"}
        if per_asset_qps_cap > 0 and qps > per_asset_qps_cap:
            return {"allowed": False, "reason": "qps_cap_exceeded"}
        return {"allowed": True, "reason": "allowed"}

    def _rank_missing_link_targets_by_information_gain(
        self,
        candidates: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        ranked: list[dict[str, Any]] = []
        for candidate in candidates:
            item = dict(candidate)
            missing_links = item.get("missing_links", [])
            evidence = item.get("evidence", {})
            if not isinstance(missing_links, list):
                missing_links = []
            if not isinstance(evidence, dict):
                evidence = {}
            evidence_gain = sum(1 for value in evidence.values() if bool(value))
            information_gain = (len(missing_links) * 2) + evidence_gain
            item["max_information_gain"] = information_gain
            ranked.append(item)
        return sorted(ranked, key=lambda item: item.get("max_information_gain", 0), reverse=True)

    def _resolve_active_probe_policy_for_program(
        self,
        runtime_policy: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        target_info = getattr(getattr(self, "context", None), "target_info", {}) or {}
        program_policy = (
            target_info.get("program_probe_policy", {})
            if isinstance(target_info, dict)
            else {}
        )
        if isinstance(program_policy, dict) and program_policy:
            return self._sanitize_active_probe_policy(
                program_policy,
                source="program_override",
                include_source=runtime_policy is not None,
            )
        if isinstance(runtime_policy, dict) and runtime_policy:
            return self._sanitize_active_probe_policy(
                runtime_policy,
                source="runtime_flag",
                include_source=True,
            )
        resolved = self._resolve_active_probe_policy()
        return self._sanitize_active_probe_policy(
            resolved,
            source="config_default",
            include_source=True,
        )

    def _sanitize_active_probe_policy(
        self,
        raw_policy: Optional[dict[str, Any]],
        *,
        source: str,
        include_source: bool,
    ) -> dict[str, Any]:
        policy = raw_policy if isinstance(raw_policy, dict) else {}
        allowed_keys = {
            "allow",
            "deny",
            "per_asset_qps_cap",
            "global_probe_budget",
        }
        ignored_keys = sorted(str(key) for key in policy.keys() if key not in allowed_keys and key != "source")
        result = {
            "allow": [str(v) for v in (policy.get("allow") or []) if str(v).strip()],
            "deny": [str(v) for v in (policy.get("deny") or []) if str(v).strip()],
            "per_asset_qps_cap": int(policy.get("per_asset_qps_cap", 0) or 0),
        }
        if "global_probe_budget" in policy:
            result["global_probe_budget"] = int(policy.get("global_probe_budget", 0) or 0)
        if include_source:
            result["source"] = source
        if ignored_keys:
            result["ignored_keys"] = ignored_keys
        return result

    def _normalize_workflow_template(self, raw_template: Optional[dict[str, Any]]) -> dict[str, Any]:
        template = raw_template if isinstance(raw_template, dict) else {}
        return {
            "template_id": str(template.get("template_id", "") or ""),
            "steps": [str(step) for step in (template.get("steps") or []) if str(step).strip()],
            "source": str(template.get("source", "") or ""),
        }

    def build_probe_runtime_context_from_chain_finding(
        self,
        finding_info: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        info = finding_info if isinstance(finding_info, dict) else {}
        raw_policy = info.get("resolved_tactical_policy", {})
        source = (
            str(raw_policy.get("source", "runtime_flag") or "runtime_flag")
            if isinstance(raw_policy, dict)
            else "runtime_flag"
        )
        return {
            "runtime_policy": self._sanitize_active_probe_policy(
                raw_policy,
                source=source,
                include_source=True,
            ),
            "workflow_template": self._normalize_workflow_template(
                info.get("resolved_workflow_template", {})
            ),
        }

    def assess_missing_link_probe_rollout(
        self,
        *,
        baseline_metrics: dict[str, Any],
        current_metrics: dict[str, Any],
        thresholds: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        thresholds = thresholds if isinstance(thresholds, dict) else {}
        baseline_ratio = float(baseline_metrics.get("blocked_defer_ratio", 0.0) or 0.0)
        current_ratio = float(current_metrics.get("blocked_defer_ratio", 0.0) or 0.0)
        baseline_tasks = int(baseline_metrics.get("planned_task_count", 0) or 0)
        current_tasks = int(current_metrics.get("planned_task_count", 0) or 0)
        baseline_qps_hits = int(baseline_metrics.get("qps_cap_hits", 0) or 0)
        current_qps_hits = int(current_metrics.get("qps_cap_hits", 0) or 0)

        ratio_threshold = float(thresholds.get("blocked_defer_ratio_delta", 0.0) or 0.0)
        task_threshold = int(thresholds.get("planned_task_delta", 0) or 0)
        qps_threshold = int(thresholds.get("qps_cap_hit_delta", 0) or 0)

        reasons: list[str] = []
        if (current_ratio - baseline_ratio) > ratio_threshold:
            reasons.append("blocked_defer_ratio_exceeded")
        if (current_tasks - baseline_tasks) > task_threshold:
            reasons.append("planned_task_delta_exceeded")
        if (current_qps_hits - baseline_qps_hits) > qps_threshold:
            reasons.append("qps_cap_hit_delta_exceeded")

        return {
            "workflow_template_mode": "read_only" if reasons else "enabled",
            "reasons": reasons,
            "baseline_metrics": {
                "blocked_defer_ratio": baseline_ratio,
                "planned_task_count": baseline_tasks,
                "qps_cap_hits": baseline_qps_hits,
            },
            "current_metrics": {
                "blocked_defer_ratio": current_ratio,
                "planned_task_count": current_tasks,
                "qps_cap_hits": current_qps_hits,
            },
        }

    def evaluate_active_probe_runtime_guard(
        self,
        outcomes: list[dict[str, Any]],
        dependency_error: bool = False,
    ) -> dict[str, Any]:
        if dependency_error:
            return {"state": "defer", "reason": "external_dependency_failure"}

        blocked_signals = 0
        for outcome in outcomes:
            if not isinstance(outcome, dict):
                continue
            status_code = int(outcome.get("status_code", 0) or 0)
            waf_detected = bool(outcome.get("waf_detected", False))
            if waf_detected or status_code == 403 or status_code >= 500:
                blocked_signals += 1

        if blocked_signals > 0:
            return {"state": "blocked", "reason": "waf_or_5xx_threshold"}
        return {"state": "continue", "reason": "allowed"}

    def build_race_profile(self, mode: str = "interval") -> dict[str, Any]:
        normalized = str(mode or "interval").strip().lower()
        profiles = {
            "burst": {"mode": "burst", "burst": 3, "interval_ms": 0, "order_permutations": 2},
            "interval": {"mode": "interval", "burst": 1, "interval_ms": 250, "order_permutations": 1},
            "ordered": {"mode": "ordered", "burst": 1, "interval_ms": 100, "order_permutations": 3},
        }
        return dict(profiles.get(normalized, profiles["interval"]))

    def build_safe_probe_variations(
        self,
        waf_name: Optional[str],
        *,
        dry_run: bool,
        allowlist: list[str],
        fail_closed: bool,
    ) -> list[dict[str, Any]]:
        normalized_allowlist = [str(item).strip().lower() for item in allowlist if str(item).strip()]
        if fail_closed and not normalized_allowlist:
            return []

        bypasser = WAFBypasser()
        mutation_types = bypasser.choose_mutation_types(waf_name)
        headers = bypasser.build_bypass_headers(waf_name, attempt=0)

        variations: list[dict[str, Any]] = []
        for mutation_type in mutation_types:
            mutation_name = getattr(mutation_type, "value", str(mutation_type)).strip().lower()
            if normalized_allowlist and mutation_name not in normalized_allowlist:
                continue
            variations.append(
                {
                    "mutation_type": mutation_name,
                    "headers": dict(headers),
                    "dry_run": bool(dry_run),
                }
            )
        return variations

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
        details = {
            "audit_event_id": audit_event_id,
            "decision_id": decision_trace.decision_id,
            "chain_key": str(chain.get("chain_key", "") or ""),
            "rule_id": str(chain.get("rule_id", "") or ""),
            "scope_basis": str(audit_context.get("scope_basis", "") or ""),
            "input_fingerprint": str(audit_context.get("input_fingerprint", "") or ""),
            "override": bool(audit_context.get("override", False)),
            "stop_reason": str(audit_context.get("stop_reason", "") or ""),
            "excluded_reasons": list(chain.get("excluded_reasons", []) or []),
            "reason_code": str(
                chain.get("reason_code")
                or audit_context.get("stop_reason")
                or next(iter(list(chain.get("excluded_reasons", []) or [])), "")
            ).strip(),
            "finding_id": str(chain.get("finding_id", "") or ""),
            "previous_state": str(chain.get("previous_state", "") or ""),
            "session_generation": chain.get("session_generation"),
            "token_epoch": chain.get("token_epoch"),
            "csrf_epoch": chain.get("csrf_epoch"),
            "final_state": str(chain.get("state", "") or "unknown"),
        }
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
        normalized_mode = str(failure_mode or "").strip().lower()
        normalized_policy = {
            str(key).strip().lower(): str(value).strip().lower()
            for key, value in dict(policy or {}).items()
            if str(key).strip()
        }
        state = normalized_policy.get(normalized_mode, "blocked")
        if state not in {"blocked", "defer", "continue"}:
            state = "blocked"
        return {
            "state": state,
            "reason": normalized_mode,
        }

    def _build_degradation_component_contract(self) -> dict[str, dict[str, str]]:
        return {
            "program_memory": {
                "allowed_fallback": "in_memory_only",
                "forbidden_transition": "submit_without_memory_consistency",
                "recovery_precondition": "memory_backend_restored",
                "ttl": "15m",
                "rollback_trigger": "ttl_expired",
            },
            "audit_logger": {
                "allowed_fallback": "buffered_events",
                "forbidden_transition": "drop_audit_events",
                "recovery_precondition": "audit_pipeline_restored",
                "ttl": "10m",
                "rollback_trigger": "buffer_flush_failed",
            },
            "report_adapter": {
                "allowed_fallback": "canonical_payload_only",
                "forbidden_transition": "platform_submit_while_degraded",
                "recovery_precondition": "adapter_health_restored",
                "ttl": "30m",
                "rollback_trigger": "submit_path_unavailable",
            },
        }

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
        details = {
            "audit_event_id": audit_event_id,
            "decision_id": decision_trace.decision_id,
            "correlation_id": str(audit_context.get("correlation_id", "") or ""),
            "policy_version": str(audit_context.get("policy_version", "") or ""),
            "component_status": normalized_status,
            "degraded_components": list(degradation_result.get("degraded_components", []) or []),
            "fallbacks": dict(degradation_result.get("fallbacks", {}) or {}),
            "reason": str(degradation_result.get("reason", "") or ""),
            "recovery_actions": dict(degradation_result.get("recovery_actions", {}) or {}),
            "submit_blocked": bool(degradation_result.get("submit_blocked", False)),
            "replay_verdict": str(degradation_result.get("replay_verdict", "") or ""),
        }
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
        normalized_status = {
            str(component).strip(): str(status).strip().lower()
            for component, status in dict(component_status or {}).items()
            if str(component).strip()
        }
        component_contract = self._build_degradation_component_contract()
        degraded_markers = {"degraded", "dependency_failure", "ttl_expired", "manual_rollback"}
        blocked_markers = {"scope_violation", "waf_repeat", "blocked"}
        defer_markers = {"dependency_failure", "ttl_expired", "manual_rollback", "defer"}
        degraded_components = [
            component
            for component, status in normalized_status.items()
            if status in degraded_markers or component == "report_adapter" and status == "degraded"
        ]
        fallbacks = {
            component: component_contract.get(component, {}).get("allowed_fallback", "best_effort")
            for component in degraded_components
        }

        reason = "nominal"
        state = "continue"
        no_go_conditions: list[str] = []
        if any(status in blocked_markers for status in normalized_status.values()):
            state = "blocked"
            reason = next(status for status in normalized_status.values() if status in blocked_markers)
            no_go_conditions.append(reason)
        elif any(status in defer_markers for status in normalized_status.values()):
            state = "defer"
            reason = next(status for status in normalized_status.values() if status in defer_markers)
        elif normalized_status.get("report_adapter") == "degraded":
            reason = "report_adapter_degraded"

        submit_blocked = state in {"blocked", "defer"} or normalized_status.get("report_adapter") == "degraded"
        replay_verdict = "not_required"
        if state == "blocked":
            replay_verdict = "not_allowed"
        elif submit_blocked:
            replay_verdict = "required"

        recovery_actions: dict[str, str] = {}
        for component in degraded_components:
            if component == "program_memory":
                recovery_actions[component] = (
                    "rollback_to_last_consistent_snapshot"
                    if normalized_status.get(component) == "ttl_expired"
                    else "restore_memory_backend"
                )
            elif component == "audit_logger":
                recovery_actions[component] = "restore_audit_pipeline"
            elif component == "report_adapter":
                recovery_actions[component] = "replay_canonical_payload"
            else:
                recovery_actions[component] = "best_effort_recovery"

        contract_view = {
            component: {
                "allowed_fallback": component_contract.get(component, {}).get("allowed_fallback", "best_effort"),
                "forbidden_transition": component_contract.get(component, {}).get(
                    "forbidden_transition", "unknown_transition"
                ),
                "recovery_precondition": component_contract.get(component, {}).get(
                    "recovery_precondition", "manual_verification_required"
                ),
                "ttl": component_contract.get(component, {}).get("ttl", "inherit_default"),
                "rollback_trigger": component_contract.get(component, {}).get(
                    "rollback_trigger", "manual_review"
                ),
            }
            for component in normalized_status.keys()
        }

        return {
            "state": state,
            "reason": reason,
            "degraded_components": degraded_components,
            "fallbacks": fallbacks,
            "component_contract": contract_view,
            "submit_blocked": submit_blocked,
            "replay_verdict": replay_verdict,
            "recovery_actions": recovery_actions,
            "no_go_conditions": no_go_conditions,
            "policy_version": "phase2_degrade_v1",
        }

    def run_pre_action_gate_shadow(
        self,
        findings: list[Finding],
        *,
        benchmark_manifest: Optional[dict[str, Any]] = None,
        runtime_context: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        if not bool(getattr(settings, "chain_llm_shadow_mode", True)):
            return {
                "state": "skipped",
                "reason": "shadow_mode_disabled",
            }

        chain_builder = getattr(self, "chain_builder", None)
        if chain_builder is None or not hasattr(chain_builder, "analyze_hybrid"):
            return {
                "state": "skipped",
                "reason": "chain_builder_unavailable",
            }

        trigger_action = self.trigger_chain_evaluation("pre_action_gate")
        result = chain_builder.analyze_hybrid(findings, runtime_context)
        proposal_engine = getattr(chain_builder, "proposal_engine", None)
        diagnostics = {}
        if proposal_engine is not None and hasattr(proposal_engine, "get_diagnostics"):
            try:
                diagnostics = dict(proposal_engine.get_diagnostics() or {})
            except (TypeError, ValueError):
                diagnostics = {}
        report = {
            "trigger_action": trigger_action,
            "benchmark_manifest_id": str((benchmark_manifest or {}).get("manifest_id", "")).strip(),
            "heuristic_chain_count": len(result.get("heuristic_chains", [])),
            "draft_candidate_count": len(result.get("draft_candidates", [])),
            "ai_candidate_count": len(result.get("ai_candidates", [])),
            "proposal_skip_reason": result.get("proposal_skip_reason"),
            **diagnostics,
        }
        draft_candidates = list(result.get("draft_candidates", []) or [])
        blocked_candidates = [
            candidate
            for candidate in draft_candidates
            if str(
                ((candidate.get("decision_trace", {}) or {}).get("feasibility", {}) or {}).get("verdict", "")
            ).strip().lower()
            == "blocked"
        ]
        report["feasibility_mode"] = str((runtime_context or {}).get("feasibility_mode", (runtime_context or {}).get("mode", "enforce"))).strip().lower() or "enforce"
        report["shadow_blocked_count"] = len(blocked_candidates)
        report["shadow_diff_count"] = len(
            [
                candidate
                for candidate in blocked_candidates
                if str(candidate.get("state", "")).strip().lower() == "draft"
            ]
        )
        report["shadow_diff_reasons"] = sorted(
            {
                reason
                for candidate in blocked_candidates
                for reason in list(candidate.get("excluded_reasons", []) or [])
                if str(reason).strip()
            }
        )
        temporal_candidates = [
            candidate
            for candidate in draft_candidates
            if any(
                str(reason).strip().lower().startswith("temporal:")
                for reason in list(candidate.get("excluded_reasons", []) or [])
            )
        ]
        temporal_reason_counts: dict[str, int] = {}
        draft_demotion_count = 0
        blocked_demotion_count = 0
        metadata_missing_count = 0
        for candidate in temporal_candidates:
            candidate_state = str(candidate.get("state", "")).strip().lower()
            if candidate_state == "draft":
                draft_demotion_count += 1
            elif candidate_state == "blocked":
                blocked_demotion_count += 1
            for reason in list(candidate.get("excluded_reasons", []) or []):
                normalized_reason = str(reason).strip().lower()
                if not normalized_reason.startswith("temporal:"):
                    continue
                temporal_reason_counts[normalized_reason] = temporal_reason_counts.get(normalized_reason, 0) + 1
                if normalized_reason == "temporal:metadata_missing":
                    metadata_missing_count += 1
        threshold = float((runtime_context or {}).get("missing_temporal_metadata_threshold", 1.0) or 1.0)
        temporal_count = len(temporal_candidates)
        metadata_ratio = (metadata_missing_count / temporal_count) if temporal_count else 0.0
        report["draft_demotion_count"] = draft_demotion_count
        report["blocked_demotion_count"] = blocked_demotion_count
        report["temporal_reason_counts"] = dict(sorted(temporal_reason_counts.items()))
        report["missing_temporal_metadata_ratio"] = metadata_ratio
        report["missing_temporal_metadata_threshold_exceeded"] = temporal_count > 0 and metadata_ratio > threshold
        ledger = getattr(self, "_chain_shadow_reports", None)
        if not isinstance(ledger, list):
            ledger = []
            setattr(self, "_chain_shadow_reports", ledger)
        ledger.append(report)
        return report

    def _resolve_active_probe_policy(self) -> dict[str, Any]:
        allow_raw = str(getattr(settings, "active_probe_strategy_allowlist", "") or "")
        deny_raw = str(getattr(settings, "active_probe_strategy_denylist", "") or "")
        allow = [v.strip().lower() for v in allow_raw.split(",") if v.strip()]
        deny = [v.strip().lower() for v in deny_raw.split(",") if v.strip()]
        qps_cap = int(getattr(settings, "active_probe_per_asset_qps_cap", 5) or 5)
        return {
            "allow": allow,
            "deny": deny,
            "per_asset_qps_cap": qps_cap,
            "global_probe_budget": int(getattr(settings, "active_probe_global_budget", 0) or 0),
        }

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
                {
                    "required": True,
                    "approved": True,
                    "mode": "hitl_resume",
                    "status": "approved",
                },
            )
            params["_intervention"] = intervention_meta
            task.params = params
            return None

        decision = self._get_intervention_decision(task)
        gate_mode = self._normalize_intervention_gate_mode()
        self._annotate_task_intervention_decision(task, decision, gate_mode)
        self._notify_scn07_12_intervention(task, decision, gate_mode)
        defer_manual_v1 = bool(getattr(settings, "defer_scn07_12_hitl_v1", True))
        if defer_manual_v1 and self._is_manual_defer_target_v1(decision):
            task.params.setdefault("_intervention", {})
            task.params["_intervention"]["approval"] = {
                "required": True,
                "approved": False,
                "mode": gate_mode,
                "status": "deferred_manual_v1",
            }
            task.state = TaskState.SKIPPED
            task.error = (
                f"Deferred for manual validation in Ver.1 (scenario={decision.get('scenario_id', 'default_route')}, "
                f"route={decision.get('route', 'shigoku_only')}, gate_mode={gate_mode})"
            )
            self._record_failure_context(task, "precheck", "intervention_gate_deferred_manual_v1")
            return {
                "success": True,
                "skipped": True,
                "pending_hitl": False,
                "manual_deferred": True,
                "message": task.error,
                "intervention": {
                    "decision": decision,
                    "gate_mode": gate_mode,
                    "approved": False,
                    "pending_hitl": False,
                    "manual_deferred": True,
                },
            }

        if not self._requires_intervention_approval(decision, gate_mode):
            return None

        route = str(decision.get("route", "shigoku_only") or "shigoku_only").strip().lower()
        has_callback = bool(getattr(self, "human_approval_callback", None))
        approved: Optional[bool] = None
        if has_callback:
            hitl_info = self._build_intervention_hitl_info(task, decision, gate_mode)
            approved = self.request_human_approval(hitl_info)
        else:
            logger.info(
                "Intervention gate marked task %s as pending HITL (route=%s, scenario=%s)",
                task.id,
                route,
                decision.get("scenario_id", "default_route"),
            )

        task.params.setdefault("_intervention", {})
        task.params["_intervention"]["approval"] = {
            "required": True,
            "approved": bool(approved) if approved is not None else False,
            "mode": gate_mode,
        }

        if approved is True:
            task.params["_intervention"]["approval"]["status"] = "approved"
            return None

        if approved is None:
            ticket_id = self._register_pending_hitl_ticket(task, decision, gate_mode)
            pending_message = (
                f"Pending HITL approval (ticket={ticket_id}, mode={gate_mode}, route={route}, "
                f"scenario={decision.get('scenario_id', 'default_route')})"
            )
            task.params["_intervention"]["approval"]["status"] = "pending"
            task.params["_intervention"]["approval"]["ticket_id"] = ticket_id
            lock_obj = getattr(self, "_state_lock", None)
            lock_ctx = lock_obj if lock_obj is not None else nullcontext()
            with lock_ctx:
                task.state = TaskState.SKIPPED
                task.error = pending_message
                self._record_failure_context(task, "precheck", "intervention_gate_pending_hitl")

                if exec_record is not None:
                    exec_record.mark_completed(
                        success=True,
                        summary=pending_message,
                        metadata={
                            "intervention": {
                                "decision": decision,
                                "gate_mode": gate_mode,
                                "approved": False,
                                "pending_hitl": True,
                                "ticket_id": ticket_id,
                            }
                        },
                    )
                    if getattr(self, "execution_log", None) is not None:
                        self.execution_log.add_record(exec_record)

            return {
                "success": True,
                "skipped": True,
                "pending_hitl": True,
                "hitl_ticket_id": ticket_id,
                "message": pending_message,
                "intervention": {
                    "decision": decision,
                    "gate_mode": gate_mode,
                    "approved": False,
                    "pending_hitl": True,
                    "ticket_id": ticket_id,
                },
            }

        if approved:
            return None

        task.params["_intervention"]["approval"]["status"] = "rejected"
        denial_error = (
            f"Blocked by intervention gate (mode={gate_mode}, route={route}, "
            f"scenario={decision.get('scenario_id', 'default_route')})"
        )
        lock_obj = getattr(self, "_state_lock", None)
        lock_ctx = lock_obj if lock_obj is not None else nullcontext()
        with lock_ctx:
            task.state = TaskState.SKIPPED
            task.error = denial_error
            self._record_failure_context(task, "precheck", "intervention_gate_denied")

            if exec_record is not None:
                exec_record.mark_completed(
                    success=False,
                    error=denial_error,
                    metadata={
                        "intervention": {
                            "decision": decision,
                            "gate_mode": gate_mode,
                            "approved": False,
                        }
                    },
                )
                if getattr(self, "execution_log", None) is not None:
                    self.execution_log.add_record(exec_record)

        return {
            "success": False,
            "skipped": True,
            "error": denial_error,
            "intervention": {
                "decision": decision,
                "gate_mode": gate_mode,
                "approved": False,
            },
        }

    def _is_scn07_to_12(self, decision: dict[str, Any]) -> bool:
        scenario_id = str(decision.get("scenario_id", "") or "").strip().lower().replace("-", "_")
        if not scenario_id.startswith("scn_"):
            return False
        number = self._extract_scn_number(scenario_id)
        return 7 <= number <= 12

    def _is_manual_defer_target_v1(self, decision: dict[str, Any]) -> bool:
        """Ver.1 manual defer policy: keep SCN11 executable for autonomous chain probing."""
        scenario_id = str(decision.get("scenario_id", "") or "").strip().lower().replace("-", "_")
        if not scenario_id.startswith("scn_"):
            return False
        number = self._extract_scn_number(scenario_id)
        return number in {7, 8, 9, 10, 12}

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

        reasons = decision.get("reasons", [])
        if not isinstance(reasons, list):
            reasons = [str(reasons)]
        matched = decision.get("matched_signals", [])
        if not isinstance(matched, list):
            matched = [str(matched)]

        scenario_titles = {
            7: "Token Trust Boundary",
            8: "Out-of-Band External Channel",
            9: "Multi-step State Machine",
            10: "Semantic Business Logic",
            11: "Multi-Vector Chain",
            12: "Advanced SSRF Internal Topology",
        }
        suspected = scenario_titles.get(number, "Manual Review Scenario")
        route = str(decision.get("route", "shigoku_only") or "shigoku_only")
        confidence = str(decision.get("confidence", 0.0))
        reason_text = " | ".join(str(x) for x in reasons[:4]) if reasons else "-"
        matched_text = " | ".join(str(x) for x in matched[:6]) if matched else "-"

        message_lines = [
            f"🔔 SCN{number:02d} Manual Validation Candidate",
            f"- Scenario: {suspected} ({scenario_id})",
            f"- Target(s): {target_summary}",
            f"- Task: {str(getattr(task, 'name', '') or '-')}",
            f"- Route/Gate: {route} / {str(gate_mode or 'observe')}",
            f"- Confidence: {confidence}",
            f"- Suspected Signals: {matched_text}",
            f"- Why Flagged: {reason_text}",
            "- Required Action: Manually validate this scenario and record outcome (verified / not reproducible / needs more evidence).",
        ]
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

    def plan(self, goal: str, target: Optional[str] = None) -> list[Task]:
        """
            実行可能なタスクのリスト
        """
        # [Phase 3.2] Pending Fuzzing Trigger
        if target == "pending_fuzz":
            logger.info("Triggering Pending Fuzzing Tasks...")
            try:
                from src.core.infra.knowledge_graph import KnowledgeGraph
                kg = KnowledgeGraph()
                pending_urls = kg.get_pending_tasks(category="fuzzing")
                scope_hosts = self._resolve_in_scope_hosts()
                if not scope_hosts:
                    logger.warning("Pending fuzzing skipped: unable to resolve in-scope hosts from context.")
                    return []
                
                tasks = []
                out_of_scope_count = 0
                for raw_url in pending_urls:
                    url = self._normalize_url_candidate(str(raw_url or "").strip())
                    if not url:
                        continue
                    if not self._is_target_url_in_scope(url, scope_hosts):
                        out_of_scope_count += 1
                        logger.debug("[MC] Skip out-of-scope pending fuzz URL: %s", url)
                        continue
                    task_id = f"fuzz-{hash(url)}"
                    tasks.append(Task(
                        id=task_id,
                        name=f"Fuzzing: {url}",
                        agent_type="fuzzing",
                        action="execute",
                        priority=10, 
                        target=url,
                        params={
                            "target": url,
                            "tags": ["force_fuzz", "api_endpoint"]
                        }
                    ))
                if out_of_scope_count > 0:
                    logger.info(
                        "[MC] Pending fuzz scope filter removed %d out-of-scope URL(s).",
                        out_of_scope_count,
                    )
                
                if not tasks:
                    logger.warning("No pending fuzzing tasks found.")
                    return []
                
                # 自分自身のキューに追加しておく必要がある（InteractiveBridgeなど外から参照される場合のため）
                self._add_tasks(tasks, source="pending_fuzz")
                return tasks

            except Exception as e:
                logger.error(f"Failed to load pending tasks: {e}")
                return []

        # Phase 3: LLM動的プランニング
        if settings.use_llm_planning and self.llm_client:
            logger.info("Attempting dynamic planning with LLM...")
            llm_tasks = self._plan_with_llm(goal, target)
            if llm_tasks:
                self.task_queue.clear()
                self.task_queue.add_batch(llm_tasks, source="llm_plan")
                return llm_tasks
            logger.warning("LLM planning returned no tasks, falling back to static plan")

        tasks = []
        
        # Goal から標準的なタスクシーケンスを生成 (Static Fallback)
        
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
                recon_start_step,
                recon_end_step,
            )
            recon_start_step = 1
            recon_end_step = 8
        
        # Phase 1: Scope確認
        tasks.append(Task(
            id="task_001",
            name="Scope Verification",
            agent_type="scope_parser",
            action="verify_scope",
            params={"target": target},
            priority=100,
        ))
        
        # Phase 2: 偵察
        tasks.append(Task(
            id="task_002",
            name="Deep Reconnaissance (Parallel)",
            agent_type="recon_master",
            action="parallel_recon",
            params={"target": target, "start_step": recon_start_step, "end_step": recon_end_step},
            priority=90,
            parent_id="task_001",
        ))
        
        if self.recipe_loader:
            recipe_tasks = self._load_recipe_tasks()
            tasks.extend(recipe_tasks)
        
        self.task_queue.clear()
        self.task_queue.add_batch(tasks, source="plan_static")
        return tasks
    
    def _load_recipe_tasks(self) -> list[Task]:
        """RecipeLoaderからRecipeを取得し、OptimizedRecipeRunnerで実行"""
        if not self.recipe_loader:
            return []
        
        # コンテキスト情報を準備
        context_dict = {
            "tech_stack": self.context.target_info.get("tech_stack", []),
            "target": self.context.target_info.get("target", ""),
        }
        
        # マッチするRecipeを検索
        matched_recipes = self.recipe_loader.match_recipes_to_context(context_dict)
        
        tasks = []
        if matched_recipes:
            target = self.context.target_info.get("target", "")
            for recipe in matched_recipes:
                recipe_task = Task(
                    id=f"recipe_exec_{recipe.name}_{uuid.uuid4().hex[:8]}",
                    name=f"Optimized Recipe: {recipe.name}",
                    agent_type="swarm",
                    action="run_recipe",
                    params={
                        "recipe_name": recipe.name,
                        "target": target,
                    },
                    priority=100
                )
                task_contract = validate_task_schema(recipe_task)
                if not task_contract.get("ok", False):
                    logger.warning(
                        "Skip invalid recipe task contract for %s: %s",
                        recipe.name,
                        task_contract.get("errors", []),
                    )
                    continue
                tasks.append(recipe_task)
        
        if tasks:
            logger.info(f"Injected {len(tasks)} optimized recipe execution tasks")
        
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
        return {
            "success": bool(result_bundle.get("success", False)),
            "message": f"Recipe {recipe_name} executed: total={total_steps}, failed={failed_steps}",
            "data": result_bundle,
        }
    
    def execute_with_replan(self, max_tasks: int = None) -> dict:
        """
        再帰的実行ループ (並列化対応版)
        """
        if max_tasks is None:
            max_tasks = getattr(settings, "max_session_tasks", 1000)
        executed = 0
        from src.core.engine.parallel_orchestrator import create_parallel_task

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
        
        while executed < max_tasks:
            if self._shutdown_requested:
                break

            # 最終カバレッジガード: CSRF 必須なのに候補タスクが皆無な場合は実行ループ側で補完する
            logger.debug("🔑 MainThread attempting to acquire _state_lock for global csrf guard")
            with self._state_lock:
                logger.debug("🔓 MainThread acquired _state_lock for global csrf guard")
                self._ensure_global_csrf_guard_task(trigger_source="execute_loop")
                self._ensure_global_xss_guard_task(trigger_source="execute_loop")
                self._ensure_global_oob_guard_task(trigger_source="execute_loop")

            # タスクキューが空で、かつ進行中のタスクもない場合、終了とみなす（無限ループ防止）
            if self.task_queue.empty():
                logger.info("[MC] Task queue is empty. Finishing execution loop.")
                break

            # 🧠 HOOK 4: 定期省察 (SelfReflection)
            # 一定数のタスク実行後に実行履歴を分析してインサイトを得る
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

            # 戦略的レビューフェーズ
            if self.optimizer.should_review(executed):
                logger.debug(f"🔑 MainThread attempting to acquire _state_lock for strategy review")
                with self._state_lock:
                    logger.debug(f"🔓 MainThread acquired _state_lock for strategy review")
                    self.optimizer.review_strategy(self.task_queue, self.graph, executed)
                
                # 🗺️ HOOK: KG-based dynamic task inference (Insights enabled)
                if executed > 0 and executed % 10 == 0:
                    logger.info("[MC] Triggering KG-based dynamic task inference with insights...")
                    insights = self.self_reflection.reflect()
                    new_tasks = self.attack_planner.infer_tasks(self.graph, self.context, insights=insights)
                    for t in new_tasks:
                        # 既存のタスクと重複していないか簡易チェック (IDベース)
                        if not self.task_queue.get_by_id(t.id):
                            self.task_queue.add(t)

            # 1. バッチ作成 (現在空いているスロット分、または動的推奨数)
            # InjectionManagerAgent のタスクは既定で逐次制限するが、
            # injection_full_parallel_dispatch=true の時は制限付き並列を許可する。
            batch_tasks = []
            suggested_batch = getattr(self.resource_manager, "get_suggested_concurrency", lambda: 5)() # fallback to 5
            full_parallel_injection = bool(getattr(settings, "injection_full_parallel_dispatch", False))
            
            # キューの先頭タスクを確認して InjectionManagerAgent ならバッチサイズ 1 に制限
            first_task = self.task_queue.peek()
            first_agent_type = (first_task.agent_type or "") if first_task else ""
            has_injection_in_queue = "injection" in first_agent_type.lower()
            if has_injection_in_queue:
                if full_parallel_injection:
                    injection_batch_limit = max(1, int(getattr(settings, "injection_batch_parallelism", 2)))
                    suggested_batch = max(1, min(int(suggested_batch or 1), injection_batch_limit))
                    logger.info(
                        "🚀 Injection full parallel dispatch enabled (suggested_batch=%s, injection_batch_parallelism=%s)",
                        suggested_batch,
                        injection_batch_limit,
                    )
                else:
                    suggested_batch = 1
                    logger.info("🔒 Limiting batch size to 1 for InjectionManagerAgent task (sequential execution)")

            logger.debug(f"🔑 MainThread attempting to acquire _state_lock for batch creation")
            with self._state_lock:
                logger.debug(f"🔓 MainThread acquired _state_lock for batch creation")
                while len(batch_tasks) < suggested_batch and not self.task_queue.is_empty():
                    task = self._select_next_task_from_queue()
                    if task is None:
                        break
                    batch_tasks.append(task)
            
            if not batch_tasks:
                # キュー空なら待機
                active_background = [t for t in threading.enumerate() if t.name.startswith("ReconWorker-")]
                if active_background:
                    time.sleep(2)
                    continue
                break

            # 2. 並列実行用の ParallelTask オブジェクトに変換
            p_tasks = []
            for t in batch_tasks:
                p_tasks.append(create_parallel_task(
                    t.id, self._execute_single_task_full_flow, t, category=t.agent_type or "default"
                ))
            
            # 3. オーケストレーターで実行
            rich_logger.show_tree(
                {f"Task: {t.name}": {"agent": t.agent_type, "priority": t.priority} for t in batch_tasks},
                title=f"Executing Batch (Total executed: {executed})"
            )

            # InjectionManagerAgent のタスクが含まれる場合、制限付き並列で実行
            # （過去のレースコンディション対策として、全並列ではなく小さなチャンクに分割）
            has_injection = any("injection" in (t.agent_type or "").lower() for t in batch_tasks)
            try:
                if has_injection:
                    batch_timeout = getattr(settings, "injection_manager_timeout", 1800)
                    chunk_size = max(1, int(getattr(settings, "injection_batch_parallelism", 2)))
                    mixed_agents = any("injection" not in (t.agent_type or "").lower() for t in batch_tasks)
                    if mixed_agents and not full_parallel_injection:
                        # 混在バッチでは Injection 系の長時間タスクに引きずられやすいため
                        # チャンクを 1 件化して巻き添え失敗を防ぐ
                        chunk_size = 1
                        batch_timeout = max(
                            int(batch_timeout),
                            int(getattr(settings, "parallel_batch_timeout", 600)),
                            900,
                        )
                    logger.info(
                        "🕒 Using extended batch timeout (%ss) for InjectionManagerAgent tasks (limited parallelism=%s)",
                        batch_timeout,
                        chunk_size,
                    )

                    # 制限付き並列実行（チャンク単位）
                    results = []
                    for i in range(0, len(p_tasks), chunk_size):
                        chunk = p_tasks[i:i + chunk_size]
                        result = self._run_async_safe(
                            self.orchestrator.execute_parallel(chunk, timeout=batch_timeout),
                            timeout_override=batch_timeout
                        )
                        results.extend(result)
                else:
                    batch_timeout = int(getattr(settings, "parallel_batch_timeout", 600))
                    has_recon_master = any(
                        "recon_master" in (t.agent_type or "").lower()
                        for t in batch_tasks
                    )
                    if has_recon_master:
                        # recon_master は long-running のため、バッチ側タイムアウトが先に切れないよう揃える
                        batch_timeout = max(
                            batch_timeout,
                            int(getattr(settings, "recon_master_timeout", 900)),
                        )
                    results = self._run_async_safe(
                        self.orchestrator.execute_parallel(p_tasks, timeout=batch_timeout),
                        timeout_override=batch_timeout
                    )
            except Exception as batch_exc:
                failure_reason = "timeout_batch" if self._is_timeout_related(batch_exc) else type(batch_exc).__name__
                logger.error("Batch execution failed (%s): %r", failure_reason, batch_exc)

                # 巻き添え失敗を避けるため、未完了タスクのみ逐次リカバリ実行
                if self._is_timeout_related(batch_exc):
                    logger.warning(
                        "Batch timeout detected. Retrying unfinished tasks sequentially (count=%d).",
                        sum(1 for t in batch_tasks if t.state not in [TaskState.SUCCESS, TaskState.FAILED]),
                    )
                    for task in batch_tasks:
                        if task.state in [TaskState.SUCCESS, TaskState.FAILED]:
                            continue
                        try:
                            self._execute_single_task_full_flow(task)
                        except Exception as recovery_exc:
                            logger.error("Sequential recovery failed for %s: %r", task.id, recovery_exc)
                            with self._state_lock:
                                if task.state not in [TaskState.SUCCESS, TaskState.FAILED]:
                                    task.state = TaskState.FAILED
                                    task.error = repr(recovery_exc)
                                    recovery_reason = (
                                        "timeout_recovery"
                                        if self._is_timeout_related(recovery_exc)
                                        else type(recovery_exc).__name__
                                    )
                                    self._record_failure_context(task, "orchestrator_batch_recovery", recovery_reason)

                with self._state_lock:
                    for task in batch_tasks:
                        if task.state not in [TaskState.SUCCESS, TaskState.FAILED, TaskState.SKIPPED]:
                            task.state = TaskState.FAILED
                            task.error = repr(batch_exc)
                            self._record_failure_context(task, "orchestrator_batch_execute", failure_reason)
                    self.completed_tasks.extend(batch_tasks)
                executed += len(batch_tasks)
                continue

            executed += len(results)
            logger.info("Executed batch of %d tasks (Total: %d)", len(results), executed)

            # Update completed_tasks and handle timeouts/errors from orchestrator
            task_map = {t.id: t for t in batch_tasks}
            for res in results:
                task = task_map.get(res.task_id)
                if task:
                     if not res.success and task.state not in [TaskState.SUCCESS, TaskState.FAILED, TaskState.SKIPPED]:
                         # Update task if orchestrator reported error but task state wasn't updated (e.g. timeout/cancel)
                         task.state = TaskState.FAILED
                         task.error = res.error
                         failure_reason = "timeout_orchestrator" if self._is_timeout_related(res.error) else (res.error or "orchestrator_failed")
                         self._record_failure_context(task, "orchestrator_batch", str(failure_reason))
            
            with self._state_lock:
                 self.completed_tasks.extend(batch_tasks)

            # セッション保存 (チェックポイント)
            if self._auto_checkpoint and executed % getattr(settings, "checkpoint_interval", 10) == 0:
                self.save_session()

        if not self._shutdown_requested:
            self._finished_normally = True
            rich_logger.status("success", "ミッションが正常に完了しました。")

        self.save_session()
        summary = self._generate_summary()
        
        # 最終サマリーの表示
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
                [
                    "Coverage Gate",
                    "PASS" if summary.get("coverage_gate_passed", False) else "FAIL",
                ],
                [
                    "Coverage",
                    f"{summary.get('coverage_gate_covered', 0)}/{summary.get('coverage_gate_required', 0)}",
                ],
                [
                    "Coverage Missing",
                    ", ".join(summary.get("coverage_gate_missing", [])) or "-",
                ],
                [
                    "Scenario Coverage",
                    f"{summary.get('scenario_covered', 0)}/{summary.get('scenario_required', 0)}",
                ],
                [
                    "Scenario Missing",
                    ", ".join(summary.get("scenario_missing", [])) or "-",
                ],
                [
                    "Pending HITL",
                    summary.get("pending_hitl_count", 0),
                ],
                [
                    "Failed Reasons",
                    (
                        ", ".join(
                            f"{code}={count}"
                            for code, count in summary.get("failed_reason_codes", {}).items()
                        )
                        if summary.get("failed_reason_codes")
                        else "-"
                    ),
                ],
            ]
        )
        
        return summary

    def _execute_single_task_full_flow(self, task: Task) -> dict:
        """
        単一タスクの全工程（事前準備、実行、事後処理）をカプセル化
        スレッドセーフに状態を更新します。
        """
        import uuid
        from src.core.models.task_execution_log import TaskExecutionRecord
        from src.core.infra.event_bus import get_event_bus, Event, EventType
        from src.core.notifications.notifier import get_notifier

        # 1. 事前準備 (Enrichment)
        with self._state_lock:
            task.state = TaskState.RUNNING
            if not self.accumulated_context.is_empty():
                task.params["_context"] = self.accumulated_context.to_dict()
            task = self.context_designer.enrich_task(task, self.context, self.accumulated_context, workspace=self.workspace)
            
        # 2. イベント通知
        event_bus = get_event_bus()
        correlation = self.context.target_info.get("correlation", {})
        started_payload = ensure_observability_fields(
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
        event_bus.emit_sync(
            Event(
                type=EventType.TASK_STARTED,
                payload=started_payload,
                source="master_conductor",
            )
        )

        # 3. 実行記録作成
        exec_record = TaskExecutionRecord(
            task_id=task.id, task_name=task.name, agent_type=task.agent_type,
            action=task.action, target_url=task.params.get("target", ""),
            parameters=task.params.copy(), source=getattr(task, 'source', 'unknown')
        )

        # 📸 HOOK: 実行前スナップショット (DiffAnalyzer)
        before_snap_id = None
        if task.action in ["fuzz", "post", "put", "delete"] or task.params.get("method") in ["POST", "PUT", "DELETE"]:
            try:
                target = task.params.get("target", "default")
                # KnowledgeGraphから現在の知見を収集 (簡易版)
                current_data = {
                    "urls": [n.url for n in self.graph.get_nodes_by_type("Page") if hasattr(n, "url")],
                    "endpoints": [n.url for n in self.graph.get_nodes_by_type("Endpoint") if hasattr(n, "url")]
                }
                _, before_snap_id = self.diff_analyzer.take_snapshot(target, current_data, label=f"before_{task.id}")
                logger.info("📸 Captured 'before' snapshot: %s", before_snap_id)
            except Exception as e:
                logger.warning("DiffAnalyzer: Failed to take 'before' snapshot: %s", e)

        try:
            # 🛡️ HOOK 1: 実行前リスク評価 (RiskPredictor)
            # 攻撃的すぎる行動やWAF検知リスクが高い場合にタスクを制御
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
                        task.state = TaskState.FAILED # SKIPPED 状態がないため FAILED 扱い
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
                        delay = min(assessment.recommended_delay, 10.0) # 最大10秒
                        logger.info("⏳ RiskPredictor: applying recommended delay %.2fs for %s", delay, task.name)
                        # メインループを止めすぎないよう注意（並列実行なら個別スレッドで停止）
                        time.sleep(delay)
                    else:
                        if delay_disabled:
                            logger.info("RiskPredictor: delay disabled by settings for %s", task.name)
                        else:
                            logger.info(
                                "RiskPredictor: skipped delay for %s (risk_level=%s, risk_score=%.2f, min_score=%.2f)",
                                task.name,
                                risk_level or "unknown",
                                risk_score,
                                min_score,
                            )
            except Exception as e:
                logger.warning(f"Intelligence: Risk assessment failed (non-critical): {e}")

            intervention_block = self._run_intervention_precheck(task, exec_record=exec_record)
            if intervention_block is not None:
                self._record_task_prioritizer_outcome(task, intervention_block)
                return intervention_block

            # 4. 実ディスパッチ (各 Swarm 呼び出し)
            logger.info(f"🚀 Dispatching {task.agent_type} (task {task.id}) via _run_async_safe")
            
            timeout_override = None
            if getattr(task, "agent_type", "") in ["InjectionManager", "InjectionManagerAgent", "injection_manager", "InjectionSwarm", "injection_manager_agent"] or "Injection" in getattr(task, "agent_type", ""):
                timeout_override = getattr(settings, "injection_manager_timeout", 1800)
                logger.debug(f"Using extended timeout {timeout_override}s for {task.agent_type}")
                
            result = self._dispatch_with_timeout_retry(task, timeout_override=timeout_override)
            task.result = result
            logger.info(f"📥 Received result from {task.agent_type} (task {task.id})")
                
            # 5. 結果処理とリプラン (ロックを保持して安全に)
            logger.debug(f"🔑 Thread {threading.get_ident()} attempting to acquire _state_lock for task {task.id} result processing")
            with self._state_lock:
                logger.debug(f"🔓 Thread {threading.get_ident()} acquired _state_lock for task {task.id} result processing")
                exec_record.mark_completed(
                    success=result.get("success", False),
                    summary=result.get("message", ""),
                    output=result.get("output", ""),
                    metadata=result.get("data", {})
                )
                for f in result.get("findings", []):
                    exec_record.add_vulnerability(f)
                
                self.execution_log.add_record(exec_record)
            
                # 🧠 HOOK: 意思決定強化 (DecisionEnhancer)
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
                        # タスクを再スケジュール (回数制限あり)
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

                # 📸 HOOK: 実行後スナップショット & 差分分析 (DiffAnalyzer)
                if before_snap_id:
                    try:
                        target = task.params.get("target", "default")
                        current_data = {
                            "urls": [n.url for n in self.graph.get_nodes_by_type("Page") if hasattr(n, "url")],
                            "endpoints": [n.url for n in self.graph.get_nodes_by_type("Endpoint") if hasattr(n, "url")]
                        }
                        _, after_snap_id = self.diff_analyzer.take_snapshot(target, current_data, label=f"after_{task.id}")
                        
                        # 差分比較
                        diffs = self.diff_analyzer.compare(
                            self.diff_analyzer.snapshots[after_snap_id],
                            self.diff_analyzer.snapshots[before_snap_id]
                        )
                        
                        has_changes = any(d.has_changes() for d in diffs.values())
                        if has_changes:
                            logger.info("🔍 State changes detected after %s!", task.id)
                            # 差分をKnowledgeGraphへ記録 (重要なもの)
                            for cat, d in diffs.items():
                                if d.added:
                                    logger.info("  [+] Added in %s: %s", cat, d.added[:5])
                    except Exception as e:
                        logger.warning("DiffAnalyzer: Failed to perform post-execution diff: %s", e)

                if result.get("success", False):
                    task.state = TaskState.SUCCESS
                    task.failure_phase = None
                    task.failure_reason = None
                    task.failure_reason_code = None
                    if isinstance(task.params, dict):
                        task.params.pop("_failure", None)
                    self.context.update_success_rate(True)
                    self._emit_task_state_event(
                        event_type=EventType.TASK_COMPLETED,
                        task=task,
                        result=result,
                    )
                    self._update_flaky_quarantine(task, success=True)
                    
                    # 📈 HOOK 2: 成功時フィードバック (SelfReflection & PriorityBooster)
                    try:
                        from src.core.intelligence import ExecutionRecord, ExecutionOutcome
                        def _get_finding_title(f):
                            return f.title if hasattr(f, 'title') else f.get('title', 'Unknown')
                        def _get_finding_type(f):
                            vt = f.vuln_type if hasattr(f, 'vuln_type') else f.get('vuln_type', f.get('type', 'Unknown'))
                            return vt.value if hasattr(vt, 'value') else str(vt)

                        self.self_reflection.record(ExecutionRecord(
                            task_id=task.id,
                            action_type=task.agent_type or "unknown",
                            target=task.params.get("target", ""),
                            outcome=ExecutionOutcome.SUCCESS,
                            duration_seconds=exec_record.duration_seconds() or 0.0,
                            findings=[f"[{_get_finding_type(f)}] {_get_finding_title(f)}" for f in result.get("findings", [])],
                            response_code=result.get("data", {}).get("status_code") or result.get("status_code"),
                            payload_used=str(task.params.get("payload", "")) if task.params.get("payload") else None
                        ))
                        
                        # PriorityBooster: レスポンス内容から重要資産を見つけて後続タスクをブースト
                        response_body = result.get("output", "") or result.get("data", {}).get("response_body", "")
                        if response_body:
                            # 待機中のタスクを対象にする
                            boost_event = self.priority_booster.auto_detect_boost(
                                target=task.params.get("target", ""),
                                content=str(response_body),
                                related_tasks=self.task_queue.get_pending_task_ids()
                            )
                            if boost_event:
                                affected_ids = self.priority_booster.boost_on_discovery(boost_event)
                                # キューの優先度にも反映 (0-100にスケーリング)
                                boost_val = int(boost_event.boost_amount * 50) # 最大50ポイント上昇
                                if affected_ids:
                                    logger.info("🔥 Discovery triggered priority boost for tasks: %s (+%d)", affected_ids, boost_val)
                                    self.task_queue.boost_priority(lambda t, aids=affected_ids: t.id in aids, boost_val)
                    except Exception as e:
                        logger.warning(f"Intelligence: Success feedback failed (non-critical): {e}")

                    # 資産発見時のプラン拡張
                    if result.get("new_assets"):
                        self._expand_plan_for_assets(result["new_assets"])
                    
                    # Finding フィードバック
                    for finding in result.get("findings", []):
                        self.handle_finding(finding)
                        # クリティカルパス分析
                        critical_actions = self.critical_path_analyzer.analyze(finding)
                        for action in critical_actions:
                            if action.action_type == "boost_priority":
                                target_tags = action.target_filter.get("tags", [])
                                def condition_fn(t, tt=target_tags):
                                    t_tags = getattr(t, 'params', {}).get('tags', [])
                                    return any(tag in tt for tag in t_tags)
                                    
                                self.task_queue.boost_priority(
                                    condition=condition_fn,
                                    new_priority=action.params.get("priority", 999)
                                )
                    
                    # 再帰的計画 (ReThink)
                    react_tasks = self._observe_and_rethink(task, result)
                    self._add_tasks(react_tasks, source="react")

                    # Handoff 処理
                    self._process_handoff(task, result)
                    
                    # コンテキスト伝搬
                    new_context = self.context_propagator.extract(result)
                    if not new_context.is_empty():
                        self.accumulated_context.merge(new_context)
                        if new_context.discovered_params:
                            self.wordlist_manager.learn_params(new_context.discovered_params)
                        self.task_queue.inject_context(new_context)

                    # ExecutionContext (TargetInfo) の直接更新
                    # ScopeParserなどが返した target_info (Cookie等) を反映
                    result_ctx = result.get("context", {})
                    if isinstance(result_ctx, dict):
                        target_info_update = result_ctx.get("target_info", {})
                        if target_info_update:
                            self.context.target_info.update(target_info_update)
                            logger.debug(f"Updated target_info from task {task.id}: {list(target_info_update.keys())}")
                else:
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
                    
                    # 🔍 HOOK 3: 失敗時分析 (ErrorAnalyzer & SelfReflection)
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
                        
                        # SelfReflection に記録（WAFブロック等は BLOCKED 扱い）
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

                    # 失敗時のリプランニング
                    if task.replan_depth < self.max_replan_depth:
                        # ErrorAnalyzer がリトライを奨励する場合のみ実行（デフォルトTrue）
                        should_replan = root_cause.retry_recommended if root_cause else True
                        if flaky_verdict.get("status") == "quarantine":
                            should_replan = False
                            task.params["_quarantine"] = {
                                "status": "quarantine",
                                "window_size": flaky_verdict.get("window_size"),
                                "failures": flaky_verdict.get("failures"),
                                "failure_rate": flaky_verdict.get("failure_rate"),
                                "reason": "flaky_auto_quarantine",
                            }
                        
                        if should_replan:
                            if root_cause and root_cause.wait_seconds:
                                logger.info(f"Intelligence: ErrorAnalyzer suggests waiting {root_cause.wait_seconds}s before replan")
                                time.sleep(min(root_cause.wait_seconds, 15.0)) # 最大15秒待機

                            failure_replan = self.replan(task, result.get("error", "Unknown error"), root_cause=root_cause)
                            for alt in failure_replan:
                                alt.replan_depth = task.replan_depth + 1
                                alt.parent_id = task.id
                            self._add_tasks(failure_replan, source="failure_replan")
                        else:
                            logger.info(f"Intelligence: ErrorAnalyzer suggests NOT retrying task {task.id} (Category: {root_cause.category if root_cause else 'unknown'})")

            # HITL チェック (並列中でもスレッドセーフに実行)
            hitl_info = self.check_hitl_required(task, result)
            if hitl_info:
                self.request_human_approval(hitl_info)

            self._mark_pending_hitl_done(task, success=bool(result.get("success", False)))
            self._record_task_prioritizer_outcome(task, result)
            return result

        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            error_msg = f"{type(e).__name__}: {str(e)}\n{tb}"
            logger.error(f"Task {task.id} critical failure: {error_msg}")
            failure_reason = "timeout_exception" if self._is_timeout_related(e) else type(e).__name__
            with self._state_lock:
                task.state = TaskState.FAILED
                task.error = error_msg
                self._record_failure_context(task, "dispatch_exception", failure_reason)
                exec_record.mark_completed(success=False, error=error_msg)
                self.execution_log.add_record(exec_record)
            self._emit_task_state_event(
                event_type=EventType.TASK_FAILED,
                task=task,
                result={"success": False, "error": str(e), "phase": "dispatch_exception"},
            )
            self._mark_pending_hitl_done(task, success=False)
            self._record_task_prioritizer_outcome(task, {"success": False, "error": str(e)})
            return {"success": False, "error": str(e)}
    
    def _emit_task_state_event(self, *, event_type: EventType, task: Task, result: dict | None = None) -> None:
        result = result or {}
        try:
            event_bus = get_event_bus()
            correlation = self.context.target_info.get("correlation", {})
            reason_code = str(getattr(task, "failure_reason_code", "") or "")
            error_message = str(result.get("error", "") or getattr(task, "error", "") or "")
            payload = ensure_observability_fields(
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

    def handle_finding(self, finding: Finding) -> None:
        """
        Finding → Task フィードバック (Implementation Plan Section 6.6)
        
        Finding の属性に基づき後続タスクを制御:
        - recommended_followup="escalate": 関連タスク優先度 +20
        - recommended_followup="report": 即時通知 + レポートタスク追加
        - is_aggressive=True: 同一ターゲットへのタスクに継承
        """
        
        if not isinstance(finding, Finding):
            return
        
        target_url = finding.target_url
        
        # DB書き込みフェーズ (バッチ)
        self.save_finding(finding)
        
        # Phase 6.2.3: VULN_FOUND イベント発火
        event_bus = get_event_bus()
        correlation = self.context.target_info.get("correlation", {})
        vuln_payload = ensure_observability_fields(
            {
                "title": finding.title,
                "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                "target": target_url,
                "vuln_type": finding.vuln_type.value if hasattr(finding.vuln_type, 'value') else str(finding.vuln_type),
                "source_agent": finding.source_agent,
                "schema_severity": str((finding.additional_info or {}).get("schema_severity", "none")),
            },
            correlation=correlation,
            endpoint=target_url,
            error_type="vuln_found",
            timeout_ms=0,
            retry_count=0,
            test_case_id=str(getattr(finding, "id", "") or "finding"),
        )
        event_bus.emit_sync(
            Event(
                type=EventType.VULN_FOUND,
                payload=vuln_payload,
                source="master_conductor",
            )
        )
        
        # Phase 6.2: 通知イベント送信
        get_notifier().notify_event(
            event_type="vuln_found",
            target=target_url,
            details={
                "title": finding.title,
                "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                "type": finding.vuln_type.value if hasattr(finding.vuln_type, 'value') else str(finding.vuln_type),
            },
        )
        
        # Phase 4.1: Finding 永続化 (Fixing missing findings)
        # Phase 4.1: Finding 永続化 (Fixing missing findings)
        if self.project_manager:
            try:
                # 非同期タスクとして投げっぱなしで実行
                self._run_async_safe_forget(self.project_manager.save_finding(finding))
            except Exception as e:
                logger.error("Failed to enqueue finding persistence: %s", e)
        else:
             logger.warning("ProjectManager not set, finding not persisted to storage: %s", finding.title)
        
        # 1. recommended_followup 処理
        if finding.recommended_followup == "escalate":
            self._boost_related_tasks(target_url, priority_delta=20)
            logger.info("Finding escalated: boosted priority for %s", target_url)
        
        elif finding.recommended_followup == "report":
            # 即時通知
            get_notifier().notify(
                f"🚨 **Critical Finding**: {finding.title}\n"
                f"Target: {finding.target_url}\n"
                f"Severity: {finding.severity.value}",
                bulk=False,  # 即時送信
            )
            
            # レポート生成タスク追加
            report_task = Task(
                id=f"report_{uuid.uuid4().hex[:8]}",
                name=f"Generate Report for Finding: {finding.title[:50]}",
                agent_type="report",
                action="generate",
                params={
                    "finding_id": finding.id,
                    "target": target_url,
                    "tags": finding.tags,
                    "findings": [finding.to_dict()],
                },
                priority=150,  # 高優先度
            )
            self._add_tasks([report_task], source="finding_feedback")
            logger.info("Report task added for critical finding: %s", finding.title)
        
        # 2. is_aggressive 継承
        if finding.is_aggressive:
            self._mark_target_as_aggressive(target_url)
            logger.info("Target marked as aggressive: %s", target_url)

        # Attack Chain 推論 (Phase 4 entry)
        # 既に攻撃チェーンとして昇格済みの Finding には再適用しない。
        try:
            tags = {str(t).lower() for t in (finding.tags or [])}
            is_chain_finding = "attack_chain" in tags or bool(
                (finding.additional_info or {}).get("is_attack_chain", False)
            )
            if not is_chain_finding:
                self._infer_and_emit_attack_chains(finding)
        except Exception as e:
            logger.debug("Attack chain inference skipped due to runtime error: %s", e)

        # RCE / SSRF / LFI 等のクリティカルな脆弱性が見つかった場合に自動連鎖
        self._trigger_post_exploit(finding)

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

    def _boost_related_tasks(self, target_url: str, priority_delta: int = 20) -> None:
        """関連ターゲットのタスク優先度をブースト"""
        
        def is_related(task):
             return task.params.get("target", "").startswith(target_url)
             
        with self._state_lock:
            self.task_queue.boost_by_delta(is_related, priority_delta)
    
    def _mark_target_as_aggressive(self, target_url: str) -> None:
        """ターゲットを aggressive としてマーク（後続タスクに継承）"""
        if "aggressive_targets" not in self.context.target_info:
            self.context.target_info["aggressive_targets"] = set()
        self.context.target_info["aggressive_targets"].add(target_url)

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
                seed = f"{reason.value}:{int(time.time() // 60)}:{self._react_observation_metrics.get('attempted', 0)}"
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

    def _should_observe(self, task: Task, result: dict) -> tuple[bool, ObservationReason]:
        if not bool(self._react_setting("enable_react_observation", False)):
            return False, ObservationReason.SKIP_DISABLED

        if not self.llm_client:
            return False, ObservationReason.SKIP_NO_LLM_CLIENT

        now = time.time()
        if now < float(getattr(self, "_react_observation_cb_open_until", 0.0)):
            return False, ObservationReason.SKIP_CIRCUIT_OPEN

        retry_budget = int(self._react_setting("react_observation_retry_budget_per_run", 20))
        if int(getattr(self, "_react_observation_retry_used", 0)) >= retry_budget:
            return False, ObservationReason.SKIP_BUDGET_EXCEEDED

        queue_maxsize = int(self._react_setting("react_observation_queue_maxsize", 100))
        pending_queue = getattr(self, "_react_observation_pending_queue", None)
        queue_depth = len(pending_queue) if pending_queue is not None else 0
        if queue_depth >= queue_maxsize:
            return False, ObservationReason.SKIP_QUEUE_OVERFLOW

        max_inflight = int(self._react_setting("max_inflight_react_requests_global", 8))
        if int(getattr(self, "_react_observation_inflight", 0)) >= max_inflight:
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
        if self._react_observation_executed_total >= max_calls_per_run:
            return False, ObservationReason.SKIP_BUDGET_EXCEEDED

        target = ""
        if isinstance(getattr(task, "params", None), dict):
            target = str(task.params.get("target", "") or "")
        max_calls_per_target = int(self._react_setting("react_observation_max_calls_per_target", 10))
        if target and self._react_observation_executed_by_target.get(target, 0) >= max_calls_per_target:
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
    
    def _observe_and_rethink(self, task: Task, result: dict) -> list[Task]:
        """
        ReAct観察→再思考: 成功結果を分析し追加攻撃ベクトルを提案
        
        Args:
            task: 成功したタスク
            result: 実行結果
        
        Returns:
            追加タスクのリスト
        """
        allowed, reason = self._should_observe(task, result)
        self._record_react_decision(reason, allowed)
        if not allowed:
            logger.debug("[ReAct] skipped for task=%s reason=%s", task.id, reason.value)
            return []
        queue_token = f"{task.id}:{time.time_ns()}"
        self._react_observation_pending_queue.append(queue_token)
        self._react_observation_inflight += 1
        self._react_observation_executed_total += 1
        target = ""
        if isinstance(getattr(task, "params", None), dict):
            target = str(task.params.get("target", "") or "")
        if target:
            self._react_observation_executed_by_target[target] = (
                self._react_observation_executed_by_target.get(target, 0) + 1
            )
        
        additional_tasks = []
        
        try:
            # 結果データを抽出
            data = result.get("data", {})
            technologies = data.get("technologies", [])
            endpoints = data.get("endpoints", [])
            hints = data.get("hints", [])
            
            # NOTE: RAG クエリは Swarm 経由に移行済み (Implementation Plan Section 3.4)
            # Swarm 内の Specialist が Recipe/RAG を直接参照する
            # 以下はフォールバック（Swarm が利用できない場合のみ）
            rag_suggestions = []
            if self.rag and technologies and not result.get("findings"):
                # Swarm 経由で findings がない場合のみフォールバック
                try:
                    tech_str = ", ".join(technologies[:3])
                    rag_results = self.rag.query(f"attack patterns for {tech_str}", n_results=2)
                    rag_suggestions = [r.content[:200] for r in rag_results]
                    logger.debug("RAG fallback used (Swarm not available)")
                except Exception:
                    pass
            
            # キャッシュチェック (Phase 2)
            # タスク名、結果データ、RAG提案をキーにする
            data_hash = hashlib.md5(json.dumps(data, sort_keys=True).encode()).hexdigest()
            rag_hash = hashlib.md5(json.dumps(rag_suggestions, sort_keys=True).encode()).hexdigest()
            cache_key = f"{task.name}_{data_hash}_{rag_hash}"
            
            if cache_key in self._react_cache:
                logger.debug(f"ReAct cache hit for task: {task.name}")
                suggestions = self._react_cache[cache_key]
            else:
                # LLMに追加攻撃ベクトルを提案させる
                from src.core.conductor.conductor_prompts import get_react_observation_prompt
                
                prompt = get_react_observation_prompt(
                    task_name=task.name,
                    task_result=data,
                    tech_stack=self.context.target_info.get("tech_stack", []),
                    rag_hints=rag_suggestions,
                )
                
                retry_max = int(self._react_setting("react_observation_retry_max", 1))
                latency_threshold = float(self._react_setting("react_observation_circuit_breaker_latency_seconds", 8.0))
                response = None
                last_exc = None
                for _attempt in range(max(1, retry_max + 1)):
                    started = time.time()
                    try:
                        response = self.llm_client.generate(
                            messages=[
                                {"role": "system", "content": "You are a security analyst. Suggest additional attack vectors based on the result. Output JSON only."},
                                {"role": "user", "content": prompt}
                            ],
                            response_format={"type": "json_object"},
                            temperature=0.3,
                            max_tokens=500,
                        )
                        elapsed = time.time() - started
                        if elapsed > latency_threshold:
                            self._react_observation_cb_failures += 1
                        break
                    except Exception as exc:
                        last_exc = exc
                        self._react_observation_retry_used += 1
                        self._react_observation_cb_failures += 1
                        if _attempt >= retry_max:
                            raise
                if response is None and last_exc is not None:
                    raise last_exc
                
                content = response.choices[0].message.content
                suggestions = json.loads(content)
                
                # 結果をキャッシュ
                self._react_cache[cache_key] = suggestions
            
            # 提案からタスクを生成
            for i, s in enumerate(suggestions.get("additional_attacks", [])[:settings.react_observation_max_additions]):
                new_task = Task(
                    id=f"{task.id}_react_{i}",
                    name=s.get("name", f"ReAct: Follow-up {i}"),
                    agent_type=s.get("agent_type", "universal"),
                    action=s.get("action", "scan"),
                    params={
                        "target": task.params.get("target"),
                        "hint": s.get("rationale", ""),
                        **s.get("params", {})
                    },
                    priority=task.priority - 5,  # 元タスクより少し低い優先度
                )
                additional_tasks.append(new_task)

            if additional_tasks:
                logger.info(f"[ReAct] Observation generated {len(additional_tasks)} additional tasks")
                if self._debug_logger:
                    self._debug_logger.log_decision(
                        agent="MasterConductor",
                        decision=f"ReAct観察で{len(additional_tasks)}個の追加タスクを生成",
                        reasoning=f"タスク '{task.name}' の成功結果を分析",
                        next_steps=[t.name for t in additional_tasks]
                    )
            # 成功経路では breaker 失敗カウンタをリセット
            self._react_observation_cb_failures = 0
            
        except Exception as e:
            self._react_observation_retry_used += 1
            self._react_observation_cb_failures += 1
            cb_threshold = int(self._react_setting("react_observation_circuit_breaker_threshold", 5))
            if self._react_observation_cb_failures >= cb_threshold:
                cooldown = int(self._react_setting("react_observation_circuit_breaker_cooldown_seconds", 120))
                self._react_observation_cb_open_until = time.time() + max(1, cooldown)
                logger.warning(
                    "[ReAct] circuit breaker opened cooldown=%ss failures=%s",
                    cooldown,
                    self._react_observation_cb_failures,
                )
            logger.warning(f"[ReAct] Observation failed: {e}")
        finally:
            if self._react_observation_inflight > 0:
                self._react_observation_inflight -= 1
            if queue_token in self._react_observation_pending_queue:
                self._react_observation_pending_queue.remove(queue_token)
            self._sync_react_observation_metrics_snapshot()
        
        return additional_tasks
    
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
            # 🧠 Intelligence 分析結果に基づくブースト適用
            dynamic_priority = failed_task.priority - 5 # 失敗時は少し下げる
            if root_cause and root_cause.confidence > 0.8:
                # 信頼度が高い分析があれば、それに基づき調整
                if root_cause.category.value == "auth_failure":
                    dynamic_priority = failed_task.priority + 20 # 認証再取得は重要

            # エラータイプに基づく代替アプローチ
            if "403" in error or "forbidden" in error.lower() or (root_cause and root_cause.category.value == "permission_denied"):
                # アクセス拒否 → プロキシローテーションを試行
                alternative_tasks.append(Task(
                    id=f"{failed_task.id}_alt_proxy",
                    name=f"Retry with proxy rotation: {failed_task.name}",
                    agent_type=failed_task.agent_type,
                    action=failed_task.action,
                    params={**failed_task.params, "use_proxy_rotation": True},
                    priority=dynamic_priority + 10,
                ))
            
            elif "timeout" in error.lower() or (root_cause and root_cause.category.value == "network_timeout"):
                # タイムアウト → 遅延を追加して再試行
                alternative_tasks.append(Task(
                    id=f"{failed_task.id}_alt_delay",
                    name=f"Retry with delay: {failed_task.name}",
                    agent_type=failed_task.agent_type,
                    action=failed_task.action,
                    params={**failed_task.params, "delay_seconds": 5},
                    priority=dynamic_priority + 5,
                ))
            
            elif "waf" in error.lower() or "blocked" in error.lower() or (root_cause and root_cause.category.value == "waf_blocked"):
                # WAFブロック → バイパス手法を適用
                for method in self.context.bypass_methods:
                    alternative_tasks.append(Task(
                        id=f"{failed_task.id}_alt_{method}",
                        name=f"Retry with bypass ({method}): {failed_task.name}",
                        agent_type=failed_task.agent_type,
                        action=failed_task.action,
                        params={**failed_task.params, "bypass_method": method},
                        priority=dynamic_priority + 15,
                    ))
            
            # ヒントからの代替アプローチ
            for hint in hints[:2]:  # 最大2つのヒント
                if isinstance(hint, dict) and hint.get("approach"):
                    alternative_tasks.append(Task(
                        id=f"{failed_task.id}_hint_{hint.get('id', 'x')}",
                        name=f"RAG hint: {hint.get('approach', 'unknown')[:50]}",
                        agent_type=failed_task.agent_type,
                        action=failed_task.action,
                        params={**failed_task.params, "hint": hint},
                        priority=dynamic_priority + 8,
                    ))
        
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
        """
        単一タスクを実行（対話モード用）
        
        InteractiveBridge から呼び出されることを想定。
        execute_with_replan() のループを1回だけ実行するイメージ。
        
        Args:
            task: 実行するタスク
            enable_react: ReAct観察を有効化するか（デフォルト: False、リスク緩和）
            enable_replan: リプランを有効化するか（デフォルト: True）
        
        Returns:
            実行結果（success, data, error等）
        """
        task.state = TaskState.RUNNING
        
        # DebugLog: アクション開始
        if self._debug_logger:
            self._debug_logger.log_action(
                agent="MasterConductor",
                action="単一タスク実行",
                target=task.name,
                result="実行中",
                details={"task_id": task.id, "agent_type": task.agent_type}
            )
        
        try:
            intervention_block = self._run_intervention_precheck(task)
            if intervention_block is not None:
                if not bool(intervention_block.get("pending_hitl", False)):
                    self.context.update_success_rate(False)
                return intervention_block

            timeout_override = None
            if getattr(task, "agent_type", "") in ["InjectionManager", "InjectionManagerAgent", "injection_manager", "InjectionSwarm", "injection_manager_agent"] or "Injection" in getattr(task, "agent_type", ""):
                timeout_override = getattr(settings, "injection_manager_timeout", 1800)
                logger.debug(f"Using extended timeout {timeout_override}s for {task.agent_type}")
                
            result = self._dispatch_with_timeout_retry(task, timeout_override=timeout_override)
            task.result = result
            
            if result.get("success", False):
                task.state = TaskState.SUCCESS
                task.failure_phase = None
                task.failure_reason = None
                task.failure_reason_code = None
                if isinstance(task.params, dict):
                    task.params.pop("_failure", None)
                self.context.update_success_rate(True)
                
                # 新しい資産が発見された場合、プランを拡張
                if result.get("new_assets"):
                    self._expand_plan_for_assets(result["new_assets"])
                
                # バイパス手法が成功した場合、記録
                if result.get("bypass_method"):
                    self.context.add_bypass_method(result["bypass_method"])

                # Findings 処理 (5.1 Notification / 5.2 Aggressive)
                findings = result.get("findings", [])
                if not findings:
                    findings = self._extract_findings_from_result_payload(result.get("data", {}))
                if findings:
                    self._process_findings(findings, task.params.get("target", ""))
                
                # ReAct観察（対話モードではデフォルトOFF）
                if enable_react and bool(self._react_setting("enable_react_observation", False)) and self.llm_client:
                    react_tasks = self._observe_and_rethink(task, result)
                    self._add_tasks(react_tasks, source="react")  # #7: ヘルパーメソッド使用
                
                # Handoff 処理 (Phase 2.7) - 単一実行モードでも有効化
                self._process_handoff(task, result)

            else:
                task.state = TaskState.FAILED
                task.error = result.get("error", "Unknown error")
                failure_phase = str(result.get("phase", "dispatch_result")) if isinstance(result, dict) else "dispatch_result"
                failure_reason = self._extract_failure_reason(result)
                if self._is_timeout_related(failure_reason):
                    failure_reason = "timeout_result"
                self._record_failure_context(task, failure_phase, failure_reason)
                self.context.update_success_rate(False)
                
                # #3: リプラン試行（タスク個別カウンター使用）
                if enable_replan and task.replan_depth < self.max_replan_depth:
                    alternative_tasks = self.replan(task, task.error)
                    
                    # 派生タスクにカウンターを引き継ぎ
                    for alt_task in alternative_tasks:
                        alt_task.replan_depth = task.replan_depth + 1
                        alt_task.parent_id = task.id
                    
                    self._add_tasks(alternative_tasks, source="replan")  # #7: ヘルパーメソッド使用
                    task.state = TaskState.REPLANNED
                else:
                    if task.replan_depth >= self.max_replan_depth:
                        logger.warning(f"Max replan depth ({self.max_replan_depth}) reached for task: {task.id}")
            
            self.completed_tasks.append(task)
            self._mark_pending_hitl_done(task, success=bool(result.get("success", False)))
            
            # #9: チェックポイント保存（5タスクごと）
            if self._auto_checkpoint:
                self._checkpoint_counter += 1
                if self._checkpoint_counter >= settings.checkpoint_interval:
                    self._checkpoint()
                    self._checkpoint_counter = 0

            self._record_task_prioritizer_outcome(task, result)
            
            return result
            
        except Exception as e:
            task.state = TaskState.FAILED
            task.error = str(e)
            failure_reason = "timeout_exception" if self._is_timeout_related(e) else type(e).__name__
            self._record_failure_context(task, "dispatch_exception", failure_reason)
            self.completed_tasks.append(task)
            self._mark_pending_hitl_done(task, success=False)
            logger.error("Task execution error: %s", e)
            
            # エラー時もチェックポイント保存
            if self._auto_checkpoint:
                self._checkpoint()

            self._record_task_prioritizer_outcome(task, {"success": False, "error": str(e)})
            
            return {
                "success": False,
                "task_id": task.id,
                "agent": task.agent_type,
                "error": str(e),
            }

    def _dispatch_scope_verification_fast_path(self, task: Task) -> dict:
        """
        Scope Verification の軽量フォールバック。

        ScopeParser の LLM/外部依存を介さずに、最低限のスコープを確定して
        初期フェーズの timeout 連鎖を防ぐ。
        """
        from urllib.parse import urlparse
        from src.core.security.ethics_guard import ScopeDefinition, get_ethics_guard

        raw_target = str(
            task.params.get("target")
            or self.context.target_info.get("target")
            or ""
        ).strip()
        if not raw_target:
            return {
                "success": False,
                "task_id": task.id,
                "agent": "scope_parser",
                "error": "Target not specified for scope verification",
            }

        normalized_target = raw_target if "://" in raw_target else f"http://{raw_target}"
        parsed = urlparse(normalized_target)
        host = (parsed.hostname or parsed.netloc or "").strip().lower()

        in_scope_domains = [host] if host else []
        scope = ScopeDefinition(
            program_name=f"Auto Scope ({host or 'target'})",
            in_scope_domains=in_scope_domains,
            max_requests_per_minute=60,
            strict_mode=False,
            allow_post_exploit=bool(getattr(settings, "allow_post_exploit", False)),
        )

        try:
            get_ethics_guard().set_scope(scope)
        except Exception as guard_exc:
            logger.warning("Failed to apply fast-path scope to EthicsGuard: %s", guard_exc)

        target_info_update: dict[str, Any] = {
            "target": normalized_target,
            "scope_source": "fast_path_auto",
        }
        if host:
            target_info_update["host"] = host
        if parsed.scheme:
            target_info_update["scheme"] = parsed.scheme
        if in_scope_domains:
            target_info_update["in_scope_domains"] = in_scope_domains

        return {
            "success": True,
            "task_id": task.id,
            "agent": "scope_parser",
            "message": "Scope verification completed via fast-path",
            "data": {
                "target": normalized_target,
                "in_scope_domains": in_scope_domains,
                "out_of_scope_domains": [],
                "strict_mode": False,
            },
            "context": {"target_info": target_info_update},
            "findings": [],
        }
    
    async def _dispatch(self, task: Task) -> dict:
        """タスクを適切なエージェントにディスパッチ"""
        logger.debug(f"Entering _dispatch with task {task.agent_type}")

        if task.agent_type == "scope_parser" and getattr(task, "action", "") == "verify_scope":
            return self._dispatch_scope_verification_fast_path(task)
        
        current_mode = self.context.target_info.get("mode", "bugbounty")
        
        # --- Scope-based Post Exploitation Control ---
        if task.agent_type in ["post_exploit", "secret_looter", "internal_recon", "pivot_scan"] or getattr(task, "action", "") in ["secret_looting", "internal_recon"]:
            from src.core.security.ethics_guard import get_ethics_guard
            guard = get_ethics_guard()
            if guard.scope:
                allow_pe = guard.scope.allow_post_exploit
            else:
                allow_pe = getattr(settings, "allow_post_exploit", False)
            
            if current_mode.lower() == "bugbounty" and not allow_pe:
                logger.info(f"Skipping post-exploit task {task.id} ({task.agent_type}) due to strict bugbounty scope rules.")
                return {
                    "success": True, 
                    "task_id": task.id, 
                    "agent": task.agent_type, 
                    "data": {"skipped": True, "reason": "Post-exploitation not allowed in current scope"}, 
                    "error": None,
                    "findings": []
                }
        
        # コンテキストに応じたエージェントフィルタリング
        context_tag = self.context.target_info.get("context_tag")
        if context_tag:
            # タスクがそのコンテキストで許可さ��ている��確認
            # (簡易実装: context_tag が "internal" なら "external" タスクを弾くなど)
            pass
        
        # === Phase 1: フェーズベースフィルタリング (CTFモード限定) ===
        current_mode = self.context.target_info.get("mode", "bugbounty")
        
        if current_mode == "ctf":
            from src.core.engine.agent_registry import is_agent_available
            
            # CTFモードではWeb限定（ユーザー要件）
            context_tag = "web"
            
            if not is_agent_available(task.agent_type, context_tag):
                logger.warning(
                    f"Agent '{task.agent_type}' is not available in CTF {context_tag} context. "
                    f"Filtering applied to prevent context pollution."
                )
                return {
                    "success": False,
                    "task_id": task.id,
                    "agent": task.agent_type,
                    "error": f"Agent filtered: not available in {context_tag} context",
                }
        
        # ワークスペースパスの取得
        workspace_root = str(self.workspace.base) if self.workspace else None

        # === Phase 1.2: New Worker Dispatch (Shigoku v2) ===
        from src.core.swarm.worker.factory import get_worker_factory
        worker_factory = get_worker_factory(self.accumulated_context, self.llm_client, self.network_client)
        worker = worker_factory.create_worker(task.agent_type)
        
        if worker:
            logger.info(f"Dispatching to Worker: {task.agent_type} (Unified Architecture)")
            # Worker実行 (Worker.execute は同期、将来的に非同期化される可能性を考慮)
            import inspect
            res = worker.execute(task)
            if inspect.isawaitable(res):
                worker_result = await res
            else:
                worker_result = res
            
            # TaskResult (Swarm/Worker) を MC 互換の dict に変換して返す
            return {
                "success": worker_result.success,
                "task_id": task.id,
                "agent": task.agent_type,
                "data": worker_result.data,
                "error": worker_result.error,
                "findings": worker_result.findings,
                "is_swarm": True # Marking it as new swarm/worker type
            }

        # === Phase 1.5: Swarm ディスパッチ ===
        # 明示 agent_type を優先し、互換目的で agent_type 未指定時のみ tags で補完する
        task_params = task.params if isinstance(task.params, dict) else {}
        normalized_agent_type = str(task.agent_type or "").strip().lower()
        has_tags = bool(task_params.get("tags"))
        if normalized_agent_type == "swarm" or (not normalized_agent_type and has_tags):
            try:
                from src.core.engine.swarm_dispatcher import get_swarm_dispatcher
                # Config/Network/LLM/Loop を渡して Dispatcher を取得し、タスクを実行 (Dependency Injection)
                dispatcher = get_swarm_dispatcher(
                    config=self.project_manager.config if self.project_manager else {},
                    network_client=self.network_client,
                    llm_client=self.llm_client,
                    loop=self._get_loop(),
                    event_bus=self.event_bus
                )
                # RecipeLoader/RAG を Swarm に渡す (MC から移行)
                if self.recipe_loader:
                    dispatcher.set_recipe_loader(self.recipe_loader)
                if self.rag:
                    dispatcher.set_rag(self.rag)
                
                # RAGから関連情報を取得 (Tier 4: Agentic RAG 統合)
                # Note: This block is placed here based on the provided Code Edit snippet's context.
                # The instruction mentioned `_get_initial_context`, but the provided code snippet
                # clearly indicates insertion within `_dispatch` after `dispatcher.set_rag(self.rag)`.
                # Assuming the Code Edit's context is the primary guide for placement.
                if self.agentic_rag:
                    logger.info("[MasterConductor] Using Agentic RAG for initial context...")
                    # 'target' variable needs to be defined for this to work.
                    # Assuming 'target' is available from task.params or self.context.target_info
                    target = task.params.get("target", self.context.target_info.get("target", ""))
                    rag_results = await self.agentic_rag.retrieve_with_feedback(
                        query=target,
                        goal=f"Initial reconnaissance and attack surface mapping for {target}"
                    )
                elif self.rag:
                    target = task.params.get("target", self.context.target_info.get("target", ""))
                    rag_results = await self.rag.retrieve(target)
                else:
                    rag_results = []

                tags = task.params.get("tags", [])
                target = task.params.get("target", self.context.target_info.get("target", ""))
                
                # 非同期実行 (Safe thread execution)
                try:
                    result = await dispatcher.dispatch(
                        tags=tags,
                        target=target,
                        task_name=task.name,
                        params=task.params,
                    )
                except Exception as e:
                    logger.error(f"Swarm execution error: {e}")
                    result = None
                
                if result:
                    # SwarmResult を MC 形式に変換
                    return {
                        "success": result.status in ["success", "partial_success"],
                        "task_id": task.id,
                        "agent": result.swarm_name,
                        "data": {
                            "findings": [f.to_dict() for f in result.findings],
                            "execution_log": result.execution_log,
                            "total_specialists": result.total_specialists,
                            "successful_specialists": result.successful_specialists,
                        },
                        "findings": result.findings,  # Finding オブジェクトも含む
                    }
                # result が None の場合、フォールバックして通常のエージェント実行へ
                logger.info(f"No matching swarm for task {task.id}, falling back to agent dispatch")
                
            except Exception as e:
                logger.error(f"Swarm dispatch error: {e}")
                # エラー時もフォールバック
                pass

        # === Phase 2: 特殊ツールの直接呼び出し ===
        # Cartographer/Fingerprinterは通常のクラスであり、
        # AgentRegistryに登録されていないため直接呼び出す
        
        if task.agent_type == "cartographer":
            try:
                from src.core.intel.cartographer import Cartographer
                target = task.params.get("target", self.context.target_info.get("target"))
                logger.info(f"Dispatching Cartographer (Async/Shared) for target: {target}")
                
                # 共有NetworkClientを注入
                cartographer = Cartographer(target, network_client=self.network_client, max_depth=3, max_pages=100)
                try:
                    # Threadから安全にAsync実行
                    sitemap = self._run_async_safe(cartographer.map_site())
                finally:
                    cartographer.close()
                return {
                    "success": True,
                    "task_id": task.id,
                    "agent": "cartographer",
                    "data": {"nodes_count": len(sitemap.nodes), "endpoints": sitemap.get_endpoints()[:20]},
                    "new_assets": sitemap.get_endpoints(),
                }
            except Exception as e:
                logger.error(f"Cartographer execution error: {e}")
                return {"success": False, "task_id": task.id, "agent": "cartographer", "error": str(e)}
        
        if task.agent_type == "fingerprinter":
            try:
                from src.core.intel.fingerprinter import Fingerprinter
                target = task.params.get("target", self.context.target_info.get("target"))
                logger.info(f"Dispatching Fingerprinter (Shared Session) for target: {target}")
                
                fingerprinter = Fingerprinter()
                # 共有NetworkClientを使用して非同期リクエスト
                resp = self._run_async_safe(self.network_client.request("GET", target, timeout=15))
                
                if resp and resp.is_success:
                    techs = fingerprinter.identify(resp.body, resp.headers)
                    tech_names = [t.name for t in techs] if techs else []
                    
                    # 知識グラフへの反映などは上位で処理される前提
                    return {
                        "success": True,
                        "task_id": task.id,
                        "agent": "fingerprinter",
                        "data": {"technologies": tech_names, "tech_details": [vars(t) for t in techs]},
                        "findings": tech_names
                    }
                else:
                    return {"success": False, "task_id": task.id, "agent": "fingerprinter", "error": f"Failed to fetch target: {target}"}
            except Exception as e:
                logger.error(f"Fingerprinter execution error: {e}")
                return {"success": False, "task_id": task.id, "agent": "fingerprinter", "error": str(e)}

        # === Phase 3: Recon Master (Parallel Pipeline) ===
        if task.agent_type == "recon_master":
            # 重複実行防止: Reconは1回のみ実行
            if hasattr(self, "_recon_executed") and self._recon_executed:
                logger.warning("Recon already executed. Skipping duplicate recon_master task.")
                return {
                    "success": True,
                    "task_id": task.id,
                    "agent": "recon_master",
                    "skipped": True,
                    "reason": "Recon already executed"
                }
                
            try:
                from src.recon.pipeline import ReconPipeline
                
                target = task.params.get("target", self.context.target_info.get("target"))
                if not target:
                    return {"success": False, "task_id": task.id, "error": "Target not specified"}

                logger.info(f"Dispatching ReconPipeline for target: {target}")
                
                # ReconPipeline 初期化 (MC を渡す)
                pipeline = ReconPipeline(
                    config=settings.model_dump() if hasattr(settings, "model_dump") else settings.dict(),
                    workspace_root=self.project_manager.project_dir if self.project_manager else workspace_root,
                    project_manager=self.project_manager,
                    master_conductor=self
                )
                
                # 実行
                # パラメータでステップ指定があれば従う（デフォルトは全ステップ）
                start_step = int(task.params.get("start_step", 1))
                end_step = int(task.params.get("end_step", 8))
                
                # 非同期実行 (別スレッドの独自ループで実行)
                def _run_pipeline_isolated():
                    import asyncio
                    new_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(new_loop)
                    try:
                        return new_loop.run_until_complete(
                            pipeline.run(target, start_step=start_step, end_step=end_step)
                        )
                    finally:
                        new_loop.close()

                # NOTE:
                # Run isolated recon in a worker thread without blocking the main asyncio loop.
                # Blocking here starves other in-batch tasks (e.g. scope_parser) and can trigger
                # false timeout cascades.
                state = await asyncio.to_thread(_run_pipeline_isolated)
                
                # PhaseGate にデータを蓄積
                for asset in state.live_subs:
                    self.phase_gate.add_asset(Phase.RECON, asset)
                
                # 技術スタック情報を蓄積
                for tech in state.tech_stack:
                    self.phase_gate.add_tech(Phase.RECON, tech)
                
                # 分類結果を保存
                if state.results:
                    self.phase_gate.set_classified_files(Phase.RECON, state.results)
                    
                    # 成果があれば ATTACK フェーズをアンロック
                    if any(v.get("count", 0) > 0 for v in state.results.values()):
                        self.phase_gate.unlock(Phase.ATTACK)
                        logger.info("ATTACK phase unlocked due to recon results")
                        
                        # Attack タスクを生成(サブエージェント生成)
                        attack_tasks = self._create_attack_tasks_from_recon(state.results)
                        if attack_tasks:
                            self._add_tasks(attack_tasks, source="recon_result")
                            logger.info(f"Added {len(attack_tasks)} attack tasks to queue")
                
                # Recon実行完了フラグをセット（重複実行防止）
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
                        "results": state.results  # 分類結果を追加
                    },
                    "new_assets": state.live_subs # 新規サブドメインを資産として追加
                }
            except Exception as e:
                logger.error(f"ReconPipeline execution error: {e}")
                return {"success": False, "task_id": task.id, "agent": "recon_master", "error": str(e)}

        # Phase 8: Optimized Recipe Execution
        if task.action == "run_recipe":
            logger.info(f"Executing optimized recipe: {task.params.get('recipe_name')}")
            try:
                return await self._execute_recipe_task(task)
            except Exception as e:
                logger.error(f"Recipe execution error: {e}")
                return {"success": False, "error": str(e)}

        # エージェント生成
        effective_model = task.params.get("model") or getattr(settings, "security_agent_model", settings.model)
        try:
            agent = AgentFactory.create_agent(
                task.agent_type,
                mode=self.context.target_info.get("mode", "security"),
                model=effective_model,
                tools=task.params.get("tools"),
                workspace_root=workspace_root,
                project_manager=self.project_manager,
                master_conductor=self
            )
        
            logger.info(f"Dispatching task {task.id} to agent {task.agent_type}")
        
            # 実行方式を判定
            result_data = None
        
            # Context-Aware Cookie Injection
            from src.core.infra.network_client import current_scan_cookies
        
            # Parse cookies from context (string "k=v; k2=v2" -> dict)
            context_auth_headers = self._get_context_auth_headers()
            raw_cookies = self._get_context_cookie_string()
            cookie_dict = {}
            if raw_cookies:
                try:
                    from http.cookies import SimpleCookie
                    cookie = SimpleCookie()
                    cookie.load(raw_cookies)
                    cookie_dict = {k: v.value for k, v in cookie.items()}
                except Exception as e:
                    logger.warning(f"Failed to parse cookies: {e}")

            token = current_scan_cookies.set(cookie_dict)
        
            # Inject auth headers into task params for Agents (Phase 3 Spec)
            if context_auth_headers:
                task_auth_headers = task.params.get("auth_headers", {})
                if not isinstance(task_auth_headers, dict):
                    task_auth_headers = {}
                task_auth_headers.update(context_auth_headers)
                task.params["auth_headers"] = task_auth_headers
                logger.debug(
                    "Injected context auth headers into task %s: %s",
                    task.id,
                    sorted(task_auth_headers.keys()),
                )

            resolved_target = self._resolve_task_target(task)
            if resolved_target:
                task.target = resolved_target
                task.params["target"] = resolved_target
        
            try:
                # 1. Swarmエージェント (execute()メソッドを持つ)
                if hasattr(agent, 'execute'):
                    logger.debug(f"Using execute() method for {task.agent_type}")
                    try:
                        # 実行 (Safe thread execution to avoid 'asyncio.run() from running loop' error)
                        logger.info(f"⏳ Executing {task.agent_type}.execute() for task {task.id}")
                        result = await agent.execute(
                            target=resolved_target or task.params.get("target"),
                            params=task.params
                        )
                        logger.info(f"✅ {task.agent_type}.execute() completed for task {task.id}")
                    except TypeError as e:
                        # エージェントごとの execute シグネチャ差異を吸収するフォールバック
                        error_msg = str(e)
                        handled = False

                        if "unexpected keyword argument" in error_msg:
                            try:
                                from src.tools.builtin.handoff import HandoffContext
                                context_payload = dict(task.params or {})
                                context_target = context_payload.get("target") or task.target
                                if context_target:
                                    context_payload["target"] = context_target
                                logger.warning(
                                    "%s execute signature mismatch (%s). Retrying with HandoffContext.",
                                    task.agent_type,
                                    error_msg,
                                )
                                result = await agent.execute(HandoffContext.from_params(context_payload))
                                handled = True
                            except Exception as context_exc:
                                logger.debug("HandoffContext fallback failed for %s: %s", task.agent_type, context_exc)

                        if not handled and "unexpected keyword argument 'params'" in error_msg:
                            logger.warning(f"{task.agent_type} does not accept 'params'. Retrying without it.")
                            result = await agent.execute(target=resolved_target or task.params.get("target"))
                            handled = True

                        if not handled and "unexpected keyword argument 'target'" in error_msg:
                            logger.warning(f"{task.agent_type} does not accept 'target'. Retrying with params only.")
                            result = await agent.execute(params=task.params)
                            handled = True

                        if not handled:
                            raise
                
                
                    # HandoffContextを辞書に変換
                    if hasattr(result, 'to_dict'):
                        result_data = result.to_dict()
                    elif hasattr(result, '__dict__'):
                        result_data = vars(result)
                    else:
                        result_data = {"result": str(result)}
            
                # 1.5. 新しい run() メソッド (ToolExecutorAgentなど)
                elif hasattr(agent, 'run') and not getattr(agent, 'force_process', False):
                    # run() は辞書を受け取り、辞書を返す新しい標準インターフェース
                    logger.debug(f"Using run() method for {task.agent_type}")
                
                    try:
                        # Taskオブジェクトを辞書に変換して渡す
                        task_dict = task.to_dict()
                        if "params" not in task_dict:
                             task_dict["params"] = task.params
                        if not task_dict.get("target"):
                            task_dict["target"] = resolved_target
                        task_params = task_dict.get("params", {})
                        if isinstance(task_params, dict) and resolved_target and not task_params.get("target"):
                            task_params["target"] = resolved_target

                        # Safe thread execution
                        logger.info(f"⏳ Executing {task.agent_type}.run() for task {task.id}")
                        result_data = await agent.run(task_dict)
                        logger.info(f"✅ {task.agent_type}.run() completed for task {task.id}")
                    
                        # 結果が辞書でない場合も可能なら構造化データとして保持
                        if not isinstance(result_data, dict):
                            if hasattr(result_data, 'to_dict'):
                                result_data = result_data.to_dict()
                            elif hasattr(result_data, '__dict__'):
                                result_data = vars(result_data)
                            else:
                                result_data = {"output": str(result_data), "task_params": task.params}

                    except Exception as e:
                        import traceback
                        logger.error(f"Async execution error in run(): {e}\n{traceback.format_exc()}")
                        result_data = {"error": str(e), "task_params": task.params}

                # 2. BaseAgent系 (process()メソッドを持つ)
                elif hasattr(agent, 'process'):
                    logger.debug(f"Using process() method for {task.agent_type}")
                    import json
                    task_input = json.dumps(task.params)
                
                    try:
                        # Safe thread execution
                        logger.info(f"⏳ Executing {task.agent_type}.process() for task {task.id}")
                        result_text = await agent.process(task_input)
                        logger.info(f"✅ {task.agent_type}.process() completed for task {task.id}")
                    except Exception as e:
                        import traceback
                        logger.error(f"Async execution error: {e}\n{traceback.format_exc()}")
                        result_text = f"Error: {e}"
                
                    result_data = {
                        "output": result_text,
                        "task_params": task.params
                    }
            
                else:
                    # 未知のエージェントタイプ
                    logger.warning(f"Agent {task.agent_type} has no execute() or process() method")
                    result_data = {
                        "error": "Unsupported agent type",
                        "agent_type": task.agent_type
                    }
            finally:
                # 1. クッキーリセット
                if token:
                    current_scan_cookies.reset(token)
                
                # 2. エージェントのリソース解放
                if agent and hasattr(agent, 'close'):
                    try:
                        logger.debug(f"Closing agent: {task.agent_type}")
                        # デッドロック防止: _run_async_safeを使わず直接awaitする
                        import inspect
                        if inspect.iscoroutinefunction(agent.close) or inspect.isawaitable(getattr(agent, 'close', None)):
                            await agent.close()
                        else:
                            agent.close()
                    except Exception as e:
                        logger.warning(f"Error closing agent {task.agent_type}: {e}")
        
            result_data, extracted_findings = self._augment_payload_with_findings(result_data)
            success_flag = True
            error_message = None
            if isinstance(result_data, dict):
                inner_success = result_data.get("success")
                if isinstance(inner_success, bool) and ("data" in result_data or "error" in result_data):
                    success_flag = inner_success
                    if not inner_success:
                        error_message = str(result_data.get("error") or "Agent reported failure")

            # 共有ワークスペースに保存
            if self.workspace and result_data:
                workspace_path = self.workspace.save_task_result(task, result_data)
                logger.info(f"Task result saved to workspace: {workspace_path}")

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
            logger.error(f"Failed to import agent {task.agent_type}: {e}")
            return {
                "success": False,
                "task_id": task.id,
                "agent": task.agent_type,
                "error": f"Agent not found: {str(e)}",
            }
        except Exception as e:
            import traceback
            logger.error(f"Task execution error in {task.agent_type}: {e}\n{traceback.format_exc()}")
            return {
                "success": False,
                "task_id": task.id,
                "agent": task.agent_type,
            "error": str(e),
        }

    def _get_context_auth_headers(self) -> dict[str, str]:
        return self._seed_service.get_context_auth_headers()

    def _get_context_cookie_string(self) -> str:
        return self._seed_service.get_context_cookie_string()

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
        """
        Smart Parallel Execution with Dependency & Decision Awareness
        
        SmartSchedulerを使用して、依存関係と意思決定依存を考慮した並列実行を行う。
        
        Args:
            max_workers: 同時実行タスク数の上限
        
        Returns:
            実行結果サマリー
        """
        scheduler = SmartScheduler(max_workers=max_workers)
        
        # 既存のtask_queueをScheduledTaskに変換してスケジューラに登録
        for task in self.task_queue:
            decision_check = self._create_decision_check_for_task(task)
            
            scheduled_task = ScheduledTask(
                id=task.id,
                name=task.name,
                agent_type=task.agent_type,
                action=task.action,
                params=task.params,
                priority=task.priority,
                depends_on=[task.parent_id] if task.parent_id else [],
                decision_check=decision_check,
            )
            scheduler.add_task(scheduled_task)
        
        # Execution Contextをスケジューラと共有
        scheduler.execution_context = {
            "tech_stack": self.context.target_info.get("tech_stack", []),
            "auth_required": self.context.target_info.get("auth_required", True),
            "discovered_assets": self.context.discovered_assets,
            "bypass_methods": self.context.bypass_methods,
        }
        
        # Task実行関数（asyncラッパー）
        async def task_executor(scheduled_task: ScheduledTask) -> dict:
            original_task = Task(
                id=scheduled_task.id,
                name=scheduled_task.name,
                agent_type=scheduled_task.agent_type,
                action=scheduled_task.action,
                params=scheduled_task.params,
                priority=scheduled_task.priority,
            )
            
            # _dispatch は async 関数なので直接 await する
            result = await self._dispatch(original_task)
            
            if result.get("success"):
                self.context.update_success_rate(True)
                if result.get("new_assets"):
                    self.context.discovered_assets.extend(result["new_assets"])
                if result.get("bypass_method"):
                    self.context.add_bypass_method(result["bypass_method"])
                if result.get("technologies"):
                    scheduler.update_context("tech_stack", 
                        self.context.target_info.get("tech_stack", []) + result["technologies"])
            else:
                self.context.update_success_rate(False)
            
            return result
        
        logger.info("Starting parallel execution with %d tasks (max_workers=%d)", 
                    len(scheduler.tasks), max_workers)
        summary = await scheduler.run(task_executor)
        
        for task_id, scheduled_task in scheduler.tasks.items():
            original_task = Task(
                id=scheduled_task.id,
                name=scheduled_task.name,
                agent_type=scheduled_task.agent_type,
                action=scheduled_task.action,
                params=scheduled_task.params,
                state=TaskState(scheduled_task.state.value),
                result=scheduled_task.result,
                error=scheduled_task.error,
                priority=scheduled_task.priority,
            )
            self.completed_tasks.append(original_task)
        
        return summary
    
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
        failed_reason_codes: dict[str, int] = {}
        failed_failure_categories: dict[str, int] = {}
        unknown_failure_count = 0
        for task in self.completed_tasks:
            if task.state != TaskState.FAILED:
                continue
            reason_code = str(getattr(task, "failure_reason_code", "") or "").strip()
            if not reason_code:
                reason_code = self._normalize_failure_reason_code(
                    str(getattr(task, "failure_phase", "") or ""),
                    getattr(task, "failure_reason", "") or getattr(task, "error", ""),
                    getattr(task, "error", ""),
                )
                task.failure_reason_code = reason_code
            failed_reason_codes[reason_code] = failed_reason_codes.get(reason_code, 0) + 1
            failure_category = classify_failure_pattern(
                reason_code=reason_code,
                error_message=str(getattr(task, "error", "") or ""),
            )
            failed_failure_categories[failure_category] = failed_failure_categories.get(failure_category, 0) + 1
            if failure_category == "unknown":
                unknown_failure_count += 1
        unknown_rate = unknown_failure_count / failed if failed > 0 else 0.0
        execution_log = getattr(self, "execution_log", None)
        records = execution_log.get_all() if execution_log is not None and hasattr(execution_log, "get_all") else []
        duration_samples = [
            float(d)
            for d in (record.duration_seconds() for record in records)
            if d is not None and d >= 0
        ]
        duration_samples.sort()

        def _percentile(samples: list[float], ratio: float) -> float:
            if not samples:
                return 0.0
            index = int(round((len(samples) - 1) * ratio))
            index = max(0, min(index, len(samples) - 1))
            return float(samples[index])

        p95_seconds = _percentile(duration_samples, 0.95)
        p99_seconds = _percentile(duration_samples, 0.99)
        pr_execution_time_slo = {
            "target_p95_seconds": 900.0,
            "target_p99_seconds": 1200.0,
            "observed_p95_seconds": p95_seconds,
            "observed_p99_seconds": p99_seconds,
            "sample_count": len(duration_samples),
            "insufficient_samples": len(duration_samples) < 100,
            "status": "pass" if p95_seconds <= 900.0 and p99_seconds <= 1200.0 else "fail",
        }
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
            "failed_reason_codes": dict(sorted(failed_reason_codes.items(), key=lambda kv: (-kv[1], kv[0]))),
            "failed_failure_categories": dict(sorted(failed_failure_categories.items(), key=lambda kv: (-kv[1], kv[0]))),
            "unknown_failure_count": unknown_failure_count,
            "unknown_rate": unknown_rate,
            "quarantined_signatures": len(getattr(self, "_quarantined_signatures", {})),
            "pr_execution_time_slo": pr_execution_time_slo,
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
        """
        現在の状態をセッションに保存（チェックポイント）
        
        タスク完了ごとに呼び出され、進捗をディスクに永続化する。
        """
        if not self._session_manager or not self._current_session:
            return
        
        pending_targets, completed_targets, metadata = build_checkpoint_session_state(
            task_queue=self.task_queue,
            completed_tasks=self.completed_tasks,
            context=self.context,
            pending_hitl=getattr(self, "pending_hitl", []),
        )
        self._current_session.pending_targets = pending_targets
        self._current_session.completed_targets = completed_targets
        self._current_session.metadata = metadata
        
        self._session_manager.save_session(self._current_session)
        logger.debug(f"Checkpoint saved: {len(self.task_queue)} pending, {len(self.completed_tasks)} completed")
    
    def resume_session(self, session_id: str) -> bool:
        """
        保存されたセッションから再開
        
        Args:
            session_id: 再開するセッションID
        
        Returns:
            成功した場合True
        """
        if not self._session_manager:
            logger.error("SessionManager not configured")
            return False
        
        session = self._session_manager.resume_session(session_id)
        if not session:
            logger.error(f"Session not found: {session_id}")
            return False
        
        self._current_session = session
        restored = restore_legacy_resume_session_state(session)
        failed_tasks = apply_restored_session_state(
            restored=restored,
            context=self.context,
            pending_hitl=self.pending_hitl,
            task_queue=self.task_queue,
        )
        if failed_tasks:
            logger.warning(f"{len(failed_tasks)} tasks could not be restored")
        
        if session.target_url:
            self.initialize_workspace(session.target_url)
        
        logger.info(f"Session resumed: {session_id} with {len(self.task_queue)} pending tasks")
        return True
    
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
