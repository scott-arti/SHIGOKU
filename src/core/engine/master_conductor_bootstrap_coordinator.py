"""
MasterConductor bootstrap coordinator (SGK-2026-0294/0299).

Handles recipe injection, pre-action risk gate, and __init__ wiring.
Takes facade reference as parameter. Does NOT hold MasterConductor instance.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Optional

from src.core.domain.model.task import Task
from src.core.infra.event_bus import Event, EventType, get_event_bus
from src.config import settings

_log = logging.getLogger(__name__)


def inject_heuristic_swarm_tasks_coordinator(facade: Any, new_techs: list[str] | None = None) -> None:
    """Inject heuristic Swarm tasks from discovery URLs (SGK-2026-0294, renamed SGK-2026-0260 Step 2).

    Creates Swarm dispatch tasks (Gate 5) based on URL-pattern heuristics.
    This is NOT the recipe selection path (Gate 9) — it bypasses RecipeLoader
    entirely and generates direct Swarm tasks for auth_ninja and
    api_spec_reconstruct workflows.

    Naming history: was `inject_recipes_coordinator` (misleading — never
    injected YAML Recipes).  Renamed `inject_heuristic_swarm_tasks_coordinator`
    to accurately reflect that this creates Swarm tasks, not Recipe tasks.
    """
    tasks_to_add: list = []
    tech_stack = new_techs if new_techs is not None else facade.context.target_info.get("tech_stack", [])
    discovered_urls = facade.context.target_info.get("discovered_urls", [])
    target_url = facade.context.target_info.get("target", "")

    def gen_task_id(prefix: str, salt: str = "") -> str:
        return f"{prefix}_{hashlib.md5(f'{prefix}:{target_url}:{salt}'.encode()).hexdigest()[:8]}"

    auth_patterns = ["login", "signin", "auth", "session", "oauth", "sso", "password"]
    auth_urls = [u for u in discovered_urls if any(p in u.lower() for p in auth_patterns)]
    if auth_urls:
        tasks_to_add.append(Task(id=gen_task_id("auth_ninja", f"len:{len(auth_urls)}"),
            name=f"AuthNinja ({len(auth_urls)} URLs)", agent_type="swarm", action="execute",
            params={"target": target_url, "auth_urls": auth_urls, "swarm_recipe": "auth_ninja"}, priority=85))

    api_patterns = ["/api/", "/graphql", "/v1/", "/v2/", "/rest/", ".json", "swagger"]
    api_urls = [u for u in discovered_urls if any(p in u.lower() for p in api_patterns)]
    if api_urls:
        tasks_to_add.append(Task(id=gen_task_id("api_spec", f"len:{len(api_urls)}"),
            name=f"API Spec ({len(api_urls)} URLs)", agent_type="swarm", action="execute",
            params={"target": target_url, "api_urls": api_urls, "swarm_recipe": "api_spec_reconstruct"}, priority=80))

    if tasks_to_add:
        facade._add_tasks(tasks_to_add, source="heuristic_swarm_injection")
        _log.info("Injected %d recipe-based tasks", len(tasks_to_add))


def run_pre_action_gate_coordinator(
    facade: Any, task: Task, result: dict, exec_record: Any = None,
) -> Optional[dict]:
    """Pre-action risk gate. Extracted from facade._run_pre_action_risk_gate."""
    from src.core.intelligence import RiskLevel
    try:
        risk_assessment = facade.risk_predictor.assess(task)
    except Exception as e:
        _log.warning("RiskPredictor failed: %s", e)
        return None
    if risk_assessment.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        block_msg = f"Pre-action gate blocked: risk={risk_assessment.risk_level.value}"
        task.state = getattr(Task, 'SKIPPED', 'SKIPPED')
        task.error = block_msg
        facade._record_failure_context(task, "pre_action_gate", "high_risk_blocked")
        return {"success": True, "skipped": True, "pending_hitl": False, "message": block_msg}
    return None


def bootstrap_wiring(
    facade: Any,
    debug_enabled: bool = False,
    human_approval_callback: Any = None,
    session_manager: Any = None,
) -> None:
    """Bootstrap MasterConductor wiring after core deps initialized.

    Extracted from facade.__init__ (SGK-2026-0299).
    Takes facade reference. Does NOT hold MasterConductor instance.
    """
    import signal
    from collections import deque
    from src.core.engine.master_conductor_facade import ExecutionContext
    from src.core.observability.phase1_contracts import generate_correlation_ids
    from src.core.engine.attack_planner import AttackPlanner
    from src.core.models.finding import Finding
    from src.core.engine.master_conductor_hitl_service import HitlService
    from src.core.engine.intervention_policy import InterventionPolicy
    from src.core.infra.event_bus import get_event_bus, EventType
    from src.core.engine.phase_gate import get_phase_gate, Phase

    try:
        from src.core.debug_logger import get_debug_logger
        HAS_DEBUG_LOGGER = True
    except ImportError:
        HAS_DEBUG_LOGGER = False
        get_debug_logger = lambda: None

    facade.attack_planner = AttackPlanner(kg=facade.graph)
    facade.agentic_rag = None
    if facade.rag and facade.llm_client:
        from src.core.intelligence.agentic_rag import AgenticRAGFeedbackLoop
        facade.agentic_rag = AgenticRAGFeedbackLoop(
            rag_client=facade.rag, llm_client=facade.llm_client,
            threshold=getattr(settings, "rag_confidence_threshold", 0.7),
        )

    facade.context = ExecutionContext()
    facade.context.target_info.setdefault("correlation", generate_correlation_ids())

    from src.core.engine.task_queue import DynamicTaskQueue, TaskContext
    from src.core.engine.context_propagator import ContextPropagator
    max_mem = getattr(settings, "task_queue_max_memory", 5000)
    facade.task_queue = DynamicTaskQueue(max_memory_size=max_mem)
    facade.context_propagator = ContextPropagator()
    facade.accumulated_context = TaskContext()

    from src.core.engine.context_designer import ContextDesigner
    facade.context_designer = ContextDesigner()

    from src.core.engine.critical_path_analyzer import CriticalPathAnalyzer
    facade.critical_path_analyzer = CriticalPathAnalyzer()

    from src.core.wordlist.wordlist_manager import get_wordlist_manager
    facade.wordlist_manager = get_wordlist_manager()

    facade.completed_tasks: list = []
    facade.current_task = None
    facade.max_replan_depth = 5
    facade._current_replan_depth = 0
    facade._derived_task_count = 0
    facade._checkpoint_counter = 0
    facade._debug_enabled = debug_enabled and HAS_DEBUG_LOGGER
    facade._debug_logger = get_debug_logger() if facade._debug_enabled else None
    facade.workspace = None

    from src.core.engine.flag_watcher import FlagWatcher
    facade.flag_watcher = FlagWatcher.get_instance()
    facade.flag_watcher.register_pattern(facade.flag_format)
    facade.flag_watcher.register_callback(facade._on_flag_found)

    facade.human_approval_callback = human_approval_callback
    try:
        facade.intervention_policy = InterventionPolicy(settings.get_intervention_scenarios())
    except Exception as e:
        _log.warning("Intervention policy fallback: %s", e)
        facade.intervention_policy = InterventionPolicy({})

    facade._loaded_recipes: set = set()
    facade._session_manager = session_manager
    facade._current_session = None
    facade._recon_executed = False
    facade._injected_task_ids: set = set()
    facade._processed_techs: set = set()
    facade.pending_hitl: list = []

    facade._hitl_service = HitlService(
        pending_hitl=facade.pending_hitl, task_queue=facade.task_queue,
        extract_scn_number=facade._extract_scn_number,
    )

    from src.core.infra.network_client import AsyncNetworkClient
    from src.core.infra.proxy_manager import get_proxy_manager
    facade.network_client = AsyncNetworkClient(proxy_manager=get_proxy_manager(), mode=facade.mode.lower())

    import threading
    facade._state_lock = threading.RLock()
    facade.phase_gate = get_phase_gate()

    from src.tools.custom.notify import NotifyTool
    facade.notify_tool = NotifyTool()

    from src.core.engine.resource_manager import SystemResourceManager
    from src.core.engine.parallel_orchestrator import ParallelOrchestrator
    facade.orchestrator = ParallelOrchestrator()
    facade.resource_manager = SystemResourceManager.get_instance()
    facade.resource_manager.set_orchestrator(facade.orchestrator)
    facade.resource_manager.start()

    signal.signal(signal.SIGINT, facade._handle_signal_shutdown)
    signal.signal(signal.SIGTERM, facade._handle_signal_shutdown)
    facade._shutdown_requested = False
    facade._react_cache = {}
    facade._react_observation_executed_total = 0
    facade._react_observation_executed_by_target: dict = {}
    facade._react_observation_metrics = {"attempted": 0, "executed": 0, "skipped": 0, "skip_reasons": {}}
    facade._react_observation_retry_used = 0
    facade._react_observation_cb_failures = 0
    facade._react_observation_cb_open_until = 0.0
    facade._react_observation_inflight = 0
    facade._react_observation_pending_queue = deque()

    facade._loop = None
    facade._loop_thread = None

    from src.core.engine.error_replanner import ErrorReplanner
    facade.error_replanner = ErrorReplanner(rag_client=facade.rag, llm_client=facade.llm_client)

    from src.core.models.decision_trace import get_decision_tracer
    from src.core.utils.audit_logger import get_audit_logger
    facade.decision_tracer = get_decision_tracer()
    facade.audit_logger = get_audit_logger()

    facade.context_enriched = False
    facade._finished_normally = False
    facade._chain_observation_buffer: list = []
    facade._emitted_attack_chain_keys: set = set()
    facade._chain_state_version: int = 0
    facade._flaky_trackers: dict = {}
    facade._quarantined_signatures: dict = {}
    facade._flaky_success_streaks: dict = {}

    import asyncio
    facade.event_bus = get_event_bus()
    facade.event_bus.subscribe(EventType.SESSION_EXPIRED, facade._handle_session_expired)
    facade.event_bus.subscribe(EventType.REAUTH_SUCCESS, facade._handle_reauth_success)
    facade.event_bus.subscribe(EventType.VULN_FOUND, facade._handle_vuln_found)
    facade.event_bus.subscribe(EventType.VULN_FOUND, facade._handle_vuln_found)
    loop = facade._get_loop()
    asyncio.run_coroutine_threadsafe(facade.event_bus.start(), loop)
