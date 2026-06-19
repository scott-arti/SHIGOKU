"""
MasterConductor: 動的リプラン司令塔 (compatibility shim)

SGK-2026-0287 Phase 1: This module is now a re-export shim.
The canonical class definitions (MasterConductor, ExecutionContext)
live in master_conductor_facade.py.

Existing import paths remain functional:
    from src.core.engine.master_conductor import MasterConductor, Task, TaskState, ...
"""

# ======== Module-level imports retained for monkeypatch compatibility ========
# Tests patch names in this module's namespace. Keeping these imports ensures
# patches like `patch("src.core.engine.master_conductor.settings")` continue to
# resolve, even if the consuming code now lives in master_conductor_facade.py.
# Full caller migration to `master_conductor_facade` target is deferred to Phase 2-5.

import asyncio
import copy
import hashlib
import json
import logging
import threading
import time
import uuid
from collections import deque
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

from src.config import settings
from src.commands import print_step, print_result
from src.core.engine.attack_planner import AttackPlanner
from src.core.engine.intervention_policy import InterventionPolicy
from src.core.engine.master_conductor_dispatch_service import (
    dispatch_cartographer as _svc_dispatch_cartographer,
    dispatch_ctf_filter as _svc_dispatch_ctf_filter,
    dispatch_fingerprinter as _svc_dispatch_fingerprinter,
    dispatch_post_exploit_guard as _svc_dispatch_post_exploit_guard,
    dispatch_recipe_check as _svc_dispatch_recipe_check,
    dispatch_scope_verification_fast_path as _svc_dispatch_scope_verification_fast_path,
    dispatch_swarm as _svc_dispatch_swarm,
    dispatch_worker as _svc_dispatch_worker,
    execute_agent_dispatch as _svc_execute_agent_dispatch,
    run_recon_pipeline_isolated,
)
from src.core.engine.master_conductor_execution_plan_service import (
    build_batch_execution_plan,
    build_batch_result_apply_plan,
    build_dispatch_timeout_decision,
    build_failure_replan_decision,
    build_timeout_recovery_plan,
    is_timeout_related as _svc_is_timeout_related,
)
from src.core.engine.master_conductor_execution_runner_service import (
    build_execution_record_init,
    build_task_started_payload,
    build_task_state_event_payload,
    compute_batch_size,
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
from src.core.engine.master_conductor_hitl_service import HitlService
from src.core.engine.master_conductor_hitl_snapshot import snapshot_task_for_hitl
from src.core.engine.master_conductor_hitl_ticket import build_pending_hitl_ticket
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
from src.core.engine.master_conductor_recon_seed_target_service import ReconSeedTargetService
from src.core.engine.master_conductor_scenario_coverage_service import (
    create_missing_core_scenario_probe_tasks as _service_create_missing_core_scenario_probe_tasks,
    evaluate_intervention_scenario_coverage as _service_evaluate_intervention_scenario_coverage,
    has_scenario_in_queue_or_history as _service_has_scenario_in_queue_or_history,
    normalize_scenario_id_for_coverage as _service_normalize_scenario_id_for_coverage,
    resolve_intervention_scenario_catalog as _service_resolve_intervention_scenario_catalog,
    task_matches_scenario as _service_task_matches_scenario,
)
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
from src.core.engine.master_conductor_summary_service import (
    compute_duration_percentile,
    compute_failure_aggregation,
)
from src.core.engine.observation_reason import ObservationReason
from src.core.engine.phase_gate import get_phase_gate, Phase
from src.core.engine.recipe_contracts import validate_task_schema
from src.core.engine.skip_reason_registry import normalize_skip_reason
from src.core.engine.smart_scheduler import ScheduledTask, SmartScheduler
from src.core.engine.task_expander import TaskExpander
from src.core.factory import AgentFactory
from src.core.infra.async_writer import AsyncDatabaseWriter
from src.core.infra.event_bus import Event, EventType, get_event_bus
from src.core.infra.knowledge_graph import KnowledgeGraph
from src.core.learning.findings_repository import get_findings_repository
from src.core.models.finding import Finding, VulnType
from src.core.models.task_execution_log import TaskExecutionRecord
from src.core.notifications.notifier import Notifier, get_notifier
from src.core.observability.flaky_quarantine import (
    FlakyQuarantinePolicy,
    FlakyQuarantineTracker,
    resolve_flaky_policy_from_settings,
)
from src.core.observability.phase1_contracts import generate_correlation_ids, ensure_observability_fields
from src.core.observability.phase2_classification import classify_failure_pattern
from src.core.utils.async_utils import SharedLoopManager, safe_run_async, safe_run_async_forget
from src.core.workspace.shared_workspace import SharedWorkspace

# DebugLogger (optional)
try:
    from src.core.debug_logger import get_debug_logger
    HAS_DEBUG_LOGGER = True
except ImportError:
    HAS_DEBUG_LOGGER = False

# ======== SCN catalog (referenced externally) ========
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


# ======== Compatibility shim re-exports (SGK-2026-0287 Phase 1) ========
# The canonical class definitions live in master_conductor_facade.py.
# This module re-exports them so existing import paths continue to work.

from src.core.engine.master_conductor_facade import ExecutionContext, MasterConductor  # noqa: E402, F401

# Re-exports from canonical source modules for external consumers
# (previously transitively available via master_conductor.py's own imports)
from src.core.domain.model.task import Task, TaskState  # noqa: E402, F401
from src.core.infra.event_bus import Event, EventType  # noqa: E402, F401
from src.core.intel.cartographer import SiteNode  # noqa: E402, F401
from src.core.models.finding import Finding  # noqa: E402, F401
