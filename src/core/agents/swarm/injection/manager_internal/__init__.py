"""Internal implementation modules for InjectionManager."""

from src.core.agents.swarm.injection.manager_internal.target_classifier import (
    classify_target_url,
)
from src.core.agents.swarm.injection.manager_internal.target_selection import (
    extract_form_field_names,
    prioritize_targets,
    score_target_priority,
)
from src.core.agents.swarm.injection.manager_internal.execution_policy import (
    cap_phase2_budget,
    is_lane2_score_eligible,
    resolve_per_url_timeout,
    resolve_risk_force_allowlist,
    should_auto_early_return,
    should_force_phase2_by_risk,
)
from src.core.agents.swarm.injection.manager_internal.builtin_probes import (
    run_csrf_minimal_check,
)
from src.core.agents.swarm.injection.manager_internal.admin_check import (
    run_admin_check as run_admin_check_helper,
)
from src.core.agents.swarm.injection.manager_internal.tool_runners import (
    build_hunter_task,
)
from src.core.agents.swarm.injection.manager_internal.unknown_hypotheses import (
    build_unknown_hypotheses,
    build_unknown_idor_candidate_finding,
)
from src.core.agents.swarm.injection.manager_internal.models import (
    DispatchContext,
    NormalizationInput,
    UrlExecutionRequest,
    UrlExecutionResult,
)
from src.core.agents.swarm.injection.manager_internal.specialist_router import (
    SPECIALIST_MAP,
    select_specialists,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_targets import (
    build_nearby_api_candidates,
    dedupe_urls,
    extract_api_like_urls,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_analysis import (
    build_authz_differential,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_evidence import (
    clip_http_text,
    render_http_request,
    render_http_response,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_headers import (
    normalize_header_keys,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_object_ab import (
    run_object_ab_comparison,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_auth_context import (
    resolve_auth_b_context,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_auth_matrix import (
    finalize_auth_context_matrix,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_object_target import (
    build_object_ab_target,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_read_probe import (
    build_fallback_read_probe_url,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_payload import (
    build_mass_assignment_probe_payload,
)
from src.core.agents.swarm.injection.manager_internal.phase1_results import (
    collect_phase1_vuln_types,
    extract_max_ssrf_score,
    has_actionable_blind_signal,
    summarize_low_ssrf_score_breakdown,
    summarize_skip_reason_counts,
    summarize_skip_reason_unknown_counts,
)
from src.core.agents.swarm.injection.manager_internal.result_normalizer import (
    build_process_url_cache_entry,
    build_url_result_from_cache,
    filter_manager_findings,
    infer_detection_class_for_finding,
    normalize_blind_correlation,
    normalize_detection_class_token,
    normalize_findings_additional_info,
    sanitize_tested_params,
    validate_manager_findings,
)

__all__ = [
    "classify_target_url",
    "extract_form_field_names",
    "prioritize_targets",
    "score_target_priority",
    "cap_phase2_budget",
    "is_lane2_score_eligible",
    "resolve_per_url_timeout",
    "resolve_risk_force_allowlist",
    "should_auto_early_return",
    "should_force_phase2_by_risk",
    "run_csrf_minimal_check",
    "run_admin_check_helper",
    "build_hunter_task",
    "build_unknown_hypotheses",
    "build_unknown_idor_candidate_finding",
    "DispatchContext",
    "NormalizationInput",
    "UrlExecutionRequest",
    "UrlExecutionResult",
    "SPECIALIST_MAP",
    "select_specialists",
    "build_nearby_api_candidates",
    "dedupe_urls",
    "extract_api_like_urls",
    "build_authz_differential",
    "clip_http_text",
    "render_http_request",
    "render_http_response",
    "normalize_header_keys",
    "run_object_ab_comparison",
    "resolve_auth_b_context",
    "finalize_auth_context_matrix",
    "build_object_ab_target",
    "build_fallback_read_probe_url",
    "build_mass_assignment_probe_payload",
    "build_process_url_cache_entry",
    "build_url_result_from_cache",
    "filter_manager_findings",
    "infer_detection_class_for_finding",
    "normalize_blind_correlation",
    "normalize_detection_class_token",
    "normalize_findings_additional_info",
    "sanitize_tested_params",
    "validate_manager_findings",
    "collect_phase1_vuln_types",
    "extract_max_ssrf_score",
    "has_actionable_blind_signal",
    "summarize_low_ssrf_score_breakdown",
    "summarize_skip_reason_counts",
    "summarize_skip_reason_unknown_counts",
]
