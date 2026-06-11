"""
Active probe policy / degradation / pre-action shadow policy 判定サービス。

MasterConductor facade から受け取った callable 群を使って
純粋判定・report builder を提供する。audit_logger / decision_tracer /
execution_log / task_queue への最終書き込みは facade 側が担当する。

依存方向: master_conductor.py -> master_conductor_policy_service.py -> なし
service は MasterConductor instance を保持せず、必要な依存は
snapshot、明示引数、または callable として受け取る。

サービス構造:
- pure evaluator: 0 callable。dict in → dict out
- policy resolver: 2-3 callable。runtime_policy/context → policy dict
- audit payload builder: 判定結果 → audit details dict (副作用なし)
- shadow report builder: findings + chain_builder → shadow report dict

代表テストファイル:
- tests/core/engine/test_master_conductor_phase1_step14.py
- tests/core/engine/test_master_conductor_phase1_step15.py
- tests/core/engine/test_master_conductor_phase25_shadow.py
- tests/core/intelligence/test_phase2_risk_clearance_checklist.py

禁止依存:
- master_conductor.py への import 禁止
- close/shutdown 対象 resource の保持禁止
- task_queue / execution_log / audit_logger への直接書き込み禁止
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from src.core.models.finding import Finding
from src.core.waf.bypasser import WAFBypasser


# ── Pure Evaluators ────────────────────────────────────────────────────
# dict in → dict out。self 参照なし。side-effect なし。


def evaluate_active_probe_policy(
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


def rank_missing_link_targets_by_information_gain(
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


def sanitize_active_probe_policy(
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


def normalize_workflow_template(raw_template: Optional[dict[str, Any]]) -> dict[str, Any]:
    template = raw_template if isinstance(raw_template, dict) else {}
    return {
        "template_id": str(template.get("template_id", "") or ""),
        "steps": [str(step) for step in (template.get("steps") or []) if str(step).strip()],
        "source": str(template.get("source", "") or ""),
    }


def assess_missing_link_probe_rollout(
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


def build_race_profile(mode: str = "interval") -> dict[str, Any]:
    normalized = str(mode or "interval").strip().lower()
    profiles = {
        "burst": {"mode": "burst", "burst": 3, "interval_ms": 0, "order_permutations": 2},
        "interval": {"mode": "interval", "burst": 1, "interval_ms": 250, "order_permutations": 1},
        "ordered": {"mode": "ordered", "burst": 1, "interval_ms": 100, "order_permutations": 3},
    }
    return dict(profiles.get(normalized, profiles["interval"]))


def build_safe_probe_variations(
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


def evaluate_phase2_operational_mode(
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


def build_degradation_component_contract() -> dict[str, dict[str, str]]:
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


# ── Policy Resolvers ──────────────────────────────────────────────────
# Callable を注入して self 依存を解決する。


def resolve_active_probe_policy_for_program(
    *,
    context_target_info: Optional[dict[str, Any]],
    sanitize: Callable[..., dict[str, Any]],
    resolve_default: Callable[[], dict[str, Any]],
    runtime_policy: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    target_info = context_target_info or {}
    program_policy = (
        target_info.get("program_probe_policy", {})
        if isinstance(target_info, dict)
        else {}
    )
    if isinstance(program_policy, dict) and program_policy:
        return sanitize(
            program_policy,
            source="program_override",
            include_source=runtime_policy is not None,
        )
    if isinstance(runtime_policy, dict) and runtime_policy:
        return sanitize(
            runtime_policy,
            source="runtime_flag",
            include_source=True,
        )
    resolved = resolve_default()
    return sanitize(
        resolved,
        source="config_default",
        include_source=True,
    )


def build_probe_runtime_context_from_chain_finding(
    finding_info: Optional[dict[str, Any]],
    *,
    sanitize: Callable[..., dict[str, Any]],
    normalize_template: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    info = finding_info if isinstance(finding_info, dict) else {}
    raw_policy = info.get("resolved_tactical_policy", {})
    source = (
        str(raw_policy.get("source", "runtime_flag") or "runtime_flag")
        if isinstance(raw_policy, dict)
        else "runtime_flag"
    )
    return {
        "runtime_policy": sanitize(
            raw_policy,
            source=source,
            include_source=True,
        ),
        "workflow_template": normalize_template(
            info.get("resolved_workflow_template", {})
        ),
    }


# ── Decision Functions ─────────────────────────────────────────────────


def resolve_component_degradation(
    component_status: dict[str, str],
    component_contract: Optional[dict[str, dict[str, str]]] = None,
) -> dict[str, Any]:
    if component_contract is None:
        component_contract = build_degradation_component_contract()

    normalized_status = {
        str(component).strip(): str(status).strip().lower()
        for component, status in dict(component_status or {}).items()
        if str(component).strip()
    }
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


def resolve_active_probe_policy_default(settings: Any) -> dict[str, Any]:
    """デフォルト resolve（settings のみを使用）。"""
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


# ── Audit Payload Builders (純粋: audit dict を返すのみ、audit_logger への書き込みはしない) ──


def build_chain_audit_details(
    chain: dict[str, Any],
    audit_context: dict[str, Any],
) -> dict[str, Any]:
    """chain audit 用の details dict を構築する（decision_tracer/audit_logger 非依存）。"""
    return {
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


def build_degradation_audit_details(
    component_status: dict[str, str],
    degradation_result: dict[str, Any],
    audit_context: dict[str, Any],
) -> dict[str, Any]:
    """degradation audit 用の details dict を構築する（decision_tracer/audit_logger 非依存）。"""
    normalized_status = {
        str(component).strip(): str(status).strip().lower()
        for component, status in dict(component_status or {}).items()
        if str(component).strip()
    }
    return {
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
