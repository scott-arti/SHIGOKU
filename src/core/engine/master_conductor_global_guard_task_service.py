"""Global guard task の候補解決と task payload 構築。

CSRF / XSS / OOB の各 global guard target 解決、候補判定、
guard task の params 構築を担当する。
task_queue への enqueue、_injected_task_ids / _derived_task_count の
更新は行わず、payload と判定結果を返すのみ。
"""

import hashlib
import logging
from typing import Any, Callable, Optional

from src.core.agents.swarm.base import Task as SwarmTask

logger = logging.getLogger(__name__)


def _task_has_auth_surface(task: Any) -> bool:
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


# ── guard target resolution ───────────────────────────────────────────


def resolve_global_oob_guard_target(
    *,
    completed_tasks: list[Any],
    task_queue: Any,
    discovered_assets: list[str],
    resolve_task_target: Callable[[Any], Optional[str]],
    normalize_url_candidate: Callable[[str], Optional[str]],
    resolve_in_scope_hosts: Callable[[], list[str]],
) -> str:
    oob_url_tokens = (
        "reset", "verify", "verification", "invite", "activation",
        "otp", "magic", "confirmation", "password",
    )
    auth_candidates: list[str] = []

    def _collect(task: Any) -> None:
        if not _task_has_auth_surface(task):
            return
        candidate = resolve_task_target(task)
        if candidate:
            auth_candidates.append(candidate)

    for task in completed_tasks:
        _collect(task)

    if task_queue is not None:
        try:
            for queued_task in task_queue:
                _collect(queued_task)
        except Exception:
            pass

    for raw in discovered_assets:
        candidate = normalize_url_candidate(str(raw or ""))
        if not candidate or not candidate.startswith(("http://", "https://")):
            continue
        lowered = candidate.lower()
        if any(token in lowered for token in oob_url_tokens):
            auth_candidates.append(candidate)

    normalized_auth_candidates: list[str] = []
    seen: set[str] = set()
    for raw in auth_candidates:
        candidate = normalize_url_candidate(raw)
        if not candidate or candidate in seen:
            continue
        if not candidate.startswith(("http://", "https://")):
            continue
        seen.add(candidate)
        normalized_auth_candidates.append(candidate)

    if not normalized_auth_candidates:
        return ""

    prioritized = [
        candidate
        for candidate in normalized_auth_candidates
        if any(token in candidate.lower() for token in oob_url_tokens)
    ]
    selected = prioritized or normalized_auth_candidates
    return selected[0] if selected else ""


def resolve_global_csrf_guard_target(
    *,
    context_target_info: Optional[dict[str, Any]],
    target_attr: str,
    discovered_assets: list[str],
    task_queue: Any,
    resolve_task_target: Callable[[Any], Optional[str]],
    normalize_url_candidate: Callable[[str], Optional[str]],
    resolve_in_scope_hosts: Callable[[], list[str]],
) -> str:
    raw_candidates: list[str] = []
    if isinstance(context_target_info, dict):
        raw_candidates.append(str(context_target_info.get("target", "") or ""))
    raw_candidates.append(str(target_attr or ""))
    raw_candidates.extend(str(asset or "") for asset in discovered_assets)

    if task_queue is not None:
        try:
            for task in task_queue:
                raw_candidates.append(resolve_task_target(task) or "")
        except Exception:
            pass

    for raw in raw_candidates:
        candidate = normalize_url_candidate(raw)
        if not candidate:
            continue
        if candidate.startswith(("http://", "https://")):
            return candidate

    fallback_hosts = resolve_in_scope_hosts()
    if fallback_hosts:
        fallback_host = str(fallback_hosts[0] or "").strip().lower()
        scheme = "http" if fallback_host in {"127.0.0.1", "localhost"} else "https"
        return f"{scheme}://{fallback_host}/"
    return ""


# ── guard task payload builders ───────────────────────────────────────


def _guard_context_base(
    discovered_assets: list[str],
    target_info: dict[str, Any],
) -> dict[str, Any]:
    return {
        "discovered_endpoints": discovered_assets[:10],
        "auth_tokens": target_info.get("auth_tokens", {}) if isinstance(target_info, dict) else {},
        "discovered_params": [],
        "tech_stack": list(target_info.get("tech_stack", [])) if isinstance(target_info, dict) else [],
        "waf_info": {},
        "critical_findings": [],
    }


def build_csrf_guard_payload(
    *,
    target: str,
    scenario_id: str,
    scenario: str,
    raw_cookies: str,
    task_auth_headers: dict[str, str],
    discovered_assets: list[str],
    target_info: dict[str, Any],
) -> dict[str, Any]:
    ctx = _guard_context_base(discovered_assets, target_info)
    ctx["csrf_seed_evidence_by_url"] = {
        target: {
            "score": -1,
            "reasons": ["global_coverage_guard"],
            "category": "coverage_backfill_guard",
            "method": "GET",
            "has_form_tag": False,
        }
    }
    payload: dict[str, Any] = {
        "category": "csrf_candidate",
        "source_category": "coverage_backfill_guard",
        "count": 1,
        "tags": ["csrf_candidate", "auth_endpoint", "coverage_guard_forced"],
        "targets": [target],
        "target": target,
        "_coverage_guard_forced": True,
        "scenario_id": scenario_id,
        "scenario": scenario,
        "attack_type": "workflow state transition",
        "description": "Global CSRF coverage guard task injected from execution loop.",
        "_context": ctx,
        "headers": {},
        "cookies": raw_cookies,
        "unknown_classification_only": False,
        "phase2_on_empty_phase1": False,
        "csrf_active_verify": False,
        "phase2_risk_force_vuln_types": [],
        "phase2_max_seconds_risk_forced": 30,
        "phase2_max_seconds": 60,
    }
    if task_auth_headers:
        payload["auth_headers"] = task_auth_headers
    return payload


def build_xss_guard_payload(
    *,
    target: str,
    scenario_id: str,
    scenario: str,
    raw_cookies: str,
    task_auth_headers: dict[str, str],
    discovered_assets: list[str],
    target_info: dict[str, Any],
) -> dict[str, Any]:
    ctx = _guard_context_base(discovered_assets, target_info)
    ctx["xss_seed_evidence_by_url"] = {
        target: {
            "score": -1,
            "reasons": ["global_coverage_guard"],
            "category": "coverage_backfill_guard",
            "method": "GET",
            "has_form_tag": False,
        }
    }
    payload: dict[str, Any] = {
        "category": "xss_candidate",
        "source_category": "coverage_backfill_guard",
        "count": 1,
        "tags": ["xss_candidate", "sqli_candidate", "coverage_guard_forced"],
        "targets": [target],
        "target": target,
        "_coverage_guard_forced": True,
        "scenario_id": scenario_id,
        "scenario": scenario,
        "attack_type": "input tampering injection",
        "description": "Global XSS coverage guard task injected from execution loop.",
        "_context": ctx,
        "headers": {},
        "cookies": raw_cookies,
        "unknown_classification_only": False,
        "phase2_on_empty_phase1": False,
        "phase2_risk_force_vuln_types": [],
        "phase2_max_seconds_risk_forced": 30,
        "phase2_max_seconds": 60,
    }
    if task_auth_headers:
        payload["auth_headers"] = task_auth_headers
    return payload


def build_oob_guard_payload(
    *,
    target: str,
    raw_cookies: str,
    task_auth_headers: dict[str, str],
    discovered_assets: list[str],
    target_info: dict[str, Any],
) -> dict[str, Any]:
    scenario_id = "scn_08_oob_external_channel_flow"
    ctx = _guard_context_base(discovered_assets, target_info)
    ctx["scenario_probe_evidence_by_url"] = {
        target: {
            "score": -1,
            "reasons": ["global_oob_guard"],
            "category": "scenario_probe_guard",
            "method": "GET",
            "has_form_tag": False,
        }
    }
    payload: dict[str, Any] = {
        "category": "auth",
        "source_category": "scenario_probe_guard",
        "count": 1,
        "tags": ["auth_endpoint", "oob_candidate", "manual_verify", "coverage_guard_forced"],
        "targets": [target],
        "target": target,
        "_coverage_guard_forced": True,
        "scenario_probe": scenario_id,
        "scenario_id": scenario_id,
        "scenario": "password reset reset token email verification verification code magic link invite acceptance account activation confirmation code oob out-of-band mailbox sms otp",
        "attack_type": "oob surface mapping",
        "description": "Global OOB scenario coverage guard task injected from execution loop.",
        "_context": ctx,
        "headers": {},
        "cookies": raw_cookies,
        "unknown_classification_only": False,
        "phase2_on_empty_phase1": False,
        "phase2_risk_force_vuln_types": [],
        "phase2_max_seconds_risk_forced": 30,
        "phase2_max_seconds": 45,
    }
    if task_auth_headers:
        payload["auth_headers"] = task_auth_headers
    return payload


# ── ensure_global_*_guard_task implementations ────────────────────────


def _resolve_family_missing(family: str, resolve_required_vuln_families: Callable[[], list[str]]) -> bool:
    return family not in set(resolve_required_vuln_families())


def _resolve_guard_decision(
    *,
    family: str,
    guard_prefix: str,
    target: str,
    task_queue: Any,
    trigger_source: str,
    resolve_required_vuln_families: Callable[[], list[str]],
) -> tuple[bool, Optional[str]]:
    if _resolve_family_missing(family, resolve_required_vuln_families):
        return False, None
    if not target:
        logger.error(
            "Global %s guard was required but no guard target could be resolved (source=%s).",
            family.upper(), trigger_source,
        )
        return False, None
    guard_hash = hashlib.sha1(target.encode("utf-8")).hexdigest()[:10]
    guard_id = f"{guard_prefix}_{guard_hash}"
    if task_queue is not None and callable(getattr(task_queue, "get_by_id", None)):
        if task_queue.get_by_id(guard_id) is not None:
            return False, None
    return True, guard_id


def ensure_global_csrf_guard_decision(
    *,
    trigger_source: str = "execute_loop",
    resolve_required_vuln_families: Callable[[], list[str]],
    resolve_guard_target: Callable[[], str],
    task_queue: Any,
    get_context_cookie_string: Callable[[], str],
    get_context_auth_headers: Callable[[], dict[str, str]],
    discovered_assets: list[str],
    target_info: dict[str, Any],
) -> tuple[bool, Optional[SwarmTask], Optional[str]]:
    if _resolve_family_missing("csrf", resolve_required_vuln_families):
        return False, None, None

    target = resolve_guard_target()
    decision, guard_id = _resolve_guard_decision(
        family="csrf", guard_prefix="csrf_guard_global", target=target,
        task_queue=task_queue, trigger_source=trigger_source,
        resolve_required_vuln_families=resolve_required_vuln_families,
    )
    if not decision or guard_id is None:
        return False, None, None

    raw_cookies = get_context_cookie_string()
    task_auth_headers = get_context_auth_headers()
    guard_params = build_csrf_guard_payload(
        target=target,
        scenario_id="scn_09_multi_step_state_machine",
        scenario="state machine multi-step flow workflow abuse state transition precondition chain chaining",
        raw_cookies=raw_cookies,
        task_auth_headers=task_auth_headers,
        discovered_assets=discovered_assets,
        target_info=target_info,
    )
    guard_task = SwarmTask(
        id=guard_id,
        name="CSRF Coverage Guard Check (global)",
        agent_type="InjectionSwarm",
        action="scan",
        phase="attack",
        params=guard_params,
        target=target,
        tags=["csrf_candidate", "auth_endpoint", "coverage_guard_forced"],
        priority=1250,
    )
    return True, guard_task, guard_id


def ensure_global_xss_guard_decision(
    *,
    trigger_source: str = "execute_loop",
    resolve_required_vuln_families: Callable[[], list[str]],
    resolve_guard_target: Callable[[], str],
    task_queue: Any,
    get_context_cookie_string: Callable[[], str],
    get_context_auth_headers: Callable[[], dict[str, str]],
    discovered_assets: list[str],
    target_info: dict[str, Any],
) -> tuple[bool, Optional[SwarmTask], Optional[str]]:
    if _resolve_family_missing("xss", resolve_required_vuln_families):
        return False, None, None

    target = resolve_guard_target()
    decision, guard_id = _resolve_guard_decision(
        family="xss", guard_prefix="xss_guard_global", target=target,
        task_queue=task_queue, trigger_source=trigger_source,
        resolve_required_vuln_families=resolve_required_vuln_families,
    )
    if not decision or guard_id is None:
        return False, None, None

    raw_cookies = get_context_cookie_string()
    task_auth_headers = get_context_auth_headers()
    guard_params = build_xss_guard_payload(
        target=target,
        scenario_id="scn_03_injection_input_tampering",
        scenario="injection input tampering payload mutation query/body/header parameter abuse",
        raw_cookies=raw_cookies,
        task_auth_headers=task_auth_headers,
        discovered_assets=discovered_assets,
        target_info=target_info,
    )
    guard_task = SwarmTask(
        id=guard_id,
        name="XSS Coverage Guard Check (global)",
        agent_type="InjectionSwarm",
        action="scan",
        phase="attack",
        params=guard_params,
        target=target,
        tags=["xss_candidate", "sqli_candidate", "coverage_guard_forced"],
        priority=1251,
    )
    return True, guard_task, guard_id


def ensure_global_oob_guard_decision(
    *,
    trigger_source: str = "execute_loop",
    resolve_guard_target: Callable[[], str],
    task_queue: Any,
    get_context_cookie_string: Callable[[], str],
    get_context_auth_headers: Callable[[], dict[str, str]],
    discovered_assets: list[str],
    target_info: dict[str, Any],
) -> tuple[bool, Optional[SwarmTask], Optional[str]]:
    target = resolve_guard_target()
    if not target:
        return False, None, None
    guard_hash = hashlib.sha1(target.encode("utf-8")).hexdigest()[:10]
    guard_id = f"oob_guard_global_{guard_hash}"
    if task_queue is not None and callable(getattr(task_queue, "get_by_id", None)):
        if task_queue.get_by_id(guard_id) is not None:
            return False, None, None

    raw_cookies = get_context_cookie_string()
    task_auth_headers = get_context_auth_headers()
    guard_params = build_oob_guard_payload(
        target=target,
        raw_cookies=raw_cookies,
        task_auth_headers=task_auth_headers,
        discovered_assets=discovered_assets,
        target_info=target_info,
    )
    guard_task = SwarmTask(
        id=guard_id,
        name="OOB Coverage Guard Check (global)",
        agent_type="InjectionSwarm",
        action="scan",
        phase="attack",
        params=guard_params,
        target=target,
        tags=["auth_endpoint", "oob_candidate", "coverage_guard_forced", "manual_verify"],
        priority=1249,
    )
    return True, guard_task, guard_id
