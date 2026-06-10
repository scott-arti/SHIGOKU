"""Scenario coverage evaluation and missing probe task generation.

MasterConductor facade から受け取った bound callable 群を使って
scenario カバレッジ評価と不足 core scenario probe task の生成を担当する。
task_queue への追加は行わず、生成した Task リストを返すのみ。
"""

import logging
import uuid
from typing import Any, Callable, Optional

from src.core.agents.swarm.base import Task as SwarmTask
from src.config import settings

logger = logging.getLogger(__name__)


def task_matches_scenario(task: Any, scenario_id: str) -> bool:
    normalized_target = str(scenario_id or "").strip().lower().replace("-", "_")
    if not normalized_target:
        return False

    params = task.params if isinstance(getattr(task, "params", None), dict) else {}
    if not isinstance(params, dict):
        params = {}

    candidates = [
        str(params.get("scenario_probe", "") or ""),
        str(params.get("scenario_id", "") or ""),
    ]
    intervention = params.get("_intervention", {})
    if isinstance(intervention, dict):
        decision = intervention.get("decision", {})
        if isinstance(decision, dict):
            candidates.append(str(decision.get("scenario_id", "") or ""))

    name = str(getattr(task, "name", "") or "")
    if "SCN08" in name and normalized_target == "scn_08_oob_external_channel_flow":
        return True

    for candidate in candidates:
        normalized_candidate = candidate.strip().lower().replace("-", "_")
        if normalized_candidate == normalized_target:
            return True
    return False


def has_scenario_in_queue_or_history(
    *,
    scenario_id: str,
    completed_tasks: list[Any],
    task_queue: Any,
    pending_hitl: list[dict],
) -> bool:
    for task in completed_tasks:
        if task_matches_scenario(task, scenario_id):
            return True

    if task_queue is not None:
        try:
            for queued_task in task_queue:
                if task_matches_scenario(queued_task, scenario_id):
                    return True
        except Exception:
            pass

    if isinstance(pending_hitl, list):
        normalized_target = str(scenario_id or "").strip().lower().replace("-", "_")
        for ticket in pending_hitl:
            if not isinstance(ticket, dict):
                continue
            task_snapshot = ticket.get("task")
            if not isinstance(task_snapshot, dict):
                continue
            params_snap = task_snapshot.get("params", {})
            if not isinstance(params_snap, dict):
                continue
            candidates = [
                str(params_snap.get("scenario_probe", "") or ""),
                str(params_snap.get("scenario_id", "") or ""),
            ]
            intervention_snap = params_snap.get("_intervention", {})
            if isinstance(intervention_snap, dict):
                decision_snap = intervention_snap.get("decision", {})
                if isinstance(decision_snap, dict):
                    candidates.append(str(decision_snap.get("scenario_id", "") or ""))
            if any(
                str(candidate or "").strip().lower().replace("-", "_") == normalized_target
                for candidate in candidates
            ):
                return True
    return False


def create_missing_core_scenario_probe_tasks(
    existing_tasks: list[SwarmTask],
    recon_results: dict[str, dict],
    *,
    evaluate_scenario_coverage: Any,
    extract_scn_number: Any,
    collect_seed_targets: Any,
    get_context_cookie_string: Any,
    get_context_auth_headers: Any,
    resolve_active_probe_policy: Any,
    select_targets_for_scenario_probe: Any,
    apply_phase2_on_empty_policy: Any,
    evaluate_active_probe_policy: Any,
    target_info: Optional[dict[str, Any]],
    discovered_assets: list[str],
    scenario_probe_target_budget: int = 2,
    active_probe_policy_enabled: bool = True,
) -> list[SwarmTask]:
    actionable_categories = {
        "admin", "auth", "id_param", "redirect_param", "file_param", "upload",
        "product_search", "basket_order", "feedback_review", "file_exposure_upload",
        "api_data", "client_route_dom", "api_candidate", "api_endpoint",
        "csrf_candidate", "xss_candidate",
    }
    has_actionable_seed = any(
        str((getattr(task, "params", {}) or {}).get("category", "")).strip().lower() in actionable_categories
        for task in existing_tasks
    )
    if not has_actionable_seed:
        return []

    scenario_coverage = evaluate_scenario_coverage(
        tasks=existing_tasks, infer_if_missing=True,
    )
    target_scenario_numbers = {1, 2, 3, 4, 5, 6, 8, 10, 11, 12}
    missing_probe_ids = [
        sid
        for sid in scenario_coverage.get("missing_scenarios", [])
        if extract_scn_number(sid) in target_scenario_numbers
    ]
    if not missing_probe_ids:
        return []

    probe_specs_by_number: dict[int, dict[str, Any]] = {
        1: {"name": "SCN01 IDOR/BOLA Object Access Probe", "agent_type": "InjectionSwarm", "category": "id_param", "tags": ["idor_candidate", "api_endpoint"], "scenario": "idor bola object level authorization authz probe cross-session weak_id", "attack_type": "id tampering", "description": "IDOR/BOLA object access probe via direct object reference tampering.", "priority": 86},
        2: {"name": "SCN02 Mass Assignment Probe", "agent_type": "InjectionSwarm", "category": "api_data", "tags": ["api_endpoint", "has_params"], "scenario": "mass assignment overposting hidden field role= is_admin permission", "attack_type": "mass assignment", "description": "Object update probe focusing on unsafe object binding and hidden fields.", "priority": 85},
        3: {"name": "SCN03 Injection Tampering Probe", "agent_type": "InjectionSwarm", "category": "xss_candidate", "tags": ["xss_candidate", "sqli_candidate"], "scenario": "sql injection nosql injection xss command injection lfi ssrf open redirect payload fuzz", "attack_type": "payload fuzz", "description": "Input tampering probe across injection families.", "priority": 84},
        4: {"name": "SCN04 Endpoint Enumeration Probe", "agent_type": "InjectionSwarm", "category": "api_candidate", "tags": ["api_endpoint", "has_params"], "scenario": "endpoint discovery improper asset management hidden api internal api /internal /v2 ffuf wordlist", "attack_type": "endpoint discovery", "description": "Hidden/internal API surface enumeration probe.", "priority": 83},
        5: {"name": "SCN05 Rate Limit Resilience Probe", "agent_type": "InjectionSwarm", "category": "api_candidate", "tags": ["api_endpoint", "auth_endpoint"], "scenario": "rate limit throttle burst request brute force request frequency", "attack_type": "rate limit", "description": "Traffic-pattern probe for throttling and brute-force resilience.", "priority": 82},
        6: {"name": "SCN06 Data Exposure Diff Probe", "agent_type": "InjectionSwarm", "category": "api_data", "tags": ["api_endpoint", "has_params", "sensitive_data_exposure"], "scenario": "data exposure sensitive field hidden attribute response diff schema diff", "attack_type": "response diff", "description": "Schema/response differential probe for sensitive field exposure.", "priority": 81},
        8: {"name": "SCN08 OOB External Channel Surface Probe", "agent_type": "InjectionSwarm", "category": "auth", "tags": ["auth_endpoint", "oob_candidate", "manual_verify"], "scenario": "password reset reset token email verification verification code magic link invite acceptance account activation confirmation code oob out-of-band mailbox sms otp", "attack_type": "oob surface mapping", "description": "Non-destructive mapping of OOB token issuance and verification surfaces before HITL/human validation.", "priority": 80, "phase2_on_empty_phase1": False, "phase2_max_seconds": 45},
        10: {"name": "SCN10 Semantic Business Logic Probe", "agent_type": "InjectionSwarm", "category": "basket_order", "tags": ["workflow_candidate", "business_logic_candidate", "manual_verify"], "scenario": "business logic semantic abuse approval flow policy bypass intent abuse pricing workflow checkout refund", "attack_type": "workflow value tampering", "description": "Low-impact workflow transition/value tampering probe for business-logic abuse candidates.", "priority": 79, "phase2_on_empty_phase1": False, "phase2_max_seconds": 45},
        11: {"name": "SCN11 Multi-Vector Chain Probe", "agent_type": "InjectionSwarm", "category": "api_data", "tags": ["api_endpoint", "auth_endpoint", "multi_vector_candidate", "manual_verify"], "scenario": "api chaining attack chain privilege escalation chain takeover chain multi vector trust transition authz data mutation", "attack_type": "cross-endpoint trust chaining", "description": "Cross-endpoint trust-transition probe to identify escalation chain footholds.", "priority": 78, "phase2_on_empty_phase1": False, "phase2_max_seconds": 45},
        12: {"name": "SCN12 Advanced SSRF Internal Topology Probe", "agent_type": "InjectionSwarm", "category": "redirect_param", "tags": ["ssrf_candidate", "redirect_candidate", "internal_topology_candidate", "manual_verify"], "scenario": "metadata endpoint 169.254.169.254 internal network map cloud metadata gopher:// dns rebinding callback url webhook", "attack_type": "internal topology ssrf", "description": "Controlled SSRF topology probe focused on internal callback and metadata exposure surfaces.", "priority": 77, "phase2_on_empty_phase1": False, "phase2_max_seconds": 45},
    }

    probe_budget = int(getattr(settings, "scenario_probe_target_budget", scenario_probe_target_budget) or scenario_probe_target_budget)
    probe_targets, probe_evidence = collect_seed_targets(
        recon_results=recon_results, budget=probe_budget,
    )
    if not probe_targets:
        return []

    raw_cookies = get_context_cookie_string()
    task_auth_headers = get_context_auth_headers()
    _target_info = target_info if isinstance(target_info, dict) else {}
    auth_tokens = _target_info.get("auth_tokens", {}) if isinstance(_target_info, dict) else {}
    tech_stack = list(_target_info.get("tech_stack", [])) if isinstance(_target_info, dict) else []

    generated: list[SwarmTask] = []
    active_probe_policy = resolve_active_probe_policy() if active_probe_policy_enabled else {}
    for scenario_id in missing_probe_ids:
        number = extract_scn_number(scenario_id)
        spec = probe_specs_by_number.get(number)
        if not spec:
            continue
        selected_targets, per_target_evidence = select_targets_for_scenario_probe(
            scenario_id=scenario_id,
            targets=probe_targets,
            evidence_by_url=probe_evidence,
            budget=probe_budget,
        )
        if not selected_targets:
            continue

        selected_target = selected_targets[0]

        params: dict[str, Any] = {
            "category": spec["category"],
            "source_category": "scenario_probe_planner",
            "scenario_probe": scenario_id,
            "scenario": spec["scenario"],
            "attack_type": spec["attack_type"],
            "description": spec["description"],
            "count": len(selected_targets),
            "tags": list(spec["tags"]),
            "targets": selected_targets,
            "target": selected_target,
            "_context": {
                "discovered_endpoints": discovered_assets[:10] if discovered_assets else [],
                "auth_tokens": auth_tokens,
                "discovered_params": [],
                "tech_stack": tech_stack,
                "waf_info": {},
                "critical_findings": [],
                "scenario_probe_evidence_by_url": per_target_evidence,
            },
            "headers": {},
            "cookies": raw_cookies,
            "unknown_classification_only": bool(spec.get("unknown_classification_only", False)),
            "phase2_on_empty_phase1": apply_phase2_on_empty_policy(
                bool(spec.get("phase2_on_empty_phase1", True))
            ),
            "phase2_risk_force_vuln_types": [],
            "phase2_max_seconds_risk_forced": int(spec.get("phase2_max_seconds_risk_forced", 30) or 30),
            "phase2_max_seconds": int(spec.get("phase2_max_seconds", 90) or 90),
        }

        if active_probe_policy:
            policy_decision = evaluate_active_probe_policy(
                probe={
                    "asset": selected_target,
                    "strategy": "scenario_probe",
                    "qps": 1,
                },
                policy=active_probe_policy,
            )
            if not policy_decision.get("allowed", False):
                logger.info(
                    "Skipped scenario probe task for %s due to active probe policy: %s",
                    scenario_id,
                    policy_decision.get("reason", "unknown"),
                )
                continue
        if task_auth_headers:
            params["auth_headers"] = task_auth_headers

        generated.append(
            SwarmTask(
                id=f"scenario_probe_{number:02d}_{uuid.uuid4().hex[:8]}",
                name=f"{spec['name']} ({len(selected_targets)} targets)",
                agent_type=spec["agent_type"],
                action="scan",
                phase="attack",
                params=params,
                target=selected_target,
                tags=list(spec["tags"]),
                priority=int(spec["priority"]),
            )
        )

    if generated:
        logger.info(
            "Created %d scenario probe task(s) for missing scenarios: %s",
            len(generated),
            ", ".join(missing_probe_ids),
        )
    return generated


def normalize_scenario_id_for_coverage(
    task: Any,
    params: dict[str, Any],
    scenario_id: str,
    route: str,
) -> tuple[str, str, Optional[str]]:
    sid = str(scenario_id or "").strip().lower().replace("-", "_")
    normalized_route = str(route or "").strip().lower()
    if sid.startswith("scn_"):
        return sid, normalized_route, None

    category = str(params.get("category", "") or "").strip().lower()

    alias_by_scenario: dict[str, str] = {
        "category_route:admin": "scn_01_idor_bola_object_access",
        "category_route:auth": "scn_07_token_trust_boundary",
        "category_route:jwt_detected": "scn_07_token_trust_boundary",
        "category_route:basket_order": "scn_09_multi_step_state_machine",
        "category_route:realtime": "scn_09_multi_step_state_machine",
        "category_route:csrf_candidate": "scn_09_multi_step_state_machine",
        "category_route:id_param": "scn_03_injection_input_tampering",
        "category_route:redirect_param": "scn_03_injection_input_tampering",
        "category_route:file_param": "scn_03_injection_input_tampering",
        "category_route:product_search": "scn_03_injection_input_tampering",
        "category_route:feedback_review": "scn_03_injection_input_tampering",
        "category_route:api_data": "scn_03_injection_input_tampering",
        "category_route:client_route_dom": "scn_03_injection_input_tampering",
        "category_route:api_candidate": "scn_03_injection_input_tampering",
        "category_route:api_endpoint": "scn_03_injection_input_tampering",
        "category_route:xss_candidate": "scn_03_injection_input_tampering",
        "category_route:file_exposure_upload": "scn_06_data_exposure_diff",
        "category_route:meta_observability": "scn_06_data_exposure_diff",
        "category_route:debug_info": "scn_06_data_exposure_diff",
    }
    alias_by_category: dict[str, str] = {
        "admin": "scn_01_idor_bola_object_access",
        "auth": "scn_07_token_trust_boundary",
        "jwt_detected": "scn_07_token_trust_boundary",
        "basket_order": "scn_09_multi_step_state_machine",
        "realtime": "scn_09_multi_step_state_machine",
        "csrf_candidate": "scn_09_multi_step_state_machine",
        "id_param": "scn_03_injection_input_tampering",
        "redirect_param": "scn_03_injection_input_tampering",
        "file_param": "scn_03_injection_input_tampering",
        "product_search": "scn_03_injection_input_tampering",
        "feedback_review": "scn_03_injection_input_tampering",
        "api_data": "scn_03_injection_input_tampering",
        "client_route_dom": "scn_03_injection_input_tampering",
        "api_candidate": "scn_03_injection_input_tampering",
        "api_endpoint": "scn_03_injection_input_tampering",
        "xss_candidate": "scn_03_injection_input_tampering",
        "file_exposure_upload": "scn_06_data_exposure_diff",
        "meta_observability": "scn_06_data_exposure_diff",
        "debug_info": "scn_06_data_exposure_diff",
    }
    if sid in alias_by_scenario:
        return alias_by_scenario[sid], normalized_route or "shigoku_hitl", "normalized_category_route"
    if category in alias_by_category:
        return alias_by_category[category], normalized_route or "shigoku_hitl", "normalized_category_alias"

    signal_chunks: list[str] = [
        str(getattr(task, "name", "") or ""),
        str(getattr(task, "action", "") or ""),
        str(getattr(task, "agent_type", "") or ""),
        str(params.get("scenario", "") or ""),
        str(params.get("attack_type", "") or ""),
        str(params.get("description", "") or ""),
        str(category or ""),
    ]
    tags = params.get("tags", [])
    if isinstance(tags, list):
        signal_chunks.extend(str(t or "") for t in tags)
    signal_text = " ".join(signal_chunks).lower()

    token_trust_markers = ("jwt", "alg:none", "algorithm confusion", "kid injection", "jwks", "token forgery", "token trust boundary")
    if any(marker in signal_text for marker in token_trust_markers):
        return "scn_07_token_trust_boundary", normalized_route or "shigoku_hitl", "normalized_signal_alias"

    state_machine_markers = ("state machine", "multi-step flow", "workflow abuse", "state transition", "precondition", "chaining", "basket", "order flow", "csrf")
    if any(marker in signal_text for marker in state_machine_markers):
        return "scn_09_multi_step_state_machine", normalized_route or "shigoku_hitl", "normalized_signal_alias"

    injection_markers = ("sqli", "sql injection", "xss", "payload", "input tampering", "parameter tampering", "mass assignment", "overposting", "prototype pollution")
    if any(marker in signal_text for marker in injection_markers):
        return "scn_03_injection_input_tampering", normalized_route or "shigoku_only", "normalized_signal_alias"

    data_exposure_markers = ("data exposure", "sensitive field", "response diff", "schema diff", "debug info", "observability")
    if any(marker in signal_text for marker in data_exposure_markers):
        return "scn_06_data_exposure_diff", normalized_route or "shigoku_only", "normalized_signal_alias"

    return sid, normalized_route, None


_SCN_CATALOG_DEFAULTS = [
    ("scn_01_idor_bola_object_access", "SCN01 IDOR/BOLA Object Access Probe"),
    ("scn_02_mass_assignment_object_binding", "SCN02 Mass Assignment Object Binding Probe"),
    ("scn_03_injection_input_tampering", "SCN03 Injection Input Tampering Probe"),
    ("scn_04_hidden_api_endpoint_enumeration", "SCN04 Hidden API Endpoint Enumeration Probe"),
    ("scn_05_rate_limit_throttle_resilience", "SCN05 Rate Limit Throttle Resilience Probe"),
    ("scn_06_data_exposure_diff", "SCN06 Data Exposure Diff Probe"),
    ("scn_07_token_trust_boundary", "SCN07 Token Trust Boundary Probe"),
    ("scn_08_oob_external_channel_flow", "SCN08 OOB External Channel Flow Probe"),
    ("scn_09_multi_step_state_machine", "SCN09 Multi-Step State Machine Probe"),
    ("scn_10_semantic_business_logic", "SCN10 Semantic Business Logic Probe"),
    ("scn_11_multi_vector_chaining", "SCN11 Multi-Vector Chaining Probe"),
    ("scn_12_advanced_ssrf_topology", "SCN12 Advanced SSRF Topology Probe"),
]


def resolve_intervention_scenario_catalog(
    *,
    intervention_policy: Any,
    extract_scn_number: Any,
    catalog_defaults: Optional[list[tuple[str, str]]] = None,
) -> list[dict[str, Any]]:
    if catalog_defaults is None:
        catalog_defaults = _SCN_CATALOG_DEFAULTS
    catalog: list[dict[str, Any]] = []
    seen: set[str] = set()

    if intervention_policy is not None:
        for scenario in getattr(intervention_policy, "scenarios", []):
            if not isinstance(scenario, dict):
                continue
            sid = str(scenario.get("id", "") or "").strip().lower().replace("-", "_")
            number = extract_scn_number(sid)
            if number < 1 or number > 12 or sid in seen:
                continue
            route = str(scenario.get("route", "shigoku_only") or "shigoku_only").strip().lower()
            title = str(scenario.get("title") or scenario.get("name") or sid).strip()
            catalog.append({"id": sid, "number": number, "route": route, "title": title})
            seen.add(sid)

    if not catalog:
        for sid, title in catalog_defaults:
            catalog.append({
                "id": sid, "number": extract_scn_number(sid),
                "route": "shigoku_only", "title": title,
            })
        return catalog

    fallback_titles = {sid: title for sid, title in catalog_defaults}
    catalog_by_number = {int(item["number"]): dict(item) for item in catalog}
    for fallback_sid, fallback_title in catalog_defaults:
        number = extract_scn_number(fallback_sid)
        if number < 1 or number > 12:
            continue
        if number in catalog_by_number:
            if not str(catalog_by_number[number].get("title", "")).strip():
                catalog_by_number[number]["title"] = fallback_title
            continue
        catalog_by_number[number] = {
            "id": fallback_sid, "number": number,
            "route": "shigoku_only", "title": fallback_title,
        }

    sorted_catalog: list[dict[str, Any]] = []
    for number in sorted(catalog_by_number.keys()):
        item = dict(catalog_by_number[number])
        sid = str(item.get("id", "") or "").strip().lower().replace("-", "_")
        item["id"] = sid
        item["number"] = number
        item["title"] = str(item.get("title") or fallback_titles.get(sid, sid)).strip()
        item["route"] = str(item.get("route", "shigoku_only") or "shigoku_only").strip().lower()
        sorted_catalog.append(item)
    return sorted_catalog


_TASK_STATE_PENDING = "pending"
_TASK_STATE_SKIPPED = "skipped"


def evaluate_intervention_scenario_coverage(
    tasks: Optional[list[Any]] = None,
    infer_if_missing: bool = True,
    *,
    completed_tasks: list[Any],
    get_intervention_decision: Any,
    extract_scn_number: Any,
    intervention_policy: Any,
    catalog_defaults: Optional[list[tuple[str, str]]] = None,
) -> dict[str, Any]:
    catalog = resolve_intervention_scenario_catalog(
        intervention_policy=intervention_policy,
        extract_scn_number=extract_scn_number,
        catalog_defaults=catalog_defaults,
    )
    required_scenarios = [str(item.get("id", "")).strip().lower() for item in catalog if str(item.get("id", "")).strip()]
    metadata_by_id = {
        str(item.get("id", "")).strip().lower(): {
            "number": int(item.get("number", 0) or 0),
            "title": str(item.get("title", "") or "").strip(),
            "route": str(item.get("route", "shigoku_only") or "shigoku_only").strip().lower(),
        }
        for item in catalog
        if str(item.get("id", "")).strip()
    }

    scenario_counts: dict[str, int] = {}
    route_counts: dict[str, int] = {}
    route_by_scenario: dict[str, str] = {}
    source_by_scenario: dict[str, str] = {}
    evaluated = list(tasks) if tasks is not None else list(completed_tasks)

    for task in evaluated:
        task_state_val = getattr(task, "state", _TASK_STATE_PENDING)
        if hasattr(task_state_val, "value"):
            task_state_str = task_state_val.value
        else:
            task_state_str = str(task_state_val or "").strip().lower()
        if task_state_str == _TASK_STATE_SKIPPED:
            continue

        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        intervention = params.get("_intervention", {})
        decision = intervention.get("decision", {}) if isinstance(intervention, dict) else {}
        scenario_id = str(decision.get("scenario_id", "") or "").strip().lower().replace("-", "_")
        route = str(decision.get("route", "") or "").strip().lower()
        source = "task_decision"

        if not scenario_id:
            scenario_id = str(params.get("scenario_id", "") or params.get("scenario_probe", "")).strip().lower().replace("-", "_")
            source = "task_params" if scenario_id else source

        if not scenario_id and infer_if_missing:
            inferred = get_intervention_decision(task)
            scenario_id = str(inferred.get("scenario_id", "") or "").strip().lower().replace("-", "_")
            route = str(inferred.get("route", route) or route).strip().lower()
            source = "inferred_by_policy" if scenario_id else source

        scenario_id, route, normalized_source = normalize_scenario_id_for_coverage(
            task=task, params=params, scenario_id=scenario_id, route=route,
        )
        if normalized_source:
            source = normalized_source

        if not scenario_id.startswith("scn_"):
            continue

        scenario_counts[scenario_id] = scenario_counts.get(scenario_id, 0) + 1
        if route:
            route_counts[route] = route_counts.get(route, 0) + 1
            route_by_scenario.setdefault(scenario_id, route)
        source_by_scenario.setdefault(scenario_id, source)

    covered_scenarios = sorted(
        scenario_counts.keys(),
        key=lambda sid: (extract_scn_number(sid), sid),
    )
    missing_scenarios = [sid for sid in required_scenarios if sid not in scenario_counts]
    required_count = len(required_scenarios)
    covered_count = len([sid for sid in required_scenarios if sid in scenario_counts])
    coverage_rate = (covered_count / required_count) if required_count > 0 else 1.0

    coverage_items: list[dict[str, Any]] = []
    for sid in required_scenarios:
        meta = metadata_by_id.get(sid, {})
        coverage_items.append(
            {
                "scenario_id": sid,
                "number": int(meta.get("number", extract_scn_number(sid)) or 0),
                "title": str(meta.get("title", sid) or sid),
                "route": str(route_by_scenario.get(sid, meta.get("route", "shigoku_only")) or "shigoku_only"),
                "covered": sid in scenario_counts,
                "count": int(scenario_counts.get(sid, 0)),
                "source": str(source_by_scenario.get(sid, "none") or "none"),
            }
        )

    return {
        "required_scenarios": required_scenarios,
        "covered_scenarios": covered_scenarios,
        "missing_scenarios": missing_scenarios,
        "required_count": required_count,
        "covered_count": covered_count,
        "coverage_rate": coverage_rate,
        "gate_passed": len(missing_scenarios) == 0,
        "coverage_items": coverage_items,
        "route_counts": dict(sorted(route_counts.items())),
    }

    category = str(params.get("category", "") or "").strip().lower()

    alias_by_scenario: dict[str, str] = {
        "category_route:admin": "scn_01_idor_bola_object_access",
        "category_route:auth": "scn_07_token_trust_boundary",
        "category_route:jwt_detected": "scn_07_token_trust_boundary",
        "category_route:basket_order": "scn_09_multi_step_state_machine",
        "category_route:realtime": "scn_09_multi_step_state_machine",
        "category_route:csrf_candidate": "scn_09_multi_step_state_machine",
        "category_route:id_param": "scn_03_injection_input_tampering",
        "category_route:redirect_param": "scn_03_injection_input_tampering",
        "category_route:file_param": "scn_03_injection_input_tampering",
        "category_route:product_search": "scn_03_injection_input_tampering",
        "category_route:feedback_review": "scn_03_injection_input_tampering",
        "category_route:api_data": "scn_03_injection_input_tampering",
        "category_route:client_route_dom": "scn_03_injection_input_tampering",
        "category_route:api_candidate": "scn_03_injection_input_tampering",
        "category_route:api_endpoint": "scn_03_injection_input_tampering",
        "category_route:xss_candidate": "scn_03_injection_input_tampering",
        "category_route:file_exposure_upload": "scn_06_data_exposure_diff",
        "category_route:meta_observability": "scn_06_data_exposure_diff",
        "category_route:debug_info": "scn_06_data_exposure_diff",
    }
    alias_by_category: dict[str, str] = {
        "admin": "scn_01_idor_bola_object_access",
        "auth": "scn_07_token_trust_boundary",
        "jwt_detected": "scn_07_token_trust_boundary",
        "basket_order": "scn_09_multi_step_state_machine",
        "realtime": "scn_09_multi_step_state_machine",
        "csrf_candidate": "scn_09_multi_step_state_machine",
        "id_param": "scn_03_injection_input_tampering",
        "redirect_param": "scn_03_injection_input_tampering",
        "file_param": "scn_03_injection_input_tampering",
        "product_search": "scn_03_injection_input_tampering",
        "feedback_review": "scn_03_injection_input_tampering",
        "api_data": "scn_03_injection_input_tampering",
        "client_route_dom": "scn_03_injection_input_tampering",
        "api_candidate": "scn_03_injection_input_tampering",
        "api_endpoint": "scn_03_injection_input_tampering",
        "xss_candidate": "scn_03_injection_input_tampering",
        "file_exposure_upload": "scn_06_data_exposure_diff",
        "meta_observability": "scn_06_data_exposure_diff",
        "debug_info": "scn_06_data_exposure_diff",
    }
    if sid in alias_by_scenario:
        return alias_by_scenario[sid], normalized_route or "shigoku_hitl", "normalized_category_route"
    if category in alias_by_category:
        return alias_by_category[category], normalized_route or "shigoku_hitl", "normalized_category_alias"

    signal_chunks: list[str] = [
        str(getattr(task, "name", "") or ""),
        str(getattr(task, "action", "") or ""),
        str(getattr(task, "agent_type", "") or ""),
        str(params.get("scenario", "") or ""),
        str(params.get("attack_type", "") or ""),
        str(params.get("description", "") or ""),
        str(category or ""),
    ]
    tags = params.get("tags", [])
    if isinstance(tags, list):
        signal_chunks.extend(str(t or "") for t in tags)
    signal_text = " ".join(signal_chunks).lower()

    token_trust_markers = ("jwt", "alg:none", "algorithm confusion", "kid injection", "jwks", "token forgery", "token trust boundary")
    if any(marker in signal_text for marker in token_trust_markers):
        return "scn_07_token_trust_boundary", normalized_route or "shigoku_hitl", "normalized_signal_alias"

    state_machine_markers = ("state machine", "multi-step flow", "workflow abuse", "state transition", "precondition", "chaining", "basket", "order flow", "csrf")
    if any(marker in signal_text for marker in state_machine_markers):
        return "scn_09_multi_step_state_machine", normalized_route or "shigoku_hitl", "normalized_signal_alias"

    injection_markers = ("sqli", "sql injection", "xss", "payload", "input tampering", "parameter tampering", "mass assignment", "overposting", "prototype pollution")
    if any(marker in signal_text for marker in injection_markers):
        return "scn_03_injection_input_tampering", normalized_route or "shigoku_only", "normalized_signal_alias"

    data_exposure_markers = ("data exposure", "sensitive field", "response diff", "schema diff", "debug info", "observability")
    if any(marker in signal_text for marker in data_exposure_markers):
        return "scn_06_data_exposure_diff", normalized_route or "shigoku_only", "normalized_signal_alias"

    return sid, normalized_route, None
