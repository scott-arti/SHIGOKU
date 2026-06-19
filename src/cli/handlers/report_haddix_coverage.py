"""report/haddix scenario coverage helpers extracted from report_haddix.py.

Functions in this module handle scenario catalog resolution, coverage computation,
scenario ID normalization, heuristic finding synthesis from execution notes,
and heuristic-to-confirmed finding merging.
"""

from typing import Any

from src.commands import print_step, print_result
from src.core.engine.intervention_policy import InterventionPolicy
from src.config import settings


def enable_debug_mode():
    """Enable debug logging with UI feedback."""
    try:
        from src.core.utils.debug_logger import enable_debug_mode as _enable
        _enable()
        print_step("\U0001f41b", "Debug mode enabled - detailed logging active")
    except ImportError as e:
        print_result(False, f"Debug logger not available: {e}")


def extract_scn_number(scenario_id: str) -> int:
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


def normalize_scenario_id_for_report(
    *,
    task: dict[str, Any],
    params: dict[str, Any],
    scenario_id: str,
    route: str,
) -> tuple[str, str, str | None]:
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
        str(task.get("name", "") or ""),
        str(task.get("action", "") or ""),
        str(task.get("agent_type", "") or ""),
        str(params.get("scenario", "") or ""),
        str(params.get("attack_type", "") or ""),
        str(params.get("description", "") or ""),
        category,
    ]
    tags = params.get("tags", [])
    if isinstance(tags, list):
        signal_chunks.extend(str(t or "") for t in tags)
    signal_text = " ".join(signal_chunks).lower()

    if any(
        marker in signal_text
        for marker in (
            "jwt",
            "alg:none",
            "algorithm confusion",
            "kid injection",
            "jwks",
            "token forgery",
            "token trust boundary",
        )
    ):
        return "scn_07_token_trust_boundary", normalized_route or "shigoku_hitl", "normalized_signal_alias"

    if any(
        marker in signal_text
        for marker in (
            "state machine",
            "multi-step flow",
            "workflow abuse",
            "state transition",
            "precondition",
            "chaining",
            "basket",
            "order flow",
            "csrf",
        )
    ):
        return "scn_09_multi_step_state_machine", normalized_route or "shigoku_hitl", "normalized_signal_alias"

    if any(
        marker in signal_text
        for marker in (
            "sqli",
            "sql injection",
            "xss",
            "payload",
            "input tampering",
            "parameter tampering",
            "mass assignment",
            "overposting",
            "prototype pollution",
        )
    ):
        return "scn_03_injection_input_tampering", normalized_route or "shigoku_only", "normalized_signal_alias"

    if any(
        marker in signal_text
        for marker in (
            "data exposure",
            "sensitive field",
            "response diff",
            "schema diff",
            "debug info",
            "observability",
        )
    ):
        return "scn_06_data_exposure_diff", normalized_route or "shigoku_only", "normalized_signal_alias"

    return sid, normalized_route, None


def resolve_scn_catalog_for_report() -> list[dict[str, Any]]:
    from src.core.engine.intervention_policy import InterventionPolicy

    fallback: tuple[tuple[str, str], ...] = (
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
    catalog: list[dict[str, Any]] = []
    seen: set[str] = set()

    try:
        policy = InterventionPolicy(settings.get_intervention_scenarios())
        for scenario in getattr(policy, "scenarios", []):
            if not isinstance(scenario, dict):
                continue
            sid = str(scenario.get("id", "") or "").strip().lower().replace("-", "_")
            number = extract_scn_number(sid)
            if number < 1 or number > 12 or sid in seen:
                continue
            catalog.append(
                {
                    "id": sid,
                    "number": number,
                    "title": str(scenario.get("title") or scenario.get("name") or sid).strip(),
                    "route": str(scenario.get("route", "shigoku_only") or "shigoku_only").strip().lower(),
                }
            )
            seen.add(sid)
    except Exception:
        pass

    if not catalog:
        for sid, title in fallback:
            catalog.append(
                {
                    "id": sid,
                    "number": extract_scn_number(sid),
                    "title": title,
                    "route": "shigoku_only",
                }
            )
        return catalog

    fallback_map = {sid: title for sid, title in fallback}
    by_number = {int(item["number"]): dict(item) for item in catalog}
    for sid, title in fallback:
        number = extract_scn_number(sid)
        if number < 1 or number > 12:
            continue
        if number in by_number:
            if not str(by_number[number].get("title", "")).strip():
                by_number[number]["title"] = title
            continue
        by_number[number] = {
            "id": sid,
            "number": number,
            "title": title,
            "route": "shigoku_only",
        }

    normalized: list[dict[str, Any]] = []
    for number in sorted(by_number.keys()):
        item = dict(by_number[number])
        sid = str(item.get("id", "") or "").strip().lower().replace("-", "_")
        normalized.append(
            {
                "id": sid,
                "number": number,
                "title": str(item.get("title", "") or fallback_map.get(sid, sid)).strip(),
                "route": str(item.get("route", "shigoku_only") or "shigoku_only").strip().lower(),
            }
        )
    return normalized


def build_scenario_coverage_for_report(session_data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(session_data, dict):
        return {}

    existing_coverage: dict[str, Any] | None = None
    existing = session_data.get("scenario_coverage")
    if not isinstance(existing, dict):
        context = session_data.get("context", {})
        if isinstance(context, dict):
            existing = context.get("scenario_coverage")
    if isinstance(existing, dict) and isinstance(existing.get("coverage_items"), list):
        existing_coverage = existing

    from types import SimpleNamespace
    from src.core.engine.intervention_policy import InterventionPolicy

    catalog = resolve_scn_catalog_for_report()
    required = [str(item.get("id", "")).strip().lower() for item in catalog if str(item.get("id", "")).strip()]
    metadata = {
        str(item.get("id", "")).strip().lower(): {
            "number": int(item.get("number", 0) or 0),
            "title": str(item.get("title", "") or "").strip(),
            "route": str(item.get("route", "shigoku_only") or "shigoku_only").strip().lower(),
        }
        for item in catalog
        if str(item.get("id", "")).strip()
    }

    policy = InterventionPolicy(settings.get_intervention_scenarios())
    scenario_counts: dict[str, int] = {}
    route_counts: dict[str, int] = {}
    route_by_scenario: dict[str, str] = {}
    source_by_scenario: dict[str, str] = {}

    for task in session_data.get("completed_tasks", []):
        if not isinstance(task, dict):
            continue
        task_state = str(task.get("state", "") or "").strip().lower()
        if task_state == "skipped":
            # HITL待ちを含む未実行タスクはシナリオ到達扱いしない
            continue
        params = task.get("params", {})
        params = params if isinstance(params, dict) else {}
        intervention = params.get("_intervention", {})
        decision = intervention.get("decision", {}) if isinstance(intervention, dict) else {}

        scenario_id = str(decision.get("scenario_id", "") or "").strip().lower().replace("-", "_")
        route = str(decision.get("route", "") or "").strip().lower()
        source = "task_decision"

        if not scenario_id:
            scenario_id = str(params.get("scenario_id", "") or params.get("scenario_probe", "")).strip().lower().replace("-", "_")
            source = "task_params" if scenario_id else source

        if not scenario_id:
            inferred = policy.decide(
                SimpleNamespace(
                    name=task.get("name", ""),
                    action=task.get("action", ""),
                    agent_type=task.get("agent_type", ""),
                    target=task.get("target", ""),
                    tags=task.get("tags", []),
                    params=params,
                )
            )
            scenario_id = str(inferred.get("scenario_id", "") or "").strip().lower().replace("-", "_")
            route = str(inferred.get("route", route) or route).strip().lower()
            source = "inferred_by_policy" if scenario_id else source

        scenario_id, route, normalized_source = normalize_scenario_id_for_report(
            task=task,
            params=params,
            scenario_id=scenario_id,
            route=route,
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

    missing = [sid for sid in required if sid not in scenario_counts]
    covered_count = len([sid for sid in required if sid in scenario_counts])
    required_count = len(required)
    coverage_items: list[dict[str, Any]] = []
    for sid in required:
        meta = metadata.get(sid, {})
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

    computed = {
        "required_scenarios": required,
        "covered_scenarios": sorted(
            scenario_counts.keys(),
            key=lambda sid: (extract_scn_number(sid), sid),
        ),
        "missing_scenarios": missing,
        "required_count": required_count,
        "covered_count": covered_count,
        "coverage_rate": (covered_count / required_count) if required_count > 0 else 1.0,
        "gate_passed": len(missing) == 0,
        "coverage_items": coverage_items,
        "route_counts": dict(sorted(route_counts.items())),
    }

    if isinstance(existing_coverage, dict):
        try:
            existing_count = int(existing_coverage.get("covered_count", 0) or 0)
        except Exception:
            existing_count = 0
        if existing_count > int(computed.get("covered_count", 0) or 0):
            return existing_coverage
    return computed


def build_heuristic_findings_from_execution_notes(
    execution_notes: list[dict[str, Any]],
    *,
    target: str,
    scenario_coverage: dict[str, Any] | None = None,
    max_candidates: int = 6,
    promote_privilege_probe_min: int = 2,
    promote_completed_probe_min: int = 2,
) -> list[dict[str, Any]]:
    """
    report-only fallback:
    既存 findings が 0 件のとき、execution notes から「要検証候補」を合成する。
    """
    if not isinstance(execution_notes, list) or not execution_notes:
        return []
    try:
        promote_privilege_probe_min = max(1, int(promote_privilege_probe_min))
    except Exception:
        promote_privilege_probe_min = 2
    try:
        promote_completed_probe_min = max(1, int(promote_completed_probe_min))
    except Exception:
        promote_completed_probe_min = 2

    def _as_float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except Exception:
            return default

    def _extract_note_http_artifact(note: dict[str, Any], keys: list[str]) -> str:
        for key in keys:
            token = str(note.get(key, "") or "").strip()
            if token:
                return token
        return ""

    def _infer_heuristic_detection_class(url: str, vuln_type: str) -> str:
        from urllib.parse import urlsplit

        path = urlsplit(str(url or "")).path.lower()
        normalized_vuln_type = str(vuln_type or "").strip().lower()
        if normalized_vuln_type == "mass_assignment":
            return "mass_assignment"
        if normalized_vuln_type == "api":
            return "endpoint_bfla"
        if normalized_vuln_type == "broken_access_control":
            return "access_control"
        if normalized_vuln_type == "unknown" and (
            "/api/" in path or "/rest/" in path or "graphql" in path
        ):
            return "endpoint_bfla"
        return ""

    normalized_target = str(target or "").strip()
    missing_scenarios = set()
    if isinstance(scenario_coverage, dict):
        raw_missing = scenario_coverage.get("missing_scenarios", [])
        if isinstance(raw_missing, list):
            missing_scenarios = {
                str(item or "").strip().lower()
                for item in raw_missing
                if str(item or "").strip()
            }

    candidates: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()
    repeat_signal_stats: dict[tuple[str, str], dict[str, set[str]]] = {}

    def _repeat_signal_key(note: dict[str, Any], tested_params: list[str], status: str, probe_sent: bool) -> str:
        task_id = str(note.get("task_id", "") or "").strip()
        if task_id:
            return f"task:{task_id}"
        params_norm = ",".join(sorted({str(param or "").strip().lower() for param in tested_params if str(param or "").strip()}))
        duration_norm = f"{_as_float(note.get('duration_seconds'), 0.0):.6f}"
        return f"status:{status}|probe:{1 if probe_sent else 0}|params:{params_norm}|duration:{duration_norm}"

    for note in execution_notes:
        if not isinstance(note, dict):
            continue
        url = str(note.get("url", "") or "").strip()
        if not url:
            continue
        vuln_type = str(note.get("vuln_type", "unknown") or "unknown").strip().lower() or "unknown"
        tested_params_raw = note.get("tested_params", [])
        tested_params: list[str] = []
        if isinstance(tested_params_raw, str):
            token = tested_params_raw.strip()
            if token:
                tested_params = [token]
        elif isinstance(tested_params_raw, list):
            tested_params = [str(p).strip() for p in tested_params_raw if str(p).strip()]
        lower_params = {param.lower() for param in tested_params}
        privilege_sensitive_params = {"role", "is_admin", "admin", "permission", "scope"}
        has_privilege_sensitive_param = bool(lower_params.intersection(privilege_sensitive_params))

        key = (url, vuln_type)
        stats = repeat_signal_stats.setdefault(
            key,
            {
                "total": set(),
                "completed_with_probe": set(),
                "privilege_probe": set(),
            },
        )
        status = str(note.get("status", "") or "").strip().lower()
        probe_sent = bool(note.get("probe_sent"))
        signal_token = _repeat_signal_key(note, tested_params, status, probe_sent)
        stats["total"].add(signal_token)
        if status == "completed" and probe_sent:
            stats["completed_with_probe"].add(signal_token)
        if has_privilege_sensitive_param and status == "completed" and probe_sent:
            stats["privilege_probe"].add(signal_token)

    for note in execution_notes:
        if not isinstance(note, dict):
            continue
        url = str(note.get("url", "") or "").strip()
        if not url:
            continue

        vuln_type = str(note.get("vuln_type", "unknown") or "unknown").strip().lower()
        if not vuln_type:
            vuln_type = "unknown"
        status = str(note.get("status", "") or "").strip().lower()
        duration_seconds = _as_float(note.get("duration_seconds"), 0.0)
        tested_params_raw = note.get("tested_params", [])
        tested_params = []
        if isinstance(tested_params_raw, str):
            token = tested_params_raw.strip()
            if token:
                tested_params = [token]
        elif isinstance(tested_params_raw, list):
            tested_params = [str(p).strip() for p in tested_params_raw if str(p).strip()]

        blind_correlation = note.get("blind_correlation", {})
        blind_correlation = blind_correlation if isinstance(blind_correlation, dict) else {}
        time_based = blind_correlation.get("time_based", {}) if isinstance(blind_correlation.get("time_based"), dict) else {}
        oob = blind_correlation.get("oob", {}) if isinstance(blind_correlation.get("oob"), dict) else {}
        blind_confirmed = bool(blind_correlation.get("correlated")) or bool(time_based.get("confirmed")) or bool(oob.get("confirmed"))
        note_poc_request = _extract_note_http_artifact(
            note,
            ["poc_request", "request", "raw_request", "request_raw"],
        )
        note_poc_response = _extract_note_http_artifact(
            note,
            ["poc_response", "response", "raw_response", "response_raw"],
        )

        confidence = 0.0
        reasons: list[str] = []
        if tested_params:
            confidence += 0.45
            reasons.append("tested_params")
        if blind_confirmed:
            confidence += 0.45
            reasons.append("blind_confirmation")
        if status in {"timeout", "error"}:
            confidence += 0.25
            reasons.append(f"status_{status}")
        if duration_seconds >= 20.0:
            confidence += 0.15
            reasons.append("long_duration")
        if duration_seconds >= 35.0:
            confidence += 0.10
            reasons.append("very_long_duration")
        if vuln_type == "unknown":
            confidence += 0.20
            reasons.append("unknown_path")

        lower_params = {param.lower() for param in tested_params}
        privilege_sensitive_params = {"role", "is_admin", "admin", "permission", "scope"}
        has_privilege_sensitive_param = bool(lower_params.intersection(privilege_sensitive_params))
        if vuln_type == "api" and has_privilege_sensitive_param:
            confidence += 0.20
            reasons.append("privilege_sensitive_param")

        confidence = min(0.95, round(confidence, 2))
        if confidence < 0.50 and not tested_params and not blind_confirmed:
            continue

        severity = "info"
        if blind_confirmed or "privilege_sensitive_param" in reasons:
            severity = "medium"
        elif confidence >= 0.70:
            severity = "low"

        signal_key = (url, "api")
        signal_stats = repeat_signal_stats.get(signal_key, {})
        privilege_probe_count = len(signal_stats.get("privilege_probe", set()))
        completed_probe_count = len(signal_stats.get("completed_with_probe", set()))
        total_signal_count = len(signal_stats.get("total", set()))
        repeated_privilege_probe = (
            privilege_probe_count >= promote_privilege_probe_min
            and completed_probe_count >= promote_completed_probe_min
        )

        if "privilege_sensitive_param" in reasons:
            title = "Potential privilege parameter tampering surface"
            vuln_type = "mass_assignment"
        elif vuln_type == "unknown":
            title = "Potential high-friction unknown attack surface"
        else:
            title = f"Potential {vuln_type.upper()} attack surface"

        scenario_hints: list[str] = []
        ssrf_like_params = {
            "url",
            "uri",
            "target",
            "dest",
            "destination",
            "callback",
            "webhook",
            "redirect",
            "next",
            "return",
            "endpoint",
            "host",
        }
        has_ssrf_like_params = bool(lower_params.intersection(ssrf_like_params))

        if vuln_type in {"api", "unknown", "mass_assignment"} and "scn_11_multi_vector_chain" in missing_scenarios:
            scenario_hints.append("scn_11_multi_vector_chain")
        should_hint_scn12 = (
            vuln_type in {"redirect", "cmd_ssrf"}
            or (
                vuln_type in {"api", "unknown"}
                and has_ssrf_like_params
                and not has_privilege_sensitive_param
            )
        )
        if should_hint_scn12 and "scn_12_advanced_ssrf_internal_topology" in missing_scenarios:
            scenario_hints.append("scn_12_advanced_ssrf_internal_topology")

        key = (url, vuln_type, title)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        if repeated_privilege_probe and "privilege_sensitive_param" in reasons:
            summary_intro = "Auto-verified heuristic signal from repeated successful privilege-parameter probes."
        else:
            summary_intro = "Heuristic candidate generated from execution telemetry; manual verification required."

        summary_parts = [
            summary_intro,
            f"status={status or '-'}",
            f"duration={duration_seconds:.3f}s" if duration_seconds > 0 else "duration=-",
        ]
        if tested_params:
            summary_parts.append(f"tested_params={', '.join(tested_params)}")
        if blind_confirmed:
            summary_parts.append("blind=confirmed")
        if scenario_hints:
            summary_parts.append(f"scenario_hint={', '.join(scenario_hints)}")

        heuristic_candidate = not (repeated_privilege_probe and "privilege_sensitive_param" in reasons)
        detection_mode = "heuristic_promoted" if not heuristic_candidate else "heuristic_fallback"
        detection_class = _infer_heuristic_detection_class(url, vuln_type)
        if heuristic_candidate:
            impact_text = "Potential security impact exists, but this item is not yet confirmed as a valid reportable vulnerability."
        else:
            impact_text = "Repeated successful privilege-parameter probes indicate elevated privilege-tampering risk and this item is promoted for remediation priority."
        candidates.append(
            {
                "title": title,
                "severity": severity,
                "vuln_type": vuln_type,
                "target_url": url,
                "summary": " | ".join(summary_parts),
                "impact": impact_text,
                "confidence": confidence,
                "poc_request": note_poc_request,
                "poc_response": note_poc_response,
                "steps_to_reproduce": [
                    "同じURL・同じ認証状態で再送し、レスポンス差分を記録する。",
                    "対象パラメータを1つずつ改ざんし、権限/状態変化の有無を比較する。",
                    "差分が再現した場合のみ、PoCを確定して正式findingへ昇格する。",
                ],
                "references": [
                    "OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/",
                ],
                "additional_info": {
                    "heuristic_candidate": heuristic_candidate,
                    "verification_required": heuristic_candidate,
                    "heuristic_source": "report_execution_notes",
                    "heuristic_reasons": reasons,
                    "detection_mode": detection_mode,
                    "detection_class": detection_class,
                    "tested_params": tested_params,
                    "blind_correlation": blind_correlation,
                    "status": status,
                    "duration_seconds": duration_seconds,
                    "poc_request": note_poc_request,
                    "poc_response": note_poc_response,
                    "scenario_hints": scenario_hints,
                    "repeat_signal": {
                        "total": int(total_signal_count),
                        "completed_with_probe": int(completed_probe_count),
                        "privilege_probe": int(privilege_probe_count),
                        "privilege_probe_min": int(promote_privilege_probe_min),
                        "completed_with_probe_min": int(promote_completed_probe_min),
                    },
                },
            }
        )

    candidates.sort(key=lambda item: float(item.get("confidence", 0.0) or 0.0), reverse=True)
    if max_candidates > 0:
        candidates = candidates[:max_candidates]

    if not candidates:
        return []

    for item in candidates:
        if not str(item.get("target_url", "") or "").strip():
            item["target_url"] = normalized_target
    return candidates


def finding_signature_for_merge(entry: Any) -> tuple[str, str, str] | None:
    if not isinstance(entry, dict):
        return None
    target = str(entry.get("target_url", entry.get("target", entry.get("url", ""))) or "").strip().lower()
    vuln_type = str(entry.get("vuln_type", entry.get("type", "")) or "").strip().lower()
    title = str(entry.get("title", "") or "").strip().lower()
    if not target and not vuln_type and not title:
        return None
    return (target, vuln_type, title)


def merge_heuristic_candidates_into_findings(
    *,
    confirmed_findings: list[Any],
    heuristic_candidates: list[dict[str, Any]],
    max_append: int = 3,
) -> list[Any]:
    """
    confirmed findings を維持したまま、重複しない heuristic candidate を追記する。
    """
    merged: list[Any] = list(confirmed_findings or [])
    if not isinstance(heuristic_candidates, list) or not heuristic_candidates:
        return merged

    seen_signatures: set[tuple[str, str, str]] = set()
    confirmed_targets: set[str] = set()
    confirmed_target_vuln_pairs: set[tuple[str, str]] = set()
    for entry in merged:
        signature = finding_signature_for_merge(entry)
        if signature is not None:
            seen_signatures.add(signature)
        if isinstance(entry, dict):
            entry_target = str(entry.get("target_url", entry.get("target", entry.get("url", ""))) or "").strip().lower()
            if entry_target:
                confirmed_targets.add(entry_target)
                entry_vuln_type = str(entry.get("vuln_type", entry.get("type", "")) or "").strip().lower()
                if entry_vuln_type:
                    confirmed_target_vuln_pairs.add((entry_target, entry_vuln_type))

    appended = 0
    append_limit = int(max_append)
    for candidate in heuristic_candidates:
        if not isinstance(candidate, dict):
            continue
        if append_limit >= 0 and appended >= append_limit:
            break
        signature = finding_signature_for_merge(candidate)
        if signature is not None and signature in seen_signatures:
            continue
        candidate_target = str(candidate.get("target_url", candidate.get("target", candidate.get("url", ""))) or "").strip().lower()
        candidate_vuln_type = str(candidate.get("vuln_type", candidate.get("type", "")) or "").strip().lower()
        candidate_info = candidate.get("additional_info", {})
        candidate_info = candidate_info if isinstance(candidate_info, dict) else {}
        candidate_detection_mode = str(candidate_info.get("detection_mode", "") or "").strip().lower()
        candidate_is_promoted = (
            candidate_detection_mode == "heuristic_promoted"
            and not bool(candidate_info.get("heuristic_candidate"))
        )
        if candidate_target and candidate_target in confirmed_targets:
            if not candidate_is_promoted:
                continue
            if candidate_vuln_type and (candidate_target, candidate_vuln_type) in confirmed_target_vuln_pairs:
                continue
        if signature is not None:
            seen_signatures.add(signature)
        merged.append(candidate)
        if candidate_target:
            confirmed_targets.add(candidate_target)
            if candidate_vuln_type:
                confirmed_target_vuln_pairs.add((candidate_target, candidate_vuln_type))
        appended += 1
    return merged
