"""InjectionManager 専用 API minimal check runner。

InjectionManager._run_api_minimal_check の実装本体。
依存は ApiProbeDependencies で注入し、self や InjectionManagerAgent 全体を受け取らない。
"""

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.agents.swarm.injection.manager_internal.api_probe_analysis import (
    build_authz_differential,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_auth_context import (
    resolve_auth_b_context,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_auth_matrix import (
    finalize_auth_context_matrix,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_evidence import (
    render_http_request,
    render_http_response,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_object_ab import (
    run_object_ab_comparison,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_object_target import (
    build_object_ab_target,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_payload import (
    build_mass_assignment_probe_payload,
    build_mass_assignment_variant_payload,
    extract_mass_assignment_schema_candidates,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_read_probe import (
    build_fallback_read_probe_url,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_targets import (
    build_nearby_api_candidates,
    dedupe_urls,
    extract_api_like_urls,
)
from src.core.agents.swarm.injection.manager_internal.models import (
    ApiProbeDependencies,
)
from src.core.agents.swarm.injection.manager_internal.result_normalizer import (
    normalize_findings_additional_info,
    sanitize_tested_params,
)


async def run_api_minimal_check(
    url: str,
    base_params: Dict[str, Any],
    *,
    deps: ApiProbeDependencies,
) -> Dict[str, Any]:
    request_client = deps["request_client"]
    findings_sink = deps["findings_sink"]
    source_agent_name = deps["source_agent_name"]
    excluded_params = deps["excluded_params"]
    looks_like_login_page = deps["looks_like_login_page"]
    resolve_detection_mode = deps["resolve_detection_mode"]

    auth = base_params.get("_auth", {}) if isinstance(base_params.get("_auth", {}), dict) else {}
    auth_headers = dict(auth.get("auth_headers", {}) or {})
    cookies = str(auth.get("cookies", "") or base_params.get("cookies", "") or "")
    if cookies and "Cookie" not in auth_headers:
        auth_headers["Cookie"] = cookies
    unauth_headers = {k: v for k, v in auth_headers.items() if k.lower() not in {"authorization", "cookie"}}
    findings_start_index = len(findings_sink)

    findings_count = 0
    detection_mode = resolve_detection_mode(base_params, "phase1")
    tested_params: List[str] = []
    api_probe_sent = False
    api_probe_skipped_reason = ""
    discovered_api_urls: List[str] = []
    comparison_checks: List[Dict[str, Any]] = []
    auth_context_matrix: Dict[str, Any] = {
        "mode": "unauth_authA_authB",
        "available": False,
        "rows": [],
        "signals": [],
    }
    object_ab_comparison: Dict[str, Any] = {"performed": False}
    object_ab_baseline_body = ""
    object_ab_variant_body = ""
    schema_candidate_params: List[str] = []
    single_request_validation = True
    probe_request_raw = ""
    probe_response_raw = ""

    resp_auth = await request_client.request(
        method="GET",
        url=url,
        headers=auth_headers,
        timeout=30,
        use_cache=False,
        allow_redirects=True,
    )
    auth_body = str(getattr(resp_auth, "body", "") or "")
    auth_status = int(getattr(resp_auth, "status", 0) or 0)
    auth_headers_resp = dict(getattr(resp_auth, "headers", {}) or {})
    auth_content_type = str(auth_headers_resp.get("Content-Type", auth_headers_resp.get("content-type", "")) or "").lower()
    api_probe_target = url

    resp_get = await request_client.request(
        method="GET",
        url=url,
        headers=unauth_headers,
        timeout=30,
        use_cache=False,
        allow_redirects=True,
    )
    body = str(getattr(resp_get, "body", "") or "")
    headers = dict(getattr(resp_get, "headers", {}) or {})
    content_type = str(headers.get("Content-Type", headers.get("content-type", "")) or "").lower()
    status = int(getattr(resp_get, "status", 0) or 0)
    looks_json = "application/json" in content_type or body.strip().startswith("{") or body.strip().startswith("[")
    auth_looks_json = "application/json" in auth_content_type or auth_body.strip().startswith("{") or auth_body.strip().startswith("[")
    body_len_delta = abs(len(body) - len(auth_body))
    path_lower = urlparse(url).path.lower()
    api_like_path = "/api/" in path_lower or path_lower.endswith("/api") or "/vulnerabilities/api" in path_lower
    unauth_login_like = looks_like_login_page(body)
    body_similarity = (
        auth_status in {200, 201, 202, 204}
        and status in {200, 201, 202, 204}
        and body_len_delta <= max(120, int(len(auth_body) * 0.2))
    )
    auth_context_matrix["rows"].append(
        {
            "actor": "unauth",
            "status": status,
            "json_like": looks_json,
            "body_length": len(body),
        }
    )
    auth_context_matrix["rows"].append(
        {
            "actor": "authA",
            "status": auth_status,
            "json_like": auth_looks_json,
            "body_length": len(auth_body),
        }
    )

    def _capture_probe_evidence(
        *,
        method: str,
        request_url: str,
        request_headers: Dict[str, Any],
        request_payload: Any,
        response_status: int,
        response_headers: Dict[str, Any],
        response_body: Any,
    ) -> None:
        nonlocal probe_request_raw, probe_response_raw
        probe_request_raw = render_http_request(
            method=method,
            request_url=request_url,
            request_headers=request_headers,
            request_payload=request_payload,
        )
        probe_response_raw = render_http_response(
            status_code=response_status,
            response_headers=response_headers,
            response_body=response_body,
        )

    # AuthZ 3-way matrix: unauth vs authA vs authB（authB は利用可能時）
    alternative_sessions: Dict[str, Any] = {}
    if bool(auth.get("auth_matrix_from_multi_session", False)):
        try:
            from src.core.session.multi_session_manager import get_multi_session_manager

            manager = get_multi_session_manager()
            alternative_sessions = manager.get_all_alternative_sessions()
        except Exception:
            alternative_sessions = {}

    auth_b_headers, auth_b_role = resolve_auth_b_context(
        auth=auth,
        auth_headers=auth_headers,
        alternative_sessions=alternative_sessions,
    )

    if auth_b_headers:
        auth_b_resp = await request_client.request(
            method="GET",
            url=url,
            headers=auth_b_headers,
            timeout=30,
            use_cache=False,
            allow_redirects=True,
        )
        auth_b_body = str(getattr(auth_b_resp, "body", "") or "")
        auth_b_status = int(getattr(auth_b_resp, "status", 0) or 0)
        auth_b_headers_resp = dict(getattr(auth_b_resp, "headers", {}) or {})
        auth_b_content_type = str(
            auth_b_headers_resp.get("Content-Type", auth_b_headers_resp.get("content-type", "")) or ""
        ).lower()
        auth_b_json_like = (
            "application/json" in auth_b_content_type
            or auth_b_body.strip().startswith("{")
            or auth_b_body.strip().startswith("[")
        )
        auth_context_matrix["rows"].append(
            {
                "actor": "authB",
                "role": auth_b_role or "authB",
                "status": auth_b_status,
                "json_like": auth_b_json_like,
                "body_length": len(auth_b_body),
            }
        )
    auth_context_matrix = finalize_auth_context_matrix(
        rows=list(auth_context_matrix.get("rows", [])),
        auth_status=auth_status,
        unauth_status=status,
    )
    comparison_checks.append(
        {
            "kind": "auth_context_three_way",
            "matrix": auth_context_matrix,
        }
    )

    # IDOR/BOLA object A/B 比較（ID が特定できる場合のみ）
    object_ab_candidate = build_object_ab_target(url)
    if object_ab_candidate:
        object_ab_result = await run_object_ab_comparison(
            request_client=request_client,
            url=url,
            auth_headers=auth_headers,
            object_ab_candidate=object_ab_candidate,
        )
        if object_ab_result.get("performed"):
            object_ab_baseline_body = str(object_ab_result.get("baseline_body", "") or "")
            object_ab_variant_body = str(object_ab_result.get("variant_body", "") or "")
            object_ab_comparison = dict(object_ab_result.get("comparison", {}) or {"performed": False})
            comparison_checks.append(
                {
                    "kind": "object_ab",
                    "comparison": object_ab_comparison,
                }
            )
            param_name = str(object_ab_result.get("param_name", "") or "").strip()
            if param_name and param_name != "path_id":
                tested_params.append(param_name)
            single_request_validation = False

    if (
        status in {200, 201, 202, 204}
        and not unauth_login_like
        and (
            looks_json
            or (auth_looks_json and body_similarity)
            or (api_like_path and body_similarity)
        )
    ):
        finding = Finding(
            vuln_type=VulnType.BROKEN_ACCESS_CONTROL,
            severity=Severity.MEDIUM,
            title="Potential Unauthenticated API Access",
            description="API-like endpoint responded successfully without auth headers/cookies and appears close to authenticated response.",
            target_url=url,
            evidence=Evidence(
                request_method="GET",
                request_url=url,
                request_headers=unauth_headers,
                response_status=status,
                response_headers=headers,
                response_body=body[:500],
            ),
            source_agent=source_agent_name,
            confidence=0.65,
            tags=["api_candidate", "manual_verify"],
            additional_info={
                "parameter": "",
                "payload": "",
                "payloads_used": [],
                "tested_params": tested_params,
                "detection_mode": detection_mode,
                "comparison_checks": comparison_checks,
                "auth_context_matrix": auth_context_matrix,
                "object_ab_comparison": object_ab_comparison,
                "schema_candidate_params": schema_candidate_params,
                "single_request_validation": single_request_validation,
                "auth_status": auth_status,
                "unauth_status": status,
                "body_length_delta": body_len_delta,
                "authz_differential": build_authz_differential(
                    scenario="unauthenticated_api_access",
                    baseline_status=auth_status,
                    test_status=status,
                    baseline_body=auth_body,
                    test_body=body,
                    baseline_json_like=auth_looks_json,
                    test_json_like=looks_json,
                    length_close=body_similarity,
                    extra_signals=["api_like_path"] if api_like_path else [],
                ),
            },
        )
        findings_sink.append(finding)
        findings_count += 1

        object_ab_ok = bool(object_ab_comparison.get("performed"))
        object_ab_status_a = int(object_ab_comparison.get("status_a", 0) or 0)
        object_ab_status_b = int(object_ab_comparison.get("status_b", 0) or 0)
        object_ab_param = str(object_ab_comparison.get("param", "") or "").strip()
        object_ab_url_b = str(object_ab_comparison.get("url_b", "") or "").strip()
        if (
            object_ab_ok
            and object_ab_param
            and object_ab_status_a in {200, 201, 202, 204}
            and object_ab_status_b in {200, 201, 202, 204}
        ):
            idor_target_url = object_ab_url_b or url
            idor_finding = Finding(
                vuln_type=VulnType.IDOR,
                severity=Severity.MEDIUM,
                title="Potential IDOR/BOLA via Object Parameter Mutation",
                description=(
                    "Object-parameter mutation changed the target resource while access remained successful "
                    "under the same authenticated context."
                ),
                target_url=idor_target_url,
                evidence=Evidence(
                    request_method="GET",
                    request_url=idor_target_url,
                    request_headers=auth_headers,
                    response_status=object_ab_status_b,
                    response_headers=headers,
                    response_body=object_ab_variant_body[:500] if object_ab_variant_body else body[:500],
                ),
                source_agent=source_agent_name,
                confidence=0.7,
                tags=["idor", "auth_context"],
                additional_info={
                    "parameter": object_ab_param,
                    "payload": "",
                    "payloads_used": [],
                    "tested_params": tested_params,
                    "detection_mode": detection_mode,
                    "comparison_checks": comparison_checks,
                    "auth_context_matrix": auth_context_matrix,
                    "object_ab_comparison": object_ab_comparison,
                    "schema_candidate_params": schema_candidate_params,
                    "single_request_validation": False,
                    "auth_status": object_ab_status_a,
                    "unauth_status": object_ab_status_b,
                    "body_length_delta": abs(
                        int(object_ab_comparison.get("body_length_a", 0) or 0)
                        - int(object_ab_comparison.get("body_length_b", 0) or 0)
                    ),
                    "detection_class": "idor_bola",
                    "authz_differential": build_authz_differential(
                        scenario="object_ab_idor_probe",
                        baseline_status=object_ab_status_a,
                        test_status=object_ab_status_b,
                        baseline_body=object_ab_baseline_body,
                        test_body=object_ab_variant_body,
                        baseline_json_like=bool(
                            str(object_ab_baseline_body or "").strip().startswith("{")
                            or str(object_ab_baseline_body or "").strip().startswith("[")
                        ),
                        test_json_like=bool(
                            str(object_ab_variant_body or "").strip().startswith("{")
                            or str(object_ab_variant_body or "").strip().startswith("[")
                        ),
                        length_close=abs(
                            int(object_ab_comparison.get("body_length_a", 0) or 0)
                            - int(object_ab_comparison.get("body_length_b", 0) or 0)
                        )
                        <= 120,
                        extra_signals=["object_ab_param_mutation"],
                    ),
                },
            )
            findings_sink.append(idor_finding)
            findings_count += 1

    # API ランディングページに紐づく実 API endpoint（例: /v2/user/）を抽出して再評価
    if findings_count == 0:
        discovered_api_urls = extract_api_like_urls(url, auth_body)
        for discovered_url in discovered_api_urls:
            try:
                probe_auth = await request_client.request(
                    method="GET",
                    url=discovered_url,
                    headers=auth_headers,
                    timeout=20,
                    use_cache=False,
                    allow_redirects=True,
                )
                probe_unauth = await request_client.request(
                    method="GET",
                    url=discovered_url,
                    headers=unauth_headers,
                    timeout=20,
                    use_cache=False,
                    allow_redirects=True,
                )
            except Exception:
                continue

            probe_auth_body = str(getattr(probe_auth, "body", "") or "")
            probe_unauth_body = str(getattr(probe_unauth, "body", "") or "")
            probe_auth_status = int(getattr(probe_auth, "status", 0) or 0)
            probe_unauth_status = int(getattr(probe_unauth, "status", 0) or 0)
            probe_auth_headers = dict(getattr(probe_auth, "headers", {}) or {})
            probe_auth_content_type = str(
                probe_auth_headers.get("Content-Type", probe_auth_headers.get("content-type", ""))
                or ""
            ).lower()
            if looks_like_login_page(probe_unauth_body):
                continue

            probe_json_like = (
                probe_unauth_body.strip().startswith("{")
                or probe_unauth_body.strip().startswith("[")
                or "application/json" in str(getattr(probe_unauth, "headers", {}).get("Content-Type", "")).lower()
            )
            probe_auth_json_like = (
                probe_auth_body.strip().startswith("{")
                or probe_auth_body.strip().startswith("[")
                or "application/json" in probe_auth_content_type
            )
            probe_len_delta = abs(len(probe_unauth_body) - len(probe_auth_body))
            probe_similar = (
                probe_auth_status in {200, 201, 202, 204}
                and probe_unauth_status in {200, 201, 202, 204}
                and probe_len_delta <= max(120, int(len(probe_auth_body) * 0.2))
            )
            if probe_unauth_status in {200, 201, 202, 204} and (probe_json_like or probe_similar):
                finding = Finding(
                    vuln_type=VulnType.BROKEN_ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    title="Unauthenticated Access to Discovered API Endpoint",
                    description="API landing page exposed an endpoint that returned successful unauthenticated response.",
                    target_url=discovered_url,
                    evidence=Evidence(
                        request_method="GET",
                        request_url=discovered_url,
                        request_headers=unauth_headers,
                        response_status=probe_unauth_status,
                        response_headers=dict(getattr(probe_unauth, "headers", {}) or {}),
                        response_body=probe_unauth_body[:500],
                    ),
                    source_agent=source_agent_name,
                    confidence=0.8,
                    tags=["api_candidate", "manual_verify"],
                    additional_info={
                        "parameter": "",
                        "payload": "",
                        "payloads_used": [],
                        "tested_params": tested_params,
                        "detection_mode": detection_mode,
                        "comparison_checks": comparison_checks,
                        "auth_context_matrix": auth_context_matrix,
                        "object_ab_comparison": object_ab_comparison,
                        "schema_candidate_params": schema_candidate_params,
                        "single_request_validation": single_request_validation,
                        "discovered_from": url,
                        "authz_differential": build_authz_differential(
                            scenario="unauthenticated_discovered_api_access",
                            baseline_status=probe_auth_status,
                            test_status=probe_unauth_status,
                            baseline_body=probe_auth_body,
                            test_body=probe_unauth_body,
                            baseline_json_like=probe_auth_json_like,
                            test_json_like=probe_json_like,
                            length_close=probe_similar,
                            extra_signals=["discovered_from_landing"],
                        ),
                    },
                )
                findings_sink.append(finding)
                findings_count += 1
                _capture_probe_evidence(
                    method="GET",
                    request_url=discovered_url,
                    request_headers=unauth_headers,
                    request_payload="",
                    response_status=probe_unauth_status,
                    response_headers=dict(getattr(probe_unauth, "headers", {}) or {}),
                    response_body=probe_unauth_body,
                )
                api_probe_target = discovered_url
                break

    resp_options = await request_client.request(
        method="OPTIONS",
        url=api_probe_target,
        headers=unauth_headers,
        timeout=20,
        use_cache=False,
        allow_redirects=False,
    )
    opt_headers = dict(getattr(resp_options, "headers", {}) or {})
    allow_hdr = str(opt_headers.get("Allow", opt_headers.get("allow", "")) or "").upper()
    if any(m in allow_hdr for m in ["PUT", "PATCH", "DELETE"]):
        finding = Finding(
            vuln_type=VulnType.MASS_ASSIGNMENT,
            severity=Severity.MEDIUM,
            title="Potential Over-Permissive API Method Exposure",
            description="Unauthenticated OPTIONS response exposed sensitive write methods. Manual verification required.",
            target_url=url,
            evidence=Evidence(
                request_method="OPTIONS",
                request_url=url,
                request_headers=unauth_headers,
                response_status=int(getattr(resp_options, "status", 0) or 0),
                response_headers=opt_headers,
                response_body="",
            ),
            source_agent=source_agent_name,
            confidence=0.55,
            tags=["api_candidate", "manual_verify"],
            additional_info={
                "parameter": "",
                "payload": "",
                "payloads_used": [],
                "tested_params": tested_params,
                "detection_mode": detection_mode,
                "comparison_checks": comparison_checks,
                "auth_context_matrix": auth_context_matrix,
                "object_ab_comparison": object_ab_comparison,
                "schema_candidate_params": schema_candidate_params,
                "single_request_validation": single_request_validation,
            },
        )
        findings_sink.append(finding)
        findings_count += 1

    # 軽量 mass-assignment probe（応答スキーマから候補キーを抽出して拡張）
    schema_probe_fields = extract_mass_assignment_schema_candidates(
        response_bodies=[auth_body, body],
        excluded_params=excluded_params,
    )
    probe_payload, schema_candidate_params = build_mass_assignment_probe_payload(schema_probe_fields)
    tested_params.extend(
        schema_candidate_params
    )
    single_request_validation = False
    has_auth_context = bool(
        str(auth_headers.get("Authorization", "") or "").strip()
        or str(auth_headers.get("Cookie", "") or "").strip()
    )
    probe_method: Optional[str] = None
    probe_headers: Dict[str, Any] = {}

    if any(m in allow_hdr for m in ["POST", "PUT", "PATCH"]) or "/api/" in urlparse(url).path.lower():
        probe_method = "POST"
        if "PATCH" in allow_hdr:
            probe_method = "PATCH"
        elif "PUT" in allow_hdr:
            probe_method = "PUT"
        probe_headers = dict(unauth_headers)
        probe_headers.setdefault("Content-Type", "application/json")
    else:
        # OPTIONS に write method が出ない場合のフォールバック探索
        discovery_payload = {"__shigoku_probe": "method_discovery", "dry_run": True}
        discovery_methods = ["PATCH", "PUT", "POST"]
        discovery_targets = dedupe_urls(
            [api_probe_target] + discovered_api_urls + build_nearby_api_candidates(api_probe_target)
        )

        for candidate_target in discovery_targets:
            for candidate_method in discovery_methods:
                discovery_headers = dict(unauth_headers)
                discovery_headers.setdefault("Content-Type", "application/json")
                try:
                    discovery_resp = await request_client.request(
                        method=candidate_method,
                        url=candidate_target,
                        headers=discovery_headers,
                        json=discovery_payload,
                        timeout=15,
                        use_cache=False,
                        allow_redirects=False,
                    )
                except Exception:
                    continue
                discovery_status = int(getattr(discovery_resp, "status", 0) or 0)
                if discovery_status not in {404, 405, 501}:
                    probe_method = candidate_method
                    probe_headers = discovery_headers
                    api_probe_target = candidate_target
                    break
            if probe_method:
                break

        if probe_method is None and has_auth_context:
            for candidate_target in discovery_targets:
                for candidate_method in discovery_methods:
                    discovery_headers = dict(auth_headers)
                    discovery_headers.setdefault("Content-Type", "application/json")
                    try:
                        discovery_resp = await request_client.request(
                            method=candidate_method,
                            url=candidate_target,
                            headers=discovery_headers,
                            json=discovery_payload,
                            timeout=15,
                            use_cache=False,
                            allow_redirects=False,
                        )
                    except Exception:
                        continue
                    discovery_status = int(getattr(discovery_resp, "status", 0) or 0)
                    if discovery_status not in {404, 405, 501}:
                        probe_method = candidate_method
                        probe_headers = discovery_headers
                        api_probe_target = candidate_target
                        break
                if probe_method:
                    break

    if probe_method:
        api_probe_sent = True
        tested_params.extend(
            [
                key
                for key in probe_payload.keys()
                if str(key or "").strip() and str(key or "").strip() != "__shigoku_probe"
            ]
        )
        mass_assignment_finding_emitted = False
        probe_resp = await request_client.request(
            method=probe_method,
            url=api_probe_target,
            headers=probe_headers,
            json=probe_payload,
            timeout=20,
            use_cache=False,
            allow_redirects=False,
        )
        probe_status = int(getattr(probe_resp, "status", 0) or 0)
        probe_body_raw = str(getattr(probe_resp, "body", "") or "")
        probe_resp_headers = dict(getattr(probe_resp, "headers", {}) or {})
        _capture_probe_evidence(
            method=probe_method,
            request_url=api_probe_target,
            request_headers=probe_headers,
            request_payload=probe_payload,
            response_status=probe_status,
            response_headers=probe_resp_headers,
            response_body=probe_body_raw,
        )
        probe_body = probe_body_raw.lower()
        reflection_markers = ["role", "is_admin", "__shigoku_probe", "admin"]
        reflection_hit = any(k in probe_body for k in reflection_markers)
        payloads_used = [json.dumps(probe_payload)]
        auto_reverification: Dict[str, Any] = {
            "performed": False,
            "reproduced": False,
            "initial_status": probe_status,
            "initial_body_length": len(probe_body_raw),
            "reflection_detected": reflection_hit,
        }

        reproducible_acceptance = False
        reflection_reproduced = False
        reflection_recheck_payload: Dict[str, Any] = {}
        reflection_recheck_status = 0
        reflection_recheck_headers: Dict[str, Any] = {}
        reflection_recheck_body_raw = ""
        recheck_payload: Dict[str, Any] = {}
        recheck_status = 0
        recheck_headers: Dict[str, Any] = {}
        recheck_body_raw = ""

        if probe_status in {200, 201, 202, 204} and reflection_hit:
            reflection_recheck_payload = build_mass_assignment_variant_payload(
                probe_payload,
                marker="mass_assignment_reflect_recheck",
            )
            payloads_used.append(json.dumps(reflection_recheck_payload))
            auto_reverification["performed"] = True
            try:
                reflection_recheck_resp = await request_client.request(
                    method=probe_method,
                    url=api_probe_target,
                    headers=probe_headers,
                    json=reflection_recheck_payload,
                    timeout=20,
                    use_cache=False,
                    allow_redirects=False,
                )
                reflection_recheck_status = int(getattr(reflection_recheck_resp, "status", 0) or 0)
                reflection_recheck_headers = dict(getattr(reflection_recheck_resp, "headers", {}) or {})
                reflection_recheck_body_raw = str(getattr(reflection_recheck_resp, "body", "") or "")
                reflection_recheck_body = reflection_recheck_body_raw.lower()
                reflection_login_like = looks_like_login_page(reflection_recheck_body_raw)
                reflection_reproduced = (
                    reflection_recheck_status in {200, 201, 202, 204}
                    and not reflection_login_like
                    and ("auditor" in reflection_recheck_body or "is_admin" in reflection_recheck_body)
                )
                auto_reverification.update(
                    {
                        "reflection_recheck_status": reflection_recheck_status,
                        "reflection_recheck_body_length": len(reflection_recheck_body_raw),
                        "reflection_recheck_login_like": reflection_login_like,
                        "reflection_reproduced": reflection_reproduced,
                    }
                )
            except Exception as exc:
                auto_reverification["reflection_recheck_error"] = str(exc)

        if probe_status in {200, 201, 202, 204} and not reflection_hit:
            recheck_payload = build_mass_assignment_variant_payload(
                probe_payload,
                marker="mass_assignment_recheck",
            )
            payloads_used.append(json.dumps(recheck_payload))
            auto_reverification["performed"] = True
            try:
                recheck_resp = await request_client.request(
                    method=probe_method,
                    url=api_probe_target,
                    headers=probe_headers,
                    json=recheck_payload,
                    timeout=20,
                    use_cache=False,
                    allow_redirects=False,
                )
                recheck_status = int(getattr(recheck_resp, "status", 0) or 0)
                recheck_headers = dict(getattr(recheck_resp, "headers", {}) or {})
                recheck_body_raw = str(getattr(recheck_resp, "body", "") or "")
                recheck_login_like = looks_like_login_page(recheck_body_raw)
                reproducible_acceptance = recheck_status in {200, 201, 202, 204} and not recheck_login_like
                auto_reverification.update(
                    {
                        "reproduced": reproducible_acceptance,
                        "recheck_status": recheck_status,
                        "recheck_body_length": len(recheck_body_raw),
                        "recheck_login_like": recheck_login_like,
                    }
                )
            except Exception as exc:
                auto_reverification["error"] = str(exc)

        if probe_status in {200, 201, 202, 204} and ((reflection_hit and reflection_reproduced) or reproducible_acceptance):
            title = (
                "Potential API Mass Assignment / Over-Posting"
                if reflection_hit and reflection_reproduced
                else "Reproducible Privileged Parameter Acceptance"
            )
            description = (
                "Unauthenticated API probe accepted privileged-looking properties. Manual verification required."
                if reflection_hit and reflection_reproduced
                else "Unauthenticated API accepted two distinct privileged-property probes in sequence. Manual verification required."
            )
            finding_tags = ["api_candidate", "manual_verify"]
            if reproducible_acceptance or reflection_reproduced:
                finding_tags.append("auto_reverified")
            finding = Finding(
                vuln_type=VulnType.MASS_ASSIGNMENT,
                severity=Severity.MEDIUM,
                title=title,
                description=description,
                target_url=url,
                evidence=Evidence(
                    request_method=probe_method,
                    request_url=url,
                    request_headers=probe_headers,
                    request_body=str(recheck_payload or reflection_recheck_payload or probe_payload),
                    response_status=recheck_status or reflection_recheck_status or probe_status,
                    response_headers=recheck_headers or reflection_recheck_headers or dict(getattr(probe_resp, "headers", {}) or {}),
                    response_body=(recheck_body_raw or reflection_recheck_body_raw or probe_body_raw)[:500],
                ),
                source_agent=source_agent_name,
                confidence=0.62 if reflection_reproduced else 0.55,
                tags=finding_tags,
                additional_info={
                    "parameter": ",".join(schema_candidate_params),
                    "payload": json.dumps(recheck_payload or reflection_recheck_payload or probe_payload),
                    "payloads_used": payloads_used,
                    "tested_params": tested_params,
                    "detection_mode": detection_mode,
                    "comparison_checks": comparison_checks,
                    "auth_context_matrix": auth_context_matrix,
                    "object_ab_comparison": object_ab_comparison,
                    "schema_candidate_params": schema_candidate_params,
                    "single_request_validation": single_request_validation,
                    "auto_reverification": auto_reverification,
                },
            )
            findings_sink.append(finding)
            findings_count += 1
            mass_assignment_finding_emitted = True
            _capture_probe_evidence(
                method=probe_method,
                request_url=api_probe_target,
                request_headers=probe_headers,
                request_payload=recheck_payload or reflection_recheck_payload or probe_payload,
                response_status=recheck_status or reflection_recheck_status or probe_status,
                response_headers=recheck_headers or reflection_recheck_headers or probe_resp_headers,
                response_body=recheck_body_raw or reflection_recheck_body_raw or probe_body_raw,
            )

        # 認証必須 API でも over-posting を見逃さないため、認証コンテキストで再検証する。
        initial_probe_used_auth_context = bool(
            str(probe_headers.get("Authorization", "") or "").strip()
            or str(probe_headers.get("Cookie", "") or "").strip()
        )
        if not mass_assignment_finding_emitted and has_auth_context and not initial_probe_used_auth_context:
            auth_probe_headers = dict(auth_headers)
            auth_probe_headers.setdefault("Content-Type", "application/json")
            auth_probe_payload = dict(probe_payload)
            auth_probe_payload["__shigoku_probe"] = "mass_assignment_auth"
            auth_payloads_used = [json.dumps(auth_probe_payload)]
            auth_probe_resp = await request_client.request(
                method=probe_method,
                url=api_probe_target,
                headers=auth_probe_headers,
                json=auth_probe_payload,
                timeout=20,
                use_cache=False,
                allow_redirects=False,
            )
            auth_probe_status = int(getattr(auth_probe_resp, "status", 0) or 0)
            auth_probe_body_raw = str(getattr(auth_probe_resp, "body", "") or "")
            auth_probe_body = auth_probe_body_raw.lower()
            auth_reflection_hit = any(k in auth_probe_body for k in reflection_markers)
            auth_auto_reverification: Dict[str, Any] = {
                "performed": False,
                "reproduced": False,
                "initial_status": auth_probe_status,
                "initial_body_length": len(auth_probe_body_raw),
                "reflection_detected": auth_reflection_hit,
                "context": "authenticated",
            }

            auth_reproduced = False
            auth_reflection_reproduced = False
            auth_reflection_recheck_payload: Dict[str, Any] = {}
            auth_reflection_recheck_status = 0
            auth_reflection_recheck_headers: Dict[str, Any] = {}
            auth_reflection_recheck_body_raw = ""
            auth_recheck_payload: Dict[str, Any] = {}
            auth_recheck_status = 0
            auth_recheck_headers: Dict[str, Any] = {}
            auth_recheck_body_raw = ""
            if auth_probe_status in {200, 201, 202, 204} and auth_reflection_hit:
                auth_reflection_recheck_payload = build_mass_assignment_variant_payload(
                    auth_probe_payload,
                    marker="mass_assignment_auth_reflect_recheck",
                )
                auth_payloads_used.append(json.dumps(auth_reflection_recheck_payload))
                auth_auto_reverification["performed"] = True
                try:
                    auth_reflection_recheck_resp = await request_client.request(
                        method=probe_method,
                        url=api_probe_target,
                        headers=auth_probe_headers,
                        json=auth_reflection_recheck_payload,
                        timeout=20,
                        use_cache=False,
                        allow_redirects=False,
                    )
                    auth_reflection_recheck_status = int(getattr(auth_reflection_recheck_resp, "status", 0) or 0)
                    auth_reflection_recheck_headers = dict(getattr(auth_reflection_recheck_resp, "headers", {}) or {})
                    auth_reflection_recheck_body_raw = str(getattr(auth_reflection_recheck_resp, "body", "") or "")
                    auth_reflection_recheck_body = auth_reflection_recheck_body_raw.lower()
                    auth_reflection_login_like = looks_like_login_page(auth_reflection_recheck_body_raw)
                    auth_reflection_reproduced = (
                        auth_reflection_recheck_status in {200, 201, 202, 204}
                        and not auth_reflection_login_like
                        and ("auditor" in auth_reflection_recheck_body or "is_admin" in auth_reflection_recheck_body)
                    )
                    auth_auto_reverification.update(
                        {
                            "reflection_recheck_status": auth_reflection_recheck_status,
                            "reflection_recheck_body_length": len(auth_reflection_recheck_body_raw),
                            "reflection_recheck_login_like": auth_reflection_login_like,
                            "reflection_reproduced": auth_reflection_reproduced,
                        }
                    )
                except Exception as exc:
                    auth_auto_reverification["reflection_recheck_error"] = str(exc)
            if auth_probe_status in {200, 201, 202, 204} and not auth_reflection_hit:
                auth_recheck_payload = build_mass_assignment_variant_payload(
                    auth_probe_payload,
                    marker="mass_assignment_auth_recheck",
                )
                auth_payloads_used.append(json.dumps(auth_recheck_payload))
                auth_auto_reverification["performed"] = True
                try:
                    auth_recheck_resp = await request_client.request(
                        method=probe_method,
                        url=api_probe_target,
                        headers=auth_probe_headers,
                        json=auth_recheck_payload,
                        timeout=20,
                        use_cache=False,
                        allow_redirects=False,
                    )
                    auth_recheck_status = int(getattr(auth_recheck_resp, "status", 0) or 0)
                    auth_recheck_headers = dict(getattr(auth_recheck_resp, "headers", {}) or {})
                    auth_recheck_body_raw = str(getattr(auth_recheck_resp, "body", "") or "")
                    auth_recheck_login_like = looks_like_login_page(auth_recheck_body_raw)
                    auth_reproduced = auth_recheck_status in {200, 201, 202, 204} and not auth_recheck_login_like
                    auth_auto_reverification.update(
                        {
                            "reproduced": auth_reproduced,
                            "recheck_status": auth_recheck_status,
                            "recheck_body_length": len(auth_recheck_body_raw),
                            "recheck_login_like": auth_recheck_login_like,
                        }
                    )
                except Exception as exc:
                    auth_auto_reverification["error"] = str(exc)

            if auth_probe_status in {200, 201, 202, 204} and ((auth_reflection_hit and auth_reflection_reproduced) or auth_reproduced):
                auth_required = probe_status not in {200, 201, 202, 204}
                auth_finding_tags = ["api_candidate", "manual_verify", "auth_context"]
                if auth_reproduced or auth_reflection_reproduced:
                    auth_finding_tags.append("auto_reverified")
                finding = Finding(
                    vuln_type=VulnType.MASS_ASSIGNMENT,
                    severity=Severity.MEDIUM,
                    title="Potential Authenticated API Mass Assignment / Over-Posting",
                    description="Authenticated API probe accepted privileged-looking properties. Manual verification required.",
                    target_url=url,
                    evidence=Evidence(
                        request_method=probe_method,
                        request_url=url,
                        request_headers=auth_probe_headers,
                        request_body=str(auth_recheck_payload or auth_reflection_recheck_payload or auth_probe_payload),
                        response_status=auth_recheck_status or auth_reflection_recheck_status or auth_probe_status,
                        response_headers=auth_recheck_headers or auth_reflection_recheck_headers or dict(getattr(auth_probe_resp, "headers", {}) or {}),
                        response_body=(auth_recheck_body_raw or auth_reflection_recheck_body_raw or auth_probe_body_raw)[:500],
                    ),
                    source_agent=source_agent_name,
                    confidence=0.64 if auth_reflection_reproduced else 0.58,
                    tags=auth_finding_tags,
                    additional_info={
                        "parameter": ",".join(schema_candidate_params),
                        "payload": json.dumps(auth_recheck_payload or auth_reflection_recheck_payload or auth_probe_payload),
                        "payloads_used": auth_payloads_used,
                        "tested_params": tested_params,
                        "detection_mode": detection_mode,
                        "comparison_checks": comparison_checks,
                        "auth_context_matrix": auth_context_matrix,
                        "object_ab_comparison": object_ab_comparison,
                        "schema_candidate_params": schema_candidate_params,
                        "single_request_validation": single_request_validation,
                        "auth_context_required": auth_required,
                        "auto_reverification": auth_auto_reverification,
                        "authz_differential": build_authz_differential(
                            scenario="authenticated_overposting_requires_auth_context",
                            baseline_status=probe_status,
                            test_status=auth_probe_status,
                            baseline_body=probe_body_raw,
                            test_body=auth_probe_body_raw,
                            baseline_json_like=probe_body_raw.strip().startswith("{")
                            or probe_body_raw.strip().startswith("["),
                            test_json_like=auth_probe_body_raw.strip().startswith("{")
                            or auth_probe_body_raw.strip().startswith("["),
                            length_close=abs(len(auth_probe_body_raw) - len(probe_body_raw))
                            <= max(120, int(len(auth_probe_body_raw) * 0.2)),
                            extra_signals=["status_improved_with_auth"] if auth_required else [],
                        ),
                    },
                )
                findings_sink.append(finding)
                findings_count += 1
    else:
        # write method が判定できない API-like endpoint でも、
        # read-only query probe を1回送って反射/挙動を観測する。
        # （破壊的な更新リクエストは送らない）
        fallback_probe_url = build_fallback_read_probe_url(api_probe_target)

        if fallback_probe_url:
            try:
                fallback_probe_resp = await request_client.request(
                    method="GET",
                    url=fallback_probe_url,
                    headers=unauth_headers,
                    timeout=20,
                    use_cache=False,
                    allow_redirects=False,
                )
                api_probe_sent = True
                tested_params.extend(schema_candidate_params or ["role", "is_admin"])
                fallback_status = int(getattr(fallback_probe_resp, "status", 0) or 0)
                fallback_body_raw = str(getattr(fallback_probe_resp, "body", "") or "")
                _capture_probe_evidence(
                    method="GET",
                    request_url=fallback_probe_url,
                    request_headers=unauth_headers,
                    request_payload="",
                    response_status=fallback_status,
                    response_headers=dict(getattr(fallback_probe_resp, "headers", {}) or {}),
                    response_body=fallback_body_raw,
                )
                fallback_body = fallback_body_raw.lower()
                if (
                    fallback_status in {200, 201, 202, 204}
                    and not looks_like_login_page(fallback_body_raw)
                    and any(token in fallback_body for token in ["__shigoku_probe", "role", "is_admin"])
                ):
                    finding = Finding(
                        vuln_type=VulnType.XSS,
                        severity=Severity.LOW,
                        title="Potential Unauthenticated Input Reflection on API-like Endpoint",
                        description="Read-only probe parameters were reflected by an unauthenticated API-like response. Manual verification required.",
                        target_url=api_probe_target,
                        evidence=Evidence(
                            request_method="GET",
                            request_url=fallback_probe_url,
                            request_headers=unauth_headers,
                            response_status=fallback_status,
                            response_headers=dict(getattr(fallback_probe_resp, "headers", {}) or {}),
                            response_body=fallback_body_raw[:500],
                        ),
                        source_agent=source_agent_name,
                        confidence=0.42,
                        tags=["api_candidate", "xss_candidate", "manual_verify", "read_probe"],
                        additional_info={
                            "parameter": "__shigoku_probe,role,is_admin",
                            "payload": "query_probe",
                            "payloads_used": ["mass_assignment_read_probe"],
                            "tested_params": tested_params,
                            "detection_mode": detection_mode,
                            "comparison_checks": comparison_checks,
                            "auth_context_matrix": auth_context_matrix,
                            "object_ab_comparison": object_ab_comparison,
                            "schema_candidate_params": schema_candidate_params,
                            "single_request_validation": single_request_validation,
                        },
                    )
                    findings_sink.append(finding)
                    findings_count += 1
            except Exception:
                api_probe_skipped_reason = "write_method_not_discovered_and_read_probe_failed"
        else:
            api_probe_skipped_reason = "write_method_not_discovered_from_options_or_fallback_probes"

    if isinstance(findings_sink, list) and findings_start_index < len(findings_sink):
        normalize_findings_additional_info(
            findings_sink[findings_start_index:],
            tested_params,
            detection_mode,
            excluded_params=excluded_params,
        )

    return {
        "findings_count": findings_count,
        "tested_params": sanitize_tested_params(tested_params, excluded_params=excluded_params),
        "probe_sent": api_probe_sent,
        "probe_skipped_reason": api_probe_skipped_reason,
        "probe_request_raw": probe_request_raw,
        "probe_response_raw": probe_response_raw,
        "comparison_checks": comparison_checks,
        "auth_context_matrix": auth_context_matrix,
        "object_ab_comparison": object_ab_comparison,
        "schema_candidate_params": schema_candidate_params,
        "single_request_validation": single_request_validation,
    }
