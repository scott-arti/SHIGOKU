"""
Recon Attack Task Planner

recon 分類結果から attack task を組み立てるロジック。
queue mutation を持たず list[Task] を返す。
PhaseGate 判定 / recon file resolve / history replay などの依存は
コンストラクタで外部から注入する。
"""

from __future__ import annotations

import json
import logging
import uuid as uuid_module
from typing import Any

from src.config import settings
from src.core.domain.model.task import Task
from src.core.engine.phase_gate import Phase
from src.core.engine.task_expander import TaskExpander

logger = logging.getLogger(__name__)

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


class ReconAttackTaskPlanner:
    """recon 結果から attack task list を構築するプランナー。

    依存はすべてコンストラクタで注入し、facade 全体の参照を持たない。
    """

    def __init__(
        self,
        *,
        phase_gate: Any,
        resolve_recon_file_path,
        collect_history_replay_targets,
        get_context_cookie_string,
        get_context_auth_headers,
        apply_phase2_on_empty_policy,
        normalize_url_candidate,
        resolve_required_vuln_families,
        collect_csrf_seed_targets,
        refine_backfill_seed_targets,
        should_enable_phase2_on_empty_for_backfill,
        resolve_task_target,
        resolve_in_scope_hosts,
        map_category_to_vuln_families,
        collect_xss_seed_targets,
        resolve_global_csrf_guard_target,
        plan_missing_link_probes,
        context,
        target_url: str,
        workspace,
    ):
        self._phase_gate = phase_gate
        self._resolve_recon_file_path = resolve_recon_file_path
        self._collect_history_replay_targets = collect_history_replay_targets
        self._get_context_cookie_string = get_context_cookie_string
        self._get_context_auth_headers = get_context_auth_headers
        self._apply_phase2_on_empty_policy = apply_phase2_on_empty_policy
        self._normalize_url_candidate = normalize_url_candidate
        self._resolve_required_vuln_families = resolve_required_vuln_families
        self._collect_csrf_seed_targets = collect_csrf_seed_targets
        self._refine_backfill_seed_targets = refine_backfill_seed_targets
        self._should_enable_phase2_on_empty_for_backfill = should_enable_phase2_on_empty_for_backfill
        self._resolve_task_target = resolve_task_target
        self._resolve_in_scope_hosts = resolve_in_scope_hosts
        self._map_category_to_vuln_families = map_category_to_vuln_families
        self._collect_xss_seed_targets = collect_xss_seed_targets
        self._resolve_global_csrf_guard_target = resolve_global_csrf_guard_target
        self._plan_missing_link_probes = plan_missing_link_probes
        self._context = context
        self._target = target_url
        self._workspace = workspace

    
    def create_attack_tasks_from_recon(self, recon_results: dict[str, dict]) -> list[Task]:
        """
        Recon 結果から Attack タスクを生成

        Args:
            recon_results: step8_return_to_mc が返す分類結果
                          {category: {file, count, description}}

        Returns:
            生成されたタスクのリスト
        """
        tasks = []
        import uuid

        # ATTACK フェーズがアンロックされているかチェック
        can_create, reason = self._phase_gate.can_create_task(Phase.ATTACK)
        if not can_create:
            logger.warning(f"Cannot create ATTACK tasks: {reason}")
            return []

        # カテゴリマップ：タグ → 説明 → Swarm 名
        non_actionable_categories = {"uncategorized", "external_link", "invalid_candidate"}
        category_map = {
            "auth": ("Authentication Analysis", "AuthSwarm", "auth"),
            "admin": ("Admin Panel Access Test", "bizlogic", "logic"),
            "id_param": ("Injection Scan (SQLi/XSS) on Parameters", "InjectionSwarm", "injection"),
            "redirect_param": ("Open Redirect/SSRF Scan", "InjectionSwarm", "injection"),
            "file_param": ("Path Injection Scan (LFI/Traversal)", "InjectionSwarm", "injection"),
            "upload": ("File Upload Vulnerability Scan", "LogicSwarm", "logic"),
            "product_search": ("Product Search Injection Scan", "InjectionSwarm", "injection"),
            "basket_order": ("Basket/Order Logic Scan", "LogicSwarm", "logic"),
            "feedback_review": ("Feedback/Review Input Security Scan", "InjectionSwarm", "injection"),
            "file_exposure_upload": ("File Exposure and Upload Security Scan", "InjectionSwarm", "injection"),
            "api_data": ("API Data Security Scan", "InjectionSwarm", "injection"),
            "client_route_dom": ("Client Route DOM Security Scan", "InjectionSwarm", "injection"),
            "realtime": ("Realtime Endpoint Security Recon", "DiscoverySwarm", "discovery"),
            "meta_observability": ("Meta/Observability Exposure Scan", "DiscoverySwarm", "discovery"),
            "debug_info": ("Debug Info Analysis", "DiscoverySwarm", "discovery"),
            "jwt_detected": ("JWT Security Analysis", "AuthSwarm", "auth"),
            "api_candidate": ("API Candidate Security Scan", "InjectionSwarm", "injection"),
            "api_endpoint": ("API Security Scan", "InjectionSwarm", "injection"),
            "csrf_candidate": ("CSRF Minimal Security Check", "InjectionSwarm", "injection"),
            "xss_candidate": ("XSS/Injection Scan on Forms", "InjectionSwarm", "injection"),
        }

        # 各分類結果からタスクを生成
        for category, data in recon_results.items():
            original_category = category
            normalized_category = category[7:] if category.startswith("tagged_") else category
            count = data.get("count", 0)
            file_path = data.get("file", "")
            
            if count <= 0 or not file_path:
                continue
            if normalized_category in non_actionable_categories:
                logger.info(
                    "Skipping non-actionable recon category '%s' (count=%d)",
                    normalized_category,
                    count,
                )
                continue

            # カテゴリマップにあればそれを使用、なければ汎用タスクを生成
            if normalized_category in category_map:
                name, agent_type, swarm_type = category_map[normalized_category]
                task_name = f"{name} ({count} targets)"
                
                # Swarm 名から適切な agent_type を決定
                if "Swarm" in agent_type:
                    actual_agent = agent_type
                else:
                    actual_agent = agent_type

                # カテゴリからタグを決定
                tag_map = {
                    "auth": ["auth_endpoint", "jwt_token", "token_auth_candidate"],
                    "admin": ["admin_panel"],
                    "id_param": ["sqli_candidate", "idor_candidate", "xss_candidate"],
                    "redirect_param": ["open_redirect", "ssrf_candidate"],
                    "file_param": ["lfi_candidate", "rce_candidate"],
                    "upload": ["file_upload", "rce_candidate"],
                    "product_search": ["api_endpoint", "sqli_candidate", "xss_candidate", "idor_candidate"],
                    "basket_order": ["payment_flow", "idor_candidate", "api_endpoint"],
                    "feedback_review": ["xss_candidate", "api_endpoint"],
                    "file_exposure_upload": ["file_upload", "lfi_candidate", "sensitive_data_exposure"],
                    "api_data": ["api_endpoint", "has_params"],
                    "client_route_dom": ["xss_candidate", "js_file"],
                    "realtime": ["api_endpoint", "auth_required"],
                    "meta_observability": ["debug_info", "api_endpoint"],
                    "debug_info": ["debug_info"],
                    "jwt_detected": ["jwt_token"],
                    "api_candidate": ["api_endpoint", "has_params"],
                    "api_endpoint": ["api_endpoint"],
                    "csrf_candidate": ["csrf_candidate", "auth_endpoint", "workflow_candidate"],
                    "xss_candidate": ["xss_candidate", "sqli_candidate"],
                }

                # --- targets_file から URL リストを事前解決 ---
                # LLM がターゲットを認識できるよう params に targets と target を含める
                resolved_targets: list[str] = []
                forms_by_url: dict[str, list] = {}
                url_evidence_by_url: dict[str, dict] = {}
                normalized_target_keys: set[str] = set()
                low_value_skipped = 0
                realtime_target_budget = int(getattr(settings, "realtime_target_budget", 5) or 5)
                meta_target_budget = int(getattr(settings, "meta_observability_target_budget", 3) or 3)

                def _normalize_target_for_category(url: str, category_name: str) -> str:
                    candidate = str(url or "").strip()
                    if not candidate:
                        return ""
                    if category_name != "realtime":
                        return candidate
                    try:
                        from urllib.parse import urlparse, parse_qs

                        parsed = urlparse(candidate)
                        query = parse_qs(parsed.query, keep_blank_values=True)
                        for volatile in ("t", "sid"):
                            query.pop(volatile, None)
                        stable_pairs = []
                        for key in sorted(query.keys()):
                            for val in query.get(key, []):
                                stable_pairs.append((key, val))
                        stable_query = "&".join(f"{k}={v}" for k, v in stable_pairs)
                        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{stable_query}"
                    except Exception:
                        return candidate

                def _is_low_value_injection_target(url: str, category_name: str, obj: dict | None = None) -> bool:
                    injection_like_categories = {
                        "xss_candidate",
                        "product_search",
                        "feedback_review",
                        "client_route_dom",
                        "api_data",
                        "api_candidate",
                        "api_endpoint",
                        "csrf_candidate",
                    }
                    if category_name not in injection_like_categories:
                        return False

                    try:
                        from urllib.parse import parse_qs, urlparse

                        parsed_url = urlparse(str(url or ""))
                        path_lower = (parsed_url.path or "").lower()
                        query_keys = {k.lower() for k in parse_qs(parsed_url.query).keys()}
                    except Exception:
                        return False

                    candidate_url_lower = str(url or "").lower()
                    static_path_tokens = (
                        "/_next/",
                        "/static/",
                        "/assets/",
                        "/dist/",
                        "/chunks/",
                    )
                    static_extensions = (
                        ".js",
                        ".css",
                        ".map",
                        ".png",
                        ".jpg",
                        ".jpeg",
                        ".gif",
                        ".svg",
                        ".ico",
                        ".webp",
                        ".woff",
                        ".woff2",
                        ".ttf",
                        ".eot",
                    )
                    interaction_keys = {"q", "query", "search", "id", "redirect", "url", "next", "file", "path"}
                    has_form_signals = isinstance(obj, dict) and isinstance(obj.get("forms", []), list) and len(obj.get("forms", [])) > 0

                    is_static_asset = any(token in path_lower for token in static_path_tokens) or path_lower.endswith(static_extensions)
                    malformed_js_fragment = (
                        "%27%29,d=f%28%27%3cscript%20type=" in candidate_url_lower
                        or ("%27%29" in candidate_url_lower and "script%20type=" in candidate_url_lower and "/static/js/" in path_lower)
                    )

                    if malformed_js_fragment:
                        return True
                    if is_static_asset and not has_form_signals and not (query_keys & interaction_keys):
                        return True
                    return False

                try:
                    tf = self._resolve_recon_file_path(file_path)
                    if tf is not None:
                        for _line in tf.read_text(encoding="utf-8").splitlines():
                            _line = _line.strip()
                            if not _line:
                                continue
                            try:
                                _obj = json.loads(_line)
                                _url = _obj.get("url", _obj.get("target", ""))
                                if _url:
                                    _url = str(_url).strip()
                                    if _is_low_value_injection_target(_url, normalized_category, _obj):
                                        low_value_skipped += 1
                                        continue
                                    _normalized_key = _normalize_target_for_category(_url, normalized_category)
                                    if not _normalized_key or _normalized_key in normalized_target_keys:
                                        continue
                                    normalized_target_keys.add(_normalized_key)
                                    resolved_targets.append(_url)
                                    _forms = _obj.get("forms", [])
                                    if isinstance(_forms, list):
                                        forms_by_url[_url] = _forms
                                    _response_headers = _obj.get("response_headers", {})
                                    if not isinstance(_response_headers, dict):
                                        _response_headers = {}
                                    url_evidence_by_url[_url] = {
                                        "method": str(_obj.get("method", "GET") or "GET").upper(),
                                        "source": str(_obj.get("source", "") or ""),
                                        "response_status": _obj.get("response_status", 0),
                                        "response_headers": _response_headers,
                                        "response_body_snippet": str(_obj.get("response_body_snippet", "") or ""),
                                        "has_form_tag": bool(_obj.get("has_form_tag", False)),
                                    }
                            except Exception:
                                pass
                except Exception as _e:
                    logger.warning(f"[MC] Failed to pre-resolve targets_file '{file_path}': {_e}")
                if low_value_skipped > 0:
                    logger.info(
                        "[MC] Skipped %d low-value targets by heuristic (category=%s)",
                        low_value_skipped,
                        normalized_category,
                    )

                # 低コストの検出密度向上:
                # auth/id/params 系は直近 tagged_urls 履歴から seed を補完して
                # 短縮ラン時の取りこぼしを減らす。
                history_replay_categories = {
                    "auth",
                    "admin",
                    "id_param",
                    "redirect_param",
                    "file_param",
                    "api_data",
                    "api_candidate",
                    "api_endpoint",
                    "xss_candidate",
                    "csrf_candidate",
                }
                if normalized_category in history_replay_categories:
                    minimum_seed_count = 3 if normalized_category in {"auth", "admin"} else 2
                    if len(resolved_targets) < minimum_seed_count:
                        replay_file_window = int(getattr(settings, "tagged_history_replay_file_window", 24) or 24)
                        replay_limit_default = int(getattr(settings, "tagged_history_replay_limit", 6) or 6)
                        replay_limit_dense = int(getattr(settings, "tagged_history_replay_limit_dense", 12) or 12)
                        replay_limit_authz = int(getattr(settings, "authz_history_replay_limit", 6) or 6)

                        if normalized_category in {"auth", "admin", "id_param"}:
                            replay_limit = replay_limit_authz
                        elif normalized_category in {"api_data", "api_candidate", "api_endpoint", "xss_candidate", "csrf_candidate"}:
                            replay_limit = replay_limit_dense
                        else:
                            replay_limit = replay_limit_default

                        replay_targets = self._collect_history_replay_targets(
                            normalized_category,
                            limit=max(1, replay_limit),
                            file_window=replay_file_window,
                            exclude_urls=set(normalized_target_keys),
                        )

                        replay_added = 0
                        for replay_url in replay_targets:
                            if (
                                normalized_category != "auth"
                                and _is_low_value_injection_target(replay_url, normalized_category, None)
                            ):
                                continue
                            _normalized_key = _normalize_target_for_category(replay_url, normalized_category)
                            if not _normalized_key or _normalized_key in normalized_target_keys:
                                continue
                            normalized_target_keys.add(_normalized_key)
                            resolved_targets.append(replay_url)
                            url_evidence_by_url.setdefault(
                                replay_url,
                                {
                                    "method": "GET",
                                    "source": "mc_history_replay",
                                    "response_status": 0,
                                    "response_headers": {},
                                    "response_body_snippet": "",
                                    "has_form_tag": False,
                                },
                            )
                            replay_added += 1

                        if replay_added > 0:
                            logger.info(
                                "[MC] History replay added %d seed target(s) for %s (resolved=%d)",
                                replay_added,
                                normalized_category,
                                len(resolved_targets),
                            )

                if (
                    normalized_category == "realtime"
                    and realtime_target_budget > 0
                    and len(resolved_targets) > realtime_target_budget
                ):
                    kept_targets = resolved_targets[:realtime_target_budget]
                    kept_set = set(kept_targets)
                    resolved_targets = kept_targets
                    forms_by_url = {u: v for u, v in forms_by_url.items() if u in kept_set}
                    url_evidence_by_url = {u: v for u, v in url_evidence_by_url.items() if u in kept_set}
                    logger.info(
                        "[MC] Realtime targets capped from %d to %d (realtime_target_budget=%d)",
                        len(normalized_target_keys),
                        len(resolved_targets),
                        realtime_target_budget,
                    )
                if (
                    normalized_category == "meta_observability"
                    and meta_target_budget > 0
                    and len(resolved_targets) > meta_target_budget
                ):
                    kept_targets = resolved_targets[:meta_target_budget]
                    kept_set = set(kept_targets)
                    resolved_targets = kept_targets
                    forms_by_url = {u: v for u, v in forms_by_url.items() if u in kept_set}
                    url_evidence_by_url = {u: v for u, v in url_evidence_by_url.items() if u in kept_set}
                    logger.info(
                        "[MC] Meta targets capped from %d to %d (meta_observability_target_budget=%d)",
                        len(normalized_target_keys),
                        len(resolved_targets),
                        meta_target_budget,
                    )

                # Injection 系カテゴリで low-value URL のみが除外されて空になった場合は、
                # discovered_assets から非 static / 非 root の候補を補完する。
                # 補完不能ならこのカテゴリのタスク生成をスキップし、
                # TaskExpander が targets_file を再読込してノイズを再注入するのを防ぐ。
                low_value_guard_categories = {
                    "xss_candidate",
                    "csrf_candidate",
                    "api_data",
                    "api_candidate",
                    "api_endpoint",
                    "product_search",
                    "feedback_review",
                    "client_route_dom",
                }
                if normalized_category in low_value_guard_categories and not resolved_targets and low_value_skipped > 0:
                    fallback_candidates: list[str] = []
                    try:
                        from urllib.parse import urlparse

                        for asset in list(getattr(self._context, "discovered_assets", []) or []):
                            candidate = str(asset or "").strip()
                            if not candidate.startswith(("http://", "https://")):
                                continue
                            parsed = urlparse(candidate)
                            if not parsed.netloc:
                                continue
                            if (parsed.path or "/") == "/":
                                continue
                            if _is_low_value_injection_target(candidate, normalized_category, None):
                                continue
                            if candidate in fallback_candidates:
                                continue
                            fallback_candidates.append(candidate)
                    except Exception:
                        fallback_candidates = []

                    if fallback_candidates:
                        fallback = fallback_candidates[0]
                        resolved_targets.append(fallback)
                        url_evidence_by_url.setdefault(
                            fallback,
                            {
                                "method": "GET",
                                "source": "mc_discovered_assets_fallback",
                                "response_status": 0,
                                "response_headers": {},
                                "response_body_snippet": "",
                                "has_form_tag": False,
                            },
                        )
                        logger.info(
                            "[MC] %s fallback target selected after low-value filtering: %s",
                            normalized_category,
                            fallback,
                        )
                    else:
                        logger.info(
                            "[MC] Skipping %s task: low-value-only targets and no fallback candidate",
                            normalized_category,
                        )
                        continue

                # 認証情報をタスクに引き継ぐ
                raw_cookies = self._get_context_cookie_string()
                task_auth_headers = self._get_context_auth_headers()

                task_params: dict = {
                    "targets_file": file_path,
                    "source_file": file_path,
                    "category": normalized_category,
                    "source_category": original_category,
                    "count": count,
                    "tags": tag_map.get(normalized_category, [normalized_category]),
                    "_context": {
                        "discovered_endpoints": self._context.discovered_assets[:10],
                        "auth_tokens": self._context.target_info.get("auth_tokens", {}),
                        "discovered_params": [],
                        "tech_stack": list(self._context.target_info.get("tech_stack", [])),
                        "waf_info": {},
                        "critical_findings": [],
                    },
                    "headers": {},
                    "cookies": raw_cookies,
                }

                # シナリオ信号を明示して、HITL系の分類精度を上げる（汎用）
                if normalized_category == "admin":
                    task_params.setdefault("scenario_id", "scn_01_idor_bola_object_access")
                    task_params.setdefault(
                        "scenario",
                        "idor bola object level authorization authz horizontal privilege escalation object reference",
                    )
                    task_params.setdefault("attack_type", "object level authorization")
                    task_params.setdefault(
                        "description",
                        "Object-level access control validation with direct object reference tampering.",
                    )
                elif normalized_category in {"auth", "jwt_detected"}:
                    task_params.setdefault("scenario_id", "scn_07_token_trust_boundary")
                    task_params.setdefault(
                        "scenario",
                        "jwt alg:none algorithm confusion kid injection jwks token forgery token trust boundary",
                    )
                    task_params.setdefault("attack_type", "jwt token trust boundary")
                    task_params.setdefault(
                        "description",
                        "Token trust-boundary analysis for JWT validation and signing-key handling.",
                    )
                elif normalized_category in {"basket_order", "realtime", "csrf_candidate"}:
                    task_params.setdefault("scenario_id", "scn_09_multi_step_state_machine")
                    task_params.setdefault(
                        "scenario",
                        "state machine multi-step flow workflow abuse state transition precondition chain chaining",
                    )
                    task_params.setdefault("attack_type", "workflow state transition")
                    task_params.setdefault(
                        "description",
                        "Multi-step state transition validation for sequence/precondition bypass conditions.",
                    )
                elif normalized_category in {
                    "id_param",
                    "redirect_param",
                    "file_param",
                    "product_search",
                    "feedback_review",
                    "api_data",
                    "client_route_dom",
                    "api_candidate",
                    "api_endpoint",
                    "xss_candidate",
                }:
                    task_params.setdefault("scenario_id", "scn_03_injection_input_tampering")
                    task_params.setdefault(
                        "scenario",
                        "injection input tampering payload mutation query/body/header parameter abuse",
                    )
                    task_params.setdefault("attack_type", "input tampering injection")
                    task_params.setdefault(
                        "description",
                        "Injection-oriented tampering analysis on request inputs and parser boundaries.",
                    )
                elif normalized_category in {"file_exposure_upload", "meta_observability", "debug_info"}:
                    task_params.setdefault("scenario_id", "scn_06_data_exposure_diff")
                    task_params.setdefault(
                        "scenario",
                        "data exposure response diff schema diff hidden field debug info observability leak",
                    )
                    task_params.setdefault("attack_type", "response differential data exposure")
                    task_params.setdefault(
                        "description",
                        "Data exposure differential analysis for hidden/sensitive response attributes.",
                    )
                # Injection 系カテゴリは unknown 分類のみで終了させず、
                # 仮説駆動スキャンまで実行して finding 取りこぼしを抑える。
                unknown_hypothesis_scan_categories = {
                    "id_param",
                    "redirect_param",
                    "file_param",
                    "product_search",
                    "feedback_review",
                    "file_exposure_upload",
                    "api_data",
                    "client_route_dom",
                    "api_candidate",
                    "api_endpoint",
                    "csrf_candidate",
                    "xss_candidate",
                }
                if normalized_category in unknown_hypothesis_scan_categories:
                    task_params["unknown_classification_only"] = False
                # Phase 1 でシグナルが拾えなくても、対象カテゴリでは Phase 2 仮説検証を実行する。
                phase2_on_empty_categories = {
                    "api_data",
                    "api_candidate",
                    "api_endpoint",
                    "xss_candidate",
                    "csrf_candidate",
                }
                if normalized_category in phase2_on_empty_categories:
                    task_params["phase2_on_empty_phase1"] = self._apply_phase2_on_empty_policy(True)

                if forms_by_url:
                    task_params["_context"]["forms_by_url"] = forms_by_url
                if url_evidence_by_url:
                    task_params["_context"]["url_evidence_by_url"] = url_evidence_by_url
                if task_auth_headers:
                    task_params["auth_headers"] = task_auth_headers

                if normalized_category == "id_param":
                    task_params["phase2_max_seconds"] = int(
                        getattr(settings, "id_param_phase2_max_seconds", 120) or 120
                    )
                    task_params["phase2_max_seconds_risk_forced"] = int(
                        getattr(settings, "id_param_phase2_max_seconds_risk_forced", 60) or 60
                    )
                    # id_param coverage runs are prone to long risk-forced phase2 loops on no-signal URLs.
                    # Keep deterministic phase1 as primary and disable risk-forced phase2 escalation.
                    task_params["phase2_risk_force_vuln_types"] = []

                if resolved_targets:
                    task_params["targets"] = resolved_targets
                    primary_target = self._normalize_url_candidate(resolved_targets[0])
                    task_params.setdefault("target", primary_target or resolved_targets[0])
                    # extra_targets (DiscoverySwarm相当) も追加
                    extra = [a for a in self._context.discovered_assets if a not in resolved_targets]
                    if extra:
                        task_params["extra_targets"] = extra[:5]

                display_count = len(resolved_targets) if resolved_targets else count
                task_display_name = f"{name} ({display_count} targets)"
                tasks.append(Task(
                    id=f"{normalized_category}_scan_{uuid.uuid4().hex[:8]}",
                    name=task_display_name,
                    agent_type=actual_agent,
                    action="scan",
                    phase="attack",
                    params=task_params,
                    target=str(task_params.get("target", "") or ""),
                    tags=tag_map.get(normalized_category, [normalized_category]),
                    priority=90 - len(tasks) * 5,
                ))
                logger.info(f"Created attack task: {task_display_name} (resolved {len(resolved_targets)} targets)")
            
            # 未知のカテゴリは Uncategorized として処理
            elif normalized_category not in ["with_auth", "cloud_aws", "cloud_azure", "cloud_gcp", "cloud_cloudflare"]:
                tasks.append(Task(
                    id=f"attack_uncategorized_{uuid.uuid4().hex[:8]}",
                    name=f"Fallback Endpoints Scan ({count} targets)",
                    agent_type="DiscoverySwarm",
                    action="scan",
                    phase="attack",
                    params={
                        "targets_file": file_path,
                        "category": normalized_category,
                        "source_category": original_category,
                        "count": count,
                    },
                    priority=50,
                ))

        # coverage gate 用の CSRF バックフィル:
        # tagged_csrf_candidate が無い場合でも、代表URLに対して最小 CSRF チェックを1本生成する。
        required_families = set(self._resolve_required_vuln_families())
        has_csrf_task = any(
            str((getattr(task, "params", {}) or {}).get("category", "")).strip().lower() == "csrf_candidate"
            for task in tasks
        )
        if "csrf" in required_families and not has_csrf_task:
            csrf_target_budget = int(getattr(settings, "csrf_target_budget", 5) or 5)
            csrf_seed_targets, csrf_seed_evidence = self._collect_csrf_seed_targets(
                recon_results=recon_results,
                budget=csrf_target_budget,
            )

            if not csrf_seed_targets:
                fallback_target = ""
                if isinstance(getattr(self._context, "target_info", {}), dict):
                    fallback_target = str(self._context.target_info.get("target", "") or "")
                if not fallback_target:
                    fallback_target = str(self._target or "")
                fallback_target = fallback_target.strip()
                if fallback_target:
                    csrf_seed_targets = [fallback_target]
                    csrf_seed_evidence = {
                        fallback_target: {
                            "score": -1,
                            "reasons": ["target_fallback_only"],
                            "category": "coverage_backfill",
                            "method": "GET",
                            "has_form_tag": False,
                        }
                    }
            if not csrf_seed_targets:
                raw_fallback_candidates: list[str] = []
                if isinstance(getattr(self._context, "target_info", {}), dict):
                    raw_fallback_candidates.append(str(self._context.target_info.get("target", "") or ""))
                raw_fallback_candidates.append(str(self._target or ""))
                for raw_asset in list(getattr(self._context, "discovered_assets", []) or []):
                    raw_fallback_candidates.append(str(raw_asset or ""))

                normalized_fallback_candidates: list[str] = []
                for raw_candidate in raw_fallback_candidates:
                    normalized_candidate = self._normalize_url_candidate(raw_candidate)
                    if not normalized_candidate:
                        continue
                    if not normalized_candidate.startswith(("http://", "https://")):
                        continue
                    if normalized_candidate in normalized_fallback_candidates:
                        continue
                    normalized_fallback_candidates.append(normalized_candidate)

                fallback_target = ""
                fallback_reason = "in_scope_host_fallback"
                if normalized_fallback_candidates:
                    fallback_target = normalized_fallback_candidates[0]
                    fallback_reason = "deterministic_backfill_fallback"
                else:
                    fallback_hosts = self._resolve_in_scope_hosts()
                    if fallback_hosts:
                        fallback_host = str(fallback_hosts[0] or "").strip().lower()
                        scheme = "http" if fallback_host in {"127.0.0.1", "localhost"} else "https"
                        fallback_target = f"{scheme}://{fallback_host}/"

                if fallback_target:
                    csrf_seed_targets = [fallback_target]
                    csrf_seed_evidence = {
                        fallback_target: {
                            "score": -1,
                            "reasons": [fallback_reason],
                            "category": "coverage_backfill",
                            "method": "GET",
                            "has_form_tag": False,
                        }
                    }

            csrf_seed_targets, csrf_seed_evidence = self._refine_backfill_seed_targets(
                targets=csrf_seed_targets,
                evidence_by_url=csrf_seed_evidence,
                budget=csrf_target_budget,
            )

            if csrf_seed_targets:
                csrf_phase2_on_empty = self._apply_phase2_on_empty_policy(
                    self._should_enable_phase2_on_empty_for_backfill(
                        targets=csrf_seed_targets,
                        evidence_by_url=csrf_seed_evidence,
                    )
                )
                raw_cookies = self._get_context_cookie_string()
                task_auth_headers = self._get_context_auth_headers()
                csrf_task_params: dict[str, Any] = {
                    "category": "csrf_candidate",
                    "source_category": "coverage_backfill",
                    "count": len(csrf_seed_targets),
                    "tags": ["csrf_candidate", "auth_endpoint"],
                    "targets": csrf_seed_targets,
                    "target": csrf_seed_targets[0],
                    "_context": {
                        "discovered_endpoints": self._context.discovered_assets[:10],
                        "auth_tokens": self._context.target_info.get("auth_tokens", {}) if isinstance(getattr(self._context, "target_info", {}), dict) else {},
                        "discovered_params": [],
                        "tech_stack": list(self._context.target_info.get("tech_stack", [])) if isinstance(getattr(self._context, "target_info", {}), dict) else [],
                        "waf_info": {},
                        "critical_findings": [],
                        "csrf_seed_evidence_by_url": csrf_seed_evidence,
                    },
                    "headers": {},
                    "cookies": raw_cookies,
                    "unknown_classification_only": False,
                    "phase2_on_empty_phase1": csrf_phase2_on_empty,
                    "csrf_active_verify": False,
                    # coverage-only CSRF backfill should not be prolonged by risk-forced phase2
                    "phase2_risk_force_vuln_types": [],
                    "phase2_max_seconds_risk_forced": 30,
                    "phase2_max_seconds": 60,
                }
                if task_auth_headers:
                    csrf_task_params["auth_headers"] = task_auth_headers
                if not csrf_phase2_on_empty:
                    logger.info(
                        "[MC] CSRF backfill seeds are low-signal; using phase1-only mode for target(s): %s",
                        ", ".join(csrf_seed_targets),
                    )

                tasks.append(
                    Task(
                        id=f"csrf_seed_{uuid.uuid4().hex[:8]}",
                        name=f"CSRF Minimal Security Check ({len(csrf_seed_targets)} targets)",
                        agent_type="InjectionSwarm",
                        action="scan",
                        phase="attack",
                        params=csrf_task_params,
                        tags=["csrf_candidate", "auth_endpoint"],
                        priority=84,
                    )
                )
                logger.info(
                    "Created CSRF backfill task with %d seed target(s) to satisfy coverage gate",
                    len(csrf_seed_targets),
                )
            else:
                logger.warning(
                    "CSRF family required but no viable CSRF seed target was found. "
                    "CSRF backfill task was not created.",
                )

        has_csrf_task_after_backfill = any(
            str((getattr(task, "params", {}) or {}).get("category", "")).strip().lower() == "csrf_candidate"
            for task in tasks
        )
        if "csrf" in required_families and not has_csrf_task_after_backfill:
            emergency_target = ""
            emergency_candidates: list[str] = []
            target_info = getattr(self._context, "target_info", {})
            if isinstance(target_info, dict):
                emergency_candidates.append(str(target_info.get("target", "") or ""))
            emergency_candidates.append(str(self._target or ""))
            emergency_candidates.extend(str(asset or "") for asset in list(getattr(self._context, "discovered_assets", []) or []))
            for planned_task in tasks:
                emergency_candidates.append(str(self._resolve_task_target(planned_task) or ""))

            for raw_candidate in emergency_candidates:
                normalized_candidate = self._normalize_url_candidate(raw_candidate)
                if not normalized_candidate:
                    continue
                if not normalized_candidate.startswith(("http://", "https://")):
                    continue
                emergency_target = normalized_candidate
                break

            if not emergency_target:
                fallback_hosts = self._resolve_in_scope_hosts()
                if fallback_hosts:
                    fallback_host = str(fallback_hosts[0] or "").strip().lower()
                    scheme = "http" if fallback_host in {"127.0.0.1", "localhost"} else "https"
                    emergency_target = f"{scheme}://{fallback_host}/"

            if emergency_target:
                raw_cookies = self._get_context_cookie_string()
                task_auth_headers = self._get_context_auth_headers()
                emergency_params: dict[str, Any] = {
                    "category": "csrf_candidate",
                    "source_category": "coverage_backfill_guard",
                    "count": 1,
                    "tags": ["csrf_candidate", "auth_endpoint", "coverage_guard_forced"],
                    "targets": [emergency_target],
                    "target": emergency_target,
                    "_coverage_guard_forced": True,
                    "_context": {
                        "discovered_endpoints": self._context.discovered_assets[:10],
                        "auth_tokens": self._context.target_info.get("auth_tokens", {}) if isinstance(getattr(self._context, "target_info", {}), dict) else {},
                        "discovered_params": [],
                        "tech_stack": list(self._context.target_info.get("tech_stack", [])) if isinstance(getattr(self._context, "target_info", {}), dict) else [],
                        "waf_info": {},
                        "critical_findings": [],
                        "csrf_seed_evidence_by_url": {
                            emergency_target: {
                                "score": -1,
                                "reasons": ["coverage_guard_forced"],
                                "category": "coverage_backfill_guard",
                                "method": "GET",
                                "has_form_tag": False,
                            }
                        },
                    },
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
                    emergency_params["auth_headers"] = task_auth_headers

                tasks.append(
                    Task(
                        id=f"csrf_guard_{uuid.uuid4().hex[:8]}",
                        name="CSRF Coverage Guard Check (forced)",
                        agent_type="InjectionSwarm",
                        action="scan",
                        phase="attack",
                        params=emergency_params,
                        tags=["csrf_candidate", "auth_endpoint", "coverage_guard_forced"],
                        priority=85,
                    )
                )
                logger.warning(
                    "Coverage planning invariant violated; force-added csrf_candidate guard task for target: %s",
                    emergency_target,
                )
            else:
                logger.error(
                    "Coverage planning invariant violated and no emergency target could be resolved; csrf_candidate task not added."
                )

        # coverage gate 用の API/Injection バックフィル:
        # tagged_api_data が無く injection/api が未達のとき、最小APIチェックを生成する。
        planned_families_after_csrf: set[str] = set()
        for planned_task in tasks:
            planned_category = str((getattr(planned_task, "params", {}) or {}).get("category", "")).strip().lower()
            if planned_category:
                planned_families_after_csrf.update(self._map_category_to_vuln_families(planned_category))

        api_injection_gap = ({"api", "injection"} & required_families) - planned_families_after_csrf
        if api_injection_gap:
            api_target_budget = int(getattr(settings, "api_injection_target_budget", 5) or 5)
            api_seed_targets, api_seed_evidence = self._collect_csrf_seed_targets(
                recon_results=recon_results,
                budget=api_target_budget,
            )

            if not api_seed_targets:
                fallback_target = ""
                if isinstance(getattr(self._context, "target_info", {}), dict):
                    fallback_target = str(self._context.target_info.get("target", "") or "")
                if not fallback_target:
                    fallback_target = str(self._target or "")
                fallback_target = fallback_target.strip()
                if fallback_target:
                    api_seed_targets = [fallback_target]
                    api_seed_evidence = {
                        fallback_target: {
                            "score": -1,
                            "reasons": ["target_fallback_only"],
                            "category": "coverage_backfill",
                            "method": "GET",
                            "has_form_tag": False,
                        }
                    }

            api_seed_targets, api_seed_evidence = self._refine_backfill_seed_targets(
                targets=api_seed_targets,
                evidence_by_url=api_seed_evidence,
                budget=api_target_budget,
            )

            if api_seed_targets:
                api_phase2_on_empty = self._apply_phase2_on_empty_policy(
                    self._should_enable_phase2_on_empty_for_backfill(
                        targets=api_seed_targets,
                        evidence_by_url=api_seed_evidence,
                    )
                )
                raw_cookies = self._get_context_cookie_string()
                task_auth_headers = self._get_context_auth_headers()
                api_task_params: dict[str, Any] = {
                    "category": "api_data",
                    "source_category": "coverage_backfill",
                    "count": len(api_seed_targets),
                    "tags": ["api_endpoint", "has_params"],
                    "targets": api_seed_targets,
                    "target": api_seed_targets[0],
                    "_context": {
                        "discovered_endpoints": self._context.discovered_assets[:10],
                        "auth_tokens": self._context.target_info.get("auth_tokens", {}) if isinstance(getattr(self._context, "target_info", {}), dict) else {},
                        "discovered_params": [],
                        "tech_stack": list(self._context.target_info.get("tech_stack", [])) if isinstance(getattr(self._context, "target_info", {}), dict) else [],
                        "waf_info": {},
                        "critical_findings": [],
                        "api_seed_evidence_by_url": api_seed_evidence,
                    },
                    "headers": {},
                    "cookies": raw_cookies,
                    "unknown_classification_only": False,
                    "phase2_on_empty_phase1": api_phase2_on_empty,
                    # coverage-only API backfill should avoid long risk-forced phase2 loops
                    "phase2_risk_force_vuln_types": [],
                    "phase2_max_seconds_risk_forced": 45,
                    "phase2_max_seconds": 90,
                }
                if task_auth_headers:
                    api_task_params["auth_headers"] = task_auth_headers
                if not api_phase2_on_empty:
                    logger.info(
                        "[MC] API/Injection backfill seeds are low-signal; using phase1-only mode for target(s): %s",
                        ", ".join(api_seed_targets),
                    )

                tasks.append(
                    Task(
                        id=f"api_seed_{uuid.uuid4().hex[:8]}",
                        name=f"API/Injection Minimal Security Check ({len(api_seed_targets)} targets)",
                        agent_type="InjectionSwarm",
                        action="scan",
                        phase="attack",
                        params=api_task_params,
                        tags=["api_endpoint", "has_params"],
                        priority=84,
                    )
                )
                logger.info(
                    "Created API/Injection backfill task with %d seed target(s). Missing families before backfill: %s",
                    len(api_seed_targets),
                    ", ".join(sorted(api_injection_gap)),
                )

        # coverage gate 用の XSS バックフィル:
        # xss_candidate が無く XSS ファミリーが未達のとき、最小XSSチェックを1本生成する。
        has_xss_task = any(
            str((getattr(task, "params", {}) or {}).get("category", "")).strip().lower() == "xss_candidate"
            for task in tasks
        )
        if "xss" in required_families and not has_xss_task:
            xss_target_budget = int(getattr(settings, "xss_target_budget", 5) or 5)
            xss_seed_targets, xss_seed_evidence = self._collect_xss_seed_targets(
                recon_results=recon_results,
                budget=xss_target_budget,
            )
            raw_xss_seed_targets = [str(url or "").strip() for url in xss_seed_targets if str(url or "").strip()]
            raw_xss_seed_evidence = dict(xss_seed_evidence)

            def _is_low_value_xss_seed(url: str) -> bool:
                try:
                    from urllib.parse import parse_qs, urlparse

                    parsed = urlparse(str(url or "").strip())
                    if parsed.scheme not in {"http", "https"}:
                        return True
                    path_lower = (parsed.path or "").lower()
                    query_keys = {k.lower() for k in parse_qs(parsed.query, keep_blank_values=True).keys()}
                except Exception:
                    return True

                static_path_tokens = ("/_next/", "/static/", "/assets/", "/dist/", "/chunks/")
                static_extensions = (
                    ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                    ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot",
                )
                interaction_keys = {"q", "query", "search", "id", "redirect", "url", "next", "file", "path"}
                candidate_lower = str(url or "").lower()
                malformed_js_fragment = (
                    "%27%29,d=f%28%27%3cscript%20type=" in candidate_lower
                    or ("%27%29" in candidate_lower and "script%20type=" in candidate_lower and "/static/js/" in path_lower)
                )
                is_static_asset = any(token in path_lower for token in static_path_tokens) or path_lower.endswith(static_extensions)
                is_root = (parsed.path or "/") == "/"

                if malformed_js_fragment:
                    return True
                if is_static_asset and not (query_keys & interaction_keys):
                    return True
                if is_root:
                    return True
                return False

            normalized_xss_targets: list[str] = []
            for target in xss_seed_targets:
                candidate = str(target or "").strip()
                if not candidate or candidate in normalized_xss_targets:
                    continue
                if _is_low_value_xss_seed(candidate):
                    continue
                normalized_xss_targets.append(candidate)
            xss_seed_targets = normalized_xss_targets

            if len(xss_seed_targets) < xss_target_budget:
                discovered_assets = list(getattr(self._context, "discovered_assets", []) or [])
                for asset in discovered_assets:
                    candidate = str(asset or "").strip()
                    if not candidate or candidate in xss_seed_targets:
                        continue
                    if _is_low_value_xss_seed(candidate):
                        continue
                    xss_seed_targets.append(candidate)
                    xss_seed_evidence.setdefault(
                        candidate,
                        {
                            "score": -1,
                            "reasons": ["discovered_asset_topup"],
                            "category": "coverage_backfill",
                            "method": "GET",
                            "has_form_tag": False,
                        },
                    )
                    if len(xss_seed_targets) >= xss_target_budget:
                        break

            if not xss_seed_targets:
                fallback_target = ""
                if isinstance(getattr(self._context, "target_info", {}), dict):
                    fallback_target = str(self._context.target_info.get("target", "") or "")
                if not fallback_target:
                    fallback_target = str(self._target or "")
                fallback_target = fallback_target.strip()
                if fallback_target:
                    xss_seed_targets = [fallback_target]
                    xss_seed_evidence = {
                        fallback_target: {
                            "score": -1,
                            "reasons": ["target_fallback_low_signal"],
                            "category": "coverage_backfill",
                            "method": "GET",
                            "has_form_tag": False,
                        }
                    }
                elif raw_xss_seed_targets:
                    fallback_seed = raw_xss_seed_targets[0]
                    xss_seed_targets = [fallback_seed]
                    xss_seed_evidence = {
                        fallback_seed: raw_xss_seed_evidence.get(
                            fallback_seed,
                            {
                                "score": -1,
                                "reasons": ["seed_fallback_low_signal"],
                                "category": "coverage_backfill",
                                "method": "GET",
                                "has_form_tag": False,
                            },
                        )
                    }

            if xss_seed_targets:
                xss_phase2_on_empty = self._apply_phase2_on_empty_policy(
                    self._should_enable_phase2_on_empty_for_backfill(
                        targets=xss_seed_targets,
                        evidence_by_url=xss_seed_evidence,
                    )
                )
                raw_cookies = self._get_context_cookie_string()
                task_auth_headers = self._get_context_auth_headers()
                xss_task_params: dict[str, Any] = {
                    "category": "xss_candidate",
                    "source_category": "coverage_backfill",
                    "count": len(xss_seed_targets),
                    "tags": ["xss_candidate", "sqli_candidate"],
                    "targets": xss_seed_targets,
                    "target": xss_seed_targets[0],
                    "_context": {
                        "discovered_endpoints": self._context.discovered_assets[:10],
                        "auth_tokens": self._context.target_info.get("auth_tokens", {}) if isinstance(getattr(self._context, "target_info", {}), dict) else {},
                        "discovered_params": [],
                        "tech_stack": list(self._context.target_info.get("tech_stack", [])) if isinstance(getattr(self._context, "target_info", {}), dict) else [],
                        "waf_info": {},
                        "critical_findings": [],
                        "xss_seed_evidence_by_url": xss_seed_evidence,
                    },
                    "headers": {},
                    "cookies": raw_cookies,
                    "unknown_classification_only": False,
                    "phase2_on_empty_phase1": xss_phase2_on_empty,
                    # coverage-only XSS backfill should avoid long risk-forced phase2 loops
                    "phase2_risk_force_vuln_types": [],
                    "phase2_max_seconds_risk_forced": 30,
                    "phase2_max_seconds": 60,
                }
                if task_auth_headers:
                    xss_task_params["auth_headers"] = task_auth_headers
                if not xss_phase2_on_empty:
                    logger.info(
                        "[MC] XSS backfill seeds are low-signal; using phase1-only mode for target(s): %s",
                        ", ".join(xss_seed_targets),
                    )

                tasks.append(
                    Task(
                        id=f"xss_seed_{uuid.uuid4().hex[:8]}",
                        name=f"XSS Minimal Security Check ({len(xss_seed_targets)} targets)",
                        agent_type="InjectionSwarm",
                        action="scan",
                        phase="attack",
                        params=xss_task_params,
                        tags=["xss_candidate", "sqli_candidate"],
                        priority=83,
                    )
                )
                logger.info(
                    "Created XSS backfill task with %d seed target(s) to satisfy coverage gate",
                    len(xss_seed_targets),
                )

        has_xss_task_after_backfill = any(
            str((getattr(task, "params", {}) or {}).get("category", "")).strip().lower() == "xss_candidate"
            for task in tasks
        )
        if "xss" in required_families and not has_xss_task_after_backfill:
            emergency_target = self._resolve_global_csrf_guard_target()
            if emergency_target:
                raw_cookies = self._get_context_cookie_string()
                task_auth_headers = self._get_context_auth_headers()
                emergency_params: dict[str, Any] = {
                    "category": "xss_candidate",
                    "source_category": "coverage_backfill_guard",
                    "count": 1,
                    "tags": ["xss_candidate", "sqli_candidate", "coverage_guard_forced"],
                    "targets": [emergency_target],
                    "target": emergency_target,
                    "_coverage_guard_forced": True,
                    "scenario_id": "scn_03_injection_input_tampering",
                    "scenario": "injection input tampering payload mutation query/body/header parameter abuse",
                    "attack_type": "input tampering injection",
                    "description": "Coverage guard fallback task forced for missing XSS family.",
                    "_context": {
                        "discovered_endpoints": self._context.discovered_assets[:10],
                        "auth_tokens": self._context.target_info.get("auth_tokens", {}) if isinstance(getattr(self._context, "target_info", {}), dict) else {},
                        "discovered_params": [],
                        "tech_stack": list(self._context.target_info.get("tech_stack", [])) if isinstance(getattr(self._context, "target_info", {}), dict) else [],
                        "waf_info": {},
                        "critical_findings": [],
                        "xss_seed_evidence_by_url": {
                            emergency_target: {
                                "score": -1,
                                "reasons": ["coverage_guard_forced"],
                                "category": "coverage_backfill_guard",
                                "method": "GET",
                                "has_form_tag": False,
                            }
                        },
                    },
                    "headers": {},
                    "cookies": raw_cookies,
                    "unknown_classification_only": False,
                    "phase2_on_empty_phase1": False,
                    "phase2_risk_force_vuln_types": [],
                    "phase2_max_seconds_risk_forced": 30,
                    "phase2_max_seconds": 60,
                }
                if task_auth_headers:
                    emergency_params["auth_headers"] = task_auth_headers

                tasks.append(
                    Task(
                        id=f"xss_guard_{uuid.uuid4().hex[:8]}",
                        name="XSS Coverage Guard Check (forced)",
                        agent_type="InjectionSwarm",
                        action="scan",
                        phase="attack",
                        params=emergency_params,
                        tags=["xss_candidate", "sqli_candidate", "coverage_guard_forced"],
                        priority=85,
                    )
                )
                logger.warning(
                    "Coverage planning invariant violated; force-added xss_candidate guard task for target: %s",
                    emergency_target,
                )
            else:
                logger.error(
                    "Coverage planning invariant violated and no emergency target could be resolved; xss_candidate task not added."
                )

        # coverage gate 用の AccessControl/BusinessLogic バックフィル:
        # タグ分類が偏っても最低1本は BizLogic 系タスクを生成し、欠損ファミリーを補完する。
        planned_families: set[str] = set()
        for planned_task in tasks:
            planned_category = str((getattr(planned_task, "params", {}) or {}).get("category", "")).strip().lower()
            if planned_category:
                planned_families.update(self._map_category_to_vuln_families(planned_category))

        access_logic_gap = ({"access_control", "business_logic"} & required_families) - planned_families
        if access_logic_gap:
            access_logic_budget = int(getattr(settings, "access_logic_target_budget", 2) or 2)
            access_logic_targets, access_logic_evidence = self._collect_csrf_seed_targets(
                recon_results=recon_results,
                budget=access_logic_budget,
            )

            if not access_logic_targets:
                fallback_target = ""
                if isinstance(getattr(self._context, "target_info", {}), dict):
                    fallback_target = str(self._context.target_info.get("target", "") or "")
                if not fallback_target:
                    fallback_target = str(self._target or "")
                fallback_target = fallback_target.strip()
                if fallback_target:
                    access_logic_targets = [fallback_target]
                    access_logic_evidence = {
                        fallback_target: {
                            "score": -1,
                            "reasons": ["target_fallback_only"],
                            "category": "coverage_backfill",
                            "method": "GET",
                            "has_form_tag": False,
                        }
                    }

            access_logic_targets, access_logic_evidence = self._refine_backfill_seed_targets(
                targets=access_logic_targets,
                evidence_by_url=access_logic_evidence,
                budget=access_logic_budget,
            )

            if access_logic_targets:
                raw_cookies = self._get_context_cookie_string()
                task_auth_headers = self._get_context_auth_headers()
                access_logic_params: dict[str, Any] = {
                    "category": "admin",
                    "source_category": "coverage_backfill",
                    "count": len(access_logic_targets),
                    "tags": ["admin_panel", "auth_required", "api_endpoint"],
                    "targets": access_logic_targets,
                    "target": access_logic_targets[0],
                    "_context": {
                        "discovered_endpoints": self._context.discovered_assets[:10],
                        "auth_tokens": self._context.target_info.get("auth_tokens", {}) if isinstance(getattr(self._context, "target_info", {}), dict) else {},
                        "discovered_params": [],
                        "tech_stack": list(self._context.target_info.get("tech_stack", [])) if isinstance(getattr(self._context, "target_info", {}), dict) else [],
                        "waf_info": {},
                        "critical_findings": [],
                        "access_logic_seed_evidence_by_url": access_logic_evidence,
                    },
                    "headers": {},
                    "cookies": raw_cookies,
                }
                if task_auth_headers:
                    access_logic_params["auth_headers"] = task_auth_headers

                tasks.append(
                    Task(
                        id=f"access_logic_seed_{uuid.uuid4().hex[:8]}",
                        name=f"Access/Logic Minimal Security Check ({len(access_logic_targets)} targets)",
                        agent_type="bizlogic",
                        action="scan",
                        phase="attack",
                        params=access_logic_params,
                        tags=["admin_panel", "auth_required", "api_endpoint"],
                        priority=83,
                    )
                )
                logger.info(
                    "Created access/business-logic backfill task with %d seed target(s). Missing families before backfill: %s",
                    len(access_logic_targets),
                    ", ".join(sorted(access_logic_gap)),
                )

        # 認証が必要そうなエンドポイント → JWTInspector（後方互換）
        auth_data = recon_results.get("with_auth", {})
        if auth_data.get("count", 0) > 0:
            tasks.append(Task(
                id=f"attack_auth_{uuid.uuid4().hex[:8]}",
                name="JWT/Auth Analysis",
                agent_type="jwt_inspector",
                action="analyze",
                phase="attack",
                params={"classification_file": auth_data.get("file")},
                priority=80,
            ))
            logger.info("Created JWT/Auth analysis task")

        # Cloud-specific tests
        for cloud in ["cloud_aws", "cloud_azure", "cloud_gcp", "cloud_cloudflare"]:
            cloud_data = recon_results.get(cloud, {})
            if cloud_data.get("count", 0) > 0:
                cloud_name = cloud.replace("cloud_", "").upper()
                tasks.append(Task(
                    id=f"attack_{cloud}_{uuid.uuid4().hex[:8]}",
                    name=f"{cloud_name} Security Check",
                    agent_type="command_agent",
                    action="run",
                    phase="attack",
                    params={
                        "classification_file": cloud_data.get("file"),
                        "check_type": cloud.replace("cloud_", ""),
                    },
                    priority=70,
                ))
                logger.info(f"Created {cloud_name} security check task")

        missing_link_probe_plan = self._plan_missing_link_probes(
            existing_tasks=tasks,
            recon_results=recon_results,
            runtime_policy=None,
        )
        scenario_probe_tasks = (
            missing_link_probe_plan.get("tasks", [])
            if isinstance(missing_link_probe_plan, dict)
            else []
        )
        if scenario_probe_tasks:
            tasks.extend(scenario_probe_tasks)

        logger.info(f"Generated {len(tasks)} base attack tasks from recon results")
        
        # --- Task Expansion Phase ---
        # 巨大な targets_file を個別タスクに展開してキューに追加
        expander = TaskExpander(self._workspace)
        final_tasks = []
        
        for base_task in tasks:
            if "targets_file" in base_task.params:
                subtasks = expander.expand(base_task)
                if subtasks:
                    logger.info("[MC] Expanded task %s into %d subtasks", base_task.id, len(subtasks))
                    final_tasks.extend(subtasks)
                    # 親タスクそのものは実行キューに入れない（サブタスクが代行するため）
                    continue
            
            final_tasks.append(base_task)

        prioritized_tasks: list[Task] = []
        regular_tasks: list[Task] = []
        for queued_task in final_tasks:
            queued_params = queued_task.params if isinstance(getattr(queued_task, "params", None), dict) else {}
            source_category = str(queued_params.get("source_category", "") or "").strip().lower()
            category = str(queued_params.get("category", "") or "").strip().lower()
            if source_category in {"coverage_backfill", "scenario_probe_planner"} or category == "csrf_candidate":
                prioritized_tasks.append(queued_task)
            else:
                regular_tasks.append(queued_task)

        if prioritized_tasks:
            logger.info(
                "Prioritized %d coverage-critical task(s) ahead of regular recon tasks",
                len(prioritized_tasks),
            )
        return prioritized_tasks + regular_tasks
