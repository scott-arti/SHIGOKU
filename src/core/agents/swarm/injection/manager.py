import asyncio
import json
import logging
import random
import re
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from src.core.agents.swarm.base_manager import BaseManagerAgent
from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.validation.finding_validator import FindingValidator, ValidationResult
from src.core.models.swarm import SwarmResult
from src.core.engine.agent_registry import AgentRegistry
from src.core.engine.tag_taxonomy_registry import (
    CATEGORY_API_CANDIDATE,
    CATEGORY_API_DATA,
    CATEGORY_API_ENDPOINT,
    CATEGORY_CSRF_CANDIDATE,
    CATEGORY_FILE_PARAM,
    CATEGORY_GRAPHQL_CANDIDATE,
    CATEGORY_ID_PARAM,
    CATEGORY_REDIRECT_PARAM,
    CATEGORY_SSRF_CANDIDATE,
    CATEGORY_XSS_CANDIDATE,
)
from src.core.engine.skip_reason_registry import (
    KNOWN_SKIP_REASONS,
    normalize_skip_reason,
)
from src.core.agents.swarm.injection.manager_internal.target_classifier import (
    classify_target_url,
)
from src.core.agents.swarm.injection.manager_internal.target_selection import (
    prioritize_targets,
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
from src.core.agents.swarm.injection.manager_internal.api_probe_targets import (
    build_nearby_api_candidates,
    dedupe_urls,
    extract_api_like_urls,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_analysis import (
    build_authz_differential,
)
from src.core.agents.swarm.injection.manager_internal.api_probe_evidence import (
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
    build_mass_assignment_variant_payload,
    extract_mass_assignment_schema_candidates,
    mutate_schema_candidate_value,
    parse_json_dict,
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
from src.core.agents.swarm.injection.manager_internal.phase1_results import (
    collect_phase1_vuln_types,
    extract_max_ssrf_score,
    has_actionable_blind_signal,
    summarize_low_ssrf_score_breakdown,
    summarize_skip_reason_counts,
    summarize_skip_reason_unknown_counts,
)
from src.core.agents.swarm.injection.manager_internal.tool_runners import (
    build_hunter_task,
    format_cors_hunter_result,
    format_simple_hunter_result,
)
from src.core.agents.swarm.injection.manager_internal.unknown_hypotheses import (
    build_unknown_hypotheses,
    build_unknown_idor_candidate_finding,
)
from src.config import settings

logger = logging.getLogger(__name__)

@AgentRegistry.register(
    names=["InjectionManager", "InjectionManagerAgent", "injection_manager", "InjectionSwarm"],
    tags=["injection", "sqli", "xss", "command_injection", "lfi", "open_redirect"]
)
class InjectionManagerAgent(BaseManagerAgent):
    """
    インジェクション攻撃マネージャー (LLM 駆動)

    役割:
    1. ターゲットのパラメータ分析と攻撃ポイントの特定
    2. 適切な Injection Specialist (SQLi, XSS, etc.) の選定と実行
    3. WAF 検知時の回避戦略の立案
    """

    name: str = "InjectionManager"
    description: str = "Expert in various injection attacks. Strategizes and delegates to specialists."
    system_prompt_template: str = "agents/injection_manager.md"
    
    # 設定定数
    MAX_URLS_TO_CHECK: int = 5  # Phase 1 でチェックする URL の最大数（早期リターン強化）
    PARALLEL_BATCH_SIZE: int = 3  # 並列実行のバッチサイズ
    INJECTION_MANAGER_TIMEOUT: int = 900  # InjectionManager 全体のタイムアウト（秒）
    PER_URL_TIMEOUT_SECONDS: int = 120  # URL 1件あたりのタイムアウト（秒）
    PER_URL_TIMEOUT_BY_TYPE: Dict[str, int] = {
        "sqli": 180,
        "xss": 210,
        "lfi": 120,
        "ssti": 150,
        "cors": 120,
        "crlf": 90,
        "redirect": 90,
        "ssrf": 180,
        "cmd_ssrf": 180,
        "graphql": 120,
        "unknown": 120,
    }
    PER_URL_TIMEOUT_BLIND_SQLI_SECONDS: int = 240
    PHASE1_TIMEOUT_RETRIES: int = 1
    TIMEOUT_CIRCUIT_BREAKER_THRESHOLD: int = 2
    TIMEOUT_BACKOFF_BASE_SECONDS: float = 1.5
    TIMEOUT_BACKOFF_MAX_SECONDS: float = 12.0
    LANE2_SCORE_THRESHOLD: int = 65
    EXCLUDED_TESTED_PARAMS = {
        "scan_profile",
        "profile",
        "forms",
        "url_evidence",
        "detection_mode",
        "_auth",
        "_context",
        "method",
        "tags",
        "category",
        "count",
        "source_file",
        "targets",
        "extra_targets",
        "auth_headers",
        "headers",
        "cookies",
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        # 各インジェクション型スキャナ (Specialist) の初期化
        self._initialize_specialists()
        self._phase2_detection_mode: str = "phase2"
        self._ephemeral_network_clients: List[Any] = []

        # FindingValidator初期化（証拠品質ゲート）
        self._finding_validator = FindingValidator()

        # LLMから呼び出し可能なツールとして登録 (Phase 2 用)
        self._register_manager_tools()

    def _register_manager_tools(self):
        """スペシャリストの実行メソッドをLLMツールとして登録"""
        if "sqli" in self.specialists:
            self.register_tool(
                "sqli_scan", 
                self.run_sqli_hunter,
                "SQLインジェクション脆弱性の詳細スキャンを実行します。URLと関連パラメータを自動でテストします。"
            )
        if "xss" in self.specialists:
            self.register_tool(
                "xss_scan", 
                self.run_xss_hunter,
                "XSS (Cross-Site Scripting) 脆弱性の詳細スキャンを実行します。反射・格納型などをテストします。"
            )
        if "lfi" in self.specialists:
            self.register_tool(
                "lfi_scan", 
                self.run_lfi_check,
                "LFI (Local File Inclusion) やディレクトリトラバーサル脆弱性をスキャンします。"
            )
        if "redirect" in self.specialists: # Changed from "open_redirect" to "redirect" to match _initialize_specialists
            self.register_tool(
                "open_redirect_scan", 
                self.run_open_redirect_check,
                "オープンリダイレクト脆弱性の詳細スキャンを実行します。"
            )
        if "cmd_ssrf" in self.specialists:
            self.register_tool(
                "cmd_ssrf_scan", 
                self.run_cmd_ssrf_hunter,
                "OSコマンドインジェクションおよびSSRF脆弱性の詳細スキャンを実行します。"
            )
        if "ssrf" in self.specialists:
            self.register_tool(
                "ssrf_scan",
                self.run_ssrf_hunter,
                "SSRF脆弱性の応答ベーススキャンを実行します。"
            )
        if "ssti" in self.specialists:
            self.register_tool(
                "ssti_scan",
                self.run_ssti_hunter,
                "SSTI (Server-Side Template Injection) 脆弱性の決定論的スキャンを実行します。"
            )
        if "cors" in self.specialists:
            self.register_tool(
                "cors_scan",
                self.run_cors_hunter,
                "CORS設定ミスの検出を実行します。"
            )
        if "crlf" in self.specialists:
            self.register_tool(
                "crlf_scan",
                self.run_crlf_hunter,
                "CRLFインジェクションの決定論的スキャンを実行します。"
            )
        self._register_initial_tools()
        # キャッシュ機構：同一 URL/パラメータの重複チェックを防止
        self._request_cache: Dict[str, Dict[str, Any]] = {}

    def _initialize_specialists(self) -> None:
        """Specialist の初期化 (Lazy import)"""
        self.specialists: Dict[str, Specialist] = {}

        # SmartSQLiHunter
        try:
            from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter
            self.specialists["sqli"] = SmartSQLiHunter(config=self.config)
        except ImportError:
            logger.warning("SmartSQLiHunter not available")

        # OpenRedirectSpecialist
        try:
            from src.core.agents.swarm.injection.open_redirect import OpenRedirectSpecialist
            self.specialists["redirect"] = OpenRedirectSpecialist(config=self.config)
        except ImportError:
            logger.warning("OpenRedirectSpecialist not available")

        # SmartLFIHunter
        try:
            from src.core.agents.swarm.injection.smart_lfi import SmartLFIHunter
            self.specialists["lfi"] = SmartLFIHunter(config=self.config)
        except ImportError:
            logger.warning("SmartLFIHunter not available")

        # SmartXSSHunter
        try:
            from src.core.agents.swarm.injection.smart_xss import SmartXSSHunter
            self.specialists["xss"] = SmartXSSHunter(config=self.config)
        except ImportError:
            logger.warning("SmartXSSHunter not available")

        # SmartCmdSSRFHunter
        try:
            from src.core.agents.swarm.injection.smart_cmd_ssrf import SmartCmdSSRFHunter
            self.specialists["cmd_ssrf"] = SmartCmdSSRFHunter(config=self.config)
        except ImportError:
            logger.warning("SmartCmdSSRFHunter not available")

        # SmartSSRFHunter
        try:
            from src.core.agents.swarm.injection.smart_ssrf import SmartSSRFHunter
            self.specialists["ssrf"] = SmartSSRFHunter(config=self.config)
        except ImportError:
            logger.warning("SmartSSRFHunter not available")

        # SmartSSTIHunter
        try:
            from src.core.agents.swarm.injection.smart_ssti import SmartSSTIHunter
            self.specialists["ssti"] = SmartSSTIHunter(config=self.config)
        except ImportError:
            logger.warning("SmartSSTIHunter not available")

        # SmartCORSHunter
        try:
            from src.core.agents.swarm.injection.smart_cors import SmartCORSHunter
            self.specialists["cors"] = SmartCORSHunter(config=self.config)
        except ImportError:
            logger.warning("SmartCORSHunter not available")

        # SmartCRLFHunter
        try:
            from src.core.agents.swarm.injection.smart_crlf import SmartCRLFHunter
            self.specialists["crlf"] = SmartCRLFHunter(config=self.config)
        except ImportError:
            logger.warning("SmartCRLFHunter not available")

        # SmartGraphQLHunter
        try:
            from src.core.agents.swarm.injection.smart_graphql import SmartGraphQLHunter
            self.specialists["graphql"] = SmartGraphQLHunter(config=self.config)
        except ImportError:
            logger.warning("SmartGraphQLHunter not available")

    def _register_initial_tools(self) -> None:
        """LLM が使用するツールの登録"""
        self.register_tool(
            "analyze_parameters",
            self.analyze_parameters,
            "Analyze URL parameters for injection entry points. Args: url (str)"
        )
        self.register_tool(
            "run_sqli_hunter",
            self.run_sqli_hunter,
            "Run Smart SQL Injection Hunter on a target. Args: url (str), params (dict)"
        )
        self.register_tool(
            "run_open_redirect_check",
            self.run_open_redirect_check,
            "Check for Open Redirect vulnerabilities. Args: url (str), params (dict)"
        )
        self.register_tool(
            "run_lfi_check",
            self.run_lfi_check,
            "Check for LFI/Path Traversal vulnerabilities. Args: url (str), params (dict)"
        )
        self.register_tool(
            "run_xss_hunter",
            self.run_xss_hunter,
            "Run Smart XSS Hunter on a target. Args: url (str), params (dict)"
        )
        self.register_tool(
            "run_cmd_ssrf_hunter",
            self.run_cmd_ssrf_hunter,
            "Run Smart Command Injection & SSRF Hunter on a target. Args: url (str), params (dict)"
        )
        self.register_tool(
            "run_ssrf_hunter",
            self.run_ssrf_hunter,
            "Run deterministic SSRF Hunter on a target. Args: url (str), params (dict)"
        )
        if "graphql" in self.specialists:
            self.register_tool(
                "graphql_scan",
                self.run_graphql_hunter,
                "GraphQL Introspection有効性を検出します。"
            )

    # --- URL の「タイプ」判定ヘルパー ---

    @staticmethod
    @staticmethod
    def _ssrf_reachability_gate(url: str, base_params: Dict[str, Any]) -> tuple[bool, str]:
        """
        SSRF が成立しうる注入ポイントがあるかを判定する。
        Wave B の即効改善: 到達性が低い対象を Lane-1 から除外。
        """
        parsed = urlparse(str(url or ""))
        query_keys = {k.lower() for k in parse_qs(parsed.query, keep_blank_values=True).keys()}
        forms = base_params.get("forms", []) if isinstance(base_params, dict) else []
        url_evidence = base_params.get("url_evidence", {}) if isinstance(base_params, dict) else {}
        if not isinstance(url_evidence, dict):
            url_evidence = {}

        url_like_keys = {
            "url", "uri", "endpoint", "host", "target", "dest", "destination",
            "src", "source", "fetch", "load", "remote", "request", "webhook", "callback",
        }
        if query_keys & url_like_keys:
            return True, "query_param"

        form_field_names: set[str] = set()
        for form in forms if isinstance(forms, list) else []:
            if not isinstance(form, dict):
                continue
            for bucket in ("fields", "inputs"):
                fields = form.get(bucket, [])
                if not isinstance(fields, list):
                    continue
                for field in fields:
                    name = ""
                    if isinstance(field, dict):
                        name = str(field.get("name", "") or "").strip().lower()
                    else:
                        name = str(field or "").strip().lower()
                    if name:
                        form_field_names.add(name)
        if form_field_names & url_like_keys:
            return True, "form_field"

        score = int(url_evidence.get("ssrf_score", 0) or 0)
        if score >= 40:
            return True, "score_threshold"

        breakdown = url_evidence.get("score_breakdown", {})
        if isinstance(breakdown, dict) and int(breakdown.get("graphql_variables", 0) or 0) >= 10:
            return True, "graphql_variables"

        return False, "no_ssrf_injection_point"

    @staticmethod
    def _dedupe_preserve_order(items: List[str]) -> List[str]:
        """順序を維持して重複を除去する。"""
        deduped: List[str] = []
        for item in items:
            if item and item not in deduped:
                deduped.append(item)
        return deduped

    async def _run_unknown_hypothesis_scans(
        self,
        url: str,
        base_params: Dict[str, Any],
        quick_mode: bool,
    ) -> Dict[str, Any]:
        """仮説に沿って必要な Specialist のみ実行する。"""
        profile = build_unknown_hypotheses(url, base_params, available_specialists=set(self.specialists.keys()))
        selected = profile.get("selected_specialists", [])

        logger.info(
            "[%s] unknown hypothesis routing: url=%s hypotheses=%s specialists=%s",
            self.name,
            url,
            profile.get("hypotheses", []),
            selected,
        )

        unknown_results: List[Dict[str, Any]] = []
        reflection_observed = False
        xss_evidence = ""
        blind_correlation: Dict[str, Any] = {}

        for specialist in selected:
            if specialist == "sqli":
                sqli_result = await self.run_sqli_hunter(url=url, params=base_params, quick_mode=quick_mode)
                unknown_results.append(sqli_result)
                if not blind_correlation:
                    blind_correlation = normalize_blind_correlation(
                        sqli_result.get("blind_correlation", {}) or {}
                    )
            elif specialist == "xss":
                xss_result = await self.run_xss_hunter(url=url, params=base_params, quick_mode=quick_mode)
                unknown_results.append(xss_result)
                reflection_observed = bool(xss_result.get("reflection_observed", False))
                xss_evidence = str(xss_result.get("evidence", "") or "")
            elif specialist == "lfi":
                unknown_results.append(await self.run_lfi_check(url=url, params=base_params, quick_mode=quick_mode))
            elif specialist == "ssti":
                ssti_result = await self.run_ssti_hunter(url=url, params=base_params, quick_mode=quick_mode)
                unknown_results.append(ssti_result)
            elif specialist == "cors":
                cors_result = await self.run_cors_hunter(url=url, params=base_params, quick_mode=quick_mode)
                unknown_results.append(cors_result)
            elif specialist == "crlf":
                crlf_result = await self.run_crlf_hunter(url=url, params=base_params, quick_mode=quick_mode)
                unknown_results.append(crlf_result)
            elif specialist == "cmd_ssrf":
                cmd_result = await self.run_cmd_ssrf_hunter(url=url, params=base_params, quick_mode=quick_mode)
                unknown_results.append(cmd_result)
                if not blind_correlation:
                    blind_correlation = normalize_blind_correlation(
                        cmd_result.get("blind_correlation", {}) or {}
                    )
            elif specialist == "ssrf":
                ssrf_result = await self.run_ssrf_hunter(url=url, params=base_params, quick_mode=quick_mode)
                unknown_results.append(ssrf_result)
            elif specialist == "graphql":
                graphql_result = await self.run_graphql_hunter(url=url, params=base_params, quick_mode=quick_mode)
                unknown_results.append(graphql_result)

        merged_params: List[str] = []
        for partial in unknown_results:
            merged_params.extend(partial.get("tested_params", []) or [])

        findings_count = sum(int(partial.get("findings_count", 0) or 0) for partial in unknown_results)
        findings_list = self.current_context["findings"][-findings_count:] if findings_count > 0 else []

        return {
            "findings_count": findings_count,
            "findings": findings_list,
            "tested_params": sanitize_tested_params(merged_params, excluded_params=self.EXCLUDED_TESTED_PARAMS),
            "reflection_observed": reflection_observed,
            "xss_evidence": xss_evidence,
            "blind_correlation": normalize_blind_correlation(blind_correlation),
            "unknown_profile": profile,
        }

    @staticmethod
    def _extract_security_level(cookies: str) -> str:
        """Cookie 文字列から security レベルを抽出する。"""
        if not cookies:
            return ""
        match = re.search(r"(?:^|;\s*)security=([^;]+)", str(cookies), re.IGNORECASE)
        if not match:
            return ""
        return match.group(1).strip().lower()

    def _generate_cache_key(self, url: str, vuln_type: str, params: Dict[str, Any]) -> str:
        """キャッシュキーを生成（profile/security/category を含めて再利用安全性を向上）。"""
        params = params or {}
        auth = params.get("_auth", {}) if isinstance(params.get("_auth", {}), dict) else {}
        cookies = str(auth.get("cookies", "") or params.get("cookies", "") or "")
        security_level = self._extract_security_level(cookies)
        scan_profile = str(
            params.get("scan_profile")
            or (params.get("_context", {}) if isinstance(params.get("_context", {}), dict) else {}).get("scan_profile")
            or "bbpt"
        ).lower()
        category = str(params.get("category", "") or "").lower()
        method = str(params.get("method", "GET") or "GET").upper()

        key_params = {
            "method": method,
            "scan_profile": scan_profile,
            "security": security_level,
            "category": category,
            "query_keys": sorted(parse_qs(urlparse(url).query).keys()),
        }
        param_str = str(sorted(key_params.items()))
        return f"{vuln_type}:{url}:{param_str}"

    def _collect_recent_tested_params(self, vuln_type: str) -> List[str]:
        """直近の Specialist 実行で試したパラメータ名を収集する。"""
        if vuln_type == "sqli":
            sqli_params = getattr(self.specialists.get("sqli"), "last_tested_params", []) or []
            xss_params = getattr(self.specialists.get("xss"), "last_tested_params", []) or []
            return sanitize_tested_params(sqli_params + xss_params, excluded_params=self.EXCLUDED_TESTED_PARAMS)
        if vuln_type == "xss":
            return sanitize_tested_params(getattr(self.specialists.get("xss"), "last_tested_params", []) or [])
        return []

    @staticmethod
    @staticmethod
    def _normalize_param_name_hints(raw: Any) -> List[str]:
        """LLM ツール呼び出し由来の param ヒントを正規化する。"""
        names: List[str] = []

        def _add(candidate: Any) -> None:
            token = str(candidate or "").strip()
            if not token:
                return
            if token not in names:
                names.append(token)

        if isinstance(raw, str):
            _add(raw)
        elif isinstance(raw, dict):
            for key in raw.keys():
                _add(key)
        elif isinstance(raw, (list, tuple, set)):
            for item in raw:
                if isinstance(item, dict):
                    for key in item.keys():
                        _add(key)
                else:
                    _add(item)
        return names

    def _normalize_tool_supplied_params(
        self,
        params: Optional[Dict[str, Any]],
        tool_kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        run_*_hunter ツール呼び出し時の `param`/`payload`/`discovered_params` を
        実際の payload params に変換する。
        """
        normalized: Dict[str, Any] = dict(params or {})

        def _pop_optional(key: str) -> Any:
            if key in normalized:
                return normalized.pop(key)
            return None

        explicit_param_raw = tool_kwargs.get("param")
        if explicit_param_raw is None:
            explicit_param_raw = tool_kwargs.get("parameter")
        if explicit_param_raw is None:
            explicit_param_raw = _pop_optional("param")
        if explicit_param_raw is None:
            explicit_param_raw = _pop_optional("parameter")

        explicit_payload = tool_kwargs.get("payload")
        if explicit_payload is None:
            explicit_payload = _pop_optional("payload")

        discovered_hints: List[str] = []
        hint_sources = [
            tool_kwargs.get("discovered_params"),
            tool_kwargs.get("candidate_params"),
            tool_kwargs.get("params_list"),
            _pop_optional("discovered_params"),
            _pop_optional("candidate_params"),
            _pop_optional("params_list"),
        ]
        for source in hint_sources:
            for name in self._normalize_param_name_hints(source):
                if name.lower() in self.EXCLUDED_TESTED_PARAMS:
                    continue
                if name not in discovered_hints:
                    discovered_hints.append(name)

        explicit_param_names = self._normalize_param_name_hints(explicit_param_raw)
        explicit_param = explicit_param_names[0] if explicit_param_names else ""

        if explicit_param:
            seed_value = explicit_payload
            if seed_value is None:
                seed_value = normalized.get(explicit_param, "1")
            normalized[explicit_param] = seed_value

        for name in discovered_hints:
            normalized.setdefault(name, "1")

        return normalized

    @staticmethod
    def _looks_like_login_page(body: str) -> bool:
        if not body:
            return False
        body_lower = body.lower()
        login_markers = [
            "login :: damn vulnerable web application",
            "name=\"username\"",
            "name=\"password\"",
        ]
        return all(marker in body_lower for marker in login_markers)

    def _resolve_request_client(self) -> Any:
        """
        Manager 共有 client が未注入でも CSRF/API 軽量チェックを実行可能にする。
        優先順: manager shared client -> specialist client -> 一時 client。
        """
        if self.network_client is not None:
            return self.network_client

        for specialist_name in ("sqli", "xss", "cmd_ssrf", "lfi", "redirect"):
            specialist = self.specialists.get(specialist_name)
            candidate = getattr(specialist, "network_client", None) if specialist else None
            if candidate is not None:
                return candidate

        from src.core.infra.network_client import AsyncNetworkClient

        client = AsyncNetworkClient(mode="bugbounty")
        self._ephemeral_network_clients.append(client)
        return client

    def _should_bypass_cache(self, url: str, vuln_type: str, params: Dict[str, Any]) -> bool:
        """高リスク対象はキャッシュ再利用を避ける（0件再利用による取りこぼし防止）。"""
        if self._is_high_risk_endpoint(url):
            return True
        if vuln_type in {"cmd_ssrf", "ssrf", "sqli", "redirect", "lfi", "csrf", "api"}:
            return True
        category = str((params or {}).get("category", "") or "").lower()
        return category in {"csrf_candidate", "api_candidate", "command_injection"}

    @staticmethod
    def _resolve_detection_mode(params: Dict[str, Any], default_mode: str) -> str:
        mode = str((params or {}).get("detection_mode", "") or default_mode).strip().lower()
        if mode in {"phase1", "phase2", "risk_forced"}:
            return mode
        return default_mode

    @staticmethod
    def _coerce_bool(value: Any, default: bool) -> bool:
        """task.params 由来の bool 風値を安全に bool へ変換する。"""
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on"}:
                return True
            if normalized in {"0", "false", "no", "off"}:
                return False
        return default

    def _resolve_scan_profile(self, task: Task) -> str:
        """scan profile を決定する（CLI/task/context/config/mode を順に参照）。"""
        task_params = task.params if isinstance(task.params, dict) else {}
        task_context = task_params.get("_context", {}) if isinstance(task_params.get("_context", {}), dict) else {}

        profile = (
            task_params.get("scan_profile")
            or task_params.get("profile")
            or task_context.get("scan_profile")
            or task_context.get("profile")
        )

        if not profile and hasattr(self, "master_conductor") and self.master_conductor:
            try:
                target_info = getattr(getattr(self.master_conductor, "context", None), "target_info", {})
                if isinstance(target_info, dict):
                    profile = target_info.get("scan_profile") or target_info.get("profile")
            except Exception:
                profile = None

        if not profile and isinstance(self.config, dict):
            profile = self.config.get("scan_profile") or self.config.get("profile")

        if not profile:
            mode = str(task_params.get("mode") or (self.config.get("mode") if isinstance(self.config, dict) else "") or "").lower()
            profile = "ctf" if mode == "ctf" else "bbpt"

        profile = str(profile).lower()
        return profile if profile in {"bbpt", "ctf"} else "bbpt"

    def _timeout_backoff_seconds(self, retry_count: int) -> float:
        """timeout リトライ時の指数バックオフ（ジッター付き）を返す。"""
        base = self.TIMEOUT_BACKOFF_BASE_SECONDS * (2 ** max(0, retry_count - 1))
        jitter = 0.85 + (random.random() * 0.3)
        return min(self.TIMEOUT_BACKOFF_MAX_SECONDS, base * jitter)

    @staticmethod
    def _build_timeout_cause_key(url: str, vuln_type: str) -> str:
        """
        timeout の同系統判定キーを作る。
        動的ID/長いhexを正規化し、query の主要キーだけを含める。
        """
        parsed = urlparse(str(url or ""))
        path = str(parsed.path or "").lower()
        path = re.sub(r"/\d+(?=/|$)", "/:num", path)
        path = re.sub(r"/[0-9a-f]{8,}(?=/|$)", "/:hex", path)
        path = re.sub(r"/{2,}", "/", path)
        query_keys = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())[:3]
        return f"{str(vuln_type or '').lower()}:{path}?{','.join(query_keys)}"

    def _refresh_auth_context_on_timeout(self, task: Task, base_params: Dict[str, Any]) -> None:
        """timeout 後の再試行前に Cookie/ヘッダーを再同期する軽量フック。"""
        if not isinstance(base_params, dict):
            return

        auth = base_params.get("_auth", {})
        if not isinstance(auth, dict):
            auth = {}
            base_params["_auth"] = auth

        auth_headers = auth.get("auth_headers", {})
        if not isinstance(auth_headers, dict):
            auth_headers = {}
            auth["auth_headers"] = auth_headers

        current_cookies = str(auth.get("cookies", "") or "")
        if current_cookies:
            auth_headers.setdefault("Cookie", current_cookies)
            return

        context_cookie = ""
        try:
            context_cookie = str(self.current_context.get("params", {}).get("cookies", "") or "")
        except Exception:
            context_cookie = ""

        if not context_cookie and hasattr(self, "master_conductor") and self.master_conductor:
            try:
                target_info = getattr(getattr(self.master_conductor, "context", None), "target_info", {})
                if isinstance(target_info, dict):
                    context_cookie = str(target_info.get("cookies") or target_info.get("cookie") or "")
            except Exception:
                context_cookie = ""

        if context_cookie:
            auth["cookies"] = context_cookie
            auth_headers["Cookie"] = context_cookie

    def _emit_phase1_heartbeat(
        self,
        target_url: str,
        vuln_type: str,
        retry_count: int,
        per_url_timeout: int,
        manager_start: float,
        manager_timeout: int,
    ) -> None:
        """Phase1 実行中の進捗 heartbeat をログへ出力する。"""
        elapsed = asyncio.get_event_loop().time() - manager_start
        remaining = max(0.0, manager_timeout - elapsed)
        logger.info(
            "[%s] Heartbeat url=%s type=%s attempt=%d timeout=%ss manager_remaining=%.1fs",
            self.name,
            target_url,
            vuln_type,
            retry_count + 1,
            per_url_timeout,
            remaining,
        )

    def _is_high_risk_endpoint(self, url: str) -> bool:
        if not url:
            return False

        parsed = urlparse(url)
        path = (parsed.path or "").lower()
        query_keys = [k.lower() for k in parse_qs(parsed.query).keys()]

        # Core+Coverage 方針: 高リスク対象のみを明示し、不要な Phase2 強制を避ける
        high_risk_tokens = (
            "exec", "cmd",
            "sqli", "sqli_blind", "blind",
            "fi", "file_inclusion", "inclusion", "page",
            "csrf",
            "api", "/api/", "graphql",
            "open_redirect", "redirect",
            "authbypass", "weak_id",
        )

        if any(token in path for token in high_risk_tokens):
            return True

        return any(any(token in key for token in high_risk_tokens) for key in query_keys)

    def _summarize_phase1_signals(self, phase1_url_results: List[Dict[str, Any]], primary_target: str) -> Dict[str, bool]:
        tool_error = False
        weak_signal = False

        urls_to_evaluate: List[str] = [primary_target] if primary_target else []
        for entry in phase1_url_results:
            if not isinstance(entry, dict):
                continue

            status = str(entry.get("status", "")).lower()
            if status in {"timeout", "error"}:
                tool_error = True

            if bool(entry.get("reflection_observed", False)):
                weak_signal = True

            if str(entry.get("xss_evidence", "") or "").strip():
                weak_signal = True

            blind = entry.get("blind_correlation", {})
            if has_actionable_blind_signal(blind):
                weak_signal = True

            url = str(entry.get("url", "") or "")
            if url:
                urls_to_evaluate.append(url)

        high_risk_endpoint = any(self._is_high_risk_endpoint(url) for url in urls_to_evaluate)

        return {
            "tool_error": tool_error,
            "weak_signal": weak_signal,
            "high_risk_endpoint": high_risk_endpoint,
        }

    async def _run_csrf_minimal_check(self, url: str, base_params: Dict[str, Any]) -> Dict[str, Any]:
        """軽量 CSRF チェック（トークン欠如 + 擬似 forged request 成立性）。"""
        findings_sink = self.current_context.setdefault("findings", []) if isinstance(self.current_context, dict) else []
        return await run_csrf_minimal_check(
            url=url,
            base_params=base_params,
            request_client=self._resolve_request_client(),
            source_agent_name=self.name,
            findings_sink=findings_sink,
            looks_like_login_page=self._looks_like_login_page,
            resolve_detection_mode=self._resolve_detection_mode,
            coerce_bool=self._coerce_bool,
        )

    async def _run_api_minimal_check(self, url: str, base_params: Dict[str, Any]) -> Dict[str, Any]:
        """軽量 API チェック（未認証アクセス候補、過剰メソッド露出候補）。"""
        request_client = self._resolve_request_client()

        auth = base_params.get("_auth", {}) if isinstance(base_params.get("_auth", {}), dict) else {}
        auth_headers = dict(auth.get("auth_headers", {}) or {})
        cookies = str(auth.get("cookies", "") or base_params.get("cookies", "") or "")
        if cookies and "Cookie" not in auth_headers:
            auth_headers["Cookie"] = cookies
        unauth_headers = {k: v for k, v in auth_headers.items() if k.lower() not in {"authorization", "cookie"}}
        current_findings = self.current_context.get("findings", []) if isinstance(self.current_context, dict) else []
        findings_start_index = len(current_findings) if isinstance(current_findings, list) else 0

        findings_count = 0
        detection_mode = self._resolve_detection_mode(base_params, "phase1")
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
        unauth_login_like = self._looks_like_login_page(body)
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
                source_agent=self.name,
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
            self.current_context["findings"].append(finding)
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
                    source_agent=self.name,
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
                self.current_context["findings"].append(idor_finding)
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
                if self._looks_like_login_page(probe_unauth_body):
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
                        source_agent=self.name,
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
                    self.current_context["findings"].append(finding)
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
                source_agent=self.name,
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
            self.current_context["findings"].append(finding)
            findings_count += 1

        # 軽量 mass-assignment probe（応答スキーマから候補キーを抽出して拡張）
        schema_probe_fields = extract_mass_assignment_schema_candidates(
            response_bodies=[auth_body, body],
            excluded_params=self.EXCLUDED_TESTED_PARAMS,
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
                    reflection_login_like = self._looks_like_login_page(reflection_recheck_body_raw)
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
                    recheck_login_like = self._looks_like_login_page(recheck_body_raw)
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
                    source_agent=self.name,
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
                self.current_context["findings"].append(finding)
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
                        auth_reflection_login_like = self._looks_like_login_page(auth_reflection_recheck_body_raw)
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
                        auth_recheck_login_like = self._looks_like_login_page(auth_recheck_body_raw)
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
                        source_agent=self.name,
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
                    self.current_context["findings"].append(finding)
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
                        and not self._looks_like_login_page(fallback_body_raw)
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
                            source_agent=self.name,
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
                        self.current_context["findings"].append(finding)
                        findings_count += 1
                except Exception:
                    api_probe_skipped_reason = "write_method_not_discovered_and_read_probe_failed"
            else:
                api_probe_skipped_reason = "write_method_not_discovered_from_options_or_fallback_probes"

        final_findings = self.current_context.get("findings", []) if isinstance(self.current_context, dict) else []
        if isinstance(final_findings, list) and findings_start_index < len(final_findings):
            normalize_findings_additional_info(
                final_findings[findings_start_index:],
                tested_params,
                detection_mode,
            excluded_params=self.EXCLUDED_TESTED_PARAMS,
            )

        return {
            "findings_count": findings_count,
            "tested_params": sanitize_tested_params(tested_params, excluded_params=self.EXCLUDED_TESTED_PARAMS),
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

    async def dispatch(self, task: Task) -> SwarmResult:
        """
        全ターゲット URL への決定的攻撃フェーズ（Phase 1）を実行してから
        LLM Think Loop（Phase 2）に引き渡す二段構えの dispatch。

        Phase 1 で全 target URL を確実にカバーすることで、LLM が最初の URL に
        固執して他を無視する問題を根本解決する。

        最適化:
        - 早期リターン：Phase 1 で脆弱性発見時は Phase 2 をスキップ
        - 並列処理：PARALLEL_BATCH_SIZE ずつ並列実行（リソース枯渇防止）
        - URL 優先度付け：重要な脆弱性を含む URL を優先チェック
        - キャッシュ：同一 URL/パラメータの重複チェックを防止
        - MAX_URLS_TO_CHECK: チェックする URL 数の上限（コスト爆発防止）
        """
        manager_start = asyncio.get_event_loop().time()
        self._phase2_detection_mode = "phase2"
        manager_timeout = int(task.params.get("manager_timeout_seconds") or self.INJECTION_MANAGER_TIMEOUT)
        default_per_url_timeout = int(task.params.get("per_url_timeout_seconds") or self.PER_URL_TIMEOUT_SECONDS)
        max_timeout_retries = int(task.params.get("phase1_timeout_retries") or self.PHASE1_TIMEOUT_RETRIES)
        scan_profile = self._resolve_scan_profile(task)
        phase1_coverage_mode = self._coerce_bool(
            task.params.get("phase1_force_full_coverage"),
            default=(scan_profile == "ctf"),
        )
        phase1_stop_on_first_hit = self._coerce_bool(
            task.params.get("phase1_stop_on_first_hit"),
            default=(not phase1_coverage_mode),
        )

        # current_context を dispatch 前に初期化しておく (BaseManager が使う)
        auth_headers = task.params.get("auth_headers", {})
        cookies_str = task.params.get("cookies", "")
        if "Cookie" not in auth_headers and cookies_str:
            auth_headers["Cookie"] = cookies_str

        self.current_context = {
            "target": task.target,
            "params": task.params,
            "auth_headers": auth_headers,
            "findings": [],
            "url_results": [],
            "scan_profile": scan_profile,
        }

        logger.info("[%s] Using scan profile: %s", self.name, scan_profile)

        # --- Phase 1: 全ターゲットへの決定的攻撃 ---
        targets: List[str] = task.params.get("targets", [])
        if task.target and task.target not in targets:
            targets = [task.target] + targets

        task_category = str(task.params.get("category", "") or "")
        context = task.params.get("_context", {})
        if not isinstance(context, dict):
            context = {}
        forms_by_url = context.get("forms_by_url", {})
        if not isinstance(forms_by_url, dict):
            forms_by_url = {}
        url_evidence_by_url = context.get("url_evidence_by_url", {})
        if not isinstance(url_evidence_by_url, dict):
            url_evidence_by_url = {}

        # URL に優先度スコアを付ける（Step6: 成立確率順）
        prioritized_targets = prioritize_targets(
            targets,
            forms_by_url=forms_by_url,
            url_evidence_by_url=url_evidence_by_url,
            category=task_category,
        )
        phase1_priority_plan = [
            {
                "url": url,
                "priority_score": int(priority_score),
                "priority_signals": list(priority_signals),
            }
            for url, priority_score, priority_signals in prioritized_targets[: self.MAX_URLS_TO_CHECK]
        ]
        logger.info(
            "[%s] Phase 1: Deterministic attack on %d targets (prioritized, max %d)",
            self.name, len(prioritized_targets), self.MAX_URLS_TO_CHECK
        )

        # 早期リターンフラグ
        phase1_found_vuln = False
        urls_checked = 0
        timeout_retry_guard_enabled = bool(
            getattr(settings, "phase1_timeout_retry_same_cause_guard", False)
        )
        timeout_retry_guard_min_priority = max(
            0,
            int(getattr(settings, "phase1_timeout_retry_guard_min_priority", 70) or 70),
        )
        timeout_cause_failures: Dict[str, int] = {}
        executed_keys: set[str] = set()

        # 並列バッチ処理
        batch_size = self.PARALLEL_BATCH_SIZE
        for batch_start in range(0, min(len(prioritized_targets), self.MAX_URLS_TO_CHECK), batch_size):
            batch_end = min(batch_start + batch_size, len(prioritized_targets), self.MAX_URLS_TO_CHECK)
            batch = prioritized_targets[batch_start:batch_end]

            elapsed = asyncio.get_event_loop().time() - manager_start
            if elapsed >= manager_timeout:
                logger.warning(
                    "[%s] Manager budget exhausted before batch start (elapsed=%.1fs, budget=%ds).",
                    self.name, elapsed, manager_timeout
                )
                break
            
            logger.info(
                "[%s] Processing batch %d-%d of %d URLs",
                self.name, batch_start + 1, batch_end, len(prioritized_targets)
            )

            # バッチ内の URL を順次処理
            # quick_mode=False で検出率を維持しつつ、URL 単位 timeout で全体ハングを防ぐ
            for target_url, priority_score, priority_signals in batch:
                vuln_type = classify_target_url(target_url, category=task_category)
                dedupe_key = f"{target_url}|{vuln_type}|{task_category}"
                if dedupe_key in executed_keys:
                    self.current_context["url_results"].append({
                        "url": target_url,
                        "vuln_type": vuln_type,
                        "status": "skipped",
                        "skip_reason": "dedupe_execution_key",
                        "priority_score": int(priority_score),
                        "priority_signals": list(priority_signals),
                        "findings_count": 0,
                        "tested_params": [],
                        "detection_mode": "phase1",
                    })
                    continue
                executed_keys.add(dedupe_key)
                logger.info(
                    "[%s] → %s classified as '%s' (priority_score: %d, signals=%s)",
                    self.name,
                    target_url,
                    vuln_type,
                    priority_score,
                    ",".join(priority_signals[:4]),
                )

                # _context からフォーム情報を取得
                url_evidence = {}
                if isinstance(url_evidence_by_url, dict):
                    raw_evidence = url_evidence_by_url.get(target_url, {})
                    if isinstance(raw_evidence, dict):
                        url_evidence = raw_evidence
                resolved_method = str(
                    url_evidence.get("method")
                    or task.params.get("method", "GET")
                ).upper()
                ssrf_score = int(url_evidence.get("ssrf_score", 0) or 0)
                score_breakdown = url_evidence.get("score_breakdown", {})
                if not isinstance(score_breakdown, dict):
                    score_breakdown = {}
                
                base_params: Dict[str, Any] = {
                    "_auth": {
                        "auth_headers": auth_headers,
                        "cookies": task.params.get("cookies", ""),
                    },
                    # method 情報を追加（POST/GET の識別に必要）
                    "method": resolved_method,
                    # フォーム情報を追加（POST SQLi に必要）
                    "forms": forms_by_url.get(target_url, []),
                    # unknown 分類用の追加証拠
                    "url_evidence": url_evidence,
                    "scan_profile": scan_profile,
                    "category": str(task.params.get("category", "") or ""),
                    "detection_mode": "phase1",
                }

                if vuln_type == "ssrf":
                    if task_category == CATEGORY_SSRF_CANDIDATE and ssrf_score < 40:
                        self.current_context["url_results"].append({
                            "url": target_url,
                            "vuln_type": vuln_type,
                            "status": "skipped",
                            "skip_reason": "low_ssrf_score",
                            "ssrf_score": ssrf_score,
                            "score_breakdown": url_evidence.get("score_breakdown", {}),
                            "priority_score": int(priority_score),
                            "priority_signals": list(priority_signals),
                            "findings_count": 0,
                            "tested_params": [],
                            "detection_mode": "phase1",
                        })
                        continue

                    reachable, gate_reason = self._ssrf_reachability_gate(target_url, base_params)
                    if not reachable:
                        self.current_context["url_results"].append({
                            "url": target_url,
                            "vuln_type": vuln_type,
                            "status": "skipped",
                            "skip_reason": "ssrf_reachability_gate",
                            "gate_reason": gate_reason,
                            "ssrf_score": ssrf_score,
                            "score_breakdown": url_evidence.get("score_breakdown", {}),
                            "priority_score": int(priority_score),
                            "priority_signals": list(priority_signals),
                            "findings_count": 0,
                            "tested_params": [],
                            "detection_mode": "phase1",
                        })
                        continue

                # キャッシュチェック
                cache_key = self._generate_cache_key(target_url, vuln_type, base_params)
                bypass_cache = self._should_bypass_cache(target_url, vuln_type, base_params)
                if not bypass_cache and cache_key in self._request_cache:
                    logger.info("[%s] Cache hit for %s (vuln_type: %s)", self.name, target_url, vuln_type)
                    cached_result = self._request_cache[cache_key]
                    self.current_context["url_results"].append(
                        build_url_result_from_cache(
                            target_url=target_url,
                            vuln_type=vuln_type,
                            priority_score=int(priority_score),
                            priority_signals=list(priority_signals),
                            cached_result=cached_result,
                            ssrf_score=ssrf_score if vuln_type == "ssrf" else 0,
                            score_breakdown=score_breakdown if vuln_type == "ssrf" else None,
                        )
                    )
                    if cached_result.get("findings_count", 0) > 0:
                        phase1_found_vuln = True
                        self.current_context["findings"].extend(cached_result.get("findings", []))
                    continue

                # quick_mode=False で十分なターン数を確保しつつ、URL 単位 timeout を適用
                per_url_timeout = resolve_per_url_timeout(
                    task,
                    target_url,
                    vuln_type,
                    default_timeout_seconds=self.PER_URL_TIMEOUT_SECONDS,
                    timeout_by_type=self.PER_URL_TIMEOUT_BY_TYPE,
                    blind_sqli_timeout_seconds=self.PER_URL_TIMEOUT_BLIND_SQLI_SECONDS,
                )
                if scan_profile == "bbpt" and vuln_type == "xss":
                    per_url_timeout = max(per_url_timeout, 180)
                elif scan_profile == "ctf" and vuln_type == "xss":
                    per_url_timeout = min(per_url_timeout, 180)
                url_start = asyncio.get_event_loop().time()
                retry_count = 0
                effective_timeout_retries = max_timeout_retries
                if vuln_type == "xss" and "xss_s" in urlparse(target_url).path.lower():
                    effective_timeout_retries = max(effective_timeout_retries, 2)
                if vuln_type == "xss" and any(
                    token in urlparse(target_url).path.lower()
                    for token in ["xss_r", "javascript"]
                ):
                    effective_timeout_retries = max(effective_timeout_retries, 2)
                if vuln_type == "sqli" and "/vulnerabilities/sqli/" in urlparse(target_url).path.lower():
                    effective_timeout_retries = max(effective_timeout_retries, 2)

                if scan_profile == "ctf" and vuln_type in {"xss", "sqli"}:
                    effective_timeout_retries = max(effective_timeout_retries, 2)
                if scan_profile == "bbpt" and vuln_type in {"xss", "sqli"}:
                    effective_timeout_retries = max(effective_timeout_retries, 1)
                timeout_cause_key = self._build_timeout_cause_key(target_url, vuln_type)
                previous_timeout_failures = int(timeout_cause_failures.get(timeout_cause_key, 0))
                if (
                    previous_timeout_failures >= self.TIMEOUT_CIRCUIT_BREAKER_THRESHOLD
                ):
                    logger.warning(
                        "[%s] Timeout circuit-breaker opened for %s (cause=%s, failures=%d)",
                        self.name,
                        target_url,
                        timeout_cause_key,
                        previous_timeout_failures,
                    )
                    self.current_context["url_results"].append({
                        "url": target_url,
                        "vuln_type": vuln_type,
                        "status": "skipped",
                        "skip_reason": "timeout_circuit_breaker_open",
                        "priority_score": int(priority_score),
                        "priority_signals": list(priority_signals),
                        "findings_count": 0,
                        "tested_params": [],
                        "detection_mode": "phase1",
                    })
                    continue
                if (
                    timeout_retry_guard_enabled
                    and previous_timeout_failures > 0
                    and int(priority_score) < timeout_retry_guard_min_priority
                ):
                    logger.info(
                        "[%s] Timeout retry guard: suppress retries for %s (cause=%s, previous_failures=%d, priority=%d < %d)",
                        self.name,
                        target_url,
                        timeout_cause_key,
                        previous_timeout_failures,
                        int(priority_score),
                        timeout_retry_guard_min_priority,
                    )
                    effective_timeout_retries = 0

                while True:
                    self._emit_phase1_heartbeat(
                        target_url=target_url,
                        vuln_type=vuln_type,
                        retry_count=retry_count,
                        per_url_timeout=per_url_timeout,
                        manager_start=manager_start,
                        manager_timeout=manager_timeout,
                    )
                    try:
                        phase1_quick_mode = (
                            (scan_profile == "ctf" and vuln_type == "xss")
                            or vuln_type == "cmd_ssrf"
                        )
                        result = await asyncio.wait_for(
                            self._process_single_url(
                                target_url,
                                vuln_type,
                                base_params,
                                quick_mode=phase1_quick_mode,
                            ),
                            timeout=per_url_timeout
                        )
                        url_elapsed = asyncio.get_event_loop().time() - url_start
                        findings_count = result.get("findings_count", 0)
                        tested_params = result.get("tested_params", [])
                        self.current_context["url_results"].append({
                            "url": target_url,
                            "vuln_type": vuln_type,
                            "status": "completed",
                            "priority_score": int(priority_score),
                            "priority_signals": list(priority_signals),
                            "duration_seconds": round(url_elapsed, 3),
                            "retry_count": retry_count,
                            "findings_count": findings_count,
                            "tested_params": tested_params,
                            "probe_sent": result.get("probe_sent"),
                            "probe_skipped_reason": result.get("probe_skipped_reason", ""),
                            "poc_request": result.get("probe_request_raw", ""),
                            "poc_response": result.get("probe_response_raw", ""),
                            "reflection_observed": result.get("reflection_observed", False),
                            "xss_evidence": result.get("xss_evidence", ""),
                            "blind_correlation": result.get("blind_correlation", {}),
                            "unknown_profile": result.get("unknown_profile", {}),
                            "comparison_checks": result.get("comparison_checks", []),
                            "auth_context_matrix": result.get("auth_context_matrix", {}),
                            "object_ab_comparison": result.get("object_ab_comparison", {}),
                            "schema_candidate_params": result.get("schema_candidate_params", []),
                            "single_request_validation": result.get("single_request_validation", True),
                            "detection_mode": result.get("detection_mode", "phase1"),
                            "ssrf_score": ssrf_score if vuln_type == "ssrf" else 0,
                            "score_breakdown": score_breakdown if vuln_type == "ssrf" else {},
                        })

                        if findings_count > 0:
                            phase1_found_vuln = True
                            detected_type = result.get("vuln_type", "unknown")
                            logger.info("[%s] Phase 1: %s vulnerability found on %s", self.name, detected_type, target_url)
                        break
                    except asyncio.TimeoutError:
                        if retry_count < effective_timeout_retries:
                            retry_count += 1
                            logger.warning(
                                "[%s] Phase 1 timeout on %s after %ds (retry %d/%d)",
                                self.name,
                                target_url,
                                per_url_timeout,
                                retry_count,
                                effective_timeout_retries,
                            )
                            self._refresh_auth_context_on_timeout(task, base_params)
                            await asyncio.sleep(self._timeout_backoff_seconds(retry_count))
                            continue

                        logger.warning(
                            "[%s] Phase 1 timeout on %s after %ds (continuing next target)",
                            self.name,
                            target_url,
                            per_url_timeout,
                        )
                        timeout_cause_failures[timeout_cause_key] = previous_timeout_failures + 1
                        timeout_tested_params = self._collect_recent_tested_params(vuln_type)
                        self.current_context["url_results"].append({
                            "url": target_url,
                            "vuln_type": vuln_type,
                            "status": "timeout",
                            "priority_score": int(priority_score),
                            "priority_signals": list(priority_signals),
                            "duration_seconds": per_url_timeout,
                            "retry_count": retry_count,
                            "findings_count": 0,
                            "tested_params": timeout_tested_params,
                            "unknown_profile": {},
                            "comparison_checks": [],
                            "auth_context_matrix": {},
                            "object_ab_comparison": {},
                            "schema_candidate_params": [],
                            "single_request_validation": True,
                            "detection_mode": "phase1",
                            "ssrf_score": ssrf_score if vuln_type == "ssrf" else 0,
                            "score_breakdown": score_breakdown if vuln_type == "ssrf" else {},
                        })
                        break
                    except Exception as exc:
                        logger.error("[%s] Phase 1 error on %s: %s", self.name, target_url, exc)
                        error_tested_params = self._collect_recent_tested_params(vuln_type)
                        self.current_context["url_results"].append({
                            "url": target_url,
                            "vuln_type": vuln_type,
                            "status": "error",
                            "priority_score": int(priority_score),
                            "priority_signals": list(priority_signals),
                            "error": str(exc),
                            "retry_count": retry_count,
                            "findings_count": 0,
                            "tested_params": error_tested_params,
                            "unknown_profile": {},
                            "comparison_checks": [],
                            "auth_context_matrix": {},
                            "object_ab_comparison": {},
                            "schema_candidate_params": [],
                            "single_request_validation": True,
                            "detection_mode": "phase1",
                            "ssrf_score": ssrf_score if vuln_type == "ssrf" else 0,
                            "score_breakdown": score_breakdown if vuln_type == "ssrf" else {},
                        })
                        break

            urls_checked += len(batch)

            # 早期停止は明示的に有効な場合のみ
            if phase1_found_vuln and phase1_stop_on_first_hit:
                logger.info(
                    "[%s] Phase 1: Vulnerability found and stop_on_first_hit enabled. Skipping remaining %d URLs.",
                    self.name,
                    len(prioritized_targets) - urls_checked,
                )
                break

        phase1_findings = list(self.current_context["findings"])
        logger.info(
            "[%s] Phase 1 complete: %d findings from %d URLs checked",
            self.name, len(phase1_findings), urls_checked
        )
        phase1_url_results = list(self.current_context.get("url_results", []))
        phase1_signals = self._summarize_phase1_signals(phase1_url_results, task.target)
        skip_reason_counts = summarize_skip_reason_counts(phase1_url_results)
        skip_reason_unknown_counts = summarize_skip_reason_unknown_counts(phase1_url_results)
        low_ssrf_score_breakdown = summarize_low_ssrf_score_breakdown(phase1_url_results)
        phase1_vuln_types = collect_phase1_vuln_types(phase1_url_results)
        risk_force_allowlist = resolve_risk_force_allowlist(task, scan_profile)
        max_ssrf_score = extract_max_ssrf_score(phase1_url_results)
        risk_override = self._coerce_bool(task.params.get("risk_override"), default=False)
        lane2_score_eligible = is_lane2_score_eligible(max_ssrf_score, risk_override, lane2_score_threshold=self.LANE2_SCORE_THRESHOLD)
        high_risk_requires_phase2 = (
            phase1_signals["high_risk_endpoint"]
            and bool(phase1_vuln_types & risk_force_allowlist)
            and (lane2_score_eligible if task_category == CATEGORY_SSRF_CANDIDATE else True)
        )
        phase2_forced_by_risk = should_force_phase2_by_risk(
            phase1_findings=phase1_findings,
            phase1_signals=phase1_signals,
            high_risk_requires_phase2=high_risk_requires_phase2,
        )
        self._phase2_detection_mode = "risk_forced" if phase2_forced_by_risk else "phase2"
        if isinstance(self.current_context.get("params"), dict):
            self.current_context["params"]["detection_mode"] = self._phase2_detection_mode

        early_return_enabled = self._coerce_bool(
            task.params.get("phase1_early_return_on_findings"),
            default=(not phase1_coverage_mode),
        )
        auto_early_return = should_auto_early_return(
            task=task,
            phase1_findings=phase1_findings,
            phase1_signals=phase1_signals,
            phase1_vuln_types=phase1_vuln_types,
            coerce_bool=self._coerce_bool,
        )
        if phase1_findings and (early_return_enabled or auto_early_return):
            reason = "phase1_early_return" if early_return_enabled else "phase1_auto_early_return_findings"
            logger.info(
                "[%s] Early return (%s) with %d Phase 1 findings. Skipping Phase 2.",
                self.name, reason, len(phase1_findings)
            )
            return SwarmResult(
                findings=phase1_findings,
                status="success",
                execution_log=[{
                    "phase": "phase1_summary",
                    "reason": reason,
                    "urls_checked": urls_checked,
                    "manager_timeout_seconds": manager_timeout,
                    "per_url_timeout_seconds": default_per_url_timeout,
                    "url_results": phase1_url_results,
                    "skip_reason_counts": skip_reason_counts,
                    "skip_reason_unknown_counts": skip_reason_unknown_counts,
                    "low_ssrf_score_breakdown": low_ssrf_score_breakdown,
                    "prioritized_targets": phase1_priority_plan,
                    "tool_error": phase1_signals["tool_error"],
                    "weak_signal": phase1_signals["weak_signal"],
                    "high_risk_endpoint": phase1_signals["high_risk_endpoint"],
                    "high_risk_requires_phase2": high_risk_requires_phase2,
                    "phase2_forced_by_risk": phase2_forced_by_risk,
                }],
                swarm_name=self.name,
                total_specialists=1,
                successful_specialists=1,
            )

        phase2_on_empty_phase1 = self._coerce_bool(
            task.params.get("phase2_on_empty_phase1"),
            default=False,
        )
        if bool(getattr(settings, "phase2_on_empty_force_disable", False)):
            phase2_on_empty_phase1 = False
        should_skip_phase2 = (
            not phase1_findings
            and not phase1_signals["tool_error"]
            and not phase1_signals["weak_signal"]
            and not high_risk_requires_phase2
            and not phase2_on_empty_phase1
        )

        if should_skip_phase2:
            logger.info(
                "[%s] Skipping Phase 2: no findings/signals and no risk-forced vuln types.",
                self.name,
            )
            return SwarmResult(
                findings=phase1_findings,
                status="success",
                execution_log=[{
                    "phase": "phase1_summary",
                    "reason": "phase1_safe_skip_no_signal",
                    "urls_checked": urls_checked,
                    "manager_timeout_seconds": manager_timeout,
                    "per_url_timeout_seconds": default_per_url_timeout,
                    "url_results": phase1_url_results,
                    "skip_reason_counts": skip_reason_counts,
                    "skip_reason_unknown_counts": skip_reason_unknown_counts,
                    "low_ssrf_score_breakdown": low_ssrf_score_breakdown,
                    "prioritized_targets": phase1_priority_plan,
                    "tool_error": phase1_signals["tool_error"],
                    "weak_signal": phase1_signals["weak_signal"],
                    "high_risk_endpoint": phase1_signals["high_risk_endpoint"],
                    "lane2_score_eligible": lane2_score_eligible,
                    "max_ssrf_score": max_ssrf_score,
                    "risk_override": risk_override,
                    "high_risk_requires_phase2": high_risk_requires_phase2,
                    "phase2_forced_by_risk": phase2_forced_by_risk,
                }],
                swarm_name=self.name,
                total_specialists=1,
                successful_specialists=1,
            )

        # --- Phase 2: LLM Think Loop で追加推論 ---
        # Phase 1 の結果を履歴に追加して LLM に伝える
        if phase1_findings:
            findings_summary = f"Phase 1 (Deterministic Scan) found {len(phase1_findings)} potential vulnerabilities: "
            findings_summary += ", ".join([str(getattr(f, 'title', f)) for f in phase1_findings])
            self.history.append({
                "role": "user", 
                "content": f"System Note: {findings_summary}. Use the tools to investigate further or confirm these findings."
            })
        else:
            self.history.append({
                "role": "user", 
                "content": "Phase 1 (Deterministic Scan) completed with no confirmed findings. Please use your tools to perform a deep analysis of the target."
            })

        logger.info("[%s] Phase 1 results injected into context. Starting Phase 2 (LLM Think Loop)...", self.name)

        elapsed_after_phase1 = asyncio.get_event_loop().time() - manager_start
        remaining_budget = max(1, manager_timeout - int(elapsed_after_phase1))
        remaining_budget = cap_phase2_budget(
            remaining_budget=remaining_budget,
            phase2_forced_by_risk=phase2_forced_by_risk,
            task_params=task.params,
        )

        if remaining_budget <= 1:
            logger.warning(
                "[%s] Skipping Phase 2 due to exhausted manager budget (elapsed=%.1fs, budget=%ds)",
                self.name, elapsed_after_phase1, manager_timeout
            )
            return SwarmResult(
                findings=phase1_findings,
                status="partial_success" if phase1_findings else "failed",
                execution_log=[{
                    "phase": "phase1",
                    "urls_checked": urls_checked,
                    "manager_timeout_seconds": manager_timeout,
                    "per_url_timeout_seconds": default_per_url_timeout,
                    "url_results": phase1_url_results,
                    "skip_reason_counts": skip_reason_counts,
                    "skip_reason_unknown_counts": skip_reason_unknown_counts,
                    "low_ssrf_score_breakdown": low_ssrf_score_breakdown,
                    "prioritized_targets": phase1_priority_plan,
                    "tool_error": phase1_signals["tool_error"],
                    "weak_signal": phase1_signals["weak_signal"],
                    "high_risk_endpoint": phase1_signals["high_risk_endpoint"],
                    "high_risk_requires_phase2": high_risk_requires_phase2,
                    "phase2_forced_by_risk": phase2_forced_by_risk,
                }],
                swarm_name=self.name,
                total_specialists=1,
                successful_specialists=1 if phase1_findings else 0,
            )

        try:
            result: SwarmResult = await asyncio.wait_for(super().dispatch(task), timeout=remaining_budget)
        except asyncio.TimeoutError:
            logger.warning(
                "[%s] Phase 2 timed out after %ds. Returning Phase 1 partial result.",
                self.name, remaining_budget
            )
            return SwarmResult(
                findings=phase1_findings,
                status="partial_success" if phase1_findings else "failed",
                execution_log=[{
                    "phase": "phase1_partial_return",
                    "reason": "phase2_timeout",
                    "urls_checked": urls_checked,
                    "manager_timeout_seconds": manager_timeout,
                    "per_url_timeout_seconds": default_per_url_timeout,
                    "url_results": phase1_url_results,
                    "skip_reason_counts": skip_reason_counts,
                    "skip_reason_unknown_counts": skip_reason_unknown_counts,
                    "low_ssrf_score_breakdown": low_ssrf_score_breakdown,
                    "prioritized_targets": phase1_priority_plan,
                    "tool_error": phase1_signals["tool_error"],
                    "weak_signal": phase1_signals["weak_signal"],
                    "high_risk_endpoint": phase1_signals["high_risk_endpoint"],
                    "high_risk_requires_phase2": high_risk_requires_phase2,
                    "phase2_forced_by_risk": phase2_forced_by_risk,
                }],
                swarm_name=self.name,
                total_specialists=1,
                successful_specialists=1 if phase1_findings else 0,
            )

        # Phase 1 の findings を LLM 結果にマージ
        all_findings = phase1_findings + [f for f in result.findings if f not in phase1_findings]
        result.findings = all_findings
        result.execution_log.append({
            "phase": "phase1_summary",
            "urls_checked": urls_checked,
            "manager_timeout_seconds": manager_timeout,
            "per_url_timeout_seconds": default_per_url_timeout,
            "url_results": phase1_url_results,
            "skip_reason_counts": skip_reason_counts,
            "skip_reason_unknown_counts": skip_reason_unknown_counts,
            "low_ssrf_score_breakdown": low_ssrf_score_breakdown,
            "prioritized_targets": phase1_priority_plan,
            "tool_error": phase1_signals["tool_error"],
            "weak_signal": phase1_signals["weak_signal"],
            "high_risk_endpoint": phase1_signals["high_risk_endpoint"],
            "high_risk_requires_phase2": high_risk_requires_phase2,
            "phase2_forced_by_risk": phase2_forced_by_risk,
        })
        return result

    async def _process_single_url(self, url: str, vuln_type: str, base_params: Dict[str, Any], quick_mode: bool = False) -> Dict[str, Any]:
        """
        単一 URL を処理するヘルパーメソッド。
        
        Args:
            url: ターゲット URL
            vuln_type: 脆弱性タイプ
            base_params: リクエストパラメータ
            quick_mode: True の場合、軽量モードで実行（ターン数制限あり）
        
        Returns:
            {"findings_count": int, "vuln_type": str, "findings": list}
        """
        findings_count = 0
        findings_list = []
        tested_params: List[str] = []
        reflection_observed = False
        xss_evidence = ""
        blind_correlation: Dict[str, Any] = {}
        unknown_profile: Dict[str, Any] = {}
        probe_sent: Optional[bool] = None
        probe_skipped_reason = ""
        comparison_checks: List[Dict[str, Any]] = []
        auth_context_matrix: Dict[str, Any] = {}
        object_ab_comparison: Dict[str, Any] = {}
        schema_candidate_params: List[str] = []
        single_request_validation = True
        probe_request_raw = ""
        probe_response_raw = ""
        detection_mode = self._resolve_detection_mode(base_params, "phase1")

        try:
            if vuln_type == "sqli":
                sqli_result = await self.run_sqli_hunter(url=url, params=base_params, quick_mode=quick_mode)
                findings_count = sqli_result.get("findings_count", 0)
                tested_params = sanitize_tested_params(sqli_result.get("tested_params", []), excluded_params=self.EXCLUDED_TESTED_PARAMS)
                blind_correlation = normalize_blind_correlation(
                    sqli_result.get("blind_correlation", {}) or {}
                )
                findings_list = self.current_context["findings"][-findings_count:] if findings_count > 0 else []
                if findings_count == 0:
                    # SQLi 発見なしの場合、XSS のみ実行
                    xss_result = await self.run_xss_hunter(url=url, params=base_params, quick_mode=quick_mode)
                    tested_params = sanitize_tested_params(tested_params + xss_result.get("tested_params", []), excluded_params=self.EXCLUDED_TESTED_PARAMS)
                    reflection_observed = bool(xss_result.get("reflection_observed", False))
                    xss_evidence = str(xss_result.get("evidence", "") or "")

            elif vuln_type == "xss":
                xss_result = await self.run_xss_hunter(url=url, params=base_params, quick_mode=quick_mode)
                findings_count = xss_result.get("findings_count", 0)
                tested_params = sanitize_tested_params(xss_result.get("tested_params", []), excluded_params=self.EXCLUDED_TESTED_PARAMS)
                findings_list = self.current_context["findings"][-findings_count:] if findings_count > 0 else []
                reflection_observed = bool(xss_result.get("reflection_observed", False))
                xss_evidence = str(xss_result.get("evidence", "") or "")

            elif vuln_type == "lfi":
                lfi_result = await self.run_lfi_check(url=url, params=base_params)
                findings_count = lfi_result.get("findings_count", 0)
                tested_params = sanitize_tested_params(lfi_result.get("tested_params", []), excluded_params=self.EXCLUDED_TESTED_PARAMS)
                findings_list = self.current_context["findings"][-findings_count:] if findings_count > 0 else []

            elif vuln_type == "ssti":
                ssti_result = await self.run_ssti_hunter(url=url, params=base_params)
                findings_count = ssti_result.get("findings_count", 0)
                tested_params = sanitize_tested_params(ssti_result.get("tested_params", []), excluded_params=self.EXCLUDED_TESTED_PARAMS)
                findings_list = self.current_context["findings"][-findings_count:] if findings_count > 0 else []

            elif vuln_type == "cors":
                cors_result = await self.run_cors_hunter(url=url, params=base_params)
                findings_count = cors_result.get("findings_count", 0)
                tested_params = sanitize_tested_params(cors_result.get("tested_params", []), excluded_params=self.EXCLUDED_TESTED_PARAMS)
                findings_list = self.current_context["findings"][-findings_count:] if findings_count > 0 else []

            elif vuln_type == "crlf":
                crlf_result = await self.run_crlf_hunter(url=url, params=base_params)
                findings_count = crlf_result.get("findings_count", 0)
                tested_params = sanitize_tested_params(crlf_result.get("tested_params", []), excluded_params=self.EXCLUDED_TESTED_PARAMS)
                findings_list = self.current_context["findings"][-findings_count:] if findings_count > 0 else []

            elif vuln_type == "redirect":
                redirect_result = await self.run_open_redirect_check(url=url, params=base_params)
                findings_count = redirect_result.get("findings_count", 0)
                findings_list = self.current_context["findings"][-findings_count:] if findings_count > 0 else []

            elif vuln_type == "cmd_ssrf":
                cmd_result = await self.run_cmd_ssrf_hunter(url=url, params=base_params)
                findings_count = cmd_result.get("findings_count", 0)
                tested_params = sanitize_tested_params(cmd_result.get("tested_params", []), excluded_params=self.EXCLUDED_TESTED_PARAMS)
                blind_correlation = normalize_blind_correlation(
                    cmd_result.get("blind_correlation", {}) or {}
                )
                findings_list = self.current_context["findings"][-findings_count:] if findings_count > 0 else []

            elif vuln_type == "ssrf":
                ssrf_result = await self.run_ssrf_hunter(url=url, params=base_params)
                findings_count = ssrf_result.get("findings_count", 0)
                tested_params = sanitize_tested_params(ssrf_result.get("tested_params", []), excluded_params=self.EXCLUDED_TESTED_PARAMS)
                findings_list = self.current_context["findings"][-findings_count:] if findings_count > 0 else []

            elif vuln_type == "csrf":
                csrf_result = await self._run_csrf_minimal_check(url=url, base_params=base_params)
                findings_count = csrf_result.get("findings_count", 0)
                tested_params = sanitize_tested_params(csrf_result.get("tested_params", []), excluded_params=self.EXCLUDED_TESTED_PARAMS)
                findings_list = self.current_context["findings"][-findings_count:] if findings_count > 0 else []

            elif vuln_type == "api":
                api_result = await self._run_api_minimal_check(url=url, base_params=base_params)
                findings_count = api_result.get("findings_count", 0)
                tested_params = sanitize_tested_params(api_result.get("tested_params", []), excluded_params=self.EXCLUDED_TESTED_PARAMS)

            elif vuln_type == "admin":
                # BizLogicSwarm代替: adminエンドポイント認可バイパス試行
                admin_result = await self.run_admin_check(url=url, params=base_params)
                findings_count = admin_result.get("findings_count", 0)
                tested_params = sanitize_tested_params(admin_result.get("tested_params", []), excluded_params=self.EXCLUDED_TESTED_PARAMS)
                findings_list = self.current_context["findings"][-findings_count:] if findings_count > 0 else []
                blind_correlation = {}  # adminチェックは現状未対応

            else:  # unknown: 仮説駆動で対象 Specialist のみ実行
                unknown_classification_only = self._coerce_bool(
                    (self.current_context.get("params", {}) if isinstance(self.current_context, dict) else {}).get("unknown_classification_only"),
                    default=True,
                )

                if unknown_classification_only:
                    unknown_profile = build_unknown_hypotheses(url, base_params, available_specialists=set(self.specialists.keys()))
                    tested_params = sanitize_tested_params(
                        list(unknown_profile.get("query_keys", [])) + list(unknown_profile.get("form_fields", [])),
                        excluded_params=self.EXCLUDED_TESTED_PARAMS,
                    )
                    idor_candidate = build_unknown_idor_candidate_finding(
                        url=url,
                        tested_params=tested_params,
                        unknown_profile=unknown_profile,
                    source_agent_name=self.name,
                    excluded_params=self.EXCLUDED_TESTED_PARAMS,
                    )
                    if idor_candidate is not None:
                        self.current_context["findings"].append(idor_candidate)
                        findings_count = 1
                        findings_list = [idor_candidate]
                    logger.info(
                        "[%s] unknown classification-only mode: url=%s hypotheses=%s specialists=%s",
                        self.name,
                        url,
                        unknown_profile.get("hypotheses", []),
                        unknown_profile.get("selected_specialists", []),
                    )
                else:
                    unknown_result = await self._run_unknown_hypothesis_scans(
                        url=url,
                        base_params=base_params,
                        quick_mode=quick_mode,
                    )
                    findings_count = unknown_result.get("findings_count", 0)
                    findings_list = unknown_result.get("findings", [])
                    tested_params = sanitize_tested_params(unknown_result.get("tested_params", []), excluded_params=self.EXCLUDED_TESTED_PARAMS)
                    reflection_observed = bool(unknown_result.get("reflection_observed", False))
                    xss_evidence = str(unknown_result.get("xss_evidence", "") or "")
                    blind_correlation = normalize_blind_correlation(
                        unknown_result.get("blind_correlation", {}) or {}
                    )
                    unknown_profile = unknown_result.get("unknown_profile", {}) or {}
                    logger.debug(
                        "[%s] unknown profile for %s => %s",
                        self.name,
                        url,
                        unknown_profile,
                    )
                    if findings_count == 0:
                        idor_candidate = build_unknown_idor_candidate_finding(
                            url=url,
                            tested_params=tested_params,
                            unknown_profile=unknown_profile,
                        source_agent_name=self.name,
                        excluded_params=self.EXCLUDED_TESTED_PARAMS,
                        )
                        if idor_candidate is not None:
                            self.current_context["findings"].append(idor_candidate)
                            findings_count = 1
                            findings_list = [idor_candidate]

            normalize_findings_additional_info(findings_list, tested_params, detection_mode, excluded_params=self.EXCLUDED_TESTED_PARAMS)

            # キャッシュに結果を保存
            cache_key = self._generate_cache_key(url, vuln_type, base_params)
            self._request_cache[cache_key] = build_process_url_cache_entry(
                vuln_type=vuln_type,
                findings_count=findings_count,
                findings=findings_list,
                tested_params=tested_params,
                reflection_observed=reflection_observed,
                xss_evidence=xss_evidence,
                blind_correlation=normalize_blind_correlation(blind_correlation),
                unknown_profile=unknown_profile,
                probe_sent=probe_sent,
                probe_skipped_reason=probe_skipped_reason,
                probe_request_raw=probe_request_raw,
                probe_response_raw=probe_response_raw,
                comparison_checks=comparison_checks,
                auth_context_matrix=auth_context_matrix,
                object_ab_comparison=object_ab_comparison,
                schema_candidate_params=schema_candidate_params,
                single_request_validation=single_request_validation,
                detection_mode=detection_mode,
            )

        except Exception as exc:
            logger.error("[%s] _process_single_url error on %s: %s", self.name, url, exc)
            # エラー時もキャッシュに保存（再試行防止）
            cache_key = self._generate_cache_key(url, vuln_type, base_params)
            self._request_cache[cache_key] = build_process_url_cache_entry(
                vuln_type=vuln_type,
                findings_count=0,
                findings=[],
                tested_params=tested_params,
                reflection_observed=False,
                xss_evidence="",
                blind_correlation=normalize_blind_correlation({}),
                unknown_profile=unknown_profile,
                probe_sent=probe_sent,
                probe_skipped_reason=probe_skipped_reason,
                probe_request_raw=probe_request_raw,
                probe_response_raw=probe_response_raw,
                comparison_checks=comparison_checks,
                auth_context_matrix=auth_context_matrix,
                object_ab_comparison=object_ab_comparison,
                schema_candidate_params=schema_candidate_params,
                single_request_validation=single_request_validation,
                detection_mode=detection_mode,
                error=str(exc),
            )

        return {
            "findings_count": findings_count,
            "vuln_type": vuln_type,
            "findings": findings_list,
            "tested_params": tested_params,
            "reflection_observed": reflection_observed,
            "xss_evidence": xss_evidence,
            "blind_correlation": normalize_blind_correlation(blind_correlation),
            "unknown_profile": unknown_profile,
            "probe_sent": probe_sent,
            "probe_skipped_reason": probe_skipped_reason,
            "probe_request_raw": probe_request_raw,
            "probe_response_raw": probe_response_raw,
            "comparison_checks": comparison_checks,
            "auth_context_matrix": auth_context_matrix,
            "object_ab_comparison": object_ab_comparison,
            "schema_candidate_params": schema_candidate_params,
            "single_request_validation": single_request_validation,
            "detection_mode": detection_mode,
        }

    # --- Tool Implementations ---

    async def analyze_parameters(self, url: str, params: Dict[str, Any] = None, **_kwargs) -> Dict[str, Any]:
        """パラメータ分析ロジック (Heuristics)"""
        parsed = urlparse(url)
        # URL クエリと引数 params の両方を対象にする
        all_params = parse_qs(parsed.query)
        if params:
            for k, v in params.items():
                if k not in all_params:
                    all_params[k] = [v] if not isinstance(v, list) else v

        # 脆弱性が疑われるパラメータ名の抽出
        suspicious = []
        sqli_keywords = ["id", "select", "where", "search", "query", "user"]
        redirect_keywords = ["url", "redirect", "next", "dest", "out", "view", "link"]
        lfi_keywords = ["file", "page", "path", "include", "doc", "template", "lang"]
        xss_keywords = ["q", "s", "search", "query", "name", "id", "msg", "title", "comment", "body", "input", "url"]
        cmd_keywords = ["ip", "host", "ping", "cmd", "exec", "daemon", "process", "run"]
        ssrf_keywords = ["url", "dest", "target", "fetch", "proxy", "uri", "next", "link", "out"]

        # URL パラメータも含めて全てをチェック
        for p in all_params:
            lp = p.lower()
            if any(k in lp for k in sqli_keywords):
                suspicious.append({"param": p, "type": "sqli_candidate"})
            if any(k in lp for k in redirect_keywords):
                suspicious.append({"param": p, "type": "redirect_candidate"})
            if any(k in lp for k in lfi_keywords):
                suspicious.append({"param": p, "type": "lfi_candidate"})
            if any(k in lp for k in xss_keywords):
                suspicious.append({"param": p, "type": "xss_candidate"})
            if any(k in lp for k in cmd_keywords):
                suspicious.append({"param": p, "type": "cmd_candidate"})
            if any(k in lp for k in ssrf_keywords):
                suspicious.append({"param": p, "type": "ssrf_candidate"})

        return {
            "path": parsed.path,
            "found_params": list((params or {}).keys()),
            "suspicious_points": suspicious,
            "recommendation": "Invoke specialists based on suspicious_points type."
        }

    async def run_sqli_hunter(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        if "sqli" not in self.specialists:
            return {"error": "SQLi Specialist not available"}

        logger.info("[%s] Delegating SQLi check to SmartSQLiHunter (quick_mode=%s)", self.name, quick_mode)

        target_task, detection_mode = build_hunter_task(
            url=url,
            specialist_key="sqli",
            task_name="SQLi Check",
            tags=["sqli"],
            params=params,
            kwargs=_kwargs,
            current_context=self.current_context,
            phase2_detection_mode=self._phase2_detection_mode,
            normalize_tool_supplied_params=self._normalize_tool_supplied_params,
            resolve_detection_mode=self._resolve_detection_mode,
        )

        findings = await self.specialists["sqli"].execute_with_retry(target_task, quick_mode=quick_mode) or []
        self.current_context["findings"].extend(findings)
        tested_params = []
        if findings and hasattr(findings[0], "additional_info"):
            tested_params = findings[0].additional_info.get("tested_params", [])
        if not tested_params:
            tested_params = getattr(self.specialists["sqli"], "last_tested_params", []) or []
        blind_correlation = {}
        if findings and hasattr(findings[0], "additional_info"):
            blind_correlation = findings[0].additional_info.get("blind_correlation", {}) or {}
        if not blind_correlation:
            blind_correlation = getattr(self.specialists["sqli"], "last_blind_correlation", {}) or {}
        blind_correlation = normalize_blind_correlation(blind_correlation)
        normalize_findings_additional_info(findings, tested_params, detection_mode, excluded_params=self.EXCLUDED_TESTED_PARAMS)

        # Layer 3: Hunter ツールの出力形式改善 - LLM が誤解しない明確な形式
        if findings:
            finding = findings[0]
            return {
                "success": True,
                "findings_count": len(findings),
                "vulnerability": "SQL Injection",
                "method": finding.evidence.request_method if hasattr(finding, 'evidence') and finding.evidence else "GET",
                "parameter": finding.additional_info.get("parameter", "") if hasattr(finding, 'additional_info') else "",
                "payload": finding.additional_info.get("payload", "") if hasattr(finding, 'additional_info') else "",
                "tested_params": tested_params,
                "blind_correlation": blind_correlation,
                "evidence": finding.description if hasattr(finding, 'description') else str(finding),
                "severity": finding.severity.name if hasattr(finding, 'severity') else "HIGH",
                "info": f"SQL Injection vulnerability confirmed in parameter '{finding.additional_info.get('parameter', 'unknown')}'"
            }
        else:
            return {
                "success": False,
                "findings_count": 0,
                "tested_params": tested_params,
                "blind_correlation": blind_correlation,
                "message": "No SQL Injection vulnerabilities found after comprehensive testing"
            }

    async def run_xss_hunter(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        if "xss" not in self.specialists:
            return {"error": "XSS Specialist not available"}

        logger.info("[%s] Delegating XSS check to SmartXSSHunter (quick_mode=%s)", self.name, quick_mode)

        target_task, detection_mode = build_hunter_task(
            url=url,
            specialist_key="xss",
            task_name="XSS Check",
            tags=["xss"],
            params=params,
            kwargs=_kwargs,
            current_context=self.current_context,
            phase2_detection_mode=self._phase2_detection_mode,
            normalize_tool_supplied_params=self._normalize_tool_supplied_params,
            resolve_detection_mode=self._resolve_detection_mode,
        )

        findings = await self.specialists["xss"].execute_with_retry(target_task, quick_mode=quick_mode) or []
        self.current_context["findings"].extend(findings)
        tested_params = []
        if findings and hasattr(findings[0], "additional_info"):
            tested_params = findings[0].additional_info.get("tested_params", [])
        if not tested_params:
            tested_params = getattr(self.specialists["xss"], "last_tested_params", []) or []
        normalize_findings_additional_info(findings, tested_params, detection_mode, excluded_params=self.EXCLUDED_TESTED_PARAMS)

        # Layer 3: Hunter ツールの出力形式改善 - LLM が誤解しない明確な形式
        if findings:
            finding = findings[0]
            reflection_observed = False
            if hasattr(finding, "additional_info") and isinstance(finding.additional_info, dict):
                reflection_observed = bool(finding.additional_info.get("reflection_observed", False))
            return {
                "success": True,
                "findings_count": len(findings),
                "vulnerability": "XSS",
                "method": finding.evidence.request_method if hasattr(finding, 'evidence') and finding.evidence else "GET",
                "parameter": finding.additional_info.get("parameter", "") if hasattr(finding, 'additional_info') else "",
                "payload": finding.additional_info.get("payload", "") if hasattr(finding, 'additional_info') else "",
                "tested_params": tested_params,
                "evidence": finding.description if hasattr(finding, 'description') else str(finding),
                "reflection_observed": reflection_observed,
                "severity": finding.severity.name if hasattr(finding, 'severity') else "HIGH",
                "info": f"XSS vulnerability confirmed in parameter '{finding.additional_info.get('parameter', 'unknown')}'"
            }
        else:
            specialist_reflection = bool(getattr(self.specialists["xss"], "reflection_observed", False))
            specialist_evidence = str(getattr(self.specialists["xss"], "evidence", "") or "")
            return {
                "success": False,
                "findings_count": 0,
                "tested_params": tested_params,
                "reflection_observed": specialist_reflection,
                "evidence": specialist_evidence,
                "message": "No XSS vulnerabilities found after comprehensive testing"
            }

    async def run_open_redirect_check(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        if "redirect" not in self.specialists:
            return {"error": "Redirect Specialist not available"}

        logger.info("[%s] Delegating Open Redirect check to specialist (quick_mode=%s)", self.name, quick_mode)

        target_task, detection_mode = build_hunter_task(
            url=url,
            specialist_key="redirect",
            task_name="Open Redirect Check",
            tags=["redirect"],
            params=params,
            kwargs=_kwargs,
            current_context=self.current_context,
            phase2_detection_mode=self._phase2_detection_mode,
            normalize_tool_supplied_params=self._normalize_tool_supplied_params,
            resolve_detection_mode=self._resolve_detection_mode,
        )

        findings = await self.specialists["redirect"].execute_with_retry(target_task, quick_mode=quick_mode) or []
        self.current_context["findings"].extend(findings)
        tested_params_from_url = sanitize_tested_params(list(parse_qs(urlparse(url).query).keys()), excluded_params=self.EXCLUDED_TESTED_PARAMS)
        normalize_findings_additional_info(findings, tested_params_from_url, detection_mode, excluded_params=self.EXCLUDED_TESTED_PARAMS)
        return format_simple_hunter_result(
            findings=findings,
            url=url,
            excluded_params=self.EXCLUDED_TESTED_PARAMS,
            vuln_name="Open Redirect",
            severity="MEDIUM",
            not_found_message="No Open Redirect vulnerabilities found",
        )

    async def run_lfi_check(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        if "lfi" not in self.specialists:
            return {"error": "LFI Specialist not available"}

        logger.info("[%s] Delegating LFI check to SmartLFIHunter (quick_mode=%s)", self.name, quick_mode)

        target_task, detection_mode = build_hunter_task(
            url=url,
            specialist_key="lfi",
            task_name="LFI/Traversal Check",
            tags=["lfi"],
            params=params,
            kwargs=_kwargs,
            current_context=self.current_context,
            phase2_detection_mode=self._phase2_detection_mode,
            normalize_tool_supplied_params=self._normalize_tool_supplied_params,
            resolve_detection_mode=self._resolve_detection_mode,
        )

        findings = await self.specialists["lfi"].execute_with_retry(target_task, quick_mode=quick_mode) or []
        self.current_context["findings"].extend(findings)

        tested_params: List[str] = []
        if findings and hasattr(findings[0], "additional_info"):
            tested_params = findings[0].additional_info.get("tested_params", []) or []
        normalize_findings_additional_info(findings, tested_params, detection_mode, excluded_params=self.EXCLUDED_TESTED_PARAMS)
        return format_simple_hunter_result(
            findings=findings,
            url=url,
            excluded_params=self.EXCLUDED_TESTED_PARAMS,
            vuln_name="LFI/Path Traversal",
            severity="HIGH",
            not_found_message="No LFI vulnerabilities found",
        )

    async def run_ssti_hunter(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        if "ssti" not in self.specialists:
            return {"error": "SSTI Specialist not available", "findings_count": 0, "tested_params": []}

        logger.info("[%s] Delegating SSTI check to SmartSSTIHunter", self.name)

        target_task, detection_mode = build_hunter_task(
            url=url,
            specialist_key="ssti",
            task_name="SSTI Check",
            tags=["ssti"],
            params=params,
            kwargs=_kwargs,
            current_context=self.current_context,
            phase2_detection_mode=self._phase2_detection_mode,
            normalize_tool_supplied_params=self._normalize_tool_supplied_params,
            resolve_detection_mode=self._resolve_detection_mode,
        )

        effective_params = target_task.params
        effective_params["use_encoding"] = _kwargs.get("use_encoding", False)
        tech_stack = (
            _kwargs.get("tech_stack")
            or self.current_context.get("tech_stack")
            or self.current_context.get("fingerprint", {}).get("tech_stack", [])
        )
        if tech_stack:
            effective_params["_context"] = {"tech_stack": list(tech_stack)}

        findings = await self.specialists["ssti"].execute(target_task, quick_mode=quick_mode) or []
        self.current_context["findings"].extend(findings)

        tested_params: List[str] = []
        if findings and hasattr(findings[0], "additional_info"):
            tested_params = findings[0].additional_info.get("tested_params", []) or []

        if findings:
            finding = findings[0]
            return {
                "findings_count": len(findings),
                "success": True,
                "vulnerability": "SSTI",
                "parameter": finding.additional_info.get("parameter", "") if hasattr(finding, "additional_info") else "",
                "engine": finding.additional_info.get("engine", "unknown") if hasattr(finding, "additional_info") else "",
                "payload": finding.additional_info.get("payload", "") if hasattr(finding, "additional_info") else "",
                "evidence": finding.description if hasattr(finding, "description") else str(finding),
                "severity": finding.severity.name if hasattr(finding, "severity") else "CRITICAL",
                "tested_params": sanitize_tested_params(tested_params, excluded_params=self.EXCLUDED_TESTED_PARAMS),
                "vulnerable": True,
            }
        else:
            fallback_tested_params = sanitize_tested_params(list(parse_qs(urlparse(url).query).keys()), excluded_params=self.EXCLUDED_TESTED_PARAMS)
            return {
                "findings_count": 0,
                "success": False,
                "vulnerable": False,
                "tested_params": fallback_tested_params,
                "message": "No SSTI vulnerabilities found",
            }

    async def run_cors_hunter(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        if "cors" not in self.specialists:
            return {"error": "CORS Specialist not available", "findings_count": 0, "tested_params": []}

        logger.info("[%s] Delegating CORS check to SmartCORSHunter", self.name)

        if not isinstance(self.current_context, dict):
            self.current_context = {}
        self.current_context.setdefault("findings", [])
        self.current_context.setdefault("auth_headers", {})
        self.current_context.setdefault("params", {})

        target_task, _detection_mode = build_hunter_task(
            url=url,
            specialist_key="cors",
            task_name="CORS Check",
            tags=["cors"],
            params=params,
            kwargs=_kwargs,
            current_context=self.current_context,
            phase2_detection_mode=self._phase2_detection_mode,
            normalize_tool_supplied_params=self._normalize_tool_supplied_params,
            resolve_detection_mode=self._resolve_detection_mode,
        )

        findings = await self.specialists["cors"].execute(target_task, quick_mode=quick_mode) or []
        self.current_context["findings"].extend(findings)
        return format_cors_hunter_result(findings=findings)

    async def run_crlf_hunter(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        """
        SmartCRLFHunter を実行（決定論的 CRLF インジェクションスキャン）

        Args:
            url: ターゲット URL
            params: リクエストパラメータ（_auth 含む）
            quick_mode: 未使用（SmartCRLFHunter は常に決定論的）
        """
        if "crlf" not in self.specialists:
            return {"error": "CRLF Specialist not available", "findings_count": 0, "tested_params": []}

        logger.info("[%s] Delegating CRLF check to SmartCRLFHunter", self.name)
        effective_params = self._normalize_tool_supplied_params(params, _kwargs)

        if not isinstance(self.current_context, dict):
            self.current_context = {}
        self.current_context.setdefault("findings", [])
        self.current_context.setdefault("auth_headers", {})
        self.current_context.setdefault("params", {})

        cookies_str = _kwargs.get("cookies") or self.current_context.get("params", {}).get("cookies", "")
        effective_params["_auth"] = {
            "auth_headers": _kwargs.get("auth_headers", self.current_context.get("auth_headers", {})),
            "cookies": cookies_str,
        }

        target_task = Task(
            id=f"inj_crlf_{id(url)}",
            name="CRLF Check",
            target=url,
            params=effective_params,
            tags=["crlf"],
        )
        findings = await self.specialists["crlf"].execute(target_task, quick_mode=quick_mode) or []
        self.current_context["findings"].extend(findings)

        if findings:
            finding = findings[0]
            return {
                "findings_count": len(findings),
                "success": True,
                "vulnerable": True,
                "vulnerability": "CRLF_INJECTION",
                "injected_header": finding.additional_info.get("injected_header", "") if hasattr(finding, "additional_info") else "",
                "payload": finding.additional_info.get("payload", "") if hasattr(finding, "additional_info") else "",
                "poc_html": finding.additional_info.get("poc_html", "") if hasattr(finding, "additional_info") else "",
                "evidence": finding.description if hasattr(finding, "description") else str(finding),
                "severity": finding.severity.name if hasattr(finding, "severity") else "MEDIUM",
                "tested_params": finding.additional_info.get("tested_params", []) if hasattr(finding, "additional_info") else [],
            }
        else:
            return {
                "findings_count": 0,
                "success": False,
                "vulnerable": False,
                "tested_params": [],
                "message": "No CRLF injection found",
            }

    async def run_graphql_hunter(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        """
        SmartGraphQLHunter を実行（GraphQL Introspection 検出）

        Args:
            url: ターゲット URL
            params: リクエストパラメータ（_auth 含む）
            quick_mode: 未使用（SmartGraphQLHunter は常に決定論的）
        """
        if "graphql" not in self.specialists:
            return {"error": "GraphQL Specialist not available", "findings_count": 0, "tested_params": []}

        logger.info("[%s] Delegating GraphQL check to SmartGraphQLHunter", self.name)

        # current_context未初期化ガード（A-2/A-3発覚）
        if not isinstance(self.current_context, dict):
            self.current_context = {}
        self.current_context.setdefault("findings", [])
        self.current_context.setdefault("auth_headers", {})
        self.current_context.setdefault("params", {})

        effective_params = self._normalize_tool_supplied_params(params, _kwargs)

        cookies_str = _kwargs.get("cookies") or self.current_context.get("params", {}).get("cookies", "")
        effective_params["_auth"] = {
            "auth_headers": _kwargs.get("auth_headers", self.current_context.get("auth_headers", {})),
            "cookies": cookies_str,
        }

        target_task = Task(
            id=f"inj_graphql_{id(url)}",
            name="GraphQL Introspection Check",
            target=url,
            params=effective_params,
            tags=["graphql"],
        )
        findings = await self.specialists["graphql"].execute(target_task, quick_mode=quick_mode) or []
        self.current_context["findings"].extend(findings)

        if findings:
            finding = findings[0]
            return {
                "findings_count": len(findings),
                "success": True,
                "vulnerable": True,
                "vulnerability": "GRAPHQL_INTROSPECTION",
                "introspection_enabled": finding.additional_info.get("introspection_enabled", False) if hasattr(finding, "additional_info") else False,
                "graphiql_enabled": finding.additional_info.get("graphiql_enabled", False) if hasattr(finding, "additional_info") else False,
                "field_suggestions_enabled": finding.additional_info.get("field_suggestions_enabled", False) if hasattr(finding, "additional_info") else False,
                "sensitive_fields": finding.additional_info.get("sensitive_fields", []) if hasattr(finding, "additional_info") else [],
                "poc_html": finding.additional_info.get("poc_html", "") if hasattr(finding, "additional_info") else "",
                "poc_request": finding.additional_info.get("poc_request", "") if hasattr(finding, "additional_info") else "",
                "poc_response": finding.additional_info.get("poc_response", "") if hasattr(finding, "additional_info") else "",
                "evidence": finding.description if hasattr(finding, "description") else str(finding),
                "severity": finding.severity.name if hasattr(finding, "severity") else "MEDIUM",
                "tested_params": finding.additional_info.get("tested_params", []) if hasattr(finding, "additional_info") else [],
            }
        else:
            return {
                "findings_count": 0,
                "success": False,
                "vulnerable": False,
                "tested_params": [],
                "message": "No GraphQL introspection enabled",
            }

    async def run_cmd_ssrf_hunter(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        if "cmd_ssrf" not in self.specialists:
            return {"error": "CmdSSRF Specialist not available"}

        logger.info("[%s] Delegating Cmd/SSRF check to SmartCmdSSRFHunter (quick_mode=%s)", self.name, quick_mode)

        target_task, detection_mode = build_hunter_task(
            url=url,
            specialist_key="cmd_ssrf",
            task_name="Cmd/SSRF Check",
            tags=["cmd_ssrf"],
            params=params,
            kwargs=_kwargs,
            current_context=self.current_context,
            phase2_detection_mode=self._phase2_detection_mode,
            normalize_tool_supplied_params=self._normalize_tool_supplied_params,
            resolve_detection_mode=self._resolve_detection_mode,
        )

        findings = await self.specialists["cmd_ssrf"].execute_with_retry(target_task, quick_mode=quick_mode) or []
        self.current_context["findings"].extend(findings)

        tested_params: List[str] = []
        blind_correlation: Dict[str, Any] = {}
        if findings and hasattr(findings[0], "additional_info"):
            tested_params = findings[0].additional_info.get("tested_params", []) or []
            blind_correlation = findings[0].additional_info.get("blind_correlation", {}) or {}
        if not tested_params:
            tested_params = getattr(self.specialists["cmd_ssrf"], "last_tested_params", []) or []
        if not blind_correlation:
            blind_correlation = getattr(self.specialists["cmd_ssrf"], "last_blind_correlation", {}) or {}
        blind_correlation = normalize_blind_correlation(blind_correlation)
        normalize_findings_additional_info(findings, tested_params, detection_mode, excluded_params=self.EXCLUDED_TESTED_PARAMS)

        # Layer 3: Hunter ツールの出力形式改善
        if findings:
            finding = findings[0]
            return {
                "findings_count": len(findings),
                "success": True,
                "vulnerability": "SSRF/Command Injection",
                "parameter": finding.additional_info.get("parameter", "") if hasattr(finding, 'additional_info') else "",
                "payload": finding.additional_info.get("payload", "") if hasattr(finding, 'additional_info') else "",
                "evidence": finding.description if hasattr(finding, 'description') else str(finding),
                "severity": finding.severity.name if hasattr(finding, 'severity') else "CRITICAL",
                "tested_params": sanitize_tested_params(tested_params, excluded_params=self.EXCLUDED_TESTED_PARAMS),
                "blind_correlation": blind_correlation,
                "info": f"SSRF/Command Injection vulnerability confirmed"
            }
        else:
            fallback_tested_params = tested_params or sanitize_tested_params(list(parse_qs(urlparse(url).query).keys()), excluded_params=self.EXCLUDED_TESTED_PARAMS)
            return {
                "findings_count": 0,
                "success": False,
                "tested_params": fallback_tested_params,
                "blind_correlation": {},
                "message": "No SSRF/Command Injection vulnerabilities found"
            }

    async def run_ssrf_hunter(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        """SmartSSRFHunter を実行する。"""
        if "ssrf" not in self.specialists:
            return {"error": "SSRF Specialist not available"}

        logger.info("[%s] Delegating SSRF check to SmartSSRFHunter (quick_mode=%s)", self.name, quick_mode)

        effective_params = self._normalize_tool_supplied_params(params, _kwargs)
        effective_params["_auth"] = {
            "auth_headers": _kwargs.get("auth_headers", self.current_context.get("auth_headers")),
            "cookies": _kwargs.get("cookies", self.current_context.get("params", {}).get("cookies"))
        }

        target_task = Task(
            id=f"inj_ssrf_{id(url)}",
            name="SSRF Check",
            target=url,
            params=effective_params,
            tags=["ssrf"],
        )
        findings = await self.specialists["ssrf"].execute_with_retry(target_task, quick_mode=quick_mode) or []
        self.current_context["findings"].extend(findings)

        tested_params: List[str] = []
        if findings and hasattr(findings[0], "additional_info"):
            tested_params = findings[0].additional_info.get("tested_params", []) or []
        if not tested_params:
            tested_params = getattr(self.specialists["ssrf"], "last_tested_params", []) or []

        if findings:
            finding = findings[0]
            info = finding.additional_info if hasattr(finding, "additional_info") else {}
            return {
                "findings_count": len(findings),
                "success": True,
                "vulnerable": True,
                "vulnerability": "SSRF",
                "payload_type": info.get("payload_type", ""),
                "payload": info.get("payload", ""),
                "evidence": info.get("evidence", "") or finding.description,
                "response_code": getattr(getattr(finding, "evidence", None), "response_status", 0),
                "matched_variant": info.get("matched_variant", ""),
                "matched_variant_source": info.get("matched_variant_source", ""),
                "severity": finding.severity.name if hasattr(finding, "severity") else "HIGH",
                "tested_params": sanitize_tested_params(tested_params, excluded_params=self.EXCLUDED_TESTED_PARAMS),
                "poc_request": info.get("poc_request", ""),
                "poc_response": info.get("poc_response", ""),
                "poc_html": info.get("poc_html", ""),
            }

        fallback_tested_params = tested_params or sanitize_tested_params(list(parse_qs(urlparse(url).query).keys()), excluded_params=self.EXCLUDED_TESTED_PARAMS)
        return {
            "findings_count": 0,
            "success": False,
            "vulnerable": False,
            "tested_params": fallback_tested_params,
            "message": "No SSRF vulnerabilities found",
        }

    def validate_findings(self, findings: Optional[List] = None) -> tuple:
        """
        Findingの証拠品質を検証（action-first判定ゲート）
        
        Args:
            findings: 検証対象findingリスト（Noneの場合はcurrent_contextから取得）
            
        Returns:
            tuple: (valid_findings, rejected_findings)
            - valid_findings: 採用されたfindingリスト
            - rejected_findings: (finding, ValidationResult)のタプルリスト
        """
        if findings is None:
            findings = self.current_context.get("findings", []) if isinstance(self.current_context, dict) else []

        valid, rejected = validate_manager_findings(
            findings,
            validate_one=self._finding_validator.validate,
        )

        for finding, result in rejected:
            logger.warning(
                "Finding rejected by validator: reason=%s, url=%s",
                result.reason,
                getattr(finding, 'target', 'unknown')
            )

        if rejected:
            logger.info(
                "[%s] Validated findings: %d valid, %d rejected",
                self.name, len(valid), len(rejected)
            )

        return valid, rejected

    def filter_valid_findings(self) -> List:
        """
        current_contextのfindingsを検証し、有効なもののみを返す
        
        Returns:
            List: 検証済み有効findingリスト
        """
        original_count = len(self.current_context.get("findings", []) or []) if isinstance(self.current_context, dict) else 0
        valid = filter_manager_findings(
            self.current_context if isinstance(self.current_context, dict) else {},
            validate_one=self._finding_validator.validate,
        )
        current_findings = self.current_context.get("findings", []) if isinstance(self.current_context, dict) else []
        filtered_count = max(0, len(getattr(self, "current_context", {}).get("findings", []) or []))
        if isinstance(current_findings, list):
            filtered_count = len(current_findings)
        removed_count = max(0, original_count - filtered_count)

        if removed_count and isinstance(self.current_context, dict):
            logger.info(
                "[%s] Filtered %d invalid findings from context",
                self.name, removed_count
            )

        return valid

    async def run_admin_check(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from .manager_internal.admin_check import run_admin_check as _run
        findings_sink: List[Any] = self.current_context.setdefault("findings", []) if isinstance(self.current_context, dict) else []
        return await _run(
            url=url,
            params=params,
            findings_sink=findings_sink,
        )

    async def close(self) -> None:
        """リソース解放"""
        # 実行中のタスクをキャンセル
        self._running = False

        for client in self._ephemeral_network_clients:
            try:
                await client.close()
            except Exception as e:
                logger.debug("Error closing ephemeral network client: %s", e)
        self._ephemeral_network_clients.clear()
        
        for s in self.specialists.values():
            try:
                await s.close()
            except Exception as e:
                logger.error(f"Error closing specialist: {e}")
        
        # Specialists 辞書をクリア
        self.specialists.clear()
        
        await super().close()
