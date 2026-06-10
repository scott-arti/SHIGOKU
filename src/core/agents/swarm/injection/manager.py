import asyncio
import json
import logging
import random
import re
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from src.core.agents.swarm.base_manager import BaseManagerAgent
from src.core.agents.swarm.base import Specialist, Task
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
    build_timeout_cause_key,
    cap_phase2_budget,
    is_high_risk_endpoint,
    is_lane2_score_eligible,
    resolve_per_url_timeout,
    resolve_risk_force_allowlist,
    should_auto_early_return,
    should_force_phase2_by_risk,
    ssrf_reachability_gate,
)
from src.core.agents.swarm.injection.manager_internal.builtin_probes import (
    run_csrf_minimal_check,
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
    run_cmd_ssrf_hunter_runner,
    run_cors_hunter_runner,
    run_crlf_hunter_runner,
    run_graphql_hunter_runner,
    run_lfi_check_runner,
    run_open_redirect_check_runner,
    run_sqli_hunter_runner,
    run_ssrf_hunter_runner,
    run_ssti_hunter_runner,
    run_xss_hunter_runner,
)
from src.core.agents.swarm.injection.manager_internal.process_url_dispatcher import (
    dispatch_vuln_type_branch,
    process_unknown_classification_only,
)
from src.core.agents.swarm.injection.manager_internal.unknown_hypotheses import (
    build_unknown_hypotheses,
    build_unknown_idor_candidate_finding,
)
from src.core.agents.swarm.injection.manager_internal.specialist_factory import (
    create_specialists,
)
from src.core.agents.swarm.injection.manager_internal.tool_registration import (
    register_initial_tools as _register_initial_tools_impl,
    register_manager_tool_scans,
)
from src.core.agents.swarm.injection.manager_internal.unknown_scan_runner import (
    run_unknown_hypothesis_scans,
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
        self._initialize_specialists()
        self._phase2_detection_mode: str = "phase2"
        self._ephemeral_network_clients: List[Any] = []
        self._finding_validator = FindingValidator()
        self._register_manager_tools()

    def _register_manager_tools(self):
        register_manager_tool_scans(
            register_tool=self.register_tool,
            specialists=self.specialists,
            run_sqli_hunter=self.run_sqli_hunter,
            run_xss_hunter=self.run_xss_hunter,
            run_lfi_check=self.run_lfi_check,
            run_open_redirect_check=self.run_open_redirect_check,
            run_cmd_ssrf_hunter=self.run_cmd_ssrf_hunter,
            run_ssrf_hunter=self.run_ssrf_hunter,
            run_ssti_hunter=self.run_ssti_hunter,
            run_cors_hunter=self.run_cors_hunter,
            run_crlf_hunter=self.run_crlf_hunter,
        )
        self._register_initial_tools()
        self._request_cache: Dict[str, Dict[str, Any]] = {}

    def _initialize_specialists(self) -> None:
        self.specialists: Dict[str, Specialist] = create_specialists(config=self.config)

    def _register_initial_tools(self) -> None:
        _register_initial_tools_impl(
            register_tool=self.register_tool,
            specialists=self.specialists,
            analyze_parameters=self.analyze_parameters,
            run_sqli_hunter=self.run_sqli_hunter,
            run_open_redirect_check=self.run_open_redirect_check,
            run_lfi_check=self.run_lfi_check,
            run_xss_hunter=self.run_xss_hunter,
            run_cmd_ssrf_hunter=self.run_cmd_ssrf_hunter,
            run_ssrf_hunter=self.run_ssrf_hunter,
            run_graphql_hunter=self.run_graphql_hunter,
        )

    # --- URL の「タイプ」判定ヘルパー ---

    @staticmethod
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
        return await run_unknown_hypothesis_scans(
            url=url,
            base_params=base_params,
            quick_mode=quick_mode,
            callables={
                "sqli": self.run_sqli_hunter,
                "xss": self.run_xss_hunter,
                "lfi": self.run_lfi_check,
                "ssti": self.run_ssti_hunter,
                "cors": self.run_cors_hunter,
                "crlf": self.run_crlf_hunter,
                "cmd_ssrf": self.run_cmd_ssrf_hunter,
                "ssrf": self.run_ssrf_hunter,
                "graphql": self.run_graphql_hunter,
            },
            specialists=self.specialists,
            current_context=self.current_context,
            excluded_params=self.EXCLUDED_TESTED_PARAMS,
            agent_name=self.name,
        )

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
        if is_high_risk_endpoint(url):
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

        high_risk_endpoint = any(is_high_risk_endpoint(url) for url in urls_to_evaluate)

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
        """軽量 API チェック（未認証アクセス候補、過剰メソッド露出候補）。

        実装本体は manager_internal.api_probe_runner.run_api_minimal_check へ移設。
        """
        from src.core.agents.swarm.injection.manager_internal.api_probe_runner import (
            run_api_minimal_check,
        )
        from src.core.agents.swarm.injection.manager_internal.models import (
            ApiProbeDependencies,
        )

        request_client = self._resolve_request_client()
        findings_sink = self.current_context.setdefault("findings", [])

        deps: ApiProbeDependencies = {
            "request_client": request_client,
            "findings_sink": findings_sink,
            "source_agent_name": self.name,
            "excluded_params": self.EXCLUDED_TESTED_PARAMS,
            "looks_like_login_page": self._looks_like_login_page,
            "resolve_detection_mode": self._resolve_detection_mode,
            "current_context": self.current_context,
        }

        return await run_api_minimal_check(
            url=url,
            base_params=base_params,
            deps=deps,
        )

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

                    reachable, gate_reason = ssrf_reachability_gate(target_url, base_params)
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
                timeout_cause_key = build_timeout_cause_key(target_url, vuln_type)
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
            branch_result = await dispatch_vuln_type_branch(
                url=url,
                vuln_type=vuln_type,
                base_params=base_params,
                quick_mode=quick_mode,
                detection_mode=detection_mode,
                callables={
                    "sqli": self.run_sqli_hunter,
                    "xss": self.run_xss_hunter,
                    "lfi": self.run_lfi_check,
                    "ssti": self.run_ssti_hunter,
                    "cors": self.run_cors_hunter,
                    "crlf": self.run_crlf_hunter,
                    "redirect": self.run_open_redirect_check,
                    "cmd_ssrf": self.run_cmd_ssrf_hunter,
                    "ssrf": self.run_ssrf_hunter,
                    "csrf": self._run_csrf_minimal_check,
                    "api": self._run_api_minimal_check,
                    "admin": self.run_admin_check,
                    "unknown_scans": self._run_unknown_hypothesis_scans,
                },
                current_context=self.current_context,
                specialists=self.specialists,
                excluded_params=self.EXCLUDED_TESTED_PARAMS,
                agent_name=self.name,
            )
            findings_count = branch_result["findings_count"]
            findings_list = branch_result["findings_list"]
            tested_params = branch_result["tested_params"]
            reflection_observed = branch_result.get("reflection_observed", False)
            xss_evidence = branch_result.get("xss_evidence", "")
            blind_correlation = branch_result.get("blind_correlation", {})
            unknown_profile = branch_result.get("unknown_profile", {})

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
            cache_key = self._generate_cache_key(url, vuln_type, base_params)
            self._request_cache[cache_key] = build_process_url_cache_entry(
                vuln_type=vuln_type,
                findings_count=0,
                findings=[],
                tested_params=[],
                reflection_observed=False,
                xss_evidence="",
                blind_correlation=normalize_blind_correlation({}),
                unknown_profile={},
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
            findings_count = 0
            findings_list = []
            tested_params = []
            reflection_observed = False
            xss_evidence = ""
            blind_correlation = {}
            unknown_profile = {}

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
        return await run_sqli_hunter_runner(
            deps={
                "specialists": self.specialists,
                "current_context": self.current_context,
                "phase2_detection_mode": self._phase2_detection_mode,
                "excluded_params": self.EXCLUDED_TESTED_PARAMS,
                "normalize_tool_supplied_params": self._normalize_tool_supplied_params,
                "resolve_detection_mode": self._resolve_detection_mode,
                "agent_name": self.name,
            },
            url=url, params=params, quick_mode=quick_mode, **_kwargs,
        )

    async def run_xss_hunter(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        return await run_xss_hunter_runner(
            deps={
                "specialists": self.specialists,
                "current_context": self.current_context,
                "phase2_detection_mode": self._phase2_detection_mode,
                "excluded_params": self.EXCLUDED_TESTED_PARAMS,
                "normalize_tool_supplied_params": self._normalize_tool_supplied_params,
                "resolve_detection_mode": self._resolve_detection_mode,
                "agent_name": self.name,
            },
            url=url, params=params, quick_mode=quick_mode, **_kwargs,
        )

    async def run_open_redirect_check(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        return await run_open_redirect_check_runner(
            deps={
                "specialists": self.specialists,
                "current_context": self.current_context,
                "phase2_detection_mode": self._phase2_detection_mode,
                "excluded_params": self.EXCLUDED_TESTED_PARAMS,
                "normalize_tool_supplied_params": self._normalize_tool_supplied_params,
                "resolve_detection_mode": self._resolve_detection_mode,
                "agent_name": self.name,
            },
            url=url, params=params, quick_mode=quick_mode, **_kwargs,
        )

    async def run_lfi_check(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        return await run_lfi_check_runner(
            deps={
                "specialists": self.specialists,
                "current_context": self.current_context,
                "phase2_detection_mode": self._phase2_detection_mode,
                "excluded_params": self.EXCLUDED_TESTED_PARAMS,
                "normalize_tool_supplied_params": self._normalize_tool_supplied_params,
                "resolve_detection_mode": self._resolve_detection_mode,
                "agent_name": self.name,
            },
            url=url, params=params, quick_mode=quick_mode, **_kwargs,
        )

    async def run_ssti_hunter(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        return await run_ssti_hunter_runner(
            deps={
                "specialists": self.specialists,
                "current_context": self.current_context,
                "phase2_detection_mode": self._phase2_detection_mode,
                "excluded_params": self.EXCLUDED_TESTED_PARAMS,
                "normalize_tool_supplied_params": self._normalize_tool_supplied_params,
                "resolve_detection_mode": self._resolve_detection_mode,
                "agent_name": self.name,
            },
            url=url, params=params, quick_mode=quick_mode, **_kwargs,
        )

    async def run_cors_hunter(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        if not isinstance(self.current_context, dict):
            self.current_context = {}
        self.current_context.setdefault("findings", [])
        self.current_context.setdefault("auth_headers", {})
        self.current_context.setdefault("params", {})
        return await run_cors_hunter_runner(
            deps={
                "specialists": self.specialists,
                "current_context": self.current_context,
                "phase2_detection_mode": self._phase2_detection_mode,
                "excluded_params": self.EXCLUDED_TESTED_PARAMS,
                "normalize_tool_supplied_params": self._normalize_tool_supplied_params,
                "resolve_detection_mode": self._resolve_detection_mode,
                "agent_name": self.name,
            },
            url=url, params=params, quick_mode=quick_mode, **_kwargs,
        )

    async def run_crlf_hunter(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        if not isinstance(self.current_context, dict):
            self.current_context = {}
        self.current_context.setdefault("findings", [])
        self.current_context.setdefault("auth_headers", {})
        self.current_context.setdefault("params", {})
        return await run_crlf_hunter_runner(
            deps={
                "specialists": self.specialists,
                "current_context": self.current_context,
                "phase2_detection_mode": self._phase2_detection_mode,
                "excluded_params": self.EXCLUDED_TESTED_PARAMS,
                "normalize_tool_supplied_params": self._normalize_tool_supplied_params,
                "resolve_detection_mode": self._resolve_detection_mode,
                "agent_name": self.name,
            },
            url=url, params=params, quick_mode=quick_mode, **_kwargs,
        )

    async def run_graphql_hunter(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        if not isinstance(self.current_context, dict):
            self.current_context = {}
        self.current_context.setdefault("findings", [])
        self.current_context.setdefault("auth_headers", {})
        self.current_context.setdefault("params", {})
        return await run_graphql_hunter_runner(
            deps={
                "specialists": self.specialists,
                "current_context": self.current_context,
                "phase2_detection_mode": self._phase2_detection_mode,
                "excluded_params": self.EXCLUDED_TESTED_PARAMS,
                "normalize_tool_supplied_params": self._normalize_tool_supplied_params,
                "resolve_detection_mode": self._resolve_detection_mode,
                "agent_name": self.name,
            },
            url=url, params=params, quick_mode=quick_mode, **_kwargs,
        )

    async def run_cmd_ssrf_hunter(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        return await run_cmd_ssrf_hunter_runner(
            deps={
                "specialists": self.specialists,
                "current_context": self.current_context,
                "phase2_detection_mode": self._phase2_detection_mode,
                "excluded_params": self.EXCLUDED_TESTED_PARAMS,
                "normalize_tool_supplied_params": self._normalize_tool_supplied_params,
                "resolve_detection_mode": self._resolve_detection_mode,
                "agent_name": self.name,
            },
            url=url, params=params, quick_mode=quick_mode, **_kwargs,
        )

    async def run_ssrf_hunter(self, url: str, params: Dict[str, Any] = None, quick_mode: bool = False, **_kwargs) -> Dict[str, Any]:
        return await run_ssrf_hunter_runner(
            deps={
                "specialists": self.specialists,
                "current_context": self.current_context,
                "phase2_detection_mode": self._phase2_detection_mode,
                "excluded_params": self.EXCLUDED_TESTED_PARAMS,
                "normalize_tool_supplied_params": self._normalize_tool_supplied_params,
                "resolve_detection_mode": self._resolve_detection_mode,
                "agent_name": self.name,
            },
            url=url, params=params, quick_mode=quick_mode, **_kwargs,
        )

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
