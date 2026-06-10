"""
Recon Seed Target Service

master_conductor.py から抽出した seed/path/target helper 群。
MasterConductor instance への参照を持たず、必要な値（context snapshot /
workspace / project_manager / target / settings）をコンストラクタで受け取る。

内部境界:
- _UrlScopeResolver:  URL 正規化・scope 判定などの stateless helper
- _SeedTargetSelector: seed スコアリング・選別のロジック（settings 参照あり）
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, unquote, urlparse

from src.config import settings
from src.core.domain.model.task import Task

logger = logging.getLogger(__name__)


class _UrlScopeResolver:
    """URL 正規化・ホスト抽出・scope 判定（stateless / settings 非依存）。"""

    @staticmethod
    def normalize_url_candidate(value: str) -> str:
        candidate = str(value or "").strip()
        if not candidate:
            return ""
        candidate = candidate.strip("`'\"")
        candidate = candidate.rstrip("`'\"),.;:]}>")
        if candidate.startswith("http:/") and not candidate.startswith("http://"):
            candidate = candidate.replace("http:/", "http://", 1)
        if candidate.startswith("https:/") and not candidate.startswith("https://"):
            candidate = candidate.replace("https:/", "https://", 1)
        return candidate

    @staticmethod
    def extract_host_candidate(value: str) -> str:
        normalized = _UrlScopeResolver.normalize_url_candidate(str(value or "").strip())
        if not normalized:
            return ""
        if normalized.startswith(("http://", "https://")):
            parsed = urlparse(normalized)
        else:
            parsed = urlparse(f"//{normalized}")
        host = str(parsed.hostname or parsed.netloc or "").strip().lower()
        if not host:
            host = normalized.split("/")[0].split("?")[0].strip().lower()
        if ":" in host:
            host = host.split(":", 1)[0].strip()
        return host

    @staticmethod
    def is_target_url_in_scope(url: str, scope_hosts: list[str]) -> bool:
        if not scope_hosts:
            return False
        host = _UrlScopeResolver.extract_host_candidate(url)
        if not host:
            return False
        return any(host == scope_host or host.endswith(f".{scope_host}") for scope_host in scope_hosts)

    @staticmethod
    def resolve_task_target(task: Task) -> str:
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        candidate_values: list[str] = []
        for raw in (
            getattr(task, "target", ""),
            params.get("target", ""),
            params.get("url", ""),
            params.get("endpoint", ""),
        ):
            normalized = _UrlScopeResolver.normalize_url_candidate(str(raw or ""))
            if normalized:
                candidate_values.append(normalized)
        targets = params.get("targets")
        if isinstance(targets, list):
            for raw in targets:
                normalized = _UrlScopeResolver.normalize_url_candidate(str(raw or ""))
                if normalized:
                    candidate_values.append(normalized)
                    break
        for candidate in candidate_values:
            if candidate.startswith(("http://", "https://")):
                return candidate
        return candidate_values[0] if candidate_values else ""


class _SeedTargetSelector:
    """seed スコアリング・選別ロジック（settings / context 参照あり）。"""

    def __init__(self, context: Any, target: str, settings_: Any) -> None:
        self._context = context
        self._target = target
        self._settings = settings_

    @staticmethod
    def score_csrf_seed_candidate(url: str, category: str, item: dict[str, Any]) -> tuple[int, list[str]]:
        parsed = urlparse(str(url or "").strip())
        if parsed.scheme not in {"http", "https"}:
            return -9999, ["unsupported_scheme"]

        path = str(parsed.path or "")
        path_lower = path.lower()
        query_keys = {k.lower() for k in parse_qs(parsed.query, keep_blank_values=True).keys()}
        try:
            response_status = int(item.get("response_status", 0) or 0)
        except Exception:
            response_status = 0
        if response_status >= 404:
            return -9999, [f"http_status:{response_status}"]
        if "/socket.io/" in path_lower:
            return -9999, ["realtime_transport"]
        if "transport=websocket" in str(parsed.query or "").lower():
            return -9999, ["websocket_transport"]

        static_path_tokens = ("/_next/", "/static/", "/assets/", "/dist/", "/chunks/")
        interaction_keys = {"q", "query", "search", "id", "redirect", "url", "next", "file", "path", "page", "token"}
        candidate_lower = str(url or "").lower()
        malformed_js_fragment = (
            "%27%29,d=f%28%27%3cscript%20type=" in candidate_lower
            or ("%27%29" in candidate_lower and "script%20type=" in candidate_lower and "/static/js/" in path_lower)
        )
        if malformed_js_fragment:
            return -9999, ["malformed_static_payload_url"]
        if any(token in path_lower for token in static_path_tokens) and not (query_keys & interaction_keys):
            return -9999, ["static_asset_path"]
        decoded_path_tokens = [token for token in unquote(path).split("/") if token]
        if decoded_path_tokens and all(not any(ch.isalnum() for ch in token) for token in decoded_path_tokens):
            return -9999, ["non_alnum_path_token"]

        static_ext = (
            ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".json",
        )
        if any(path_lower.endswith(ext) for ext in static_ext):
            return -9999, ["static_asset"]

        category_weight = {
            "auth": 48,
            "basket_order": 44,
            "feedback_review": 40,
            "api_data": 34,
            "api_candidate": 30,
            "id_param": 26,
            "admin": 24,
            "client_route_dom": 18,
            "product_search": 12,
        }
        stateful_tokens = {
            "change", "update", "delete", "remove", "edit", "save", "submit",
            "password", "profile", "address", "email", "account", "user",
            "checkout", "order", "basket", "cart", "payment", "coupon",
            "redeem", "feedback", "complaint", "review",
        }
        sensitive_surface_tokens = {
            "account", "profile", "user", "basket", "order", "checkout", "payment", "admin",
        }

        path_tokens = {token for token in unquote(path_lower).split("/") if token}

        method = str(item.get("method", "GET") or "GET").upper()
        forms = item.get("forms", [])
        form_fields: set[str] = set()
        if isinstance(forms, list):
            for form in forms:
                if not isinstance(form, dict):
                    continue
                for field in form.get("fields", []) or []:
                    if isinstance(field, dict):
                        name = str(field.get("name", "")).strip().lower()
                        if name:
                            form_fields.add(name)
        has_form_tag = bool(item.get("has_form_tag", False) or form_fields)
        body_snippet = str(item.get("response_body_snippet", "") or "").lower()

        score = int(category_weight.get(str(category or "").strip().lower(), 10))
        reasons: list[str] = [f"category:{category}"]

        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            score += 40
            reasons.append(f"method:{method}")
        if has_form_tag:
            score += 24
            reasons.append("form_surface")
        if form_fields & stateful_tokens:
            score += 18
            reasons.append("stateful_form_field")
        if path_tokens & stateful_tokens:
            score += 26
            reasons.append("stateful_path_token")
        if query_keys & stateful_tokens:
            score += 14
            reasons.append("stateful_query_key")
        if any(token in body_snippet for token in stateful_tokens):
            score += 10
            reasons.append("stateful_response_snippet")
        if path_tokens & sensitive_surface_tokens:
            score += 10
            reasons.append("sensitive_surface")
        if "/api/" in path_lower or "/rest/" in path_lower:
            score += 6
            reasons.append("api_surface")

        normalized_path = path_lower.strip()
        if normalized_path in {"", "/"}:
            score -= 80
            reasons.append("root_penalty")
        else:
            score += min(8, len(path_tokens))

        return score, reasons

    @staticmethod
    def score_xss_seed_candidate(url: str, category: str, item: dict[str, Any]) -> tuple[int, list[str]]:
        parsed = urlparse(str(url or "").strip())
        if parsed.scheme not in {"http", "https"}:
            return -9999, ["unsupported_scheme"]

        path = str(parsed.path or "")
        path_lower = path.lower()
        query_keys = {k.lower() for k in parse_qs(parsed.query, keep_blank_values=True).keys()}
        try:
            response_status = int(item.get("response_status", 0) or 0)
        except Exception:
            response_status = 0
        if response_status >= 404:
            return -9999, [f"http_status:{response_status}"]

        static_path_tokens = ("/_next/", "/static/", "/assets/", "/dist/", "/chunks/")
        static_ext = (
            ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".json",
        )
        candidate_lower = str(url or "").lower()
        malformed_js_fragment = (
            "%27%29,d=f%28%27%3cscript%20type=" in candidate_lower
            or ("%27%29" in candidate_lower and "script%20type=" in candidate_lower and "/static/js/" in path_lower)
        )
        if malformed_js_fragment:
            return -9999, ["malformed_static_payload_url"]
        if any(token in path_lower for token in static_path_tokens) and not query_keys:
            return -9999, ["static_asset_path"]
        if any(path_lower.endswith(ext) for ext in static_ext):
            return -9999, ["static_asset"]

        decoded_path_tokens = {token for token in unquote(path_lower).split("/") if token}
        xss_surface_tokens = {
            "search", "query", "q", "comment", "feedback", "review", "message",
            "profile", "chat", "post", "title", "content", "name",
        }
        context_tokens = {"profile", "account", "comment", "review", "chat", "message", "search"}
        query_signal_keys = {"q", "query", "search", "keyword", "term", "name", "comment", "message", "content", "title"}

        method = str(item.get("method", "GET") or "GET").upper()
        forms = item.get("forms", [])
        form_fields: set[str] = set()
        if isinstance(forms, list):
            for form in forms:
                if not isinstance(form, dict):
                    continue
                for field in form.get("fields", []) or []:
                    if isinstance(field, dict):
                        name = str(field.get("name", "")).strip().lower()
                        if name:
                            form_fields.add(name)
        has_form_tag = bool(item.get("has_form_tag", False) or form_fields)
        body_snippet = str(item.get("response_body_snippet", "") or "").lower()

        category_weight = {
            "xss_candidate": 56,
            "feedback_review": 50,
            "product_search": 44,
            "client_route_dom": 40,
            "id_param": 32,
            "api_data": 24,
            "api_candidate": 20,
            "auth": 16,
        }

        score = int(category_weight.get(str(category or "").strip().lower(), 12))
        reasons: list[str] = [f"category:{category}"]

        if query_keys & query_signal_keys:
            score += 26
            reasons.append("query_signal_key")
        if has_form_tag:
            score += 24
            reasons.append("form_surface")
        if form_fields & query_signal_keys:
            score += 18
            reasons.append("xss_form_field")
        if decoded_path_tokens & xss_surface_tokens:
            score += 16
            reasons.append("xss_path_token")
        if decoded_path_tokens & context_tokens:
            score += 10
            reasons.append("context_surface")
        if method in {"POST", "PUT", "PATCH"}:
            score += 8
            reasons.append(f"method:{method}")
        if any(token in body_snippet for token in ("<form", "textarea", "comment", "review", "feedback", "search")):
            score += 8
            reasons.append("response_interaction_hint")
        if any(token in path_lower for token in ("/api/", "/rest/")):
            score += 3
            reasons.append("api_surface")

        normalized_path = path_lower.strip()
        if normalized_path in {"", "/"} and not (query_keys & query_signal_keys):
            score -= 70
            reasons.append("root_penalty")
        else:
            score += min(8, len(decoded_path_tokens))

        return score, reasons

    @staticmethod
    def is_low_value_backfill_target(url: str) -> bool:
        candidates = str(url or "").strip()
        if not candidates:
            return True
        try:
            parsed = urlparse(candidates)
        except Exception:
            return True

        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return True

        path_lower = str(parsed.path or "").lower()
        query_keys = {k.lower() for k in parse_qs(parsed.query, keep_blank_values=True).keys()}

        static_path_tokens = ("/_next/", "/static/", "/assets/", "/dist/", "/chunks/")
        static_extensions = (
            ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot",
        )
        interaction_keys = {"q", "query", "search", "id", "redirect", "url", "next", "file", "path", "page", "token"}

        is_static_asset = any(token in path_lower for token in static_path_tokens) or path_lower.endswith(static_extensions)
        is_root = (parsed.path or "/").strip("/") == ""

        if is_static_asset and not (query_keys & interaction_keys):
            return True
        if is_root and not (query_keys & interaction_keys):
            return True
        return False

    def should_enable_phase2_on_empty_for_backfill(
        self,
        targets: list[str],
        evidence_by_url: dict[str, dict[str, Any]],
    ) -> bool:
        if bool(getattr(self._settings, "phase2_on_empty_force_disable", False)):
            return False
        minimum_score = int(getattr(self._settings, "csrf_backfill_min_score", 20) or 20)
        for target in targets:
            if not _SeedTargetSelector.is_low_value_backfill_target(target):
                return True
            evidence = evidence_by_url.get(target, {}) if isinstance(evidence_by_url, dict) else {}
            if not isinstance(evidence, dict):
                evidence = {}
            method = str(evidence.get("method", "GET") or "GET").upper()
            has_form_tag = bool(evidence.get("has_form_tag", False))
            try:
                score = int(evidence.get("score", 0) or 0)
            except Exception:
                score = 0
            if method in {"POST", "PUT", "PATCH", "DELETE"} or has_form_tag or score >= minimum_score:
                return True
        return False

    @staticmethod
    def apply_phase2_on_empty_policy(enabled: bool) -> bool:
        if bool(getattr(settings, "phase2_on_empty_force_disable", False)):
            return False
        return bool(enabled)


class ReconSeedTargetService:
    """seed / path / target helper の統合サービス。

    MasterConductor instance を保持せず、必要な情報はコンストラクタで受け取る。
    facade 側の wrapper から遅延初期化で利用する前提のため、
    欠損し得る属性には ``getattr(... , None)`` で安全にアクセスする。
    """

    def __init__(
        self,
        *,
        context: Any = None,
        workspace: Any = None,
        project_manager: Any = None,
        target: str = "",
        settings_: Any = None,
    ) -> None:
        self._context = context
        self._workspace = workspace
        self._project_manager = project_manager
        self._target = target
        self._settings = settings_ if settings_ is not None else settings

        self.scope = _UrlScopeResolver()
        self.seed = _SeedTargetSelector(context, target, self._settings)

    # ---- stateless URL/scope helpers (delegate to _UrlScopeResolver) ----

    def normalize_url_candidate(self, value: str) -> str:
        return self.scope.normalize_url_candidate(value)

    def extract_host_candidate(self, value: str) -> str:
        return self.scope.extract_host_candidate(value)

    def is_target_url_in_scope(self, url: str, scope_hosts: list[str]) -> bool:
        return self.scope.is_target_url_in_scope(url, scope_hosts)

    def resolve_task_target(self, task: Task) -> str:
        return self.scope.resolve_task_target(task)

    # ---- context/workspace 依存の path helpers ----

    def get_context_auth_headers(self) -> dict[str, str]:
        target_info = getattr(self._context, "target_info", {})
        if not isinstance(target_info, dict):
            return {}

        headers: dict[str, str] = {}
        raw_headers = target_info.get("auth_headers", {})
        if isinstance(raw_headers, dict):
            for key, value in raw_headers.items():
                header_name = str(key).strip()
                header_value = str(value).strip()
                if header_name and header_value:
                    headers[header_name] = header_value

        raw_cookies = str(target_info.get("cookies", "") or "").strip()
        if raw_cookies:
            headers.setdefault("Cookie", raw_cookies)

        bearer_token = str(target_info.get("bearer_token", "") or "").strip()
        if bearer_token:
            if bearer_token.lower().startswith("bearer "):
                bearer_token = bearer_token[7:].strip()
            if bearer_token:
                headers.setdefault("Authorization", f"Bearer {bearer_token}")

        return headers

    def get_context_cookie_string(self) -> str:
        return str(self.get_context_auth_headers().get("Cookie", "") or "")

    def resolve_recon_file_path(self, file_path: str) -> Optional[Path]:
        candidate = str(file_path or "").strip()
        if not candidate:
            return None

        direct = Path(candidate)
        if direct.exists():
            return direct

        tried: list[Path] = []

        def _append(path: Path) -> None:
            if path in tried:
                return
            tried.append(path)

        _append(direct)

        if not direct.is_absolute():
            _append(Path("workspace") / candidate)

            if self._project_manager and hasattr(self._project_manager, "project_dir"):
                project_dir = Path(self._project_manager.project_dir)
                _append(project_dir / candidate)
                _append(project_dir.parent / candidate)
                _append(project_dir.parent.parent / candidate)

            workspace_obj = self._workspace
            workspace_root = getattr(workspace_obj, "root", None)
            if workspace_root:
                root_path = Path(workspace_root)
                _append(root_path / candidate)
                _append(root_path.parent / candidate)

        for path in tried:
            if path.exists():
                return path
        return None

    def resolve_project_tagged_dir(self) -> Optional[Path]:
        candidates: list[Path] = []

        if self._project_manager and hasattr(self._project_manager, "project_dir"):
            project_dir = Path(self._project_manager.project_dir)
            candidates.append(project_dir / "tagged_urls")
            candidates.append(project_dir / "scans" / "tagged_urls")

        target_info = (
            self._context.target_info
            if isinstance(getattr(self._context, "target_info", {}), dict)
            else {}
        )
        target_url = str(target_info.get("target", "") or "")
        workspace_obj = self._workspace
        workspace_root = getattr(workspace_obj, "root", None)
        if workspace_root and target_url:
            try:
                project_name = urlparse(target_url).netloc
            except Exception:
                project_name = ""
            if project_name:
                root_path = Path(workspace_root)
                candidates.append(root_path / "projects" / project_name / "tagged_urls")

        for candidate in candidates:
            if candidate.exists() and candidate.is_dir():
                return candidate
        return None

    def resolve_in_scope_hosts(self) -> list[str]:
        hosts: list[str] = []
        seen: set[str] = set()

        def _push(raw: str) -> None:
            host = self.scope.extract_host_candidate(raw)
            if not host or host in seen:
                return
            seen.add(host)
            hosts.append(host)

        target_info = getattr(self._context, "target_info", {})
        if isinstance(target_info, dict):
            _push(str(target_info.get("target", "") or ""))
            _push(str(target_info.get("host", "") or ""))
            for raw in target_info.get("in_scope_domains", []) or []:
                _push(str(raw or ""))

        _push(str(self._target or ""))
        for raw in list(getattr(self._context, "discovered_assets", []) or [])[:20]:
            _push(str(raw or ""))

        return hosts

    # ---- seed scorers (delegate to _SeedTargetSelector) ----

    def score_csrf_seed_candidate(
        self, url: str, category: str, item: dict[str, Any]
    ) -> tuple[int, list[str]]:
        return self.seed.score_csrf_seed_candidate(url, category, item)

    def score_xss_seed_candidate(
        self, url: str, category: str, item: dict[str, Any]
    ) -> tuple[int, list[str]]:
        return self.seed.score_xss_seed_candidate(url, category, item)

    def is_low_value_backfill_target(self, url: str) -> bool:
        return self.seed.is_low_value_backfill_target(url)

    def should_enable_phase2_on_empty_for_backfill(
        self,
        targets: list[str],
        evidence_by_url: dict[str, dict[str, Any]],
    ) -> bool:
        return self.seed.should_enable_phase2_on_empty_for_backfill(targets, evidence_by_url)

    def apply_phase2_on_empty_policy(self, enabled: bool) -> bool:
        return self.seed.apply_phase2_on_empty_policy(enabled)

    # ---- seed collectors / refiners ----

    def collect_csrf_seed_targets(
        self,
        recon_results: dict[str, dict],
        budget: int,
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        seed_categories = [
            "auth",
            "basket_order",
            "feedback_review",
            "api_data",
            "api_candidate",
            "xss_candidate",
            "id_param",
            "admin",
            "client_route_dom",
            "product_search",
            "uncategorized",
        ]
        minimum_score = int(getattr(self._settings, "csrf_backfill_min_score", 20) or 20)
        ranked: dict[str, dict[str, Any]] = {}

        candidate_count = 0
        skip_reason_counts: dict[str, int] = {}
        empty_line_count = 0
        json_parse_failure_count = 0
        missing_url_count = 0
        score_filtered_count = 0

        for seed_category in seed_categories:
            entry = recon_results.get(f"tagged_{seed_category}") or recon_results.get(seed_category) or {}
            seed_file = str(entry.get("file", "") or "").strip()
            if not seed_file:
                continue
            tf = self.resolve_recon_file_path(seed_file)
            if tf is None:
                continue
            try:
                for raw_line in tf.read_text(encoding="utf-8").splitlines():
                    line = raw_line.strip()
                    if not line:
                        empty_line_count += 1
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        json_parse_failure_count += 1
                        continue
                    candidate_url = str(obj.get("url", obj.get("target", "")) or "").strip()
                    if not candidate_url:
                        missing_url_count += 1
                        continue
                    candidate_count += 1
                    score, reasons = self.score_csrf_seed_candidate(
                        candidate_url,
                        seed_category,
                        obj if isinstance(obj, dict) else {},
                    )
                    if score <= -999:
                        score_filtered_count += 1
                        for reason in reasons:
                            skip_reason_counts[reason] = skip_reason_counts.get(reason, 0) + 1
                        continue
                    existing = ranked.get(candidate_url)
                    if existing is None or score > int(existing.get("score", -10_000)):
                        ranked[candidate_url] = {
                            "score": score,
                            "reasons": reasons,
                            "category": seed_category,
                            "method": str(obj.get("method", "GET") or "GET").upper(),
                            "has_form_tag": bool(obj.get("has_form_tag", False) or obj.get("forms")),
                        }
            except Exception:
                continue

        ranked_items = sorted(
            ranked.items(),
            key=lambda kv: (
                int(kv[1].get("score", 0)),
                len(urlparse(str(kv[0])).path or ""),
            ),
            reverse=True,
        )
        strong = [item for item in ranked_items if int(item[1].get("score", 0)) >= minimum_score]
        selected = strong[: max(1, budget)]

        if not selected and ranked_items:
            non_root = [item for item in ranked_items if (urlparse(str(item[0])).path or "").strip("/") != ""]
            selected = (non_root or ranked_items)[:1]

        selected_urls = [url for url, _ in selected][: max(1, budget)]
        selected_evidence = {url: evidence for url, evidence in selected}

        logger.info(
            "[MC] CSRF seed-targets: candidates=%d selected=%d budget=%d min_score=%d "
            "empty_lines=%d json_fail=%d missing_url=%d score_filtered=%d skip_reasons=%s",
            candidate_count,
            len(selected_urls),
            budget,
            minimum_score,
            empty_line_count,
            json_parse_failure_count,
            missing_url_count,
            score_filtered_count,
            dict(sorted(skip_reason_counts.items(), key=lambda kv: -kv[1])[:10]),
        )

        return selected_urls, selected_evidence

    def collect_xss_seed_targets(
        self,
        recon_results: dict[str, dict],
        budget: int,
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        seed_categories = [
            "xss_candidate",
            "feedback_review",
            "product_search",
            "client_route_dom",
            "id_param",
            "api_data",
            "api_candidate",
            "auth",
            "uncategorized",
        ]
        minimum_score = 18
        ranked: dict[str, dict[str, Any]] = {}

        candidate_count = 0
        skip_reason_counts: dict[str, int] = {}
        empty_line_count = 0
        json_parse_failure_count = 0
        missing_url_count = 0
        score_filtered_count = 0

        for seed_category in seed_categories:
            entry = recon_results.get(f"tagged_{seed_category}") or recon_results.get(seed_category) or {}
            seed_file = str(entry.get("file", "") or "").strip()
            if not seed_file:
                continue
            tf = self.resolve_recon_file_path(seed_file)
            if tf is None:
                continue
            try:
                for raw_line in tf.read_text(encoding="utf-8").splitlines():
                    line = raw_line.strip()
                    if not line:
                        empty_line_count += 1
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        json_parse_failure_count += 1
                        continue
                    candidate_url = str(obj.get("url", obj.get("target", "")) or "").strip()
                    if not candidate_url:
                        missing_url_count += 1
                        continue
                    candidate_count += 1
                    score, reasons = self.score_xss_seed_candidate(
                        candidate_url,
                        seed_category,
                        obj if isinstance(obj, dict) else {},
                    )
                    if score <= -999:
                        score_filtered_count += 1
                        for reason in reasons:
                            skip_reason_counts[reason] = skip_reason_counts.get(reason, 0) + 1
                        continue
                    existing = ranked.get(candidate_url)
                    if existing is None or score > int(existing.get("score", -10_000)):
                        ranked[candidate_url] = {
                            "score": score,
                            "reasons": reasons,
                            "category": seed_category,
                            "method": str(obj.get("method", "GET") or "GET").upper(),
                            "has_form_tag": bool(obj.get("has_form_tag", False) or obj.get("forms")),
                        }
            except Exception:
                continue

        ranked_items = sorted(
            ranked.items(),
            key=lambda kv: (
                int(kv[1].get("score", 0)),
                len(urlparse(str(kv[0])).path or ""),
            ),
            reverse=True,
        )
        strong = [item for item in ranked_items if int(item[1].get("score", 0)) >= minimum_score]
        selected = strong[: max(1, budget)]

        if not selected and ranked_items:
            non_root = [item for item in ranked_items if (urlparse(str(item[0])).path or "").strip("/") != ""]
            selected = (non_root or ranked_items)[:1]

        selected_urls = [url for url, _ in selected][: max(1, budget)]
        selected_evidence = {url: evidence for url, evidence in selected}

        logger.info(
            "[MC] XSS seed-targets: candidates=%d selected=%d budget=%d min_score=%d "
            "empty_lines=%d json_fail=%d missing_url=%d score_filtered=%d skip_reasons=%s",
            candidate_count,
            len(selected_urls),
            budget,
            minimum_score,
            empty_line_count,
            json_parse_failure_count,
            missing_url_count,
            score_filtered_count,
            dict(sorted(skip_reason_counts.items(), key=lambda kv: -kv[1])[:10]),
        )

        return selected_urls, selected_evidence

    def collect_history_replay_targets(
        self,
        category: str,
        *,
        limit: int,
        file_window: int,
        exclude_urls: Optional[set[str]] = None,
    ) -> list[str]:
        normalized_category = str(category or "").strip().lower()
        if not normalized_category:
            return []
        max_targets = max(0, int(limit or 0))
        if max_targets <= 0:
            return []

        tagged_dir = self.resolve_project_tagged_dir()
        if tagged_dir is None:
            return []

        file_limit = max(1, int(file_window or 1))
        scope_hosts = self.resolve_in_scope_hosts()
        excluded = {str(url or "").strip() for url in (exclude_urls or set()) if str(url or "").strip()}
        collected: list[str] = []
        seen: set[str] = set(excluded)

        candidate_count = 0
        scope_filtered_count = 0
        compatibility_filtered_count = 0
        duplicate_count = 0
        invalid_url_count = 0
        json_parse_failure_count = 0

        def _is_history_replay_candidate_compatible(url: str, item: dict[str, Any]) -> bool:
            try:
                response_status = int(item.get("response_status", 0) or 0)
            except Exception:
                response_status = 0
            if response_status >= 400:
                return False

            parsed = urlparse(str(url or "").strip())
            decoded_path = unquote(parsed.path or "")
            path_tokens = {token for token in decoded_path.lower().strip("/").split("/") if token}
            query_keys = {k.lower() for k in parse_qs(parsed.query, keep_blank_values=True).keys()}

            if normalized_category == "auth":
                auth_tokens = {
                    "auth", "login", "signin", "session", "token", "account",
                    "profile", "settings", "security", "password", "mfa", "2fa", "me",
                }
                auth_query_tokens = {"token", "session", "otp", "code", "mfa", "next", "redirect", "return"}
                api_tokens = {
                    "api", "rest", "graphql", "rpc", "chatbot", "genai", "assistant",
                    "prompt", "completion", "message", "messages", "history", "state",
                }
                api_query_tokens = {"format", "fields", "include", "expand", "limit", "offset"}

                auth_hits = len(path_tokens & auth_tokens) + len(query_keys & auth_query_tokens)
                api_hits = len(path_tokens & api_tokens) + len(query_keys & api_query_tokens)

                if api_hits >= 2 and auth_hits <= 1:
                    return False

            if normalized_category == "admin":
                admin_tokens = {
                    "admin", "manage", "management", "moderator", "staff", "role",
                    "permission", "tenant", "organization", "org", "account",
                    "security", "settings", "user", "users",
                }
                admin_query_tokens = {
                    "role", "permission", "user", "account", "tenant", "org", "id",
                }
                if not ((path_tokens & admin_tokens) or (query_keys & admin_query_tokens)):
                    return False

            return True

        replay_source_categories: list[str] = [normalized_category]
        replay_aliases: dict[str, list[str]] = {
            "api_endpoint": ["api_candidate", "api_data"],
            "api_candidate": ["api_data", "api_endpoint"],
            "admin": ["auth", "api_candidate", "api_endpoint"],
        }
        for alias_category in replay_aliases.get(normalized_category, []):
            alias_norm = str(alias_category or "").strip().lower()
            if alias_norm and alias_norm not in replay_source_categories:
                replay_source_categories.append(alias_norm)

        files: list[Path] = []
        for source_category in replay_source_categories:
            patterns = [
                f"*tagged_{source_category}.jsonl",
                f"*tagged_uncategorized_promoted_{source_category}.jsonl",
            ]
            for pattern in patterns:
                for path in tagged_dir.glob(pattern):
                    if path not in files:
                        files.append(path)

        files = sorted(
            files,
            key=lambda p: (p.name, float(p.stat().st_mtime) if p.exists() else 0.0),
            reverse=True,
        )[:file_limit]

        for path in files:
            try:
                for raw_line in path.read_text(encoding="utf-8").splitlines():
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        json_parse_failure_count += 1
                        continue
                    raw_url = str(obj.get("url", obj.get("target", "")) or "").strip()
                    url = self.scope.normalize_url_candidate(raw_url)
                    if not url or not url.startswith(("http://", "https://")):
                        invalid_url_count += 1
                        continue
                    if scope_hosts and not self.scope.is_target_url_in_scope(url, scope_hosts):
                        scope_filtered_count += 1
                        continue
                    candidate_count += 1
                    if not _is_history_replay_candidate_compatible(url, obj if isinstance(obj, dict) else {}):
                        compatibility_filtered_count += 1
                        continue
                    if url in seen:
                        duplicate_count += 1
                        continue
                    seen.add(url)
                    collected.append(url)
                    if len(collected) >= max_targets:
                        logger.info(
                            "[MC] history-replay %s: candidates=%d selected=%d "
                            "scope_filtered=%d compat_filtered=%d duplicate=%d "
                            "invalid_url=%d json_fail=%d file_limit=%d",
                            normalized_category,
                            candidate_count,
                            len(collected),
                            scope_filtered_count,
                            compatibility_filtered_count,
                            duplicate_count,
                            invalid_url_count,
                            json_parse_failure_count,
                            file_limit,
                        )
                        return collected
            except Exception:
                continue

        logger.info(
            "[MC] history-replay %s: candidates=%d selected=%d "
            "scope_filtered=%d compat_filtered=%d duplicate=%d "
            "invalid_url=%d json_fail=%d file_limit=%d",
            normalized_category,
            candidate_count,
            len(collected),
            scope_filtered_count,
            compatibility_filtered_count,
            duplicate_count,
            invalid_url_count,
            json_parse_failure_count,
            file_limit,
        )
        return collected

    def refine_backfill_seed_targets(
        self,
        targets: list[str],
        evidence_by_url: dict[str, dict[str, Any]],
        budget: int,
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        max_targets = max(1, int(budget or 1))
        normalized_evidence: dict[str, dict[str, Any]] = {}
        if isinstance(evidence_by_url, dict):
            for url, evidence in evidence_by_url.items():
                key = str(url or "").strip()
                if not key:
                    continue
                if isinstance(evidence, dict):
                    normalized_evidence[key] = evidence
                else:
                    normalized_evidence[key] = {}

        deduped_targets: list[str] = []
        seen: set[str] = set()
        for raw in targets:
            candidate = str(raw or "").strip()
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            deduped_targets.append(candidate)

        input_count = len(deduped_targets)
        low_value_filtered = input_count - len([url for url in deduped_targets if not self.is_low_value_backfill_target(url)])
        discovered_topup = 0

        refined: list[str] = [
            url for url in deduped_targets
            if not self.is_low_value_backfill_target(url)
        ][:max_targets]

        if len(refined) < max_targets:
            for asset in list(getattr(self._context, "discovered_assets", []) or []):
                candidate = str(asset or "").strip()
                if not candidate or candidate in seen:
                    continue
                if self.is_low_value_backfill_target(candidate):
                    continue
                seen.add(candidate)
                refined.append(candidate)
                discovered_topup += 1
                normalized_evidence.setdefault(
                    candidate,
                    {
                        "score": -1,
                        "reasons": ["discovered_asset_topup"],
                        "category": "coverage_backfill",
                        "method": "GET",
                        "has_form_tag": False,
                    },
                )
                if len(refined) >= max_targets:
                    break

        fallback_used = False
        if not refined:
            fallback_target = ""
            if isinstance(getattr(self._context, "target_info", {}), dict):
                fallback_target = str(self._context.target_info.get("target", "") or "")
            if not fallback_target:
                fallback_target = str(self._target or "")
            fallback_target = fallback_target.strip()
            if fallback_target:
                refined = [fallback_target]
                fallback_used = True
                normalized_evidence.setdefault(
                    fallback_target,
                    {
                        "score": -1,
                        "reasons": ["target_fallback_only"],
                        "category": "coverage_backfill",
                        "method": "GET",
                        "has_form_tag": False,
                    },
                )
            elif deduped_targets:
                refined = deduped_targets[:1]

        refined_evidence: dict[str, dict[str, Any]] = {}
        for url in refined:
            refined_evidence[url] = normalized_evidence.get(
                url,
                {
                    "score": -1,
                    "reasons": ["target_fallback_only"],
                    "category": "coverage_backfill",
                    "method": "GET",
                    "has_form_tag": False,
                },
            )

        logger.info(
            "[MC] refine-backfill: input=%d low_value_filtered=%d "
            "discovered_topup=%d fallback=%s selected=%d budget=%d",
            input_count,
            low_value_filtered,
            discovered_topup,
            fallback_used,
            len(refined),
            max_targets,
        )
        return refined, refined_evidence

    # ---- scenario seed helpers ----

    def collect_scenario_probe_seed_targets(
        self,
        recon_results: dict[str, dict],
        budget: int = 2,
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        budget = max(1, int(budget or 2))
        seeds, evidence = self.collect_csrf_seed_targets(
            recon_results=recon_results,
            budget=max(3, budget),
        )
        seeds, evidence = self.refine_backfill_seed_targets(
            targets=seeds,
            evidence_by_url=evidence,
            budget=budget,
        )

        normalized_targets: list[str] = []
        for raw in seeds:
            candidate = str(raw or "").strip()
            if not candidate or candidate in normalized_targets:
                continue
            normalized_targets.append(candidate)

        discovered_asset_fallback_count = 0
        if len(normalized_targets) < budget:
            for raw in list(getattr(self._context, "discovered_assets", []) or []):
                candidate = str(raw or "").strip()
                if not candidate.startswith(("http://", "https://")):
                    continue
                if candidate in normalized_targets:
                    continue
                normalized_targets.append(candidate)
                discovered_asset_fallback_count += 1
                evidence.setdefault(
                    candidate,
                    {
                        "score": -1,
                        "reasons": ["discovered_asset_fallback"],
                        "category": "scenario_probe",
                        "method": "GET",
                        "has_form_tag": False,
                    },
                )
                if len(normalized_targets) >= budget:
                    break

        fallback_used = False
        if not normalized_targets:
            fallback_target = ""
            if isinstance(getattr(self._context, "target_info", {}), dict):
                fallback_target = str(self._context.target_info.get("target", "") or "")
            if not fallback_target:
                fallback_target = str(self._target or "")
            fallback_target = fallback_target.strip()
            if fallback_target:
                normalized_targets = [fallback_target]
                fallback_used = True
                evidence = {
                    fallback_target: {
                        "score": -1,
                        "reasons": ["target_fallback_only"],
                        "category": "scenario_probe",
                        "method": "GET",
                        "has_form_tag": False,
                    }
                }

        result_targets = normalized_targets[:budget]
        logger.info(
            "[MC] scenario-probe-seed: seed_count=%d discovered_fallback=%d "
            "target_fallback=%s selected=%d budget=%d",
            len(seeds),
            discovered_asset_fallback_count,
            fallback_used,
            len(result_targets),
            budget,
        )
        return result_targets, evidence

    def select_targets_for_scenario_probe(
        self,
        *,
        scenario_id: str,
        targets: list[str],
        evidence_by_url: dict[str, dict[str, Any]],
        budget: int,
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        normalized_scenario_id = str(scenario_id or "").strip().lower().replace("-", "_")
        max_targets = max(1, int(budget or 1))
        normalized_targets = [str(url or "").strip() for url in targets if str(url or "").strip()]
        if normalized_scenario_id != "scn_10_semantic_business_logic":
            selected_targets = normalized_targets[:max_targets]
        else:
            workflow_categories = {"basket_order", "feedback_review", "product_search", "csrf_candidate"}
            workflow_keywords = (
                "checkout",
                "cart",
                "basket",
                "order",
                "payment",
                "refund",
                "invoice",
                "purchase",
                "subscription",
                "plan",
                "billing",
                "review",
                "feedback",
                "coupon",
                "discount",
            )

            workflow_targets: list[str] = []
            non_auth_targets: list[str] = []
            for url in normalized_targets:
                evidence = evidence_by_url.get(url, {}) if isinstance(evidence_by_url, dict) else {}
                if not isinstance(evidence, dict):
                    evidence = {}
                category = str(evidence.get("category", "") or "").strip().lower()
                path = (urlparse(url).path or "").strip().lower()
                is_workflow_like = category in workflow_categories or any(
                    keyword in path for keyword in workflow_keywords
                )
                is_auth_like = category == "auth" or any(
                    token in path for token in ("/account", "/password", "/login", "/register")
                )
                if is_workflow_like and url not in workflow_targets:
                    workflow_targets.append(url)
                if not is_auth_like and url not in non_auth_targets:
                    non_auth_targets.append(url)

            if workflow_targets:
                selected_targets = workflow_targets[:max_targets]
            elif non_auth_targets:
                selected_targets = non_auth_targets[:max_targets]
            else:
                selected_targets = normalized_targets[:1]

        selected_evidence = {
            url: (
                evidence_by_url.get(url, {})
                if isinstance(evidence_by_url, dict) and isinstance(evidence_by_url.get(url, {}), dict)
                else {
                    "score": -1,
                    "reasons": ["scenario_probe_default_target"],
                    "category": "scenario_probe",
                    "method": "GET",
                    "has_form_tag": False,
                }
            )
            for url in selected_targets
        }
        return selected_targets, selected_evidence
