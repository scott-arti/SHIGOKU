"""
Recon Seed Selector (SGK-2026-0303 Step 4)

seed scoring / refine / phase2-on-empty policy helpers.
context / target / settings に依存する scorer と refine policy をここに閉じ込める。
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from src.config import settings


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
