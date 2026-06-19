"""
Recon Seed Replay / Probe helpers (SGK-2026-0307)

history replay / scenario probe seed / scenario target selection の helper 群。
_SeedCollectors の二段分割先。seed 収集・refine の責務は collectors 側に残る。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, unquote, urlparse

from src.core.engine.master_conductor_recon_url_scope import _UrlScopeResolver

logger = logging.getLogger(__name__)


class _SeedReplayProbe:
    """history replay / scenario probe / scenario target selection helper。

    _SeedCollectors への参照を持ち、collect_csrf_seed_targets /
    refine_backfill_seed_targets を呼び出す。
    MasterConductor instance の逆参照は禁止。
    """

    def __init__(
        self,
        *,
        context: Any,
        workspace: Any,
        project_manager: Any,
        target: str,
        settings_: Any,
        scope: _UrlScopeResolver,
        collectors: Any,
    ) -> None:
        self._context = context
        self._workspace = workspace
        self._project_manager = project_manager
        self._target = target
        self._settings = settings_
        self.scope = scope
        self._collectors = collectors

    # ---- history replay collector ----

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

        tagged_dir = self._collectors.resolve_project_tagged_dir()
        if tagged_dir is None:
            return []

        file_limit = max(1, int(file_window or 1))
        scope_hosts = self._collectors.resolve_in_scope_hosts()
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

    # ---- scenario probe seed helpers ----

    def collect_scenario_probe_seed_targets(
        self,
        recon_results: dict[str, dict],
        budget: int = 2,
    ) -> tuple[list[str], dict[str, dict[str, Any]]]:
        budget = max(1, int(budget or 2))
        seeds, evidence = self._collectors.collect_csrf_seed_targets(
            recon_results=recon_results,
            budget=max(3, budget),
        )
        seeds, evidence = self._collectors.refine_backfill_seed_targets(
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
