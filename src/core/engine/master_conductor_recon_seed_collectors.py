"""
Recon Seed Collectors (SGK-2026-0303/0307)

tagged file seed 収集 / CSRF / XSS collector / backfill refine。
history replay / scenario probe は SGK-2026-0307 で replay_probe へ移行。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from src.core.engine.master_conductor_recon_url_scope import _UrlScopeResolver
from src.core.engine.master_conductor_recon_seed_selector import _SeedTargetSelector

logger = logging.getLogger(__name__)

class _SeedCollectors:
    """seed 収集 / refine の helper 群。

    context / workspace / project_manager / target / settings を
    コンストラクタで注入し、scope / seed の delegate も保持する。
    MasterConductor instance への参照は持たない。
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
        seed: _SeedTargetSelector,
    ) -> None:
        self._context = context
        self._workspace = workspace
        self._project_manager = project_manager
        self._target = target
        self._settings = settings_
        self.scope = scope
        self.seed = seed

    # ---- context/workspace 依存の auth helpers ----

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

    # ---- path resolution helpers ----

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

    # ---- seed collectors ----

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
                    score, reasons = self.seed.score_csrf_seed_candidate(
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
                    score, reasons = self.seed.score_xss_seed_candidate(
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

    # history replay / scenario probe: moved to _SeedReplayProbe (SGK-2026-0307)

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
        low_value_filtered = input_count - len([url for url in deduped_targets if not self.seed.is_low_value_backfill_target(url)])
        discovered_topup = 0

        refined: list[str] = [
            url for url in deduped_targets
            if not self.seed.is_low_value_backfill_target(url)
        ][:max_targets]

        if len(refined) < max_targets:
            for asset in list(getattr(self._context, "discovered_assets", []) or []):
                candidate = str(asset or "").strip()
                if not candidate or candidate in seen:
                    continue
                if self.seed.is_low_value_backfill_target(candidate):
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

