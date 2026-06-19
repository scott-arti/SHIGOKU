"""
Recon URL Scope helpers (SGK-2026-0303 Step 3)

stateless URL normalisation / host extraction / scope judgement helper.
MasterConductor instance や settings に依存しない pure helper。
"""

from __future__ import annotations

from urllib.parse import parse_qs, unquote, urlparse

from src.core.domain.model.task import Task


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
