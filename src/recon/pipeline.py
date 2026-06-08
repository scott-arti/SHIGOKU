"""
Reconnaissance Pipeline

Wildcard Recon フローと並行タスク処理を提供する。

フロー:
- メインフロー (Step 1-8) は直列完了
- 並行タスクは各自完了次第、分類→PM保存→MC返却を独立実行
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from datetime import datetime
from src.core.utils.json_utils import robust_json_loads
from src.tools.custom.katana import KatanaTool
from src.tools.custom.httpx import HttpxTool
from src.tools.custom.gau import GAUTool
from src.tools.custom.playwright_recon import PlaywrightCrawler
from src.core.intel.tagging_filter import TaggingFilter
from src.core.validation.url_classifier import URLClassifier, classify_url
from src.config import settings
from src.core.engine.adaptive_rate_limiter import get_rate_limiter
from src.core.engine.tag_taxonomy_registry import (
    PIPELINE_HISTORY_CANDIDATE_CATEGORIES,
    tags_for_category,
)

logger = logging.getLogger(__name__)


@dataclass
class ReconState:
    """Recon パイプラインの状態管理
    
    中断・再開用の状態管理と並行タスク制御フラグを保持する。
    """
    
    # 中断・再開用
    current_step: int = 0
    completed_steps: list[str] = field(default_factory=list)
    
    # 並行タスク制御
    permutation_executed: bool = False
    attack_phase_active: bool = False
    
    # 結果キャッシュ
    all_subs: list[str] = field(default_factory=list)
    live_subs: list[str] = field(default_factory=list)
    dead_subs: list[str] = field(default_factory=list)
    
    # メタデータ
    target: str = ""
    project_name: str = ""
    screenshots_count: int = 0
    tech_stack: list[str] = field(default_factory=list)  # 検出された技術スタック
    results: dict[str, dict] | None = None  # Step 8 の分類結果
    
    def mark_step_complete(self, step_name: str) -> None:
        """ステップを完了としてマーク"""
        if step_name not in self.completed_steps:
            self.completed_steps.append(step_name)
        self.current_step += 1
        logger.debug("Step completed: %s", step_name)
    
    def is_step_complete(self, step_name: str) -> bool:
        """ステップが完了済みか確認"""
        return step_name in self.completed_steps
    
    def save(self, path: Path) -> None:
        """状態をJSONファイルに保存"""
        import json
        data = {
            "current_step": self.current_step,
            "completed_steps": self.completed_steps,
            "permutation_executed": self.permutation_executed,
            "attack_phase_active": self.attack_phase_active,
            "all_subs": self.all_subs,
            "live_subs": self.live_subs,
            "dead_subs": self.dead_subs,
            "target": self.target,
            "project_name": self.project_name,
        }
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        logger.info("State saved: %s", path)
    
    @classmethod
    def load(cls, path: Path) -> "ReconState":
        """JSONファイルから状態を復元"""
        import json
        if not path.exists():
            return cls()
        data = json.loads(path.read_text())
        return cls(
            current_step=data.get("current_step", 0),
            completed_steps=data.get("completed_steps", []),
            permutation_executed=data.get("permutation_executed", False),
            attack_phase_active=data.get("attack_phase_active", False),
            all_subs=data.get("all_subs", []),
            live_subs=data.get("live_subs", []),
            dead_subs=data.get("dead_subs", []),
            target=data.get("target", ""),
            project_name=data.get("project_name", ""),
        )


class ReconPipeline:
    """Wildcard Recon パイプライン
    
    メインフロー (Step 1-8) と並行タスクを管理する。
    
    使用例:
        pipeline = ReconPipeline(
            target="*.example.com",
            project_manager=pm,
            config=config,
        )
        result = await pipeline.run()
    """
    
    def __init__(
        self,
        config: dict[str, Any],
        project_manager: Any,
        target: str = "",
        master_conductor: Any = None,
        workspace_root: str | Path | None = None,
    ) -> None:
        """初期化
        
        Args:
            config: 設定辞書
            project_manager: ProjectManager インスタンス
            target: ターゲットドメイン (例: "*.example.com")
            master_conductor: MasterConductor インスタンス
            workspace_root: ワークスペースルートパス
        """
        self.target = target
        self.pm = project_manager
        self.config = config
        self.mc = master_conductor
        
        # Prioritize ProjectManager directory if available and workspace_root not explicitly set
        if not workspace_root and self.pm and hasattr(self.pm, "project_dir"):
            self.workspace_root = self.pm.project_dir
        else:
            self.workspace_root = Path(workspace_root) if workspace_root else Path.cwd()
        
        # 状態管理
        self.state = ReconState(target=target, project_name=self.target.lstrip("*."))
        
        # ToolRunner 初期化 (遅延インポートで循環参照回避)
        from src.recon.tool_runner import ToolRunner
        self.runner = ToolRunner()
        self.pm_initialized = False

        from src.recon.parallel_tasks import ParallelTasks
        self.tasks = ParallelTasks(config, project_manager, master_conductor)
        
        # 並行処理制御
        max_concurrent = config.get("scan", {}).get("max_concurrent_tasks", getattr(settings, "max_concurrent_tasks", 4))
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.active_recon_sem = asyncio.Semaphore(2)  # Active Scan 用同時実行制限
        
        # レートリミッター
        self.limiters = {
            "passive": get_rate_limiter("intel_passive"),
            "active": get_rate_limiter("intel_active"),
        }
        
        # ファイル書き込み排他制御
        self.file_lock = asyncio.Lock()
        
        # Maintain references to background tasks to prevent GC
        self.background_tasks = set()
        # authbypass/weak_id 向け BizLogic タスクの重複投入抑止
        self._seeded_authz_verify_targets: set[str] = set()
        
        logger.info("ReconPipeline initialized: %s (Workspace: %s)", target, self.workspace_root)
        
    def _get_path(self, type_name: str, ext: str) -> Path:
        """命名規則に従ったファイルパスを取得する
        形式: YYYYMMDD_<project_name>_<type_name>.<ext>
        """
        date_str = datetime.now().strftime("%Y%m%d")
        project = "recon"
        if self.state and hasattr(self.state, "project_name") and self.state.project_name:
            project = self.state.project_name.replace(".", "_")
        elif isinstance(self.state, str) and self.state:
            project = self.state.replace(".", "_")
        
        # Structure: projects/{target}/scans/raw/YYYYMMDD_project_typename.ext
        if self.pm and hasattr(self.pm, "project_dir"):
            raw_dir = self.pm.project_dir / "scans" / "raw"
            raw_dir.mkdir(parents=True, exist_ok=True)
            return raw_dir / f"{date_str}_{project}_{type_name}.{ext}"
        
        return self.workspace_root / f"{date_str}_{project}_{type_name}.{ext}"
        
    
    # === Step 1-2: Subdomain Discovery ===
    
    def _get_context_auth_headers(self) -> dict[str, str]:
        """Contextから認証ヘッダーを取得し、Cookie/Bearerを補完する。"""
        headers: dict[str, str] = {}
        target_info = {}
        if self.mc and self.mc.context and isinstance(self.mc.context.target_info, dict):
            target_info = self.mc.context.target_info

        raw_headers = target_info.get("auth_headers", {})
        if isinstance(raw_headers, dict):
            for key, value in raw_headers.items():
                header_name = str(key).strip()
                header_value = str(value).strip()
                if header_name and header_value:
                    headers[header_name] = header_value

        cookies = str(target_info.get("cookies", "") or "").strip()
        if cookies:
            headers.setdefault("Cookie", cookies)

        bearer_token = str(target_info.get("bearer_token", "") or "").strip()
        if bearer_token:
            if bearer_token.lower().startswith("bearer "):
                bearer_token = bearer_token[7:].strip()
            if bearer_token:
                headers.setdefault("Authorization", f"Bearer {bearer_token}")

        return headers

    def _get_auth_header_lines(self) -> list[str]:
        """ツール連携向けに `Header: value` 形式で返す。"""
        return [f"{name}: {value}" for name, value in self._get_context_auth_headers().items()]

    def _get_cookie_header(self) -> str | None:
        """ContextからCookieヘッダーを取得"""
        cookie = self._get_context_auth_headers().get("Cookie")
        if cookie:
            return f"Cookie: {cookie}"
        return None

    def _is_host_in_scope(self, host: str) -> bool:
        target_host_raw = (
            str(self.target or "")
            .replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
            .lstrip("*.")
            .lower()
        )
        target_host = str(target_host_raw).split(":")[0].strip().lower()
        candidate = str(host or "").split(":")[0].strip().lower()
        if not target_host or not candidate:
            return False
        return candidate == target_host or candidate.endswith(f".{target_host}")

    def _is_low_value_playwright_seed_url(self, candidate_url: str, allow_root: bool = False) -> bool:
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(str(candidate_url or "").strip())
        if parsed.scheme not in {"http", "https"}:
            return True
        if not self._is_host_in_scope(parsed.netloc):
            return True

        path_lower = (parsed.path or "").lower()
        query_keys = {k.lower() for k in parse_qs(parsed.query, keep_blank_values=True).keys()}
        static_path_tokens = ("/_next/", "/static/", "/assets/", "/dist/", "/chunks/")
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
        interaction_keys = {"q", "query", "search", "id", "redirect", "url", "next", "file", "path", "page"}
        candidate_lower = str(candidate_url or "").lower()
        malformed_js_fragment = (
            "%27%29,d=f%28%27%3cscript%20type=" in candidate_lower
            or ("%27%29" in candidate_lower and "script%20type=" in candidate_lower and "/static/js/" in path_lower)
        )
        is_static_asset = any(token in path_lower for token in static_path_tokens) or path_lower.endswith(static_extensions)
        is_root = (parsed.path or "/") == "/" and not parsed.query

        if malformed_js_fragment:
            return True
        if is_static_asset and not (query_keys & interaction_keys):
            return True
        if is_root and not allow_root:
            return True
        return False

    def _score_playwright_seed_url(self, candidate_url: str, method: str = "GET") -> int:
        from urllib.parse import parse_qs, unquote, urlparse

        parsed = urlparse(str(candidate_url or "").strip())
        path_lower = (parsed.path or "").lower()
        query_keys = {k.lower() for k in parse_qs(parsed.query, keep_blank_values=True).keys()}
        path_tokens = {token for token in unquote(path_lower).split("/") if token}
        method_upper = str(method or "GET").upper()

        stateful_tokens = {
            "account", "profile", "user", "users", "order", "orders", "checkout", "payment",
            "search", "query", "review", "feedback", "comment", "message", "chatbot", "wallet",
            "coupon", "redeem", "admin", "settings", "address", "email", "password",
        }
        auth_tokens = {
            "auth",
            "login",
            "signin",
            "sign-in",
            "session",
            "token",
            "jwt",
            "oauth",
            "sso",
            "mfa",
            "2fa",
            "password",
            "account",
            "profile",
        }
        id_tokens = {
            "id",
            "uid",
            "user_id",
            "account_id",
            "order_id",
            "report_id",
            "video_id",
            "item_id",
            "product_id",
            "vehicle_id",
            "tenant_id",
            "org_id",
            "organization_id",
        }
        sensitive_param_keys = {
            "id",
            "user_id",
            "account_id",
            "order_id",
            "report_id",
            "video_id",
            "item_id",
            "role",
            "admin",
            "permission",
            "token",
            "jwt",
            "price",
            "amount",
            "quantity",
            "coupon",
            "discount",
            "redirect",
            "url",
            "next",
            "file",
            "path",
            "include",
        }

        score = 0
        if parsed.query:
            score += 10
        if method_upper in {"POST", "PUT", "PATCH", "DELETE"}:
            score += 8
        if "/api/" in path_lower or "/rest/" in path_lower:
            score += 6
        if path_tokens & stateful_tokens:
            score += 8
        if query_keys & stateful_tokens:
            score += 4
        if path_tokens & auth_tokens:
            score += 10
        if query_keys & auth_tokens:
            score += 6
        if path_tokens & id_tokens:
            score += 8
        if query_keys & id_tokens:
            score += 10
        if query_keys & sensitive_param_keys:
            score += 8
        score += min(6, len(path_tokens))
        return score

    def _select_playwright_seed_targets(
        self,
        base_targets: list[str],
        discovered_entries: list[dict[str, Any]],
        budget: int,
    ) -> list[str]:
        if budget <= 0:
            return []

        bootstrap_targets: list[str] = []
        seen: set[str] = set()
        for seed in base_targets:
            candidate = str(seed or "").strip()
            if not candidate or candidate in seen:
                continue
            if self._is_low_value_playwright_seed_url(candidate, allow_root=True):
                continue
            bootstrap_targets.append(candidate)
            seen.add(candidate)

        ranked_dynamic: list[tuple[int, str]] = []
        for entry in discovered_entries:
            if not isinstance(entry, dict):
                continue
            candidate = str(entry.get("url", "") or "").strip()
            if not candidate or candidate in seen:
                continue
            if self._is_low_value_playwright_seed_url(candidate, allow_root=False):
                continue
            score = self._score_playwright_seed_url(candidate, method=str(entry.get("method", "GET") or "GET"))
            ranked_dynamic.append((score, candidate))
            seen.add(candidate)

        ranked_dynamic.sort(key=lambda item: item[0], reverse=True)

        selected: list[str] = []
        if bootstrap_targets:
            selected.append(bootstrap_targets[0])

        for _, candidate in ranked_dynamic:
            if candidate in selected:
                continue
            selected.append(candidate)
            if len(selected) >= budget:
                break

        if len(selected) < budget:
            for candidate in bootstrap_targets[1:]:
                if candidate in selected:
                    continue
                selected.append(candidate)
                if len(selected) >= budget:
                    break

        if not selected and bootstrap_targets:
            selected.append(bootstrap_targets[0])

        return selected[:budget]

    def _collect_recent_playwright_history_seeds(
        self,
        tagged_dir: Path,
        target_url: str,
        max_urls: int,
        max_files: int,
    ) -> list[str]:
        from urllib.parse import urlparse

        if not tagged_dir.exists():
            return []

        parsed_target = urlparse(str(target_url or "").strip())
        target_host = (parsed_target.netloc or "").lower()
        if not target_host:
            return []

        max_urls = max(1, int(max_urls or 1))
        max_files = max(1, int(max_files or 1))
        candidate_categories = PIPELINE_HISTORY_CANDIDATE_CATEGORIES

        candidate_files: list[Path] = []
        for category in candidate_categories:
            candidate_files.extend(tagged_dir.glob(f"*_tagged_{category}.jsonl"))
            candidate_files.extend(tagged_dir.glob(f"*_tagged_uncategorized_promoted_{category}.jsonl"))

        if not candidate_files:
            return []

        ranked: list[tuple[int, str]] = []
        seen_urls: set[str] = set()
        for hist_file in sorted(candidate_files, reverse=True)[:max_files]:
            try:
                with open(hist_file, "r", encoding="utf-8") as fh:
                    for idx, line in enumerate(fh):
                        if idx >= 500:
                            break
                        parsed_items = robust_json_loads(line)
                        if not isinstance(parsed_items, list):
                            continue
                        for item in parsed_items:
                            if not isinstance(item, dict):
                                continue
                            candidate = str(item.get("url", "") or "").strip()
                            if not candidate or candidate in seen_urls:
                                continue
                            parsed = urlparse(candidate)
                            if (parsed.netloc or "").lower() != target_host:
                                continue
                            if self._is_low_value_playwright_seed_url(candidate, allow_root=False):
                                continue
                            score = self._score_playwright_seed_url(
                                candidate,
                                method=str(item.get("method", "GET") or "GET"),
                            )
                            if score <= 0:
                                continue
                            ranked.append((score, candidate))
                            seen_urls.add(candidate)
            except Exception:
                continue

        ranked.sort(key=lambda item: item[0], reverse=True)
        return [url for _, url in ranked[:max_urls]]

    # === Step 1-2: Subdomain Discovery ===
    
    async def step1_subdomain_discovery(self) -> list[str]:
        """Step 1: サブドメイン列挙
        
        subfinder, amass, bbot を実行して結果を統合。
        
        Returns:
            全サブドメインのリスト
        """
        logger.info("[Step 1] Subdomain Discovery started")
        
        # Phase 5: イベント発火
        from src.core.infra.event_bus import get_event_bus, Event, EventType
        event_bus = get_event_bus()
        event_bus.emit_sync(Event(
            type=EventType.RECON_STEP_START,
            payload={"step": 1, "name": "Subdomain Discovery"},
            source="recon_pipeline",
        ))
        
        # ツールチェック (Strict check removed for resilience)
        # self.runner.check_tools(["subfinder", "amass", "bbot", "anew"])
        
        all_subs = set()
        
        # 1. subfinder
        if self.runner.is_tool_available("subfinder"):
            subfinder_out = await self.runner.run(
                ["subfinder", "-d", self.target.lstrip("*."), "-all", "-silent"],
                timeout=600,
            )
            # 個別ファイル保存
            self.workspace_root.mkdir(parents=True, exist_ok=True)
            subfinder_file = self._get_path("subfinder", "txt")
            subfinder_file.write_text(subfinder_out)
            
            subs = set(line.strip() for line in subfinder_out.splitlines() if line.strip())
            all_subs.update(subs)
            logger.info("subfinder found %d subdomains", len(subs))
        else:
            logger.warning("subfinder not found, skipping")

        
        # 2. amass (JSON出力)
        if self.runner.is_tool_available("amass"):
            amass_json = await self.runner.run_json(
                ["amass", "enum", "-d", self.target.lstrip("*."), "-active", "-json"],
                timeout=3600,
            )
            
            # 個別ファイル保存 (recon_scenario.md 要件)
            import json
            amass_file = self._get_path("amass", "json")
            amass_file.write_text(json.dumps(amass_json, indent=2, ensure_ascii=False))
            logger.info("Saved amass output: %s", amass_file)
            
            # ASN/DNS 抽出 (recon_scenario.md 要件)
            asn_data = [item for item in amass_json if item.get("tag") == "asn"]
            dns_data = [item for item in amass_json if item.get("tag") == "dns"]
            if asn_data:
                asn_file = self._get_path("asn", "json")
                asn_file.write_text(json.dumps(asn_data, indent=2, ensure_ascii=False))
                logger.info("Saved ASN data: %s (%d entries)", asn_file, len(asn_data))
            if dns_data:
                dns_file = self._get_path("dns", "json")
                dns_file.write_text(json.dumps(dns_data, indent=2, ensure_ascii=False))
                logger.info("Saved DNS data: %s (%d entries)", dns_file, len(dns_data))
            
            amass_subs = {item["name"] for item in amass_json if "name" in item}
            all_subs.update(amass_subs)
            logger.info("amass found %d subdomains (total: %d)", len(amass_subs), len(all_subs))
        else:
            logger.warning("amass not found, skipping")
        
        # 3. bbot
        if self.runner.is_tool_available("bbot"):
            # bbot raw output を取得
            bbot_raw_output = await self.runner.run(
                ["bbot", "-t", self.target.lstrip("*."), "-p", "subdomain-enum", "-f", "asn", "-f", "cloud-enum"],
                timeout=1800,
            )
            
            # bbot output saving
            bbot_file = self._get_path("bbot", "jsonl")
            bbot_file.write_text(bbot_raw_output)
            logger.info("Saved bbot output: %s", bbot_file)
            
            # BUCKET extraction - Streamingパース
            from src.core.utils.json_utils import stream_jsonl
            import json # Import json here for json.dumps
            
            # Process bbot output using stream_jsonl
            bbot_results = list(stream_jsonl(str(bbot_file)))

            buckets = [item for item in bbot_results if item.get("type") == "STORAGE_BUCKET"]
            if buckets:
                buckets_file = self._get_path("buckets", "json")
                buckets_file.write_text(json.dumps(buckets, indent=2, ensure_ascii=False))
                logger.info("Saved BUCKET data: %s (%d entries)", buckets_file, len(buckets))
            
            bbot_subs = {item["data"] for item in bbot_results if item.get("type") == "SUBDOMAIN"}
            all_subs.update(bbot_subs)
            logger.info("bbot found %d subdomains (total: %d)", len(bbot_subs), len(all_subs))
        else:
            logger.warning("bbot not found, skipping")
        
        result = sorted(all_subs)
        
        # 統合結果を保存 (recon_scenario.md 要件: YYYYMMDD_all_subs.txt)
        all_subs_file = self._get_path("all_subs", "txt")
        all_subs_file.write_text("\n".join(result))
        logger.info("Saved all subdomains: %s (%d entries)", all_subs_file, len(result))
        
        logger.info("[Step 1] Subdomain Discovery completed: %d total subdomains", len(result))
        
        # Phase 5: イベント発火
        event_bus.emit_sync(Event(
            type=EventType.RECON_STEP_END,
            payload={"step": 1, "name": "Subdomain Discovery", "result": f"{len(result)} subdomains"},
            source="recon_pipeline",
        ))
        
        return result
    
    async def step2_historical_discovery(self, all_subs: list[str]) -> list[str]:
        """Step 2: 過去URL履歴からサブドメイン抽出
        
        gau で取得したURLからホスト部を抽出し、既存リストに追加。
        
        Args:
            all_subs: Step 1 で取得したサブドメインリスト
        
        Returns:
            更新されたサブドメインリスト
        """
        logger.info("[Step 2] Historical Discovery started")
        
        # ツールチェック
        # self.runner.check_tools(["gau"])
        
        if self.runner.is_tool_available("gau"):
            gau_cmd = ["gau", "--subs", self.target.lstrip("*.")]
            
            # Global Proxy Strategy: Inject proxy if configured
            proxy_url = settings.get_proxy_url()
            if proxy_url:
                gau_cmd.extend(["--proxy", proxy_url])
                logger.info("Injecting proxy into gau: %s", proxy_url)
                
            gau_out = await self.runner.run(
                gau_cmd,
                timeout=600,
            )
        else:
            logger.warning("gau not found, skipping")
            gau_out = ""
        
        # gau 出力をファイルに保存 (後続の gf 分類で使用)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        gau_urls_file = self._get_path("gau_urls", "txt")
        gau_urls_file.write_text(gau_out)
        logger.info("Saved gau URLs: %s", gau_urls_file)
        
        # URL → ホスト抽出
        import urllib.parse
        hosts = set()
        for line in gau_out.strip().split("\n"):
            if not line:
                continue
            try:
                parsed = urllib.parse.urlparse(line)
                if parsed.hostname:
                    hosts.add(parsed.hostname)
            except Exception as e:
                logger.debug("Failed to parse URL: %s - %s", line, e)
        
        logger.info("gau found %d historical hosts", len(hosts))
        
        # 既存リストに追加
        result = sorted(set(all_subs) | hosts)
        logger.info("[Step 2] Historical Discovery completed: %d total subdomains", len(result))
        
        return result
    
    # === Step 3-4: Live Check & WAF Detection ===
    
    async def fetch_resolvers(self, count: int = 25) -> Path:
        """Fresh-Resolvers からDNSリゾルバーを取得
        
        Args:
            count: 取得するリゾルバー数
        
        Returns:
            リゾルバーファイルのパス
        """
        resolvers_file = self._get_path("resolvers", "txt")
        
        if self.runner.dev_mode:
            # DEV_MODE: モックリゾルバー
            mock_resolvers = "\n".join([
                "8.8.8.8",
                "1.1.1.1",
                "9.9.9.9",
            ])
            resolvers_file.write_text(mock_resolvers)
            logger.info("DEV_MODE: Created mock resolvers file")
            return resolvers_file
        
        # 本番: Fresh-Resolvers から取得
        url = "https://raw.githubusercontent.com/proabiral/Fresh-Resolvers/master/resolvers.txt"
        
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    text = await resp.text()
                    resolvers = text.strip().split("\n")[:count]
                    resolvers_file.write_text("\n".join(resolvers))
                    logger.info("Fetched %d resolvers from Fresh-Resolvers", len(resolvers))
        except Exception as e:
            logger.warning("Failed to fetch resolvers: %s, using defaults", e)
            # フォールバック
            default_resolvers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
            resolvers_file.write_text("\n".join(default_resolvers))
        
        return resolvers_file
    
    async def step3_live_check(self, all_subs: list[str]) -> tuple[list[str], list[str]]:
        """Step 3: 生存確認とテクノロジースタック取得
        
        shuffledns, httpx, whatweb を実行してライブサブドメインを特定。
        
        Args:
            all_subs: Step 1-2 で収集したサブドメインリスト
        
        Returns:
            (live_subs, dead_subs) のタプル
        """
        logger.info("[Step 3] Live Check & Technology started")
        
        # 1. Fresh-Resolvers 取得 (Single URL Modeでは不要だが、念のため)
        resolvers_file = await self.fetch_resolvers(count=25)

        # Check for Single URL Mode (Stateから判定)
        # Note: pipeline.run() で Single URL Mode なら state.target は URL そのものになっているはず
        # all_subs には hostname が1つだけ入っている
        is_single_url = False
        import urllib.parse
        target_parsed = urllib.parse.urlparse(self.state.target) if self.state.target else None
        
        # 簡易判定: all_subs が1つで、かつターゲット(ホスト名)と一致する場合
        if len(all_subs) == 1 and target_parsed and all_subs[0] == target_parsed.hostname:
            is_single_url = True
            logger.info("Single URL Mode detected in Step 3: Skipping DNS Resolution (shuffledns)")

        # all_subdomains.txt 作成
        all_subs_file = self._get_path("all_subdomains", "txt")
        all_subs_file.write_text("\n".join(all_subs))
        logger.info("Saved all subdomains to %s", all_subs_file)
        
        resolved_file = self._get_path("resolved", "txt")
        shuffledns_out = ""
        
        if not is_single_url and self.runner.is_tool_available("shuffledns"):
            # Wildcard/Domain Mode: Run shuffledns
            # shuffledns -d example.com -list all_subs.txt ...
            # -d にはドメインのみ渡す必要がある (*.example.com -> example.com)
            domain_only = self.target.replace("*.", "").strip()
            
            # URLが渡された場合のクリーニング (http://example.com -> example.com)
            if "://" in domain_only:
                 p = urllib.parse.urlparse(domain_only)
                 domain_only = p.hostname or domain_only

            shuffledns_out = await self.runner.run(
                ["shuffledns", "-d", domain_only, "-list", str(all_subs_file), "-r", str(resolvers_file), "-o", str(resolved_file)],
                timeout=900,
            )
            # resolved_file から読み込み
            if self.runner.dev_mode:
                resolved = shuffledns_out.strip().split("\n")
            else:
                resolved = resolved_file.read_text().strip().split("\n") if resolved_file.exists() else []

        else:
            # Single URL Mode, or shuffledns missing: Skip DNS resolution
            if is_single_url:
                 # Single URL Mode: No need to resolve, assume the input hostname is the target
                 # However, httpx needs full URLs or hostnames.
                 # If we have the full URL in self.state.target, we should probably verify THAT specific URL.
                 # But Step 3 contract says it returns live_subs (hostnames).
                 # So we pass the hostname to httpx.
                 logger.info("Skipping shuffledns logic. Using input hostname directly: %s", all_subs[0])
                 resolved = all_subs
            else:
                logger.warning("shuffledns not found or skipped, using input list as resolved")
                resolved = all_subs
            
            # Save manually to resolved_file for consistency
            resolved_file.write_text("\n".join(resolved))
        
        resolved = [s.strip() for s in resolved if s.strip()]
        logger.info("DNS resolution completed: %d subdomains", len(resolved))
        
        # 4. httpx で HTTP(S) プローブ
        # resolved.txt からホストのみ抽出 (httpx はホストリストを期待)
        resolved_file_for_httpx = self._get_path("resolved_for_httpx", "txt")
        
        # Single URL Mode の場合、httpx には正確なターゲットURLを渡したい
        # しかし httpx -l はリストを受け取る。
        # もし target が http://localhost:4280/vulnerabilities/exec/ なら、httpxにはこのFull URLを渡すべきか？
        # ホスト名だけ渡すと http://localhost:80 とかに行きかねない。
        
        httpx_input_list = resolved
        if is_single_url and self.state.target.startswith("http"):
             # Use the exact target URL for httpx probing if in Single URL Mode
             httpx_input_list = [self.state.target]
             logger.info("Using full target URL for httpx probe: %s", self.state.target)

        resolved_file_for_httpx.write_text("\n".join(httpx_input_list))
        
        httpx_json_file = self._get_path("httpx", "json")
        httpx_out = []
        if self.runner.is_tool_available("httpx"):
            # Use configured tool path (wrapper support)
            tool_httpx = self.config.get("tool_httpx_path", "httpx")
            logger.info(f"Executing httpx tool: {tool_httpx}")
            
            httpx_cmd = [tool_httpx, "-l", str(resolved_file_for_httpx), "-json", "-o", str(httpx_json_file)]
            
            # Global Proxy Strategy: Inject proxy if configured
            proxy_url = settings.get_proxy_url()
            if proxy_url:
                httpx_cmd.extend(["-http-proxy", proxy_url])
                logger.info("Injecting proxy into httpx probe: %s", proxy_url)
            
            # Inject auth headers (Cookie / Authorization / custom headers)
            auth_headers = self._get_auth_header_lines()
            if auth_headers:
                for header in auth_headers:
                    httpx_cmd.extend(["-H", header])
                logger.info("Injecting %d auth headers into httpx", len(auth_headers))
                
            httpx_out = await self.runner.run_json(
                httpx_cmd,
                timeout=600,
            )
        else:
            logger.warning("httpx not found, skipping")
        
        # httpx 結果から live_subs を抽出
        live_subs = []
        for item in httpx_out:
            if item.get("status_code") and item["status_code"] < 500:
                # URL からホスト抽出
                import urllib.parse
                parsed = urllib.parse.urlparse(item.get("url", ""))
                if parsed.hostname:
                    live_subs.append(parsed.hostname)
        
        live_subs = sorted(set(live_subs))
        logger.info("httpx found %d live subdomains", len(live_subs))
        
        # レートリミッターへのフィードバック
        limiter = self.limiters.get("active")
        if limiter:
            for item in httpx_out:
                status = item.get("status_code")
                if status:
                    limiter.on_response(status)
        
        # 5. whatweb で Tech Stack 補完 (recon_scenario.md 要件)
        whatweb_file = self._get_path("whatweb", "json")
        whatweb_out = ""
        if self.runner.is_tool_available("whatweb"):
            whatweb_out = await self.runner.run(
                ["whatweb", "--log-json=" + str(whatweb_file), "-i", str(resolved_file_for_httpx)],
                timeout=600,
            )
        else:
            logger.warning("whatweb not found, skipping")
        
        # DEV_MODE: whatweb は --log-json でファイル出力するため、mock時は手動で作成
        if self.runner.dev_mode and not whatweb_file.exists():
            whatweb_file.write_text(whatweb_out)
        
        logger.info("Saved whatweb output: %s", whatweb_file)
        
        # 6. dead_subs = all_subs - resolved
        dead_subs = sorted(set(all_subs) - set(resolved))
        logger.info("[Step 3] Live Check completed: %d live, %d dead", len(live_subs), len(dead_subs))
        
        # takeover_candidates.json 生成 (recon_scenario.md 要件)
        import json
        if dead_subs:
            takeover_file = self._get_path("takeover_candidates", "json")
            takeover_data = [{"subdomain": sub, "status": "NXDOMAIN"} for sub in dead_subs]
            takeover_file.write_text(json.dumps(takeover_data, indent=2, ensure_ascii=False))
            logger.info("Saved takeover candidates: %s (%d entries)", takeover_file, len(dead_subs))
        
        # live_subs.txt 保存 (recon_scenario.md 要件)
        live_subs_file = self._get_path("live_subs", "txt")
        live_subs_file.write_text("\n".join(live_subs))
        logger.info("Saved live subdomains: %s (%d entries)", live_subs_file, len(live_subs))
        
        
        # 技術スタック情報を抽出 (whatweb 結果 + 詳細 Fingerprinting)
        try:
            whatweb_data = []
            content_to_parse = ""

            if whatweb_out:
                content_to_parse = whatweb_out
            elif whatweb_file.exists():
                content_to_parse = whatweb_file.read_text()

            if content_to_parse:
                # 堅牢なJSONパース（JSONL, concatenated objects, junk dataに対応）
                try:
                    whatweb_data = robust_json_loads(content_to_parse)
                    if not whatweb_data:
                        logger.warning("Failed to parse whatweb JSON using robust method")
                except Exception as e:
                    logger.warning(f"Exception during whatweb JSON parsing: {e}")
                    whatweb_data = []

            tech_set = set()

            # 1. whatweb からの簡易的な抽出
            for entry in whatweb_data:
                plugins = entry.get("plugins", {})
                # 代表的なプラグイン名を抽出
                for plugin_name, plugin_data in plugins.items():
                    if plugin_name in ["HTTPServer", "X-Powered-By", "WordPress", "nginx", "Apache", "IIS"]:
                        if isinstance(plugin_data, dict) and "string" in plugin_data:
                            for tech in plugin_data["string"]:
                                tech_set.add(tech)
                        elif isinstance(plugin_data, dict) and "version" in plugin_data:
                            tech_set.add(f"{plugin_name} {plugin_data['version']}")
                        else:
                            tech_set.add(plugin_name)
            
            # 2. 詳細 Fingerprinting (ScopeParserAgent ロジック) - サンプル URL で実行
            if live_subs:
                try:
                    from src.core.agents.specialized.scope_parser import ScopeParserAgent
                    
                    # 代表的な URL (最初の5件) で詳細解析
                    sample_urls = [f"https://{sub}" for sub in live_subs[:5]]
                    fingerprinter = ScopeParserAgent()
                    
                    for url in sample_urls:
                        try:
                            result = await fingerprinter.fingerprint(url)
                            if result and result.get("technologies"):
                                tech_set.update(result["technologies"])
                                logger.debug(f"Advanced fingerprinting for {url}: {result['technologies']}")
                        except Exception as e:
                            logger.debug(f"Advanced fingerprinting failed for {url}: {e}")
                            continue
                    
                    logger.info("Advanced fingerprinting completed for %d sample URLs", len(sample_urls))
                except ImportError as e:
                    logger.warning("ScopeParserAgent not available for advanced fingerprinting: %s", e)
                except Exception as e:
                    logger.warning("Advanced fingerprinting failed: %s", e)
            
            self.state.tech_stack = sorted(list(tech_set))
            if self.state.tech_stack:
                logger.info("Detected tech stack: %s", ", ".join(self.state.tech_stack))
        except Exception as e:
            logger.warning("Failed to extract tech stack: %s", e)
        
        return live_subs, dead_subs

    
    async def step3b_hybrid_url_discovery(self, live_subs: list[str]) -> dict[str, int]:
        """Step 3b: Hybrid URL Discovery & Tagging
        
        Katana, GAU, Httpx を使用して URL を収集し、Caido Proxy を経由させ、
        TaggingFilter で分類・タグ付けを行う。
        
        Args:
            live_subs: Live サブドメインリスト
        
        Returns:
            タグごとの検知数統計
        """
        logger.info("[Step 3b] Hybrid URL Discovery started")
        
        if not live_subs:
            logger.warning("[Step 3b] No live subdomains available for crawling. Skipping.")
            return {}

        proxy_url = settings.get_proxy_url() or "http://127.0.0.1:8080"
        
        # ツール初期化
        katana = KatanaTool()
        gau = GAUTool()
        httpx = HttpxTool()
        
        # 1. Katana Execution (Live Subs -> Katana -> Proxy)
        # live_subs は hostname のみなので、http:// を付与してファイルに書き出し
        # 修正: httpx.json から Full URL (Scheme + Port) を取得して使用する
        live_subs_file = self._get_path("live_subs_for_crawl", "txt")
        katana_targets = []
        
        httpx_json_file = self._get_path("httpx", "json")
        if httpx_json_file.exists():
            try:
                import json
                # httpx は JSONL 形式 (1行1オブジェクト) で出力する
                httpx_data = []
                for line in httpx_json_file.read_text().splitlines():
                    line = line.strip()
                    if line:
                        try:
                            httpx_data.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                # Full URL を優先して使用
                katana_targets = [item["url"] for item in httpx_data if item.get("url")]
                logger.info("Loaded %d full URLs from httpx.json for Katana", len(katana_targets))
            except Exception as e:
                logger.warning("Failed to load httpx.json for Katana targets: %s", e)
        
        if not katana_targets:
            logger.info("Falling back to live_subs for Katana targets (Defaulting to http://)")
            katana_targets = [f"http://{sub}" for sub in live_subs if not sub.startswith("http")]

        live_subs_file.write_text("\n".join(katana_targets if katana_targets else live_subs))
        
        # Auth Headers
        auth_headers = self._get_auth_header_lines()
        if auth_headers:
            logger.info("Katana auth headers configured: %s", auth_headers)
        else:
            logger.warning("No auth headers configured for Katana. Set via context target_info auth_headers/cookies")

        logger.info("Running Katana on %d targets via proxy %s...", len(katana_targets), proxy_url)
        
        katana_entries = []
        import json

        def _parse_katana_jsonl(self, jsonl_content: str) -> list[dict]:
            """KatanaのJSONL出力を標準フォーマットに変換。"""
            results = []
            for line in jsonl_content.splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    req = data.get("request", {})
                    resp = data.get("response", {})
                    forms = data.get("forms", [])

                    url = req.get("endpoint", "")
                    if not url:
                        continue

                    method = req.get("method", "GET")
                    headers = req.get("headers", {})
                    body = req.get("body", "")

                    status = resp.get("status_code", 0)
                    resp_headers = resp.get("headers", {})
                    resp_body = resp.get("body", "")

                    entry = {
                        "url": url,
                        "method": method,
                        "headers": headers,
                        "body": body,
                        "response": {
                            "status": status,
                            "headers": resp_headers,
                            "body": resp_body,
                        },
                        "forms": forms, # ADDED Forms details
                        "source": "katana",
                    }
                    results.append(entry)
                except json.JSONDecodeError as e:
                    logger.debug(f"Katana JSON parse error: {e}")

            return results

        if self.runner.is_tool_available("katana"):
            # 1. Standard Mode (Fast & Broad)
            logger.info("Executing Katana in Standard mode for broad discovery...")
            std_out = katana.run(
                str(live_subs_file),
                mode="standard",
                proxy=proxy_url,
                headers=auth_headers
            )
            katana_entries.extend(_parse_katana_jsonl(self, std_out))
            
            # 2. Headless Mode (Deep JS)
            logger.info("Executing Katana in Headless mode for deep JS analysis...")
            headless_out = katana.run(
                str(live_subs_file), 
                mode="headless",
                proxy=proxy_url,
                headers=auth_headers
            )
            katana_entries.extend(_parse_katana_jsonl(self, headless_out))
            
            # UNIQUE ONLY
            unique_k_urls = {}
            for e in katana_entries:
                unique_k_urls[e["url"]] = e
            katana_entries = list(unique_k_urls.values())
        else:
            logger.warning("katana not found, skipping")
        
        logger.info("Katana found %d unique URLs total (Standard + Headless)", len(katana_entries))

        # レートリミッターへのフィードバック
        limiter = self.limiters.get("active")
        if limiter:
            for entry in katana_entries:
                status = entry.get("response", {}).get("status")
                if status:
                    limiter.on_response(status)

        # 2. GAU & Httpx Execution (All Subs -> GAU -> Filter -> Httpx -> Proxy)
        # GAU はターゲットドメイン全体に対して実行し、スコープ外とdead_subsを除外
        logger.info("Running GAU & Httpx on all subdomains...")
        
        gau_urls = set()
        target_domain = self.target.replace("*.", "")  # *.example.com -> example.com
        gau_out_raw = ""
        if self.runner.is_tool_available("gau"):
            gau_out_raw = gau.run(target_domain, mode="standard")
        else:
            logger.warning("gau not found, skipping")
        
        # URLパース用
        from urllib.parse import urlparse
        
        # dead_subs を含む URL & スコープ外 URL を除外
        dead_subs = self.state.dead_subs or []
        for line in gau_out_raw.splitlines():
            url = line.strip()
            if not url:
                continue
            
            # 1. スコープチェック: URL のホストがターゲットドメインに属するか
            try:
                parsed = urlparse(url)
                host = parsed.netloc.lower()
                # ターゲットドメインで終わるかチェック (example.com, sub.example.com)
                if not host.endswith(target_domain):
                    continue  # スコープ外
            except Exception:
                continue  # パースエラー
            
            # 2. dead_subs に含まれるホストを持つ URL を除外
            if any(dead_sub in url for dead_sub in dead_subs):
                continue
            
            gau_urls.add(url)
        
        logger.info("GAU found %d URLs (after scope and dead_subs filter)", len(gau_urls))
        
        # === SubdomainEnricher: 新サブドメインの抽出と Enrich ===
        # GAU URL からサブドメインを抽出
        gau_subdomains = set()
        for url in gau_urls:
            try:
                parsed = urlparse(url)
                host = parsed.netloc.lower()
                # ポート番号を除去
                if ":" in host:
                    host = host.split(":")[0]
                gau_subdomains.add(host)
            except Exception:
                pass
        
        # Step 1 で見つかったサブドメインと比較し、新規サブドメインを特定
        known_subs = set(self.state.live_subs or [])
        new_subdomains = list(gau_subdomains - known_subs)
        
        subdomain_context: dict[str, dict] = {}  # {subdomain: {waf, ports, tech}}
        
        if new_subdomains:
            logger.info("SubdomainEnricher: Found %d new subdomains from GAU (not in Step 1)", len(new_subdomains))
            
            # 1. WAF 検出（step4 再利用）
            try:
                waf_map = await self.step4_waf_detection(new_subdomains)
            except Exception as e:
                logger.warning("SubdomainEnricher: WAF detection failed: %s", e)
                waf_map = {}
            
            # 2. Port スキャン（step5 再利用）
            try:
                port_map = await self.step5_port_scan_phase1(new_subdomains)
            except Exception as e:
                logger.warning("SubdomainEnricher: Port scan failed: %s", e)
                port_map = {}
            
            # 3. コンテキスト構築
            for sub in new_subdomains:
                subdomain_context[sub] = {
                    "waf": waf_map.get(sub, "unknown"),
                    "ports": port_map.get(sub, []),
                    "source": "gau",  # Step 1 ではなく GAU から発見
                }
            
            logger.info("SubdomainEnricher: Enriched %d subdomains with WAF/Port context", len(subdomain_context))
        else:
            logger.info("SubdomainEnricher: No new subdomains found from GAU")
        
        # Katana で既に見つかったものは除外
        known_urls = {e["url"] for e in katana_entries}
        unique_gau_urls = [u for u in gau_urls if u not in known_urls]
        
        # URL サンプリング: 大量の URL を処理するとタイムアウトするため制限
        max_limit = getattr(settings, "max_httpx_urls", 500)
        if len(unique_gau_urls) > max_limit:
            logger.info("Sampling %d URLs out of %d for httpx (limit: %d)", 
                       max_limit, len(unique_gau_urls), max_limit)
            unique_gau_urls = unique_gau_urls[:max_limit]
        
        httpx_entries = []
        if unique_gau_urls:
            # Httpx で Live Check (Proxy 経由)
            gau_urls_file = self._get_path("gau_live_candidates", "txt")
            gau_urls_file.write_text("\n".join(unique_gau_urls))
            
            logger.info("Running Httpx on %d unique GAU URLs via proxy...", len(unique_gau_urls))
            httpx_out_raw = httpx.run(
                str(gau_urls_file), 
                mode="standard", 
                proxy=proxy_url,
                headers=auth_headers
            )
            
            for line in httpx_out_raw.splitlines():
                try:
                    if not line.strip(): continue
                    data = json.loads(line)
                    url = data.get("url", "")
                    
                    # URL からホストを抽出して subdomain_context を取得
                    entry_host = ""
                    try:
                        parsed = urlparse(url)
                        entry_host = parsed.netloc.lower()
                        if ":" in entry_host:
                            entry_host = entry_host.split(":")[0]
                    except Exception:
                        pass
                    
                    # Httpx to Caido Entry format (with subdomain context)
                    entry = {
                        "url": url,
                        "method": "GET",  # GAU gives URLs, implied GET
                        "response": {
                            "status": data.get("status_code", 0),
                            "body": data.get("body", ""),
                            "headers": data.get("header", {})
                        },
                        "headers": {},
                        # SubdomainEnricher コンテキスト追加
                        "subdomain_context": subdomain_context.get(entry_host, {
                            "waf": "unknown",
                            "ports": [],
                            "source": "step1"  # 既知サブドメイン
                        })
                    }
                    if entry["url"]:
                        httpx_entries.append(entry)
                except json.JSONDecodeError:
                    pass
            logger.info("Httpx confirmed %d live URLs", len(httpx_entries))
        
        # ====== 追加: Caido Integration ======
        caido_entries = []
        try:
            from src.core.agents.specialized.caido_sitemap_agent import CaidoSitemapAgent
            caido_agent = CaidoSitemapAgent()
            
            # ターゲットドメインを特定して履歴検索
            target_domain = self.target.replace("*.", "")
            try:
                parsed_target = urlparse(target_domain if "://" in target_domain else f"http://{target_domain}")
                normalized_target_domain = str(parsed_target.hostname or "").strip().lower()
                if normalized_target_domain:
                    target_domain = normalized_target_domain
            except Exception:
                pass
            
            logger.info("Executing CaidoSitemapAgent for domain: %s", target_domain)
            caido_contexts = await caido_agent.fetch_recent_requests(domain=target_domain, limit=500)
            
            for ctx in caido_contexts:
                # URLからホスト抽出（WAF等のサブドメインコンテキスト適用のため）
                entry_host = ""
                try:
                    parsed = urlparse(ctx.url)
                    entry_host = parsed.netloc.lower().split(":")[0]
                except Exception:
                    pass

                entry = {
                    "url": ctx.url,
                    "method": ctx.method,
                    "response": {
                        "status": ctx.response_status,
                        "body": "",  # ボディは一旦空
                        "headers": {}
                    },
                    "headers": ctx.headers,
                    "auth_context": ctx.auth_context,  # Caidoから抽出したCookieやAuthorization
                    "subdomain_context": subdomain_context.get(entry_host, {
                        "waf": "unknown",
                        "ports": [],
                        "source": "caido"
                    })
                }
                if entry["url"]:
                    caido_entries.append(entry)
                    
            logger.info("CaidoSitemapAgent extracted %d endpoints", len(caido_entries))
        except Exception as e:
            logger.warning("Failed to integrate Caido: %s", e)
        # ==================================

        # 3. Dynamic Recon with Playwright (XHR, Fetch Capture)
        logger.info("Executing Dynamic Recon with Playwright for XHR/Fetch capture...")
        playwright_entries = []
        try:
            from urllib.parse import urljoin, urlparse

            crawler = PlaywrightCrawler()
            auth_headers_map = self._get_context_auth_headers()
            cookies_str = str(auth_headers_map.get("Cookie", "") or "")

            scan_cfg = self.config.get("scan", {}) if isinstance(self.config, dict) else {}
            playwright_target_budget = int(
                scan_cfg.get("playwright_target_budget", getattr(settings, "playwright_target_budget", 12)) or 12
            )
            playwright_max_pages_per_seed = int(
                scan_cfg.get("playwright_max_pages_per_seed", getattr(settings, "playwright_max_pages_per_seed", 6)) or 6
            )
            playwright_max_clicks_per_page = int(
                scan_cfg.get("playwright_max_clicks_per_page", getattr(settings, "playwright_max_clicks_per_page", 6)) or 6
            )
            playwright_max_forms_per_page = int(
                scan_cfg.get("playwright_max_forms_per_page", getattr(settings, "playwright_max_forms_per_page", 3)) or 3
            )
            playwright_max_post_login_actions_per_page = int(
                scan_cfg.get(
                    "playwright_max_post_login_actions_per_page",
                    getattr(settings, "playwright_max_post_login_actions_per_page", 8),
                )
                or 8
            )
            playwright_max_route_hints_per_page = int(
                scan_cfg.get(
                    "playwright_max_route_hints_per_page",
                    getattr(settings, "playwright_max_route_hints_per_page", 20),
                )
                or 20
            )

            discovery_entries = katana_entries + httpx_entries + caido_entries
            targets_to_playwright = self._select_playwright_seed_targets(
                base_targets=katana_targets,
                discovered_entries=discovery_entries,
                budget=playwright_target_budget,
            )
            logger.info(
                "Playwright seeds selected: %d target(s) (budget=%d)",
                len(targets_to_playwright),
                playwright_target_budget,
            )

            crawl_errors: list[str] = []
            for target_url in targets_to_playwright:
                try:
                    p_result = await crawler.crawl(
                        target_url,
                        auth_headers=auth_headers_map or None,
                        cookies_str=cookies_str or None,
                        max_pages=playwright_max_pages_per_seed,
                        max_clicks_per_page=playwright_max_clicks_per_page,
                        max_forms_per_page=playwright_max_forms_per_page,
                        max_post_login_actions_per_page=playwright_max_post_login_actions_per_page,
                        max_route_hints_per_page=playwright_max_route_hints_per_page,
                    )
                    p_errors = p_result.get("errors", [])
                    if isinstance(p_errors, list):
                        for err in p_errors:
                            err_str = str(err or "").strip()
                            if err_str:
                                crawl_errors.append(f"{target_url}: {err_str}")
                    
                    # 結果を共通フォーマットに変換
                    for url_data in p_result.get("urls", []):
                        response_status = 0
                        if isinstance(url_data, str):
                            normalized_url = url_data.strip()
                            normalized_method = "GET"
                        elif isinstance(url_data, dict):
                            normalized_url = str(url_data.get("url", "") or "").strip()
                            normalized_method = str(url_data.get("method", "GET") or "GET")
                            try:
                                response_status = int(url_data.get("response_status", 0) or 0)
                            except Exception:
                                response_status = 0
                        else:
                            continue
                        if not normalized_url:
                            continue
                        # PlaywrightCrawler の出力を shim
                        entry = {
                            "url": normalized_url,
                            "method": normalized_method,
                            "headers": {}, # 必要に応じて追加
                            "body": "",
                            "response": {
                                "status": response_status,
                                "headers": {},
                                "body": ""
                            },
                            "source": "playwright_dynamic"
                        }
                        playwright_entries.append(entry)
                except Exception as e:
                    logger.warning(f"Playwright crawl failed for {target_url}: {e}")

            # Playwright 収集が空なら、動的候補URLを保険として注入する
            if not playwright_entries:
                fallback_paths_cfg = scan_cfg.get("playwright_fallback_paths", []) if isinstance(scan_cfg, dict) else []
                playwright_history_seed_limit = int(
                    scan_cfg.get(
                        "playwright_history_seed_limit",
                        getattr(settings, "playwright_history_seed_limit", 10),
                    )
                    or 10
                )
                tagged_history_replay_file_window = int(
                    scan_cfg.get(
                        "tagged_history_replay_file_window",
                        getattr(settings, "tagged_history_replay_file_window", 24),
                    )
                    or 24
                )
                default_fallback_paths = [
                    "/chatbot/genai/state",
                    "/profile",
                    "/orders/history?query=test",
                    "/search?q=test",
                    "/reviews",
                ]
                fallback_paths: list[str] = []
                if isinstance(fallback_paths_cfg, list):
                    for path in fallback_paths_cfg:
                        path_str = str(path or "").strip()
                        if path_str:
                            fallback_paths.append(path_str)
                if not fallback_paths:
                    fallback_paths = default_fallback_paths

                fallback_bases = targets_to_playwright if targets_to_playwright else katana_targets
                seeded_urls: list[str] = []
                seed_seen: set[str] = set()
                tagged_history_dir = self.workspace_root / "tagged_urls"
                history_seed_urls: list[str] = []
                if fallback_bases:
                    history_seed_urls = self._collect_recent_playwright_history_seeds(
                        tagged_dir=tagged_history_dir,
                        target_url=fallback_bases[0],
                        max_urls=playwright_history_seed_limit,
                        max_files=tagged_history_replay_file_window,
                    )
                for candidate in history_seed_urls:
                    candidate_str = str(candidate or "").strip()
                    if not candidate_str or candidate_str in seed_seen:
                        continue
                    if self._is_low_value_playwright_seed_url(candidate_str, allow_root=False):
                        continue
                    seed_seen.add(candidate_str)
                    seeded_urls.append(candidate_str)
                    if len(seeded_urls) >= max(1, playwright_target_budget):
                        break
                for base in fallback_bases[:3]:
                    if len(seeded_urls) >= max(1, playwright_target_budget):
                        break
                    base_str = str(base or "").strip()
                    if not base_str:
                        continue
                    parsed_base = urlparse(base_str)
                    if not parsed_base.scheme or not parsed_base.netloc:
                        continue
                    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
                    for path in fallback_paths:
                        candidate = urljoin(origin, path)
                        if candidate in seed_seen:
                            continue
                        if self._is_low_value_playwright_seed_url(candidate, allow_root=False):
                            continue
                        seed_seen.add(candidate)
                        seeded_urls.append(candidate)
                        if len(seeded_urls) >= max(1, playwright_target_budget):
                            break
                    if len(seeded_urls) >= max(1, playwright_target_budget):
                        break

                for candidate in seeded_urls:
                    playwright_entries.append(
                        {
                            "url": candidate,
                            "method": "GET",
                            "headers": {},
                            "body": "",
                            "response": {
                                "status": 0,
                                "headers": {},
                                "body": "",
                            },
                            "source": "playwright_seed_fallback",
                        }
                    )
                if seeded_urls:
                    logger.warning(
                        "Playwright returned no dynamic URLs. Injected %d fallback seed URL(s): %s",
                        len(seeded_urls),
                        ", ".join(seeded_urls[:5]),
                    )
                    if history_seed_urls:
                        logger.info(
                            "Playwright fallback included %d URL(s) from recent tagged history",
                            len([u for u in seeded_urls if u in set(history_seed_urls)]),
                        )
                else:
                    logger.warning("Playwright returned no dynamic URLs and no fallback seed URL could be built.")

            if crawl_errors:
                preview = "; ".join(crawl_errors[:3])
                logger.warning(
                    "Playwright crawl reported %d error(s). Sample: %s",
                    len(crawl_errors),
                    preview,
                )
            
            logger.info("Playwright dynamic recon found %d endpoints", len(playwright_entries))
        except Exception as e:
            logger.warning("Failed to run Playwright dynamic recon: %s", e)

        # 4. Merge & Tagging
        all_entries = katana_entries + httpx_entries + caido_entries + playwright_entries
        
        # 一時保存 (TaggingFilter 入力用)
        all_urls_file = self._get_path("all_urls_for_tagging", "json")
        all_urls_file.write_text(json.dumps(all_entries, ensure_ascii=False, indent=2))
        
        logger.info("Total %d URLs ready for tagging", len(all_entries))
        
        # TaggingFilter 実行
        tagged_output_dir = self.workspace_root / "tagged_urls"
        tagging_filter = TaggingFilter(project_name=self.state.project_name or "target")
        stats = tagging_filter.process_file(str(all_urls_file), str(tagged_output_dir))
        
        # URLClassifierによる拡張タグ付け（計画書4.1タクソノミー）
        try:
            url_classifier = URLClassifier()
            extended_tags_file = tagged_output_dir / "extended_taxonomy_tags.json"
            extended_results = []
            
            for entry in all_entries:
                url = entry.get("url", "") if isinstance(entry, dict) else str(entry)
                method = entry.get("method", "GET") if isinstance(entry, dict) else "GET"
                if url:
                    classification = url_classifier.classify(url, method)
                    if classification.tags:
                        extended_results.append({
                            "url": url,
                            "method": method,
                            "tags": list(classification.tags),
                            "primary_tag": classification.primary_tag,
                            "confidence": classification.confidence,
                        })
            
            if extended_results:
                extended_tags_file.write_text(
                    json.dumps(extended_results, ensure_ascii=False, indent=2)
                )
                logger.info(
                    "[URLClassifier] Extended taxonomy applied: %d URLs classified",
                    len(extended_results)
                )
                stats["extended_taxonomy"] = {
                    "file": str(extended_tags_file),
                    "count": len(extended_results),
                }
        except Exception as e:
            logger.warning("[URLClassifier] Extended tagging failed: %s", e)
        
        return stats

    async def step4_waf_detection(self, live_subs: list[str]) -> dict[str, str]:
        """Step 4: WAF検知
        
        wafw00f を使用してWAF/CDNを検出。
        
        Args:
            live_subs: ライブサブドメインリスト
        
        Returns:
            {subdomain: waf_name} のマッピング
        """
        logger.info("[Step 4] WAF Detection started")
        
        if not live_subs:
            logger.warning("[Step 4] No live subdomains available for WAF detection. Skipping.")
            return {}
        
        # ツールチェック
        # self.runner.check_tools(["wafw00f"])
        
        # live_subdomains.txt 作成
        live_subs_file = self._get_path("live_subdomains", "txt")
        live_subs_file.write_text("\n".join(live_subs))
        logger.info("Saved live subdomains to %s", live_subs_file)
        
        wafw00f_out = ""
        if self.runner.is_tool_available("wafw00f"):
            cmd = ["wafw00f", "-i", str(live_subs_file)]
            
            # Inject auth headers
            headers = self._get_auth_header_lines()
            if headers:
                # wafw00f's -H takes a filename, not a raw header string
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                    f.write("\n".join(headers))
                    headers_file = f.name
                cmd.extend(["-H", headers_file])

            try:
                wafw00f_out = await self.runner.run(
                    cmd,
                    timeout=600,
                    mock_output=(
                        "www.example.com is behind Cloudflare\n"
                        "api.example.com is not behind a WAF\n"
                    ),
                )
            finally:
                # Clean up the temporary headers file
                if 'headers_file' in locals():
                    import os
                    try:
                        os.unlink(headers_file)
                    except:
                        pass
        else:
            logger.warning("wafw00f not found, skipping")
        
        # 結果パース
        waf_map = {}
        for line in wafw00f_out.strip().split("\n"):
            if not line:
                continue
            # "www.example.com is behind Cloudflare" or "www.example.com is not behind a WAF"
            if " is behind " in line:
                parts = line.split(" is behind ")
                if len(parts) == 2:
                    waf_map[parts[0].strip()] = parts[1].strip()
            elif " is not behind " in line:
                parts = line.split(" is not behind ")
                if len(parts) == 2:
                    waf_map[parts[0].strip()] = "None"
        
        logger.info("[Step 4] WAF Detection completed: %d results", len(waf_map))
        
        # JSON形式で保存 (Step 6 で使用)
        import json
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        wafw00f_file = self._get_path("wafw00f", "json")
        wafw00f_file.write_text(json.dumps(waf_map, indent=2, ensure_ascii=False))
        logger.info("Saved wafw00f results: %s", wafw00f_file)
        
        return waf_map
    
    # === Step 5: Port Scan ===
    
    async def step5_port_scan_phase1(self, live_subs: list[str]) -> dict[str, list[str]]:
        """Step 5 Phase 1: Top 20 ポートスキャン (直列実行)
        
        naabu でトップ20ポートをスキャンし、nmap でサービス特定。
        
        Args:
            live_subs: ライブサブドメインリスト
        
        Returns:
            {host: [ports]} のマッピング
        """
        logger.info("[Step 5 Phase 1] Top 20 Port Scan started")
        
        if not live_subs:
            logger.warning("[Step 5 Phase 1] No live subdomains available for port scanning. Skipping.")
            return {}
        
        # ツールチェック
        # self.runner.check_tools(["naabu", "nmap"])
        
        # Top 20 ポートリスト (設計書より)
        top_20_ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
        
        # live_subs をファイルに書き出し
        live_subs_file = self._get_path("live_subs_for_portscan", "txt")
        live_subs_file.write_text("\n".join(live_subs))
        
        # naabu 実行
        naabu_out_file = self._get_path("naabu_top20", "txt")
        naabu_out = ""
        if self.runner.is_tool_available("naabu"):
            naabu_out = await self.runner.run(
                [
                    "naabu",
                    "-l", str(live_subs_file),
                    "-p", top_20_ports,
                    "-o", str(naabu_out_file),
                ],
                timeout=1800,  # 30分
                mock_output=(
                    "www.example.com:80 [http]\n"
                    "www.example.com:443 [https]\n"
                    "api.example.com:443 [https]\n"
                ),
            )
        else:
            logger.warning("naabu not found, skipping")
        
        # 結果パース
        port_map: dict[str, list[str]] = {}
        for line in naabu_out.strip().split("\n"):
            if not line or ":" not in line:
                continue
            # "www.example.com:80" or "www.example.com:80 [http]"
            parts = line.split(":")
            if len(parts) >= 2:
                host = parts[0].strip()
                port_info = parts[1].split()[0].strip()  # "80" from "80 [http]"
                if host not in port_map:
                    port_map[host] = []
                port_map[host].append(port_info)
        
        logger.info("[Step 5 Phase 1] Top 20 Port Scan completed: %d hosts with open ports", len(port_map))

        # naabu + nmap を分離して安定性と指紋深度を両立する
        if port_map and self.runner.is_tool_available("nmap"):
            nmap_targets_file = self._get_path("nmap_top20_targets", "txt")
            nmap_targets_file.write_text("\n".join(sorted(port_map.keys())))
            unique_ports = sorted(
                {port for ports in port_map.values() for port in ports},
                key=lambda p: int(p) if p.isdigit() else p,
            )
            nmap_out_file = self._get_path("nmap_top20_services", "txt")
            try:
                await self.runner.run(
                    [
                        "nmap",
                        "-sV",
                        "-sC",
                        "-iL",
                        str(nmap_targets_file),
                        "-p",
                        ",".join(unique_ports),
                        "-oN",
                        str(nmap_out_file),
                    ],
                    timeout=1800,  # 30分
                    mock_output="",
                )
                logger.info("Saved nmap service fingerprint: %s", nmap_out_file)
            except Exception as e:
                logger.warning("nmap service fingerprint step failed: %s", e)
        elif port_map:
            logger.warning("nmap not found, skipping service fingerprint step")
        
        # JSON形式でも保存 (Step 6 で使用)
        import json
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        naabu_json_file = self._get_path("naabu_top20", "json")
        naabu_json_file.write_text(json.dumps(port_map, indent=2, ensure_ascii=False))
        logger.info("Saved naabu JSON: %s", naabu_json_file)
        
        return port_map
    
    async def step5_port_scan_phase2(self, live_subs: list[str]) -> None:
        """
        Step 5 Phase 2: Full Port Scan & Dead Subdomain Scan (Parallel)
        
        バックグラウンドスレッドで実行し、メインフローは即座に進める (Fire and Forget)。
        MasterConductorのイベントループ寿命に依存しないよう、独立したスレッドとループを使用する。
        """
        import threading
        
        # スレッド名にタイムスタンプ等を付与して識別しやすくする
        import time
        thread_name = f"ReconWorker-{int(time.time())}"
        
        # デーモン=False にすることで、メインプロセス終了時もこのスレッドは生き残る
        # (すべての非デーモンスレッドが終了するまでプロセスは終了しない)
        t = threading.Thread(
            target=self._run_parallel_tasks_in_thread,
            args=(live_subs,),
            name=thread_name,
            daemon=False
        )
        t.start()
        
        logger.info(f"Launched background recon thread: {thread_name}")

    def _run_parallel_tasks_in_thread(self, live_subs: list[str]) -> None:
        """
        別スレッドで実行されるエントリーポイント。
        独自のイベントループを作成して非同期タスクを実行する。
        """
        import asyncio
        
        # 新しいイベントループを作成・設定
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            logger.info("Recon background thread started")
            loop.run_until_complete(self.run_parallel_tasks(live_subs))
        except Exception as e:
            logger.error(f"Recon background thread failed: {e}")
        finally:
            try:
                # 保留中のタスクがあればキャンセル
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                
                # キャンセル処理を実行させるために少し回す
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                
                loop.close()
                logger.info("Recon background thread event loop closed")
            except Exception as e:
                logger.error(f"Error closing recon background loop: {e}")
    
    # === Step 6-8: 分類・保存・返却 ===
    
    async def step6_classify(self) -> dict[str, Path]:
        """Step 6: 分類ファイル生成
        
        httpx/wafw00f/naabu/whatweb の結果を統合し、サブドメインを分類。
        
        分類カテゴリ:
        - HTTPステータス: live_200, live_403, live_401_302
        - サブドメイン名: dev_staging, internal_names, high_value
        - ポート: web_ports, database_ports, other_ports
        - テクノロジー: tech_nginx, tech_apache, tech_iis, tech_other
        - 未分類: live_uncategorized
        
        Returns:
            {category: file_path} の辞書
        """
        import json
        import re
        
        logger.info("[Step 6] Classification started")
        
        # === 1. 入力データ読み込み ===
        httpx_data = self._load_step_json("httpx") or []
        waf_data = self._load_step_json("wafw00f") or {}
        port_data = self._load_step_json("naabu_top20") or {}
        tech_data = self._load_step_json("whatweb") or []
        
        # whatweb データを subdomain -> tech[] にマッピング
        tech_map: dict[str, list[str]] = {}
        for item in tech_data:
            if isinstance(item, dict):
                target = item.get("target", "")
                plugins = item.get("plugins", {})
                # URL からホスト抽出
                import urllib.parse
                parsed = urllib.parse.urlparse(target)
                host = parsed.hostname or ""
                if host and plugins:
                    tech_list = list(plugins.keys())
                    tech_map[host] = tech_list
        
        # === 2. サブドメインごとに統合エントリ構築 ===
        entries: list[dict] = []
        for item in httpx_data:
            if not isinstance(item, dict):
                continue
            
            url = item.get("url", "")
            status_code = item.get("status_code", 0)
            
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            subdomain = parsed.hostname or ""
            
            if not subdomain:
                continue
            
            entry = {
                "subdomain": subdomain,
                "url": url,
                "status_code": status_code,
                "ports": port_data.get(subdomain, []),
                "waf": waf_data.get(subdomain),
                "tech": tech_map.get(subdomain, []),
            }
            entries.append(entry)
        
        logger.info("Built %d entries for classification", len(entries))
        
        # === 3. 分類パターン定義 ===
        SUBDOMAIN_PATTERNS = {
            "dev_staging": r"(^|\.)(dev|staging|test|uat|qa|sandbox|stg|preprod)\.",
            "internal_names": r"(^|\.)(internal|corp|intranet|vpn|private|local)\.",
            "high_value": r"(^|\.)(payment|billing|admin|secret|api-key|checkout|vault)\.",
        }
        
        WEB_PORTS = {80, 443, 8080, 8443, 3000, 5000}
        DATABASE_PORTS = {3306, 5432, 1433, 27017, 6379}

        # クラウド/CDNキーワード (小文字)
        CLOUD_KEYWORDS = {
            "cloud_aws": ["aws", "amazon", "cloudfront", "elastic beanstalk", "ec2"],
            "cloud_azure": ["azure", "microsoft", "frontdoor"],
            "cloud_gcp": ["google", "gcp", "app engine", "cloud storage"],
            "cloud_cloudflare": ["cloudflare"],
        }
        
        # === 4. 分類実行 ===
        classified: dict[str, list[dict]] = {
            # HTTPステータス
            "live_200": [],
            "live_403": [],
            "live_401_302": [],
            # サブドメイン名
            "dev_staging": [],
            "internal_names": [],
            "high_value": [],
            # ポート
            "web_ports": [],
            "database_ports": [],
            "other_ports": [],
            # テクノロジー
            "tech_nginx": [],
            "tech_apache": [],
            "tech_iis": [],
            "tech_other": [],
            # クラウド
            "cloud_aws": [],
            "cloud_azure": [],
            "cloud_gcp": [],
            "cloud_cloudflare": [],
            # 未分類
            "live_uncategorized": [],
        }
        
        for entry in entries:
            categorized = False
            subdomain = entry["subdomain"]
            status_code = entry["status_code"]
            ports = [int(p) for p in entry["ports"] if str(p).isdigit()]
            tech_list = entry["tech"]
            waf = entry["waf"] or ""
            
            # HTTPステータス分類
            if status_code == 200:
                classified["live_200"].append(entry)
                categorized = True
            elif status_code == 403:
                classified["live_403"].append(entry)
                categorized = True
            elif status_code in [401, 302, 307]:
                classified["live_401_302"].append(entry)
                categorized = True
            
            # サブドメイン名分類
            for category, pattern in SUBDOMAIN_PATTERNS.items():
                if re.search(pattern, subdomain, re.IGNORECASE):
                    classified[category].append(entry)
                    categorized = True
            
            # ポート分類
            port_set = set(ports)
            if port_set & WEB_PORTS:
                classified["web_ports"].append(entry)
                categorized = True
            if port_set & DATABASE_PORTS:
                classified["database_ports"].append(entry)
                categorized = True
            other_ports = port_set - WEB_PORTS - DATABASE_PORTS
            if other_ports:
                classified["other_ports"].append(entry)
                categorized = True
            
            # テクノロジー分類
            tech_lower = [t.lower() for t in tech_list]
            if any("nginx" in t for t in tech_lower):
                classified["tech_nginx"].append(entry)
                categorized = True
            elif any("apache" in t for t in tech_lower):
                classified["tech_apache"].append(entry)
                categorized = True
            elif any("iis" in t or "microsoft" in t for t in tech_lower):
                classified["tech_iis"].append(entry)
                categorized = True
            elif tech_list:
                classified["tech_other"].append(entry)
                categorized = True

            # クラウド分類
            combined_tech_waf = " ".join(tech_lower + [waf.lower()])
            for category, keywords in CLOUD_KEYWORDS.items():
                if any(k in combined_tech_waf for k in keywords):
                    classified[category].append(entry)
                    categorized = True
            
            # 未分類
            if not categorized:
                classified["live_uncategorized"].append(entry)
        
        # === 5. JSON ファイル保存 ===
        result: dict[str, Path] = {}
        for category, items in classified.items():
            if items:  # 空でない場合のみ保存
                file_path = self._get_path(category, "json")
                file_path.write_text(json.dumps(items, indent=2, ensure_ascii=False))
                result[category] = file_path
                logger.info("Saved %s: %d entries", category, len(items))
        
        # === 6. 既存ファイルをマージ ===
        existing_files = ["takeover_candidates", "buckets", "asn"]
        for name in existing_files:
            path = self._get_path(name, "json")
            if path.exists():
                result[name] = path
                logger.debug("Included existing file: %s", name)
        
        logger.info("[Step 6] Classification completed: %d categories", len(result))
        return result
    
    def _load_step_json(self, type_name: str) -> list | dict | None:
        """Step 1-5 で生成された JSON ファイルを読み込む"""
        import json
        
        file_path = self._get_path(type_name, "json")
        if not file_path.exists():
            logger.warning("File not found: %s", file_path)
            return None
        
        try:
            content = file_path.read_text()
            # 堅牢なパースを試行
            data = robust_json_loads(content)
            if not data:
                return None
            
            # 元々の I/F が list | dict | None なので、要素が1つならその要素を返す
            # (ただし whatweb のようにリスト前提の場合はリストのままの方が良いが、
            #  このメソッドの利用箇所に依存する)
            if len(data) == 1:
                return data[0]
            return data
        except Exception as e:
            logger.warning("Failed to parse JSON: %s - %s", file_path, e)
            return None

    def _collect_step8_tagged_candidates(self, tagged_urls_dir: Path) -> list[Path]:
        date_str = datetime.now().strftime("%Y%m%d")
        today_candidates = sorted(tagged_urls_dir.glob(f"{date_str}_*.jsonl"))
        if today_candidates:
            return today_candidates

        all_tagged = sorted(tagged_urls_dir.glob("*_tagged_*.jsonl"))
        if not all_tagged:
            return []

        latest_by_category: dict[str, Path] = {}
        for file_path in all_tagged:
            category = str(file_path.stem.split("_tagged_")[-1] or "").strip()
            if not category:
                continue
            existing = latest_by_category.get(category)
            if existing is None:
                latest_by_category[category] = file_path
                continue
            try:
                if file_path.stat().st_mtime > existing.stat().st_mtime:
                    latest_by_category[category] = file_path
            except Exception:
                continue

        selected = sorted(latest_by_category.values())
        if selected:
            logger.info(
                "No tagged URLs for current date (%s); using latest-per-category fallback (%d files)",
                date_str,
                len(selected),
            )
        return selected
    
    async def step7_save_to_project(self, classified_files: dict[str, Path]) -> None:
        """Step 7: ProjectManager に保存
        
        分類ファイルを ProjectManager の save_raw_scan で保存。
        
        Args:
            classified_files: 分類ファイルの辞書
        """
        logger.info("[Step 7] Saving to ProjectManager started")
        
        if not self.pm:
            logger.warning("ProjectManager not available, skipping save")
            return
        
        # 各ファイルを保存
        for category, file_path in classified_files.items():
            try:
                # save_raw_scan を呼び出し
                self.pm.save_raw_scan(
                    scan_type=category,
                    content=file_path.read_text(),
                    filename=file_path.name,
                )
                logger.debug("Saved %s: %s", category, file_path.name)
            except Exception as e:
                logger.warning("Failed to save %s: %s", category, e)
        
        logger.info("[Step 7] Saving to ProjectManager completed: %d files", len(classified_files))
    
    async def step8_return_to_mc(self, classified_files: dict[str, Path]) -> dict[str, dict]:
        """Step 8: MasterConductor へ結果返却
        
        分類ファイルのメタデータ付き辞書を返却。
        
        Args:
            classified_files: 分類ファイルの辞書
        
        Returns:
            {category: {file, count, description, tags}} の辞書
        """
        import json
        
        logger.info("[Step 8] Preparing results for MasterConductor")
        
        DESCRIPTIONS = {
            "live_200": "200 OKを返すライブサブドメイン",
            "live_403": "403 Forbiddenを返すサブドメイン（バイパス試行対象）",
            "live_401_302": "認証が必要なサブドメイン（401/302/307）",
            "dev_staging": "開発/ステージング環境のサブドメイン",
            "internal_names": "内部向けと思われるサブドメイン",
            "high_value": "決済/認証等の高価値サブドメイン",
            "web_ports": "Webポートが開いているホスト",
            "database_ports": "DBポートが開いているホスト（要確認）",
            "other_ports": "不明なポートが開いているホスト",
            "tech_nginx": "nginxで動作しているサブドメイン",
            "tech_apache": "Apacheで動作しているサブドメイン",
            "tech_iis": "IISで動作しているサブドメイン",
            "tech_other": "その他のテクノロジーで動作しているサブドメイン",
            "cloud_aws": "AWSを使用しているサブドメイン",
            "cloud_azure": "Azureを使用しているサブドメイン",
            "cloud_gcp": "GCPを使用しているサブドメイン",
            "cloud_cloudflare": "Cloudflareを使用しているサブドメイン",
            "live_uncategorized": "分類に該当しなかったサブドメイン",
            "takeover_candidates": "サブドメイン乗っ取り候補（NXDOMAIN/Dead）",
            "buckets": "S3/GCS/Azure等のクラウドストレージバケット",
            "asn": "ASN情報",
        }
        
        # カテゴリ → Swarm ルーティング用タグ
        CATEGORY_TAGS = {
            "live_200": ["has_params", "api_endpoint"],
            "live_403": ["403_response", "auth_required"],
            "live_401_302": ["401_response", "auth_endpoint", "auth_required"],
            "dev_staging": ["env_file", "config_file"],
            "internal_names": ["auth_required"],
            "high_value": ["payment_flow", "auth_endpoint", "auth_required"],
            "web_ports": ["api_endpoint", "has_params"],
            "database_ports": ["api_endpoint"],
            "other_ports": [],
            "tech_nginx": [],
            "tech_apache": [],
            "tech_iis": [],
            "tech_other": [],
            "cloud_aws": ["cloud_url"],
            "cloud_azure": ["cloud_url"],
            "cloud_gcp": ["cloud_url"],
            "cloud_cloudflare": [],
            "live_uncategorized": ["unknown_path"],
            "takeover_candidates": [],
            "buckets": ["cloud_url"],
            "asn": [],
        }
        
        result = {}
        direct_enqueue_skip_categories = {"meta_observability", "realtime"}
        for category, file_path in classified_files.items():
            try:
                # ファイルからcount取得
                data = json.loads(file_path.read_text())
                count = len(data) if isinstance(data, list) else 1
                
                result[category] = {
                    "file": str(file_path),
                    "count": count,
                    "description": DESCRIPTIONS.get(category, f"{category}の分類結果"),
                    "tags": CATEGORY_TAGS.get(category, []),  # Swarm ルーティング用タグ
                }
            except Exception as e:
                logger.warning("Failed to read %s: %s", category, e)
        
        # Step 3b で保存した tagged_urls を読み込み
        tagged_urls_dir = self.pm.project_dir / "tagged_urls"
        if tagged_urls_dir.exists():
            tagged_candidates = self._collect_step8_tagged_candidates(tagged_urls_dir)
            for file_path in tagged_candidates:
                try:
                    # ファイル名からカテゴリ推定 (e.g. 20260211_target_tagged_id_param.jsonl -> id_param)
                    category = file_path.stem.split("_tagged_")[-1]
                    # promoted ファイルは uncategorized 処理時に取り込み済みのため再読込しない
                    if "_promoted_" in category:
                        logger.debug("Skipping promoted tagged file to avoid duplicate counting: %s", file_path.name)
                        continue
                    if category == "uncategorized":
                        promoted = self._promote_uncategorized_tagged_file(file_path)
                        existing_promoted_pattern = f"{file_path.stem}_promoted_*.jsonl"
                        for promoted_path in sorted(file_path.parent.glob(existing_promoted_pattern)):
                            promoted_category = str(promoted_path.stem.split("_promoted_")[-1] or "").strip()
                            if not promoted_category:
                                continue
                            if promoted_category not in promoted:
                                promoted[promoted_category] = promoted_path
                        for promoted_category, promoted_path in promoted.items():
                            promoted_count = 0
                            with open(promoted_path, "r", encoding="utf-8") as pf:
                                promoted_count = sum(1 for _ in pf)
                            if promoted_count <= 0:
                                continue
                            promoted_tags = self._map_tagged_category_to_tags(promoted_category)
                            result_key = f"tagged_{promoted_category}"
                            existing = result.get(result_key)
                            if existing:
                                existing["count"] = int(existing.get("count", 0)) + promoted_count
                            else:
                                result[result_key] = {
                                    "file": str(promoted_path),
                                    "count": promoted_count,
                                    "description": f"Tagged URLs ({promoted_category}) [promoted from uncategorized]",
                                    "tags": promoted_tags,
                                }
                            if (
                                self.mc
                                and promoted_count > 0
                                and promoted_category not in direct_enqueue_skip_categories
                            ):
                                self._generate_tasks_for_tagged_urls(promoted_category, promoted_path, promoted_tags)
                            elif self.mc and promoted_count > 0:
                                logger.debug(
                                    "Skipping direct enqueue for promoted category '%s' (handled by MC expansion)",
                                    promoted_category,
                                )

                    count = 0
                    with open(file_path, "r") as f:
                        count = sum(1 for _ in f)
                    
                    if count > 0:
                        mapped_tags = self._map_tagged_category_to_tags(category)
                        
                        result[f"tagged_{category}"] = {
                            "file": str(file_path),
                            "count": count,
                            "description": f"Tagged URLs ({category})",
                            "tags": mapped_tags,
                        }
                        
                        # MasterConductorに直接タスクを追加（Phase 3b統合）
                        if self.mc and count > 0 and category not in direct_enqueue_skip_categories:
                            self._generate_tasks_for_tagged_urls(category, file_path, mapped_tags)
                        elif self.mc and count > 0:
                            logger.debug(
                                "Skipping direct enqueue for category '%s' (handled by MC expansion)",
                                category,
                            )
                            
                except Exception as e:
                    logger.warning("Failed to read tagged urls %s: %s", file_path, e)
        
        # tech_stack からタグを追加
        if self.state.tech_stack:
            result["_tech_stack"] = {
                "technologies": self.state.tech_stack,
                "tags": self._generate_tech_tags(self.state.tech_stack),
            }
        
        logger.info("[Step 8] Returning %d categorized results to MC", len(result))
        
        return result
    
    def _generate_tech_tags(self, tech_stack: list[str]) -> list[str]:
        """tech_stack から Swarm ルーティング用タグを生成"""
        tags = []
        tech_lower = [t.lower() for t in tech_stack]
        
        # JWT/OAuth 検出
        if any("jwt" in t for t in tech_lower):
            tags.append("jwt_token")
        if any("oauth" in t or "openid" in t for t in tech_lower):
            tags.append("oauth_flow")
        
        # API フレームワーク検出
        if any(t in tech_lower for t in ["graphql", "rest", "api", "swagger", "openapi"]):
            tags.append("api_endpoint")
        
        # JavaScript 関連
        if any(t in tech_lower for t in ["react", "vue", "angular", "next.js", "nuxt"]):
            tags.append("js_file")
        
        return tags

    def _map_tagged_category_to_tags(self, category: str) -> list[str]:
        return tags_for_category(category)

    def _promote_uncategorized_tagged_file(self, file_path: Path) -> dict[str, Path]:
        """
        tagged_uncategorized のうち、低セキュリティで重要な csrf/api/fi(page) を昇格させる。
        元ファイルは昇格分を除外して上書きする。
        """
        import json
        import re
        from urllib.parse import urlparse, parse_qs, unquote

        realtime_target_budget = 5
        try:
            scan_cfg = self.config.get("scan", {}) if isinstance(self.config, dict) else {}
            realtime_target_budget = int(scan_cfg.get("realtime_target_budget", 5) or 5)
        except Exception:
            realtime_target_budget = 5

        promoted_items: dict[str, list[dict[str, Any]]] = {
            "admin": [],
            "auth": [],
            "product_search": [],
            "basket_order": [],
            "feedback_review": [],
            "file_exposure_upload": [],
            "api_data": [],
            "client_route_dom": [],
            "realtime": [],
            "meta_observability": [],
            "file_param": [],
            "csrf_candidate": [],
            "api_candidate": [],
            "cors_candidate": [],
            "external_link": [],
            "invalid_candidate": [],
        }
        remaining_items: list[dict[str, Any]] = []
        seen_realtime_keys: set[str] = set()
        skipped_realtime_duplicates = 0
        skipped_auth_non_success = 0
        target_host = ""
        try:
            target_host = (urlparse(str(self.target or "")).hostname or "").strip().lower()
        except Exception:
            target_host = ""

        def normalize_realtime_target_key(url: str) -> str:
            candidate = str(url or "").strip()
            if not candidate:
                return ""
            parsed = urlparse(candidate)
            query = parse_qs(parsed.query, keep_blank_values=True)
            for volatile in ("t", "sid"):
                query.pop(volatile, None)
            stable_pairs: list[tuple[str, str]] = []
            for key in sorted(query.keys()):
                for val in query.get(key, []):
                    stable_pairs.append((key, val))
            stable_query = "&".join(f"{k}={v}" for k, v in stable_pairs)
            if stable_query:
                return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{stable_query}"
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        def classify(item: dict[str, Any]) -> str:
            url = str(item.get("url", "") or "")
            parsed = urlparse(str(url or ""))
            path = (parsed.path or "").lower()
            query_keys = {k.lower() for k in parse_qs(parsed.query).keys()}
            fragment = (parsed.fragment or "").lower()
            fragment_path = fragment.split("?", 1)[0]
            path_tokens = {token for token in path.strip("/").split("/") if token}
            host = (parsed.hostname or parsed.netloc or "").strip().lower()
            method = str(item.get("method", "GET") or "GET").upper()
            response_headers = (
                item.get("response_headers")
                or item.get("response", {}).get("headers", {})
                or {}
            )
            if not isinstance(response_headers, dict):
                response_headers = {}
            content_type = ""
            for key, value in response_headers.items():
                if str(key).lower() == "content-type":
                    content_type = str(value).lower()
                    break
            path_ext = Path(path).suffix.lower()
            static_asset_exts = {
                ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf"
            }
            decoded_any = " ".join(
                [
                    unquote(parsed.path or ""),
                    unquote(parsed.query or ""),
                    unquote(parsed.fragment or ""),
                ]
            ).lower()

            def host_is_external() -> bool:
                if not host or not target_host:
                    return False
                if host == target_host:
                    return False
                if host.endswith(f".{target_host}") or target_host.endswith(f".{host}"):
                    return False
                return True

            def is_invalid_candidate() -> bool:
                # テンプレート未展開やJS断片など、攻撃対象として意味の薄い壊れたURL候補
                if "%7b%7b" in str(url).lower() or "%7d%7d" in str(url).lower():
                    return True
                if "{{" in decoded_any and "}}" in decoded_any:
                    return True
                if re.search(r"[\"']\s*\+\s*[a-z_$][\w$]*(?:\(|\[)", decoded_any):
                    return True
                return False

            def looks_api_like() -> bool:
                if any(token in path for token in ["/rest/", "/api/", "graphql", "openapi", "swagger"]):
                    return True
                if path_tokens & {"api", "graphql", "gql", "rpc", "rest"}:
                    return True
                if len(path_tokens) >= 2 and any(re.fullmatch(r"v\d+", token) for token in path_tokens):
                    return True
                if (path_tokens & {"chatbot", "genai", "assistant", "ai"}) and (
                    path_tokens & {"state", "session", "message", "messages", "history", "conversation", "prompt", "completion"}
                ):
                    return True
                if (
                    method in {"GET", "POST", "PUT", "PATCH", "DELETE"}
                    and "application/json" in content_type
                    and len(path_tokens) >= 2
                    and path_ext not in static_asset_exts
                ):
                    return True
                return False

            # Framework-agnostic分類: 固有製品のURL固定値よりも機能トークンを優先
            if any(token in path for token in ["/socket.io/", "/ws", "/websocket", "/realtime"]) or "websocket" in parsed.query.lower():
                return "realtime"
            if host_is_external():
                return "external_link"
            if is_invalid_candidate():
                return "invalid_candidate"
            if path_tokens & {
                "admin", "administrator", "dashboard", "console", "manage", "manager", "panel",
                "role", "roles", "permission", "permissions", "acl", "rbac", "tenant", "tenants",
                "organization", "organizations",
            }:
                return "admin"
            if (
                query_keys & {"role", "role_id", "permission", "permission_id", "tenant", "tenant_id", "organization_id", "org_id", "user_id", "account_id"}
                and path_tokens & {"users", "user", "accounts", "account", "manage", "admin", "settings", "team", "teams"}
            ):
                return "admin"
            if path_tokens & {"login", "signin", "sign-in", "register", "signup", "logout", "session", "auth", "oauth", "sso", "token"}:
                return "auth"
            if path_tokens & {"account", "accounts", "profile", "profiles", "me"} and path_ext not in static_asset_exts:
                return "auth"
            if query_keys & {"q", "query", "search", "keyword"} and (path_tokens & {"search", "product", "products", "item", "items", "catalog"}):
                return "product_search"
            if path_tokens & {
                "basket", "cart", "order", "orders", "checkout", "coupon", "payment", "invoice",
                "wallet", "balance", "redeem", "voucher", "discount", "promo", "subscription", "plan", "billing",
            }:
                return "basket_order"
            if (
                query_keys & {"coupon", "voucher", "promo", "discount", "amount", "price", "quantity", "qty", "points"}
                and path_tokens & {"wallet", "redeem", "checkout", "order", "orders", "cart", "payment", "purchase", "billing", "invoice"}
            ):
                return "basket_order"
            if path_tokens & {"feedback", "review", "reviews", "comment", "comments", "complaint", "complaints", "rating"}:
                return "feedback_review"
            if path_tokens & {"ftp", "upload", "uploads", "download", "downloads", "backup", "backups", "exports", "imports", "files", "attachments", "media"}:
                return "file_exposure_upload"
            if query_keys & {"file", "path", "page", "include", "template", "download", "folder", "doc"}:
                return "file_exposure_upload"
            if path_tokens & {"metrics", "health", "healthz", "status", "version", "config", "configuration", "settings", "logs", "log", "locale", "language", "languages", "i18n"}:
                return "meta_observability"
            # CORS: レスポンスヘッダーに Access-Control-Allow-Origin が存在するURLを分類
            acao_present = any(
                str(k).lower() == "access-control-allow-origin"
                for k in response_headers.keys()
            )
            if acao_present:
                return "cors_candidate"

            if looks_api_like():
                return "api_data"
            if fragment_path.startswith("/") and any(token in fragment_path for token in [
                "/search",
                "/admin",
                "/basket",
                "/account",
                "/profile",
                "/complaint",
                "/contact",
            ]):
                return "client_route_dom"
            if any(token in path for token in ["/rest/", "/api/", "graphql", "openapi", "swagger"]):
                return "api_data"
            if any(token in path for token in ["/vulnerabilities/csrf/", "/csrf/", "csrf"]):
                return "csrf_candidate"
            if any(token in path for token in ["/vulnerabilities/api/", "/api/", "graphql", "openapi", "swagger"]):
                return "api_candidate"
            if any(token in path for token in ["/vulnerabilities/fi/", "/fi/", "file_inclusion", "inclusion"]):
                return "file_param"
            if query_keys & {"page", "file", "path", "include", "template"}:
                return "file_param"
            return ""

        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    item = json.loads(line)
                    url = str(item.get("url", "") or "")
                    promoted_category = classify(item)
                    if promoted_category:
                        if promoted_category == "auth":
                            try:
                                response_status = int(item.get("response_status", 0) or 0)
                            except Exception:
                                response_status = 0
                            if response_status >= 400:
                                skipped_auth_non_success += 1
                                remaining_items.append(item)
                                continue
                        if promoted_category == "realtime":
                            normalized_key = normalize_realtime_target_key(url)
                            if not normalized_key:
                                remaining_items.append(item)
                                continue
                            if normalized_key in seen_realtime_keys:
                                skipped_realtime_duplicates += 1
                                continue
                            seen_realtime_keys.add(normalized_key)
                        promoted_items[promoted_category].append(item)
                    else:
                        remaining_items.append(item)

            capped_realtime = 0
            if realtime_target_budget > 0 and len(promoted_items["realtime"]) > realtime_target_budget:
                capped_realtime = len(promoted_items["realtime"]) - realtime_target_budget
                promoted_items["realtime"] = promoted_items["realtime"][:realtime_target_budget]

            with open(file_path, "w", encoding="utf-8") as fh:
                for item in remaining_items:
                    fh.write(json.dumps(item, ensure_ascii=False) + "\n")

            created: dict[str, Path] = {}
            for category, items in promoted_items.items():
                if not items:
                    continue
                promoted_path = file_path.with_name(f"{file_path.stem}_promoted_{category}.jsonl")
                with open(promoted_path, "w", encoding="utf-8") as out:
                    for item in items:
                        out.write(json.dumps(item, ensure_ascii=False) + "\n")
                created[category] = promoted_path

            if created:
                logger.info(
                    "Promoted %d uncategorized URLs from %s (%s)",
                    sum(len(v) for v in promoted_items.values()),
                    file_path.name,
                    ", ".join([f"{k}:{len(promoted_items[k])}" for k in created.keys()]),
                )
                if skipped_realtime_duplicates > 0:
                    logger.info(
                        "Skipped %d duplicate realtime URLs during uncategorized promotion (normalized by t/sid)",
                        skipped_realtime_duplicates,
                    )
                if skipped_auth_non_success > 0:
                    logger.info(
                        "Skipped %d auth promoted URLs due to non-success response_status (>=400)",
                        skipped_auth_non_success,
                    )
                if capped_realtime > 0:
                    logger.info(
                        "Capped realtime promoted URLs by budget: dropped=%d budget=%d",
                        capped_realtime,
                        realtime_target_budget,
                    )
            return created
        except Exception as e:
            logger.warning("Failed to promote uncategorized tagged URLs from %s: %s", file_path, e)
            return {}

    def _collect_recent_authz_history_urls(
        self,
        file_path: Path,
        current_urls: list[str],
        target_category: str = "auth",
    ) -> list[str]:
        """
        直近の tagged_urls から AuthZ 系 URL を補完する。

        Katana/Caido の収集揺らぎで authbypass 系ページが当日ログから欠落するケースに備え、
        同一ホストの直近 tagged_auth/tagged_id_param から再試行候補を少量復元する。
        """
        max_urls = int(getattr(settings, "authz_history_replay_limit", 4) or 4)
        max_files = int(getattr(settings, "tagged_history_replay_file_window", 24) or 24)
        return self._collect_recent_tagged_history_urls(
            file_path=file_path,
            current_urls=current_urls,
            categories=("auth", "id_param"),
            target_category=target_category,
            token_hints=(
                "authbypass",
                "get_user_data",
                "weak_id",
                "login",
                "signin",
                "auth",
                "oauth",
                "token",
                "jwt",
                "session",
                "account",
                "profile",
                "admin",
                "role",
                "permission",
                "id=",
                "user_id=",
                "account_id=",
                "order_id=",
                "report_id=",
                "video_id=",
            ),
            max_urls=max_urls,
            max_files=max_files,
        )

    def _collect_recent_tagged_history_urls(
        self,
        file_path: Path,
        current_urls: list[str],
        categories: tuple[str, ...],
        target_category: str = "",
        token_hints: tuple[str, ...] = (),
        max_urls: int = 6,
        max_files: int = 24,
    ) -> list[str]:
        from urllib.parse import parse_qs, unquote, urlparse

        current_host = ""
        if current_urls:
            current_host = urlparse(current_urls[0]).netloc.lower()
        if not current_host:
            current_host = urlparse(str(self.target or "")).netloc.lower()
        if not current_host:
            return []

        tagged_dir = file_path.parent
        if not tagged_dir.exists():
            return []

        category_set = {str(c or "").strip() for c in categories if str(c or "").strip()}
        if not category_set:
            return []

        candidate_files: list[Path] = []
        for category in sorted(category_set):
            candidate_files.extend(tagged_dir.glob(f"*_tagged_{category}.jsonl"))
            candidate_files.extend(tagged_dir.glob(f"*_tagged_uncategorized_promoted_{category}.jsonl"))

        if not candidate_files:
            return []

        max_files = max(1, int(max_files or 1))
        max_urls = max(1, int(max_urls or 1))
        candidate_files = sorted(
            [p for p in candidate_files if p.resolve() != file_path.resolve()],
            reverse=True,
        )[:max_files]

        collected: list[str] = []
        seen = {str(u).strip() for u in current_urls if str(u).strip()}
        token_hints_norm = tuple(str(token or "").lower() for token in token_hints if str(token or "").strip())
        normalized_target_category = str(target_category or "").strip().lower()

        def _is_history_replay_candidate_compatible(url: str, item: dict[str, Any]) -> bool:
            try:
                response_status = int(item.get("response_status", 0) or 0)
            except Exception:
                response_status = 0
            if response_status >= 400:
                return False

            if normalized_target_category != "auth":
                return True

            parsed = urlparse(str(url or "").strip())
            decoded_path = unquote(parsed.path or "")
            path_tokens = {token for token in decoded_path.lower().strip("/").split("/") if token}
            query_keys = {k.lower() for k in parse_qs(parsed.query, keep_blank_values=True).keys()}

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

            return True

        for hist_file in candidate_files:
            try:
                with open(hist_file, "r", encoding="utf-8") as fh:
                    for idx, line in enumerate(fh):
                        if idx >= 400:
                            break
                        parsed_items = robust_json_loads(line)
                        if not isinstance(parsed_items, list):
                            continue
                        for item in parsed_items:
                            if not isinstance(item, dict):
                                continue
                            url = str(item.get("url", "") or "").strip()
                            if not url or url in seen:
                                continue
                            if not _is_history_replay_candidate_compatible(url, item):
                                continue
                            parsed = urlparse(url)
                            if (parsed.netloc or "").lower() != current_host:
                                continue
                            if token_hints_norm:
                                path_query = f"{parsed.path}?{parsed.query}".lower()
                                if not any(token in path_query for token in token_hints_norm):
                                    continue
                            if self._is_low_value_playwright_seed_url(url, allow_root=False):
                                continue
                            collected.append(url)
                            seen.add(url)
                            if len(collected) >= max_urls:
                                return collected
            except Exception:
                continue

        return collected

    @staticmethod
    def _extract_nested_keys(payload: Any, prefix: str = "") -> set[str]:
        keys: set[str] = set()
        if isinstance(payload, dict):
            for raw_key, value in payload.items():
                key = str(raw_key or "").strip()
                if not key:
                    continue
                full = f"{prefix}.{key}" if prefix else key
                keys.add(full.lower())
                keys |= ReconPipeline._extract_nested_keys(value, full)
        elif isinstance(payload, list):
            for item in payload:
                keys |= ReconPipeline._extract_nested_keys(item, prefix)
        return keys

    def _score_ssrf_candidate(self, url: str, item: dict[str, Any]) -> tuple[int, dict[str, int]]:
        """
        SSRF 候補の即効スコアを算出する（Wave B）。
        URL/Body/GraphQL variables/Header 文脈を加点し、0-100に正規化する。
        """
        import re
        from urllib.parse import parse_qs, urlparse

        breakdown = {
            "query_url_param": 0,
            "body_url_param": 0,
            "graphql_variables": 0,
            "header_context": 0,
            "path_context": 0,
        }
        parsed = urlparse(str(url or "").strip())
        query_keys = {k.lower() for k in parse_qs(parsed.query, keep_blank_values=True).keys()}
        path_lower = str(parsed.path or "").lower()

        url_like_keys = {
            "url", "uri", "endpoint", "host", "target", "dest", "destination",
            "src", "source", "fetch", "load", "remote", "request", "webhook", "callback",
        }
        if query_keys & url_like_keys:
            breakdown["query_url_param"] = min(30, 12 + (len(query_keys & url_like_keys) * 6))

        if any(token in path_lower for token in ("proxy", "fetch", "import", "webhook", "callback", "redirect")):
            breakdown["path_context"] = 14

        body_text = str(item.get("body", "") or "")
        parsed_body = None
        if body_text:
            parsed_body_list = robust_json_loads(body_text)
            if parsed_body_list and isinstance(parsed_body_list[0], dict):
                parsed_body = parsed_body_list[0]
        if isinstance(parsed_body, dict):
            nested_keys = self._extract_nested_keys(parsed_body)
            if any(k.split(".")[-1] in url_like_keys for k in nested_keys):
                breakdown["body_url_param"] = 20

            graphql_key_like = {"variables", "operationname", "query", "mutation"}
            if any(k.split(".")[-1] in graphql_key_like for k in nested_keys):
                variable_like_hits = [
                    k for k in nested_keys
                    if ".variables." in k and k.split(".")[-1] in url_like_keys
                ]
                if variable_like_hits:
                    breakdown["graphql_variables"] = 24
                else:
                    breakdown["graphql_variables"] = 10
        else:
            body_lower = body_text.lower()
            if re.search(r'"(url|uri|endpoint|target|webhook|callback)"\s*:', body_lower):
                breakdown["body_url_param"] = 14
            if "variables" in body_lower and re.search(r'"variables"\s*:\s*{', body_lower):
                breakdown["graphql_variables"] = max(breakdown["graphql_variables"], 10)

        headers = item.get("headers", {})
        if not isinstance(headers, dict):
            headers = {}
        header_keys = {str(k).strip().lower() for k in headers.keys()}
        if header_keys & {
            "x-forwarded-host",
            "x-original-url",
            "x-rewrite-url",
            "referer",
            "origin",
        }:
            breakdown["header_context"] = 12

        score = max(0, min(100, sum(int(v) for v in breakdown.values())))
        return score, breakdown
    
    def _generate_tasks_for_tagged_urls(self, category: str, file_path: Path, tags: list[str]) -> None:
        """タグ付けされたURLに対して攻撃タスクを生成
        
        Args:
            category: URLカテゴリ (id_param, file_param等)
            file_path: 対象のJSONLファイルパス
            tags: 関連タグリスト
        """
        import json
        import uuid
        from urllib.parse import parse_qs, urlparse, urlsplit
        from src.core.agents.swarm.base import Task
        
        # カテゴリごとのタスクマッピング（実在するエージェントを使用）
        task_mapping = {
            "id_param": {
                "agent": "InjectionManagerAgent",  # SQLi/XSSを含むインジェクション全般
                "action": "scan",
                "priority": 80,
                "name": "Injection Scan (SQLi/XSS) on Parameters"
            },
            "admin": {
                "agent": "bizlogic",
                "action": "scan",
                "priority": 88,
                "name": "Admin Access Control Scan"
            },
            "file_param": {
                "agent": "InjectionManagerAgent",  # LFI/Path Traversalもインジェクション
                "action": "scan",
                "priority": 85,
                "name": "Path Injection Scan (LFI/Traversal)"
            },
            "redirect_param": {
                "agent": "InjectionManagerAgent",  # SSRF/Open Redirect も Injection の一種
                "action": "scan",
                "priority": 75,
                "name": "Open Redirect/SSRF Scan"
            },
            "xss_candidate": {
                "agent": "InjectionManagerAgent",  # XSS 専用スキャン
                "action": "scan",
                "priority": 82,
                "name": "XSS Injection Scan"
            },
            "upload": {
                "agent": "LogicSwarm",  # File Upload Specialization
                "action": "scan",
                "priority": 90,
                "name": "File Upload Vulnerability Scan"
            },
            "auth": {
                "agent": "AuthNinja",
                "action": "scan",
                "priority": 70,
                "name": "Authentication Analysis"
            },
            "product_search": {
                "agent": "InjectionManagerAgent",
                "action": "scan",
                "priority": 86,
                "name": "Product Search Injection Scan"
            },
            "basket_order": {
                "agent": "LogicSwarm",
                "action": "scan",
                "priority": 84,
                "name": "Basket/Order Logic Scan"
            },
            "feedback_review": {
                "agent": "InjectionManagerAgent",
                "action": "scan",
                "priority": 81,
                "name": "Feedback/Review Input Security Scan"
            },
            "file_exposure_upload": {
                "agent": "InjectionManagerAgent",
                "action": "scan",
                "priority": 87,
                "name": "File Exposure and Upload Security Scan"
            },
            "api_data": {
                "agent": "InjectionManagerAgent",
                "action": "scan",
                "priority": 83,
                "name": "API Data Security Scan"
            },
            "client_route_dom": {
                "agent": "InjectionManagerAgent",
                "action": "scan",
                "priority": 79,
                "name": "Client Route DOM Security Scan"
            },
            "realtime": {
                "agent": "DiscoverySwarm",
                "action": "scan",
                "priority": 76,
                "name": "Realtime Endpoint Security Recon"
            },
            "meta_observability": {
                "agent": "DiscoverySwarm",
                "action": "scan",
                "priority": 74,
                "name": "Meta/Observability Exposure Scan"
            },
            "csrf_candidate": {
                "agent": "InjectionManagerAgent",
                "action": "scan",
                "priority": 84,
                "name": "CSRF Minimal Security Check"
            },
            "api_candidate": {
                "agent": "InjectionManagerAgent",
                "action": "scan",
                "priority": 83,
                "name": "API Minimal Security Check"
            },
            "ssti_candidate": {
                "agent": "InjectionManagerAgent",
                "action": "scan",
                "priority": 88,
                "name": "SSTI Injection Scan"
            },
            "cors_candidate": {
                "agent": "InjectionManagerAgent",
                "action": "scan",
                "priority": 80,
                "name": "CORS Misconfiguration Scan"
            },
            "crlf_candidate": {
                "agent": "InjectionManagerAgent",
                "action": "scan",
                "priority": 65,
                "name": "CRLF Injection Scan"
            },
            "graphql_candidate": {
                "agent": "InjectionManagerAgent",
                "action": "scan",
                "priority": 72,
                "name": "GraphQL Introspection Scan"
            },
            "ssrf_candidate": {
                "agent": "InjectionManagerAgent",
                "action": "scan",
                "priority": 80,
                "name": "SSRF Response-based Scan"
            }
        }
        
        if category not in task_mapping:
            logger.debug(f"No task mapping for category: {category}")
            return
            
        task_config = task_mapping[category]
        
        try:
            # JSONLファイルからURL読み込み（最大20件に制限）
            # JSONL ファイルから URL とフォーム情報を読み込み（最大 20 件に制限）
            urls = []
            seen_urls = set()
            seen_url_keys = set()
            forms_by_url = {}  # URL ごとのフォーム情報を保持
            url_evidence_by_url = {}  # URL ごとの分類証拠を保持
            realtime_target_budget = 5
            meta_target_budget = 3
            tagged_target_cap = 20
            tagged_scan_window = 200
            try:
                scan_cfg = self.config.get("scan", {}) if isinstance(self.config, dict) else {}
                realtime_target_budget = int(scan_cfg.get("realtime_target_budget", 5) or 5)
                meta_target_budget = int(scan_cfg.get("meta_observability_target_budget", 3) or 3)
                tagged_target_cap = int(scan_cfg.get("tagged_candidate_target_cap", 20) or 20)
                tagged_scan_window = int(scan_cfg.get("tagged_candidate_scan_window", 200) or 200)
            except Exception:
                realtime_target_budget = 5
                meta_target_budget = 3
                tagged_target_cap = 20
                tagged_scan_window = 200

            tagged_target_cap = max(1, tagged_target_cap)
            tagged_scan_window = max(tagged_target_cap, tagged_scan_window)

            def normalize_target_key(candidate_url: str) -> str:
                if category != "realtime":
                    return candidate_url
                parsed = urlparse(candidate_url)
                query = parse_qs(parsed.query, keep_blank_values=True)
                # socket/realtime系で変動しやすいセッション識別子は除外して重複を抑える
                for volatile in ("t", "sid"):
                    query.pop(volatile, None)
                stable_pairs = []
                for key in sorted(query.keys()):
                    for val in query.get(key, []):
                        stable_pairs.append((key, val))
                stable_query = "&".join(f"{k}={v}" for k, v in stable_pairs)
                return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{stable_query}"

            def is_low_value_injection_target(candidate_url: str, item: dict | None = None) -> bool:
                injection_like_categories = {
                    "xss_candidate",
                    "product_search",
                    "feedback_review",
                    "client_route_dom",
                    "api_data",
                    "api_candidate",
                    "csrf_candidate",
                }
                if category not in injection_like_categories:
                    return False

                parsed_url = urlparse(candidate_url)
                path_lower = (parsed_url.path or "").lower()
                candidate_url_lower = candidate_url.lower()
                query_keys = {k.lower() for k in parse_qs(parsed_url.query).keys()}

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

                has_form_signals = False
                if isinstance(item, dict):
                    forms = item.get("forms", [])
                    has_form_signals = isinstance(forms, list) and len(forms) > 0

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

            def should_include_url(candidate_url: str, item: dict | None = None) -> bool:
                parsed_url = urlparse(candidate_url)
                path_lower = (parsed_url.path or "").lower()
                query_keys = {k.lower() for k in parse_qs(parsed_url.query).keys()}

                redirect_keys = {"redirect", "url", "next", "dest", "destination", "return", "goto", "callback", "continue"}
                file_keys = {"file", "path", "page", "include", "template", "doc", "download", "folder"}

                if category == "id_param":
                    if any(token in path_lower for token in ["open_redirect", "redirect", "forward", "/fi/", "file_inclusion", "upload"]):
                        return False
                    if query_keys & redirect_keys:
                        return False
                    if query_keys & file_keys:
                        return False
                    return True

                if category == "redirect_param":
                    if query_keys & redirect_keys:
                        return True
                    return any(token in path_lower for token in ["redirect", "forward", "oauth", "callback"])

                if category == "file_param":
                    if query_keys & file_keys:
                        return True
                    return any(token in path_lower for token in ["file", "include", "download", "template", "/fi/", "inclusion"])

                return True
            
            with open(file_path, "r", encoding="utf-8") as f:
                low_value_skipped = 0
                scanned_lines = 0
                for line in f:
                    if scanned_lines >= tagged_scan_window:
                        break
                    scanned_lines += 1
                    if line.strip():
                        item = json.loads(line)
                        url = str(item.get("url", "") or "")
                        if not url:
                            continue
                        normalized_key = normalize_target_key(url)
                        if normalized_key in seen_url_keys:
                            continue
                        if is_low_value_injection_target(url, item):
                            low_value_skipped += 1
                            continue
                        if not should_include_url(url, item):
                            continue

                        urls.append(url)
                        seen_urls.add(url)
                        seen_url_keys.add(normalized_key)
                        if len(urls) >= tagged_target_cap:
                            break

                        forms = item.get("forms", [])
                        if isinstance(forms, list):
                            forms_by_url[url] = forms

                        response_headers = item.get("response_headers", {})
                        if not isinstance(response_headers, dict):
                            response_headers = {}

                        url_evidence_by_url[url] = {
                            "method": str(item.get("method", "GET") or "GET").upper(),
                            "source": str(item.get("source", "") or ""),
                            "response_status": item.get("response_status", 0),
                            "response_headers": response_headers,
                            "response_body_snippet": str(item.get("response_body_snippet", "") or ""),
                            "has_form_tag": bool(item.get("has_form_tag", False)),
                        }
                        ssrf_score, score_breakdown = self._score_ssrf_candidate(url, item)
                        if ssrf_score > 0:
                            url_evidence_by_url[url]["ssrf_score"] = ssrf_score
                            url_evidence_by_url[url]["score_breakdown"] = score_breakdown

            # auth/id_param は収集揺らぎで欠落しやすい AuthZ URL を履歴から少量補完する
            if category in {"auth", "id_param"}:
                replay_urls = self._collect_recent_authz_history_urls(
                    file_path=file_path,
                    current_urls=urls,
                    target_category=category,
                )
                replay_added = 0
                for replay_url in replay_urls:
                    normalized_key = normalize_target_key(replay_url)
                    if normalized_key in seen_url_keys:
                        continue
                    if is_low_value_injection_target(replay_url):
                        low_value_skipped += 1
                        continue
                    if not should_include_url(replay_url):
                        continue
                    urls.append(replay_url)
                    seen_urls.add(replay_url)
                    seen_url_keys.add(normalized_key)
                    replay_added += 1
                if replay_added > 0:
                    logger.info(
                        "Added %d authz replay URL(s) from recent tagged history for category=%s",
                        replay_added,
                        category,
                    )
            # API/UI系カテゴリは当日収集が揺らぐことがあるため、直近実行から同カテゴリURLを補完する
            history_replay_tokens: dict[str, tuple[str, ...]] = {
                "auth": ("login", "signin", "auth", "oauth", "token", "session", "jwt", "account", "profile", "password", "mfa"),
                "id_param": ("id=", "user_id", "account_id", "order_id", "report_id", "video_id", "product_id", "vehicle_id"),
                "admin": ("admin", "role", "permission", "manage", "settings", "team"),
                "api_data": ("/api/", "/rest/", "graphql", "genai", "state", "session", "message", "history"),
                "api_candidate": ("/api/", "/rest/", "graphql", "swagger", "openapi"),
                "csrf_candidate": ("profile", "account", "settings", "order", "checkout", "wallet"),
                "xss_candidate": ("search", "query", "review", "comment", "feedback", "profile", "account", "message"),
                "product_search": ("search", "query", "catalog", "product", "item"),
                "feedback_review": ("review", "feedback", "comment", "rating", "complaint"),
                "client_route_dom": ("#/account", "#/profile", "#/search", "#/orders", "/account", "/profile"),
                "basket_order": ("order", "orders", "checkout", "cart", "basket", "payment", "wallet", "coupon"),
            }
            if category in history_replay_tokens:
                replay_limit = int(getattr(settings, "tagged_history_replay_limit", 6) or 6)
                replay_file_window = int(getattr(settings, "tagged_history_replay_file_window", 24) or 24)
                dense_replay_categories = {
                    "auth",
                    "id_param",
                    "xss_candidate",
                    "csrf_candidate",
                    "api_data",
                    "api_candidate",
                    "basket_order",
                    "feedback_review",
                    "product_search",
                    "client_route_dom",
                }
                if category in dense_replay_categories:
                    dense_replay_limit = int(getattr(settings, "tagged_history_replay_limit_dense", 12) or 12)
                    replay_limit = max(replay_limit, dense_replay_limit)
                replay_urls = self._collect_recent_tagged_history_urls(
                    file_path=file_path,
                    current_urls=urls,
                    categories=(category,),
                    target_category=category,
                    token_hints=history_replay_tokens.get(category, ()),
                    max_urls=replay_limit,
                    max_files=replay_file_window,
                )
                replay_added = 0
                for replay_url in replay_urls:
                    normalized_key = normalize_target_key(replay_url)
                    if normalized_key in seen_url_keys:
                        continue
                    if is_low_value_injection_target(replay_url):
                        low_value_skipped += 1
                        continue
                    if not should_include_url(replay_url):
                        continue
                    urls.append(replay_url)
                    seen_urls.add(replay_url)
                    seen_url_keys.add(normalized_key)
                    replay_added += 1
                if replay_added > 0:
                    logger.info(
                        "Added %d category replay URL(s) from recent tagged history for category=%s",
                        replay_added,
                        category,
                    )
            if low_value_skipped > 0:
                logger.info(
                    "Skipped %d low-value targets by heuristic for category=%s",
                    low_value_skipped,
                    category,
                )

            if category == "realtime" and realtime_target_budget > 0 and len(urls) > realtime_target_budget:
                kept_urls = urls[:realtime_target_budget]
                kept_set = set(kept_urls)
                urls = kept_urls
                forms_by_url = {u: v for u, v in forms_by_url.items() if u in kept_set}
                url_evidence_by_url = {u: v for u, v in url_evidence_by_url.items() if u in kept_set}
                logger.info(
                    "Realtime targets capped from %d to %d (realtime_target_budget=%d)",
                    len(seen_url_keys),
                    len(urls),
                    realtime_target_budget,
                )
            if category == "meta_observability" and meta_target_budget > 0 and len(urls) > meta_target_budget:
                kept_urls = urls[:meta_target_budget]
                kept_set = set(kept_urls)
                urls = kept_urls
                forms_by_url = {u: v for u, v in forms_by_url.items() if u in kept_set}
                url_evidence_by_url = {u: v for u, v in url_evidence_by_url.items() if u in kept_set}
                logger.info(
                    "Meta targets capped from %d to %d (meta_observability_target_budget=%d)",
                    len(seen_url_keys),
                    len(urls),
                    meta_target_budget,
                )

            if not urls:
                return

            scan_profile = "bbpt"
            if self.mc and hasattr(self.mc, "context"):
                target_info = getattr(self.mc.context, "target_info", {})
                if isinstance(target_info, dict):
                    scan_profile = str(
                        target_info.get("scan_profile")
                        or target_info.get("profile")
                        or scan_profile
                    ).lower()
            if scan_profile not in {"bbpt", "ctf"}:
                scan_profile = "bbpt"

            # フォーム情報を context に追加
            context_with_forms = self.state.__dict__ if self.state else {}
            if forms_by_url:
                context_with_forms["forms_by_url"] = forms_by_url
                logger.info(f"Added forms info for {len(forms_by_url)} URLs")
            if url_evidence_by_url:
                context_with_forms["url_evidence_by_url"] = url_evidence_by_url
                logger.info(f"Added URL evidence for {len(url_evidence_by_url)} URLs")
            context_with_forms["scan_profile"] = scan_profile

            # タスク生成
            task_params = {
                "targets": urls,
                "source_file": str(file_path),
                "category": category,
                "tags": tags,
                "scan_profile": scan_profile,
                "_context": context_with_forms
            }

            if task_config["agent"] == "InjectionManagerAgent":
                task_params.update({
                    "phase1_force_full_coverage": True,
                    "phase1_stop_on_first_hit": False,
                    "phase1_early_return_on_findings": False,
                })
                if category == "id_param":
                    task_params.update({
                        "phase2_max_seconds": int(
                            getattr(settings, "id_param_phase2_max_seconds", 120) or 120
                        ),
                        "phase2_max_seconds_risk_forced": int(
                            getattr(settings, "id_param_phase2_max_seconds_risk_forced", 60) or 60
                        ),
                        "phase2_risk_force_vuln_types": [],
                    })

            task = Task(
                id=f"{category}_scan_{uuid.uuid4().hex[:8]}",
                name=f"{task_config['name']} ({len(urls)} targets)",
                agent_type=task_config["agent"],
                action=task_config["action"],
                params=task_params,
                priority=task_config["priority"]
            )
            if hasattr(self.mc, "_add_tasks"):
                self.mc._add_tasks([task], source=f"recon.tagged_{category}")
                logger.info(f"✅ Added {task_config['name']} task with {len(urls)} targets")

                # command injection 系 URL は InjectionManager を明示起動して
                # cmd_ssrf ルートへ優先的に流す
                command_targets = [
                    u for u in urls
                    if any(token in u.lower() for token in [
                        "/vulnerabilities/exec/", "/exec/", "command", "cmd", "ping"
                    ])
                ]
                if command_targets:
                    cmd_task = Task(
                        id=f"cmd_focus_{uuid.uuid4().hex[:8]}",
                        name=f"Command Injection Focused Scan ({len(command_targets)} targets)",
                        agent_type="InjectionManagerAgent",
                        action="scan",
                        params={
                            "targets": command_targets,
                            "source_file": str(file_path),
                            "category": "command_injection",
                            "tags": ["cmd_candidate", "rce_candidate", "ssrf_candidate"],
                            "scan_profile": scan_profile,
                            "phase1_force_full_coverage": True,
                            "phase1_stop_on_first_hit": False,
                            "phase1_early_return_on_findings": False,
                            "_context": context_with_forms,
                        },
                        priority=max(task_config["priority"], 88),
                    )
                    self.mc._add_tasks([cmd_task], source=f"recon.tagged_{category}.cmd_focus")
                    logger.info("✅ Added explicit command-injection focus task (%d targets)", len(command_targets))

                # weak session id (DVWA weak_id 等) は SessionHijacker を明示起動
                weak_session_targets = [u for u in urls if "weak_id" in u.lower()]
                if weak_session_targets:
                    target_info = {}
                    if self.mc and hasattr(self.mc, "context"):
                        maybe_target_info = getattr(self.mc.context, "target_info", {})
                        if isinstance(maybe_target_info, dict):
                            target_info = maybe_target_info

                    credentials = target_info.get("credentials", {}) if isinstance(target_info, dict) else {}
                    weak_target = weak_session_targets[0]

                    if not credentials:
                        parts = urlsplit(weak_target)
                        if parts.hostname in {"localhost", "127.0.0.1"}:
                            credentials = {"username": "admin", "password": "password"}

                    parts = urlsplit(weak_target)
                    base_url = f"{parts.scheme}://{parts.netloc}"
                    login_url = f"{base_url}/login.php"

                    session_task = Task(
                        id=f"session_weakid_{uuid.uuid4().hex[:8]}",
                        name="Session Weak-ID Analysis",
                        target=weak_target,
                        agent_type="sessionhijacker",
                        action="scan",
                        params={
                            "target": weak_target,
                            "login_url": login_url,
                            "test_endpoint": weak_target,
                            "credentials": credentials,
                            "scan_profile": scan_profile,
                            "tags": ["weak_session_id", "session"],
                        },
                        tags=["weak_session_id", "session"],
                        priority=max(task_config["priority"], 86),
                    )
                    self.mc._add_tasks([session_task], source=f"recon.tagged_{category}.weak_session")
                    logger.info("✅ Added explicit SessionHijacker task for weak_id endpoint")

                # authbypass / weak_id 系 URL は BizLogicHunter を明示的に起動して
                # cookie privilege escalation / authz differential / IDOR を検証する
                if category in {"id_param", "auth"}:
                    bizlogic_targets = list(dict.fromkeys([
                        u for u in urls
                        if "/authbypass" in u.lower() or "/get_user_data" in u.lower() or "/weak_id/" in u.lower()
                    ]))
                    if bizlogic_targets:
                        extra_tasks = []
                        emitted_targets: set[str] = set()
                        for idx, biz_target in enumerate(bizlogic_targets[:3]):
                            verify_target = biz_target
                            smell_type = "admin_endpoint"
                            method = "GET"
                            parameters = {}
                            verify_target_lower = verify_target.lower()

                            if "/authbypass" in verify_target_lower and "get_user_data" not in verify_target_lower:
                                if not verify_target.endswith("/"):
                                    verify_target = f"{verify_target}/"
                                verify_target = f"{verify_target}get_user_data.php?id=2"
                                smell_type = "idor_candidate"
                                parameters = {"id_param": "id", "authz_probe": "authbypass_idor"}
                            elif "/get_user_data" in verify_target_lower:
                                smell_type = "idor_candidate"
                                parameters = {"id_param": "id", "authz_probe": "authbypass_idor"}
                            elif "/weak_id/" in verify_target_lower and "id=" not in verify_target_lower:
                                separator = "&" if "?" in verify_target else "?"
                                verify_target = f"{verify_target}{separator}id=2"
                                smell_type = "idor_candidate"
                                parameters = {"id_param": "id", "authz_probe": "weak_id_idor"}

                            verify_key = verify_target.lower()
                            if verify_key in emitted_targets or verify_key in self._seeded_authz_verify_targets:
                                continue
                            emitted_targets.add(verify_key)
                            self._seeded_authz_verify_targets.add(verify_key)

                            extra_tasks.append(Task(
                                id=f"bizlogic_authbypass_{uuid.uuid4().hex[:8]}",
                                name=f"BizLogic AuthZ Differential Check ({idx + 1})",
                                target=verify_target,
                                agent_type="bizlogic",
                                action="verify",
                                params={
                                    "target": verify_target,
                                    "candidate": {
                                        "smell_type": smell_type,
                                        "method": method,
                                        "confidence": 0.8,
                                        "parameters": parameters,
                                    },
                                    "scan_profile": scan_profile,
                                },
                                tags=["idor_candidate", "admin_endpoint", "admin_panel", "authz_differential"],
                                priority=max(task_config["priority"] - 1, 1),
                            ))
                        self.mc._add_tasks(extra_tasks, source=f"recon.tagged_{category}.bizlogic")
                        logger.info("✅ Added %d explicit BizLogicHunter task(s) for authbypass", len(extra_tasks))
            else:
                logger.warning("MasterConductor does not support _add_tasks")
                
        except Exception as e:
            logger.error(f"Failed to generate tasks for {category}: {e}")

    
    async def run(self, target: str = "", start_step: int = 1, end_step: int = 8) -> ReconState:
        """Wildcard Recon メインフロー実行
        
        Args:
            target: ターゲット (省略時はinitのtarget)
            start_step: 開始ステップ
            end_step: 終了ステップ
            
        Returns:
            ReconState: 最終状態
        """
        if target:
            self.target = target.strip()  # Strip whitespace
            self.state.target = self.target
            
        logger.info("Starting Recon: '%s' (Steps %d-%d)", self.target, start_step, end_step)
        
        # 0. Proxy Gatekeeper Check (Phase 1 Requirement)
        # settings.scan.proxy が設定されている場合、Caido等の接続が必須。
        # 接続できない場合はスキャンを中断し、ユーザーに警告を出す。
        proxy_url = getattr(settings, "scan", {}).get("proxy") or settings.get_proxy_url()
        if proxy_url:
            from src.core.infra.network_client import AsyncNetworkClient
            # TCP接続チェック (2秒タイムアウト)
            if not AsyncNetworkClient._check_proxy_reachable(proxy_url):
                logger.critical("🚨 Mandatory Proxy (Caido/Burp) is NOT reachable at %s", proxy_url)
                logger.critical("SHIGOKU requires proxy for logging and analysis. Please start Caido and try again.")
                raise RuntimeError(f"Proxy mandatory but unreachable: {proxy_url}")
            logger.info("✅ Proxy check passed: %s is reachable.", proxy_url)
        
        # Check for Single URL Mode
        is_single_url = False
        # Treat as Single URL if:
        # 1. Starts with http:// or https://
        # 2. No wildcard (*)
        if (self.target.startswith("http://") or self.target.startswith("https://")) and "*" not in self.target:
            import urllib.parse
            parsed = urllib.parse.urlparse(self.target)
            if parsed.hostname:
                is_single_url = True
                self.state.all_subs = [parsed.hostname]
                logger.info("Single URL Mode detected: Skipping Subdomain & Historical Discovery. Host: %s", parsed.hostname)
        else:
             logger.info("Wildcard/Domain Mode detected: Proceeding with Subdomain Discovery.")

        logger.debug(f"is_single_url={is_single_url}, start_step={start_step}")

        try:
            # Step 1 & 2: Subdomain & Historical Discovery (Parallel)
            if not is_single_url and (start_step <= 1 <= end_step or start_step <= 2 <= end_step):
                logger.info("[Step 1&2] Parallel Discovery started")
                
                tasks = []
                if start_step <= 1 <= end_step:
                    tasks.append(self.step1_subdomain_discovery())
                else:
                    async def dummy_s1(): return []
                    tasks.append(dummy_s1())
                
                if start_step <= 2 <= end_step:
                    # 并列実行のため空リストを渡し、後でマージする
                    tasks.append(self.step2_historical_discovery([]))
                else:
                    async def dummy_s2(): return []
                    tasks.append(dummy_s2())
                
                # 並列実行
                results = await asyncio.gather(*tasks)
                
                # 結果のマージ
                res1 = results[0]
                res2 = results[1]
                self.state.all_subs = sorted(list(set(res1) | set(res2)))
                
                if start_step <= 1 <= end_step:
                    self.state.mark_step_complete("subdomain_discovery")
                if start_step <= 2 <= end_step:
                    self.state.mark_step_complete("historical_discovery")
                
                logger.info("[Step 1&2] Parallel Discovery completed: %d total subdomains", len(self.state.all_subs))
                
            elif is_single_url:
                self.state.mark_step_complete("subdomain_discovery_skipped")
                self.state.mark_step_complete("historical_discovery_skipped")
            
            # Step 3: Live Check & Technology
            if start_step <= 3 <= end_step:
                live_subs, dead_subs = await self.step3_live_check(self.state.all_subs)
                self.state.live_subs = live_subs
                self.state.dead_subs = dead_subs
                self.state.mark_step_complete("live_check")
            
            # Step 3b, 4, 5 Phase 1: Controlled Parallel Execution
            if start_step <= 3 <= end_step or start_step <= 4 <= end_step or start_step <= 5 <= end_step:
                logger.info("[Step 3b, 4, 5] Controlled Parallel Execution started")
                active_tasks = []
                
                if start_step <= 3 <= end_step:
                    active_tasks.append(self._run_with_active_sem(self.step3b_hybrid_url_discovery, self.state.live_subs))
                
                if start_step <= 4 <= end_step:
                    active_tasks.append(self._run_with_active_sem(self.step4_waf_detection, self.state.live_subs))
                
                if start_step <= 5 <= end_step:
                    # Phase 1: Top 20 ポートスキャン
                    active_tasks.append(self._run_with_active_sem(self.step5_port_scan_phase1, self.state.live_subs))
                
                if active_tasks:
                    await asyncio.gather(*active_tasks)
                    # 完了マーク
                    if start_step <= 3 <= end_step: self.state.mark_step_complete("url_discovery")
                    if start_step <= 4 <= end_step: self.state.mark_step_complete("waf_detection")
                    if start_step <= 5 <= end_step: self.state.mark_step_complete("port_scan_phase1")
                
                logger.info("[Step 3b, 4, 5] Controlled Parallel Execution completed")
                
                # Phase 2: 並行タスク (Fire and Forget)
                logger.info("Step 5 Phase 2: Starting parallel tasks")
                await self.step5_port_scan_phase2(self.state.live_subs)
                self.state.mark_step_complete("port_scan_phase2")
            
            # Step 6: 分類ファイル生成
            classified_files: dict[str, Path] = {}
            if start_step <= 6 <= end_step:
                classified_files = await self.step6_classify()
                self.state.mark_step_complete("classification")
            
            # Step 7: ProjectManager 保存
            if start_step <= 7 <= end_step:
                await self.step7_save_to_project(classified_files)
                self.state.mark_step_complete("save_to_project")
            
            # Step 8: MC へ結果返却
            if start_step <= 8 <= end_step:
                self.state.results = await self.step8_return_to_mc(classified_files)
                self.state.mark_step_complete("return_to_mc")
            
        except Exception as e:
            logger.error(f"Pipeline execution failed: {e}")
            raise

        return self.state
    
    async def run_parallel_tasks(self, live_subs: list[str]) -> None:
        """並行タスクを実行
        
        各タスクは完了次第、分類→PM保存→MC返却を独立実行する。
        
        Args:
            live_subs: ライブサブドメインのリスト
        """
        if not live_subs:
            logger.warning("No live subdomains for parallel tasks")
            return
        
        logger.info("Starting parallel tasks for %d live subdomains", len(live_subs))
        
        # ParallelTasks インスタンス作成
        from src.recon.parallel_tasks import ParallelTasks
        tasks = ParallelTasks(self.config, self.pm, self.mc)
        
        # ワークスペースディレクトリ
        workspace = self.pm.project_dir if self.pm else Path.cwd() / "workspace" / "projects" / "unknown"
        workspace = Path(workspace)
        workspace.mkdir(parents=True, exist_ok=True)
        
        # 独立した並行タスク (Task B: Visual Recon, Task C: Permutation)
        independent_tasks = [
            self._run_with_semaphore(tasks.visual_recon, live_subs, workspace),
            self._run_with_semaphore(
                tasks.permutation_scan,
                self.state.all_subs,
                self.target.replace("*.", ""),  # *.example.com -> example.com
                workspace,
                self.state,
            ),
        ]
        
        # 依存関係のあるタスク (Task A: Full Port → Task D: Dead Sub)
        async def chained_port_scans():
            # Task A: Full Port Scan
            result_a = await self._run_with_semaphore(
                tasks.full_port_scan, live_subs, workspace, self.state
            )
            logger.info("Full Port Scan result: %s", result_a.get("status"))
            
            # Task D: Dead Sub Scan
            result_d = await self._run_with_semaphore(
                tasks.dead_subdomain_scan,
                self.state.all_subs,
                live_subs,
                workspace,
                self.state,
            )
            logger.info("Dead Sub Scan result: %s", result_d.get("status"))
        
        # Task D を含む chained_port_scans もコルーチンとしてリストに追加
        # Note: chained_port_scans() は coroutine object を返す
        independent_tasks.append(chained_port_scans())
        
        # 全タスク実行
        results = await asyncio.gather(*independent_tasks, return_exceptions=True)
        
        # エラーチェック
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error("Parallel task %d failed: %s", i, result)
        
        logger.info("All parallel tasks completed")
    
    async def _run_with_semaphore(self, coro_func, *args) -> Any:
        """Semaphore で同時実行数を制限してコルーチンを実行"""
        async with self.semaphore:
            return await coro_func(*args)

    async def _run_with_active_sem(self, coro_func, *args) -> Any:
        """Active Scan 用 Semaphore で同時実行数を制限して実行"""
        async with self.active_recon_sem:
            return await coro_func(*args)
