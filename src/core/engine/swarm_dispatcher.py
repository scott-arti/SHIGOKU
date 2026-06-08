"""
SwarmDispatcher: タグベースで適切な Swarm にタスクをルーティング

MasterConductor から呼び出され、タスクのタグに基づいて
適切な Swarm Manager を選択し、実行を委譲する。

Implementation Plan Section 3.4 準拠
"""

import logging
from typing import Dict, Any, Optional, List, Type

from src.core.agents.swarm.base import SwarmManager, Task as SwarmTask
from src.core.models.swarm import SwarmResult
from src.core.engine.aggressive_limiter import get_aggressive_limiter, AggressiveLimiter
from src.core.engine.tag_taxonomy_registry import (
    SUBDOMAIN_TAG_TO_SWARM,
    URL_TAG_TO_SWARM,
    TAG_TO_SWARM,
)

logger = logging.getLogger(__name__)


# Swarm のインポート (遅延評価のため関数内でインポート)
def _get_swarm_classes() -> Dict[str, Type[SwarmManager]]:
    """利用可能な Swarm クラスを取得"""
    from src.core.agents.swarm.injection import InjectionSwarm
    from src.core.agents.swarm.auth import AuthSwarm
    from src.core.agents.swarm.logic import LogicSwarm
    from src.core.agents.swarm.discovery import DiscoverySwarm
    from src.core.agents.swarm.scanner import ScannerSwarm
    from src.core.agents.swarm.secret import SecretSwarm
    from src.core.agents.swarm.intelligence import IntelligenceSwarm
    from src.core.agents.swarm.fuzzing.manager import FuzzingSwarm
    
    return {
        "injection": InjectionSwarm,
        "auth": AuthSwarm,
        "logic": LogicSwarm,
        "discovery": DiscoverySwarm,
        "scanner": ScannerSwarm,
        "secret": SecretSwarm,
        "intelligence": IntelligenceSwarm,
        "fuzzing": FuzzingSwarm,
    }

# ========================================
# タグ → Swarm マッピング（分離）
# ========================================

# Tag taxonomy is centralized in tag_taxonomy_registry.py


class SwarmDispatcher:
    """
    タグベースで Swarm にタスクをルーティング
    
    使用例:
        dispatcher = SwarmDispatcher()
        result = await dispatcher.dispatch(tags=["has_params", "api_endpoint"], target="https://api.example.com")
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, project_manager: Any = None, master_conductor: Any = None, network_client: Any = None, llm_client: Any = None, loop: Any = None, event_bus: Any = None):
        self.config = config or {}
        self.project_manager = project_manager
        self.master_conductor = master_conductor
        self.network_client = network_client
        self.llm_client = llm_client
        self.loop = loop
        self.event_bus = event_bus
        self._swarm_pool: Dict[str, SwarmManager] = {} # オブジェクトプール
        self._recipe_loader = None
        self._rag = None
        self._aggressive_limiter: AggressiveLimiter = get_aggressive_limiter()
    
    def set_recipe_loader(self, recipe_loader) -> None:
        """RecipeLoader を設定（Swarm で使用）"""
        self._recipe_loader = recipe_loader
        for swarm in self._swarm_pool.values(): # Changed from _swarm_instances
            swarm.set_recipe_loader(recipe_loader)
    
    def set_rag(self, rag) -> None:
        """RAG を設定（Swarm で使用）"""
        self._rag = rag
        for swarm in self._swarm_pool.values(): # Changed from _swarm_instances
            swarm.set_rag(rag)
    
    def _get_or_create_swarm(self, swarm_name: str) -> Any:
        """Swarm Manager を取得または作成（プールを利用）"""
        if swarm_name in self._swarm_pool:
            return self._swarm_pool[swarm_name]

        swarm = None
        swarm_classes = _get_swarm_classes()
        if swarm_name in swarm_classes:
            # LLM が必要な Swarm かつ llm_client が None の場合は作成をスキップ
            swarm_class = swarm_classes[swarm_name]
            requires_llm = swarm_name in ["injection", "auth", "logic", "secret", "intelligence"]
            
            if requires_llm and not self.llm_client:
                logger.warning(f"[_get_or_create_swarm] Skipping {swarm_name}: LLM client not available")
                return None
            
            swarm = swarm_class(self.config)

        if swarm:
            # Shared Network Client を設定
            if self.network_client and hasattr(swarm, 'set_network_client'):
                swarm.set_network_client(self.network_client)

            # Shared LLM Client を設定
            if self.llm_client and hasattr(swarm, 'set_llm_client'):
                swarm.set_llm_client(self.llm_client)

            # Shared Event Loop を設定
            if self.loop and hasattr(swarm, 'set_event_loop'):
                swarm.set_event_loop(self.loop)

            # Shared Event Bus を設定
            if self.event_bus and hasattr(swarm, 'set_event_bus'):
                swarm.set_event_bus(self.event_bus)

            # Recipe/RAG を設定
            if hasattr(self, '_recipe_loader') and self._recipe_loader:
                swarm.set_recipe_loader(self._recipe_loader)
            if self._rag:
                swarm.set_rag(self._rag)

            self._swarm_pool[swarm_name] = swarm

        return self._swarm_pool.get(swarm_name)
    
    def determine_swarms(self, tags: List[str]) -> List[str]:
        """
        タグから該当する全ての Swarm を決定
        
        複数のタグが異なる Swarm に該当する場合、全てを返す。
        これにより、漏れなく攻撃を実行できる。
        
        優先順位（ソート用）: auth > injection > logic > secret > discovery > scanner
        
        Returns:
            該当する Swarm 名のリスト（優先度順）
        """
        matched_swarms: set[str] = set()
        
        # 特殊ルール: upload系タグがある場合、rce_candidate は logic に向ける
        has_upload = any(t in ["upload", "file_upload", "tagged_upload"] for t in tags)
        
        for tag in tags:
            if tag == "rce_candidate" and has_upload:
                # ファイルアップロードに関連するRCEなら LogicSwarm (FileUploadSpecialist) が担当すべき
                matched_swarms.add("logic")
            elif tag in TAG_TO_SWARM:
                matched_swarms.add(TAG_TO_SWARM[tag])
        
        if not matched_swarms:
            return []
        
        # 優先順位でソート
        priority = ["auth", "injection", "logic", "secret", "discovery", "scanner"]
        return sorted(
            matched_swarms,
            key=lambda x: priority.index(x) if x in priority else 100
        )
    
    def determine_swarm(self, tags: List[str]) -> Optional[str]:
        """
        後方互換性のため: 最優先の Swarm を1つだけ返す
        
        新規コードは determine_swarms() を使用すること。
        """
        swarms = self.determine_swarms(tags)
        return swarms[0] if swarms else None

    async def close(self) -> None:
        """全 Swarm インスタンスのリソースを解放"""
        logger.info("Closing SwarmDispatcher...")

        # 各 Swarm の close() を呼び出し
        for swarm_name, swarm in list(self._swarm_pool.items()):
            try:
                if hasattr(swarm, "close"):
                    await swarm.close()
                logger.debug(f"Closed swarm: {swarm_name}")
            except Exception as e:
                logger.error(f"Error closing swarm {swarm_name}: {e}")

        # インスタンス辞書をクリア
        self._swarm_pool.clear()
        
        # グローバルインスタンスをリセット（次回起動時に新規作成）
        global _dispatcher
        _dispatcher = None
        
        logger.info("SwarmDispatcher closed successfully")

    
    async def dispatch(
        self,
        tags: List[str],
        target: str,
        task_name: str = "swarm_task",
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[SwarmResult]:
        """
        タグに基づいて該当する全ての Swarm にタスクをディスパッチ
        
        複数の Swarm が該当する場合、順次実行して結果をマージする。
        
        Args:
            tags: タスクのタグリスト
            target: ターゲット URL
            task_name: タスク名
            params: 追加パラメータ
        
        Returns:
            マージされた SwarmResult または None (該当 Swarm なし)
        """
        swarm_names = self.determine_swarms(tags)
        
        if not swarm_names:
            logger.info("No matching swarm for tags: %s", tags)
            return None
        
        logger.info(
            "[SwarmDispatcher] Routing to %d swarm(s): %s for tags: %s",
            len(swarm_names), swarm_names, tags
        )
        
        # 全ての該当 Swarm に順次ディスパッチ
        all_findings = []
        all_execution_logs = []
        total_specialists = 0
        successful_specialists = 0
        statuses = []
        
        for swarm_name in swarm_names:
            try:
                swarm = self._get_or_create_swarm(swarm_name)
                
                # SwarmTask を作成
                swarm_task = SwarmTask(
                    id=f"swarm_{swarm_name}_{hash(target) % 10000}",
                    name=f"{task_name} ({swarm_name})",
                    target=target,
                    tags=tags,
                    params=params or {},
                )
                
                result = await swarm.dispatch(swarm_task)
                
                if result:
                    all_findings.extend(result.findings)
                    all_execution_logs.extend(result.execution_log)
                    total_specialists += result.total_specialists
                    successful_specialists += result.successful_specialists
                    statuses.append(result.status)
                    logger.info(
                        "[SwarmDispatcher] %s completed: %d findings",
                        swarm_name, len(result.findings)
                    )
                
            except Exception as e:
                logger.error("[SwarmDispatcher] Error dispatching to %s: %s", swarm_name, e)
                all_execution_logs.append({"swarm": swarm_name, "error": str(e)})
                statuses.append("failed")
        
        # 結果をマージ
        if "success" in statuses:
            merged_status = "success"
        elif "partial_success" in statuses:
            merged_status = "partial_success"
        else:
            merged_status = "failed"
        
        return SwarmResult(
            findings=all_findings,
            status=merged_status,
            execution_log=all_execution_logs,
            swarm_name=",".join(swarm_names),  # 複数 Swarm 名をカンマ区切り
            total_specialists=total_specialists,
            successful_specialists=successful_specialists,
        )
    
    async def dispatch_rich_url(
        self,
        rich_context: 'RichUrlContext',
        task_name: str = "url_analysis",
    ) -> List[SwarmResult]:
        """
        RichUrlContext を直接受け取り、タグごとに個別のコンテキストでディスパッチ
        
        各 TagMatch に対して、そのタグ専用のコンテキストを含む params を作成し、
        対応する Swarm にディスパッチする。同じ Swarm への複数タグは個別に処理。
        
        Args:
            rich_context: TaggingFilter からの RichUrlContext
            task_name: タスク名
        
        Returns:
            SwarmResult のリスト (タグなしの場合は空リスト)
        """
        from src.core.models.url_context import RichUrlContext
        
        if not isinstance(rich_context, RichUrlContext):
            logger.error("dispatch_rich_url requires RichUrlContext, got %s", type(rich_context))
            return []
        
        if not rich_context.tags:
            logger.info("No tags for URL: %s", rich_context.url)
            return []
        
        results: List[SwarmResult] = []
        
        # 共通コンテキスト（全タグで共有）
        common_context = {
            "url": rich_context.url,
            "method": rich_context.method,
            "headers": rich_context.headers,
            "body": rich_context.body,
            "response_status": rich_context.response_status,
            "response_body_preview": rich_context.response_body_preview,
            "auth_context": rich_context.auth_context,
        }
        
        if rich_context.subdomain_context:
            common_context["subdomain_context"] = rich_context.subdomain_context.to_dict()
        
        # 各タグごとに個別のコンテキストでディスパッチ
        for tag_match in rich_context.tags:
            swarm_name = TAG_TO_SWARM.get(tag_match.tag)
            
            if not swarm_name:
                logger.warning("No Swarm mapping for tag: %s", tag_match.tag)
                continue
            
            # このタグ専用の params を作成
            tag_specific_params = {
                **common_context,
                # タグ固有のマッチ情報
                "tag": tag_match.tag,
                "rule_name": tag_match.rule_name,
                "matched_on": tag_match.matched_on,
                "matched_value": tag_match.matched_value,
                "param_name": tag_match.param_name,
            }
            
            logger.info(
                "[dispatch_rich_url] Tag '%s' (rule=%s, matched_on=%s) -> %s",
                tag_match.tag, tag_match.rule_name, tag_match.matched_on, swarm_name
            )
            
            # 単一 Swarm にディスパッチ
            try:
                result = await self._dispatch_to_single_swarm(
                    swarm_name=swarm_name,
                    target=rich_context.url,
                    task_name=f"{task_name}_{tag_match.tag}",
                    params=tag_specific_params,
                )
                if result:
                    results.append(result)
            except Exception as e:
                logger.error("Error dispatching tag '%s' to %s: %s", tag_match.tag, swarm_name, e)
        
        return results
    
    async def _dispatch_to_single_swarm(
        self,
        swarm_name: str,
        target: str,
        task_name: str,
        params: Dict[str, Any],
    ) -> Optional[SwarmResult]:
        """
        単一の Swarm にタスクをディスパッチ
        
        AggressiveLimiter で以下を制御:
        - POST/PUT/DELETE は HITL 確認
        - is_aggressive タスクは同時 1 つまで
        """
        swarm_classes = _get_swarm_classes()
        
        if swarm_name not in swarm_classes:
            logger.error("Unknown swarm: %s", swarm_name)
            return None
        
        # is_aggressive 判定
        is_aggressive = self._aggressive_limiter.should_be_aggressive(params)
        
        # タスク情報を構築（HITL 表示用）
        task_info = {
            "target": target,
            "swarm": swarm_name,
            "method": params.get("method", "GET"),
            "action": task_name,
            "tag": params.get("tag"),
            "is_aggressive": is_aggressive,
        }
        
        # AggressiveLimiter で承認チェック & セマフォ取得
        approved = await self._aggressive_limiter.acquire(task_info)
        if not approved:
            logger.info("Task skipped (user rejected): %s -> %s", target, swarm_name)
            return SwarmResult(
                findings=[],
                status="skipped",
                execution_log=[{"swarm": swarm_name, "skipped": "user_rejected"}],
                swarm_name=swarm_name,
            )
        
        # 承認済みならパラメータに注入（Specialistが参照可能にする）
        if approved:
            params["user_approved"] = True
        
        try:
            swarm_class = swarm_classes[swarm_name]
            # プールにある場合はそれを使用、ない場合は作成
            swarm = self._get_or_create_swarm(swarm_name)
            if not swarm:
                # プール外の直接生成時のフォールバック
                swarm = swarm_class(self.config)
                if self.network_client and hasattr(swarm, 'set_network_client'):
                    swarm.set_network_client(self.network_client)
            
            task = SwarmTask(
                id=f"task_{swarm_name}_{id(params) % 10000}",
                name=task_name,
                target=target,
                tags=[params.get("tag", "unknown")],
                params=params,
                is_aggressive=is_aggressive,
            )
            
            result = await swarm.execute(task)
            logger.info("[_dispatch_to_single_swarm] %s completed: %d findings", swarm_name, len(result.findings))
            return result
            
        except Exception as e:
            logger.error("[_dispatch_to_single_swarm] %s error: %s", swarm_name, e)
            return SwarmResult(
                findings=[],
                status="failed",
                execution_log=[{"swarm": swarm_name, "error": str(e)}],
                swarm_name=swarm_name,
            )
        finally:
            # セマフォ解放
            await self._aggressive_limiter.release(is_aggressive)
    
    async def dispatch_to_all(
        self,
        target: str,
        task_name: str = "full_scan",
        params: Optional[Dict[str, Any]] = None,
    ) -> List[SwarmResult]:
        """
        全 Swarm に対してタスクをディスパッチ（フルスキャン用）
        
        Args:
            target: ターゲット URL
            task_name: タスク名
            params: 追加パラメータ
        
        Returns:
            全 Swarm の結果リスト
        """
        results = []
        swarm_classes = _get_swarm_classes()
        
        for swarm_name in swarm_classes:
            try:
                swarm = self._get_or_create_swarm(swarm_name)
                swarm_task = SwarmTask(
                    id=f"full_{swarm_name}_{hash(target) % 10000}",
                    name=task_name,
                    target=target,
                    tags=[],  # 全 Specialist を実行
                    params=params or {},
                )
                result = await swarm.dispatch(swarm_task)
                results.append(result)
            except Exception as e:
                logger.error(f"[SwarmDispatcher] Error in {swarm_name}: {e}")
        
        return results


# シングルトンインスタンス
_dispatcher: Optional[SwarmDispatcher] = None


def get_swarm_dispatcher(config: Optional[Dict[str, Any]] = None, network_client: Any = None, llm_client: Any = None, loop: Any = None, event_bus: Any = None) -> SwarmDispatcher:
    """SwarmDispatcher のシングルトンを取得

    初回呼び出し時に渡されたパラメータで初期化され、以降は同じインスタンスを返す。
    2 回目以降の呼び出しでパラメータが指定された場合、常に上書き更新する。
    これにより、並列実行時のレースコンディションを防止する。
    """
    global _dispatcher
    if _dispatcher is None:
        # 初回：新規作成
        _dispatcher = SwarmDispatcher(config, network_client=network_client, llm_client=llm_client, loop=loop, event_bus=event_bus)
        
        # llm_client が None の場合は警告（InjectionSwarm が機能しなくなる）
        if llm_client is None:
            logger.warning("[get_swarm_dispatcher] Initialized with llm_client=None. InjectionSwarm may not function correctly.")
    else:
        # 2 回目以降：常に上書き更新（並列実行時のレースコンディション防止）
        if network_client is not None:
            _dispatcher.network_client = network_client
        if llm_client is not None:
            _dispatcher.llm_client = llm_client
        if loop is not None:
            _dispatcher.loop = loop
        if event_bus is not None:
            _dispatcher.event_bus = event_bus

    return _dispatcher
