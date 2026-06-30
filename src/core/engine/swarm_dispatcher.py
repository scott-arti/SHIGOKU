"""
SwarmDispatcher: タグベースで適切な Swarm にタスクをルーティング

MasterConductor から呼び出され、タスクのタグに基づいて
適切な Swarm Manager を選択し、実行を委譲する。

Implementation Plan Section 3.4 準拠
"""

import asyncio
import logging
import threading
from typing import Dict, Any, Optional, List, Type

from src.core.agents.swarm.base import SwarmManager, Task as SwarmTask
from src.core.models.swarm import SwarmResult, PerUrlSubResult
from src.core.engine.aggressive_limiter import get_aggressive_limiter, AggressiveLimiter
from src.core.engine.budget_policy import ExecutionBudgetPolicy, BudgetDecision
from src.core.engine.tag_taxonomy_registry import (
    SUBDOMAIN_TAG_TO_SWARM,
    URL_TAG_TO_SWARM,
    TAG_TO_SWARM,
)
from src.core.models.run_ledger import (
    RunLedgerEventType, get_run_ledger_recorder,
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
        self._budget_policy: ExecutionBudgetPolicy = ExecutionBudgetPolicy()
        self.run_ledger_recorder = get_run_ledger_recorder()
    
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
        """Swarm Manager を新規生成（Phase 3: per-dispatch instance / pool 再利用廃止）。

        shared service (network/llm/event_bus/recipe/rag) を注入するが、インスタンスは
        キャッシュしない。呼び出し元は dispatch 後に try/finally で close() すること。
        """
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

            # Phase 3: self._swarm_pool[swarm_name] = swarm は行わない（キャッシュ廃止）

        return swarm  # NOTE: 呼び出し元が try/finally で close() する
    
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

    def _classify_swarm_shadow(self, swarm_name: str) -> Dict[str, Any]:
        """Phase 8 Step 2: Classify swarm for inner parallelism shadow decision.

        Returns a shadow decision entry (type='shadow_parallel_decision').
        This is RECORDING ONLY; execution order is unchanged.
        """
        swarm_classes = _get_swarm_classes()
        swarm_class = swarm_classes.get(swarm_name)
        if not swarm_class:
            return {
                "type": "shadow_parallel_decision",
                "source_layer": "swarm_dispatcher",
                "source_unit": swarm_name,
                "candidate": False,
                "parallelism_type": None,
                "state_isolation": None,
                "rejection_reason": "unknown_swarm_class",
            }
        try:
            from src.core.agents.swarm.base_manager import BaseManagerAgent
            is_stateful = issubclass(swarm_class, BaseManagerAgent)
        except Exception:
            is_stateful = True

        if is_stateful:
            return {
                "type": "shadow_parallel_decision",
                "source_layer": "swarm_dispatcher",
                "source_unit": swarm_name,
                "candidate": False,
                "parallelism_type": None,
                "state_isolation": "per_dispatch",
                "rejection_reason": "stateful_manager (BaseManagerAgent subclass)",
            }
        else:
            return {
                "type": "shadow_parallel_decision",
                "source_layer": "swarm_dispatcher",
                "source_unit": swarm_name,
                "candidate": True,
                "parallelism_type": "read_only",
                "state_isolation": "stateless",
                "rejection_reason": None,
            }

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
        
        # --- Phase 8 Step 2: Shadow parallel decision ---
        shadow_decisions: List[Dict[str, Any]] = []
        for sn in swarm_names:
            shadow_decisions.append(self._classify_swarm_shadow(sn))
        
        # --- Phase 8 Step 3: Limited inner parallel (read_only/stateless only) ---
        if self._is_inner_parallelism_enabled():
            return await self._dispatch_with_limited_parallel(
                swarm_names, tags, target, task_name, params, shadow_decisions
            )
        
        # 全ての該当 Swarm に順次ディスパッチ
        return await self._dispatch_serial(
            swarm_names, tags, target, task_name, params, shadow_decisions
        )

    def _is_inner_parallelism_enabled(self) -> bool:
        """Phase 8 Step 3: Check if inner parallelism is enabled (not killed)."""
        p = self.config.get("parallelism", {}) if isinstance(self.config, dict) else {}
        if p.get("kill_switch", False):
            return False
        return p.get("enabled", False)

    async def _dispatch_serial(
        self,
        swarm_names: List[str],
        tags: List[str],
        target: str,
        task_name: str,
        params: Optional[Dict[str, Any]],
        shadow_decisions: List[Dict[str, Any]],
    ) -> SwarmResult:
        """Original serial dispatch path (kept intact for regression safety)."""
        all_findings = []
        all_execution_logs = []
        total_specialists = 0
        successful_specialists = 0
        statuses = []

        for swarm_name in swarm_names:
            swarm_result = await self._dispatch_one_swarm(
                swarm_name, tags, target, task_name, params,
            )
            if swarm_result is not None:
                all_findings.extend(swarm_result.findings)
                all_execution_logs.extend(swarm_result.execution_log)
                total_specialists += swarm_result.total_specialists
                successful_specialists += swarm_result.successful_specialists
                statuses.append(swarm_result.status)
            else:
                all_execution_logs.append({"swarm": swarm_name, "error": "dispatch_failed"})
                statuses.append("failed")

        merged_status = self._merge_status(statuses)
        return SwarmResult(
            findings=all_findings,
            status=merged_status,
            execution_log=all_execution_logs,
            swarm_name=",".join(swarm_names),
            total_specialists=total_specialists,
            successful_specialists=successful_specialists,
            shadow_decisions=shadow_decisions,
        )

    async def _dispatch_with_limited_parallel(
        self,
        swarm_names: List[str],
        tags: List[str],
        target: str,
        task_name: str,
        params: Optional[Dict[str, Any]],
        shadow_decisions: List[Dict[str, Any]],
    ) -> SwarmResult:
        """Phase 8 Step 3: Limited parallel dispatch for stateless/read_only swarms.

        Deterministic merge order: results assembled in swarm_names order.
        Partial failure: failed swarms produce error entries, not dropped.
        """
        # Classify swarms: parallel (stateless) vs serial (stateful)
        parallel_names: List[str] = []
        serial_names: List[str] = []
        for sn in swarm_names:
            shadow = self._classify_swarm_shadow(sn)
            if shadow.get("candidate") is True:
                parallel_names.append(sn)
            else:
                serial_names.append(sn)

        # Execute parallel group via asyncio.gather with return_exceptions=True
        parallel_results: Dict[str, Optional[SwarmResult]] = {}
        if parallel_names:
            tasks = [
                self._dispatch_one_swarm(sn, tags, target, task_name, params)
                for sn in parallel_names
            ]
            raw_results = await asyncio.gather(*tasks, return_exceptions=True)
            for sn, raw in zip(parallel_names, raw_results):
                if isinstance(raw, Exception):
                    logger.error("[SwarmDispatcher] Parallel %s failed: %s", sn, raw)
                    parallel_results[sn] = SwarmResult(
                        findings=[],
                        status="failed",
                        execution_log=[{"swarm": sn, "error": str(raw)}],
                        swarm_name=sn,
                    )
                else:
                    parallel_results[sn] = raw

        # Execute serial group sequentially
        serial_results: Dict[str, Optional[SwarmResult]] = {}
        for sn in serial_names:
            serial_results[sn] = await self._dispatch_one_swarm(
                sn, tags, target, task_name, params,
            )

        # Deterministic merge in swarm_names order
        all_findings = []
        all_execution_logs = []
        total_specialists = 0
        successful_specialists = 0
        statuses = []

        for sn in swarm_names:
            swarm_result = parallel_results.get(sn) or serial_results.get(sn)
            if swarm_result is not None:
                all_findings.extend(swarm_result.findings)
                all_execution_logs.extend(swarm_result.execution_log)
                total_specialists += swarm_result.total_specialists
                successful_specialists += swarm_result.successful_specialists
                statuses.append(swarm_result.status)
            else:
                all_execution_logs.append({"swarm": sn, "error": "no_result"})
                statuses.append("failed")

        merged_status = self._merge_status(statuses)
        self._record_swarm_merged(statuses, len(all_findings))
        return SwarmResult(
            findings=all_findings,
            status=merged_status,
            execution_log=all_execution_logs,
            swarm_name=",".join(swarm_names),
            total_specialists=total_specialists,
            successful_specialists=successful_specialists,
            shadow_decisions=shadow_decisions,
        )

    async def _dispatch_one_swarm(
        self,
        swarm_name: str,
        tags: List[str],
        target: str,
        task_name: str,
        params: Optional[Dict[str, Any]],
    ) -> Optional[SwarmResult]:
        """Dispatch a single swarm and return its SwarmResult (or None on failure).

        Closes the swarm in finally. Ledger recording is attempted but never
        affects the core flow.
        """
        swarm = None
        try:
            swarm = self._get_or_create_swarm(swarm_name)

            swarm_task = SwarmTask(
                id=f"swarm_{swarm_name}_{hash(target) % 10000}",
                name=f"{task_name} ({swarm_name})",
                target=target,
                tags=tags,
                params=params or {},
            )

            try:
                self.run_ledger_recorder.record(
                    event_type=RunLedgerEventType.SWARM_DISPATCHED,
                    phase="attack",
                    actor_type="SwarmDispatcher",
                    actor_name=swarm_name,
                    task_id=getattr(swarm_task, "id", None) if swarm_task else None,
                    input_summary=f"Dispatch to {swarm_name}",
                    action="dispatch",
                    result="dispatched",
                )
            except Exception:
                pass

            result = await swarm.dispatch(swarm_task)

            if result:
                logger.info(
                    "[SwarmDispatcher] %s completed: %d findings",
                    swarm_name, len(result.findings),
                )
                try:
                    self.run_ledger_recorder.record(
                        event_type=RunLedgerEventType.SWARM_COMPLETED,
                        phase="attack",
                        actor_type="SwarmDispatcher",
                        actor_name=swarm_name,
                        result="completed",
                        source_refs={"findings_count": len(result.findings)}
                        if result.findings else {"findings_count": 0},
                    )
                except Exception:
                    pass
            return result

        except Exception as e:
            logger.error("[SwarmDispatcher] Error dispatching to %s: %s", swarm_name, e)
            try:
                self.run_ledger_recorder.record(
                    event_type=RunLedgerEventType.SWARM_FAILED,
                    phase="attack",
                    actor_type="SwarmDispatcher",
                    actor_name=swarm_name,
                    result="failed",
                    error=str(e)[:500],
                )
            except Exception:
                pass
            return None
        finally:
            if swarm is not None and hasattr(swarm, "close"):
                try:
                    await swarm.close()
                except Exception as ce:
                    logger.error("[SwarmDispatcher] Error closing swarm %s: %s", swarm_name, ce)

    @staticmethod
    def _merge_status(statuses: List[str]) -> str:
        """Merge statuses: any success → success, any partial → partial, else failed."""
        if "success" in statuses:
            return "success"
        elif "partial_success" in statuses:
            return "partial_success"
        return "failed"

    def _record_swarm_merged(self, statuses, total_findings):
        try:
            self.run_ledger_recorder.record(
                event_type=RunLedgerEventType.SWARM_MERGED,
                phase="attack",
                actor_type="SwarmDispatcher",
                actor_name="all",
                result="merged",
                source_refs={"statuses": statuses, "total_findings": total_findings},
            )
        except Exception:
            pass

    def _build_per_url_sub_result(
        self,
        source_url: str,
        origin_key: str,
        request_fingerprint: str = "",
        payload_fingerprint: str = "",
    ) -> PerUrlSubResult:
        """Phase 9 T-3.1: Budget-enforced PerUrlSubResult factory.

        Calls ExecutionBudgetPolicy.consume(origin_key) before each URL worker.
        Records the budget decision in PerUrlSubResult.budget_decision.
        Sets status="skipped" when budget is rejected (not allowed).
        Sets status="rejected" when the budget decision has a blocking reason_code.

        Workers MUST NOT directly mutate shared current_context — they return
        PerUrlSubResult objects.
        """
        decision: BudgetDecision = self._budget_policy.consume(origin_key)

        budget_decision_dict = {
            "allowed": decision.allowed,
            "wait_seconds": decision.wait_seconds,
            "reason_code": decision.reason_code,
        }

        if not decision.allowed:
            status = "rejected" if decision.reason_code else "skipped"
            return PerUrlSubResult(
                source_url=source_url,
                origin_key=origin_key,
                request_fingerprint=request_fingerprint,
                payload_fingerprint=payload_fingerprint,
                budget_decision=budget_decision_dict,
                status=status,
            )

        # Budget allowed — return pending skeleton; worker fills in the results
        return PerUrlSubResult(
            source_url=source_url,
            origin_key=origin_key,
            request_fingerprint=request_fingerprint,
            payload_fingerprint=payload_fingerprint,
            budget_decision=budget_decision_dict,
            status="pending",
        )

    @staticmethod
    def _merge_per_url_sub_results(
        sub_results: List[PerUrlSubResult],
    ) -> Dict[str, Any]:
        """Phase 9 T-3.2: Deterministic post-join merge of PerUrlSubResult objects.

        Sorts by (source_url, request_fingerprint, payload_fingerprint) for
        deterministic order. Merges findings, url_results, and tested_params
        from non-skipped/non-rejected results (status "success" or "failed").

        Returns a merged result dict suitable for assembly into final context.
        """
        # Sort for deterministic order
        sorted_results = sorted(
            sub_results,
            key=lambda r: (r.source_url, r.request_fingerprint, r.payload_fingerprint),
        )

        all_findings: List[Any] = []
        merged_url_results: Dict[str, Any] = {}
        merged_tested_params: List[str] = []
        success_count = 0
        skipped_count = 0
        rejected_count = 0
        failed_count = 0

        for sr in sorted_results:
            if sr.is_skipped_or_rejected:
                if sr.status == "skipped":
                    skipped_count += 1
                else:
                    rejected_count += 1
                continue

            # Non-skipped, non-rejected: merge findings, url_results, tested_params
            all_findings.extend(sr.findings)
            merged_url_results.update(sr.url_result)
            # Deduplicate tested_params
            for param in sr.tested_params:
                if param not in merged_tested_params:
                    merged_tested_params.append(param)

            if sr.status == "success":
                success_count += 1
            elif sr.status == "failed":
                failed_count += 1
            elif sr.status == "pending":
                # Pending results (budget allowed but not yet executed) - count separately
                pass

        return {
            "findings": all_findings,
            "url_results": merged_url_results,
            "tested_params": merged_tested_params,
            "counts": {
                "success": success_count,
                "skipped": skipped_count,
                "rejected": rejected_count,
                "failed": failed_count,
                "total": len(sub_results),
            },
        }

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
        
        swarm = None
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
            
            try:
                self.run_ledger_recorder.record(
                    event_type=RunLedgerEventType.SWARM_DISPATCHED,
                    phase="attack",
                    actor_type="SwarmDispatcher",
                    actor_name=swarm_name,
                    task_id=getattr(task, "id", None),
                    input_summary=f"Dispatch to {swarm_name}",
                    action="dispatch",
                    result="dispatched",
                )
            except Exception:
                pass  # ledger recording must not affect core flow
            
            result = await swarm.execute(task)
            logger.info("[_dispatch_to_single_swarm] %s completed: %d findings", swarm_name, len(result.findings))
            try:
                self.run_ledger_recorder.record(
                    event_type=RunLedgerEventType.SWARM_COMPLETED,
                    phase="attack",
                    actor_type="SwarmDispatcher",
                    actor_name=swarm_name,
                    result="completed",
                    source_refs={"findings_count": len(result.findings)} if result.findings else {"findings_count": 0},
                )
            except Exception:
                pass  # ledger recording must not affect core flow
            return result
            
        except Exception as e:
            logger.error("[_dispatch_to_single_swarm] %s error: %s", swarm_name, e)
            try:
                self.run_ledger_recorder.record(
                    event_type=RunLedgerEventType.SWARM_FAILED,
                    phase="attack",
                    actor_type="SwarmDispatcher",
                    actor_name=swarm_name,
                    result="failed",
                    error=str(e)[:500],
                )
            except Exception:
                pass  # ledger recording must not affect core flow
            return SwarmResult(
                findings=[],
                status="failed",
                execution_log=[{"swarm": swarm_name, "error": str(e)}],
                swarm_name=swarm_name,
            )
        finally:
            # セマフォ解放
            await self._aggressive_limiter.release(is_aggressive)
            if swarm is not None and hasattr(swarm, "close"):
                try:
                    await swarm.close()
                except Exception as ce:
                    logger.error("[_dispatch_to_single_swarm] Error closing %s: %s", swarm_name, ce)
    
    async def dispatch_injection_urls_with_budget(
        self,
        urls: List[str],
        origin_key: str,
        swarm_name: str = "injection",
        task_name: str = "injection_url_task",
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Phase 9 T-3: Budget-enforced per-URL dispatch for Injection URLs.

        Integrates _build_per_url_sub_result() budget enforcement with actual
        swarm dispatch, followed by deterministic post-join merge via
        _merge_per_url_sub_results().

        For each URL:
        1. _build_per_url_sub_result(origin_key) checks budget
        2. If rejected/skipped: record PerUrlSubResult immediately, skip dispatch
        3. If allowed: dispatch to swarm via _dispatch_to_single_swarm,
           collect findings into PerUrlSubResult

        After all URLs: deterministic merge with skip/reject evidence.

        Returns:
            Merged dict with keys: findings, url_results, tested_params, counts
            Counts include success, skipped, rejected, failed, total.
        """
        sub_results: List[PerUrlSubResult] = []

        for url in urls:
            sub_result = self._build_per_url_sub_result(
                source_url=url,
                origin_key=origin_key,
            )

            if sub_result.is_skipped_or_rejected:
                sub_results.append(sub_result)
                continue

            # Budget allowed — dispatch to swarm
            try:
                swarm_result = await self._dispatch_to_single_swarm(
                    swarm_name=swarm_name,
                    target=url,
                    task_name=task_name,
                    params=params or {},
                )
                if swarm_result:
                    sub_result.findings = swarm_result.findings
                    sub_result.status = swarm_result.status
                    if swarm_result.status == "failed":
                        sub_result.error = (
                            swarm_result.execution_log[0].get("error", "swarm_dispatch_failed")
                            if swarm_result.execution_log
                            else "swarm_dispatch_failed"
                        )
                else:
                    sub_result.status = "failed"
                    sub_result.error = "swarm_result_none"
            except Exception as e:
                sub_result.status = "failed"
                sub_result.error = str(e)

            sub_results.append(sub_result)

        # Post-join deterministic merge
        return self._merge_per_url_sub_results(sub_results)

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
            swarm = None
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
            finally:
                if swarm is not None and hasattr(swarm, "close"):
                    try:
                        await swarm.close()
                    except Exception as ce:
                        logger.error("[dispatch_to_all] Error closing %s: %s", swarm_name, ce)
        
        return results


# シングルトンインスタンス
_dispatcher: Optional[SwarmDispatcher] = None
_dispatcher_lock = threading.Lock()  # Phase 5 (SGK-2026-0314 LB-7)


def get_swarm_dispatcher(config: Optional[Dict[str, Any]] = None, network_client: Any = None, llm_client: Any = None, loop: Any = None, event_bus: Any = None) -> SwarmDispatcher:
    """SwarmDispatcher のシングルトンを取得

    初回呼び出し時に渡されたパラメータで初期化され、以降は同じインスタンスを返す。
    2 回目以降の呼び出しでパラメータが指定された場合、常に上書き更新する。
    これにより、並列実行時のレースコンディションを防止する。

    Thread-safe (Phase 5 LB-7): _dispatcher_lock protects singleton access.
    """
    global _dispatcher
    with _dispatcher_lock:
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
