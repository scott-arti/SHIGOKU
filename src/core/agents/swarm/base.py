"""
Swarm Base Classes: SwarmManager と Specialist

SwarmManager: 配下の Specialist を直列実行し、結果を蓄積して SwarmResult を返す
Specialist: 個別の攻撃ロジックを持つ実行者

Implementation Plan Section 2, 3.4 準拠
"""

import asyncio
import logging
from typing import List, Any, Dict, Optional, Type, Union, TypedDict
from datetime import datetime
from abc import ABC, abstractmethod

# TYPE_CHECKING を使わずにインポート (実行時に使用するため)
# 循環参照に注意


from src.core.models.swarm import SwarmResult
from src.core.models.finding import Finding
from src.core.security.middleware import with_input_guard

logger = logging.getLogger(__name__)

# Delayed imports to avoid cycles
# RetryEngine is imported in Specialist.__init__
# SharedWorkspace is imported in Specialist.workspace


from src.core.domain.model.task import Task


class ContextSchema(TypedDict, total=True):
    """Agent/Specialist 間で受け渡す実行コンテキストのスキーマ。

    全キーは必須（total=True）。省略可能キーが必要な場合は NotRequired[...] で個別制御する。
    project_id は workspace/projects/<project_id>/ 配下のファイルパス解決にも使用される。
    """

    project_id: str
    session_id: str
    auth_headers: Dict[str, str]


class Specialist(ABC):
    """
    個別の攻撃ロジックを持つ Specialist 基底クラス
    
    各 Specialist は特定の脆弱性タイプに特化した検査を行う。
    BaseAgent を継承せず、シンプルな構造を維持。
    """
    
    # サブクラスでオーバーライド
    name: str = "BaseSpecialist"
    description: str = "Base specialist class"
    timeout_seconds: int = 300
    is_aggressive: bool = False  # デフォルトで安全な検査
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._start_time: Optional[datetime] = None
        self.network_client: Any = None  # Shared Network Client
        self._workspace_instance: Optional['SharedWorkspace'] = None
        
        # RetryEngine 統合（遅延インポート）
        self._retry_engine = None
        try:
            from src.core.agents.swarm.retry_engine import SwarmRetryEngine, RetryConfig
            # Config値の取得 (Dict or Object)
            def _get_conf(key, default):
                if isinstance(self.config, dict):
                    return self.config.get(key, default)
                return getattr(self.config, key, default)

            retry_config = RetryConfig(
                max_attempts=_get_conf("max_attempts", 3),
                enable_mutation=_get_conf("enable_mutation", True),
                backoff_factor=_get_conf("backoff_factor", 1.0),
            )
            self._retry_engine = SwarmRetryEngine(retry_config)
        except ImportError:
            pass  # RetryEngine が利用不可な場合は無視
    
    @abstractmethod
    async def execute(self, task: Task) -> List[Finding]:
        """
        タスクを実行して Finding リストを返す
        
        Args:
            task: 実行タスク
        
        Returns:
            発見した脆弱性のリスト
        """
        pass
    
    async def execute_with_retry(self, task: Task, quick_mode: bool = False, **kwargs) -> List[Finding]:
        """
        リトライロジック付きで実行

        WAF Blocking 検出時に自動的にペイロードをミューテーションして再試行。
        
        Args:
            task: タスク情報
            quick_mode: True の場合、軽量モードで実行（ターン数制限あり）
            **kwargs: 追加引数
        """
        self._start_time = datetime.now()

        if self._retry_engine:
            try:
                findings, metadata = await self._retry_engine.execute_with_retry(
                    self.execute,
                    task,
                    quick_mode=quick_mode,
                    **kwargs
                )
                # メタデータを findings に付加
                for f in findings:
                    if hasattr(f, 'evidence') and isinstance(f.evidence, dict):
                        f.evidence["retry_metadata"] = metadata.to_dict()
                return findings
            except Exception as e:
                logger.error("Retry execution failed for %s: %s", self.name, e)
                return []
        else:
            # RetryEngine が利用不可な場合は通常実行
            return await self.run_with_timeout(task)
    
    @property
    def workspace(self) -> 'SharedWorkspace':
        """Lazy initialization of SharedWorkspace (Phase 2 core alignment)"""
        if not hasattr(self, "_workspace_instance") or self._workspace_instance is None:
            # We look for workspace_root in config or default to standard workspace
            def _get_conf(key, default):
                if isinstance(self.config, dict):
                    return self.config.get(key, default)
                return getattr(self.config, key, default)
            
            from src.core.workspace.shared_workspace import SharedWorkspace
            ws_root = _get_conf("workspace_root", "./workspace")
            self._workspace_instance = SharedWorkspace(workspace_root=str(ws_root))
        return self._workspace_instance

    def set_network_client(self, network_client: Any) -> None:
        """Shared Network Client を設定"""
        self.network_client = network_client

    async def close(self):
        """リソース解放 (サブクラスで必要に応じてオーバーライド)"""
        # Note: self.network_client は共有リソースのため、ここでは close しないこと。
        # MasterConductor がライフサイクルを管理する。
        for attr_name in dir(self):
            if attr_name == "network_client" or attr_name.startswith("__"):
                continue
            try:
                attr = getattr(self, attr_name)
                # 自前の NetworkClient や Tester クラスの client を安全に解放
                if type(attr).__name__ == "AsyncNetworkClient" and hasattr(attr, "close") and callable(attr.close):
                    await attr.close()
                elif hasattr(attr, "network_client") and type(attr.network_client).__name__ == "AsyncNetworkClient" and hasattr(attr.network_client, "close") and callable(attr.network_client.close):
                    if attr.network_client != getattr(self, "network_client", None):
                        await attr.network_client.close()
                elif hasattr(attr, "client") and type(attr.client).__name__ == "AsyncNetworkClient" and hasattr(attr.client, "close") and callable(attr.client.close):
                    if attr.client != getattr(self, "network_client", None):
                        await attr.client.close()
                elif hasattr(attr, "_client") and type(attr._client).__name__ == "AsyncNetworkClient" and hasattr(attr._client, "close") and callable(attr._client.close):
                    if attr._client != getattr(self, "network_client", None):
                        await attr._client.close()
            except Exception:
                pass

    @with_input_guard
    async def run_with_timeout(self, task: Task, **kwargs) -> List[Finding]:
        """タイムアウト付きで実行
        
        Args:
            task: 実行タスク
            **kwargs: Specialist.execute に渡す追加引数（例：quick_mode）
        """
        self._start_time = datetime.now()
        try:
            return await asyncio.wait_for(
                self.execute(task, **kwargs),
                timeout=self.timeout_seconds
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Specialist %s timed out after %ds", self.name, self.timeout_seconds
            )
            return []
        except Exception as e:
            logger.error("Specialist %s failed: %s", self.name, e)
            return []
    
    def _ingest_if_available(self, url: str, body: Optional[str] = None, role: Optional[str] = None):
        """レスポンスからIDを抽出して共有ワークスペースに蓄積（存在する場合のみ）"""
        if self.workspace:
            try:
                # 共有ワークスペースの統一APIを呼び出す
                self.workspace.ingest_response(url, body, role)
            except Exception as e: # pylint: disable=broad-except
                logger.debug("[%s] Automatic ID ingestion failed: %s", self.name, e)

    def get_execution_time(self) -> float:
        """実行時間を取得（秒）"""
        if self._start_time:
            return (datetime.now() - self._start_time).total_seconds()
        return 0.0


class SwarmManager(ABC):
    """
    Swarm Manager 基底クラス
    
    配下の Specialist を直列実行し、結果を蓄積して SwarmResult を返す。
    失敗した Specialist があっても Continue-on-Error で次へ進む。
    """
    
    # サブクラスでオーバーライド
    name: str = "BaseSwarm"
    description: str = "Base swarm manager"
    default_timeout_seconds: int = 600
    
    def __init__(self, config: Optional[Union[Dict[str, Any], 'AgentConfig']] = None, project_manager: Any = None, master_conductor: Any = None, workspace_root: Optional[str] = None):
        self.config = config or {}
        self.project_manager = project_manager
        self.master_conductor = master_conductor
        self.workspace_root = workspace_root
        
        self.network_client: Any = None  # Shared Network Client
        self.llm_client: Any = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._specialists: List[Specialist] = []
        self._recipe_loader = None  # Swarm 用 RecipeLoader (遅延初期化)
        self._rag = None  # Swarm 用 RAG (遅延初期化)
        
        # Concurrency control
        max_concurrent = self.config.get("max_concurrent_tasks", 5)
        self.semaphore = asyncio.Semaphore(max_concurrent)
        logger.debug("[%s] Initialized with semaphore (limit=%d)", self.name, max_concurrent)
    
    async def close(self) -> None:
        """配下の Specialist のリソースを解放"""
        for specialist in self._specialists:
            try:
                await specialist.close()
            except Exception as e:
                logger.error(f"Error closing specialist {specialist.name}: {e}")
        
        # Specialists リストをクリア
        self._specialists.clear()
    
    @abstractmethod
    def get_specialists(self, tags: List[str]) -> List[Specialist]:
        """
        タグに応じて実行する Specialist リストを返す
        
        Args:
            tags: タスクのタグリスト
        
        Returns:
            実行する Specialist のリスト
        """
        pass
    
    def set_recipe_loader(self, recipe_loader) -> None:
        """RecipeLoader を設定（MC ではなく Swarm で使用）"""
        self._recipe_loader = recipe_loader
    
    def set_rag(self, rag) -> None:
        """RAG を設定（MC ではなく Swarm で使用）"""
        self._rag = rag
        
    def set_network_client(self, client: Any) -> None:
        """Shared Network Client を設定"""
        self.network_client = client
        # 配下の Specialist にも伝播
        # Note: _specialists は List[Specialist] なので、.values() は使用しない
        for s in self._specialists:
            if hasattr(s, 'set_network_client'):
                s.set_network_client(client)

    def set_llm_client(self, client: Any) -> None:
        """Shared LLM Client を設定"""
        self.llm_client = client

    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Shared Event Loop を設定"""
        self.loop = loop
    
    async def run(self, task_dict: Dict[str, Any]) -> Any:
        """MasterConductor compatibility: run task from dict."""
        from src.core.domain.model.task import Task
        task = Task(**task_dict)
        return await self.dispatch(task)

    async def process(self, task_input: str) -> str:
        """MasterConductor compatibility: process task from JSON string."""
        import json
        from src.core.domain.model.task import Task
        params = json.loads(task_input)
        task = Task(id=params.get("id", "tmp"), name=params.get("name", "process_task"), target=params.get("target", ""), tags=params.get("tags", []), params=params)
        result = await self.dispatch(task)
        return str(result)

    async def dispatch(self, task: Task) -> SwarmResult:
        """
        タスクを受け取り、配下の Specialist を直列実行
        
        Args:
            task: 実行タスク
        
        Returns:
            全 Specialist の結果を蓄積した SwarmResult
        """
        start_time = datetime.now()
        all_findings: List[Finding] = []
        execution_log: List[Dict[str, Any]] = []
        
        specialists = self.get_specialists(task.tags)
        total_specialists = len(specialists)
        successful_count = 0
        failed_count = 0
        
        logger.info(
            "[%s] Dispatching task '%s' to %d specialists",
            self.name, task.name, total_specialists
        )
        
        for specialist in specialists:
            specialist_start = datetime.now()
            try:
                # Semaphore による同時実行制御
                async with self.semaphore:
                    findings = await specialist.run_with_timeout(task)
                
                all_findings.extend(findings)
                
                execution_log.append({
                    "specialist": specialist.name,
                    "status": "success",
                    "findings_count": len(findings),
                    "execution_time": specialist.get_execution_time(),
                })
                successful_count += 1
                
                logger.info(
                    "  [%s] Completed: %d findings",
                    specialist.name, len(findings)
                )

                # --- Tier 4: Adaptive logic - Skip remaining specialists if a critical finding is found ---
                from src.core.models.finding import Severity
                critical_findings = [f for f in findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
                if critical_findings and task.params.get("adaptive_skip_enabled", True):
                    logger.warning(
                        "[%s] 🚨 Critical/High finding detected by %s. Skipping remaining %d specialists to escalate.",
                        self.name, specialist.name, len(specialists) - (specialists.index(specialist) + 1)
                    )
                    # 残りの Specialist をスキップとして記録
                    for remaining in specialists[specialists.index(specialist) + 1:]:
                        execution_log.append({
                            "specialist": remaining.name,
                            "status": "skipped",
                            "reason": "critical_finding_detected"
                        })
                    break
                
            except Exception as e:
                # Continue-on-Error: 次の Specialist へ進む
                execution_log.append({
                    "specialist": specialist.name,
                    "status": "failed",
                    "error": str(e),
                    "execution_time": (datetime.now() - specialist_start).total_seconds(),
                })
                failed_count += 1
                
                logger.warning(
                    "  [%s] Failed: %s (continuing)",
                    specialist.name, e
                )
            finally:
                # Specialist のリソース解放 (AsyncNetworkClient 等)
                try:
                    await specialist.close()
                except Exception as e:
                    logger.error("Error closing specialist %s: %s", specialist.name, e)
        
        # ステータス判定
        if failed_count == 0:
            status = "success"
        elif successful_count > 0:
            status = "partial_success"
        else:
            status = "failed"
        
        total_time = (datetime.now() - start_time).total_seconds()
        
        # Finding にタグを継承
        for finding in all_findings:
            if not finding.tags:
                finding.tags = list(task.tags)
        
        # output_tags を生成 (findings から追加タグを収集)
        output_tags = list(task.tags)  # input_tags をベースに
        for finding in all_findings:
            # 発見した脆弱性タイプに基づいて追加タグを生成
            vuln_value = finding.vuln_type.value
            if vuln_value == "sqli":
                output_tags.append("sqli_confirmed")
            elif vuln_value == "xss":
                output_tags.append("xss_confirmed")
            elif vuln_value == "ssrf":
                output_tags.append("ssrf_confirmed")
            elif vuln_value == "idor":
                output_tags.append("idor_confirmed")
            elif vuln_value == "lfi":
                output_tags.append("lfi_confirmed")
            elif vuln_value.startswith("jwt_"):
                output_tags.append("jwt_vuln_confirmed")
            elif vuln_value.startswith("oauth_"):
                output_tags.append("oauth_vuln_confirmed")
            elif vuln_value == "mfa_bypass":
                output_tags.append("mfa_bypass_confirmed")
            elif vuln_value == "secret_leak":
                output_tags.append("secret_leak_confirmed")
            elif vuln_value == "api_key_exposure":
                output_tags.append("secret_leak_confirmed")  # 統一して secret_leak として扱う
            elif vuln_value == "broken_access_control":
                output_tags.append("broken_access_control_confirmed")
        output_tags = list(set(output_tags))  # 重複除去
        
        result = SwarmResult(
            findings=all_findings,
            status=status,
            execution_log=execution_log,
            swarm_name=self.name,
            total_specialists=total_specialists,
            successful_specialists=successful_count,
            failed_specialists=failed_count,
            execution_time_seconds=total_time,
            input_tags=list(task.tags),  # 入力タグを記録
            output_tags=output_tags,  # 出力タグを記録
        )
        
        logger.info(
            f"[{self.name}] Completed: {status}, "
            f"{len(all_findings)} findings, {total_time:.1f}s"
        )
        
        return result
    
    def register_specialist(self, specialist: Specialist) -> None:
        """Specialist を登録"""
        # 共有クライアントがあれば注入
        if self.network_client and hasattr(specialist, 'set_network_client'):
            specialist.set_network_client(self.network_client)
            
        self._specialists.append(specialist)
        logger.debug(f"Registered specialist: {specialist.name}")
    
    def register_specialists(self, specialists: List[Specialist]) -> None:
        """複数の Specialist を一括登録"""
        for specialist in specialists:
            self.register_specialist(specialist)


# =====================================================
# Specialist 登録用ユーティリティ
# =====================================================

def create_specialist_from_class(
    specialist_class: Type[Specialist],
    config: Optional[Dict[str, Any]] = None
) -> Specialist:
    """Specialist クラスからインスタンスを生成"""
    return specialist_class(config=config)
