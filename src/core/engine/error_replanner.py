"""
ErrorReplanner: エラー分析と回復計画の生成

失敗したタスクのエラー内容を分析し、
静的ルールやLLMを用いて回復のための代替タスク（リプラン）を生成する。
Implementation Plan Phase 1.5 準拠
"""

import logging
from typing import List, Optional, Any, Dict, TYPE_CHECKING
from src.config import settings

if TYPE_CHECKING:
    from src.core.engine.master_conductor import Task, ExecutionContext

logger = logging.getLogger(__name__)

class ErrorReplanner:
    """
    エラー分析とリプラン生成を担当するコンポーネント
    """
    
    def __init__(self, rag_client=None, llm_client=None):
        self.rag_client = rag_client
        self.llm_client = llm_client
        
    def analyze_error_and_replan(
        self, 
        failed_task: Any,  # Task type, type checked via TYPE_CHECKING
        error_message: str, 
        context: Optional['ExecutionContext'] = None
    ) -> List[Any]: # Returns List[Task]
        """
        エラーを分析して再実行または代替手段のタスクを生成する
        
        Args:
            failed_task: 失敗したタスク
            error_message: エラー詳細
            context: 現在の実行コンテキスト
            
        Returns:
            代替タスクのリスト
        """
        # Local import to avoid circular dependency
        from src.core.engine.master_conductor import Task
        
        alternative_tasks = []
        error_lower = error_message.lower()
        
        # 1. Static Rules (高速・低コスト)
        
        # 403 Forbidden / Access Denied -> Proxy Rotation
        if any(x in error_lower for x in ["403", "forbidden", "access denied", "blocked"]):
            logger.info(f"[ErrorReplanner] Detected Access Blocking for task {failed_task.id}")
            
            # プロキシ有効化で再試行
            alt_task_params = failed_task.params.copy()
            alt_task_params["use_proxy_rotation"] = True
            
            # タスクParamsにタグを保持
            if hasattr(failed_task, "tags") and failed_task.tags:
                 alt_task_params["tags"] = failed_task.tags

            alternative_tasks.append(Task(
                id=f"{failed_task.id}_retry_proxy",
                name=f"Retry with Proxy: {failed_task.name}",
                agent_type=failed_task.agent_type,
                action=failed_task.action,
                params=alt_task_params,
                priority=failed_task.priority + 10,  # 優先度を上げて再試行
            ))
            
            # 可能ならWAFバイパスも検討
            bypass_methods = context.bypass_methods if context else []
            for method in bypass_methods:
                bypass_params = failed_task.params.copy()
                bypass_params["bypass_method"] = method
                if hasattr(failed_task, "tags") and failed_task.tags:
                     bypass_params["tags"] = failed_task.tags + ["bypass_attempt"]
                
                alternative_tasks.append(Task(
                    id=f"{failed_task.id}_retry_{method}",
                    name=f"Retry with Bypass ({method}): {failed_task.name}",
                    agent_type=failed_task.agent_type,
                    action=failed_task.action,
                    params=bypass_params,
                    priority=failed_task.priority + 15,
                ))

        # Timeout / Connection Error -> Delay & Retry
        elif any(x in error_lower for x in ["timeout", "timed out", "connection error", "connection refused"]):
            logger.info(f"[ErrorReplanner] Detected Connection Issue for task {failed_task.id}")
            
            retry_params = failed_task.params.copy()
            retry_params["delay_seconds"] = 5
            if hasattr(failed_task, "tags") and failed_task.tags:
                 retry_params["tags"] = failed_task.tags
            
            alternative_tasks.append(Task(
                id=f"{failed_task.id}_retry_delay",
                name=f"Retry with Delay: {failed_task.name}",
                agent_type=failed_task.agent_type,
                action=failed_task.action,
                params=retry_params,
                priority=failed_task.priority + 5,
            ))

        # 429 Too Many Requests -> Backoff
        elif "429" in error_lower or "too many requests" in error_lower:
            logger.info("[ErrorReplanner] Detected Rate Limiting for task %s", failed_task.id)
             
            backoff_params = failed_task.params.copy()
            backoff_params["delay_seconds"] = 30
            backoff_params["use_proxy_rotation"] = True # プロキシも変える
            if hasattr(failed_task, "tags") and failed_task.tags:
                 backoff_params["tags"] = failed_task.tags
             
            alternative_tasks.append(Task(
                id=f"{failed_task.id}_retry_backoff",
                name=f"Retry with Backoff (30s): {failed_task.name}",
                agent_type=failed_task.agent_type,
                action=failed_task.action,
                params=backoff_params,
                priority=failed_task.priority + 20, # 高優先度で確実に
            ))

        # 2. RAG Hints (中コスト)
        # 既存ルールでカバーできない、かつRAGが有効な場合
        if not alternative_tasks and self.rag_client:
            try:
                hints = self.rag_client.query(f"how to bypass {error_message}", n_results=2)
                for i, hint in enumerate(hints):
                    hint_content = hint.content if hasattr(hint, 'content') else str(hint)
                    
                    rag_params = failed_task.params.copy()
                    rag_params["rag_hint"] = hint_content
                    if hasattr(failed_task, "tags") and failed_task.tags:
                         rag_params["tags"] = failed_task.tags + ["rag_assisted"]
                    
                    alternative_tasks.append(Task(
                        id=f"{failed_task.id}_rag_hint_{i}",
                        name=f"Retry with RAG Hint {i+1}",
                        agent_type=failed_task.agent_type,
                        action=failed_task.action,
                        params=rag_params,
                        priority=failed_task.priority + 5,
                    ))
            except Exception as e:
                logger.warning("[ErrorReplanner] RAG query failed: %s", e)

        # 3. LLM Analysis (高コスト・最終手段)
        # まだ解決策がなく、かつ複雑なエラーの場合
        # (コスト削減のため、設定で有効な場合のみ)
        if not alternative_tasks and self.llm_client and settings.use_llm_planning:
             # ここでLLMを呼び出してエラー分析と提案を行わせる
             # TODO: Implement LLM based replanning logic derived from MasterConductor._observe_and_rethink
             pass

        if alternative_tasks:
            logger.info(f"[ErrorReplanner] Generated {len(alternative_tasks)} recovery tasks for {failed_task.id}")
            
        return alternative_tasks
