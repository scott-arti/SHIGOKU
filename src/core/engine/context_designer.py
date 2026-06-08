"""
ContextDesigner: タスク強化エンジン

実行前のタスクに対して、蓄積されたコンテキスト（認証トークン、技術スタック、WAF情報など）を
注入し、タスクの成功率を高めるための調整を行う。
"""

import logging
from typing import Optional, Dict, Any, List

from src.core.agents.swarm.base import Task
from src.core.engine.master_conductor import ExecutionContext
from src.core.engine.task_queue import TaskContext

logger = logging.getLogger(__name__)

class ContextDesigner:
    """
    タスク強化を行うデザイナー
    """

    def __init__(self):
        pass

    def enrich_task(
        self, 
        task: Task, 
        context: ExecutionContext, 
        accumulated_context: Optional[TaskContext] = None,
        workspace: Any = None
    ) -> Task:
        """
        タスクにコンテキスト情報を注入して強化する
        
        Args:
            task: 対象タスク
            context: MasterConductorの実行コンテキスト (TargetInfo, History)
            accumulated_context: 蓄積された技術コンテキスト (Tokens, Endpoints)
            
        Returns:
            強化されたタスク
        """
        # 1. Aggressive Mode 継承
        aggressive_targets = context.target_info.get("aggressive_targets", [])
        target = task.params.get("target", "")
        if target and target in aggressive_targets:
            if not task.params.get("is_aggressive"):
                task.params["is_aggressive"] = True
                logger.debug(f"[{task.name}] Enriched with is_aggressive=True")

        # 2. Target Info からの Raw Cookie 注入 (最優先)
        # ScopeParser 等が取得した生のクッキー文字列 (PHPSESSID=... など) を使用
        raw_cookie = context.target_info.get("cookies", "")
        if raw_cookie:
            if "cookies" not in task.params:
                task.params["cookies"] = raw_cookie
            else:
                # 既存の params["cookies"] があれば結合 (ただし重複に注意)
                if raw_cookie not in task.params["cookies"]:
                    task.params["cookies"] = f"{task.params['cookies']}; {raw_cookie}"
            logger.debug(f"[{task.name}] Enriched with raw cookies from target_info")

        # 3. Accumulated Context (Tokens, WAF, etc) 注入
        if accumulated_context:
            # 認証トークン
            if accumulated_context.auth_tokens:
                if "headers" not in task.params:
                    task.params["headers"] = {}
                
                # 自動的にAuthorizationヘッダーを構築
                for token_type, token_val in accumulated_context.auth_tokens.items():
                    if token_type.lower() == "bearer":
                        task.params["headers"]["Authorization"] = f"Bearer {token_val}"
                    elif token_type.lower() == "jwt":
                        if "Authorization" not in task.params["headers"]:
                            task.params["headers"]["Authorization"] = f"Bearer {token_val}"
                    elif token_type.lower() == "session":
                        # Cookieとして追加 (既にRaw Cookieに含まれている場合はスキップ)
                        cookie_str = task.params.get("cookies", "")
                        if token_val not in cookie_str:
                            if cookie_str:
                                cookie_str += f"; session_id={token_val}"
                            else:
                                cookie_str = f"session_id={token_val}"
                            task.params["cookies"] = cookie_str
                
                logger.debug(f"[{task.name}] Enriched with {len(accumulated_context.auth_tokens)} auth tokens")

            # WAF情報 -> 回避オプション
            if accumulated_context.waf_info:
                if "waf_bypass" not in task.params:
                    task.params["waf_bypass"] = True
                    task.params["waf_info"] = accumulated_context.waf_info
                    logger.debug(f"[{task.name}] Enriched with WAF bypass context")

            # 技術スタック -> Tags追加
            if accumulated_context.tech_stack:
                current_tags = task.params.get("tags", [])
                new_tags = []
                for tech in accumulated_context.tech_stack:
                    if "php" in tech.lower() and "php" not in current_tags:
                        new_tags.append("php")
                    if "sql" in tech.lower() and "db" not in current_tags:
                        new_tags.append("db")
                
                if new_tags:
                    task.params["tags"] = list(set(current_tags + new_tags))
                    logger.debug(f"[{task.name}] Enriched with tags: {new_tags}")

        # 3. Target Info からの注入 (Scope, Credentials)
        # 認証情報が既知の場合
        if context.target_info.get("has_credentials"):
            # Credentialを含む辞書があれば注入 (security riskあるため慎重に)
            creds = context.target_info.get("credentials", {})
            if creds:
                task.params["credentials"] = creds
                logger.debug(f"[{task.name}] Enriched with user credentials")

        # 4. Workspace からのマルチセッション情報注入
        if workspace and hasattr(workspace, "get_user_sessions"):
            user_sessions = workspace.get_user_sessions()
            if user_sessions:
                # 自身の現在の認証情報 (auth_tokens等) と重複しないものを alternative として注入
                # ここではシンプルに全て注入し、エージェント側で判断させる
                task.params["alternative_sessions"] = user_sessions
                logger.debug(f"[{task.name}] Enriched with {len(user_sessions)} alternative sessions")

        return task
