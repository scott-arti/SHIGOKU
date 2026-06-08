"""
SecurityMiddleware - ガードレールのミドルウェア統合

Specialistの実行前後でセキュリティチェックを行うデコレータを提供する。
"""

import logging
from functools import wraps
from typing import Any, Callable, Dict, Optional

from src.core.models.finding import Finding
from src.core.security.guardrails import InputGuardrail, OutputGuardrail

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """セキュリティ違反によるエラー"""
    pass


def with_input_guard(func: Callable) -> Callable:
    """
    入力ガードレールデコレータ
    
    Task.params 内の値をチェックし、Prompt Injection 等を検知する。
    
    使用例:
    @with_input_guard
    async def execute(self, task: Task):
        pass
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # args[0] is self, args[1] is usually task
        # kwargs might contain task
        
        task = kwargs.get("task")
        if not task and len(args) > 1:
            task = args[1]
            
        if hasattr(task, "params") and isinstance(task.params, dict):
            # params 内の全文字列値をチェック
            for key, value in task.params.items():
                if isinstance(value, str):
                    is_safe, reason = InputGuardrail.check(value)
                    if not is_safe:
                        logger.warning(
                            "Input blocked by guardrail for task %s (param: %s): %s",
                            task.id, key, reason
                        )
                        raise SecurityError(f"Dangerous input detected: {reason}")
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            is_safe, reason = InputGuardrail.check(item)
                            if not is_safe:
                                logger.warning(
                                    "Input blocked by guardrail for task %s (param: %s): %s",
                                    task.id, key, reason
                                )
                                raise SecurityError(f"Dangerous input detected: {reason}")

        return await func(*args, **kwargs)
    return wrapper


def with_output_guard(func: Callable) -> Callable:
    """
    出力ガードレールデコレータ (コマンド実行等)
    
    危険なコマンド実行を検知する。
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        cmd = kwargs.get("cmd") or (args[1] if len(args) > 1 else None)
        
        if cmd and isinstance(cmd, str):
            is_safe, reason = OutputGuardrail.check(cmd)
            if not is_safe:
                logger.error(f"Command blocked by guardrail: {reason}")
                raise SecurityError(f"Dangerous command detected: {reason}")
                
        return await func(*args, **kwargs)
    return wrapper
