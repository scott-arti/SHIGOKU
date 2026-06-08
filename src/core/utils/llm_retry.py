import asyncio
import random
import time
import logging
import functools
from typing import Any, Callable, TypeVar, cast, Awaitable

import litellm
try:
    from litellm.exceptions import (
        RateLimitError, 
        ServiceUnavailableError, 
        Timeout, 
        InternalServerError,
    )
except ImportError:
    # 実行環境にlitellmがない場合（テスト時など）のフォールバック
    class RateLimitError(Exception): pass
    class ServiceUnavailableError(Exception): pass
    class Timeout(Exception): pass
    class InternalServerError(Exception): pass

logger = logging.getLogger(__name__)

T = TypeVar("T")

def retry_llm(
    max_retries: int = 3,
    initial_backoff: float = 1.0,
    max_backoff: float = 60.0,
    backoff_factor: float = 2.0,
    jitter: bool = True
):
    """
    LLM API呼び出し用のリトライデコレータ
    
    指数バックオフとジッター（Jitter）を実装し、Thundering Herd問題を回避する。
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            retries = 0
            while True:
                try:
                    return await func(*args, **kwargs)
                except (RateLimitError, ServiceUnavailableError, Timeout, InternalServerError) as e:
                    retries += 1
                    if retries > max_retries:
                        logger.error(f"LLM API MAX RETRIES REACHED: {func.__name__} failed: {e}")
                        raise e
                    
                    # バックオフ計算
                    wait_time = min(max_backoff, initial_backoff * (backoff_factor ** (retries - 1)))
                    if jitter:
                        wait_time = wait_time * (0.5 + random.random())
                    
                    logger.warning(
                        f"LLM API Error ({type(e).__name__}). "
                        f"Retrying in {wait_time:.2f}s... (Attempt {retries}/{max_retries})"
                    )
                    await asyncio.sleep(wait_time)
                except Exception as e:
                    # 想定外のエラーは再試行せず即座に投げる
                    logger.error(f"LLM API Unrecoverable Error: {e}")
                    raise e

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            retries = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except (RateLimitError, ServiceUnavailableError, Timeout, InternalServerError) as e:
                    retries += 1
                    if retries > max_retries:
                        logger.error(f"LLM API MAX RETRIES REACHED (sync): {func.__name__} failed: {e}")
                        raise e
                    
                    wait_time = min(max_backoff, initial_backoff * (backoff_factor ** (retries - 1)))
                    if jitter:
                        wait_time = wait_time * (0.5 + random.random())
                    
                    logger.warning(
                        f"LLM API Error (sync) ({type(e).__name__}). "
                        f"Retrying in {wait_time:.2f}s... (Attempt {retries}/{max_retries})"
                    )
                    time.sleep(wait_time)
                except Exception as e:
                    logger.error(f"LLM API Unrecoverable Error (sync): {e}")
                    raise e

        # 非同期関数かどうかでラッパーを選択
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator
