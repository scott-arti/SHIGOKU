"""
Profiling Utilities for SHIGOKU

Provides decorators to measure execution time of functions and methods,
logging warnings if they exceed a specified threshold.
"""
import time
import functools
import logging
from typing import Optional, Any, Callable, TypeVar, cast

logger = logging.getLogger("shigoku.perf")

# Type variables for better type hinting support
F = TypeVar('F', bound=Callable[..., Any])

def timed(name: Optional[str] = None, threshold_ms: int = 100) -> Callable[[F], F]:
    """
    Decorator to measure execution time of a synchronous function.
    
    Args:
        name: Optional name for the operation. Defaults to function's qualified name.
        threshold_ms: Threshold in milliseconds. Logs a warning if exceeded.
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                duration_ms = (time.perf_counter() - start_time) * 1000
                if duration_ms > threshold_ms:
                    op_name = name or func.__qualname__
                    logger.warning("SLOW_OP: %s took %.2fms (threshold: %dms)", op_name, duration_ms, threshold_ms)
        return cast(F, wrapper)
    return decorator

def timed_async(name: Optional[str] = None, threshold_ms: int = 100) -> Callable[[F], F]:
    """
    Decorator to measure execution time of an asynchronous function.
    
    Args:
        name: Optional name for the operation. Defaults to function's qualified name.
        threshold_ms: Threshold in milliseconds. Logs a warning if exceeded.
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.perf_counter()
            try:
                return await func(*args, **kwargs)
            finally:
                duration_ms = (time.perf_counter() - start_time) * 1000
                if duration_ms > threshold_ms:
                    op_name = name or func.__qualname__
                    logger.warning("SLOW_OP: %s took %.2fms (threshold: %dms)", op_name, duration_ms, threshold_ms)
        return cast(F, wrapper)
    return decorator
