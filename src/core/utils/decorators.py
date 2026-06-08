"""
Tool Execution Decorators

ツール実行制御のためのデコレータ
"""

from functools import wraps
from typing import Callable, Any
import logging

logger = logging.getLogger(__name__)


def require_tool(tool_name: str):
    """
    ツールが有効な場合のみ関数を実行するデコレータ
    
    Usage:
        @require_tool("jwt_inspector")
        def run_jwt_attack(...):
            ...
    
    Args:
        tool_name: ツールレジストリ内のツール名
    
    Returns:
        デコレータ関数
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            from src.core.tool_registry import get_tool_registry
            
            registry = get_tool_registry()
            
            if not registry.is_enabled(tool_name):
                logger.info(f"Tool '{tool_name}' is disabled by mode preset, skipping {func.__name__}")
                return None
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_any_tool(*tool_names: str):
    """
    複数のツールのうち、いずれか1つが有効な場合に関数を実行
    
    Usage:
        @require_any_tool("jwt_inspector", "oauth_dancer")
        def run_auth_tests(...):
            ...
    
    Args:
        *tool_names: ツール名のリスト
    
    Returns:
        デコレータ関数
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            from src.core.tool_registry import get_tool_registry
            
            registry = get_tool_registry()
            enabled_tools = [t for t in tool_names if registry.is_enabled(t)]
            
            if not enabled_tools:
                logger.info(
                    f"None of the required tools {tool_names} are enabled, "
                    f"skipping {func.__name__}"
                )
                return None
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_all_tools(*tool_names: str):
    """
    複数のツールが全て有効な場合のみ関数を実行
    
    Usage:
        @require_all_tools("cartographer", "fingerprinter")
        def run_full_recon(...):
            ...
    
    Args:
        *tool_names: ツール名のリスト
    
    Returns:
        デコレータ関数
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            from src.core.tool_registry import get_tool_registry
            
            registry = get_tool_registry()
            disabled_tools = [t for t in tool_names if not registry.is_enabled(t)]
            
            if disabled_tools:
                logger.info(
                    f"Required tools {disabled_tools} are disabled, "
                    f"skipping {func.__name__}"
                )
                return None
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator
