"""
外部ツール統合アダプターモジュール

統一されたインターフェースで外部セキュリティツールを管理・実行する基盤。
"""

from .base_external_adapter import BaseExternalAdapter, ToolInput, ToolResult, ToolStatus
from .binary_manager import BinaryManager, BinaryVerificationError

__all__ = [
    "BaseExternalAdapter",
    "ToolInput",
    "ToolResult",
    "ToolStatus",
    "BinaryManager",
    "BinaryVerificationError",
]
