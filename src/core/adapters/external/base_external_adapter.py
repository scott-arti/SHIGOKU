"""
BaseExternalAdapter: 外部ツール統合の抽象基底クラス

型安全なインターフェースを提供し、全ての外部ツールアダプターの基底となる。
過度な抽象化を避け、柔軟な拡張ポイントを確保する設計。
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Tuple
from pathlib import Path
import asyncio
import logging

from .external_tool_logger import ExternalToolLogger, get_logger
from .constants import ToolStatusValue

logger = logging.getLogger(__name__)


class ToolStatus(Enum):
    """ツール実行結果の状態
    
    ToolStatusValueと同期を保つこと
    """
    SUCCESS = ToolStatusValue.SUCCESS
    FAILURE = ToolStatusValue.FAILURE
    TIMEOUT = ToolStatusValue.TIMEOUT
    ERROR = ToolStatusValue.ERROR


@dataclass
class ToolInput:
    """ツール入力の型安全なコンテナ
    
    全ての外部ツールアダプターが受け入れる標準入力形式。
    ツール固有の追加パラメータはkwargsで柔軟に受け入れる。
    """
    target: str
    options: Optional[Dict[str, Any]] = None
    timeout_seconds: int = 60
    retry_count: int = 0
    # ツール固有の追加パラメータ（柔軟な拡張ポイント）
    kwargs: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    """ツール実行結果の型安全なコンテナ
    
    全ての外部ツールアダプターが返却する標準出力形式。
    統一された戻り値でAIエージェントが構造化データを理解可能に。
    """
    status: ToolStatus
    data: Any
    execution_time_ms: float
    error_message: Optional[str] = None
    raw_output: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class BaseExternalAdapter(ABC):
    """外部ツールアダプターの抽象基底クラス
    
    全ての外部ツール（DalFox, Nuclei, Nmap等）のアダプターは
    このクラスを継承し、抽象メソッドを実装すること。
    
    設計原則:
    - 過度な抽象化を避ける（抽象メソッドは最小限3つのみ）
    - **kwargsによる柔軟な拡張ポイントを確保
    - 型安全な入出力（ToolInput/ToolResult）
    - 例外戦略はtry-exceptブロックで統一
    
    Example:
        class DalFoxAdapter(BaseExternalAdapter):
            async def execute(self, input_data: ToolInput) -> ToolResult:
                try:
                    result = await self._run_dalfox(input_data.target)
                    return ToolResult(
                        status=ToolStatus.SUCCESS,
                        data=result,
                        execution_time_ms=elapsed_time
                    )
                except asyncio.TimeoutError:
                    return ToolResult(
                        status=ToolStatus.TIMEOUT,
                        data=None,
                        execution_time_ms=timeout_ms,
                        error_message="DalFox execution timed out"
                    )
                except Exception as e:
                    return ToolResult(
                        status=ToolStatus.ERROR,
                        data=None,
                        execution_time_ms=0,
                        error_message=str(e)
                    )
    """
    
    def __init__(self, tool_name: str, config: Optional[Dict[str, Any]] = None):
        """初期化
        
        Args:
            tool_name: ツール識別名（loggingや設定参照用）
            config: ツール固有の設定辞書
        """
        self.tool_name = tool_name
        self.config = config or {}
        self.logger = logging.getLogger(f"external_tool.{tool_name}")
    
    @abstractmethod
    async def execute(self, input_data: ToolInput) -> ToolResult:
        """ツールを実行し、結果を返却
        
        全ての具象アダプターはこのメソッドを実装すること。
        例外は全てキャッチし、ToolResultのstatusで表現すること。
        
        Args:
            input_data: 標準化された入力（ToolInput）
            
        Returns:
            ToolResult: 標準化された実行結果
        """
        pass
    
    @abstractmethod
    def validate_inputs(self, input_data: ToolInput) -> Tuple[bool, Optional[str]]:
        """入力検証
        
        実行前に入力パラメータの妥当性を検証。
        
        Args:
            input_data: 検証対象の入力
            
        Returns:
            Tuple[bool, Optional[str]]: (検証結果OKか, エラーメッセージ)
            検証OK時: (True, None)
            検証NG時: (False, "エラー説明")
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """ヘルスチェック
        
        ツールが利用可能かどうかを確認。
        バイナリ存在確認、バージョンチェック、基本的な実行テストを実施。
        
        Returns:
            bool: ツールが利用可能ならTrue
        """
        pass
    
    async def run_with_validation(self, input_data: ToolInput) -> ToolResult:
        """入力検証付きでツールを実行
        
        標準的な実行フロー:
        1. 入力検証
        2. ヘルスチェック
        3. ツール実行
        4. 結果ロギング
        
        Args:
            input_data: 実行入力
            
        Returns:
            ToolResult: 実行結果
        """
        # ExternalToolLogger取得
        tool_logger = get_logger(self.tool_name)
        
        # 1. 入力検証
        is_valid, error_msg = self.validate_inputs(input_data)
        if not is_valid:
            result = ToolResult(
                status=ToolStatus.ERROR,
                data=None,
                execution_time_ms=0,
                error_message=f"Input validation failed: {error_msg}"
            )
            tool_logger.info_execution([], result, {"target": input_data.target})
            return result
        
        # 2. ヘルスチェック
        if not await self.health_check():
            result = ToolResult(
                status=ToolStatus.ERROR,
                data=None,
                execution_time_ms=0,
                error_message=f"Tool '{self.tool_name}' is not available"
            )
            tool_logger.info_execution([], result, {"target": input_data.target})
            return result
        
        # 3. 実行
        result = await self.execute(input_data)
        
        # 4. ロギング
        tool_logger.info_execution([], result, {"target": input_data.target})
        tool_logger.debug_execution([], result, {"target": input_data.target})
        
        return result
