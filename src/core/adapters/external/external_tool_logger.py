"""
ExternalToolLogger: 外部ツール実行の詳細ロギング制御

DEBUG/INFOレベル使い分けとパフォーマンス影響閾値（5倍以上遅延時警告）を実装。
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .constants import ToolStatusValue

if TYPE_CHECKING:
    from .base_external_adapter import ToolResult


@dataclass
class LogLevelConfig:
    """ログレベル設定"""
    # INFOレベル: 基本情報のみ
    info_level_fields: List[str] = field(default_factory=lambda: [
        "tool_name", "status", "execution_time_ms"
    ])
    
    # DEBUGレベル: 詳細情報
    debug_level_fields: List[str] = field(default_factory=lambda: [
        "tool_name", "status", "execution_time_ms", "command",
        "raw_output", "error_message", "metadata"
    ])


@dataclass
class PerformanceThresholds:
    """パフォーマンス閾値設定"""
    # 警告閾値: 5倍以上遅延時に警告
    warning_slow_factor: float = 5.0
    # エラーを発生させる閾値: 10倍以上遅延時
    error_slow_factor: float = 10.0
    # 基準実行時間（ms）- これより長い場合は警告対象
    baseline_execution_time_ms: float = 1000.0


class ExternalToolLogger:
    """外部ツール実行の詳細ロギング制御クラス
    
    DEBUG/INFOレベルの使い分けとパフォーマンス影響監視を実装。
    
    設計方針:
    - INFOレベル: 基本情報のみ（ツール名、ステータス、実行時間）
    - DEBUGレベル: 詳細情報（コマンド、出力、エラー、メタデータ）
    - パフォーマンス閾値: 5倍以上遅延時に警告、10倍以上でエラー
    
    Example:
        logger = ExternalToolLogger("dalfox")
        
        # INFOレベル: 基本情報のみ
        logger.info_execution(command, result)
        
        # DEBUGレベル: 詳細情報（開発・デバッグ時のみ）
        logger.debug_execution(command, result, context={"target": url})
    """
    
    def __init__(
        self,
        tool_name: str,
        config: Optional[LogLevelConfig] = None,
        thresholds: Optional[PerformanceThresholds] = None
    ):
        """初期化
        
        Args:
            tool_name: ツール名
            config: ログレベル設定
            thresholds: パフォーマンス閾値設定
        """
        self.tool_name = tool_name
        self.config = config or LogLevelConfig()
        self.thresholds = thresholds or PerformanceThresholds()
        
        # ロガー取得
        self.logger = logging.getLogger(f"external_tool.{tool_name}")
        
        # 基準実行時間の追跡（移動平均）
        self._execution_times: List[float] = []
        self._max_history = 10
    
    def _get_baseline_time(self) -> float:
        """基準実行時間を計算（移動平均）"""
        if not self._execution_times:
            return self.thresholds.baseline_execution_time_ms
        return sum(self._execution_times) / len(self._execution_times)
    
    def _update_baseline(self, execution_time_ms: float):
        """基準実行時間を更新"""
        self._execution_times.append(execution_time_ms)
        if len(self._execution_times) > self._max_history:
            self._execution_times.pop(0)
    
    def _check_performance(self, execution_time_ms: float) -> Optional[str]:
        """パフォーマンスをチェックし、閾値を超えていれば警告メッセージを返却
        
        Args:
            execution_time_ms: 実行時間（ms）
            
        Returns:
            Optional[str]: 閾値超過時の警告メッセージ、問題なし時はNone
        """
        baseline = self._get_baseline_time()
        
        if baseline <= 0:
            return None
        
        slow_factor = execution_time_ms / baseline
        
        if slow_factor >= self.thresholds.error_slow_factor:
            return (
                f"CRITICAL: Execution is {slow_factor:.1f}x slower than baseline "
                f"({execution_time_ms:.0f}ms vs {baseline:.0f}ms baseline)"
            )
        elif slow_factor >= self.thresholds.warning_slow_factor:
            return (
                f"WARNING: Execution is {slow_factor:.1f}x slower than baseline "
                f"({execution_time_ms:.0f}ms vs {baseline:.0f}ms baseline)"
            )
        
        return None
    
    def info_execution(
        self,
        command: List[str],
        result: "ToolResult",
        context: Optional[Dict[str, Any]] = None
    ):
        """INFOレベルでの実行ログ
        
        基本情報のみを記録（ツール名、ステータス、実行時間）。
        
        Args:
            command: 実行コマンド
            result: 実行結果
            context: 追加コンテキスト（オプション）
        """
        # 基準時間更新
        self._update_baseline(result.execution_time_ms)
        
        # パフォーマンスチェック
        perf_warning = self._check_performance(result.execution_time_ms)
        
        # 基本ログメッセージ
        log_data = {
            "tool": self.tool_name,
            "status": result.status.value,
            "time_ms": round(result.execution_time_ms, 2),
            "command_summary": f"{' '.join(command)[:50]}..." if len(' '.join(command)) > 50 else ' '.join(command)
        }
        
        if context:
            log_data["context"] = {k: str(v)[:100] for k, v in context.items()}
        
        # パフォーマンス警告がある場合は追加
        if perf_warning:
            log_data["performance_warning"] = perf_warning
            self.logger.warning(json.dumps(log_data))
        else:
            self.logger.info(json.dumps(log_data))
    
    def debug_execution(
        self,
        command: List[str],
        result: "ToolResult",
        context: Optional[Dict[str, Any]] = None
    ):
        """DEBUGレベルでの詳細実行ログ
        
        詳細情報を記録（コマンド、出力、エラー、メタデータ）。
        開発・デバッグ時のみ使用。
        
        Args:
            command: 実行コマンド
            result: 実行結果
            context: 追加コンテキスト
        """
        log_data = {
            "tool": self.tool_name,
            "status": result.status.value,
            "time_ms": round(result.execution_time_ms, 2),
            "command": command,
            "raw_output": result.raw_output[:1000] if result.raw_output else None,
            "error_message": result.error_message,
            "data_summary": str(result.data)[:500] if result.data else None,
        }
        
        if context:
            log_data["context"] = context
        
        if result.metadata:
            log_data["metadata"] = result.metadata
        
        self.logger.debug(json.dumps(log_data, default=str))
    
    def error_execution(
        self,
        command: List[str],
        exception: Exception,
        context: Optional[Dict[str, Any]] = None
    ):
        """ERRORレベルでのエラーログ
        
        Args:
            command: 実行コマンド
            exception: 発生した例外
            context: 追加コンテキスト
        """
        log_data = {
            "tool": self.tool_name,
            "status": "error",
            "command": command,
            "error_type": type(exception).__name__,
            "error_message": str(exception),
        }
        
        if context:
            log_data["context"] = context
        
        self.logger.error(json.dumps(log_data))
    
    def log_result_summary(self, results: List["ToolResult"]):
        """複数実行結果のサマリーをログ
        
        Args:
            results: 実行結果リスト
        """
        total = len(results)
        # ToolStatusValueを使用して比較（型安全）
        success = sum(1 for r in results if r.status.value == ToolStatusValue.SUCCESS)
        failure = sum(1 for r in results if r.status.value == ToolStatusValue.FAILURE)
        timeout = sum(1 for r in results if r.status.value == ToolStatusValue.TIMEOUT)
        error = sum(1 for r in results if r.status.value == ToolStatusValue.ERROR)
        
        avg_time = sum(r.execution_time_ms for r in results) / total if total > 0 else 0
        
        summary = {
            "tool": self.tool_name,
            "batch_summary": {
                "total": total,
                "success": success,
                "failure": failure,
                "timeout": timeout,
                "error": error,
                "avg_time_ms": round(avg_time, 2)
            }
        }
        
        self.logger.info(json.dumps(summary))


def get_logger(tool_name: str) -> ExternalToolLogger:
    """ExternalToolLoggerを取得
    
    Args:
        tool_name: ツール名
        
    Returns:
        ExternalToolLogger: ロガーインスタンス
    """
    return ExternalToolLogger(tool_name)
