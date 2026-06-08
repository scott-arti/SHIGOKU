"""
外部ツールアダプター共通定数

循環インポート回避のため、両方のモジュールから参照可能な定数を定義
"""

from enum import Enum


class ToolStatusValue(str, Enum):
    """ツール実行結果の状態値（文字列Enum）
    
    external_tool_logger.pyとbase_external_adapter.pyの
    両方から参照可能にするための共通定義
    """
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    ERROR = "error"


# セマフォ統計用のデフォルト値
DEFAULT_MAX_CONCURRENT = 5
DEFAULT_TIMEOUT_SECONDS = 300.0

# パフォーマンス閾値デフォルト
DEFAULT_WARNING_SLOW_FACTOR = 5.0
DEFAULT_ERROR_SLOW_FACTOR = 10.0
DEFAULT_BASELINE_TIME_MS = 1000.0
