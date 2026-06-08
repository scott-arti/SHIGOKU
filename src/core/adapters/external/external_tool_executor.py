"""
ExternalToolExecutor: 外部ツール実行の並行度制御とセマフォ管理

セマフォによる非同期制御（並行度管理）を実装。
環境変数 SHIGOKU_EXTERNAL_TOOL_CONCURRENCY で並行度を調整可能。
"""

import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from .base_external_adapter import BaseExternalAdapter, ToolInput, ToolResult, ToolStatus

logger = logging.getLogger(__name__)


def _get_default_concurrency() -> int:
    """環境変数からデフォルト並行度を取得
    
    SHIGOKU_EXTERNAL_TOOL_CONCURRENCY で設定可能。
    無効な値の場合は5を返す。
    """
    try:
        value = os.getenv("SHIGOKU_EXTERNAL_TOOL_CONCURRENCY", "5")
        concurrency = int(value)
        # 妥当性チェック: 1-20の範囲
        if not 1 <= concurrency <= 20:
            logger.warning(
                f"Invalid SHIGOKU_EXTERNAL_TOOL_CONCURRENCY value: {concurrency}. "
                f"Must be between 1-20. Using default: 5"
            )
            return 5
        return concurrency
    except ValueError:
        logger.warning(
            f"Invalid SHIGOKU_EXTERNAL_TOOL_CONCURRENCY value: {value}. "
            f"Must be an integer. Using default: 5"
        )
        return 5


def _normalize_concurrency(value: int) -> int:
    """並行度を安全な範囲に正規化する。"""
    if not 1 <= value <= 20:
        logger.warning(
            "Invalid max_concurrent value: %s. Must be between 1-20. Using default: 5",
            value,
        )
        return 5
    return value


@dataclass
class ExecutorConfig:
    """エグゼキューター設定
    
    環境変数 SHIGOKU_EXTERNAL_TOOL_CONCURRENCY で並行度を調整可能。
    例: SHIGOKU_EXTERNAL_TOOL_CONCURRENCY=10
    """
    max_concurrent: int = field(default_factory=_get_default_concurrency)
    timeout_seconds: float = 300.0  # デフォルトタイムアウト
    enable_semaphore: bool = True  # セマフォ制御有効化

    def __post_init__(self) -> None:
        self.max_concurrent = _normalize_concurrency(self.max_concurrent)


class ExternalToolExecutor:
    """外部ツール実行の並行度制御エグゼキューター
    
    セマフォによる非同期制御を実装し、外部ツールの並行実行数を制限。
    これにより、リソース枯渇や外部サービスへの過剰な負荷を防止。
    
    設計方針:
    - 単純なasyncio.Semaphoreによる並行度制御
    - ツールごとの設定による柔軟な制御
    - タイムアウト制御の統合
    
    Example:
        executor = ExternalToolExecutor(max_concurrent=3)
        
        # 複数のツールを並行実行（最大3つまで）
        results = await asyncio.gather(
            executor.execute(adapter1, input1),
            executor.execute(adapter2, input2),
            executor.execute(adapter3, input3),
            executor.execute(adapter4, input4),  # これは待機される
        )
    """
    
    def __init__(self, config: Optional[ExecutorConfig] = None):
        """初期化
        
        Args:
            config: エグゼキューター設定。未指定時はデフォルト値。
        """
        self.config = config or ExecutorConfig()
        
        # セマフォによる並行度制御
        if self.config.enable_semaphore:
            self.semaphore = asyncio.Semaphore(self.config.max_concurrent)
            logger.debug(f"Semaphore initialized with max_concurrent={self.config.max_concurrent}")
        else:
            self.semaphore = None
            logger.warning("Semaphore control is disabled")
        
        # セマフォ統計情報
        self._stats = {
            "total_executed": 0,
            "total_waiting_time_ms": 0.0,
            "max_concurrent_reached": 0,
            "current_active": 0,
            "total_errors": 0,
        }
        
        # アラート閾値設定（CTOレビュー指摘対応）
        self._alert_thresholds = {
            "avg_wait_ms": 500.0,      # 500ms超過で警告
            "error_rate": 0.05,        # 5%エラー率で警告
            "slow_factor": 2.0,        # 基準2倍時間で警告
        }
        
        # ベースライン実行時間（ツール別に動的更新）
        self._baseline_times: dict[str, float] = {}
    
    async def execute(
        self,
        adapter: BaseExternalAdapter,
        input_data: ToolInput,
        timeout_seconds: Optional[float] = None
    ) -> ToolResult:
        """アダプターを実行（セマフォ制御付き）
        
        セマフォによる並行度制御とタイムアウト制御を統合。
        
        Args:
            adapter: 実行するアダプター
            input_data: 入力データ
            timeout_seconds: タイムアウト秒数（未指定時はconfigの値）
            
        Returns:
            ToolResult: 実行結果
        """
        import time
        timeout = timeout_seconds or self.config.timeout_seconds
        
        if self.semaphore:
            # セマフォ待機時間計測開始
            wait_start = time.time()
            
            # セマフォによる並行度制御
            async with self.semaphore:
                wait_time_ms = (time.time() - wait_start) * 1000
                self._stats["total_waiting_time_ms"] += wait_time_ms
                self._stats["current_active"] += 1
                self._stats["max_concurrent_reached"] = max(
                    self._stats["max_concurrent_reached"],
                    self._stats["current_active"]
                )
                
                logger.debug(
                    f"Acquired semaphore slot for {adapter.tool_name} "
                    f"(waited {wait_time_ms:.1f}ms, active: {self._stats['current_active']})"
                )
                
                result: Optional[ToolResult] = None
                try:
                    result = await self._execute_with_timeout(adapter, input_data, timeout)
                except Exception as exc:
                    logger.exception("External tool execution failed for %s: %s", adapter.tool_name, exc)
                    result = ToolResult(
                        status=ToolStatus.ERROR,
                        data=None,
                        execution_time_ms=(time.time() - wait_start) * 1000,
                        error_message=f"Unhandled execution error: {exc}",
                    )
                finally:
                    self._stats["current_active"] -= 1
                    self._stats["total_executed"] += 1
                    
                    # エラー統計更新
                    if result and result.status in (ToolStatus.ERROR, ToolStatus.FAILURE, ToolStatus.TIMEOUT):
                        self._stats["total_errors"] += 1
                
                # アラートチェック
                if result is not None:
                    self._check_alerts(adapter.tool_name, result)
                    return result

                # Defensive fallback (result should always be set).
                return ToolResult(
                    status=ToolStatus.ERROR,
                    data=None,
                    execution_time_ms=(time.time() - wait_start) * 1000,
                    error_message="Execution failed without result",
                )
        else:
            # セマフォなし（無制限実行）
            self._stats["total_executed"] += 1
            return await self._execute_with_timeout(adapter, input_data, timeout)
    
    async def _execute_with_timeout(
        self,
        adapter: BaseExternalAdapter,
        input_data: ToolInput,
        timeout_seconds: float
    ) -> ToolResult:
        """タイムアウト制御付きで実行"""
        try:
            return await asyncio.wait_for(
                adapter.run_with_validation(input_data),
                timeout=timeout_seconds
            )
        except asyncio.TimeoutError:
            logger.error(f"Execution timeout for {adapter.tool_name} after {timeout_seconds}s")
            return ToolResult(
                status=ToolStatus.TIMEOUT,
                data=None,
                execution_time_ms=timeout_seconds * 1000,
                error_message=f"Execution timeout after {timeout_seconds} seconds"
            )
    
    async def execute_batch(
        self,
        tasks: list[tuple[BaseExternalAdapter, ToolInput]],
        timeout_seconds: Optional[float] = None
    ) -> list[ToolResult]:
        """複数タスクをバッチ実行
        
        Args:
            tasks: (アダプター, 入力データ)のタプルリスト
            timeout_seconds: 各タスクのタイムアウト
            
        Returns:
            list[ToolResult]: 実行結果リスト
        """
        coroutines = [
            self.execute(adapter, input_data, timeout_seconds)
            for adapter, input_data in tasks
        ]
        
        return await asyncio.gather(*coroutines, return_exceptions=False)
    
    def get_semaphore_stats(self) -> dict:
        """セマフォの現在の状態を取得
        
        Returns:
            dict: セマフォ統計情報
        """
        if not self.semaphore:
            return {
                "enabled": False,
                "stats": self._stats.copy()
            }
        
        # Semaphoreの内部状態を取得
        # Python 3.12+では_internal_lock_countが存在
        locked_count = getattr(self.semaphore, '_internal_lock_count', 0)
        
        # 平均待機時間を計算
        avg_wait_ms = (
            self._stats["total_waiting_time_ms"] / self._stats["total_executed"]
            if self._stats["total_executed"] > 0 else 0.0
        )
        
        return {
            "enabled": True,
            "max_concurrent": self.config.max_concurrent,
            "locked_slots": locked_count,
            "available_slots": self.config.max_concurrent - locked_count,
            "current_active": self._stats["current_active"],
            "max_concurrent_reached": self._stats["max_concurrent_reached"],
            "total_executed": self._stats["total_executed"],
            "total_errors": self._stats["total_errors"],
            "avg_waiting_time_ms": round(avg_wait_ms, 2),
            "error_rate": round(
                self._stats["total_errors"] / max(self._stats["total_executed"], 1), 4
            ),
        }
    
    def _check_alerts(self, tool_name: str, result: ToolResult) -> None:
        """実行結果に基づきアラートをチェック
        
        CTOレビュー指摘対応: 自動異常検知のための閾値チェック。
        警告はログ出力のみ（将来的にWebhook通知等を追加可能）。
        
        Args:
            tool_name: ツール名
            result: 実行結果
        """
        alerts = []
        
        # 1. 実行時間アラート（ベースライン比較）
        baseline = self._baseline_times.get(tool_name, 1000.0)  # デフォルト1秒
        if result.execution_time_ms > baseline * self._alert_thresholds["slow_factor"]:
            alerts.append(
                f"Slow execution: {result.execution_time_ms:.0f}ms "
                f"(baseline: {baseline:.0f}ms, factor: {self._alert_thresholds['slow_factor']})"
            )
        
        # ベースラインを動的更新（指数移動平均）
        if result.status == ToolStatus.SUCCESS:
            alpha = 0.3  # 平滑化係数
            new_baseline = baseline * (1 - alpha) + result.execution_time_ms * alpha
            self._baseline_times[tool_name] = new_baseline
        
        # 2. エラー率アラート
        total = self._stats["total_executed"]
        if total > 10:  # 十分なサンプル数がある場合のみ
            error_rate = self._stats["total_errors"] / total
            if error_rate > self._alert_thresholds["error_rate"]:
                alerts.append(
                    f"High error rate: {error_rate:.1%} "
                    f"(threshold: {self._alert_thresholds['error_rate']:.1%})"
                )
        
        # 3. セマフォ待機時間アラート（直近の実行のみ）
        stats = self.get_semaphore_stats()
        if stats["enabled"] and stats["avg_waiting_time_ms"] > self._alert_thresholds["avg_wait_ms"]:
            # 統計ベースの警告（頻繁に出すとノイズになるので間引き）
            if total % 10 == 0:  # 10件ごとに警告
                alerts.append(
                    f"High avg wait time: {stats['avg_waiting_time_ms']:.1f}ms "
                    f"(threshold: {self._alert_thresholds['avg_wait_ms']:.0f}ms). "
                    f"Consider increasing SHIGOKU_EXTERNAL_TOOL_CONCURRENCY"
                )
        
        # アラート出力
        for alert in alerts:
            logger.warning(f"[ALERT][{tool_name}] {alert}")


# グローバルエグゼキューター（シングルトン）
_global_executor: Optional[ExternalToolExecutor] = None


def get_global_executor() -> ExternalToolExecutor:
    """グローバルエグゼキューターを取得（シングルトン）"""
    global _global_executor
    if _global_executor is None:
        _global_executor = ExternalToolExecutor()
    return _global_executor


def reset_global_executor():
    """グローバルエグゼキューターをリセット（テスト用）"""
    global _global_executor
    _global_executor = None
