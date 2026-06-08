"""
RetryTracker: 試行回数の記憶とループ停止判断

タスクの試行回数を追跡し、適応型閾値に基づいて
ループを停止すべきかを判断する。
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from src.core.config.feature_config import get_feature_config

logger = logging.getLogger(__name__)


@dataclass
class RetryRecord:
    """試行記録"""
    task_id: str
    attempts: int = 0
    successes: int = 0
    last_attempt_at: float = field(default_factory=time.time)
    first_attempt_at: float = field(default_factory=time.time)
    last_error: Optional[str] = None

    @property
    def success_rate(self) -> float:
        """成功率を計算"""
        if self.attempts == 0:
            return 0.0
        return self.successes / self.attempts

    @property
    def consecutive_failures(self) -> int:
        """連続失敗回数（概算）"""
        return max(0, self.attempts - self.successes)


@dataclass
class StopDecision:
    """停止判断結果"""
    should_stop: bool
    reason: str
    attempts: int
    max_allowed: int
    success_rate: float


class RetryTracker:
    """
    試行回数の追跡と停止判断
    
    機能:
    - タスク別の試行回数追跡
    - 適応型閾値計算（過去の成功率ベース）
    - ループ検出と停止判断
    
    使用例:
        tracker = RetryTracker()
        
        # 試行を記録
        tracker.record_attempt("task_xss_scan", success=False, error="WAF blocked")
        
        # 停止すべきかチェック
        decision = tracker.should_stop("task_xss_scan")
        if decision.should_stop:
            print(f"Stopping: {decision.reason}")
    """

    def __init__(self, max_retries: Optional[int] = None):
        config = get_feature_config().retry_control
        
        self.max_retries = max_retries or config.max_retries_per_task
        self.adaptive_threshold = config.adaptive_threshold
        self.low_success_multiplier = config.low_success_multiplier
        
        self._records: dict[str, RetryRecord] = {}
        self._global_stats = {
            "total_attempts": 0,
            "total_successes": 0,
            "stopped_tasks": 0,
        }
        
        # ターゲット別の成功率履歴（適応型閾値用）
        self._target_history: dict[str, list[float]] = defaultdict(list)

    def record_attempt(
        self, 
        task_id: str, 
        success: bool, 
        error: Optional[str] = None,
        target: Optional[str] = None
    ) -> RetryRecord:
        """
        試行を記録
        
        Args:
            task_id: タスクID
            success: 成功したか
            error: エラーメッセージ（失敗時）
            target: ターゲットURL（適応型閾値用）
            
        Returns:
            更新された記録
        """
        if task_id not in self._records:
            self._records[task_id] = RetryRecord(task_id=task_id)
        
        record = self._records[task_id]
        record.attempts += 1
        record.last_attempt_at = time.time()
        
        if success:
            record.successes += 1
        else:
            record.last_error = error
        
        # グローバル統計更新
        self._global_stats["total_attempts"] += 1
        if success:
            self._global_stats["total_successes"] += 1
        
        # ターゲット履歴更新
        if target:
            self._target_history[target].append(1.0 if success else 0.0)
            # 履歴を最大100件に制限
            if len(self._target_history[target]) > 100:
                self._target_history[target] = self._target_history[target][-100:]
        
        logger.debug(
            f"Retry recorded: {task_id} attempt={record.attempts} "
            f"success={success} rate={record.success_rate:.2%}"
        )
        
        return record

    def should_stop(
        self, 
        task_id: str,
        target: Optional[str] = None
    ) -> StopDecision:
        """
        タスクを停止すべきか判断
        
        Args:
            task_id: タスクID
            target: ターゲットURL（適応型閾値用）
            
        Returns:
            停止判断結果
        """
        record = self._records.get(task_id)
        
        if not record:
            return StopDecision(
                should_stop=False,
                reason="No attempts recorded",
                attempts=0,
                max_allowed=self.max_retries,
                success_rate=0.0,
            )
        
        # 適応型閾値を計算
        max_allowed = self._calculate_adaptive_threshold(target)
        
        # 判断ロジック
        should_stop = False
        reason = ""
        
        # 1. 最大試行回数超過
        if record.attempts >= max_allowed:
            should_stop = True
            reason = f"Max retries exceeded ({record.attempts}/{max_allowed})"
        
        # 2. 成功率が極端に低い（5回以上試行して0%）
        elif record.attempts >= 5 and record.success_rate == 0.0:
            should_stop = True
            reason = f"Zero success rate after {record.attempts} attempts"
        
        # 3. 連続失敗が閾値の半分を超えた場合の早期停止
        elif record.consecutive_failures >= max_allowed // 2 + 1:
            # 最後のエラーがWAF/ブロック系なら早期停止
            if record.last_error and any(
                kw in record.last_error.lower() 
                for kw in ["waf", "blocked", "banned", "rate limit", "403", "429"]
            ):
                should_stop = True
                reason = f"Likely blocked: {record.last_error[:50]}"
        
        if should_stop:
            self._global_stats["stopped_tasks"] += 1
            logger.warning(f"Task stop decision: {task_id} - {reason}")
        
        return StopDecision(
            should_stop=should_stop,
            reason=reason,
            attempts=record.attempts,
            max_allowed=max_allowed,
            success_rate=record.success_rate,
        )

    def _calculate_adaptive_threshold(self, target: Optional[str]) -> int:
        """適応型閾値を計算"""
        if not self.adaptive_threshold:
            return self.max_retries
        
        # ターゲット固有の履歴がある場合
        if target and target in self._target_history:
            history = self._target_history[target]
            if len(history) >= 5:
                avg_success = sum(history) / len(history)
                
                # 成功率が低い場合は閾値を下げる
                if avg_success < 0.2:
                    return max(2, int(self.max_retries * self.low_success_multiplier))
                elif avg_success < 0.5:
                    return max(3, int(self.max_retries * 0.7))
        
        # グローバル成功率で調整
        global_rate = self.get_global_success_rate()
        if global_rate < 0.1:
            return max(2, int(self.max_retries * self.low_success_multiplier))
        
        return self.max_retries

    def get_record(self, task_id: str) -> Optional[RetryRecord]:
        """タスクの記録を取得"""
        return self._records.get(task_id)

    def get_global_success_rate(self) -> float:
        """グローバル成功率を取得"""
        total = self._global_stats["total_attempts"]
        if total == 0:
            return 0.0
        return self._global_stats["total_successes"] / total

    def get_stats(self) -> dict:
        """統計情報を取得"""
        return {
            **self._global_stats,
            "global_success_rate": self.get_global_success_rate(),
            "tracked_tasks": len(self._records),
            "tracked_targets": len(self._target_history),
        }

    def reset(self, task_id: Optional[str] = None) -> None:
        """
        記録をリセット
        
        Args:
            task_id: 特定タスクのみリセット。Noneなら全てリセット。
        """
        if task_id:
            if task_id in self._records:
                del self._records[task_id]
        else:
            self._records.clear()
            self._target_history.clear()
        
        logger.info(f"Retry tracker reset: {task_id or 'all'}")

    def get_high_risk_tasks(self, threshold: float = 0.3) -> list[str]:
        """
        成功率が低いタスクを取得
        
        Args:
            threshold: 成功率の閾値
            
        Returns:
            高リスクタスクIDのリスト
        """
        return [
            task_id
            for task_id, record in self._records.items()
            if record.attempts >= 3 and record.success_rate < threshold
        ]


# シングルトンインスタンス
_tracker_instance: Optional[RetryTracker] = None


def get_retry_tracker() -> RetryTracker:
    """RetryTrackerのシングルトンインスタンスを取得"""
    global _tracker_instance
    if _tracker_instance is None:
        _tracker_instance = RetryTracker()
    return _tracker_instance
