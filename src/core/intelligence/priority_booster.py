"""
PriorityBooster: 動的優先度ブースティング

発見内容に基づいてタスク優先度を動的に調整する。
重要な資産発見時に関連タスクの優先度を上げる。
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time

logger = logging.getLogger(__name__)


class BoostTrigger(str, Enum):
    """優先度ブーストのトリガー"""
    HIGH_VALUE_ASSET = "high_value_asset"  # 管理画面、認証系
    VULN_INDICATOR = "vuln_indicator"  # 脆弱性の兆候
    TECH_STACK_MATCH = "tech_stack_match"  # 既知の脆弱な技術
    AUTH_BYPASS = "auth_bypass"  # 認証バイパスの可能性
    SENSITIVE_DATA = "sensitive_data"  # 機密データ露出
    ERROR_LEAK = "error_leak"  # エラー情報漏洩


@dataclass
class BoostEvent:
    """優先度ブーストイベント"""
    trigger: BoostTrigger
    target: str
    boost_amount: float  # 0.0 - 1.0
    reason: str
    related_tasks: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    expires_in: float = 3600.0  # 有効期限（秒）
    
    def is_expired(self) -> bool:
        """有効期限切れかチェック"""
        return time.time() > (self.timestamp + self.expires_in)


@dataclass
class TaskPriority:
    """タスク優先度"""
    task_id: str
    base_priority: float  # 0.0 - 1.0
    boost: float = 0.0
    boost_reasons: list[str] = field(default_factory=list)
    
    @property
    def effective_priority(self) -> float:
        """実効優先度"""
        return min(self.base_priority + self.boost, 1.0)


class PriorityBooster:
    """
    動的優先度ブースター
    
    発見内容に基づいてタスクの優先度を動的に調整する。
    
    使用例:
        booster = PriorityBooster()
        
        # 管理画面発見時にブースト
        booster.boost_on_discovery(BoostEvent(
            trigger=BoostTrigger.HIGH_VALUE_ASSET,
            target="https://example.com/admin",
            boost_amount=0.3,
            reason="Admin panel discovered",
            related_tasks=["auth_test", "access_control"],
        ))
        
        # タスクの実効優先度を取得
        priority = booster.get_priority("auth_test")
    """
    
    # トリガーごとのデフォルトブースト量
    DEFAULT_BOOSTS = {
        BoostTrigger.HIGH_VALUE_ASSET: 0.3,
        BoostTrigger.VULN_INDICATOR: 0.4,
        BoostTrigger.TECH_STACK_MATCH: 0.2,
        BoostTrigger.AUTH_BYPASS: 0.5,
        BoostTrigger.SENSITIVE_DATA: 0.4,
        BoostTrigger.ERROR_LEAK: 0.25,
    }
    
    # 高価値資産パターン
    HIGH_VALUE_PATTERNS = [
        "admin", "login", "auth", "api/v",
        "dashboard", "console", "manage",
        "config", "settings", "internal",
    ]
    
    def __init__(self):
        self._lock = threading.RLock()
        self._boosts: list[BoostEvent] = []
        self._task_priorities: dict[str, TaskPriority] = {}
    
    def register_task(
        self,
        task_id: str,
        base_priority: float = 0.5,
    ) -> None:
        """
        タスクを登録
        
        Args:
            task_id: タスクID
            base_priority: 基本優先度
        """
        with self._lock:
            self._task_priorities[task_id] = TaskPriority(
                task_id=task_id,
                base_priority=base_priority,
            )
    
    def boost_on_discovery(self, event: BoostEvent) -> list[str]:
        """
        発見に基づいて優先度をブースト
        
        Args:
            event: ブーストイベント
            
        Returns:
            影響を受けたタスクIDのリスト
        """
        with self._lock:
            self._boosts.append(event)
            affected = []

            for task_id in event.related_tasks:
                if task_id in self._task_priorities:
                    priority = self._task_priorities[task_id]
                    priority.boost += event.boost_amount
                    priority.boost_reasons.append(event.reason)
                    affected.append(task_id)
        
        logger.info(
            "Priority boost: %s (+%.2f) -> %s",
            event.trigger.value,
            event.boost_amount,
            affected,
        )
        
        return affected
    
    def auto_detect_boost(
        self,
        target: str,
        content: str,
        related_tasks: Optional[list[str]] = None,
    ) -> Optional[BoostEvent]:
        """
        コンテンツから自動でブーストを検出
        
        Args:
            target: ターゲットURL
            content: レスポンスコンテンツ
            related_tasks: 関連タスク
            
        Returns:
            生成されたBoostEvent（なければNone）
        """
        related = related_tasks or []
        target_lower = target.lower()
        content_lower = content.lower()
        
        # 高価値資産チェック
        for pattern in self.HIGH_VALUE_PATTERNS:
            if pattern in target_lower:
                return BoostEvent(
                    trigger=BoostTrigger.HIGH_VALUE_ASSET,
                    target=target,
                    boost_amount=self.DEFAULT_BOOSTS[BoostTrigger.HIGH_VALUE_ASSET],
                    reason=f"High-value asset pattern: {pattern}",
                    related_tasks=related,
                )
        
        # エラー情報漏洩チェック
        error_indicators = ["stack trace", "exception", "debug", "error in"]
        for indicator in error_indicators:
            if indicator in content_lower:
                return BoostEvent(
                    trigger=BoostTrigger.ERROR_LEAK,
                    target=target,
                    boost_amount=self.DEFAULT_BOOSTS[BoostTrigger.ERROR_LEAK],
                    reason=f"Error information leak: {indicator}",
                    related_tasks=related,
                )
        
        # 機密データチェック
        sensitive_patterns = ["password", "api_key", "secret", "token", "credential"]
        for pattern in sensitive_patterns:
            if pattern in content_lower:
                return BoostEvent(
                    trigger=BoostTrigger.SENSITIVE_DATA,
                    target=target,
                    boost_amount=self.DEFAULT_BOOSTS[BoostTrigger.SENSITIVE_DATA],
                    reason=f"Sensitive data indicator: {pattern}",
                    related_tasks=related,
                )
        
        return None
    
    def get_priority(self, task_id: str) -> float:
        """
        タスクの実効優先度を取得
        
        Args:
            task_id: タスクID
            
        Returns:
            実効優先度
        """
        with self._lock:
            self._cleanup_expired()

            if task_id not in self._task_priorities:
                return 0.5  # デフォルト

            return self._task_priorities[task_id].effective_priority
    
    def get_sorted_tasks(self) -> list[tuple[str, float]]:
        """
        優先度順にソートされたタスクを取得
        
        Returns:
            (タスクID, 優先度) のリスト
        """
        with self._lock:
            self._cleanup_expired()

            tasks = [
                (tid, p.effective_priority)
                for tid, p in self._task_priorities.items()
            ]
            return sorted(tasks, key=lambda x: x[1], reverse=True)
    
    def _cleanup_expired(self) -> None:
        """期限切れブーストをクリーンアップ"""
        with self._lock:
            expired = [b for b in self._boosts if b.is_expired()]

            for event in expired:
                for task_id in event.related_tasks:
                    if task_id in self._task_priorities:
                        priority = self._task_priorities[task_id]
                        priority.boost = max(0, priority.boost - event.boost_amount)
                self._boosts.remove(event)
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        with self._lock:
            trigger_counts = {}
            for trigger in BoostTrigger:
                trigger_counts[trigger.value] = sum(
                    1 for b in self._boosts if b.trigger == trigger
                )

            return {
                "active_boosts": len(self._boosts),
                "registered_tasks": len(self._task_priorities),
                "trigger_counts": trigger_counts,
            }


# シングルトンインスタンス
_default_booster: Optional[PriorityBooster] = None


def get_priority_booster() -> PriorityBooster:
    """デフォルトのPriorityBoosterインスタンスを取得"""
    global _default_booster
    if _default_booster is None:
        _default_booster = PriorityBooster()
    return _default_booster
