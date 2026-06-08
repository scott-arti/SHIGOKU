"""
SelfReflection: 自己省察モジュール

実行結果を振り返り、成功/失敗パターンを分析して
次回の判断改善に活かす。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time
from src.core.learning.repository import get_learning_repository, LearningRepository
from src.core.security.pii_masker import get_pii_masker

logger = logging.getLogger(__name__)


class ExecutionOutcome(str, Enum):
    """実行結果"""
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"


@dataclass
class ExecutionRecord:
    """実行記録"""
    task_id: str
    action_type: str
    target: str
    outcome: ExecutionOutcome
    duration_seconds: float
    error_message: Optional[str] = None
    payload_used: Optional[str] = None
    response_code: Optional[int] = None
    findings: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> dict:
        """辞書形式に変換"""
        return {
            "task_id": self.task_id,
            "action_type": self.action_type,
            "target": self.target,
            "outcome": self.outcome.value,
            "duration_seconds": self.duration_seconds,
            "error_message": self.error_message,
            "payload_used": self.payload_used,
            "response_code": self.response_code,
            "findings": self.findings,
            "timestamp": self.timestamp,
        }


@dataclass
class ReflectionInsight:
    """省察から得られた洞察"""
    category: str  # "success_pattern", "failure_pattern", "improvement"
    insight: str
    confidence: float  # 0.0 - 1.0
    actionable: bool
    suggested_action: Optional[str] = None
    
    def to_dict(self) -> dict:
        """辞書形式に変換"""
        return {
            "category": self.category,
            "insight": self.insight,
            "confidence": self.confidence,
            "actionable": self.actionable,
            "suggested_action": self.suggested_action,
        }


class SelfReflection:
    """
    自己省察エンジン
    
    実行記録を分析し、パターンを抽出して
    次回の意思決定を改善する提案を生成する。
    
    使用例:
        reflection = SelfReflection()
        
        # 実行記録を追加
        reflection.record(ExecutionRecord(
            task_id="task_001",
            action_type="sql_injection",
            target="https://example.com/api",
            outcome=ExecutionOutcome.SUCCESS,
            duration_seconds=2.5,
        ))
        
        # 省察を実行
        insights = reflection.reflect()
    """
    
    def __init__(self, max_history: int = 100, repository: Optional[LearningRepository] = None):
        self._history: list[ExecutionRecord] = []
        self._max_history = max_history
        self._insights_cache: list[ReflectionInsight] = []
        self.repository = repository or get_learning_repository()
    
    def record(self, execution: ExecutionRecord) -> None:
        """
        実行記録を追加
        
        Args:
            execution: 実行記録
        """
        self._history.append(execution)
        
        # 履歴制限
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]
        
        # キャッシュ無効化
        self._insights_cache.clear()
        
        logger.debug(
            "Recorded execution: %s -> %s",
            execution.action_type,
            execution.outcome.value,
        )
        
        # 知識リポジトリへの保存 (SUCCESS または BLOCKED の場合)
        if execution.outcome in [ExecutionOutcome.SUCCESS, ExecutionOutcome.BLOCKED]:
            self._store_in_repository(execution)

    def _store_in_repository(self, execution: ExecutionRecord) -> None:
        """実行記録をリポジトリに保存"""
        category = "success_payloads" if execution.outcome == ExecutionOutcome.SUCCESS else "failure_patterns"
        key = f"{execution.action_type}:{execution.target}"
        
        # PII マスキング
        masker = get_pii_masker()
        data = execution.to_dict()
        
        if data.get("payload_used"):
            data["payload_used"] = masker.mask(data["payload_used"]).masked
        
        if data.get("findings"):
            data["findings"] = [masker.mask(f).masked for f in data["findings"]]
            
        self.repository.store(category, key, data)
    
    async def reflect_async(self) -> list[ReflectionInsight]:
        """
        蓄積された記録を非同期で分析（CPUバウンド処理をオフロード）
        
        Returns:
            洞察のリスト
        """
        import asyncio
        return await asyncio.to_thread(self.reflect)

    def reflect(self) -> list[ReflectionInsight]:
        """
        蓄積された記録を分析し洞察を生成
        
        Returns:
            洞察のリスト
        """
        if self._insights_cache:
            return self._insights_cache
        
        insights = []
        
        # 成功パターン分析
        insights.extend(self._analyze_success_patterns())
        
        # 失敗パターン分析
        insights.extend(self._analyze_failure_patterns())
        
        # 改善提案生成
        insights.extend(self._generate_improvements())
        
        self._insights_cache = insights
        
        # 洞察の永続化
        for insight in insights:
            if insight.confidence > 0.8:
                # 洞察もマスクして保存
                masker = get_pii_masker()
                insight_data = insight.to_dict()
                insight_data["insight"] = masker.mask(insight_data["insight"]).masked
                
                self.repository.store(
                    "reflection_insights", 
                    f"{insight.category}:{insight.insight[:30]}", 
                    insight_data
                )
                
        return insights
    
    def _analyze_success_patterns(self) -> list[ReflectionInsight]:
        """成功パターンを分析"""
        insights = []
        
        successes = [
            r for r in self._history
            if r.outcome in [ExecutionOutcome.SUCCESS, ExecutionOutcome.PARTIAL_SUCCESS]
        ]
        
        if not successes:
            return insights
        
        # アクションタイプ別成功率
        action_stats = {}
        for record in self._history:
            action = record.action_type
            if action not in action_stats:
                action_stats[action] = {"success": 0, "total": 0}
            action_stats[action]["total"] += 1
            if record.outcome == ExecutionOutcome.SUCCESS:
                action_stats[action]["success"] += 1
        
        for action, stats in action_stats.items():
            rate = stats["success"] / stats["total"] if stats["total"] > 0 else 0
            if rate > 0.7 and stats["total"] >= 3:
                insights.append(ReflectionInsight(
                    category="success_pattern",
                    insight=f"{action} has high success rate ({rate:.0%})",
                    confidence=min(0.5 + (stats["total"] * 0.05), 0.95),
                    actionable=True,
                    suggested_action=f"Prioritize {action} for similar targets",
                ))
        
        return insights
    
    def _analyze_failure_patterns(self) -> list[ReflectionInsight]:
        """失敗パターンを分析"""
        insights = []
        
        failures = [
            r for r in self._history
            if r.outcome in [ExecutionOutcome.FAILURE, ExecutionOutcome.BLOCKED]
        ]
        
        if not failures:
            return insights
        
        # エラーメッセージのパターン
        error_counts = {}
        for record in failures:
            if record.error_message:
                key = record.error_message[:50]  # 最初の50文字
                error_counts[key] = error_counts.get(key, 0) + 1
        
        for error_pattern, count in error_counts.items():
            if count >= 2:
                insights.append(ReflectionInsight(
                    category="failure_pattern",
                    insight=f"Recurring error: {error_pattern}...",
                    confidence=0.6 + min(count * 0.1, 0.3),
                    actionable=True,
                    suggested_action="Investigate root cause and adjust approach",
                ))
        
        # ブロックされたアクション
        blocked = [r for r in failures if r.outcome == ExecutionOutcome.BLOCKED]
        if len(blocked) >= 2:
            blocked_actions = list(set(r.action_type for r in blocked))
            insights.append(ReflectionInsight(
                category="failure_pattern",
                insight=f"Actions frequently blocked: {', '.join(blocked_actions)}",
                confidence=0.8,
                actionable=True,
                suggested_action="Consider stealth mode or alternative approach",
            ))
        
        return insights
    
    def _generate_improvements(self) -> list[ReflectionInsight]:
        """改善提案を生成"""
        insights = []
        
        if len(self._history) < 5:
            return insights
        
        # 平均実行時間の分析
        avg_duration = sum(r.duration_seconds for r in self._history) / len(self._history)
        slow_tasks = [r for r in self._history if r.duration_seconds > avg_duration * 2]
        
        if len(slow_tasks) >= 3:
            insights.append(ReflectionInsight(
                category="improvement",
                insight=f"{len(slow_tasks)} tasks took unusually long (>{avg_duration*2:.1f}s)",
                confidence=0.7,
                actionable=True,
                suggested_action="Consider timeout adjustments or parallel execution",
            ))
        
        # 全体的な成功率
        total = len(self._history)
        success_count = sum(
            1 for r in self._history
            if r.outcome == ExecutionOutcome.SUCCESS
        )
        overall_rate = success_count / total
        
        if overall_rate < 0.3:
            insights.append(ReflectionInsight(
                category="improvement",
                insight=f"Overall success rate is low ({overall_rate:.0%})",
                confidence=0.85,
                actionable=True,
                suggested_action="Review target selection or attack methodology",
            ))
        
        return insights
    
    def get_success_rate(self, action_type: Optional[str] = None) -> float:
        """
        成功率を取得
        
        Args:
            action_type: フィルタするアクションタイプ（Noneなら全体）
            
        Returns:
            成功率 (0.0 - 1.0)
        """
        records = self._history
        if action_type:
            records = [r for r in records if r.action_type == action_type]
        
        if not records:
            return 0.0
        
        successes = sum(
            1 for r in records
            if r.outcome in [ExecutionOutcome.SUCCESS, ExecutionOutcome.PARTIAL_SUCCESS]
        )
        return successes / len(records)
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        outcome_counts = {}
        for outcome in ExecutionOutcome:
            outcome_counts[outcome.value] = sum(
                1 for r in self._history if r.outcome == outcome
            )
        
        return {
            "total_records": len(self._history),
            "outcome_counts": outcome_counts,
            "overall_success_rate": self.get_success_rate(),
            "cached_insights": len(self._insights_cache),
        }
    
    def clear_history(self) -> None:
        """履歴をクリア"""
        self._history.clear()
        self._insights_cache.clear()


# シングルトンインスタンス
_default_reflection: Optional[SelfReflection] = None


def get_self_reflection() -> SelfReflection:
    """デフォルトのSelfReflectionインスタンスを取得"""
    global _default_reflection
    if _default_reflection is None:
        _default_reflection = SelfReflection()
    return _default_reflection
