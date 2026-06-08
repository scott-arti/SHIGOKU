"""
DecisionEnhancer: 意思決定改善

コンテキストを考慮した判断を行い、
過去の経験から学んで意思決定を最適化する。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time
from src.core.learning.repository import get_learning_repository, LearningRepository

logger = logging.getLogger(__name__)


class Decision(str, Enum):
    """判断結果"""
    PROCEED = "proceed"
    RETRY = "retry"
    SKIP = "skip"
    ESCALATE = "escalate"
    MODIFY = "modify"


@dataclass
class DecisionContext:
    """判断コンテキスト"""
    action_type: str
    target_url: str
    previous_attempts: int = 0
    waf_detected: bool = False
    rate_limit_active: bool = False
    risk_score: float = 0.5
    success_rate_historical: float = 0.5
    priority: float = 0.5
    
    def to_dict(self) -> dict:
        return {
            "action_type": self.action_type,
            "target_url": self.target_url,
            "previous_attempts": self.previous_attempts,
            "waf_detected": self.waf_detected,
            "rate_limit_active": self.rate_limit_active,
            "risk_score": self.risk_score,
            "success_rate_historical": self.success_rate_historical,
            "priority": self.priority,
        }


@dataclass
class EnhancedDecision:
    """強化された判断結果"""
    decision: Decision
    confidence: float  # 0.0 - 1.0
    reasoning: str
    modifications: list[str] = field(default_factory=list)
    wait_seconds: float = 0.0
    
    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "modifications": self.modifications,
            "wait_seconds": self.wait_seconds,
        }


class DecisionEnhancer:
    """
    意思決定強化エンジン
    
    コンテキストと履歴を考慮して最適な判断を下す。
    
    使用例:
        enhancer = DecisionEnhancer()
        
        context = DecisionContext(
            action_type="sql_injection",
            target_url="https://example.com/api",
            waf_detected=True,
            risk_score=0.7,
        )
        
        decision = enhancer.decide(context)
        if decision.decision == Decision.PROCEED:
            for mod in decision.modifications:
                apply_modification(mod)
    """
    
    # アクションタイプごとの最大リトライ数
    MAX_RETRIES = {
        "sql_injection": 3,
        "xss": 4,
        "auth_bypass": 2,
        "file_upload": 2,
        "ssrf": 3,
        "default": 3,
    }
    
    def __init__(self, repository: Optional[LearningRepository] = None):
        self._decision_history: list[tuple[DecisionContext, EnhancedDecision]] = []
        self.repository = repository or get_learning_repository()
    
    def decide(self, context: DecisionContext) -> EnhancedDecision:
        """
        コンテキストに基づいて判断
        
        Args:
            context: 判断コンテキスト
            
        Returns:
            強化された判断結果
        """
        decision, confidence, reasoning, mods, wait = self._evaluate(context)
        
        result = EnhancedDecision(
            decision=decision,
            confidence=confidence,
            reasoning=reasoning,
            modifications=mods,
            wait_seconds=wait,
        )
        
        self._decision_history.append((context, result))
        
        logger.debug(
            "Decision: %s (confidence: %.2f) - %s",
            decision.value,
            confidence,
            reasoning[:50],
        )
        
        return result
    
    def _evaluate(
        self,
        ctx: DecisionContext,
    ) -> tuple[Decision, float, str, list[str], float]:
        """コンテキストを評価"""
        
        # リトライ回数チェック
        max_retries = self.MAX_RETRIES.get(
            ctx.action_type,
            self.MAX_RETRIES["default"]
        )
        
        if ctx.previous_attempts >= max_retries:
            return (
                Decision.SKIP,
                0.9,
                f"Max retries ({max_retries}) exceeded",
                [],
                0.0,
            )
        
        # レート制限中
        if ctx.rate_limit_active:
            return (
                Decision.RETRY,
                0.85,
                "Rate limit active, should wait",
                [],
                30.0,
            )
        
        # 高リスク + 低成功率
        if ctx.risk_score > 0.8 and ctx.success_rate_historical < 0.2:
            return (
                Decision.SKIP,
                0.75,
                "High risk with low success probability",
                [],
                0.0,
            )
        
        # WAF検出時の修正提案
        if ctx.waf_detected:
            mods = self._suggest_waf_evasion(ctx.action_type)
            if ctx.previous_attempts > 0:
                return (
                    Decision.MODIFY,
                    0.7,
                    "WAF detected, applying evasion techniques",
                    mods,
                    2.0,
                )
        
        # 低優先度 + 多数の試行
        if ctx.priority < 0.3 and ctx.previous_attempts >= 2:
            return (
                Decision.SKIP,
                0.6,
                "Low priority with multiple failed attempts",
                [],
                0.0,
            )
            
        # 過去の成功パターンの検索
        historical_success = self._get_historical_success(ctx.action_type, ctx.target_url)
        if historical_success:
            # 過去に成功したペイロード情報があれば、それを元に再構成
            payload = historical_success.get("payload_used")
            if payload:
                return (
                    Decision.MODIFY,
                    0.8,
                    f"Applying historically successful pattern for {ctx.action_type}",
                    [f"use_payload:{payload}"],
                    0.0,
                )
        
        # デフォルト: 実行
        confidence = 0.5 + (ctx.success_rate_historical * 0.3) - (ctx.risk_score * 0.2)
        return (
            Decision.PROCEED,
            min(max(confidence, 0.3), 0.9),
            "Default proceed with standard approach",
            [],
            0.0,
        )
    
    def _suggest_waf_evasion(self, action_type: str) -> list[str]:
        """WAF回避の修正を提案"""
        suggestions = {
            "sql_injection": [
                "Use inline comments (/**/) between keywords",
                "Try case variation (SeLeCt)",
                "Use URL encoding for special chars",
            ],
            "xss": [
                "Use event handlers instead of script tags",
                "Try unicode encoding",
                "Use data: URLs",
            ],
            "default": [
                "Add random delays",
                "Use alternative encoding",
                "Try chunked transfer",
            ],
        }
        return suggestions.get(action_type, suggestions["default"])
    
    def _get_historical_success(self, action_type: str, target: str) -> Optional[dict]:
        """過去の成功パターンをリポジトリから取得"""
        # キーは SelfReflection と合わせる必要がある
        key = f"{action_type}:{target}"
        return self.repository.retrieve("success_payloads", key)
    
    def should_escalate(self, context: DecisionContext) -> bool:
        """
        エスカレーションすべきか判定
        
        Args:
            context: 判断コンテキスト
            
        Returns:
            エスカレーションすべきならTrue
        """
        # 高リスク行動
        if context.risk_score > 0.9:
            return True
        
        # 認証系で多数の失敗
        if "auth" in context.action_type and context.previous_attempts >= 3:
            return True
        
        return False
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        decision_counts = {}
        for d in Decision:
            decision_counts[d.value] = sum(
                1 for _, ed in self._decision_history
                if ed.decision == d
            )
        
        return {
            "total_decisions": len(self._decision_history),
            "decision_counts": decision_counts,
        }


# シングルトンインスタンス
_default_enhancer: Optional[DecisionEnhancer] = None


def get_decision_enhancer() -> DecisionEnhancer:
    """デフォルトのDecisionEnhancerインスタンスを取得"""
    global _default_enhancer
    if _default_enhancer is None:
        _default_enhancer = DecisionEnhancer()
    return _default_enhancer
