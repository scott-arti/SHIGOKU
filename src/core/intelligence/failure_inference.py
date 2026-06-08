"""
FailureInference: 失敗原因推論

過去の失敗パターンから学習し、
類似状況での失敗を予測・回避する。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional
import time

from src.core.intelligence.error_analyzer import ErrorCategory

logger = logging.getLogger(__name__)


@dataclass
class FailureContext:
    """失敗コンテキスト"""
    target_url: str
    action_type: str
    error_category: ErrorCategory
    payload_pattern: Optional[str] = None
    waf_detected: bool = False
    auth_required: bool = False
    timestamp: float = field(default_factory=time.time)


@dataclass
class FailurePrediction:
    """失敗予測結果"""
    likely_to_fail: bool
    failure_probability: float  # 0.0 - 1.0
    predicted_category: Optional[ErrorCategory] = None
    reasoning: str = ""
    prevention_tips: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """辞書形式に変換"""
        return {
            "likely_to_fail": self.likely_to_fail,
            "failure_probability": self.failure_probability,
            "predicted_category": self.predicted_category.value if self.predicted_category else None,
            "reasoning": self.reasoning,
            "prevention_tips": self.prevention_tips,
        }


class FailureInference:
    """
    失敗推論エンジン
    
    過去の失敗パターンを学習し、
    新しいアクションの失敗確率を予測する。
    
    使用例:
        inference = FailureInference()
        
        # 失敗を記録
        inference.record_failure(FailureContext(
            target_url="https://example.com/api",
            action_type="sql_injection",
            error_category=ErrorCategory.WAF_BLOCKED,
        ))
        
        # 予測
        prediction = inference.predict(
            target_url="https://example.com/api/users",
            action_type="sql_injection",
        )
    """
    
    def __init__(self, max_history: int = 200):
        self._failures: list[FailureContext] = []
        self._max_history = max_history
    
    def record_failure(self, context: FailureContext) -> None:
        """
        失敗を記録
        
        Args:
            context: 失敗コンテキスト
        """
        self._failures.append(context)
        
        if len(self._failures) > self._max_history:
            self._failures = self._failures[-self._max_history:]
        
        logger.debug(
            "Recorded failure: %s on %s (%s)",
            context.action_type,
            context.target_url[:50],
            context.error_category.value,
        )
    
    def predict(
        self,
        target_url: str,
        action_type: str,
        payload_pattern: Optional[str] = None,
    ) -> FailurePrediction:
        """
        失敗を予測
        
        Args:
            target_url: ターゲットURL
            action_type: アクションタイプ
            payload_pattern: ペイロードパターン
            
        Returns:
            失敗予測結果
        """
        if not self._failures:
            return FailurePrediction(
                likely_to_fail=False,
                failure_probability=0.0,
                reasoning="No failure history available",
            )
        
        # 類似失敗を検索
        similar = self._find_similar_failures(target_url, action_type, payload_pattern)
        
        if not similar:
            return FailurePrediction(
                likely_to_fail=False,
                failure_probability=0.1,  # ベースライン
                reasoning="No similar failures found",
            )
        
        # 失敗確率計算
        probability = self._calculate_probability(similar, len(self._failures))
        
        # 最も頻繁なエラーカテゴリ
        category_counts = {}
        for ctx in similar:
            category_counts[ctx.error_category] = category_counts.get(ctx.error_category, 0) + 1
        
        most_common = max(category_counts.items(), key=lambda x: x[1])
        predicted_category = most_common[0]
        
        # 予防策
        prevention_tips = self._generate_prevention_tips(predicted_category, similar)
        
        return FailurePrediction(
            likely_to_fail=probability > 0.5,
            failure_probability=probability,
            predicted_category=predicted_category,
            reasoning=f"Found {len(similar)} similar past failures",
            prevention_tips=prevention_tips,
        )
    
    def _find_similar_failures(
        self,
        target_url: str,
        action_type: str,
        payload_pattern: Optional[str],
    ) -> list[FailureContext]:
        """類似失敗を検索"""
        similar = []
        
        for ctx in self._failures:
            score = 0
            
            # 同じアクションタイプ
            if ctx.action_type == action_type:
                score += 3
            
            # 同じドメイン
            target_domain = self._extract_domain(target_url)
            ctx_domain = self._extract_domain(ctx.target_url)
            if target_domain == ctx_domain:
                score += 2
            
            # 同じパス構造
            if self._similar_path(target_url, ctx.target_url):
                score += 1
            
            # ペイロードパターン一致
            if payload_pattern and ctx.payload_pattern:
                if payload_pattern in ctx.payload_pattern or ctx.payload_pattern in payload_pattern:
                    score += 2
            
            if score >= 3:
                similar.append(ctx)
        
        return similar
    
    def _extract_domain(self, url: str) -> str:
        """URLからドメインを抽出"""
        try:
            from urllib.parse import urlparse
            return urlparse(url).netloc
        except Exception:
            return url
    
    def _similar_path(self, url1: str, url2: str) -> bool:
        """パス構造が類似しているか判定"""
        try:
            from urllib.parse import urlparse
            path1 = urlparse(url1).path.split("/")
            path2 = urlparse(url2).path.split("/")
            
            # 最初の2セグメントが一致
            return path1[:2] == path2[:2]
        except Exception:
            return False
    
    def _calculate_probability(
        self,
        similar: list[FailureContext],
        total: int,
    ) -> float:
        """失敗確率を計算"""
        if not similar:
            return 0.1
        
        # 類似失敗の割合
        base_prob = len(similar) / max(total, 1)
        
        # 最近の失敗を重視
        now = time.time()
        recent = sum(
            1 for ctx in similar
            if now - ctx.timestamp < 3600  # 1時間以内
        )
        recency_boost = min(recent * 0.1, 0.3)
        
        return min(base_prob + recency_boost, 0.95)
    
    def _generate_prevention_tips(
        self,
        category: ErrorCategory,
        similar: list[FailureContext],
    ) -> list[str]:
        """予防策を生成"""
        tips = []
        
        if category == ErrorCategory.WAF_BLOCKED:
            tips.append("Use URL encoding or alternative payload syntax")
            tips.append("Try case variation or comment insertion")
        
        elif category == ErrorCategory.RATE_LIMITED:
            tips.append("Increase delay between requests")
            tips.append("Enable stealth mode")
        
        elif category == ErrorCategory.AUTH_FAILURE:
            tips.append("Verify credentials are still valid")
            tips.append("Check for session token expiration")
        
        elif category == ErrorCategory.NETWORK_TIMEOUT:
            tips.append("Increase timeout value")
            tips.append("Check target availability first")
        
        # WAF検出履歴
        waf_count = sum(1 for ctx in similar if ctx.waf_detected)
        if waf_count > 0:
            tips.append(f"WAF detected in {waf_count} similar cases - use evasion")
        
        return tips[:3]  # 最大3つ
    
    def get_high_risk_targets(self) -> list[str]:
        """高リスクターゲットを取得"""
        domain_failures = {}
        for ctx in self._failures:
            domain = self._extract_domain(ctx.target_url)
            domain_failures[domain] = domain_failures.get(domain, 0) + 1
        
        return [
            domain for domain, count in domain_failures.items()
            if count >= 3
        ]
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        category_counts = {}
        for ctx in self._failures:
            cat = ctx.error_category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        return {
            "total_failures": len(self._failures),
            "category_counts": category_counts,
            "high_risk_targets": self.get_high_risk_targets(),
        }


# シングルトンインスタンス
_default_inference: Optional[FailureInference] = None


def get_failure_inference() -> FailureInference:
    """デフォルトのFailureInferenceインスタンスを取得"""
    global _default_inference
    if _default_inference is None:
        _default_inference = FailureInference()
    return _default_inference
