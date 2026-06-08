"""
RiskPredictor: アクションリスクスコアリング

アクションの検知リスクを事前評価し、
失敗コストを最小化する。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ActionType(str, Enum):
    """アクションタイプ"""
    # 低リスク
    PASSIVE_RECON = "passive_recon"
    READ_ONLY = "read_only"
    
    # 中リスク
    PARAM_FUZZING = "param_fuzzing"
    AUTH_TESTING = "auth_testing"
    
    # 高リスク
    INJECTION_TESTING = "injection_testing"
    FILE_UPLOAD = "file_upload"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    
    # 非常に高リスク
    DESTRUCTIVE = "destructive"
    BRUTE_FORCE = "brute_force"


class RiskLevel(str, Enum):
    """リスクレベル"""
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ActionRiskProfile:
    """アクションのリスクプロファイル"""
    action_type: ActionType
    target_url: str
    payload: Optional[str] = None
    headers: dict = field(default_factory=dict)
    
    # オプション: 追加のリスク要因
    is_authenticated: bool = False
    requires_session: bool = False
    has_waf: bool = False
    consecutive_failures: int = 0


@dataclass
class RiskAssessment:
    """リスク評価結果"""
    risk_level: RiskLevel
    risk_score: float  # 0.0 - 1.0
    detection_probability: float  # 0.0 - 1.0
    recommended_delay: float  # 推奨遅延（秒）
    warnings: list[str] = field(default_factory=list)
    
    @property
    def should_proceed(self) -> bool:
        """実行すべきか判定"""
        return self.risk_level not in [RiskLevel.CRITICAL]
    
    def to_dict(self) -> dict:
        """辞書形式に変換"""
        return {
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "detection_probability": self.detection_probability,
            "recommended_delay": self.recommended_delay,
            "should_proceed": self.should_proceed,
            "warnings": self.warnings,
        }


class RiskPredictor:
    """
    アクションリスク予測器
    
    アクションの検知確率とリスクスコアを計算し、
    推奨される遅延時間や警告を提供する。
    
    使用例:
        predictor = RiskPredictor()
        profile = ActionRiskProfile(
            action_type=ActionType.INJECTION_TESTING,
            target_url="https://example.com/api",
        )
        assessment = predictor.assess(profile)
        if assessment.should_proceed:
            await asyncio.sleep(assessment.recommended_delay)
            # アクション実行
    """
    
    # アクションタイプごとの基本リスクスコア
    BASE_RISK_SCORES = {
        ActionType.PASSIVE_RECON: 0.1,
        ActionType.READ_ONLY: 0.15,
        ActionType.PARAM_FUZZING: 0.4,
        ActionType.AUTH_TESTING: 0.5,
        ActionType.INJECTION_TESTING: 0.7,
        ActionType.FILE_UPLOAD: 0.75,
        ActionType.EXPLOIT_ATTEMPT: 0.85,
        ActionType.DESTRUCTIVE: 0.95,
        ActionType.BRUTE_FORCE: 0.9,
    }
    
    # 高リスクペイロードパターン
    HIGH_RISK_PATTERNS = [
        "' OR",
        "UNION SELECT",
        "<script",
        "{{",
        "${",
        "eval(",
        "system(",
        "../",
        "%00",
    ]
    
    def __init__(self, conservative: bool = True):
        """
        初期化
        
        Args:
            conservative: 保守的評価（リスクを高めに見積もる）
        """
        self.conservative = conservative
        self._history: list[RiskAssessment] = []
    
    def assess(self, profile: ActionRiskProfile) -> RiskAssessment:
        """
        アクションのリスクを評価
        
        Args:
            profile: アクションのリスクプロファイル
            
        Returns:
            リスク評価結果
        """
        warnings = []
        
        # 基本リスクスコア
        base_score = self.BASE_RISK_SCORES.get(profile.action_type, 0.5)
        
        # 修正係数
        multiplier = 1.0
        
        # WAF存在時はリスク増加
        if profile.has_waf:
            multiplier *= 1.3
            warnings.append("WAF detected - higher detection risk")
        
        # 連続失敗時はリスク増加
        if profile.consecutive_failures > 0:
            failure_penalty = min(profile.consecutive_failures * 0.1, 0.3)
            multiplier *= (1 + failure_penalty)
            warnings.append(f"Consecutive failures: {profile.consecutive_failures}")
        
        # 高リスクペイロードパターン検出
        if profile.payload:
            for pattern in self.HIGH_RISK_PATTERNS:
                if pattern.lower() in profile.payload.lower():
                    multiplier *= 1.2
                    warnings.append(f"High-risk pattern detected: {pattern}")
                    break
        
        # 認証済みセッション使用時はリスク低下
        if profile.is_authenticated:
            multiplier *= 0.9
        
        # 保守的評価
        if self.conservative:
            multiplier *= 1.1
        
        # 最終スコア計算
        risk_score = min(base_score * multiplier, 1.0)
        
        # 検知確率（リスクスコアに基づく推定）
        detection_probability = self._estimate_detection_prob(risk_score, profile)
        
        # リスクレベル判定
        risk_level = self._score_to_level(risk_score)
        
        # 推奨遅延計算
        recommended_delay = self._calculate_delay(risk_score, profile)
        
        assessment = RiskAssessment(
            risk_level=risk_level,
            risk_score=risk_score,
            detection_probability=detection_probability,
            recommended_delay=recommended_delay,
            warnings=warnings,
        )
        
        self._history.append(assessment)
        
        logger.debug(
            "Risk assessment: %s (score: %.2f, detection: %.2f)",
            risk_level.value,
            risk_score,
            detection_probability,
        )
        
        return assessment
    
    def _estimate_detection_prob(
        self,
        risk_score: float,
        profile: ActionRiskProfile,
    ) -> float:
        """検知確率を推定"""
        base_prob = risk_score * 0.8
        
        if profile.has_waf:
            base_prob *= 1.5
        
        return min(base_prob, 0.95)
    
    def _score_to_level(self, score: float) -> RiskLevel:
        """スコアをリスクレベルに変換"""
        if score < 0.2:
            return RiskLevel.MINIMAL
        elif score < 0.4:
            return RiskLevel.LOW
        elif score < 0.6:
            return RiskLevel.MEDIUM
        elif score < 0.8:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL
    
    def _calculate_delay(
        self,
        risk_score: float,
        profile: ActionRiskProfile,
    ) -> float:
        """推奨遅延を計算"""
        # リスクに応じた遅延（0-5秒）
        base_delay = risk_score * 5.0
        
        # 連続失敗時は追加遅延
        if profile.consecutive_failures > 0:
            base_delay += profile.consecutive_failures * 1.0
        
        # WAF存在時は追加遅延
        if profile.has_waf:
            base_delay += 1.0
        
        return min(base_delay, 10.0)
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        if not self._history:
            return {"total_assessments": 0}
        
        risk_counts = {}
        for level in RiskLevel:
            risk_counts[level.value] = sum(
                1 for a in self._history if a.risk_level == level
            )
        
        return {
            "total_assessments": len(self._history),
            "average_risk_score": sum(a.risk_score for a in self._history) / len(self._history),
            "risk_level_counts": risk_counts,
            "blocked_count": sum(1 for a in self._history if not a.should_proceed),
        }
    
    def reset_history(self) -> None:
        """履歴をリセット"""
        self._history.clear()


# シングルトンインスタンス
_default_predictor: Optional[RiskPredictor] = None


def get_risk_predictor() -> RiskPredictor:
    """デフォルトのRiskPredictorインスタンスを取得"""
    global _default_predictor
    if _default_predictor is None:
        _default_predictor = RiskPredictor()
    return _default_predictor
