"""
BountyTimelinePredictor: ROI最適化エンジン

報告書の優先順位決定と「いつお金になるか」の予測。

ROI = (Expected_Bounty * Success_Probability) / Time_Cost
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional
import math


@dataclass
class BountyPrediction:
    """報酬予測結果"""
    program: str
    vuln_type: str
    severity: str
    
    # 金額予測
    expected_bounty: float
    min_bounty: float
    max_bounty: float
    
    # 確率
    acceptance_probability: float
    duplicate_risk: float
    
    # 時間予測
    estimated_triage_days: float
    estimated_payout_days: float
    predicted_payout_date: Optional[datetime] = None
    
    # ROIスコア
    roi_score: float = 0.0
    priority_rank: int = 0
    
    def to_dict(self) -> dict:
        return {
            "program": self.program,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "expected_bounty": self.expected_bounty,
            "acceptance_probability": self.acceptance_probability,
            "duplicate_risk": self.duplicate_risk,
            "roi_score": self.roi_score,
            "priority_rank": self.priority_rank,
            "predicted_payout_date": self.predicted_payout_date.isoformat() if self.predicted_payout_date else None,
        }


@dataclass
class FindingCandidate:
    """報告候補のFinding"""
    id: str
    program: str
    vuln_type: str
    severity: str
    title: str
    estimated_effort_hours: float = 2.0  # レポート作成等の追加工数
    
    # 追加情報
    has_poc: bool = True
    is_chained: bool = False  # 複数脆弱性のチェーン
    affects_auth: bool = False  # 認証に影響
    
    prediction: Optional[BountyPrediction] = None


class BountyTimelinePredictor:
    """
    Time-to-Bounty Predictor: ROI最適化エンジン
    
    過去データから以下を予測:
    - トリアージまでの期間
    - 支払いまでの期間
    - 期待報酬額
    - 採択確率
    
    これらを組み合わせてROIスコアを算出し、
    報告の優先順位を決定する。
    """
    
    # デフォルトの報酬テーブル（プラットフォーム平均）
    DEFAULT_BOUNTIES = {
        "critical": {"low": 5000, "mid": 10000, "high": 25000},
        "high": {"low": 1000, "mid": 3000, "high": 7500},
        "medium": {"low": 300, "mid": 750, "high": 1500},
        "low": {"low": 50, "mid": 150, "high": 500},
    }
    
    # デフォルトのタイムライン（日数）
    DEFAULT_TIMELINES = {
        "triage": {"fast": 3, "normal": 14, "slow": 45},
        "payout": {"fast": 7, "normal": 30, "slow": 90},
    }
    
    # 脆弱性タイプ別の重み（高いほど採択されやすい傾向）
    VULN_TYPE_WEIGHTS = {
        "rce": 1.5,
        "sqli": 1.3,
        "ssrf": 1.2,
        "idor": 1.1,
        "auth_bypass": 1.4,
        "xss": 0.8,  # Duplicateになりやすい
        "csrf": 0.7,
        "info_disclosure": 0.5,
    }
    
    def __init__(self, pam = None):
        """
        Args:
            pam: ProgramAwareMemory instance for historical data
        """
        self.pam = pam
        self.predictions_cache: dict[str, BountyPrediction] = {}
    
    def predict(
        self,
        program: str,
        vuln_type: str,
        severity: str,
        estimated_effort_hours: float = 2.0,
    ) -> BountyPrediction:
        """
        報酬とタイムラインを予測
        
        Args:
            program: プログラム名
            vuln_type: 脆弱性タイプ
            severity: 重要度（critical, high, medium, low）
            estimated_effort_hours: 追加工数
        
        Returns:
            BountyPrediction
        """
        # 報酬予測
        bounty_range = self._predict_bounty(program, vuln_type, severity)
        
        # 確率予測
        acceptance_prob = self._predict_acceptance(program, vuln_type)
        duplicate_risk = self._estimate_duplicate_risk(vuln_type)
        
        # タイムライン予測
        triage_days = self._predict_triage_time(program)
        payout_days = self._predict_payout_time(program)
        
        predicted_date = datetime.now() + timedelta(days=triage_days + payout_days)
        
        # ROI計算
        roi = self._calculate_roi(
            expected_bounty=bounty_range["mid"],
            success_prob=acceptance_prob * (1 - duplicate_risk),
            time_hours=estimated_effort_hours,
        )
        
        prediction = BountyPrediction(
            program=program,
            vuln_type=vuln_type,
            severity=severity,
            expected_bounty=bounty_range["mid"],
            min_bounty=bounty_range["low"],
            max_bounty=bounty_range["high"],
            acceptance_probability=acceptance_prob,
            duplicate_risk=duplicate_risk,
            estimated_triage_days=triage_days,
            estimated_payout_days=payout_days,
            predicted_payout_date=predicted_date,
            roi_score=roi,
        )
        
        return prediction
    
    def rank_findings(self, findings: list[FindingCandidate]) -> list[FindingCandidate]:
        """
        複数のFinding候補をROIでランク付け
        
        Returns:
            ROI順にソートされたFindingリスト
        """
        for finding in findings:
            if not finding.prediction:
                finding.prediction = self.predict(
                    program=finding.program,
                    vuln_type=finding.vuln_type,
                    severity=finding.severity,
                    estimated_effort_hours=finding.estimated_effort_hours,
                )
            
            # ボーナス調整
            bonus = 1.0
            if finding.has_poc:
                bonus *= 1.2  # PoCありは採択率UP
            if finding.is_chained:
                bonus *= 1.5  # チェーン攻撃は報酬UP
            if finding.affects_auth:
                bonus *= 1.3  # 認証影響は重要度UP
            
            finding.prediction.roi_score *= bonus
        
        # ROIでソート
        sorted_findings = sorted(
            findings,
            key=lambda f: -f.prediction.roi_score if f.prediction else 0
        )
        
        # ランク付け
        for i, finding in enumerate(sorted_findings):
            if finding.prediction:
                finding.prediction.priority_rank = i + 1
        
        return sorted_findings
    
    def _predict_bounty(self, program: str, vuln_type: str, severity: str) -> dict:
        """報酬額を予測"""
        # PAMからヒストリカルデータを取得
        if self.pam:
            historical = self.pam.estimate_reward(program, vuln_type, severity)
            if historical > 0:
                variance = historical * 0.3  # 30%の変動幅
                return {
                    "low": historical - variance,
                    "mid": historical,
                    "high": historical + variance,
                }
        
        # デフォルトテーブルから取得
        severity_lower = severity.lower()
        if severity_lower in self.DEFAULT_BOUNTIES:
            return self.DEFAULT_BOUNTIES[severity_lower]
        
        return self.DEFAULT_BOUNTIES["medium"]
    
    def _predict_acceptance(self, program: str, vuln_type: str) -> float:
        """採択確率を予測"""
        base_prob = 0.4  # デフォルト40%
        
        # PAMからヒストリカルデータを取得
        if self.pam:
            historical_rate = self.pam.get_acceptance_rate(program)
            if historical_rate > 0:
                base_prob = historical_rate
        
        # 脆弱性タイプによる調整
        weight = self.VULN_TYPE_WEIGHTS.get(vuln_type.lower(), 1.0)
        adjusted_prob = min(base_prob * weight, 0.95)
        
        return round(adjusted_prob, 2)
    
    def _estimate_duplicate_risk(self, vuln_type: str) -> float:
        """Duplicate（重複）リスクを推定"""
        # 一般的なDuplicate率
        duplicate_rates = {
            "xss": 0.5,  # XSSは非常にDuplicateになりやすい
            "csrf": 0.4,
            "info_disclosure": 0.6,
            "idor": 0.25,
            "sqli": 0.2,
            "rce": 0.1,
            "ssrf": 0.2,
            "auth_bypass": 0.15,
        }
        
        return duplicate_rates.get(vuln_type.lower(), 0.3)
    
    def _predict_triage_time(self, program: str) -> float:
        """トリアージまでの日数を予測"""
        if self.pam:
            triage_delta = self.pam.get_triage_speed(program)
            return triage_delta.days
        
        return self.DEFAULT_TIMELINES["triage"]["normal"]
    
    def _predict_payout_time(self, program: str) -> float:
        """支払いまでの日数を予測"""
        if self.pam:
            payout_delta = self.pam.get_payout_speed(program)
            return payout_delta.days
        
        return self.DEFAULT_TIMELINES["payout"]["normal"]
    
    def _calculate_roi(
        self,
        expected_bounty: float,
        success_prob: float,
        time_hours: float,
    ) -> float:
        """
        ROIスコアを計算
        
        ROI = (Expected_Bounty * Success_Probability) / Time_Cost
        """
        if time_hours <= 0:
            time_hours = 0.5  # 最低0.5時間
        
        roi = (expected_bounty * success_prob) / time_hours
        
        # 対数スケールで正規化（見やすくするため）
        normalized_roi = math.log10(max(roi, 1)) * 100
        
        return round(normalized_roi, 2)
    
    def predict_payout_date(self, program: str, vuln_type: str) -> datetime:
        """支払い予定日を予測"""
        triage = self._predict_triage_time(program)
        payout = self._predict_payout_time(program)
        return datetime.now() + timedelta(days=triage + payout)
    
    def calculate_roi_score(self, task: dict) -> float:
        """タスクからROIスコアを計算（MasterConductor連携用）"""
        prediction = self.predict(
            program=task.get("program", "unknown"),
            vuln_type=task.get("vuln_type", "unknown"),
            severity=task.get("severity", "medium"),
            estimated_effort_hours=task.get("effort_hours", 2.0),
        )
        return prediction.roi_score
