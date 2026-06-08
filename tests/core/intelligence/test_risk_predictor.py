"""
RiskPredictorのテスト
"""
import pytest
from src.core.intelligence.risk_predictor import (
    RiskPredictor,
    ActionRiskProfile,
    ActionType,
    RiskLevel,
    get_risk_predictor,
)


class TestRiskPredictor:
    """RiskPredictorクラスのテスト"""
    
    @pytest.fixture
    def predictor(self):
        """テスト用プレディクター"""
        return RiskPredictor(conservative=True)
    
    def test_low_risk_action(self, predictor):
        """低リスクアクションの評価"""
        profile = ActionRiskProfile(
            action_type=ActionType.PASSIVE_RECON,
            target_url="https://example.com",
        )
        
        assessment = predictor.assess(profile)
        
        assert assessment.risk_level in [RiskLevel.MINIMAL, RiskLevel.LOW]
        assert assessment.risk_score < 0.3
        assert assessment.should_proceed is True
    
    def test_high_risk_action(self, predictor):
        """高リスクアクションの評価"""
        profile = ActionRiskProfile(
            action_type=ActionType.EXPLOIT_ATTEMPT,
            target_url="https://example.com",
            has_waf=True,
        )
        
        assessment = predictor.assess(profile)
        
        assert assessment.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert assessment.risk_score > 0.8
    
    def test_injection_with_payload(self, predictor):
        """ペイロード付きインジェクションテスト"""
        profile = ActionRiskProfile(
            action_type=ActionType.INJECTION_TESTING,
            target_url="https://example.com/api",
            payload="' OR 1=1--",
        )
        
        assessment = predictor.assess(profile)
        
        assert len(assessment.warnings) > 0
        assert any("pattern" in w.lower() for w in assessment.warnings)
    
    def test_waf_increases_risk(self, predictor):
        """WAFがリスクを増加させることを確認"""
        profile_no_waf = ActionRiskProfile(
            action_type=ActionType.PARAM_FUZZING,
            target_url="https://example.com",
            has_waf=False,
        )
        
        profile_with_waf = ActionRiskProfile(
            action_type=ActionType.PARAM_FUZZING,
            target_url="https://example.com",
            has_waf=True,
        )
        
        assessment_no_waf = predictor.assess(profile_no_waf)
        assessment_with_waf = predictor.assess(profile_with_waf)
        
        assert assessment_with_waf.risk_score > assessment_no_waf.risk_score
    
    def test_consecutive_failures_increase_risk(self, predictor):
        """連続失敗がリスクを増加させることを確認"""
        profile_no_failures = ActionRiskProfile(
            action_type=ActionType.AUTH_TESTING,
            target_url="https://example.com",
            consecutive_failures=0,
        )
        
        profile_with_failures = ActionRiskProfile(
            action_type=ActionType.AUTH_TESTING,
            target_url="https://example.com",
            consecutive_failures=3,
        )
        
        assessment_no_failures = predictor.assess(profile_no_failures)
        assessment_with_failures = predictor.assess(profile_with_failures)
        
        assert assessment_with_failures.risk_score > assessment_no_failures.risk_score
        assert assessment_with_failures.recommended_delay > assessment_no_failures.recommended_delay
    
    def test_recommended_delay(self, predictor):
        """推奨遅延の計算テスト"""
        profile = ActionRiskProfile(
            action_type=ActionType.EXPLOIT_ATTEMPT,
            target_url="https://example.com",
            has_waf=True,
        )
        
        assessment = predictor.assess(profile)
        
        assert assessment.recommended_delay > 0
        assert assessment.recommended_delay <= 10.0
    
    def test_authentication_reduces_risk(self, predictor):
        """認証がリスクを低下させることを確認"""
        profile_unauth = ActionRiskProfile(
            action_type=ActionType.PARAM_FUZZING,
            target_url="https://example.com",
            is_authenticated=False,
        )
        
        profile_auth = ActionRiskProfile(
            action_type=ActionType.PARAM_FUZZING,
            target_url="https://example.com",
            is_authenticated=True,
        )
        
        assessment_unauth = predictor.assess(profile_unauth)
        assessment_auth = predictor.assess(profile_auth)
        
        assert assessment_auth.risk_score < assessment_unauth.risk_score
    
    def test_stats(self, predictor):
        """統計情報テスト"""
        predictor.assess(ActionRiskProfile(
            action_type=ActionType.READ_ONLY,
            target_url="https://example.com",
        ))
        predictor.assess(ActionRiskProfile(
            action_type=ActionType.EXPLOIT_ATTEMPT,
            target_url="https://example.com",
        ))
        
        stats = predictor.get_stats()
        
        assert stats["total_assessments"] == 2
        assert "average_risk_score" in stats
    
    def test_to_dict(self, predictor):
        """辞書変換テスト"""
        profile = ActionRiskProfile(
            action_type=ActionType.PARAM_FUZZING,
            target_url="https://example.com",
        )
        
        assessment = predictor.assess(profile)
        d = assessment.to_dict()
        
        assert "risk_level" in d
        assert "risk_score" in d
        assert "detection_probability" in d
        assert "should_proceed" in d


class TestGetRiskPredictor:
    """get_risk_predictor関数のテスト"""
    
    def test_singleton(self):
        """シングルトン動作テスト"""
        p1 = get_risk_predictor()
        p2 = get_risk_predictor()
        assert p1 is p2
