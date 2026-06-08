"""
Phase 2 Intelligence モジュールのテスト
SelfReflection, ErrorAnalyzer, FailureInference
"""
import pytest
from src.core.intelligence.self_reflection import (
    SelfReflection,
    ExecutionRecord,
    ExecutionOutcome,
    get_self_reflection,
)
from src.core.intelligence.error_analyzer import (
    ErrorAnalyzer,
    ErrorRecord,
    ErrorCategory,
    get_error_analyzer,
)
from src.core.intelligence.failure_inference import (
    FailureInference,
    FailureContext,
    get_failure_inference,
)


class TestSelfReflection:
    """SelfReflectionクラスのテスト"""
    
    @pytest.fixture
    def reflection(self):
        """テスト用インスタンス"""
        return SelfReflection()
    
    def test_record_execution(self, reflection):
        """実行記録テスト"""
        reflection.record(ExecutionRecord(
            task_id="task_001",
            action_type="sql_injection",
            target="https://example.com",
            outcome=ExecutionOutcome.SUCCESS,
            duration_seconds=1.5,
        ))
        
        assert len(reflection._history) == 1
    
    def test_success_rate(self, reflection):
        """成功率計算テスト"""
        reflection.record(ExecutionRecord(
            task_id="1", action_type="xss", target="a",
            outcome=ExecutionOutcome.SUCCESS, duration_seconds=1,
        ))
        reflection.record(ExecutionRecord(
            task_id="2", action_type="xss", target="b",
            outcome=ExecutionOutcome.FAILURE, duration_seconds=1,
        ))
        
        rate = reflection.get_success_rate("xss")
        assert rate == 0.5
    
    def test_reflect_success_pattern(self, reflection):
        """成功パターン分析テスト"""
        for i in range(5):
            reflection.record(ExecutionRecord(
                task_id=f"task_{i}", action_type="param_fuzz",
                target=f"https://example.com/{i}",
                outcome=ExecutionOutcome.SUCCESS, duration_seconds=1,
            ))
        
        insights = reflection.reflect()
        success_insights = [i for i in insights if i.category == "success_pattern"]
        
        assert len(success_insights) >= 1
    
    def test_reflect_failure_pattern(self, reflection):
        """失敗パターン分析テスト"""
        for i in range(3):
            reflection.record(ExecutionRecord(
                task_id=f"task_{i}", action_type="exploit",
                target=f"https://example.com/{i}",
                outcome=ExecutionOutcome.BLOCKED, duration_seconds=1,
                error_message="Blocked by WAF",
            ))
        
        insights = reflection.reflect()
        failure_insights = [i for i in insights if i.category == "failure_pattern"]
        
        assert len(failure_insights) >= 1


class TestErrorAnalyzer:
    """ErrorAnalyzerクラスのテスト"""
    
    @pytest.fixture
    def analyzer(self):
        """テスト用インスタンス"""
        return ErrorAnalyzer()
    
    def test_categorize_429(self, analyzer):
        """429エラー分類テスト"""
        record = ErrorRecord(
            error_message="Too Many Requests",
            status_code=429,
        )
        
        analysis = analyzer.analyze(record)
        
        assert analysis.category == ErrorCategory.RATE_LIMITED
        assert analysis.retry_recommended is True
    
    def test_categorize_waf(self, analyzer):
        """WAFブロック分類テスト"""
        record = ErrorRecord(
            error_message="Request blocked by WAF security rules",
        )
        
        analysis = analyzer.analyze(record)
        
        assert analysis.category == ErrorCategory.WAF_BLOCKED
    
    def test_categorize_timeout(self, analyzer):
        """タイムアウト分類テスト"""
        record = ErrorRecord(
            error_message="Connection timed out after 30 seconds",
        )
        
        analysis = analyzer.analyze(record)
        
        assert analysis.category == ErrorCategory.NETWORK_TIMEOUT
        assert analysis.wait_seconds is not None
    
    def test_mitigation_recommendation(self, analyzer):
        """対処法推奨テスト"""
        record = ErrorRecord(
            error_message="403 Forbidden",
            status_code=403,
        )
        
        analysis = analyzer.analyze(record)
        
        assert analysis.category == ErrorCategory.PERMISSION_DENIED
        assert analysis.mitigation != ""


class TestFailureInference:
    """FailureInferenceクラスのテスト"""
    
    @pytest.fixture
    def inference(self):
        """テスト用インスタンス"""
        return FailureInference()
    
    def test_record_failure(self, inference):
        """失敗記録テスト"""
        inference.record_failure(FailureContext(
            target_url="https://example.com/api",
            action_type="sql_injection",
            error_category=ErrorCategory.WAF_BLOCKED,
        ))
        
        assert len(inference._failures) == 1
    
    def test_predict_no_history(self, inference):
        """履歴なし予測テスト"""
        prediction = inference.predict(
            target_url="https://example.com",
            action_type="xss",
        )
        
        assert prediction.failure_probability == 0.0
        assert prediction.likely_to_fail is False
    
    def test_predict_with_similar_failures(self, inference):
        """類似失敗ありの予測テスト"""
        for i in range(3):
            inference.record_failure(FailureContext(
                target_url=f"https://example.com/api/v{i}",
                action_type="sql_injection",
                error_category=ErrorCategory.WAF_BLOCKED,
            ))
        
        prediction = inference.predict(
            target_url="https://example.com/api/v3",
            action_type="sql_injection",
        )
        
        assert prediction.failure_probability > 0.3
        assert prediction.predicted_category == ErrorCategory.WAF_BLOCKED
    
    def test_prevention_tips(self, inference):
        """予防策提案テスト"""
        inference.record_failure(FailureContext(
            target_url="https://example.com/api",
            action_type="sqli",
            error_category=ErrorCategory.WAF_BLOCKED,
            waf_detected=True,
        ))
        
        prediction = inference.predict(
            target_url="https://example.com/api/users",
            action_type="sqli",
        )
        
        assert len(prediction.prevention_tips) > 0
    
    def test_high_risk_targets(self, inference):
        """高リスクターゲット検出テスト"""
        for i in range(5):
            inference.record_failure(FailureContext(
                target_url="https://hardened.com/api",
                action_type="attack",
                error_category=ErrorCategory.WAF_BLOCKED,
            ))
        
        high_risk = inference.get_high_risk_targets()
        
        assert "hardened.com" in high_risk


class TestSingletons:
    """シングルトン関数のテスト"""
    
    def test_reflection_singleton(self):
        r1 = get_self_reflection()
        r2 = get_self_reflection()
        assert r1 is r2
    
    def test_analyzer_singleton(self):
        a1 = get_error_analyzer()
        a2 = get_error_analyzer()
        assert a1 is a2
    
    def test_inference_singleton(self):
        i1 = get_failure_inference()
        i2 = get_failure_inference()
        assert i1 is i2
