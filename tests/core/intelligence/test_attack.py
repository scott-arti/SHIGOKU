"""
Phase 3 Intelligence モジュールのテスト
PriorityBooster, DecisionEnhancer, AdaptiveFuzzer
"""
import pytest
from src.core.intelligence.priority_booster import (
    PriorityBooster,
    BoostEvent,
    BoostTrigger,
    get_priority_booster,
)
from src.core.intelligence.decision_enhancer import (
    DecisionEnhancer,
    DecisionContext,
    Decision,
    get_decision_enhancer,
)
from src.core.intelligence.adaptive_fuzzer import (
    AdaptiveFuzzer,
    PayloadResult,
    FuzzResult,
    get_adaptive_fuzzer,
)


class TestPriorityBooster:
    """PriorityBoosterクラスのテスト"""
    
    @pytest.fixture
    def booster(self):
        return PriorityBooster()
    
    def test_register_task(self, booster):
        """タスク登録テスト"""
        booster.register_task("task_1", 0.5)
        assert booster.get_priority("task_1") == 0.5
    
    def test_boost_on_discovery(self, booster):
        """ブーストイベントテスト"""
        booster.register_task("auth_test", 0.5)
        
        booster.boost_on_discovery(BoostEvent(
            trigger=BoostTrigger.HIGH_VALUE_ASSET,
            target="https://example.com/admin",
            boost_amount=0.3,
            reason="Admin panel found",
            related_tasks=["auth_test"],
        ))
        
        priority = booster.get_priority("auth_test")
        assert priority == 0.8  # 0.5 + 0.3
    
    def test_auto_detect_admin(self, booster):
        """自動検出テスト（管理画面）"""
        event = booster.auto_detect_boost(
            target="https://example.com/admin/login",
            content="Admin Login Page",
            related_tasks=["scan"],
        )
        
        assert event is not None
        assert event.trigger == BoostTrigger.HIGH_VALUE_ASSET
    
    def test_auto_detect_error_leak(self, booster):
        """自動検出テスト（エラー漏洩）"""
        event = booster.auto_detect_boost(
            target="https://example.com/api",
            content="Stack trace: at Line 42...",
            related_tasks=["scan"],
        )
        
        assert event is not None
        assert event.trigger == BoostTrigger.ERROR_LEAK
    
    def test_sorted_tasks(self, booster):
        """優先度ソートテスト"""
        booster.register_task("low", 0.2)
        booster.register_task("high", 0.8)
        booster.register_task("mid", 0.5)
        
        sorted_tasks = booster.get_sorted_tasks()
        
        assert sorted_tasks[0][0] == "high"
        assert sorted_tasks[-1][0] == "low"


class TestDecisionEnhancer:
    """DecisionEnhancerクラスのテスト"""
    
    @pytest.fixture
    def enhancer(self):
        return DecisionEnhancer()
    
    def test_proceed_default(self, enhancer):
        """デフォルト実行判断テスト"""
        context = DecisionContext(
            action_type="xss",
            target_url="https://example.com",
            success_rate_historical=0.6,
        )
        
        decision = enhancer.decide(context)
        
        assert decision.decision == Decision.PROCEED
    
    def test_skip_max_retries(self, enhancer):
        """最大リトライ超過スキップテスト"""
        context = DecisionContext(
            action_type="sql_injection",
            target_url="https://example.com",
            previous_attempts=5,
        )
        
        decision = enhancer.decide(context)
        
        assert decision.decision == Decision.SKIP
        assert "Max retries" in decision.reasoning
    
    def test_retry_rate_limit(self, enhancer):
        """レート制限リトライテスト"""
        context = DecisionContext(
            action_type="xss",
            target_url="https://example.com",
            rate_limit_active=True,
        )
        
        decision = enhancer.decide(context)
        
        assert decision.decision == Decision.RETRY
        assert decision.wait_seconds > 0
    
    def test_modify_waf(self, enhancer):
        """WAF検出修正テスト"""
        context = DecisionContext(
            action_type="sql_injection",
            target_url="https://example.com",
            waf_detected=True,
            previous_attempts=1,
        )
        
        decision = enhancer.decide(context)
        
        assert decision.decision == Decision.MODIFY
        assert len(decision.modifications) > 0
    
    def test_escalate_high_risk(self, enhancer):
        """高リスクエスカレーションテスト"""
        context = DecisionContext(
            action_type="auth_bypass",
            target_url="https://example.com",
            risk_score=0.95,
        )
        
        assert enhancer.should_escalate(context) is True


class TestAdaptiveFuzzer:
    """AdaptiveFuzzerクラスのテスト"""
    
    @pytest.fixture
    def fuzzer(self):
        return AdaptiveFuzzer()
    
    def test_report_result(self, fuzzer):
        """結果報告テスト"""
        fuzzer.report_result(PayloadResult(
            payload="<script>alert(1)</script>",
            result=FuzzResult.BLOCKED,
        ))
        
        assert len(fuzzer._history) == 1
    
    def test_adapt_blocked_payload(self, fuzzer):
        """ブロックされたペイロードの適応テスト"""
        original = "<script>alert(1)</script>"
        
        adapted = fuzzer.adapt_payload(original, FuzzResult.BLOCKED)
        
        assert adapted.original == original
        assert adapted.mutation_type in ["url_encode", "case_variation", "unicode_escape", "none"]
    
    def test_cache_success(self, fuzzer):
        """成功キャッシュテスト"""
        fuzzer.report_result(PayloadResult(
            payload="<img onerror=alert(1) src=x>",
            result=FuzzResult.SUCCESS,
        ))
        
        adapted = fuzzer.adapt_payload("<img onerror=alert(1) src=x>")
        
        assert adapted.mutation_type == "cached_success"
        assert adapted.confidence > 0.8
    
    def test_get_next_payload(self, fuzzer):
        """次のペイロード取得テスト"""
        payload = fuzzer.get_next_payload("xss")
        
        assert payload is not None
        assert payload.adapted != ""
    
    def test_stats(self, fuzzer):
        """統計情報テスト"""
        fuzzer.report_result(PayloadResult(
            payload="test", result=FuzzResult.SUCCESS,
        ))
        fuzzer.report_result(PayloadResult(
            payload="test2", result=FuzzResult.BLOCKED,
        ))
        
        stats = fuzzer.get_stats()
        
        assert stats["total_attempts"] == 2
        assert stats["result_counts"]["success"] == 1


class TestPhase3Singletons:
    """シングルトン関数のテスト"""
    
    def test_booster_singleton(self):
        b1 = get_priority_booster()
        b2 = get_priority_booster()
        assert b1 is b2
    
    def test_enhancer_singleton(self):
        e1 = get_decision_enhancer()
        e2 = get_decision_enhancer()
        assert e1 is e2
    
    def test_fuzzer_singleton(self):
        f1 = get_adaptive_fuzzer()
        f2 = get_adaptive_fuzzer()
        assert f1 is f2
