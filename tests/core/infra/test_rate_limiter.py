"""
AdaptiveRateLimiterのテスト
"""
import asyncio
import pytest
from src.core.infra.rate_limiter import (
    AdaptiveRateLimiter,
    RateLimitConfig,
    RateLimitMode,
    ResponseMetrics,
    get_rate_limiter,
)


class TestAdaptiveRateLimiter:
    """AdaptiveRateLimiterクラスのテスト"""
    
    @pytest.fixture
    def limiter(self):
        """テスト用リミッター"""
        config = RateLimitConfig(
            stealth_recovery_seconds=1,
            cautious_recovery_seconds=1,
        )
        return AdaptiveRateLimiter(config)
    
    def test_initial_mode_is_normal(self, limiter):
        """初期モードがNORMALであることを確認"""
        assert limiter.mode == RateLimitMode.NORMAL
    
    def test_detect_429_rate_limit(self, limiter):
        """429ステータスでレート制限検知"""
        limiter.report_response(ResponseMetrics(status_code=429, elapsed_time=0.5))
        assert limiter._consecutive_rate_limits == 1
        assert limiter._rate_limit_count == 1
    
    def test_enter_cautious_mode(self, limiter):
        """警戒モードへの移行テスト"""
        # 1回目のレート制限で警戒モードへ
        limiter.report_response(ResponseMetrics(status_code=429, elapsed_time=0.5))
        assert limiter.mode == RateLimitMode.CAUTIOUS
    
    def test_enter_stealth_mode(self, limiter):
        """ステルスモードへの移行テスト"""
        # 3回連続でレート制限
        for _ in range(3):
            limiter.report_response(ResponseMetrics(status_code=429, elapsed_time=0.5))
        
        assert limiter.mode == RateLimitMode.STEALTH
    
    def test_detect_rate_limit_by_keyword(self, limiter):
        """キーワードでレート制限検知"""
        limiter.report_response(ResponseMetrics(
            status_code=200,
            elapsed_time=0.5,
            body_preview="rate limit exceeded",
        ))
        assert limiter._rate_limit_count == 1
    
    def test_baseline_update(self, limiter):
        """ベースライン更新テスト"""
        # 正常レスポンスを報告
        for elapsed in [0.1, 0.2, 0.15, 0.18, 0.12]:
            limiter.report_response(ResponseMetrics(status_code=200, elapsed_time=elapsed))
        
        assert limiter._baseline_avg is not None
        assert 0.1 < limiter._baseline_avg < 0.2
    
    def test_detect_slow_response(self, limiter):
        """遅いレスポンスでレート制限検知"""
        # まずベースラインを設定
        for _ in range(5):
            limiter.report_response(ResponseMetrics(status_code=200, elapsed_time=0.1))
        
        # ベースラインの2倍以上遅いレスポンス
        limiter.report_response(ResponseMetrics(status_code=200, elapsed_time=0.5))
        assert limiter._rate_limit_count == 1
    
    def test_recovery_from_cautious(self, limiter):
        """警戒モードからの復帰テスト"""
        # 警戒モードに入る
        limiter.report_response(ResponseMetrics(status_code=429, elapsed_time=0.5))
        assert limiter.mode == RateLimitMode.CAUTIOUS
        
        # 復帰時間経過
        import time
        time.sleep(1.1)
        
        assert limiter.mode == RateLimitMode.NORMAL
    
    def test_wait_if_needed_normal(self, limiter):
        """NORMALモードでは待機なし"""
        async def run_test():
            delay = await limiter.wait_if_needed()
            assert delay == 0.0
        
        asyncio.run(run_test())
    
    def test_wait_if_needed_stealth(self, limiter):
        """STEALTHモードでは待機あり"""
        # ステルスモードに入る
        for _ in range(3):
            limiter.report_response(ResponseMetrics(status_code=429, elapsed_time=0.5))
        
        async def run_test():
            delay = await limiter.wait_if_needed()
            assert delay >= limiter.config.stealth_delay_min
            assert delay <= limiter.config.stealth_delay_max
        
        asyncio.run(run_test())
    
    def test_stats(self, limiter):
        """統計情報テスト"""
        limiter.report_response(ResponseMetrics(status_code=200, elapsed_time=0.1))
        limiter.report_response(ResponseMetrics(status_code=429, elapsed_time=0.5))
        
        stats = limiter.stats
        assert stats["total_requests"] == 2
        assert stats["rate_limit_count"] == 1
    
    def test_reset(self, limiter):
        """リセットテスト"""
        limiter.report_response(ResponseMetrics(status_code=429, elapsed_time=0.5))
        limiter.reset()
        
        assert limiter.mode == RateLimitMode.NORMAL
        assert limiter._consecutive_rate_limits == 0


class TestGetRateLimiter:
    """get_rate_limiter関数のテスト"""
    
    def test_singleton(self):
        """シングルトン動作テスト"""
        limiter1 = get_rate_limiter()
        limiter2 = get_rate_limiter()
        assert limiter1 is limiter2
