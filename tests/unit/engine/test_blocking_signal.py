"""
T-5.1 / T-5.2: BlockingSignalEvent detection tests.

Tests:
  - T-5.1: 403 response → BlockingSignalEvent recorded
  - T-5.2: 429 response → BlockingSignalEvent recorded
  - Additional: 200/404/500 do NOT generate signals
"""
from src.core.engine.adaptive_rate_limiter import (
    AdaptiveRateLimiter,
    BlockingSignalEvent,
)


class TestBlockingSignalDetection:
    """T-5.1 / T-5.2: Blocking signal detection in on_response()."""

    def test_403_generates_blocking_signal(self):
        """T-5.1: 403 response → BlockingSignalEvent with status_code=403."""
        limiter = AdaptiveRateLimiter()
        limiter.on_response(403, target="https://example.com")

        assert len(limiter.blocking_signals) == 1
        signal = limiter.blocking_signals[0]
        assert isinstance(signal, BlockingSignalEvent)
        assert signal.status_code == 403
        assert signal.origin_key == "https://example.com"
        assert signal.timestamp > 0

    def test_429_generates_blocking_signal(self):
        """T-5.2: 429 response → BlockingSignalEvent with status_code=429."""
        limiter = AdaptiveRateLimiter()
        limiter.on_response(429, target="https://api.example.com")

        assert len(limiter.blocking_signals) == 1
        signal = limiter.blocking_signals[0]
        assert signal.status_code == 429
        assert signal.origin_key == "https://api.example.com"

    def test_406_generates_blocking_signal(self):
        """406 (Not Acceptable) also generates a blocking signal."""
        limiter = AdaptiveRateLimiter()
        limiter.on_response(406, target="https://example.com")

        assert len(limiter.blocking_signals) == 1
        assert limiter.blocking_signals[0].status_code == 406

    def test_200_does_not_generate_signal(self):
        """200 response → no blocking signal."""
        limiter = AdaptiveRateLimiter()
        limiter.on_response(200, target="https://example.com")
        assert len(limiter.blocking_signals) == 0

    def test_404_does_not_generate_signal(self):
        """404 response → no blocking signal (not a rate/WAF block)."""
        limiter = AdaptiveRateLimiter()
        limiter.on_response(404, target="https://example.com")
        assert len(limiter.blocking_signals) == 0

    def test_500_does_not_generate_signal(self):
        """500 response → no blocking signal (server error, not block)."""
        limiter = AdaptiveRateLimiter()
        limiter.on_response(500, target="https://example.com")
        assert len(limiter.blocking_signals) == 0

    def test_multiple_signals_accumulated(self):
        """Multiple blocking responses → all signals recorded."""
        limiter = AdaptiveRateLimiter()
        limiter.on_response(403, target="https://a.com")
        limiter.on_response(429, target="https://b.com")
        limiter.on_response(403, target="https://a.com")

        assert len(limiter.blocking_signals) == 3
        codes = [s.status_code for s in limiter.blocking_signals]
        assert codes == [403, 429, 403]

    def test_existing_429_throttle_behavior_preserved(self):
        """Existing 429 rate adjustment behavior is preserved (target-specific)."""
        limiter = AdaptiveRateLimiter(initial_rps=50.0, min_rps=1.0)
        limiter.on_response(429, target="https://example.com")

        # Rate for target should have decreased (existing behavior)
        target_rps = limiter._get_rps("https://example.com")
        assert target_rps < 50.0
        # Signal should also be recorded (new behavior)
        assert len(limiter.blocking_signals) == 1

    def test_repeated_blocking_signals_trigger_origin_degrade(self):
        """T-7.6: 403/406/429 signals activate a protective per-origin degrade gate."""
        limiter = AdaptiveRateLimiter(blocking_degrade_threshold=3)

        limiter.on_response(403, target="https://example.com")
        limiter.on_response(406, target="https://example.com")
        assert limiter.is_origin_degraded("https://example.com") is False

        limiter.on_response(429, target="https://example.com")

        assert limiter.is_origin_degraded("https://example.com") is True
        assert limiter.get_origin_degrade_reason("https://example.com") == "blocking_signal_threshold"
        assert limiter.degrade_events[-1]["origin_key"] == "https://example.com"
