"""
AdaptiveRateLimiter: 適応型レート制限回避

レスポンス時間とステータスコードを監視し、
レート制限を検知したら自動でステルスモードに移行する。
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class RateLimitMode(str, Enum):
    """レート制限モード"""
    NORMAL = "normal"
    CAUTIOUS = "cautious"
    STEALTH = "stealth"


@dataclass
class RateLimitConfig:
    """レート制限設定"""
    # ベースライン測定
    baseline_samples: int = 5
    baseline_timeout_multiplier: float = 2.0
    
    # ステルスモード設定
    stealth_delay_min: float = 2.0  # 最小遅延（秒）
    stealth_delay_max: float = 5.0  # 最大遅延（秒）
    stealth_recovery_seconds: int = 300  # 復帰までの秒数
    
    # 警戒モード設定
    cautious_delay_multiplier: float = 1.5
    cautious_recovery_seconds: int = 60
    
    # 検知キーワード
    rate_limit_keywords: list[str] = field(default_factory=lambda: [
        "rate limit",
        "too many requests",
        "slow down",
        "try again later",
        "throttle",
    ])


@dataclass
class ResponseMetrics:
    """レスポンスメトリクス"""
    status_code: int
    elapsed_time: float
    body_preview: str = ""
    timestamp: float = field(default_factory=time.time)


class AdaptiveRateLimiter:
    """
    適応型レート制限回避
    
    レスポンス時間とステータスコードを監視し、
    レート制限を検知したら自動でステルスモードに移行する。
    
    使用例:
        limiter = AdaptiveRateLimiter()
        
        # リクエスト前に待機
        await limiter.wait_if_needed()
        
        # レスポンス後にメトリクス報告
        limiter.report_response(ResponseMetrics(
            status_code=200,
            elapsed_time=0.5,
        ))
    """
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._mode = RateLimitMode.NORMAL
        self._baseline_times: list[float] = []
        self._baseline_avg: Optional[float] = None
        self._mode_entered_at: float = 0
        self._consecutive_rate_limits: int = 0
        self._total_requests: int = 0
        self._rate_limit_count: int = 0
    
    @property
    def mode(self) -> RateLimitMode:
        """現在のモード"""
        self._check_recovery()
        return self._mode
    
    @property
    def stats(self) -> dict:
        """統計情報"""
        return {
            "mode": self._mode.value,
            "total_requests": self._total_requests,
            "rate_limit_count": self._rate_limit_count,
            "baseline_avg_ms": (self._baseline_avg or 0) * 1000,
            "consecutive_rate_limits": self._consecutive_rate_limits,
        }
    
    def _check_recovery(self) -> None:
        """モード復帰をチェック"""
        if self._mode == RateLimitMode.NORMAL:
            return
        
        elapsed = time.time() - self._mode_entered_at
        
        if self._mode == RateLimitMode.STEALTH:
            if elapsed > self.config.stealth_recovery_seconds:
                logger.info("Recovering from STEALTH to CAUTIOUS mode")
                self._mode = RateLimitMode.CAUTIOUS
                self._mode_entered_at = time.time()
                self._consecutive_rate_limits = 0
        
        elif self._mode == RateLimitMode.CAUTIOUS:
            if elapsed > self.config.cautious_recovery_seconds:
                logger.info("Recovering from CAUTIOUS to NORMAL mode")
                self._mode = RateLimitMode.NORMAL
                self._consecutive_rate_limits = 0
    
    def _detect_rate_limit(self, metrics: ResponseMetrics) -> bool:
        """レート制限を検知"""
        # 429 Too Many Requests
        if metrics.status_code == 429:
            return True
        
        # 503 Service Unavailable（しばしばレート制限）
        if metrics.status_code == 503:
            return True
        
        # ベースラインと比較して異常に遅い
        if self._baseline_avg and metrics.elapsed_time > (
            self._baseline_avg * self.config.baseline_timeout_multiplier
        ):
            return True
        
        # レスポンスボディにレート制限キーワード
        body_lower = metrics.body_preview.lower()
        for keyword in self.config.rate_limit_keywords:
            if keyword in body_lower:
                return True
        
        return False
    
    def _update_baseline(self, elapsed_time: float) -> None:
        """ベースラインを更新"""
        if len(self._baseline_times) < self.config.baseline_samples:
            self._baseline_times.append(elapsed_time)
        else:
            self._baseline_times.pop(0)
            self._baseline_times.append(elapsed_time)
        
        self._baseline_avg = sum(self._baseline_times) / len(self._baseline_times)
    
    def report_response(self, metrics: ResponseMetrics) -> None:
        """
        レスポンスメトリクスを報告
        
        Args:
            metrics: レスポンスメトリクス
        """
        self._total_requests += 1
        
        if self._detect_rate_limit(metrics):
            self._rate_limit_count += 1
            self._consecutive_rate_limits += 1
            logger.warning(
                "Rate limit detected (count: %d, consecutive: %d)",
                self._rate_limit_count,
                self._consecutive_rate_limits,
            )
            
            # モード昇格
            if self._consecutive_rate_limits >= 3:
                self._enter_stealth_mode()
            elif self._consecutive_rate_limits >= 1 and self._mode == RateLimitMode.NORMAL:
                self._enter_cautious_mode()
        else:
            # 成功時はベースライン更新とカウントリセット
            self._update_baseline(metrics.elapsed_time)
            if self._consecutive_rate_limits > 0:
                self._consecutive_rate_limits = max(0, self._consecutive_rate_limits - 1)
    
    def _enter_cautious_mode(self) -> None:
        """警戒モードに移行"""
        if self._mode != RateLimitMode.CAUTIOUS:
            logger.warning("Entering CAUTIOUS mode")
            self._mode = RateLimitMode.CAUTIOUS
            self._mode_entered_at = time.time()
    
    def _enter_stealth_mode(self) -> None:
        """ステルスモードに移行"""
        if self._mode != RateLimitMode.STEALTH:
            logger.warning("Entering STEALTH mode")
            self._mode = RateLimitMode.STEALTH
            self._mode_entered_at = time.time()
    
    async def wait_if_needed(self) -> float:
        """
        必要に応じて待機
        
        Returns:
            実際に待機した秒数
        """
        self._check_recovery()
        
        if self._mode == RateLimitMode.NORMAL:
            return 0.0
        
        if self._mode == RateLimitMode.CAUTIOUS:
            base_delay = (self._baseline_avg or 0.5) * self.config.cautious_delay_multiplier
            delay = min(base_delay, 2.0)  # 最大2秒
        
        elif self._mode == RateLimitMode.STEALTH:
            import random
            delay = random.uniform(
                self.config.stealth_delay_min,
                self.config.stealth_delay_max,
            )
        else:
            delay = 0.0
        
        if delay > 0:
            logger.debug("Rate limit delay: %.2fs (mode: %s)", delay, self._mode.value)
            await asyncio.sleep(delay)
        
        return delay
    
    def wait_if_needed_sync(self) -> float:
        """
        同期版: 必要に応じて待機
        
        Returns:
            実際に待機した秒数
        """
        self._check_recovery()
        
        if self._mode == RateLimitMode.NORMAL:
            return 0.0
        
        if self._mode == RateLimitMode.CAUTIOUS:
            base_delay = (self._baseline_avg or 0.5) * self.config.cautious_delay_multiplier
            delay = min(base_delay, 2.0)
        
        elif self._mode == RateLimitMode.STEALTH:
            import random
            delay = random.uniform(
                self.config.stealth_delay_min,
                self.config.stealth_delay_max,
            )
        else:
            delay = 0.0
        
        if delay > 0:
            logger.debug("Rate limit delay (sync): %.2fs", delay)
            time.sleep(delay)
        
        return delay
    
    def reset(self) -> None:
        """状態をリセット"""
        self._mode = RateLimitMode.NORMAL
        self._baseline_times.clear()
        self._baseline_avg = None
        self._consecutive_rate_limits = 0
        logger.info("Rate limiter reset")


# シングルトンインスタンス
_default_limiter: Optional[AdaptiveRateLimiter] = None


def get_rate_limiter() -> AdaptiveRateLimiter:
    """デフォルトのAdaptiveRateLimiterインスタンスを取得"""
    global _default_limiter
    if _default_limiter is None:
        _default_limiter = AdaptiveRateLimiter()
    return _default_limiter
