"""
Adaptive Rate Limiter - 動的レート制限

429応答検知で自動減速、正常時は徐々に加速する動的制御。
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# Phase 2 (SGK-2026-0311): Blocking signal status codes.
_BLOCKING_STATUS_CODES: frozenset[int] = frozenset({403, 406, 429})


@dataclass
class BlockingSignalEvent:
    """Structured record of a blocking response signal.

    Detected in on_response() for 403/406/429 status codes.
    Circuit breaker action is deferred to Phase 7 (SGK-2026-0316).
    """
    status_code: int
    origin_key: str = ""
    timestamp: float = 0.0


@dataclass
class RateLimitStats:
    """レート制限統計"""
    total_requests: int = 0
    throttled_count: int = 0
    current_rps: float = 10.0
    min_rps_reached: int = 0
    max_rps_reached: int = 0


class AdaptiveRateLimiter:
    """
    動的レート制限
    
    - 429応答検知で自動減速 (0.5倍)
    - 正常時は徐々に加速 (1.1倍)
    - ターゲット別のレート管理
    """
    
    def __init__(
        self,
        initial_rps: float = 10.0,
        min_rps: float = 1.0,
        max_rps: float = 50.0,
        backoff_factor: float = 0.5,
        recovery_factor: float = 1.1,
        window_seconds: float = 1.0,
        blocking_degrade_threshold: int = 3,
        blocking_degrade_window_seconds: float = 60.0,
    ):
        self.initial_rps = initial_rps
        self.min_rps = min_rps
        self.max_rps = max_rps
        self.backoff_factor = backoff_factor
        self.recovery_factor = recovery_factor
        self.window_seconds = window_seconds
        self.blocking_degrade_threshold = max(1, int(blocking_degrade_threshold))
        self.blocking_degrade_window_seconds = max(0.0, float(blocking_degrade_window_seconds))
        
        self.current_rps = initial_rps
        self._lock = threading.Lock()
        self._last_request_time = 0.0
        self._request_count = 0
        self._window_start = time.time()
        
        # 統計
        self.stats = RateLimitStats(current_rps=initial_rps)
        
        # ターゲット別レート
        self._target_rates: dict[str, float] = {}

        # Phase 2 (SGK-2026-0311): Blocking signal event log.
        self.blocking_signals: list[BlockingSignalEvent] = []
        self._degraded_origins: dict[str, str] = {}
        self.degrade_events: list[dict] = []
    
    def wait(self, target: str = None) -> float:
        """
        リクエスト前に適切な待機時間を待つ
        
        Returns:
            実際に待機した秒数
        """
        with self._lock:
            rps = self._get_rps(target)
            interval = 1.0 / rps if rps > 0 else 0
            
            now = time.time()
            elapsed = now - self._last_request_time
            
            if elapsed < interval:
                wait_time = interval - elapsed
                time.sleep(wait_time)
                self._last_request_time = time.time()
                return wait_time
            
            self._last_request_time = now
            return 0.0
    
    def on_response(self, status_code: int, target: str = None) -> None:
        """
        レスポンス受信時にレート調整

        Phase 2 (SGK-2026-0311): Detects blocking signals (403/406/429)
        and records structured BlockingSignalEvent for later use.
        Circuit breaker action is deferred to Phase 7 (SGK-2026-0316).

        Args:
            status_code: HTTPステータスコード
            target: ターゲット識別子（ドメイン等）
        """
        with self._lock:
            self.stats.total_requests += 1

            if status_code in _BLOCKING_STATUS_CODES:
                self.blocking_signals.append(BlockingSignalEvent(
                    status_code=status_code,
                    origin_key=target or "",
                    timestamp=time.time(),
                ))
                self._maybe_degrade_origin(target or "")

            if status_code == 429:
                # レート制限検知 → 減速
                self._decrease_rate(target)
                self.stats.throttled_count += 1
                logger.warning(
                    "Rate limit hit (429). Reducing RPS: %.1f -> %.1f",
                    self.current_rps / self.backoff_factor,
                    self.current_rps
                )
            elif status_code < 400:
                # 正常 → 徐々に加速
                self._increase_rate(target)
    
    def _get_rps(self, target: str = None) -> float:
        """現在のRPSを取得"""
        if target and target in self._target_rates:
            return self._target_rates[target]
        return self.current_rps
    
    def _decrease_rate(self, target: str = None) -> None:
        """レートを減少"""
        if target:
            current = self._target_rates.get(target, self.current_rps)
            self._target_rates[target] = max(self.min_rps, current * self.backoff_factor)
        else:
            self.current_rps = max(self.min_rps, self.current_rps * self.backoff_factor)
        
        self.stats.current_rps = self.current_rps
        if self.current_rps <= self.min_rps:
            self.stats.min_rps_reached += 1
    
    def _increase_rate(self, target: str = None) -> None:
        """レートを増加"""
        if target:
            current = self._target_rates.get(target, self.current_rps)
            self._target_rates[target] = min(self.max_rps, current * self.recovery_factor)
        else:
            self.current_rps = min(self.max_rps, self.current_rps * self.recovery_factor)
        
        self.stats.current_rps = self.current_rps
        if self.current_rps >= self.max_rps:
            self.stats.max_rps_reached += 1
    
    def reset(self, target: str = None) -> None:
        """レートをリセット"""
        with self._lock:
            if target:
                self._target_rates[target] = self.initial_rps
                self._degraded_origins.pop(target, None)
            else:
                self.current_rps = self.initial_rps
                self._target_rates.clear()
                self._degraded_origins.clear()

    def _maybe_degrade_origin(self, origin_key: str) -> None:
        if not origin_key or origin_key in self._degraded_origins:
            return

        now = time.time()
        window_start = now - self.blocking_degrade_window_seconds
        recent = [
            signal for signal in self.blocking_signals
            if signal.origin_key == origin_key
            and (
                self.blocking_degrade_window_seconds <= 0.0
                or signal.timestamp >= window_start
            )
        ]
        if len(recent) < self.blocking_degrade_threshold:
            return

        reason = "blocking_signal_threshold"
        self._degraded_origins[origin_key] = reason
        self.degrade_events.append({
            "origin_key": origin_key,
            "reason": reason,
            "signal_count": len(recent),
            "timestamp": now,
        })

    def is_origin_degraded(self, origin_key: str) -> bool:
        with self._lock:
            return origin_key in self._degraded_origins

    def get_origin_degrade_reason(self, origin_key: str) -> str:
        with self._lock:
            return self._degraded_origins.get(origin_key, "")
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        return {
            "total_requests": self.stats.total_requests,
            "throttled_count": self.stats.throttled_count,
            "current_rps": self.current_rps,
            "throttle_rate": self.stats.throttled_count / max(1, self.stats.total_requests),
            "degraded_origins": sorted(self._degraded_origins.keys()),
        }


# カテゴリ別プリセット
RATE_LIMIT_PRESETS = {
    "intel_passive": AdaptiveRateLimiter(initial_rps=50, max_rps=100),  # DNS, Cert
    "intel_active": AdaptiveRateLimiter(initial_rps=10, max_rps=30),    # Crawl
    "attack_auth": AdaptiveRateLimiter(initial_rps=5, max_rps=15),      # JWT, OAuth
    "attack_inject": AdaptiveRateLimiter(initial_rps=3, max_rps=10),    # SQLi, XSS
    "external_api": AdaptiveRateLimiter(initial_rps=2, max_rps=5),      # Shodan, NVD
}


def get_rate_limiter(category: str) -> AdaptiveRateLimiter:
    """カテゴリ別レートリミッター取得"""
    return RATE_LIMIT_PRESETS.get(category, AdaptiveRateLimiter())
