"""
CacheManager - SHIGOKU 階層型キャッシュ基盤

L1 (メモリ/LRU) と L2 (Redis) を組み合わせた非同期キャッシュシステム。
Redis が利用不可能な場合は L1 のみで動作する。
"""

import logging
import time
from typing import Optional, Any, Dict, Tuple
from collections import OrderedDict

try:
    import redis.asyncio as redis
    import msgpack
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

logger = logging.getLogger(__name__)

class TimedLRUCache:
    """
    メモリ内 L1 キャッシュ
    (src/core/infra/async_writer.py から移植・洗練)
    """
    def __init__(self, max_size: int = 5000, ttl_seconds: int = 300):
        self._cache: OrderedDict[str, Tuple[Any, float]] = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl_seconds
        self._stats = {"hit": 0, "miss": 0, "expired": 0, "evicted": 0}

    def get(self, key: str) -> Optional[Any]:
        if key not in self._cache:
            self._stats["miss"] += 1
            return None
        
        value, timestamp = self._cache[key]
        if time.time() - timestamp >= self._ttl:
            del self._cache[key]
            self._stats["expired"] += 1
            return None
        
        self._cache.move_to_end(key)
        self._stats["hit"] += 1
        return value

    def set(self, key: str, value: Any) -> None:
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = (value, time.time())
        
        if len(self._cache) > self._max_size:
            self._cache.popitem(last=False)
            self._stats["evicted"] += 1

    def get_stats(self) -> dict:
        """統計情報を返す"""
        total = self._stats["hit"] + self._stats["miss"]
        hit_rate = (self._stats["hit"] / total * 100) if total > 0 else 0.0
        return {
            **self._stats,
            "size": len(self._cache),
            "hit_rate": f"{hit_rate:.1f}%"
        }

    def clear(self):
        self._cache.clear()

class OptimizedCache:
    """
    L1/L2 階層型キャッシュ
    """
    def __init__(
        self, 
        redis_url: str = "redis://localhost:6379/0",
        l1_size: int = 10000,
        l1_ttl: int = 3600,
        enable_l2: bool = True
    ):
        self.l1 = TimedLRUCache(max_size=l1_size, ttl_seconds=l1_ttl)
        self.redis_url = redis_url
        self._redis: Optional[Any] = None
        self._enable_l2 = enable_l2 and HAS_REDIS
        self._hit_stats = {"l1": 0, "l2": 0, "miss": 0}

    async def _get_redis(self):
        """Redis接続の遅延初期化"""
        if not self._enable_l2:
            return None
        
        if self._redis is None:
            try:
                self._redis = redis.from_url(self.redis_url)
                # 接続テスト
                await self._redis.ping()
                logger.info("✅ Connected to Redis at %s", self.redis_url)
            except Exception as e:
                logger.warning("❌ Redis connection failed, falling back to L1 only: %s", e)
                self._enable_l2 = False
                self._redis = None
        return self._redis

    async def get(self, key: str) -> Optional[Any]:
        """キャッシュ取得 (L1 -> L2)"""
        # L1 チェック
        val = self.l1.get(key)
        if val is not None:
            self._hit_stats["l1"] += 1
            return val

        # L2 チェック
        r = await self._get_redis()
        if r:
            try:
                raw = await r.get(key)
                if raw:
                    self._hit_stats["l2"] += 1
                    # msgpack に redis.asyncio が対応しているか、or raw bytes かを確認
                    # ここでは明示的に msgpack でデコード
                    data = msgpack.unpackb(raw, raw=False)
                    # L1 に昇格
                    self.l1.set(key, data)
                    return data
            except Exception as e:
                logger.debug("L2 hit failed: %s", e)

        self._hit_stats["miss"] += 1
        return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """キャッシュ設定 (L1 & L2)"""
        # L1 にセット
        self.l1.set(key, value)

        # L2 にセット
        r = await self._get_redis()
        if r:
            try:
                packed = msgpack.packb(value, use_bin_type=True)
                await r.set(key, packed, ex=ttl or self.l1._ttl)
            except Exception as e:
                logger.debug("L2 set failed: %s", e)

    async def delete(self, key: str) -> None:
        """キャッシュ削除"""
        if key in self.l1._cache: # pylint: disable=protected-access
            del self.l1._cache[key] # pylint: disable=protected-access
        
        r = await self._get_redis()
        if r:
            try:
                await r.delete(key)
            except Exception:
                pass

    def get_stats(self) -> Dict[str, Any]:
        """統計情報の取得"""
        total = sum(self._hit_stats.values())
        hit_rate = ((self._hit_stats["l1"] + self._hit_stats["l2"]) / total * 100) if total > 0 else 0.0
        return {
            "hits": self._hit_stats,
            "hit_rate": f"{hit_rate:.1f}%",
            "l1_stats": self.l1.get_stats(),
            "l2_enabled": self._enable_l2
        }

# シングルトン
_default_cache: Optional[OptimizedCache] = None

def get_cache() -> OptimizedCache:
    global _default_cache
    if _default_cache is None:
        _default_cache = OptimizedCache()
    return _default_cache
