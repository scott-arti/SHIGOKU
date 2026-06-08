import pytest
import asyncio
import time
from unittest.mock import MagicMock, patch
from src.core.infra.cache_manager import OptimizedCache, TimedLRUCache

@pytest.mark.asyncio
async def test_l1_only_behavior():
    """Redisがない環境（デフォルト）でのL1動作確認"""
    # enable_l2=False で強制的にL1のみにする
    cache = OptimizedCache(enable_l2=False)
    
    await cache.set("test_key", "test_value")
    val = await cache.get("test_key")
    
    assert val == "test_value"
    stats = cache.get_stats()
    assert stats["hits"]["l1"] == 1
    assert stats["hits"]["l2"] == 0
    assert stats["l2_enabled"] is False

@pytest.mark.asyncio
async def test_cache_expiration():
    """TTLによる期限切れの確認"""
    cache = OptimizedCache(l1_ttl=1, enable_l2=False)
    
    await cache.set("expire_key", "data")
    assert await cache.get("expire_key") == "data"
    
    # 1.1秒待機
    await asyncio.sleep(1.1)
    assert await cache.get("expire_key") is None
    
    stats = cache.get_stats()
    assert stats["l1_stats"]["expired"] == 1

@pytest.mark.asyncio
async def test_complex_data_serialization():
    """複雑なデータ構造のキャッシュ動作"""
    cache = OptimizedCache(enable_l2=False)
    data = {
        "status": 200,
        "headers": {"Content-Type": "text/html"},
        "nested": [1, 2, {"a": "b"}]
    }
    
    await cache.set("complex", data)
    retrieved = await cache.get("complex")
    assert retrieved == data
    assert retrieved["nested"][2]["a"] == "b"

@pytest.mark.asyncio
async def test_redis_fallback():
    """Redis接続失敗時のフォールバック動作"""
    # 存在しないホストを指定
    cache = OptimizedCache(redis_url="redis://nonexistent:6379", enable_l2=True)
    
    # 初回の get/set で接続試行し、失敗してL1フォールバックするはず
    await cache.set("fallback_key", "fallback_val")
    val = await cache.get("fallback_key")
    
    assert val == "fallback_val"
    assert cache._enable_l2 is False
