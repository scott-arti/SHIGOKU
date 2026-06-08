
import time
from src.core.infra.async_writer import TimedLRUCache

def test_basic_get_set():
    """基本的なget/set動作"""
    cache = TimedLRUCache(max_size=3, ttl_seconds=10)
    cache.set("key1", "value1")
    assert cache.get("key1") == "value1"
    assert cache.get("nonexistent") is None

def test_ttl_expiration():
    """TTL期限切れの確認"""
    cache = TimedLRUCache(max_size=10, ttl_seconds=1)
    # 値を設定
    cache.set("key1", "value1")
    
    # 直後は取得可能
    assert cache.get("key1") == "value1"
    
    # 1.1秒待機（TTL切れ）
    time.sleep(1.1)
    assert cache.get("key1") is None
    
    stats = cache.get_stats()
    assert stats["expired"] >= 1

def test_lru_eviction():
    """サイズ上限到達時のLRUエビクション"""
    cache = TimedLRUCache(max_size=3, ttl_seconds=100)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.set("c", 3)
    
    # ここまでは全て残っているはず
    assert cache.get("a") == 1
    
    # "a"にアクセスしたので、"a"が最新になる。"b"が最古になるはず
    # 順序: b, c, a
    
    cache.set("d", 4)  # "b"が削除されるはず
    
    assert cache.get("b") is None  # 最も古いキーが削除
    assert cache.get("a") == 1     # "a"は残っている
    assert cache.get("d") == 4
    
    stats = cache.get_stats()
    assert stats["evicted"] >= 1

def test_hit_rate_stats():
    """ヒット率統計の確認"""
    cache = TimedLRUCache(max_size=10, ttl_seconds=10)
    cache.set("key1", "value1")
    
    cache.get("key1")  # hit
    cache.get("key1")  # hit
    cache.get("key2")  # miss
    
    stats = cache.get_stats()
    assert stats["hit"] == 2
    assert stats["miss"] == 1
    assert "66.7%" in stats["hit_rate"]  # 2/3 = 66.7%
