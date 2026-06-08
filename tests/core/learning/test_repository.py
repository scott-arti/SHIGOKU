"""
LearningRepositoryのテスト
"""
import os
import tempfile
import time
import pytest
from src.core.learning.repository import (
    LearningRepository,
    LearningEntry,
)


class TestLearningRepository:
    """LearningRepositoryクラスのテスト"""
    
    @pytest.fixture
    def temp_db_path(self):
        """一時データベースパス"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield os.path.join(tmpdir, "test_learning.db")
    
    @pytest.fixture
    def repo(self, temp_db_path):
        """テスト用リポジトリ"""
        return LearningRepository(db_path=temp_db_path, default_ttl_days=1)
    
    def test_store_and_retrieve(self, repo):
        """保存と取得テスト"""
        repo.store(
            category="waf_bypass",
            key="cloudflare_xss",
            value={"pattern": "<img onerror=alert(1)>", "success_rate": 0.8},
        )
        
        result = repo.retrieve("waf_bypass", "cloudflare_xss")
        
        assert result is not None
        assert result["pattern"] == "<img onerror=alert(1)>"
        assert result["success_rate"] == 0.8
    
    def test_retrieve_nonexistent(self, repo):
        """存在しないキーの取得テスト"""
        result = repo.retrieve("waf_bypass", "nonexistent")
        assert result is None
    
    def test_update_existing(self, repo):
        """既存エントリの更新テスト"""
        repo.store("test", "key1", {"version": 1})
        repo.store("test", "key1", {"version": 2})
        
        result = repo.retrieve("test", "key1")
        assert result["version"] == 2
    
    def test_list_by_category(self, repo):
        """カテゴリ別一覧取得テスト"""
        repo.store("errors", "err1", {"solution": "retry"})
        repo.store("errors", "err2", {"solution": "skip"})
        repo.store("other", "key1", {"data": "test"})
        
        entries = repo.list_by_category("errors")
        
        assert len(entries) == 2
        assert all(e.category == "errors" for e in entries)
    
    def test_search(self, repo):
        """検索テスト"""
        repo.store("payloads", "xss_basic", {"payload": "<script>alert(1)</script>"})
        repo.store("payloads", "xss_img", {"payload": "<img onerror=alert(1)>"})
        repo.store("payloads", "sqli_union", {"payload": "' UNION SELECT--"})
        
        results = repo.search("payloads", "xss")
        
        assert len(results) == 2
        assert all("xss" in e.key for e in results)
    
    def test_delete(self, repo):
        """削除テスト"""
        repo.store("test", "to_delete", {"data": "temp"})
        
        assert repo.retrieve("test", "to_delete") is not None
        
        deleted = repo.delete("test", "to_delete")
        
        assert deleted is True
        assert repo.retrieve("test", "to_delete") is None
    
    def test_cleanup_expired(self, repo):
        """期限切れクリーンアップテスト"""
        import sqlite3
        
        # 通常のエントリを作成
        repo.store("test", "valid", {"data": "new"}, ttl_days=30)
        
        # 直接DBに期限切れエントリを挿入
        conn = sqlite3.connect(str(repo.db_path))
        conn.execute("""
            INSERT INTO learning_entries 
                (category, key, value, created_at, expires_at, hit_count)
            VALUES (?, ?, ?, ?, ?, 0)
        """, ("test", "expired", '{"data": "old"}', time.time() - 100, time.time() - 1))
        conn.commit()
        conn.close()
        
        cleaned = repo.cleanup_expired()
        
        assert cleaned >= 1
        assert repo.retrieve("test", "expired") is None
        assert repo.retrieve("test", "valid") is not None
    
    def test_get_stats(self, repo):
        """統計情報取得テスト"""
        repo.store("cat1", "key1", {"data": 1})
        repo.store("cat1", "key2", {"data": 2})
        repo.store("cat2", "key1", {"data": 3})
        
        stats = repo.get_stats()
        
        assert stats["total_entries"] == 3
        assert stats["by_category"]["cat1"] == 2
        assert stats["by_category"]["cat2"] == 1
    
    def test_hit_count_increment(self, repo):
        """ヒットカウント増加テスト"""
        repo.store("test", "popular", {"data": "accessed often"})
        
        # 複数回取得
        for _ in range(5):
            repo.retrieve("test", "popular")
        
        entries = repo.list_by_category("test")
        assert entries[0].hit_count >= 5


class TestLearningEntry:
    """LearningEntryクラスのテスト"""
    
    def test_is_expired(self):
        """期限切れチェックテスト"""
        expired_entry = LearningEntry(
            category="test",
            key="expired",
            value={},
            created_at=time.time() - 100,
            expires_at=time.time() - 1,  # 過去
        )
        
        valid_entry = LearningEntry(
            category="test",
            key="valid",
            value={},
            created_at=time.time(),
            expires_at=time.time() + 3600,  # 1時間後
        )
        
        assert expired_entry.is_expired() is True
        assert valid_entry.is_expired() is False
    
    def test_to_dict(self):
        """辞書変換テスト"""
        entry = LearningEntry(
            category="waf",
            key="bypass1",
            value={"pattern": "test"},
            created_at=1234567890.0,
            expires_at=1234567890.0 + 86400,
            hit_count=10,
        )
        
        d = entry.to_dict()
        
        assert d["category"] == "waf"
        assert d["key"] == "bypass1"
        assert d["value"]["pattern"] == "test"
        assert d["hit_count"] == 10
