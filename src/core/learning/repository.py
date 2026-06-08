"""
LearningRepository: 学習結果の永続化

SQLiteベースの軽量学習リポジトリ。
WAF回避パターン、エラー解決策、成功ペイロード等を保存・共有する。
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator, Optional

logger = logging.getLogger(__name__)


@dataclass
class LearningEntry:
    """学習エントリ"""
    category: str
    key: str
    value: dict
    created_at: float
    expires_at: float
    hit_count: int = 0
    
    def is_expired(self) -> bool:
        """有効期限切れかチェック"""
        return time.time() > self.expires_at
    
    def to_dict(self) -> dict:
        """辞書形式に変換"""
        return {
            "category": self.category,
            "key": self.key,
            "value": self.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "hit_count": self.hit_count,
        }


class LearningRepository:
    """
    SQLiteベースの学習リポジトリ
    
    カテゴリ別に学習データを保存し、TTL管理を行う。
    
    カテゴリ例:
    - waf_bypass: WAF回避パターン
    - error_solutions: エラー解決策
    - success_payloads: 成功ペイロード
    - vuln_patterns: 脆弱性パターン
    
    使用例:
        repo = LearningRepository()
        repo.store("waf_bypass", "cloudflare_xss", {"pattern": "..."})
        result = repo.retrieve("waf_bypass", "cloudflare_xss")
    """
    
    DEFAULT_DB_PATH = "~/.shigoku/learning/learning.db"
    DEFAULT_TTL_DAYS = 30
    
    def __init__(
        self,
        db_path: Optional[str] = None,
        default_ttl_days: int = DEFAULT_TTL_DAYS,
    ):
        """
        初期化
        
        Args:
            db_path: SQLiteデータベースパス
            default_ttl_days: デフォルトのTTL（日数）
        """
        self.db_path = Path(
            os.path.expanduser(db_path or self.DEFAULT_DB_PATH)
        )
        self.default_ttl_days = default_ttl_days
        
        # ディレクトリ作成
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # テーブル初期化
        self._init_db()
    
    def _init_db(self) -> None:
        """データベースとテーブルを初期化"""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS learning_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    hit_count INTEGER DEFAULT 0,
                    UNIQUE(category, key)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_category 
                ON learning_entries(category)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_expires 
                ON learning_entries(expires_at)
            """)
            conn.commit()
        logger.info("LearningRepository initialized: %s", self.db_path)
    
    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        """データベース接続を取得"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def store(
        self,
        category: str,
        key: str,
        value: dict,
        ttl_days: Optional[int] = None,
    ) -> None:
        """
        学習データを保存
        
        Args:
            category: カテゴリ名
            key: キー
            value: 保存する値（辞書）
            ttl_days: TTL（日数）、Noneならデフォルト
        """
        ttl = ttl_days or self.default_ttl_days
        now = time.time()
        expires_at = now + (ttl * 24 * 60 * 60)
        
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO learning_entries 
                    (category, key, value, created_at, expires_at, hit_count)
                VALUES (?, ?, ?, ?, ?, 0)
                ON CONFLICT(category, key) DO UPDATE SET
                    value = excluded.value,
                    expires_at = excluded.expires_at,
                    hit_count = hit_count + 1
            """, (category, key, json.dumps(value), now, expires_at))
            conn.commit()
        
        logger.debug("Stored learning entry: %s/%s", category, key)
    
    def retrieve(
        self,
        category: str,
        key: str,
        increment_hit: bool = True,
    ) -> Optional[dict]:
        """
        学習データを取得
        
        Args:
            category: カテゴリ名
            key: キー
            increment_hit: ヒットカウントを増加させるか
            
        Returns:
            保存された値、なければNone
        """
        with self._get_connection() as conn:
            row = conn.execute("""
                SELECT value, expires_at FROM learning_entries
                WHERE category = ? AND key = ? AND expires_at > ?
            """, (category, key, time.time())).fetchone()
            
            if row is None:
                return None
            
            if increment_hit:
                conn.execute("""
                    UPDATE learning_entries SET hit_count = hit_count + 1
                    WHERE category = ? AND key = ?
                """, (category, key))
                conn.commit()
            
            return json.loads(row["value"])
    
    def list_by_category(
        self,
        category: str,
        limit: int = 100,
    ) -> list[LearningEntry]:
        """
        カテゴリ内のエントリを一覧取得
        
        Args:
            category: カテゴリ名
            limit: 最大取得件数
            
        Returns:
            エントリのリスト
        """
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM learning_entries
                WHERE category = ? AND expires_at > ?
                ORDER BY hit_count DESC, created_at DESC
                LIMIT ?
            """, (category, time.time(), limit)).fetchall()
            
            return [
                LearningEntry(
                    category=row["category"],
                    key=row["key"],
                    value=json.loads(row["value"]),
                    created_at=row["created_at"],
                    expires_at=row["expires_at"],
                    hit_count=row["hit_count"],
                )
                for row in rows
            ]
    
    def search(
        self,
        category: str,
        query: str,
        limit: int = 10,
    ) -> list[LearningEntry]:
        """
        キーまたは値でエントリを検索
        
        Args:
            category: カテゴリ名
            query: 検索クエリ
            limit: 最大取得件数
            
        Returns:
            マッチしたエントリのリスト
        """
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM learning_entries
                WHERE category = ? 
                AND expires_at > ?
                AND (key LIKE ? OR value LIKE ?)
                ORDER BY hit_count DESC
                LIMIT ?
            """, (category, time.time(), f"%{query}%", f"%{query}%", limit)).fetchall()
            
            return [
                LearningEntry(
                    category=row["category"],
                    key=row["key"],
                    value=json.loads(row["value"]),
                    created_at=row["created_at"],
                    expires_at=row["expires_at"],
                    hit_count=row["hit_count"],
                )
                for row in rows
            ]
    
    def delete(self, category: str, key: str) -> bool:
        """
        エントリを削除
        
        Args:
            category: カテゴリ名
            key: キー
            
        Returns:
            削除成功ならTrue
        """
        with self._get_connection() as conn:
            cursor = conn.execute("""
                DELETE FROM learning_entries
                WHERE category = ? AND key = ?
            """, (category, key))
            conn.commit()
            return cursor.rowcount > 0
    
    def cleanup_expired(self) -> int:
        """
        期限切れエントリを削除
        
        Returns:
            削除したエントリ数
        """
        with self._get_connection() as conn:
            cursor = conn.execute("""
                DELETE FROM learning_entries
                WHERE expires_at < ?
            """, (time.time(),))
            conn.commit()
            count = cursor.rowcount
        
        if count > 0:
            logger.info("Cleaned up %d expired learning entries", count)
        
        return count
    
    def get_stats(self) -> dict:
        """
        統計情報を取得
        
        Returns:
            統計情報の辞書
        """
        with self._get_connection() as conn:
            total = conn.execute(
                "SELECT COUNT(*) as count FROM learning_entries"
            ).fetchone()["count"]
            
            by_category = conn.execute("""
                SELECT category, COUNT(*) as count 
                FROM learning_entries 
                GROUP BY category
            """).fetchall()
            
            expired = conn.execute("""
                SELECT COUNT(*) as count FROM learning_entries
                WHERE expires_at < ?
            """, (time.time(),)).fetchone()["count"]
            
            return {
                "total_entries": total,
                "expired_entries": expired,
                "by_category": {
                    row["category"]: row["count"] for row in by_category
                },
                "db_path": str(self.db_path),
            }


# シングルトンインスタンス
_default_repo: Optional[LearningRepository] = None


def get_learning_repository() -> LearningRepository:
    """デフォルトのLearningRepositoryインスタンスを取得"""
    global _default_repo
    if _default_repo is None:
        _default_repo = LearningRepository()
    return _default_repo
