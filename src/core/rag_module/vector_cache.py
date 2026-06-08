"""
Simple vector cache implementation for RAG optimization.
Uses a SQLite database to persist embedding vectors, reducing API calls and latency.
"""
import sqlite3
import json
import hashlib
import pickle
import logging
from pathlib import Path
from typing import Optional, List, Any

logger = logging.getLogger(__name__)

class VectorCache:
    """
    SQLite-based Cache for Vector Embeddings.
    
    Schema:
        key (TEXT PRIMARY KEY): hash(text + model_name)
        vector (BLOB): pickled list of floats
        text (TEXT): original text (for debugging/verification)
        model (TEXT): model name
        created_at (TIMESTAMP): default current_timestamp
    """
    
    def __init__(self, db_path: str = "data/cache/vector_cache.sqlite"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._hit_count = 0
        self._miss_count = 0

    def _init_db(self):
        """Initialize SQLite database table."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS embeddings (
                        key TEXT PRIMARY KEY,
                        vector BLOB NOT NULL,
                        text TEXT,
                        model TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                # Index for model-based cleanup if needed
                conn.execute("CREATE INDEX IF NOT EXISTS idx_model ON embeddings(model)")
        except Exception as e:
            logger.error(f"Failed to initialize vector cache DB: {e}")

    def _generate_key(self, text: str, model_name: str) -> str:
        """Generate a unique key for the text and model."""
        content = f"{model_name}:{text}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def get(self, text: str, model_name: str) -> Optional[List[float]]:
        """Retrieve embedding vector from cache."""
        key = self._generate_key(text, model_name)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT vector FROM embeddings WHERE key = ?", (key,))
                row = cursor.fetchone()
                if row:
                    self._hit_count += 1
                    return pickle.loads(row[0])
        except Exception as e:
            logger.warning(f"Vector cache read failed: {e}")
        
        self._miss_count += 1
        return None

    def set(self, text: str, model_name: str, vector: List[float]):
        """Save embedding vector to cache."""
        key = self._generate_key(text, model_name)
        blob = pickle.dumps(vector)
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO embeddings (key, vector, text, model) VALUES (?, ?, ?, ?)",
                    (key, blob, text, model_name)
                )
        except Exception as e:
            logger.error(f"Vector cache write failed: {e}")

    def get_stats(self) -> dict:
        """Return cache statistics."""
        return {
            "hits": self._hit_count,
            "misses": self._miss_count,
            "ratio": self._hit_count / (self._hit_count + self._miss_count) if (self._hit_count + self._miss_count) > 0 else 0.0
        }

# Singleton instance
_vector_cache = None

def get_vector_cache(db_path: str = "data/cache/vector_cache.sqlite") -> VectorCache:
    global _vector_cache
    if _vector_cache is None:
        _vector_cache = VectorCache(db_path)
    return _vector_cache
