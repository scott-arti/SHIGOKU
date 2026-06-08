"""
Wordlist Learner

発見されたパスを収集し、カスタムワードリストを自動生成
"""

import logging
from pathlib import Path
from typing import List, Set
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class WordlistLearner:
    """
    ワードリスト自動学習クラス
    
    スキャン中に発見されたパスを収集し、
    次回スキャンで再利用できるカスタムワードリストを生成
    """
    
    def __init__(self, wordlists_dir: Path = None):
        if wordlists_dir is None:
            wordlists_dir = Path(__file__).parent.parent.parent.parent / "wordlists"
        
        self.wordlists_dir = wordlists_dir
        self.custom_dir = wordlists_dir / "custom"
        self.custom_dir.mkdir(parents=True, exist_ok=True)
        
        # 発見パス収集用
        self.discovered_paths: Set[str] = set()
        self.discovered_subdomains: Set[str] = set()
        self.discovered_params: Set[str] = set()
    
    def add_url(self, url: str) -> None:
        """
        URLから学習
        
        Args:
            url: 発見されたURL
        """
        try:
            parsed = urlparse(url)
            
            # パス抽出
            path = parsed.path.strip('/')
            if path:
                # パスの各セグメントを収集
                segments = path.split('/')
                for segment in segments:
                    # 数字のみ、UUIDなどは除外
                    if segment and not self._is_dynamic(segment):
                        self.discovered_paths.add(segment)
            
            # サブドメイン抽出
            hostname = parsed.hostname
            if hostname:
                parts = hostname.split('.')
                if len(parts) > 2:
                    subdomain = parts[0]
                    if not self._is_dynamic(subdomain):
                        self.discovered_subdomains.add(subdomain)
            
            # パラメータ抽出
            query = parsed.query
            if query:
                for param in query.split('&'):
                    if '=' in param:
                        key = param.split('=')[0]
                        if key and not self._is_dynamic(key):
                            self.discovered_params.add(key)
                            
        except Exception as e:
            logger.debug("Failed to parse URL %s: %s", url, e)
    
    def add_urls(self, urls: List[str]) -> None:
        """複数URLを一括学習"""
        for url in urls:
            self.add_url(url)
    
    def _is_dynamic(self, segment: str) -> bool:
        """
        動的なセグメントかどうか判定
        
        動的例: 数字のみ、UUID、ハッシュ値など
        """
        # 数字のみ
        if segment.isdigit():
            return True
        
        # UUID形式
        if len(segment) == 36 and segment.count('-') == 4:
            return True
        
        # ハッシュ風（16進数長文字列）
        if len(segment) > 20 and all(c in '0123456789abcdef' for c in segment.lower()):
            return True
        
        # 単一文字
        if len(segment) <= 1:
            return True
        
        return False
    
    def save_wordlist(self, purpose: str = "paths") -> Path:
        """
        収集したワードを保存
        
        Args:
            purpose: 用途（paths, subdomains, params）
        
        Returns:
            保存先パス
        """
        timestamp = datetime.now().strftime("%Y%m%d")
        
        if purpose == "paths":
            words = self.discovered_paths
        elif purpose == "subdomains":
            words = self.discovered_subdomains
        elif purpose == "params":
            words = self.discovered_params
        else:
            words = self.discovered_paths
        
        if not words:
            logger.info("No words to save for %s", purpose)
            return None
        
        # 既存ファイル読み込み・統合
        filename = f"discovered_{purpose}.txt"
        output_path = self.custom_dir / filename
        
        existing_words = set()
        if output_path.exists():
            existing_words = set(output_path.read_text(encoding='utf-8').splitlines())
        
        # 統合
        all_words = existing_words | words
        
        # ソートして保存
        sorted_words = sorted(all_words)
        output_path.write_text('\n'.join(sorted_words) + '\n', encoding='utf-8')
        
        new_count = len(words - existing_words)
        logger.info(
            "Saved %d words to %s (%d new)",
            len(all_words), output_path.name, new_count
        )
        
        return output_path
    
    def save_all(self) -> dict:
        """すべてのカテゴリを保存"""
        results = {}
        
        for purpose in ["paths", "subdomains", "params"]:
            path = self.save_wordlist(purpose)
            if path:
                results[purpose] = str(path)
        
        return results
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        return {
            "paths": len(self.discovered_paths),
            "subdomains": len(self.discovered_subdomains),
            "params": len(self.discovered_params),
        }
    
    def clear(self) -> None:
        """収集データをクリア"""
        self.discovered_paths.clear()
        self.discovered_subdomains.clear()
        self.discovered_params.clear()


# シングルトン
_learner_instance = None

def get_wordlist_learner() -> WordlistLearner:
    """WordlistLearnerのシングルトン取得"""
    global _learner_instance
    if _learner_instance is None:
        _learner_instance = WordlistLearner()
    return _learner_instance
