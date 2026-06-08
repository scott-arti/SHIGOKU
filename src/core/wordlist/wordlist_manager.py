"""
Wordlist Manager

ワードリスト選択・管理システム
メタデータベースでAIが最適なワードリストを選択
"""

import logging
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class WordlistInfo:
    """ワードリスト情報"""
    name: str
    path: Path
    source: str  # SecLists, JHaddix, AssetNote, custom
    lines: int
    size: str  # small, medium, high
    purpose: str  # subdomain, directory, api, params
    strength: List[str] = field(default_factory=list)
    best_for: List[str] = field(default_factory=list)


class WordlistManager:
    """ワードリスト管理クラス"""
    
    SIZE_THRESHOLDS = {
        "small": 5000,
        "medium": 30000,
        "high": float('inf')
    }
    
    def __init__(self, wordlists_dir: Path = None):
        if wordlists_dir is None:
            wordlists_dir = Path(__file__).parent.parent.parent.parent / "wordlists"
        self.wordlists_dir = wordlists_dir
        self.wordlists: Dict[str, List[WordlistInfo]] = {}
        self._load_metadata()
    
    def _load_metadata(self) -> None:
        """メタデータをロード"""
        import yaml
        
        for purpose_dir in self.wordlists_dir.iterdir():
            if not purpose_dir.is_dir():
                continue
            
            purpose = purpose_dir.name
            metadata_file = purpose_dir / "metadata.yaml"
            
            if metadata_file.exists():
                try:
                    with open(metadata_file, encoding='utf-8') as f:
                        metadata = yaml.safe_load(f)
                    
                    if metadata and metadata.get('files'):
                        self.wordlists[purpose] = []
                        for file_info in metadata['files']:
                            wl = WordlistInfo(
                                name=file_info['name'],
                                path=purpose_dir / file_info['name'],
                                source=file_info.get('source', 'unknown'),
                                lines=file_info.get('lines', 0),
                                size=file_info.get('size', 'medium'),
                                purpose=purpose,
                                strength=file_info.get('strength', []),
                                best_for=file_info.get('best_for', [])
                            )
                            self.wordlists[purpose].append(wl)
                except Exception as e:
                    logger.warning("Failed to load metadata for %s: %s", purpose, e)
    
    def select(
        self,
        purpose: str,
        mode: str = "bugbounty",
        tech_stack: List[str] = None,
        strategy: str = "standard",
        sources: List[str] = None
    ) -> Optional[WordlistInfo]:
        """
        最適なワードリストを選択
        
        Args:
            purpose: 用途 (subdomain, directory, api...)
            mode: ハンティングモード
            tech_stack: 技術スタック
            strategy: スキャン戦略 (quick, standard, deep)
            sources: 優先ソース
        
        Returns:
            選択されたワードリスト情報
        """
        if purpose not in self.wordlists:
            logger.warning("No wordlists found for purpose: %s", purpose)
            return None
        
        candidates = self.wordlists[purpose]
        
        if not candidates:
            return None
        
        # サイズでフィルタリング
        size_filter = {"quick": "small", "standard": "medium", "deep": "high"}
        target_size = size_filter.get(strategy, "medium")
        
        filtered = [w for w in candidates if w.size == target_size]
        if not filtered:
            filtered = candidates  # フォールバック
        
        # ソースで優先順位
        if sources:
            for source in sources:
                for wl in filtered:
                    if wl.source.lower() == source.lower():
                        return wl
        
        # モード適合性チェック
        for wl in filtered:
            if mode in wl.best_for:
                return wl
        
        # 技術スタック適合性チェック
        if tech_stack:
            for wl in filtered:
                if any(tech in wl.best_for for tech in tech_stack):
                    return wl
        
        # デフォルト: 最初のもの
        return filtered[0] if filtered else None
    
    def list_available(self, purpose: str = None) -> Dict[str, List[WordlistInfo]]:
        """利用可能なワードリスト一覧"""
        if purpose:
            return {purpose: self.wordlists.get(purpose, [])}
        return self.wordlists
    
    def get_summary(self) -> Dict[str, Any]:
        """サマリー情報（AI向け）"""
        summary = {}
        for purpose, wordlists in self.wordlists.items():
            summary[purpose] = {
                "count": len(wordlists),
                "sources": list(set(w.source for w in wordlists)),
                "sizes": {
                    "small": len([w for w in wordlists if w.size == "small"]),
                    "medium": len([w for w in wordlists if w.size == "medium"]),
                    "high": len([w for w in wordlists if w.size == "high"]),
                }
            }
        
        # 学習パラメータ情報
        summary["learned"] = {
            "params_count": len(self.learned_params) if hasattr(self, "learned_params") else 0
        }
        return summary
        
    def learn_params(self, params: List[str]) -> None:
        """
        発見したパラメータ名を学習し、カスタムワードリストに追加する。
        
        Args:
            params: パラメータ名のリスト
        """
        if not hasattr(self, "learned_params"):
            self._init_learning()
            
        new_params = set(params) - self.learned_params
        if not new_params:
            return

        self.learned_params.update(new_params)
        logger.info(f"Learned {len(new_params)} new parameters. Total: {len(self.learned_params)}")
        
        # 永続化 (custom/params.txt)
        custom_dir = self.wordlists_dir / "custom"
        custom_dir.mkdir(parents=True, exist_ok=True)
        params_file = custom_dir / "learned_params.txt"
        
        try:
            with open(params_file, "a", encoding="utf-8") as f:
                for p in new_params:
                    f.write(f"{p}\n")
        except Exception as e:
            logger.error("Failed to save learned params: %s", e)

    def _init_learning(self):
        """学習データの初期ロード"""
        self.learned_params = set()
        custom_dir = self.wordlists_dir / "custom"
        params_file = custom_dir / "learned_params.txt"
        
        if params_file.exists():
            try:
                with open(params_file, encoding="utf-8") as f:
                    self.learned_params = set(line.strip() for line in f if line.strip())
            except Exception as e:
                logger.warning("Failed to load learned params: %s", e)

    def get_fuzzing_wordlist(self, base_wordlist: List[str]) -> List[str]:
        """
        ベースのワードリストに学習済みパラメータをマージして返す
        """
        if not hasattr(self, "learned_params"):
            self._init_learning()
        
        return list(set(base_wordlist) | self.learned_params)


# シングルトン
_manager_instance = None

def get_wordlist_manager() -> WordlistManager:
    """WordlistManagerのシングルトン取得"""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = WordlistManager()
    return _manager_instance
