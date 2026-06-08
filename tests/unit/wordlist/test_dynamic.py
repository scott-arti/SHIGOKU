"""
WordlistManager 動的学習機能テスト

パラメータ学習と永続化ロジックの検証
"""

import pytest
from pathlib import Path
from src.core.wordlist.wordlist_manager import WordlistManager

class TestDynamicWordlist:
    
    @pytest.fixture
    def manager(self, tmp_path):
        # テスト用ディレクトリを使用
        return WordlistManager(wordlists_dir=tmp_path)
    
    def test_learn_params(self, manager):
        """パラメータ学習の基本動作"""
        new_params = ["user_id", "token", "debug"]
        
        manager.learn_params(new_params)
        
        # メモリ内反映確認
        assert "user_id" in manager.learned_params
        assert len(manager.learned_params) == 3
        
        # 永続化確認
        learned_file = manager.wordlists_dir / "custom" / "learned_params.txt"
        assert learned_file.exists()
        
        content = learned_file.read_text(encoding="utf-8")
        assert "user_id" in content
        assert "token" in content

    def test_learn_duplicates(self, manager):
        """重複排除"""
        manager.learn_params(["p1", "p2"])
        manager.learn_params(["p2", "p3"])
        
        assert len(manager.learned_params) == 3
        
    def test_init_loading(self, tmp_path):
        """初期化時のロード"""
        # 事前にファイル作成
        custom_dir = tmp_path / "custom"
        custom_dir.mkdir()
        (custom_dir / "learned_params.txt").write_text("loaded_param\n", encoding="utf-8")
        
        # 新しいマネージャーでロード
        manager = WordlistManager(wordlists_dir=tmp_path)
        # 属性へのアクセス時にロードされる（または明示的ロード）
        # get_fuzzing_wordlist などを呼ぶとロードされる設計
        
        combined = manager.get_fuzzing_wordlist(["base"])
        assert "loaded_param" in combined
        assert "loaded_param" in manager.learned_params

    def test_fuzzing_wordlist_merge(self, manager):
        """Fuzzingリストへのマージ"""
        manager.learn_params(["learned"])
        
        base = ["standard1", "standard2"]
        merged = manager.get_fuzzing_wordlist(base)
        
        assert len(merged) == 3
        assert "learned" in merged
        assert "standard1" in merged
