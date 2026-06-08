"""
FfufTool Wordlist Path Resolver tests
"""
import pytest
from pathlib import Path
from unittest.mock import patch
from src.tools.custom.ffuf import FfufTool


def test_wordlist_path_resolver_existing_path(tmp_path):
    """実在するパスをそのまま返すテスト"""
    tool = FfufTool()
    
    # 一時ワードリストファイルを作成
    wordlist = tmp_path / "test_wordlist.txt"
    wordlist.write_text("test\nword\nlist\n")
    
    resolved = tool._resolve_wordlist_path(str(wordlist))
    
    assert resolved == str(wordlist)


def test_wordlist_path_resolver_docker_mount():
    """Dockerマウントパスへのフォールバックテスト"""
    tool = FfufTool()
    
    def mock_exists(self):
        # /wordlists/common.txt が存在する想定
        return str(self) == "/wordlists/common.txt"
    
    with patch.object(Path, "exists", mock_exists):
        resolved = tool._resolve_wordlist_path("/usr/share/wordlists/common.txt")
        
        assert resolved == "/wordlists/common.txt"


def test_wordlist_path_resolver_not_found():
    """見つからない場合は元のパスを返すテスト"""
    tool = FfufTool()
    
    with patch.object(Path, "exists", return_value=False):
        original = "/nonexistent/path/to/wordlist.txt"
        resolved = tool._resolve_wordlist_path(original)
        
        assert resolved == original
