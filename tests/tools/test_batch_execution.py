import os
from unittest.mock import patch
from src.core.utils.batch_utils import create_batch_file
from src.tools.custom.httpx import HttpxTool
from src.tools.custom.nuclei import NucleiTool
from src.core.security.ethics_guard import ActionResult

def test_batch_file_creation():
    """バッチファイルが正しく作成・削除されるかテスト"""
    targets = ["example.com", "test.com"]
    
    with patch("src.core.utils.batch_utils.get_ethics_guard") as mock_guard:
        # すべて許可
        mock_guard.return_value.check_action.return_value = (ActionResult.ALLOWED, "OK")
        
        with create_batch_file(targets) as path:
            assert path is not None
            assert os.path.exists(path)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().splitlines()
                assert content == targets
        
        # コンテキストを抜けた後にファイルが消えていること
        assert not os.path.exists(path)

def test_batch_file_with_blocking():
    """一部がブロックされた場合に許可されたものだけが含まれるかテスト"""
    targets = ["allowed.com", "blocked.com"]
    
    def side_effect(_action_type, target, params=None):
        if target == "allowed.com":
            return ActionResult.ALLOWED, "OK"
        return ActionResult.BLOCKED, "NO"

    with patch("src.core.utils.batch_utils.get_ethics_guard") as mock_guard:
        mock_guard.return_value.check_action.side_effect = side_effect
        
        with create_batch_file(targets) as path:
            assert path is not None
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().splitlines()
                assert content == ["allowed.com"]

@patch("src.tools.custom.httpx.safe_run")
def test_httpx_batch_execution(mock_safe_run):
    """HttpxToolがリストを受け取った時にバッチ実行されるかテスト"""
    mock_safe_run.return_value.stdout = '{"url": "http://a.com"}\n{"url": "http://b.com"}'
    mock_safe_run.return_value.returncode = 0
    
    tool = HttpxTool()
    targets = ["a.com", "b.com"]
    
    with patch("src.tools.custom.httpx.create_batch_file") as mock_create:
        mock_create.return_value.__enter__.return_value = "/tmp/fake_batch.txt"
        
        _result = tool.run(target=targets)
        
        # safe_run に -l オプションが渡されているか
        args, _kwargs = mock_safe_run.call_args
        cmd = args[0]
        assert "-l" in cmd
        assert "/tmp/fake_batch.txt" in cmd
        
@patch("src.tools.custom.nuclei.safe_run")
def test_nuclei_batch_execution(mock_safe_run):
    """NucleiToolがリストを受け取った時にバッチ実行されるかテスト"""
    mock_safe_run.return_value.stdout = '{"template-id": "test"}'
    mock_safe_run.return_value.returncode = 0
    
    tool = NucleiTool()
    targets = ["a.com", "b.com"]
    
    with patch("src.tools.custom.nuclei.create_batch_file") as mock_create:
        mock_create.return_value.__enter__.return_value = "/tmp/fake_nuclei_batch.txt"
        
        _result = tool.run(target=targets)
        
        args, _kwargs = mock_safe_run.call_args
        cmd = args[0]
        assert "-l" in cmd
        assert "/tmp/fake_nuclei_batch.txt" in cmd
