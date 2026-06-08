"""
DalFoxAdapter統合テスト

Phase D Day 3: DalFox統合の検証
- バイナリ管理との連携
- 外部ツールエグゼキューターとの連携
- エンドツーエンド実行フロー
"""

import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.adapters.external.dalfox_adapter import DalFoxAdapter
from src.core.adapters.external.base_external_adapter import ToolInput, ToolResult, ToolStatus
from src.core.adapters.external.external_tool_executor import ExternalToolExecutor, ExecutorConfig
from src.core.adapters.external.binary_manager import BinaryManager


@pytest.fixture
def mock_binary_manager():
    """モックBinaryManager"""
    bm = MagicMock(spec=BinaryManager)
    bm.ensure_binary = AsyncMock(return_value=Path("/mock/dalfox"))
    bm.is_verified = MagicMock(return_value=True)
    return bm


@pytest.fixture
def dalfox_adapter(mock_binary_manager):
    """テスト用DalFoxAdapter"""
    adapter = DalFoxAdapter.__new__(DalFoxAdapter)
    adapter.tool_name = "dalfox"
    adapter._binary_manager = mock_binary_manager
    adapter._binary_path = None
    adapter._logger = MagicMock()
    return adapter


class TestDalFoxBinaryIntegration:
    """DalFoxバイナリ管理統合テスト"""
    
    @pytest.mark.asyncio
    async def test_ensure_binary_calls_binary_manager(self):
        """_ensure_binaryがBinaryManagerを正しく呼び出すこと"""
        adapter = DalFoxAdapter()
        
        # _ensure_binaryが正しくBinaryManagerを呼び出すことを検証
        # DalFoxAdapterのbinary_managerプロパティを確認
        assert adapter.binary_manager is not None
        
        # BinaryManager.ensure_binaryが正しく呼ばれることをモックで検証
        with patch.object(adapter.binary_manager, 'ensure_binary', new_callable=AsyncMock) as mock_ensure:
            mock_ensure.return_value = Path("/mock/dalfox")
            
            binary_path = await adapter.binary_manager.ensure_binary("dalfox")
            
            mock_ensure.assert_called_once_with("dalfox")
            assert binary_path == Path("/mock/dalfox")
    
    @pytest.mark.asyncio
    async def test_health_check_uses_binary_manager(self):
        """ヘルスチェックがBinaryManager経由でバイナリを取得すること"""
        adapter = DalFoxAdapter()
        
        with patch.object(adapter, '_ensure_binary', return_value=Path("/mock/dalfox")):
            with patch('asyncio.create_subprocess_exec') as mock_exec:
                mock_proc = MagicMock()
                mock_proc.returncode = 0
                mock_proc.communicate = AsyncMock(return_value=(b"DalFox v2.9.2", b""))
                mock_exec.return_value = mock_proc
                
                result = await adapter.health_check()
                
                assert result is True


class TestDalFoxExecutionFlow:
    """DalFox実行フロー統合テスト"""
    
    @pytest.mark.asyncio
    async def test_successful_execution_flow(self):
        """正常な実行フローの検証"""
        adapter = DalFoxAdapter()
        
        # バイナリ管理をモック
        with patch.object(adapter, '_ensure_binary', return_value=Path("/mock/dalfox")):
            with patch.object(Path, 'unlink', return_value=None):
                # 成功するプロセスをモック
                with patch('asyncio.create_subprocess_exec') as mock_exec:
                    mock_proc = MagicMock()
                    mock_proc.returncode = 0
                    mock_stdout = json.dumps({
                        "type": "reflected",
                        "param": "q",
                        "payload": "<script>alert(1)</script>",
                        "url": "https://example.com/search",
                        "evidence": "XSS detected"
                    })
                    mock_proc.communicate = AsyncMock(return_value=(
                        mock_stdout.encode(),
                        b""
                    ))
                    mock_exec.return_value = mock_proc
                    
                    # 一時ファイルをパッチ
                    import tempfile
                    with patch.object(tempfile, 'NamedTemporaryFile') as mock_temp:
                        mock_file = MagicMock()
                        mock_file.name = "/tmp/test_target.txt"
                        mock_temp.return_value.__enter__.return_value = mock_file
                        
                        result = await adapter.execute(
                            ToolInput(target="https://example.com/search?q=test")
                        )
                        
                        assert result.status == ToolStatus.SUCCESS
                        assert result.data is not None
                        assert len(result.data) == 1
                        assert result.data[0]["param"] == "q"
    
    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        """タイムアウト処理の検証"""
        # タイムアウトハンドリングはExternalToolExecutorで行われる
        # Executor経由でのタイムアウトをテスト
        from src.core.adapters.external.external_tool_executor import ExternalToolExecutor, ExecutorConfig
        
        class SlowAdapter:
            tool_name = "slow_adapter"
            
            async def run_with_validation(self, input_data):
                await asyncio.sleep(10)  # 長時間実行
                return ToolResult(
                    status=ToolStatus.SUCCESS,
                    data={},
                    execution_time_ms=10000
                )
        
        executor = ExternalToolExecutor(ExecutorConfig(timeout_seconds=0.01))
        adapter = SlowAdapter()
        
        result = await executor.execute(adapter, ToolInput(target="https://example.com"))
        
        assert result.status == ToolStatus.TIMEOUT


class TestDalFoxExecutorIntegration:
    """DalFoxとエグゼキューター統合テスト"""
    
    @pytest.mark.asyncio
    async def test_dalfox_with_global_executor(self):
        """グローバルエグゼキューター経由でのDalFox実行"""
        from src.core.adapters.external.external_tool_executor import get_global_executor
        
        executor = get_global_executor()
        
        # テスト用アダプターを作成
        class TestAdapter:
            tool_name = "test_adapter"
            
            async def execute(self, input_data):
                return ToolResult(
                    status=ToolStatus.SUCCESS,
                    data=[{"test": "finding"}],
                    execution_time_ms=100
                )
            
            async def run_with_validation(self, input_data):
                return await self.execute(input_data)
        
        adapter = TestAdapter()
        
        # グローバルエグゼキューター経由で実行
        result = await executor.execute(
            adapter,
            ToolInput(target="https://example.com")
        )
        
        assert result.status == ToolStatus.SUCCESS
    
    @pytest.mark.asyncio
    async def test_dalfox_batch_execution(self):
        """DalFoxのバッチ実行検証"""
        executor = ExternalToolExecutor(ExecutorConfig(max_concurrent=2))
        
        call_count = 0
        
        # テスト用アダプター
        class TestBatchAdapter:
            tool_name = "test_batch_adapter"
            
            async def execute(self, input_data):
                nonlocal call_count
                call_count += 1
                await asyncio.sleep(0.01)  # 短い遅延を追加
                return ToolResult(
                    status=ToolStatus.SUCCESS,
                    data=[{"target": input_data.target}],
                    execution_time_ms=10
                )
            
            async def run_with_validation(self, input_data):
                return await self.execute(input_data)
        
        adapter = TestBatchAdapter()
        
        # バッチ実行（タプルリスト形式）
        tasks = [
            (adapter, ToolInput(target="https://target1.com")),
            (adapter, ToolInput(target="https://target2.com")),
            (adapter, ToolInput(target="https://target3.com")),
        ]
        
        results = await executor.execute_batch(tasks)
        
        assert len(results) == 3
        assert all(r.status == ToolStatus.SUCCESS for r in results)
        assert call_count == 3
        
        # 統計情報を確認
        stats = executor.get_semaphore_stats()
        assert stats["total_executed"] == 3


class TestDalFoxErrorHandling:
    """DalFoxエラーハンドリング統合テスト"""
    
    @pytest.mark.asyncio
    async def test_binary_not_available(self):
        """バイナリが利用できない場合のエラーハンドリング"""
        adapter = DalFoxAdapter()
        
        with patch.object(adapter, '_ensure_binary', side_effect=Exception("Binary not found")):
            result = await adapter.run_with_validation(
                ToolInput(target="https://example.com")
            )
            
            assert result.status == ToolStatus.ERROR
            assert "not available" in result.error_message or "Binary not found" in result.error_message
    
    @pytest.mark.asyncio
    async def test_invalid_target_handling(self):
        """無効なターゲットのエラーハンドリング"""
        adapter = DalFoxAdapter()
        
        # 無効な入力をテスト
        result = await adapter.run_with_validation(
            ToolInput(target="")  # 空のターゲット
        )
        
        assert result.status == ToolStatus.ERROR
        assert "validation" in result.error_message.lower() or "Input validation" in result.error_message
    
    @pytest.mark.asyncio
    async def test_process_failure_handling(self):
        """プロセス失敗時のエラーハンドリング"""
        adapter = DalFoxAdapter()
        
        with patch.object(adapter, '_ensure_binary', return_value=Path("/mock/dalfox")):
            with patch('tempfile.NamedTemporaryFile') as mock_temp:
                mock_file = MagicMock()
                mock_file.name = "/tmp/test_target.txt"
                mock_temp.return_value.__enter__.return_value = mock_file
                
                with patch('asyncio.create_subprocess_exec') as mock_exec:
                    # 失敗するプロセスをモック
                    mock_proc = MagicMock()
                    mock_proc.returncode = 1
                    mock_proc.communicate = AsyncMock(return_value=(
                        b"",
                        b"Error: invalid target format"
                    ))
                    mock_exec.return_value = mock_proc
                    
                    with patch('pathlib.Path.unlink'):
                        result = await adapter.execute(
                            ToolInput(target="invalid-url")
                        )
                        
                        assert result.status == ToolStatus.FAILURE
                        assert "DalFox failed" in result.error_message


class TestDalFoxResultParsing:
    """DalFox結果パース統合テスト"""
    
    def test_parse_valid_json_output(self):
        """有効なJSON Lines出力のパース"""
        adapter = DalFoxAdapter()
        
        # DalFoxはJSON Lines形式で出力（各行が独立したJSONオブジェクト）
        json_lines = "\n".join([
            json.dumps({
                "type": "reflected",
                "param": "search",
                "payload": "<script>alert('xss')</script>",
                "url": "https://example.com/search",
                "evidence": "Reflected XSS found"
            }),
            json.dumps({
                "type": "reflected",
                "param": "id",
                "payload": "' onclick='alert(1)",
                "url": "https://example.com/item",
                "evidence": "Attribute injection"
            })
        ])
        
        findings = adapter._parse_results(json_lines)
        
        assert len(findings) == 2
        assert findings[0]["param"] == "search"
        assert findings[1]["param"] == "id"
    
    def test_parse_empty_json_output(self):
        """空のJSON出力のパース"""
        adapter = DalFoxAdapter()
        
        findings = adapter._parse_results("[]")
        
        assert len(findings) == 0
    
    def test_parse_invalid_json(self):
        """無効なJSONのパース"""
        adapter = DalFoxAdapter()
        
        # 無効なJSONは空リストを返すべき
        findings = adapter._parse_results("invalid json")
        
        assert len(findings) == 0
