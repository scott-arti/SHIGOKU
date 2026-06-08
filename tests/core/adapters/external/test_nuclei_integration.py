"""
NucleiAdapter統合テスト

Nuclei統合の動作を検証する包括的なテストスイート。
"""

import asyncio
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch
from dataclasses import dataclass

from src.core.adapters.external.nuclei_adapter import NucleiAdapter
from src.core.adapters.external.base_external_adapter import ToolInput, ToolResult, ToolStatus
from src.core.adapters.external.external_tool_executor import ExternalToolExecutor, ExecutorConfig


class TestNucleiBinaryIntegration:
    """Nucleiバイナリ管理統合テスト"""
    
    @pytest.mark.asyncio
    async def test_ensure_binary_calls_binary_manager(self):
        """_ensure_binaryがBinaryManagerを正しく呼び出すこと"""
        adapter = NucleiAdapter()
        
        # BinaryManager.ensure_binaryをモック
        mock_ensure = AsyncMock(return_value=Path("/mock/nuclei"))
        adapter.binary_manager.ensure_binary = mock_ensure
        
        binary_path = await adapter.binary_manager.ensure_binary("nuclei")
        
        mock_ensure.assert_called_once_with("nuclei")
        assert binary_path == Path("/mock/nuclei")
    
    @pytest.mark.asyncio
    async def test_health_check_uses_binary_manager(self):
        """ヘルスチェックがBinaryManager経由でバイナリを取得すること"""
        adapter = NucleiAdapter()
        
        with patch.object(adapter, '_ensure_binary', return_value=Path("/mock/nuclei")):
            with patch('asyncio.create_subprocess_exec') as mock_exec:
                mock_proc = MagicMock()
                mock_proc.returncode = 0
                mock_proc.communicate = AsyncMock(return_value=(b"[INF] Nuclei 3.1.0", b""))
                mock_exec.return_value = mock_proc
                
                result = await adapter.health_check()
                
                assert result is True


class TestNucleiExecutionFlow:
    """Nuclei実行フロー統合テスト"""
    
    @pytest.mark.asyncio
    async def test_successful_execution_flow(self):
        """正常な実行フローの検証"""
        adapter = NucleiAdapter()
        
        # バイナリ管理をモック
        with patch.object(adapter, '_ensure_binary', return_value=Path("/mock/nuclei")):
            with patch('asyncio.create_subprocess_exec') as mock_exec:
                mock_proc = MagicMock()
                mock_proc.returncode = 0
                
                # Nuclei JSON Lines形式の出力
                mock_stdout = json.dumps({
                    "template-id": "CVE-2023-1234",
                    "info": {
                        "name": "Test Vulnerability",
                        "severity": "high",
                        "description": "Test description",
                        "reference": ["https://example.com"],
                        "tags": ["cve", "test"]
                    },
                    "host": "https://example.com",
                    "matched-at": "https://example.com/vuln",
                    "curl-command": "curl -X GET 'https://example.com/vuln'",
                    "request": "GET /vuln HTTP/1.1",
                    "response": "HTTP/1.1 200 OK"
                })
                mock_proc.communicate = AsyncMock(return_value=(
                    mock_stdout.encode(),
                    b""
                ))
                mock_exec.return_value = mock_proc
                
                result = await adapter.execute(
                    ToolInput(target="https://example.com")
                )
                
                assert result.status == ToolStatus.SUCCESS
                assert result.data is not None
                assert len(result.data) == 1
                assert result.data[0]["template_id"] == "CVE-2023-1234"
                assert result.data[0]["severity"] == "high"
    
    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        """タイムアウト処理の検証"""
        from src.core.adapters.external.external_tool_executor import ExternalToolExecutor, ExecutorConfig
        
        class SlowAdapter:
            tool_name = "slow_nuclei"
            
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


class TestNucleiExecutorIntegration:
    """Nucleiとエグゼキューター統合テスト"""
    
    @pytest.mark.asyncio
    async def test_nuclei_with_global_executor(self):
        """グローバルエグゼキューター経由でのNuclei実行"""
        from src.core.adapters.external.external_tool_executor import get_global_executor
        
        executor = get_global_executor()
        
        # テスト用アダプターを作成
        class TestAdapter:
            tool_name = "test_nuclei"
            
            async def execute(self, input_data):
                return ToolResult(
                    status=ToolStatus.SUCCESS,
                    data=[{"test": "finding"}],
                    execution_time_ms=100
                )
            
            async def run_with_validation(self, input_data):
                return await self.execute(input_data)
        
        adapter = TestAdapter()
        
        result = await executor.execute(
            adapter,
            ToolInput(target="https://example.com")
        )
        
        assert result.status == ToolStatus.SUCCESS
    
    @pytest.mark.asyncio
    async def test_nuclei_batch_execution(self):
        """Nucleiのバッチ実行検証"""
        executor = ExternalToolExecutor(ExecutorConfig(max_concurrent=2))
        
        call_count = 0
        
        class TestBatchAdapter:
            tool_name = "test_batch_nuclei"
            
            async def execute(self, input_data):
                nonlocal call_count
                call_count += 1
                await asyncio.sleep(0.01)
                return ToolResult(
                    status=ToolStatus.SUCCESS,
                    data=[{"target": input_data.target}],
                    execution_time_ms=10
                )
            
            async def run_with_validation(self, input_data):
                return await self.execute(input_data)
        
        adapter = TestBatchAdapter()
        
        tasks = [
            (adapter, ToolInput(target="https://target1.com")),
            (adapter, ToolInput(target="https://target2.com")),
            (adapter, ToolInput(target="https://target3.com")),
        ]
        
        results = await executor.execute_batch(tasks)
        
        assert len(results) == 3
        assert all(r.status == ToolStatus.SUCCESS for r in results)
        assert call_count == 3
        
        stats = executor.get_semaphore_stats()
        assert stats["total_executed"] == 3


class TestNucleiErrorHandling:
    """Nucleiエラーハンドリング統合テスト"""
    
    @pytest.mark.asyncio
    async def test_binary_not_available(self):
        """バイナリが利用できない場合のエラーハンドリング"""
        adapter = NucleiAdapter()
        
        with patch.object(adapter, '_ensure_binary', side_effect=Exception("Binary not found")):
            result = await adapter.run_with_validation(
                ToolInput(target="https://example.com")
            )
            
            assert result.status == ToolStatus.ERROR
            assert "not available" in result.error_message or "Binary not found" in result.error_message
    
    @pytest.mark.asyncio
    async def test_invalid_target_handling(self):
        """無効なターゲットのエラーハンドリング"""
        adapter = NucleiAdapter()
        
        result = await adapter.run_with_validation(
            ToolInput(target="")  # 空のターゲット
        )
        
        assert result.status == ToolStatus.ERROR
    
    @pytest.mark.asyncio
    async def test_process_failure_handling(self):
        """プロセス失敗時のエラーハンドリング"""
        adapter = NucleiAdapter()
        
        with patch.object(adapter, '_ensure_binary', return_value=Path("/mock/nuclei")):
            with patch('asyncio.create_subprocess_exec') as mock_exec:
                mock_proc = MagicMock()
                mock_proc.returncode = 1  # 失敗
                mock_proc.communicate = AsyncMock(return_value=(
                    b"",
                    b"Error: template not found"
                ))
                mock_exec.return_value = mock_proc
                
                result = await adapter.execute(
                    ToolInput(target="https://example.com")
                )
                
                assert result.status == ToolStatus.FAILURE
                assert "Nuclei failed" in result.error_message


class TestNucleiResultParsing:
    """Nuclei結果パース統合テスト"""
    
    def test_parse_valid_json_output(self):
        """有効なJSON Lines出力のパース"""
        adapter = NucleiAdapter()
        
        # Nuclei JSON Lines形式
        json_lines = "\n".join([
            json.dumps({
                "template-id": "CVE-2023-0001",
                "info": {
                    "name": "Critical Vuln",
                    "severity": "critical",
                    "description": "Test critical vuln"
                },
                "host": "https://example.com",
                "matched-at": "https://example.com/admin"
            }),
            json.dumps({
                "template-id": "CVE-2023-0002",
                "info": {
                    "name": "High Vuln",
                    "severity": "high",
                    "description": "Test high vuln"
                },
                "host": "https://example.com",
                "matched-at": "https://example.com/api"
            })
        ])
        
        findings = adapter._parse_results(json_lines)
        
        assert len(findings) == 2
        assert findings[0]["template_id"] == "CVE-2023-0001"
        assert findings[0]["severity"] == "critical"
        assert findings[1]["template_id"] == "CVE-2023-0002"
        assert findings[1]["severity"] == "high"
    
    def test_parse_empty_json_output(self):
        """空のJSON出力のパース"""
        adapter = NucleiAdapter()
        
        findings = adapter._parse_results("")
        
        assert len(findings) == 0
    
    def test_parse_invalid_json(self):
        """無効なJSONのパース"""
        adapter = NucleiAdapter()
        
        # 一部が無効なJSON
        mixed_output = json.dumps({
            "template-id": "VALID-001",
            "info": {"name": "Valid", "severity": "medium"},
            "host": "https://example.com"
        }) + "\n" + "invalid json line"
        
        findings = adapter._parse_results(mixed_output)
        
        # 有効な行だけがパースされる
        assert len(findings) == 1
        assert findings[0]["template_id"] == "VALID-001"


class TestNucleiInputValidation:
    """Nuclei入力検証統合テスト"""
    
    def test_valid_input(self):
        """有効な入力の検証"""
        adapter = NucleiAdapter()
        
        is_valid, error = adapter.validate_inputs(
            ToolInput(target="https://example.com", timeout_seconds=60.0)
        )
        
        assert is_valid is True
        assert error is None
    
    def test_empty_target(self):
        """空ターゲットの検証"""
        adapter = NucleiAdapter()
        
        is_valid, error = adapter.validate_inputs(
            ToolInput(target="", timeout_seconds=60.0)
        )
        
        assert is_valid is False
        assert "required" in error.lower()
    
    def test_invalid_url_format(self):
        """無効なURL形式の検証"""
        adapter = NucleiAdapter()
        
        is_valid, error = adapter.validate_inputs(
            ToolInput(target="not-a-url", timeout_seconds=60.0)
        )
        
        assert is_valid is False
        assert "Invalid URL" in error
    
    def test_invalid_timeout(self):
        """無効なタイムアウト値の検証"""
        adapter = NucleiAdapter()
        
        is_valid, error = adapter.validate_inputs(
            ToolInput(target="https://example.com", timeout_seconds=0)
        )
        
        assert is_valid is False
        assert "positive" in error.lower()
