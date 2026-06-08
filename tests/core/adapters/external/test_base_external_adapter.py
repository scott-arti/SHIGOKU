"""
BaseExternalAdapterのテスト

型安全なインターフェースの動作検証
"""

import pytest
from src.core.adapters.external.base_external_adapter import (
    BaseExternalAdapter,
    ToolInput,
    ToolResult,
    ToolStatus,
)


class MockAdapter(BaseExternalAdapter):
    """テスト用のモックアダプター"""
    
    def __init__(self):
        super().__init__("mock_tool")
        self.executed = False
    
    async def execute(self, input_data: ToolInput) -> ToolResult:
        self.executed = True
        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={"target": input_data.target},
            execution_time_ms=100.0
        )
    
    def validate_inputs(self, input_data: ToolInput):
        if not input_data.target:
            return False, "Target is required"
        return True, None
    
    async def health_check(self) -> bool:
        return True


def test_tool_input_creation():
    """ToolInputの作成テスト"""
    input_data = ToolInput(
        target="https://example.com",
        options={"timeout": 30},
        timeout_seconds=60,
        retry_count=0
    )
    
    assert input_data.target == "https://example.com"
    assert input_data.options == {"timeout": 30}
    assert input_data.timeout_seconds == 60
    assert input_data.retry_count == 0


def test_tool_result_creation():
    """ToolResultの作成テスト"""
    result = ToolResult(
        status=ToolStatus.SUCCESS,
        data={"findings": []},
        execution_time_ms=150.0,
        error_message=None,
        raw_output="test output"
    )
    
    assert result.status == ToolStatus.SUCCESS
    assert result.data == {"findings": []}
    assert result.execution_time_ms == 150.0
    assert result.error_message is None
    assert result.raw_output == "test output"


@pytest.mark.asyncio
async def test_mock_adapter_execute():
    """モックアダプターの実行テスト"""
    adapter = MockAdapter()
    input_data = ToolInput(target="https://example.com/test")
    
    result = await adapter.execute(input_data)
    
    assert adapter.executed is True
    assert result.status == ToolStatus.SUCCESS
    assert result.data["target"] == "https://example.com/test"
    assert result.execution_time_ms == 100.0


@pytest.mark.asyncio
async def test_run_with_validation_success():
    """入力検証付き実行の成功テスト"""
    adapter = MockAdapter()
    input_data = ToolInput(target="https://example.com")
    
    result = await adapter.run_with_validation(input_data)
    
    assert result.status == ToolStatus.SUCCESS


@pytest.mark.asyncio
async def test_run_with_validation_failure():
    """入力検証付き実行の失敗テスト（無効な入力）"""
    adapter = MockAdapter()
    input_data = ToolInput(target="")  # 無効な入力
    
    result = await adapter.run_with_validation(input_data)
    
    assert result.status == ToolStatus.ERROR
    assert "Input validation failed" in result.error_message


@pytest.mark.asyncio
async def test_health_check():
    """ヘルスチェックテスト"""
    adapter = MockAdapter()
    
    result = await adapter.health_check()
    
    assert result is True
