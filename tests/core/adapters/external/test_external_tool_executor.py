"""
ExternalToolExecutorのテスト

セマフォによる並行度制御の動作検証
"""

import asyncio
import pytest

from src.core.adapters.external.external_tool_executor import (
    ExternalToolExecutor,
    ExecutorConfig,
    get_global_executor,
    reset_global_executor,
)
from src.core.adapters.external.base_external_adapter import (
    BaseExternalAdapter,
    ToolInput,
    ToolResult,
    ToolStatus,
)


class MockSlowAdapter(BaseExternalAdapter):
    """遅延実行するモックアダプター"""
    
    def __init__(self, delay_seconds: float = 0.1):
        super().__init__("mock_slow")
        self.delay_seconds = delay_seconds
        self.executed_count = 0
    
    async def execute(self, input_data: ToolInput) -> ToolResult:
        await asyncio.sleep(self.delay_seconds)
        self.executed_count += 1
        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={"delay": self.delay_seconds},
            execution_time_ms=self.delay_seconds * 1000
        )
    
    def validate_inputs(self, input_data: ToolInput):
        return True, None
    
    async def health_check(self) -> bool:
        return True


class MockErrorAdapter(BaseExternalAdapter):
    """実行時に例外を送出するモックアダプター"""

    def __init__(self):
        super().__init__("mock_error")

    async def execute(self, input_data: ToolInput) -> ToolResult:
        raise RuntimeError("boom")

    def validate_inputs(self, input_data: ToolInput):
        return True, None

    async def health_check(self) -> bool:
        return True


@pytest.mark.asyncio
async def test_semaphore_limits_concurrency():
    """セマフォが並行実行数を制限することを検証"""
    config = ExecutorConfig(max_concurrent=2, enable_semaphore=True)
    executor = ExternalToolExecutor(config)
    
    adapter = MockSlowAdapter(delay_seconds=0.2)
    
    # 3つ同時に実行（最大2つまで並行）
    start_time = asyncio.get_event_loop().time()
    
    results = await asyncio.gather(
        executor.execute(adapter, ToolInput(target="test1")),
        executor.execute(adapter, ToolInput(target="test2")),
        executor.execute(adapter, ToolInput(target="test3")),
    )
    
    elapsed = asyncio.get_event_loop().time() - start_time
    
    # 最大2つ並行なので、3つ目は待機が必要
    # 0.2s x 2（最初の2つ）+ 0.2s（3つ目）= 約0.4s以上
    assert elapsed >= 0.4, f"Expected >= 0.4s but got {elapsed}s"
    
    # 全て成功していること
    assert all(r.status == ToolStatus.SUCCESS for r in results)


@pytest.mark.asyncio
async def test_timeout_control():
    """タイムアウト制御が機能することを検証"""
    config = ExecutorConfig(timeout_seconds=0.1)
    executor = ExternalToolExecutor(config)
    
    # 0.5秒かかるアダプター
    adapter = MockSlowAdapter(delay_seconds=0.5)
    
    result = await executor.execute(adapter, ToolInput(target="test"))
    
    # タイムアウトしていること
    assert result.status == ToolStatus.TIMEOUT
    assert "timeout" in result.error_message.lower()


@pytest.mark.asyncio
async def test_batch_execution():
    """バッチ実行が機能することを検証"""
    config = ExecutorConfig(max_concurrent=3)
    executor = ExternalToolExecutor(config)
    
    adapter = MockSlowAdapter(delay_seconds=0.05)
    
    tasks = [
        (adapter, ToolInput(target=f"test{i}"))
        for i in range(5)
    ]
    
    results = await executor.execute_batch(tasks)
    
    # 5つ全て実行されていること
    assert len(results) == 5
    assert all(r.status == ToolStatus.SUCCESS for r in results)


def test_semaphore_stats():
    """セマフォ統計情報が取得できることを検証"""
    config = ExecutorConfig(max_concurrent=5)
    executor = ExternalToolExecutor(config)
    
    stats = executor.get_semaphore_stats()
    
    assert stats["enabled"] is True
    assert stats["max_concurrent"] == 5


def test_global_executor_singleton():
    """グローバルエグゼキューターがシングルトンであることを検証"""
    reset_global_executor()
    
    executor1 = get_global_executor()
    executor2 = get_global_executor()
    
    # 同一インスタンスであること
    assert executor1 is executor2
    
    # リセット後は別インスタンス
    reset_global_executor()
    executor3 = get_global_executor()
    
    assert executor1 is not executor3


@pytest.mark.asyncio
async def test_no_semaphore_mode():
    """セマフォ無効モードが機能することを検証"""
    config = ExecutorConfig(enable_semaphore=False)
    executor = ExternalToolExecutor(config)
    
    adapter = MockSlowAdapter(delay_seconds=0.05)
    
    result = await executor.execute(adapter, ToolInput(target="test"))
    
    assert result.status == ToolStatus.SUCCESS
    
    # セマフォ無効時の統計
    stats = executor.get_semaphore_stats()
    assert stats["enabled"] is False


@pytest.mark.asyncio
async def test_execute_returns_error_result_on_unhandled_exception():
    """アダプター例外時にERROR結果で返却されることを検証"""
    config = ExecutorConfig(max_concurrent=1)
    executor = ExternalToolExecutor(config)
    adapter = MockErrorAdapter()

    result = await executor.execute(adapter, ToolInput(target="test"))

    assert result.status == ToolStatus.ERROR
    assert "Unhandled execution error" in (result.error_message or "")
