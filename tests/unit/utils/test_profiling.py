import pytest
import asyncio
import time
import logging
from src.core.utils.profiling import timed, timed_async

@pytest.fixture
def caplog_perf(caplog):
    caplog.set_level(logging.WARNING, logger="shigoku.perf")
    return caplog

def test_timed_basic(caplog_perf):
    @timed(threshold_ms=10)
    def fast_func():
        return "ok"
    
    @timed(threshold_ms=10)
    def slow_func():
        time.sleep(0.02)
        return "slow"
    
    assert fast_func() == "ok"
    assert len(caplog_perf.records) == 0
    
    assert slow_func() == "slow"
    assert len(caplog_perf.records) == 1
    assert "SLOW_OP: test_timed_basic.<locals>.slow_func" in caplog_perf.text

@pytest.mark.asyncio
async def test_timed_async_basic(caplog_perf):
    @timed_async(threshold_ms=10)
    async def fast_async():
        await asyncio.sleep(0.001)
        return "ok"
    
    @timed_async(threshold_ms=10)
    async def slow_async():
        await asyncio.sleep(0.02)
        return "slow"
    
    assert await fast_async() == "ok"
    assert len(caplog_perf.records) == 0
    
    assert await slow_async() == "slow"
    assert len(caplog_perf.records) == 1
    assert "SLOW_OP: test_timed_async_basic.<locals>.slow_async" in caplog_perf.text

def test_timed_with_custom_name(caplog_perf):
    @timed(name="CustomOp", threshold_ms=0)
    def named_func():
        return True
    
    named_func()
    assert "SLOW_OP: CustomOp" in caplog_perf.text

def test_timed_exception_safety(caplog_perf):
    @timed(threshold_ms=0)
    def error_func():
        raise ValueError("test error")
    
    with pytest.raises(ValueError, match="test error"):
        error_func()
    
    # Should still log even if exception occurs
    assert "SLOW_OP" in caplog_perf.text
