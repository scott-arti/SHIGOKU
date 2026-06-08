import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock
from src.core.agents.swarm.base import SwarmManager, Specialist, Task
from src.core.models.swarm import SwarmResult

class MockSpecialist(Specialist):
    def __init__(self, name, delay=0.1, config=None):
        super().__init__(config)
        self.name = name
        self.delay = delay
        self.call_count = 0
        self.active_count = 0
        self.max_active = 0

    async def execute(self, task: Task):
        self.call_count += 1
        self.active_count += 1
        self.max_active = max(self.max_active, self.active_count)
        
        await asyncio.sleep(self.delay)
        
        self.active_count -= 1
        return []

class ConcreteSwarmManager(SwarmManager):
    def get_specialists(self, tags):
        return self._specialists

@pytest.mark.asyncio
async def test_swarm_manager_semaphore_sequential():
    """単一の dispatch 内では Specialist は順次実行されるが、Semaphore で保護されていることを確認"""
    config = {"max_concurrent_tasks": 1}
    manager = ConcreteSwarmManager(config)
    
    spec1 = MockSpecialist("spec1", delay=0.1)
    spec2 = MockSpecialist("spec2", delay=0.1)
    manager.register_specialists([spec1, spec2])
    
    task = Task(id="test", name="test", target="http://target", tags=["test"])
    
    # dispatch 自体は内部で for ループなので順次実行
    result = await manager.dispatch(task)
    
    assert result.status == "success"
    assert spec1.call_count == 1
    assert spec2.call_count == 1
    assert spec1.max_active == 1
    assert spec2.max_active == 1

@pytest.mark.asyncio
async def test_swarm_manager_semaphore_concurrent_dispatches():
    """複数の dispatch が並行して呼ばれた場合、Semaphore によって同時実行が制限されることを確認"""
    # 同時実行数を 2 に制限
    config = {"max_concurrent_tasks": 2}
    manager = ConcreteSwarmManager(config)
    
    # 3つの Specialist を持つ
    # 各 Specialist は 0.2秒かかる
    spec1 = MockSpecialist("spec1", delay=0.2)
    manager.register_specialist(spec1)
    
    task = Task(id="test", name="test", target="http://target", tags=["test"])
    
    # 5つの dispatch を並行して開始
    # 各 dispatch は spec1 を1回実行する
    start_time = asyncio.get_event_loop().time()
    results = await asyncio.gather(*[manager.dispatch(task) for _ in range(5)])
    end_time = asyncio.get_event_loop().time()
    
    # 各実行 0.2s * 5回 = 1.0s (並行度1の場合)
    # 並行度 2 の場合: 
    # Batch 1: 0.2s (2 tasks)
    # Batch 2: 0.2s (2 tasks)
    # Batch 3: 0.2s (1 task)
    # 合計 0.6s 前後になるはず
    
    duration = end_time - start_time
    assert 0.5 <= duration <= 0.8  # 並列度2なら 0.6s 前後
    assert spec1.call_count == 5
    assert spec1.max_active <= 2  # 同時最大実行数が 2 以下であることを検証
