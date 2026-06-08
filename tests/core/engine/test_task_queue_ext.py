import pytest
from dataclasses import dataclass, field
from typing import Dict, Any
from src.core.engine.task_queue import DynamicTaskQueue

@dataclass
class MockTask:
    id: str
    name: str
    agent_type: str
    priority: int = 0
    params: Dict[str, Any] = field(default_factory=dict)
    asset_id: str = None

def test_remove_tasks_for_assets():
    queue = DynamicTaskQueue()
    t1 = MockTask(id="t1", name="Task 1", agent_type="discovery", asset_id="asset1")
    t2 = MockTask(id="t2", name="Task 2", agent_type="discovery", asset_id="asset2")
    t3 = MockTask(id="t3", name="Task 3", agent_type="injection", params={"target": "http://asset1/path"})
    
    queue.add(t1)
    queue.add(t2)
    queue.add(t3)
    
    assert len(queue) == 3
    
    # asset1 に関連するタスクを削除 (t1 と t3)
    removed = queue.remove_tasks_for_assets(["asset1"])
    assert removed == 2
    assert len(queue) == 1
    assert queue.pop().id == "t2"

def test_boost_priority_for_assets():
    queue = DynamicTaskQueue()
    t1 = MockTask(id="t1", name="Task 1", agent_type="discovery", asset_id="asset1", priority=10)
    t2 = MockTask(id="t2", name="Task 2", agent_type="discovery", asset_id="asset2", priority=10)
    
    queue.add(t1)
    queue.add(t2)
    
    # asset1 の優先度をブースト
    queue.boost_priority_for_assets(["asset1"], 50)
    
    highest = queue.pop()
    assert highest.id == "t1"
    assert highest.priority == 60
    
    next_task = queue.pop()
    assert next_task.id == "t2"
    assert next_task.priority == 10

def test_get_tasks_summary():
    queue = DynamicTaskQueue()
    queue.add(MockTask(id="t1", name="Discovery 1", agent_type="discovery", priority=100))
    queue.add(MockTask(id="t2", name="Discovery 2", agent_type="discovery", priority=50))
    queue.add(MockTask(id="t3", name="Injection 1", agent_type="injection", priority=10))
    
    summary = queue.get_tasks_summary()
    assert "Total tasks: 3" in summary
    assert "discovery: 2" in summary
    assert "injection: 1" in summary
    assert "Discovery 1" in summary
