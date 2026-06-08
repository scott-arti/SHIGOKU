import pytest
from dataclasses import dataclass, field
from typing import Dict, Any, List
from src.core.engine.task_queue import DynamicTaskQueue, TaskContext, InjectionRule

@dataclass
class MockTask:
    id: str
    name: str = "Test Task"
    priority: int = 0
    agent_type: str = "test"
    params: Dict[str, Any] = field(default_factory=dict)
    asset_id: str = None

def test_add_pop_priority():
    """優先度順に取り出されるか確認"""
    q = DynamicTaskQueue()
    t1 = MockTask(id="1", priority=10)
    t2 = MockTask(id="2", priority=20)
    t3 = MockTask(id="3", priority=5)

    q.add(t1)
    q.add(t2)
    q.add(t3)

    assert q.pop().id == "2" # Priority 20
    assert q.pop().id == "1" # Priority 10
    assert q.pop().id == "3" # Priority 5
    assert q.pop() is None

def test_stability():
    """同優先度のタスクがFIFOで取り出されるか確認 (安定性)"""
    q = DynamicTaskQueue()
    t1 = MockTask(id="1", priority=10)
    t2 = MockTask(id="2", priority=10)
    t3 = MockTask(id="3", priority=10)

    q.add(t1)
    q.add(t2)
    q.add(t3)

    assert q.pop().id == "1"
    assert q.pop().id == "2"
    assert q.pop().id == "3"

def test_boost_priority():
    """優先度ブーストが正しく反映され、ソート順が変わるか確認"""
    q = DynamicTaskQueue()
    t1 = MockTask(id="1", priority=10)
    t2 = MockTask(id="2", priority=20)

    q.add(t1)
    q.add(t2)

    # Boost t1 by +30 => 40
    count = q.boost_by_delta(lambda t: t.id == "1", 30)
    assert count == 1
    assert t1.priority == 40

    # Should pop t1 first now (40 > 20)
    assert q.pop().id == "1"
    assert q.pop().id == "2"

def test_remove_by_id():
    """ID指定削除とLazy removalの確認"""
    q = DynamicTaskQueue()
    t1 = MockTask(id="1", priority=10)
    q.add(t1)
    
    assert q.remove_by_id("1") is True
    assert q.pop() is None
    # 既に削除済み
    assert q.remove_by_id("1") is False

def test_task_context_merge():
    """TaskContextのマージで重複排除と順序保持がされるか確認"""
    c1 = TaskContext(discovered_endpoints=["/a", "/b"])
    c2 = TaskContext(discovered_endpoints=["/b", "/c"])
    
    c1.merge(c2)
    
    # a, b, b, c -> a, b, c となるべき
    assert len(c1.discovered_endpoints) == 3
    assert c1.discovered_endpoints == ["/a", "/b", "/c"] # Order preserved

def test_remove_tasks_for_assets():
    """資産IDに関連するタスクの削除確認"""
    q = DynamicTaskQueue()
    t1 = MockTask(id="t1", asset_id="asset1", priority=10)
    t2 = MockTask(id="t2", asset_id="asset2", priority=20)
    t3 = MockTask(id="t3", params={"target": "http://asset1/foo"}, priority=30)
    
    q.add(t1)
    q.add(t2)
    q.add(t3)
    
    removed = q.remove_tasks_for_assets(["asset1"])
    assert removed == 2 # t1, t3
    
    remaining = q.pop()
    assert remaining.id == "t2"
    assert q.pop() is None

def test_inject_context_priority_boost():
    """InjectContextによる優先度変更"""
    
    # ルール定義: contextに 'target' があれば boost +100
    rule = InjectionRule(
        name="test_boost",
        trigger=lambda ctx: 'target' in ctx.discovered_endpoints,
        target_filter=lambda t: True,
        boost_priority=100
    )
    
    q = DynamicTaskQueue(injection_rules=[rule])
    t1 = MockTask(id="1", priority=10)
    q.add(t1)
    
    ctx = TaskContext(discovered_endpoints=['target'])
    affected = q.inject_context(ctx)
    
    assert affected == 1
    assert t1.priority == 100
    
    # Priority update check
    t2 = MockTask(id="2", priority=50)
    q.add(t2)
    
    # t1 (100) > t2 (50)
    assert q.pop().id == "1"

def test_performance_simulation():
    """大量タスクでの基本動作確認"""
    q = DynamicTaskQueue()
    # Add 1000 tasks
    for i in range(1000):
        q.add(MockTask(id=str(i), priority=i))
    
    assert len(q) == 1000
    
    # Pop 500
    # Priority is i, so higher i pops first
    last_pri = 1001
    for _ in range(500):
        t = q.pop()
        assert t.priority < last_pri
        last_pri = t.priority
        
    assert len(q) == 500
