"""
DynamicTaskQueue ユニットテスト

タスクキューの追加・取り出し・コンテキスト注入をテスト
"""

import pytest
from dataclasses import dataclass, field
from typing import Dict, Any, Optional

from src.core.engine.task_queue import (
    TaskContext,
    InjectionRule,
    DynamicTaskQueue,
    create_dynamic_queue,
)


@dataclass
class MockTask:
    """テスト用タスククラス"""
    id: str
    name: str
    priority: int = 0
    agent_type: str = "general"
    params: Dict[str, Any] = field(default_factory=dict)


class TestTaskContext:
    """TaskContext のテスト"""
    
    def test_empty_context(self):
        """空のコンテキスト判定"""
        ctx = TaskContext()
        assert ctx.is_empty() is True
    
    def test_non_empty_context(self):
        """非空のコンテキスト判定"""
        ctx = TaskContext(auth_tokens={"jwt": "eyJ..."})
        assert ctx.is_empty() is False
    
    def test_merge_contexts(self):
        """コンテキストのマージ"""
        ctx1 = TaskContext(
            discovered_endpoints=["https://a.com"],
            auth_tokens={"jwt": "token1"},
        )
        ctx2 = TaskContext(
            discovered_endpoints=["https://b.com"],
            auth_tokens={"bearer": "token2"},
            critical_findings=["admin_panel"],
        )
        
        ctx1.merge(ctx2)
        
        assert "https://a.com" in ctx1.discovered_endpoints
        assert "https://b.com" in ctx1.discovered_endpoints
        assert ctx1.auth_tokens["jwt"] == "token1"
        assert ctx1.auth_tokens["bearer"] == "token2"
        assert "admin_panel" in ctx1.critical_findings
    
    def test_merge_no_duplicates(self):
        """マージ時の重複排除"""
        ctx1 = TaskContext(discovered_endpoints=["https://a.com"])
        ctx2 = TaskContext(discovered_endpoints=["https://a.com"])
        
        ctx1.merge(ctx2)
        
        assert len(ctx1.discovered_endpoints) == 1
    
    def test_to_dict(self):
        """辞書変換"""
        ctx = TaskContext(auth_tokens={"jwt": "abc"})
        d = ctx.to_dict()
        
        assert d["auth_tokens"] == {"jwt": "abc"}


class TestDynamicTaskQueue:
    """DynamicTaskQueue のテスト"""
    
    @pytest.fixture
    def queue(self) -> DynamicTaskQueue:
        return DynamicTaskQueue()
    
    # ==========================================
    # 基本操作
    # ==========================================
    
    def test_add_and_pop(self, queue: DynamicTaskQueue):
        """追加と取り出し"""
        task = MockTask(id="1", name="Test")
        queue.add(task)
        
        assert len(queue) == 1
        
        popped = queue.pop()
        assert popped.id == "1"
        assert len(queue) == 0
    
    def test_priority_ordering(self, queue: DynamicTaskQueue):
        """優先度順の取り出し"""
        queue.add(MockTask(id="1", name="Low", priority=10))
        queue.add(MockTask(id="2", name="High", priority=100))
        queue.add(MockTask(id="3", name="Medium", priority=50))
        
        assert queue.pop().id == "2"  # 優先度100が最初
        assert queue.pop().id == "3"  # 優先度50が次
        assert queue.pop().id == "1"  # 優先度10が最後
    
    def test_is_empty(self, queue: DynamicTaskQueue):
        """空判定"""
        assert queue.is_empty() is True
        
        queue.add(MockTask(id="1", name="Test"))
        assert queue.is_empty() is False
        
        queue.pop()
        assert queue.is_empty() is True
    
    def test_peek(self, queue: DynamicTaskQueue):
        """参照（取り出さない）"""
        queue.add(MockTask(id="1", name="Test"))
        
        assert queue.peek().id == "1"
        assert len(queue) == 1  # まだキューに残っている
    
    def test_add_batch(self, queue: DynamicTaskQueue):
        """一括追加"""
        tasks = [
            MockTask(id="1", name="A", priority=10),
            MockTask(id="2", name="B", priority=20),
        ]
        
        count = queue.add_batch(tasks, source="test")
        
        assert count == 2
        assert len(queue) == 2
    
    def test_bool_compatibility(self, queue: DynamicTaskQueue):
        """既存 `if self.task_queue:` との互換性"""
        assert bool(queue) is False
        
        queue.add(MockTask(id="1", name="Test"))
        assert bool(queue) is True
    
    # ==========================================
    # コンテキスト注入
    # ==========================================
    
    def test_inject_auth_tokens(self, queue: DynamicTaskQueue):
        """JWT発見時にAuthタスクに注入"""
        # Authタスクを追加
        auth_task = MockTask(id="1", name="Auth Check", agent_type="auth")
        queue.add(auth_task)
        
        # JWT発見をシミュレート
        context = TaskContext(auth_tokens={"jwt": "eyJ.test.token"})
        
        affected = queue.inject_context(context)
        
        assert affected >= 1
        assert "discovered_tokens" in auth_task.params
        assert auth_task.params["discovered_tokens"]["jwt"] == "eyJ.test.token"
    
    def test_inject_admin_priority_boost(self, queue: DynamicTaskQueue):
        """Admin発見時に優先度ブースト"""
        auth_task = MockTask(id="1", name="Auth Check", agent_type="auth", priority=50)
        queue.add(auth_task)
        
        context = TaskContext(critical_findings=["admin_panel"])
        
        queue.inject_context(context)
        
        # 優先度が999にブーストされている
        assert auth_task.priority == 999
    
    def test_inject_no_effect_empty_context(self, queue: DynamicTaskQueue):
        """空コンテキストでは影響なし"""
        task = MockTask(id="1", name="Test")
        queue.add(task)
        
        affected = queue.inject_context(TaskContext())
        
        assert affected == 0
    
    # ==========================================
    # 優先度操作
    # ==========================================
    
    def test_boost_priority(self, queue: DynamicTaskQueue):
        """条件付き優先度変更"""
        queue.add(MockTask(id="1", name="Auth Task", agent_type="auth", priority=10))
        queue.add(MockTask(id="2", name="Scan Task", agent_type="scan", priority=10))
        
        affected = queue.boost_priority(
            condition=lambda t: t.agent_type == "auth",
            new_priority=100,
        )
        
        assert affected == 1
        assert queue.get_by_id("1").priority == 100
        assert queue.get_by_id("2").priority == 10
    
    def test_boost_by_delta(self, queue: DynamicTaskQueue):
        """優先度増減"""
        queue.add(MockTask(id="1", name="Test", priority=50))
        
        queue.boost_by_delta(condition=lambda t: True, delta=20)
        
        assert queue.get_by_id("1").priority == 70
    
    def test_priority_reorder_after_boost(self, queue: DynamicTaskQueue):
        """優先度変更後の再ソート"""
        queue.add(MockTask(id="1", name="Low", priority=10))
        queue.add(MockTask(id="2", name="High", priority=100))
        
        # Low の優先度をブースト
        queue.boost_priority(
            condition=lambda t: t.id == "1",
            new_priority=999,
        )
        
        # Low が先頭に来る
        assert queue.pop().id == "1"
    
    # ==========================================
    # ユーティリティ
    # ==========================================
    
    def test_get_by_id(self, queue: DynamicTaskQueue):
        """ID でタスク取得"""
        queue.add(MockTask(id="test123", name="Test"))
        
        task = queue.get_by_id("test123")
        assert task is not None
        assert task.name == "Test"
    
    def test_remove_by_id(self, queue: DynamicTaskQueue):
        """ID でタスク削除"""
        queue.add(MockTask(id="1", name="A"))
        queue.add(MockTask(id="2", name="B"))
        
        assert queue.remove_by_id("1") is True
        assert len(queue) == 1
        assert queue.get_by_id("1") is None
    
    def test_clear(self, queue: DynamicTaskQueue):
        """キュークリア"""
        queue.add(MockTask(id="1", name="A"))
        queue.add(MockTask(id="2", name="B"))
        
        queue.clear()
        
        assert len(queue) == 0
        assert queue.is_empty() is True


class TestInjectionRule:
    """InjectionRule のテスト"""
    
    def test_applies_to(self):
        """ルール適用判定"""
        rule = InjectionRule(
            name="test",
            trigger=lambda ctx: ctx.has_auth_tokens(),
            target_filter=lambda t: t.agent_type == "auth",
        )
        
        task = MockTask(id="1", name="Auth", agent_type="auth")
        context = TaskContext(auth_tokens={"jwt": "abc"})
        
        assert rule.applies_to(task, context) is True
    
    def test_does_not_apply_wrong_task(self):
        """タスクがマッチしない場合"""
        rule = InjectionRule(
            name="test",
            trigger=lambda ctx: ctx.has_auth_tokens(),
            target_filter=lambda t: t.agent_type == "auth",
        )
        
        task = MockTask(id="1", name="Scan", agent_type="scan")
        context = TaskContext(auth_tokens={"jwt": "abc"})
        
        assert rule.applies_to(task, context) is False
    
    def test_does_not_apply_wrong_context(self):
        """コンテキストがマッチしない場合"""
        rule = InjectionRule(
            name="test",
            trigger=lambda ctx: ctx.has_auth_tokens(),
            target_filter=lambda t: t.agent_type == "auth",
        )
        
        task = MockTask(id="1", name="Auth", agent_type="auth")
        context = TaskContext()  # トークンなし
        
        assert rule.applies_to(task, context) is False


class TestCreateDynamicQueue:
    """create_dynamic_queue ヘルパーのテスト"""
    
    def test_create_default(self):
        """デフォルト設定での作成"""
        queue = create_dynamic_queue()
        
        assert isinstance(queue, DynamicTaskQueue)
        assert len(queue._injection_rules) > 0  # デフォルトルールあり
