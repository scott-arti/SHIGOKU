"""
EventBusのテスト
"""
import asyncio
import pytest
from src.core.infra.event_bus import (
    EventBus,
    Event,
    EventType,
    get_event_bus,
)


class TestEvent:
    """Eventクラスのテスト"""
    
    def test_create_event(self):
        """イベント作成テスト"""
        event = Event(
            type=EventType.ASSET_FOUND,
            payload={"url": "http://example.com/admin"},
            source="recon_bot",
        )
        
        assert event.type == EventType.ASSET_FOUND
        assert event.payload["url"] == "http://example.com/admin"
        assert event.source == "recon_bot"
        assert event.event_id.startswith("evt_")
    
    def test_event_to_dict(self):
        """辞書変換テスト"""
        event = Event(
            type=EventType.VULN_FOUND,
            payload={"severity": "HIGH"},
            source="attack_agent",
        )
        
        d = event.to_dict()
        assert d["type"] == "vuln_found"
        assert d["payload"]["severity"] == "HIGH"
        assert "timestamp" in d


class TestEventBus:
    """EventBusクラスのテスト"""
    
    @pytest.fixture
    def event_bus(self):
        """テスト用EventBus"""
        return EventBus()
    
    def test_subscribe_and_emit(self, event_bus):
        """購読とイベント発行テスト"""
        async def run_test():
            received_events = []
            
            async def handler(event: Event):
                received_events.append(event)
            
            event_bus.subscribe(EventType.TASK_COMPLETED, handler)
            
            await event_bus.start()
            try:
                await event_bus.emit(Event(
                    type=EventType.TASK_COMPLETED,
                    payload={"task_id": "123"},
                    source="test",
                ))
                
                # イベント処理を待つ
                await asyncio.sleep(0.1)
                
                assert len(received_events) == 1
                assert received_events[0].payload["task_id"] == "123"
            finally:
                await event_bus.stop()
        
        asyncio.run(run_test())
    
    def test_unsubscribe(self, event_bus):
        """購読解除テスト"""
        async def run_test():
            received_count = 0
            
            async def handler(event: Event):
                nonlocal received_count
                received_count += 1
            
            event_bus.subscribe(EventType.ASSET_FOUND, handler)
            event_bus.unsubscribe(EventType.ASSET_FOUND, handler)
            
            await event_bus.start()
            try:
                await event_bus.emit(Event(
                    type=EventType.ASSET_FOUND,
                    payload={},
                    source="test",
                ))
                
                await asyncio.sleep(0.1)
                assert received_count == 0
            finally:
                await event_bus.stop()
        
        asyncio.run(run_test())
    
    def test_multiple_subscribers(self, event_bus):
        """複数購読者テスト"""
        async def run_test():
            results = {"handler1": 0, "handler2": 0}
            
            async def handler1(event: Event):
                results["handler1"] += 1
            
            async def handler2(event: Event):
                results["handler2"] += 1
            
            event_bus.subscribe(EventType.VULN_FOUND, handler1)
            event_bus.subscribe(EventType.VULN_FOUND, handler2)
            
            await event_bus.start()
            try:
                await event_bus.emit(Event(
                    type=EventType.VULN_FOUND,
                    payload={},
                    source="test",
                ))
                
                await asyncio.sleep(0.1)
                assert results["handler1"] == 1
                assert results["handler2"] == 1
            finally:
                await event_bus.stop()
        
        asyncio.run(run_test())
    
    def test_duplicate_event_ignored(self, event_bus):
        """重複イベント無視テスト"""
        async def run_test():
            received_count = 0
            
            async def handler(event: Event):
                nonlocal received_count
                received_count += 1
            
            event_bus.subscribe(EventType.TASK_STARTED, handler)
            
            await event_bus.start()
            try:
                # 同じイベントを2回発行
                event = Event(
                    type=EventType.TASK_STARTED,
                    payload={},
                    source="test",
                )
                await event_bus.emit(event)
                await event_bus.emit(event)  # 同じevent_id
                
                await asyncio.sleep(0.1)
                assert received_count == 1  # 1回のみ処理
            finally:
                await event_bus.stop()
        
        asyncio.run(run_test())
    
    def test_emit_sync(self, event_bus):
        """同期発行テスト"""
        event = Event(
            type=EventType.ERROR_OCCURRED,
            payload={"error": "test"},
            source="test",
        )
        
        event_bus.emit_sync(event)
        assert event_bus.pending_count == 1


class TestGetEventBus:
    """get_event_bus関数のテスト"""
    
    def test_singleton(self):
        """シングルトン動作テスト"""
        bus1 = get_event_bus()
        bus2 = get_event_bus()
        assert bus1 is bus2


class TestPhase5EventTypes:
    """Phase 5: リアルタイムダッシュボード用EventTypeのテスト"""
    
    def test_llm_event_types_exist(self):
        """LLM関連EventTypeが定義されていることを確認"""
        assert hasattr(EventType, 'LLM_CALL_START')
        assert hasattr(EventType, 'LLM_CALL_END')
        assert hasattr(EventType, 'LLM_ERROR')
        assert EventType.LLM_CALL_START.value == "llm_call_start"
        assert EventType.LLM_CALL_END.value == "llm_call_end"
        assert EventType.LLM_ERROR.value == "llm_error"
    
    def test_decision_event_type_exists(self):
        """意思決定EventTypeが定義されていることを確認"""
        assert hasattr(EventType, 'DECISION_MADE')
        assert EventType.DECISION_MADE.value == "decision_made"
    
    def test_recon_step_event_types_exist(self):
        """ReconステップEventTypeが定義されていることを確認"""
        assert hasattr(EventType, 'RECON_STEP_START')
        assert hasattr(EventType, 'RECON_STEP_END')
        assert EventType.RECON_STEP_START.value == "recon_step_start"
        assert EventType.RECON_STEP_END.value == "recon_step_end"
    
    def test_specialist_event_type_exists(self):
        """Specialist実行EventTypeが定義されていることを確認"""
        assert hasattr(EventType, 'SPECIALIST_EXECUTE')
        assert EventType.SPECIALIST_EXECUTE.value == "specialist_execute"

