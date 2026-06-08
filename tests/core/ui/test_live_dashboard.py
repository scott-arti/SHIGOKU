"""
LiveDashboardのテスト
"""
import pytest

from src.core.infra.event_bus import EventBus, Event, EventType
from src.core.ui.live_dashboard import LiveDashboard, ActivityLogEntry


class TestActivityLogEntry:
    """ActivityLogEntryのテスト"""
    
    def test_create_entry(self):
        """エントリ作成テスト"""
        entry = ActivityLogEntry(
            timestamp=1707235200.0,  # 2026-02-06 12:00:00
            category="TASK",
            message="Test message",
            level="info",
        )
        
        assert entry.category == "TASK"
        assert entry.message == "Test message"
        assert entry.level == "info"
    
    def test_formatted_time(self):
        """時刻フォーマットテスト"""
        entry = ActivityLogEntry(
            timestamp=1707235200.0,
            category="TASK",
            message="Test",
        )
        
        # フォーマットが HH:MM:SS の形式であることを確認
        formatted = entry.formatted_time()
        assert len(formatted) == 8
        assert ":" in formatted


class TestLiveDashboard:
    """LiveDashboardのテスト"""
    
    @pytest.fixture
    def event_bus(self):
        """テスト用EventBus"""
        return EventBus()
    
    @pytest.fixture
    def dashboard(self, event_bus):
        """テスト用LiveDashboard"""
        return LiveDashboard(event_bus)
    
    def test_initialization(self, dashboard):
        """初期化テスト"""
        assert dashboard.activity_log == []
        assert dashboard.current_task is None
        assert dashboard.current_agent is None
        assert dashboard.llm_status == "待機中"
        assert dashboard.task_count == 0
        assert dashboard.completed_count == 0
        assert dashboard.finding_count == 0
    
    def test_add_log(self, dashboard):
        """ログ追加テスト"""
        dashboard._add_log("TASK", "Test message", "info")
        
        assert len(dashboard.activity_log) == 1
        assert dashboard.activity_log[0].category == "TASK"
        assert dashboard.activity_log[0].message == "Test message"
    
    def test_add_log_max_entries(self, dashboard):
        """ログ最大件数制限テスト"""
        # 最大件数を超えてログを追加
        for i in range(20):
            dashboard._add_log("TASK", f"Message {i}")
        
        assert len(dashboard.activity_log) == dashboard.MAX_LOG_ENTRIES
    
    def test_process_task_started_event(self, dashboard):
        """タスク開始イベント処理テスト"""
        event = Event(
            type=EventType.TASK_STARTED,
            payload={
                "task_name": "test_task",
                "agent": "test_agent",
                "target": "http://example.com",
            },
            source="test",
        )
        
        dashboard._process_event(event)
        
        assert dashboard.current_task == "test_task"
        assert dashboard.current_agent == "test_agent"
        assert dashboard.current_target == "http://example.com"
        assert dashboard.task_count == 1
        assert len(dashboard.activity_log) == 1
    
    def test_process_task_completed_event(self, dashboard):
        """タスク完了イベント処理テスト"""
        # 先にタスクを開始
        dashboard.current_task = "test_task"
        
        event = Event(
            type=EventType.TASK_COMPLETED,
            payload={"task_name": "test_task"},
            source="test",
        )
        
        dashboard._process_event(event)
        
        assert dashboard.current_task is None
        assert dashboard.completed_count == 1
    
    def test_process_llm_call_start_event(self, dashboard):
        """LLMコール開始イベント処理テスト"""
        event = Event(
            type=EventType.LLM_CALL_START,
            payload={"model": "gemini-2.5-flash"},
            source="test",
        )
        
        dashboard._process_event(event)
        
        assert "実行中" in dashboard.llm_status
        assert dashboard.llm_last_call is not None
    
    def test_process_llm_error_event(self, dashboard):
        """LLMエラーイベント処理テスト"""
        event = Event(
            type=EventType.LLM_ERROR,
            payload={"error": "Rate limit exceeded"},
            source="test",
        )
        
        dashboard._process_event(event)
        
        assert "エラー" in dashboard.llm_status
        assert len(dashboard.errors) == 1
        assert dashboard.errors[0] == "Rate limit exceeded"
    
    def test_process_recon_step_events(self, dashboard):
        """Reconステップイベント処理テスト"""
        # 開始
        start_event = Event(
            type=EventType.RECON_STEP_START,
            payload={"step": 1, "name": "Subdomain Discovery"},
            source="test",
        )
        dashboard._process_event(start_event)
        
        assert len(dashboard.activity_log) == 1
        assert "Step 1" in dashboard.activity_log[0].message
        
        # 終了
        end_event = Event(
            type=EventType.RECON_STEP_END,
            payload={"step": 1, "name": "Subdomain Discovery", "result": "15 found"},
            source="test",
        )
        dashboard._process_event(end_event)
        
        assert len(dashboard.activity_log) == 2
    
    def test_process_vuln_found_event(self, dashboard):
        """脆弱性発見イベント処理テスト"""
        event = Event(
            type=EventType.VULN_FOUND,
            payload={"severity": "HIGH", "title": "SQL Injection"},
            source="test",
        )
        
        dashboard._process_event(event)
        
        assert dashboard.finding_count == 1
        assert len(dashboard.activity_log) == 1
        assert "SQL Injection" in dashboard.activity_log[0].message
    
    def test_build_layout(self, dashboard):
        """レイアウト構築テスト"""
        # いくつかのログを追加
        dashboard._add_log("TASK", "Test task")
        dashboard._add_log("RECON", "Step 1")
        
        layout = dashboard._build_layout()
        
        # レイアウトが正しく構築されることを確認
        assert layout is not None
        assert "header" in [child.name for child in layout.children]
        assert "main_area" in [child.name for child in layout.children]
        assert "footer" in [child.name for child in layout.children]
