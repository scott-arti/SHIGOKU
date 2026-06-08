
import pytest
from src.core.engine.context_designer import ContextDesigner
from src.core.engine.master_conductor import ExecutionContext
from src.core.engine.task_queue import TaskContext
from src.core.agents.swarm.base import Task

class TestContextDesignerCookieInjection:
    
    @pytest.fixture
    def designer(self):
        return ContextDesigner()

    def test_enrich_task_prioritizes_raw_cookie_from_target_info(self, designer):
        """target_info の raw_cookie が最優先される確認"""
        task = Task(id="test_task", name="Test", agent_type="logic", action="scan", params={})
        
        # Setup Context with Raw Cookie (TargetInfo is a dict in ExecutionContext)
        target_info = {
            "target": "http://example.com",
            "visited_urls": [],
            "cookies": "PHPSESSID=raw_cookie_value"
        }
        context = ExecutionContext(target_info=target_info)

        
        # Setup Accumulated Context with a DIFFERENT session token (to simulate potential conflict)
        accumulated = TaskContext()
        accumulated.auth_tokens = {"session": "heuristic_token_value"}
        
        enriched_task = designer.enrich_task(task, context, accumulated)
        
        # Expectation: Raw Cookie should be present from target_info
        assert "PHPSESSID=raw_cookie_value" in enriched_task.params["cookies"]
        
        # The heuristic token might be appended if not present, but raw cookie MUST be there.
        # Current logic appends if token value is not in string.
        assert "session_id=heuristic_token_value" in enriched_task.params["cookies"]

    def test_enrich_task_suppresses_redundant_session_token(self, designer):
        """raw_cookie に既にトークンが含まれている場合、session_id=... を重複追加しない確認"""
        task = Task(id="test_task", name="Test", agent_type="logic", action="scan", params={})
        
        # Raw Cookie matches the session token value
        token_val = "cafe1234"
        target_info = {
            "target": "http://example.com",
            "visited_urls": [],
            "cookies": f"PHPSESSID={token_val}"
        }
        context = ExecutionContext(target_info=target_info)
        
        accumulated = TaskContext()
        accumulated.auth_tokens = {"session": token_val}
        
        enriched_task = designer.enrich_task(task, context, accumulated)
        
        # Expectation: Only raw cookie, no "session_id=cafe1234" appended
        assert enriched_task.params["cookies"] == f"PHPSESSID={token_val}"
        assert "; session_id=" not in enriched_task.params["cookies"]

    def test_enrich_task_merges_cookies(self, designer):
        """既存の task.params['cookies'] と raw_cookie が正しく結合されるか確認"""
        # Task already has a cookie
        task = Task(id="test_task", name="Test", agent_type="logic", action="scan", 
                   params={"cookies": "lang=en"})
        
        target_info = {
            "target": "http://example.com",
            "visited_urls": [],
            "cookies": "PHPSESSID=new_cookie"
        }
        context = ExecutionContext(target_info=target_info)
        
        enriched_task = designer.enrich_task(task, context, None)
        
        assert "lang=en" in enriched_task.params["cookies"]
        assert "PHPSESSID=new_cookie" in enriched_task.params["cookies"]
        # Order doesn't strictly matter for functionality, but check format
        assert "; " in enriched_task.params["cookies"]
