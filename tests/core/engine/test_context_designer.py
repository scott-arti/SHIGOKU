import pytest
from unittest.mock import MagicMock
from src.core.engine.context_designer import ContextDesigner
from src.core.agents.swarm.base import Task
from src.core.engine.master_conductor import ExecutionContext
from src.core.engine.task_queue import TaskContext

class TestContextDesigner:
    @pytest.fixture
    def designer(self):
        return ContextDesigner()

    @pytest.fixture
    def mock_context(self):
        ctx = MagicMock(spec=ExecutionContext)
        ctx.target_info = {"aggressive_targets": ["http://aggressive.com"]}
        return ctx

    @pytest.fixture
    def mock_accumulated_context(self):
        ctx = TaskContext()
        ctx.auth_tokens = {"Bearer": "verify_token_123"}
        ctx.tech_stack = ["PHP", "MySQL"]
        ctx.waf_info = {"detected": True, "type": "Cloudflare"}
        return ctx

    def test_enrich_aggressive_target(self, designer, mock_context):
        task = Task(id="test_1", name="Test Task", agent_type="test", action="run", params={"target": "http://aggressive.com"})
        enriched_task = designer.enrich_task(task, mock_context)
        assert enriched_task.params.get("is_aggressive") is True

    def test_enrich_auth_tokens(self, designer, mock_context, mock_accumulated_context):
        task = Task(id="test_2", name="Auth Task", agent_type="test", action="run", params={"target": "http://example.com"})
        enriched_task = designer.enrich_task(task, mock_context, mock_accumulated_context)
        
        assert "headers" in enriched_task.params
        assert enriched_task.params["headers"]["Authorization"] == "Bearer verify_token_123"

    def test_enrich_tech_stack_tags(self, designer, mock_context, mock_accumulated_context):
        task = Task(id="test_3", name="Tech Task", agent_type="test", action="run", params={"target": "http://example.com", "tags": ["base"]})
        enriched_task = designer.enrich_task(task, mock_context, mock_accumulated_context)
        
        tags = enriched_task.params.get("tags", [])
        assert "php" in tags
        assert "db" in tags
        assert "base" in tags

    def test_enrich_waf_bypass(self, designer, mock_context, mock_accumulated_context):
        task = Task(id="test_4", name="WAF Task", agent_type="test", action="run", params={"target": "http://example.com"})
        enriched_task = designer.enrich_task(task, mock_context, mock_accumulated_context)
        
        assert enriched_task.params.get("waf_bypass") is True
        assert enriched_task.params.get("waf_info") == {"detected": True, "type": "Cloudflare"}
