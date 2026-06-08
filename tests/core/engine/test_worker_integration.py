import pytest
from unittest.mock import MagicMock, patch
from src.core.engine.master_conductor import MasterConductor
from src.core.domain.model.task import Task, TaskResult

@pytest.fixture
def mock_mc():
    with patch("src.core.engine.recipe_loader.RecipeLoader"):
        with patch("src.core.engine.task_queue.DynamicTaskQueue"):
            with patch("src.core.engine.context_propagator.ContextPropagator"):
                mc = MasterConductor()
                mc.accumulated_context = MagicMock()
                mc.llm_client = MagicMock()
                return mc

@pytest.mark.asyncio
async def test_dispatch_to_worker(mock_mc):
    """Workerへのディスパッチが優先されることを検証"""
    task = Task(
        id="test_js",
        name="JS Analysis",
        agent_type="js_mine",
        params={"target": "http://example.com/test.js"}
    )
    
    with patch("src.core.swarm.worker.factory.WorkerFactory.create_worker") as mock_create:
        from unittest.mock import AsyncMock
        mock_worker = AsyncMock()
        mock_worker.execute.return_value = TaskResult(
            success=True, 
            data={"findings": ["secret_found"]},
            findings=[]
        )
        mock_create.return_value = mock_worker
        
        result = await mock_mc._dispatch(task)
        
        assert result["success"] is True
        assert result["agent"] == "js_mine"
        assert result.get("is_swarm") is True
        mock_worker.execute.assert_called_once_with(task)

@pytest.mark.asyncio
async def test_fallback_to_legacy_agent(mock_mc):
    """Workerが存在しない場合にレガシーエージェントにフォールバックすることを検証"""
    task = Task(
        id="legacy_task",
        name="Legacy Action",
        agent_type="unknown_worker",
        params={"target": "http://example.com"}
    )
    
    with patch("src.core.swarm.worker.factory.WorkerFactory.create_worker") as mock_create:
        mock_create.return_value = None
        
        with patch("src.core.factory.AgentFactory.create_agent") as mock_agent_factory:
            from unittest.mock import AsyncMock
            mock_agent = AsyncMock()
            mock_agent.execute.return_value = {"success": True, "legacy": True}
            mock_agent_factory.return_value = mock_agent
            
            result = await mock_mc._dispatch(task)
            
            assert result["success"] is True
            # MC legacy wrapper puts the result in data['result']
            assert "legacy" in str(result["data"])
            assert "is_swarm" not in result

