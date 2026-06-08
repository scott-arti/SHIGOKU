import pytest
import asyncio
from unittest.mock import MagicMock, patch
from src.core.domain.model.target import TargetAsset, TargetType
from src.core.recon.orchestrator import ReconOrchestrator
from src.core.recon.recipes import ReconMode

@pytest.fixture
def mock_config():
    config = MagicMock()
    config.environment = "BUG_BOUNTY"
    return config

@pytest.fixture
def orchestrator(mock_config):
    return ReconOrchestrator(knowledge_graph=MagicMock(), config=mock_config)

@pytest.mark.asyncio
async def test_orchestrator_recipe_selection(orchestrator):
    # Wildcard Domain
    asset = TargetAsset.from_input("*.example.com")
    mode = orchestrator._determine_recipe_type = MagicMock(return_value=ReconMode.WILDCARD_BB) # 内部メソッド呼び出しを検証
    
    with patch("src.core.recon.factory.ReconRecipeFactory.create") as mock_create:
        mock_recipe = MagicMock()
        mock_create.return_value = mock_recipe
        
        await orchestrator.run_pipeline([asset])
        
        assert mock_create.called
        assert mock_recipe.execute_fast_phase.called
        assert len(orchestrator.background_tasks) == 1

@pytest.mark.asyncio
async def test_run_tool_integration(orchestrator):
    # run_tool が WorkerFactory を呼び出すか検証
    with patch("src.core.recon.orchestrator.get_worker_factory") as mock_get_factory:
        mock_factory = MagicMock()
        mock_worker = MagicMock()
        
        # AsyncMock または返り値が awaitable な Mock にする
        async def mock_execute(params):
            return {"status": "success"}
        mock_worker.execute = mock_execute
        
        mock_factory.create_worker.return_value = mock_worker
        mock_get_factory.return_value = mock_factory
        
        result = await orchestrator.run_tool("subfinder", "example.com")
        
        assert result == {"status": "success"}
        assert orchestrator.get_results("subfinder") == {"status": "success"}
