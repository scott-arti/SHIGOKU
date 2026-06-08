import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from src.core.agents.swarm.discovery.manager import DiscoveryManagerAgent
from src.core.agents.swarm.base import Task

@pytest.mark.asyncio
async def test_discovery_manager_delegation():
    """
    DiscoveryManagerAgentがWorkerを正しく呼び出すかテスト
    """
    # 1. Mocking LLM
    mock_llm_response = MagicMock()
    mock_llm_response.choices = [MagicMock()]
    mock_llm_response.choices[0].message.content = "Thought: Need to see.\nAction: run_visual_recon({\"url\": \"http://example.com\"})"
    
    mock_llm_response_2 = MagicMock()
    mock_llm_response_2.choices = [MagicMock()]
    mock_llm_response_2.choices[0].message.content = "Thought: Done.\nFinal Answer: Visual check complete."

    # 2. Setup Manager
    manager = DiscoveryManagerAgent(config={"model": "test-model"})
    manager.llm.agenerate = AsyncMock(side_effect=[mock_llm_response, mock_llm_response_2])

    # 3. Running with Mocked Workers
    with patch("src.core.agents.swarm.discovery.visual_recon.VisualRecon.run_as_tool", new_callable=AsyncMock) as mock_vr_tool:
        mock_vr_tool.return_value = {"interesting_elements": ["Login Form"], "logs": []}
        
        task = Task(id="test-discovery", name="Test Discovery", target="http://example.com")
        result = await manager.dispatch(task)

        # 4. Verification
        assert result.status == "success"
        
        # Tool呼び出し確認
        mock_vr_tool.assert_called_once_with("http://example.com")
