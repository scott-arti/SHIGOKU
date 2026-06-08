import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from src.core.agents.swarm.base_manager import BaseManagerAgent
from src.core.agents.swarm.base import Task

@pytest.mark.asyncio
async def test_base_manager_think_loop():
    """
    BaseManagerAgentの思考ループ（Think-Act-Observe）をテスト
    """
    # 1. Setup Manager with Mock LLM
    manager = BaseManagerAgent(config={"model": "test-model"})
    
    # Mock LLM Client
    mock_llm = MagicMock()
    manager.set_llm_client(mock_llm)
    
    # シナリオ:
    # Turn 1: Thought -> Action(test_tool)
    # Turn 2: Thought -> Final Answer
    mock_llm_response = MagicMock()
    mock_llm_response.choices = [MagicMock()]
    mock_llm_response.choices[0].message.content = "Thought: I need to test.\nAction: test_tool(param='value')"
    
    response2 = MagicMock()
    response2.choices = [MagicMock()]
    response2.choices[0].message.content = "Thought: Done.\nFinal Answer: Success"
    
    mock_llm.agenerate = AsyncMock(side_effect=[mock_llm_response, response2])


    # 2. Register Mock Tool
    mock_tool = MagicMock(return_value={"status": "ok"})
    manager.register_tool("test_tool", mock_tool, "A test tool")

    # 3. Create Task
    task = Task(id="test-1", name="Test Task", target="http://example.com")

    # 4. Execute Dispatch
    result = await manager.dispatch(task)

    # 5. Assertions
    assert result.status == "success"
    assert len(result.execution_log) >= 2
    
    # Toolが呼ばれたか
    mock_tool.assert_called_once_with(param="value")
    
    # ログ確認
    action_log = next(l for l in result.execution_log if l["type"] == "action")
    assert action_log["action"] == "test_tool"
    assert action_log["result"] == {"status": "ok"}
