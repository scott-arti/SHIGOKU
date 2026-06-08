
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock

from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter

@pytest.mark.asyncio
async def test_smart_sqli_hunter_mock_flow():
    # Mock LLM and Network
    mock_llm = AsyncMock()
    mock_network = AsyncMock()
    
    # Setup Hunter
    hunter = SmartSQLiHunter()
    hunter.llm = mock_llm
    hunter.smart_client.client = mock_network
    
    # Mock LLM Responses strictly
    # Response 1: Probe
    resp1 = MagicMock()
    msg1 = MagicMock()
    msg1.content = "THOUGHT: Analyzing param.\nACTION: request\nINPUT: ' OR 1=1"
    choice1 = MagicMock()
    choice1.message = msg1
    resp1.choices = [choice1]
    
    # Response 2: Finish
    resp2 = MagicMock()
    msg2 = MagicMock()
    msg2.content = "THOUGHT: Error confirmed.\nACTION: finish\nINPUT: Vulnerable"
    choice2 = MagicMock()
    choice2.message = msg2
    resp2.choices = [choice2]
    
    mock_llm.agenerate.side_effect = [resp1, resp2]
    
    # Network Responses
    # 1. Probe response (500 Error)
    resp_net_1 = MagicMock(status=500, headers={}, body="MySQL Syntax Error")
    mock_network.request.return_value = resp_net_1
    
    # Execute
    task = MagicMock()
    task.target = "http://example.com/vuln?id=1"
    
    findings = await hunter.execute(task)
    
    assert len(findings) == 1
    # Fix: VulnType.SQLI.value is "sqli"
    assert findings[0].vuln_type.value == "sqli" 
    assert "id" in findings[0].title
