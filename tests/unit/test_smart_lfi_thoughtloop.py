import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from src.core.agents.swarm.injection.smart_lfi import SmartLFIHunter
from src.core.models.finding import VulnType

@pytest.mark.asyncio
async def test_smart_lfi_hunter_thought_loop_success():
    """
    SmartLFIHunter が ThoughtLoop を通じて脆弱性を検知するフローを確認
    """
    # 1. Mock LLM
    mock_llm = AsyncMock()
    
    # Turn 1: LLM decides to test a payload
    resp1 = MagicMock()
    resp1.choices = [MagicMock()]
    resp1.choices[0].message.content = "THOUGHT: Testing etc/passwd.\nACTION: request\nINPUT: ../../../etc/passwd"
    
    # Turn 2: LLM finishes because it saw success in observation (though act() sets vulnerability_found directly)
    # 実際の実装では act() が成功時に vulnerability_found=True にするため、ループが早期終了する場合がある
    mock_llm.agenerate.side_effect = [resp1]

    # 2. Mock Network (LFI Indicator)
    mock_network = AsyncMock()
    mock_network.request.return_value = MagicMock(
        status=200, 
        text="root:x:0:0:root:/root:/bin/bash"
    )

    # 3. Setup Hunter
    hunter = SmartLFIHunter(config={"model": "test-model"})
    hunter.llm = mock_llm
    hunter.tester.network_client = mock_network

    # 4. Execute
    findings = await hunter._run_ai_bypass_loop("http://example.com/view.php", "file")

    # 5. Verification
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnType.LFI
    assert "../../../etc/passwd" in findings[0].description
    assert hunter.status.value == "completed"

@pytest.mark.asyncio
async def test_smart_lfi_hunter_thought_loop_fail():
    """
    LLM が試行を繰り返して最終的に Safe と判定するフロー
    """
    mock_llm = AsyncMock()
    
    # Turn 1: request
    resp1 = MagicMock()
    resp1.choices = [MagicMock()]
    resp1.choices[0].message.content = "THOUGHT: Guessing filter.\nACTION: request\nINPUT: /etc/passwd"
    
    # Turn 2: finish
    resp2 = MagicMock()
    resp2.choices = [MagicMock()]
    resp2.choices[0].message.content = "THOUGHT: No luck.\nACTION: finish\nINPUT: Safe"
    
    mock_llm.agenerate.side_effect = [resp1, resp2]

    mock_network = AsyncMock()
    mock_network.request.return_value = MagicMock(status=200, text="Nothing here")

    hunter = SmartLFIHunter()
    hunter.llm = mock_llm
    hunter.tester.network_client = mock_network

    findings = await hunter._run_ai_bypass_loop("http://example.com/", "p")

    assert len(findings) == 0
    assert hunter.status.value == "completed"
