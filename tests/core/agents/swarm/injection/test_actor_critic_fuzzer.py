import pytest
from unittest.mock import AsyncMock, MagicMock
from src.core.agents.swarm.injection.actor_critic_fuzzer import ActorCriticFuzzer
from src.core.infra.smart_request import SmartRequest
from src.core.infra.network_client import AsyncNetworkClient

@pytest.fixture
def mock_smart_request():
    mock_client = AsyncMock(spec=AsyncNetworkClient)
    req = SmartRequest(network_client=mock_client)
    req.request = AsyncMock()
    return req

@pytest.mark.asyncio
async def test_fuzzer_initialization(mock_smart_request):
    fuzzer = ActorCriticFuzzer(target_request=mock_smart_request)
    assert fuzzer.name == "ActorCriticFuzzer"

@pytest.mark.asyncio
async def test_fuzzer_mutation(mock_smart_request):
    fuzzer = ActorCriticFuzzer(target_request=mock_smart_request)
    base = "<script>"
    mutated = fuzzer._apply_mutation(base, "lower_upper")
    assert mutated.lower() == base

@pytest.mark.asyncio
async def test_run_prober_parallel(mock_smart_request):
    fuzzer = ActorCriticFuzzer(target_request=mock_smart_request)
    
    # Mock baseline response
    mock_smart_request.request.side_effect = [
        {"status": 200, "body": "<html>shigoku_canary_1234</html>", "diff": ""}, # Baseline
        {"status": 200, "body": "<html>reflected_1</html>", "diff": "diff_1"},      # Payload 1
        {"status": 403, "body": "Forbidden", "diff": "diff_forbidden"}             # Payload 2
    ]
    
    payload_input = [
        {"strategy": "none", "payload": "reflected_1"},
        {"strategy": "none", "payload": "<script>"}
    ]
    
    summary = await fuzzer._run_prober(payload_input)
    
    assert summary["total_sent"] == 2
    assert "Status:200 Length:24" in summary["status_codes"]
    assert "Status:403 Length:9" in summary["status_codes"]
    assert len(summary["promising"]) >= 1
    assert any(p["payload"] == "reflected_1" for p in summary["promising"])
    assert "reflection_context" in summary
    assert "baseline_diffs" in summary
