import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from src.core.agents.swarm.biz_logic_hunter import BizLogicHunter
from src.core.agents.specialized.taint_analysis_agent import TaintAnalysisAgent
from src.core.agents.specialized.api_spec_reconstructor import APISpecReconstructor
from src.core.agents.specialized.graphql_navigator import GraphQLNavigator
from src.core.infra.network_client import NetworkResponse
from src.core.security.ethics_guard import ActionResult
from src.core.agents.base import AgentConfig

dummy_config = AgentConfig(
    name="test_agent",
    description="test",
    model="test-model",
    instructions="test"
)

@pytest.mark.asyncio
async def test_bizlogic_hunter_uses_proxy():
    with patch("src.core.agents.swarm.biz_logic_hunter.AsyncNetworkClient") as MockClient, \
         patch("src.core.agents.swarm.biz_logic_hunter.get_ethics_guard") as MockGetGuard:
        
        # Mock EthicsGuard
        mock_guard = MockGetGuard.return_value
        mock_guard.check_action.return_value = (ActionResult.ALLOWED, "Allowed")
        
        mock_instance = MockClient.return_value
        mock_instance.request = AsyncMock(return_value=NetworkResponse(
            status=200, headers={}, body="OK", elapsed=0.1, url="http://example.com"
        ))
        
        agent = BizLogicHunter(config=dummy_config)
        task = {"target": "http://example.com/api/users/123", "candidate": {"smell_type": "idor_candidate", "method": "GET"}}
        
        result = await agent.run(task)
        
        # Verify AsyncNetworkClient.request called
        assert mock_instance.request.called
        # Check use_proxy_rotation=True
        args, kwargs = mock_instance.request.call_args
        assert kwargs.get("use_proxy_rotation") is True

@pytest.mark.asyncio
async def test_taint_analysis_uses_proxy():
    with patch("src.core.agents.specialized.taint_analysis_agent.AsyncNetworkClient") as MockClient:
        mock_instance = MockClient.return_value
        mock_instance.request = AsyncMock(return_value=NetworkResponse(
            status=200, headers={}, body="<html></html>", elapsed=0.1, url="http://example.com"
        ))
        
        agent = TaintAnalysisAgent(config=dummy_config)
        await agent.execute("http://example.com", {"param_name": "q"})
        
        assert mock_instance.request.called
        args, kwargs = mock_instance.request.call_args
        assert kwargs.get("use_proxy_rotation") is True

@pytest.mark.asyncio
async def test_api_spec_reconstructor_uses_proxy():
    with patch("src.core.agents.specialized.api_spec_reconstructor.AsyncNetworkClient") as MockClient:
        mock_instance = MockClient.return_value
        mock_instance.request = AsyncMock(return_value=NetworkResponse(
            status=200, headers={}, body="<html><script src='app.js'></script></html>", elapsed=0.1, url="http://example.com"
        ))
        
        agent = APISpecReconstructor(config=dummy_config)
        await agent.execute("http://example.com", {})
        
        # Check at least one call used proxy
        assert mock_instance.request.called
        # Verify ALL calls used proxy
        for call in mock_instance.request.call_args_list:
            args, kwargs = call
            assert kwargs.get("use_proxy_rotation") is True

@pytest.mark.asyncio
async def test_graphql_navigator_uses_proxy():
    with patch("src.core.agents.specialized.graphql_navigator.AsyncNetworkClient") as MockClient:
        mock_instance = MockClient.return_value
        # Mock introspection failure so it proceeds to field suggestion etc.
        mock_instance.request = AsyncMock(return_value=NetworkResponse(
            status=404, headers={}, body="Not Found", elapsed=0.1, url="http://example.com/graphql"
        ))
        
        agent = GraphQLNavigator(config=dummy_config)
        await agent.execute("http://example.com/graphql", {})
        
        assert mock_instance.request.called
        for call in mock_instance.request.call_args_list:
            args, kwargs = call
            assert kwargs.get("use_proxy_rotation") is True
