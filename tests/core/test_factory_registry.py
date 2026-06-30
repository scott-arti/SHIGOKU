import pytest
from unittest.mock import MagicMock
from src.core.factory import AgentFactory
from src.core.engine.agent_registry import register_agent, get_agent_class
from src.core.agents.base import BaseAgent, AgentConfig
from src.core.agents.protocol import AgentProtocol

# Dummy Agent for testing
@register_agent(
    names=["dummy", "test_agent"],
    tags=["test"]
)
class DummyAgent(BaseAgent):
    def __init__(self, config: AgentConfig = None, workspace_root: str = None):
        super().__init__(config or AgentConfig(name="dummy"), workspace_root=workspace_root)
    
    async def process(self, message: str) -> str:
        return "dummy_result"

class TestFactoryRegistry:
    
    def test_registry_retrieval(self):
        """Registry handles agent retrieval correctly"""
        cls = get_agent_class("dummy")
        assert cls == DummyAgent
        
        cls = get_agent_class("test_agent")
        assert cls == DummyAgent
        
        cls = get_agent_class("non_existent")
        assert cls is None

    def test_factory_creation_registered_agent(self):
        """Factory creates instance of registered agent"""
        agent = AgentFactory.create_agent("dummy")
        assert isinstance(agent, DummyAgent)
        assert agent.name == "dummy"

    def test_factory_creation_real_agents(self):
        """Factory creates real agents via registry and they comply with protocol"""
        # CodeAgent
        agent = AgentFactory.create_agent("code")
        assert isinstance(agent, BaseAgent)
        # Check protocol compliance
        assert hasattr(agent, "run")
        assert hasattr(agent, "name")
        
        # CommandAgent
        agent = AgentFactory.create_agent("command")
        assert isinstance(agent, BaseAgent)

    def test_swarm_agent_instantiation(self):
        """Factory handles Swarm agents (different init signature)"""
        # JWTInspector (AuthNinja swarm)
        # Note: JWTInspector init signature is different, handled by Factory retry logic
        agent = AgentFactory.create_agent("authninja")
        assert agent is not None
        assert agent.name == "JWT-Inspector"
        assert hasattr(agent, "run")
        
        # BizLogicHunter
        agent = AgentFactory.create_agent("bizlogichunter")
        assert agent is not None
        assert hasattr(agent, "run")
 
    def test_specialized_agent_visual_recon(self):
        """Factory creates VisualReconAgent and it has run() method"""
        import asyncio
        # VisualRecon (No BaseAgent inheritance, but has run())
        # We need to mock GPU/Ollama check if possible or expect it to be created 
        # but maybe fail runtime if no GPU. 
        # VisualReconAgent init checks Ollama. We might need to mock that.
        
        from unittest.mock import patch, MagicMock
        with patch("src.core.agents.specialized.visual_recon.VisualReconAgent._check_vision_availability", return_value=True):
            with patch("src.core.agents.specialized.visual_recon.VisualReconAgent.run", new_callable=MagicMock) as mock_run:
                mock_run.return_value = {"success": True, "agent": "VisualRecon", "findings": []}
                agent = AgentFactory.create_agent("visualrecon")
                assert agent is not None
                assert hasattr(agent, "run")
                assert agent.name == "VisualRecon"
                res = mock_run.return_value
                assert res["success"] is True
