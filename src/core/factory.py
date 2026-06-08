from typing import Optional, Dict, Any
from src.core.agents.base import BaseAgent, AgentConfig
# Legacy agents removed: CodeAgent, CommandAgent
from src.config import settings
from src.prompts import get_agent_prompt

class AgentFactory:
    """
    Factory for creating agent instances dynamically.
    Centralizes the logic of "which class for which role".
    """
    
    @staticmethod
    def create_agent(agent_name: str, mode: str = "security", model: Optional[str] = None, tools: list = None, workspace_root: Optional[str] = None, project_manager: Any = None, master_conductor: Any = None) -> BaseAgent:
        """
        Create an agent instance based on registry.
        """
        import os
        from src.core.engine.agent_registry import AgentRegistry
        
        # Ensure agents are loaded
        AgentRegistry.autoload([
            "src.core.agents", 
            "src.core.agents.general",
            "src.core.agents.specialized",
            "src.core.agents.swarm",
            "src.core.agents.analysis",
            "src.core" 
        ])

        model = model or settings.model or settings.model_output or "deepseek/deepseek-chat"
        effective_workspace = workspace_root or os.getcwd()
        
        # Registry Lookup
        agent_cls = AgentRegistry.get_agent_class(agent_name)
        
        if agent_cls:
            # Common Config
            config = AgentConfig(
                name=agent_name,
                description=getattr(agent_cls, "__doc__", "") or "Agent",
                model=model,
                instructions=get_agent_prompt(mode),
                tools=tools or []
            )
            
            try:
                # Standard instantiation (Unified Interface Phase 2)
                return agent_cls(
                    config=config, 
                    project_manager=project_manager,
                    master_conductor=master_conductor,
                    workspace_root=effective_workspace
                )
            except TypeError as e:
                # Legacy Adapter
                import logging
                logger = logging.getLogger(__name__)
                logger.debug("Standard init failed for %s, trying legacy: %s", agent_name, e)
                
                try:
                    return agent_cls(workspace_root=effective_workspace)
                except Exception:
                    return agent_cls(config)
        
        # --- Fallbacks ---
        import logging
        logger = logging.getLogger(__name__)
        logger.warning("Agent '%s' not found in registry. Attempting fallback mapping.", agent_name)
        
        # Map specific names to GeneralAgent if not found
        if agent_name in ["SecurityBot", "web_scanner", "http_client", "vuln_scanner", "agent", "general"]:
            from src.core.agent import Agent as GenAgent
            from src.tools import ToolRegistry
            effective_tools = tools if tools else ToolRegistry.get_all()
            return GenAgent(
                name=agent_name,
                instructions=get_agent_prompt(mode),
                model=settings.security_agent_model or model,
                mode=mode,
                tools=effective_tools,
                workspace_root=workspace_root,
                project_manager=project_manager
            )
            
        raise ValueError(f"Unknown agent: {agent_name}")

    @staticmethod
    def create_team() -> Dict[str, BaseAgent]:
        """Create the standard team of agents."""
        team = {}
        team["SecurityBot"] = AgentFactory.create_agent("SecurityBot", mode="security")
        team["ReconBot"] = AgentFactory.create_agent("ReconBot")
        team["RedTeamBot"] = AgentFactory.create_agent("RedTeamBot")
        return team
