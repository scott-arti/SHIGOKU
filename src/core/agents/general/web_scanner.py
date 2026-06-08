from src.core.agent import Agent as GeneralAgent
from src.core.agents.base import BaseAgent, AgentConfig

class WebScannerAgent(GeneralAgent):
    """
    Web Scanner Agent
    """
    def __init__(self, config: AgentConfig, workspace_root: str = "./workspace"):
        super().__init__(
            name=config.name,
            instructions=config.instructions,
            model=config.model,
            mode="security",
            tools=config.tools,
            workspace_root=workspace_root
        )