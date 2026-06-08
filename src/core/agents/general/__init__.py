from src.core.engine.agent_registry import register_agent
from .web_scanner import WebScannerAgent

@register_agent(names=["web_scanner"])
class WebScannerAgent(WebScannerAgent):
    pass
