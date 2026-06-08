"""
Custom Notify Tool - ProjectDiscovery Notification System.
"""
from typing import Dict, Any
import subprocess
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class NotifyTool(BaseTool):
    """
    Notify - Send notifications via various providers (Slack, Discord, etc.)
    Requires proper configuration in ~/.config/notify/provider-config.yaml
    """
    
    name = "notify"
    description = "Send notifications about findings to configured providers."
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "message": {
                            "type": "string",
                            "description": "Message to send"
                        },
                        "provider": {
                            "type": "string",
                            "enum": ["slack", "discord", "telegram", "all"],
                            "default": "all"
                        }
                    },
                    "required": ["message"]
                }
            }
        }

    def run(self, message: str, provider: str = "all") -> str:
        # Sanitize message (no shell special chars)
        if any(c in message for c in ["`", "$"]):
            return "Error: Unsafe characters in message."
        
        cmd = ["notify", "-silent"]
        if provider != "all":
            cmd += ["-provider", provider]
        
        try:
            result = subprocess.run(
                cmd, input=message, capture_output=True, text=True, timeout=30, check=False
            )
            return result.stdout or "Notification sent."
        except Exception as e:
            return f"Error: {e}"
