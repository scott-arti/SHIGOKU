"""
Custom Amass Tool - In-depth Asset Discovery.
"""
from typing import Dict, Any, Optional
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class AmassTool(BaseTool):
    """
    Amass asset discovery tool.
    Note: Amass is slow. Set timeouts appropriately.
    """
    
    name = "amass"
    description = "Deep asset discovery using Owasp Amass."
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Target domain"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["passive", "active"],
                            "description": "Scan profile (passive=enum -passive)",
                            "default": "passive"
                        },
                        "timeout_minutes": {
                            "type": "integer",
                            "description": "Timeout in minutes",
                            "default": 15
                        }
                    },
                    "required": ["domain"]
                }
            }
        }

    def run(self, domain: str, mode: str = "passive", timeout_minutes: int = 15) -> str:
        # subcommand enum is standard for discovery
        cmd = ["amass", "enum", "-d", domain, "-json", "-silent"]
        
        if mode == "passive":
            cmd.append("-passive")
        elif mode == "active":
            cmd.append("-active")
            
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_minutes * 60,
                check=False
            )
            return result.stdout or "No results found."
        except subprocess.TimeoutExpired:
            return "Error: Amass timed out."
        except Exception as e:
            return f"Error: {str(e)}"
