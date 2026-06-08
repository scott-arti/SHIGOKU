"""
Custom 403Bypasser Tool - Bypass 403 Forbidden responses.
"""
from typing import Dict, Any
import subprocess
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class ForbiddenBypasserTool(BaseTool):
    """
    403 Bypasser - Attempt to bypass 403 Forbidden responses.
    Uses common bypass techniques (path manipulation, headers, etc.)
    """
    
    name = "forbidden_bypasser"
    description = "Attempt to bypass 403 Forbidden responses using various techniques."
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL returning 403"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["quick", "full"],
                            "default": "quick"
                        }
                    },
                    "required": ["url"]
                }
            }
        }

    def run(self, url: str, mode: str = "quick") -> str:
        # Note: safe_run enforces shell=False, so injection is prevents at OS level
        
        cmd = ["403bypasser", "-u", url]
        if mode == "full":
            cmd += ["-a"]  # All techniques
        
        try:
            from src.core.security.safe_subprocess import safe_run, SecurityViolationError
            
            result = safe_run(cmd, capture_output=True, timeout=300, check=False)
            return result.stdout or result.stderr or "No bypasses found."
            
        except FileNotFoundError:
            return "Error: 403bypasser not installed. Try: pip install 403bypasser"
        except SecurityViolationError as e:
            return f"Security Error: {e}"
        except Exception as e:
            return f"Error: {e}"
