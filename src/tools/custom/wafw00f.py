"""
Custom wafw00f Tool - WAF Detection and Fingerprinting.
"""
from typing import Dict, Any, Optional
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry


@ToolRegistry.register
class Wafw00fTool(BaseTool):
    """
    wafw00f for Web Application Firewall detection.
    
    Profiles:
    - quick: Test for known WAFs only
    - all: Test all known WAFs
    - fingerprint: Detailed fingerprinting
    """
    
    name = "wafw00f"
    description = "Detect and fingerprint Web Application Firewalls (WAFs)."
    
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
                            "description": "Target URL to check for WAF"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["quick", "all", "fingerprint"],
                            "description": "Detection mode",
                            "default": "quick"
                        },
                        "extra_args": {
                            "type": "string",
                            "description": "Additional flags (sanitized)"
                        }
                    },
                    "required": ["url"]
                }
            }
        }

    def run(self, url: str, mode: str = "quick", extra_args: Optional[str] = None) -> str:
        cmd = ["wafw00f", url]
        
        if mode == "all":
            cmd.append("-a")
        elif mode == "fingerprint":
            cmd += ["-a", "-v"]
        # mode == "quick" uses defaults

        if extra_args:
            if any(char in extra_args for char in [";", "|", "&", "$", "`"]):
                return "Error: Unsafe characters detected in extra_args."
            cmd += shlex.split(extra_args)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120, check=False
            )
            return result.stdout or "No WAF detected."
        except subprocess.TimeoutExpired:
            return "Error: wafw00f timed out."
        except Exception as e:
            return f"Error: {e}"
