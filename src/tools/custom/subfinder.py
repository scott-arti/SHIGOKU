"""
Custom Subfinder Tool - Passive Subdomain Discovery.
"""
from typing import Dict, Any, Optional
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class SubfinderTool(BaseTool):
    """
    Subfinder subdomain discovery tool.
    
    Profiles:
    - fast: Single thread, top sources
    - standard: Default sources
    - all: All sources
    """
    
    name = "subfinder"
    description = "Passive subdomain discovery using subfinder."
    
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
                            "enum": ["fast", "standard", "all"],
                            "description": "Scan profile",
                            "default": "standard"
                        },
                         "extra_args": {
                            "type": "string",
                            "description": "Additional flags (sanitized)"
                        }
                    },
                    "required": ["domain"]
                }
            }
        }

    def run(self, domain: str, mode: str = "standard", extra_args: Optional[str] = None) -> str:
        cmd = ["subfinder", "-d", domain, "-json", "-silent"]
        
        if mode == "fast":
            cmd += ["-t", "10", "-max-time", "5"]
        elif mode == "standard":
            pass # Use defaults
        elif mode == "all":
            cmd += ["-all"]

        if extra_args:
            if any(char in extra_args for char in [";", "|", "&", "$", "`"]):
                 return "Error: Unsafe characters detected in extra_args."
            cmd += shlex.split(extra_args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                check=False
            )
            return result.stdout or "No subdomains found."
        except Exception as e:
            return f"Error: {str(e)}"
