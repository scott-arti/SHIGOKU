"""
Custom GAU Tool - Get All URLs from Wayback Machine and more.
"""
from typing import Dict, Any, Optional
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class GAUTool(BaseTool):
    """
    GAU (Get All URLs) tool for historical URL discovery.
    
    Profiles:
    - fast: Basic providers only
    - standard: All providers
    - filtered: Filter by extensions
    """
    
    name = "gau"
    description = "Fetch known URLs from Wayback Machine, Common Crawl, etc."
    
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
                            "enum": ["fast", "standard", "filtered"],
                            "description": "Fetch profile",
                            "default": "standard"
                        },
                        "extra_args": {
                            "type": "string",
                            "description": "Additional flags"
                        }
                    },
                    "required": ["domain"]
                }
            }
        }

    def run(self, domain: str, mode: str = "standard", extra_args: Optional[str] = None) -> str:
        cmd = ["gau", "--subs", domain]
        
        if mode == "fast":
            cmd += ["--providers", "wayback"]
        elif mode == "standard":
            pass  # All providers by default
        elif mode == "filtered":
            cmd += ["--blacklist", "png,jpg,gif,css,woff,woff2,svg,ico"]

        if extra_args:
            if any(c in extra_args for c in [";", "|", "&", "$", "`"]):
                return "Error: Unsafe characters in extra_args."
            cmd += shlex.split(extra_args)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300, check=False
            )
            return result.stdout or "No URLs found."
        except subprocess.TimeoutExpired:
            return "Error: Fetch timed out."
        except Exception as e:
            return f"Error: {e}"
