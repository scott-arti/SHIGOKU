"""
Custom BBOT Tool - Recursive Internet Scanner.
"""
from typing import Dict, Any, Optional
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class BBotTool(BaseTool):
    """
    BBOT - Recursive internet scanner for OSINT and attack surface mapping.
    
    Profiles:
    - subdomain-enum: Subdomain enumeration only
    - web-basic: Basic web scan
    - web-thorough: Comprehensive web scan
    """
    
    name = "bbot"
    description = "Recursive scanner for subdomain enumeration and web analysis."
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target domain or URL"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["subdomain-enum", "web-basic", "web-thorough"],
                            "description": "Scan profile",
                            "default": "subdomain-enum"
                        },
                        "extra_args": {
                            "type": "string",
                            "description": "Additional flags"
                        }
                    },
                    "required": ["target"]
                }
            }
        }

    def run(self, target: str, mode: str = "subdomain-enum", extra_args: Optional[str] = None) -> str:
        cmd = ["bbot", "-t", target, "-o", "/tmp/bbot_out", "-y"]
        
        if mode == "subdomain-enum":
            cmd += ["-p", "subdomain-enum"]
        elif mode == "web-basic":
            cmd += ["-p", "web-basic"]
        elif mode == "web-thorough":
            cmd += ["-p", "web-thorough"]

        if extra_args:
            if any(c in extra_args for c in [";", "|", "&", "$", "`"]):
                return "Error: Unsafe characters in extra_args."
            cmd += shlex.split(extra_args)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=1800, check=False
            )
            return result.stdout or result.stderr or "Scan complete. Check /tmp/bbot_out"
        except subprocess.TimeoutExpired:
            return "Error: Scan timed out (30 min limit)."
        except Exception as e:
            return f"Error: {e}"
