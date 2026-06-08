"""
Custom Gospider Tool - Web Crawler for Security Testing.
"""
from typing import Dict, Any, Optional
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class GospiderTool(BaseTool):
    """
    Gospider web crawler tool.
    
    Profiles:
    - fast: Quick crawl with limited depth
    - standard: Balanced crawl
    - deep: Comprehensive crawl with JS rendering
    """
    
    name = "gospider"
    description = "Web crawler for discovering endpoints, JS files, and links."
    
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
                            "description": "Target URL to crawl"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["fast", "standard", "deep"],
                            "description": "Crawl profile",
                            "default": "standard"
                        },
                        "extra_args": {
                            "type": "string",
                            "description": "Additional flags (sanitized)"
                        }
                    },
                    "required": ["target"]
                }
            }
        }

    def run(self, target: str, mode: str = "standard", extra_args: Optional[str] = None) -> str:
        cmd = ["gospider", "-s", target, "-o", "/tmp/gospider_out", "--json"]
        
        if mode == "fast":
            cmd += ["-d", "1", "-c", "5", "-t", "5"]
        elif mode == "standard":
            cmd += ["-d", "2", "-c", "10", "-t", "10"]
        elif mode == "deep":
            cmd += ["-d", "5", "-c", "20", "-t", "20", "--js"]

        if extra_args:
            if any(c in extra_args for c in [";", "|", "&", "$", "`"]):
                return "Error: Unsafe characters in extra_args."
            cmd += shlex.split(extra_args)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600, check=False
            )
            return result.stdout or result.stderr or "Crawl complete. Check /tmp/gospider_out"
        except subprocess.TimeoutExpired:
            return "Error: Crawl timed out."
        except Exception as e:
            return f"Error: {e}"
