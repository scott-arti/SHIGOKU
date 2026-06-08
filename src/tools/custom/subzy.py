"""
Custom Subzy Tool - Subdomain Takeover Detection.
"""
from typing import Dict, Any, Optional
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry


@ToolRegistry.register
class SubzyTool(BaseTool):
    """
    Subzy for subdomain takeover vulnerability detection.
    
    Profiles:
    - single: Check single target
    - list: Check from file
    """
    
    name = "subzy"
    description = "Detect subdomain takeover vulnerabilities."
    
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
                            "description": "Single subdomain or path to file with subdomains"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["single", "list"],
                            "description": "Scan mode",
                            "default": "single"
                        },
                        "concurrency": {
                            "type": "integer",
                            "description": "Number of concurrent checks",
                            "default": 10
                        }
                    },
                    "required": ["target"]
                }
            }
        }

    def run(self, target: str, mode: str = "single", concurrency: int = 10) -> str:
        concurrency = min(max(concurrency, 1), 50)  # Limit concurrency
        
        if mode == "single":
            cmd = ["subzy", "run", "--target", target, "--concurrency", str(concurrency)]
        else:
            cmd = ["subzy", "run", "--targets", target, "--concurrency", str(concurrency)]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300, check=False
            )
            output = result.stdout
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"
            return output or "No takeover vulnerabilities found."
        except subprocess.TimeoutExpired:
            return "Error: subzy timed out."
        except Exception as e:
            return f"Error: {e}"
