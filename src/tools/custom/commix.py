"""
Custom Commix Tool - Command Injection Detection and Exploitation.
"""
from typing import Dict, Any, Optional
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry


@ToolRegistry.register
class CommixTool(BaseTool):
    """
    Commix for automated command injection detection and exploitation.
    
    Profiles:
    - detect: Detection only (safe)
    - exploit: Full exploitation
    """
    
    name = "commix"
    description = "Detect and exploit command injection vulnerabilities."
    
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
                            "description": "Target URL"
                        },
                        "data": {
                            "type": "string",
                            "description": "POST data (optional)"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["detect", "exploit"],
                            "description": "Scan mode",
                            "default": "detect"
                        },
                        "level": {
                            "type": "integer",
                            "description": "Level of tests (1-3)",
                            "default": 1
                        }
                    },
                    "required": ["url"]
                }
            }
        }

    def run(
        self,
        url: str,
        data: Optional[str] = None,
        mode: str = "detect",
        level: int = 1
    ) -> str:
        level = min(max(level, 1), 3)  # Limit level
        cmd = ["commix", "-u", url, "--batch", "--level", str(level)]
        
        if data:
            if any(char in data for char in [";", "|", "&", "$", "`"]):
                return "Error: Unsafe characters in data parameter."
            cmd += ["--data", data]

        if mode == "exploit":
            cmd.append("--os-cmd=id")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300, check=False
            )
            return result.stdout or "No command injection vulnerability detected."
        except subprocess.TimeoutExpired:
            return "Error: commix timed out."
        except Exception as e:
            return f"Error: {e}"
