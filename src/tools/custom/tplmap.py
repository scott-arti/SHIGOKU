"""
Custom tplmap Tool - Server-Side Template Injection Detection.
"""
from typing import Dict, Any, Optional
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry


@ToolRegistry.register
class TplmapTool(BaseTool):
    """
    tplmap for SSTI (Server-Side Template Injection) detection and exploitation.
    
    Profiles:
    - detect: Detection only
    - exploit: Detection and exploitation
    """
    
    name = "tplmap"
    description = "Detect and exploit Server-Side Template Injection (SSTI) vulnerabilities."
    
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
                            "description": "Target URL with injection point (use * to mark)"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["detect", "exploit"],
                            "description": "Scan mode",
                            "default": "detect"
                        },
                        "engine": {
                            "type": "string",
                            "description": "Template engine to test (jinja2, mako, smarty, etc.)"
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

    def run(
        self,
        url: str,
        mode: str = "detect",
        engine: Optional[str] = None,
        extra_args: Optional[str] = None
    ) -> str:
        cmd = ["tplmap", "-u", url]
        
        if mode == "detect":
            cmd.append("--level=1")
        elif mode == "exploit":
            cmd += ["--level=5", "--os-shell"]

        if engine:
            if any(char in engine for char in [";", "|", "&", "$", "`"]):
                return "Error: Unsafe characters in engine parameter."
            cmd += ["-e", engine]

        if extra_args:
            if any(char in extra_args for char in [";", "|", "&", "$", "`"]):
                return "Error: Unsafe characters detected in extra_args."
            cmd += shlex.split(extra_args)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300, check=False
            )
            return result.stdout or "No SSTI vulnerability detected."
        except subprocess.TimeoutExpired:
            return "Error: tplmap timed out."
        except Exception as e:
            return f"Error: {e}"
