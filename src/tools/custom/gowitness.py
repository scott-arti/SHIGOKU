"""
Custom Gowitness Tool - Web Screenshot Tool.
"""
from typing import Dict, Any, Optional
import subprocess
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class GowitnessTool(BaseTool):
    """
    Gowitness - Take screenshots of web pages.
    """
    
    name = "gowitness"
    description = "Take screenshots of web pages for visual reconnaissance."
    
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
                            "description": "Single URL or file with URLs"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["single", "file", "nmap"],
                            "default": "single"
                        },
                        "output_dir": {
                            "type": "string",
                            "description": "Output directory",
                            "default": "/tmp/gowitness"
                        }
                    },
                    "required": ["target"]
                }
            }
        }

    def run(self, target: str, mode: str = "single", output_dir: str = "/tmp/gowitness") -> str:
        if any(c in target for c in [";", "|", "&", "$", "`"]):
            return "Error: Unsafe characters."
        
        cmd = ["gowitness"]
        if mode == "single":
            cmd += ["single", target]
        elif mode == "file":
            cmd += ["file", "-f", target]
        elif mode == "nmap":
            cmd += ["nmap", "-f", target]
        
        cmd += ["-P", output_dir]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
            return f"Screenshots saved to {output_dir}. {result.stdout}"
        except Exception as e:
            return f"Error: {e}"
