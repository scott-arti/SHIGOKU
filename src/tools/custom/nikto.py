"""
Custom Nikto Tool - Web Server Scanner.
"""
from typing import Dict, Any
import subprocess
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class NiktoTool(BaseTool):
    """
    Nikto web server scanner.
    """
    
    name = "nikto"
    description = "Scan web server for known vulnerabilities using Nikto."
    
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
                            "description": "Target URL or hostname"
                        },
                        "timeout_seconds": {
                            "type": "integer",
                            "description": "Max execution time",
                            "default": 600
                        }
                    },
                    "required": ["target"]
                }
            }
        }

    def run(self, target: str, timeout_seconds: int = 600) -> str:
        cmd = ["nikto", "-h", target]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False
            )
            return result.stdout or "No output."
        except subprocess.TimeoutExpired:
            return "Error: Nikto timed out."
        except Exception as e:
            return f"Error: {str(e)}"
