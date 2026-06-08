"""
Custom XXEinjector Tool - XXE Vulnerability Detection.
"""
from typing import Dict, Any, Optional
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry


@ToolRegistry.register
class XXEInjectorTool(BaseTool):
    """
    XXEinjector for XXE (XML External Entity) vulnerability detection and exploitation.
    
    Requires Ruby runtime. The tool is located at /opt/xxeinjector.
    """
    
    name = "xxeinjector"
    description = "Detect and exploit XXE (XML External Entity) vulnerabilities."
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": "Target host (e.g., http://target.com/endpoint)"
                        },
                        "request_file": {
                            "type": "string",
                            "description": "Path to file containing the HTTP request"
                        },
                        "path": {
                            "type": "string",
                            "description": "Path to read via XXE (e.g., /etc/passwd)",
                            "default": "/etc/passwd"
                        },
                        "oob_host": {
                            "type": "string",
                            "description": "Out-of-band host for receiving data (your IP)"
                        }
                    },
                    "required": ["host", "request_file"]
                }
            }
        }

    def run(
        self,
        host: str,
        request_file: str,
        path: str = "/etc/passwd",
        oob_host: Optional[str] = None
    ) -> str:
        cmd = [
            "ruby", "/opt/xxeinjector/XXEinjector.rb",
            "--host", host,
            "--file", request_file,
            "--path", path
        ]
        
        if oob_host:
            if any(char in oob_host for char in [";", "|", "&", "$", "`"]):
                return "Error: Unsafe characters in oob_host."
            cmd += ["--oob", oob_host]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300, check=False
            )
            output = result.stdout
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"
            return output or "No XXE vulnerability detected."
        except subprocess.TimeoutExpired:
            return "Error: XXEinjector timed out."
        except Exception as e:
            return f"Error: {e}"
