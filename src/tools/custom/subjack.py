"""
Custom Subjack Tool - Subdomain Takeover Scanner.
"""
from typing import Dict, Any, Optional
import subprocess
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class SubjackTool(BaseTool):
    """
    Subjack - Subdomain takeover vulnerability scanner.
    """
    
    name = "subjack"
    description = "Scan for subdomain takeover vulnerabilities."
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "subdomain_file": {
                            "type": "string",
                            "description": "File containing subdomains to check"
                        },
                        "fingerprints": {
                            "type": "string",
                            "description": "Path to fingerprints file (optional)"
                        }
                    },
                    "required": ["subdomain_file"]
                }
            }
        }

    def run(self, subdomain_file: str, fingerprints: Optional[str] = None) -> str:
        if any(c in subdomain_file for c in [";", "|", "&", "$", "`"]):
            return "Error: Unsafe characters."
        
        cmd = ["subjack", "-w", subdomain_file, "-t", "50", "-timeout", "30", "-ssl"]
        if fingerprints:
            if any(c in fingerprints for c in [";", "|", "&", "$", "`"]):
                return "Error: Unsafe characters in fingerprints path."
            cmd += ["-c", fingerprints]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
            return result.stdout or "No takeover vulnerabilities found."
        except Exception as e:
            return f"Error: {e}"
