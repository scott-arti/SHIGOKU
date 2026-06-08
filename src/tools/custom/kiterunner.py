"""
Custom Kiterunner Tool - API Discovery Tool.
"""
from typing import Dict, Any, Optional
import subprocess
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class KiterunnerTool(BaseTool):
    """
    Kiterunner - Context-aware API discovery tool.
    """
    
    name = "kiterunner"
    description = "Discover API endpoints using curated wordlists."
    
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
                            "description": "Target URL"
                        },
                        "wordlist": {
                            "type": "string",
                            "description": "Wordlist to use (kite format)",
                            "default": "routes-small.kite"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["scan", "brute"],
                            "default": "scan"
                        }
                    },
                    "required": ["target"]
                }
            }
        }

    def run(self, target: str, wordlist: str = "routes-small.kite", mode: str = "scan") -> str:
        if any(c in target for c in [";", "|", "&", "$", "`"]):
            return "Error: Unsafe characters."
        
        cmd = ["kr", mode, target, "-w", wordlist, "-o", "json"]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=900, check=False)
            return result.stdout or "No API endpoints found."
        except FileNotFoundError:
            return "Error: kiterunner (kr) not installed."
        except Exception as e:
            return f"Error: {e}"
