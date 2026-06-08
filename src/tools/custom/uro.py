"""
Custom URO Tool - URL Optimizer/Deduplicator.
"""
from typing import Dict, Any, Optional
import subprocess
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class UroTool(BaseTool):
    """
    URO - Deduplicate and optimize URL lists.
    
    Profiles:
    - standard: Basic deduplication
    - aggressive: Remove parameters and fragments
    """
    
    name = "uro"
    description = "Deduplicate and clean URL lists for efficient scanning."
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url_file": {
                            "type": "string",
                            "description": "Path to file containing URLs"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["standard", "aggressive"],
                            "default": "standard"
                        }
                    },
                    "required": ["url_file"]
                }
            }
        }

    def run(self, url_file: str, mode: str = "standard") -> str:
        if any(c in url_file for c in [";", "|", "&", "$", "`"]):
            return "Error: Unsafe characters in path."
        
        cmd = ["uro", "-i", url_file]
        if mode == "aggressive":
            cmd += ["-b"]  # Blacklist common extensions
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
            return result.stdout or "No URLs after filtering."
        except Exception as e:
            return f"Error: {e}"
