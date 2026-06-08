"""
Custom Naabu Tool - Port Scanner.
"""
from typing import Dict, Any, Optional
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry
from src.config import settings

@ToolRegistry.register
class NaabuTool(BaseTool):
    """
    Naabu fast port scanner.
    """
    
    name = "naabu"
    description = "Fast port scanner (naabu). Can pipe to nmap for service versioning."
    
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
                            "description": "Target host or IP"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["fast", "full", "verify"],
                            "description": "Scan profile",
                            "default": "fast"
                        },
                        "nmap_integrate": {
                            "type": "boolean",
                            "description": "Run nmap on found ports (-nmap-cli)",
                            "default": False
                        },
                        "extra_args": {
                            "type": "string",
                            "description": "Additional naabu arguments"
                        }
                    },
                    "required": ["host"]
                }
            }
        }

    def run(self, host: str, mode: str = "fast", nmap_integrate: bool = False, extra_args: str = None) -> str:
        cmd = ["naabu", "-host", host, "-json", "-silent"]
        
        # Add threads based on config
        cmd += ["-t", str(getattr(settings.scan, "threads", 10))]
        
        if mode == "fast":
            # Top 100 ports default if no ports specified, but let's be explicit
            cmd += ["-top-ports", "100"] 
        elif mode == "full":
            cmd += ["-p", "-"] # All ports
        elif mode == "verify":
            cmd += ["-verify"] # Verify open ports
            
        if nmap_integrate:
            # Requires nmap installed
            cmd += ["-nmap-cli", "nmap -sV -sC"]
            
        if extra_args:
            cmd += shlex.split(extra_args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600, # 10 min
                check=False
            )
            return result.stdout or "No ports found."
        except Exception as e:
            return f"Error: {str(e)}"
