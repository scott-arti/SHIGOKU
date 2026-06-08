"""
Custom Hydra Tool - Login Cracker.
"""
from typing import Dict, Any
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class HydraTool(BaseTool):
    """
    Hydra login cracker tool.
    Wrapper for the hydra binary.
    """
    
    name = "hydra"
    description = "Execute Hydra brute-force attacks against network services."
    
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
                            "description": "Target IP/Hostname or URL"
                        },
                        "service": {
                            "type": "string",
                            "description": "Protocol/Service (ssh, ftp, http-post-form, etc.)",
                            "default": "ssh"
                        },
                        "user_list": {
                            "type": "string",
                            "description": "Path to username list (absolute path) or single user via '-l user'",
                            "default": ""
                        },
                        "pass_list": {
                            "type": "string",
                            "description": "Path to password list (absolute path)",
                            "default": ""
                        },
                        "login_user": {
                            "type": "string",
                            "description": "Single username to attack (alternative to user_list)",
                            "default": ""
                        }
                    },
                    "required": ["target", "service", "pass_list"]
                }
            }
        }

    def run(self, target: str, service: str, pass_list: str, user_list: str = "", login_user: str = "") -> str:
        # Input validation
        if not target or not service or not pass_list:
            return "Error: specific arguments required."
        
        cmd = ["hydra"]
        
        # User selection
        if login_user:
            cmd.extend(["-l", login_user])
        elif user_list:
            cmd.extend(["-L", user_list])
        else:
            return "Error: Either user_list or login_user must be specified."
            
        cmd.extend(["-P", pass_list])
        
        # Service specific handling
        # http-post-form requires special formatting in target often, but basic wrapper here
        # assumes target is host and service handles the rest or target contains necessary info
        
        cmd.append(target)
        cmd.append(service)
        
        # Safety / Timeouts
        cmd.extend(["-t", "4"]) # Limit tasks to 4 to be gentle
        cmd.extend(["-W", "1"]) # Wait time
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300, # 5 min timeout
                check=False
            )
            return result.stdout or "No results or failed execution."
        except subprocess.TimeoutExpired:
            return "Error: Hydra timed out."
        except Exception as e:
            return f"Error: {str(e)}"
