"""
Custom Nmap Tool - Network Exploration and Security Auditing.
"""
from typing import Dict, Any, List
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class NmapTool(BaseTool):
    """
    Nmap network scanning tool.
    Wrapper for the nmap binary with safety checks.
    """
    
    name = "nmap"
    description = "Execute Nmap network scans using predefined safety profiles."
    
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
                            "description": "Target IP or hostname"
                        },
                        "scan_type": {
                            "type": "string",
                            "enum": ["fast", "safe", "version", "full"],
                            "description": "Scan profile to execute",
                            "default": "safe"
                        },
                        "extra_args": {
                            "type": "string",
                            "description": "Optional extra arguments (carefully filtered)",
                            "default": ""
                        }
                    },
                    "required": ["target"]
                }
            }
        }

    def run(self, target: str, scan_type: str = "safe", extra_args: str = "") -> str:
        # Prevent command injection on target
        target = target.strip()
        if any(c in target for c in [";", "|", "&", "$", "`"]):
            return "Error: Invalid target format"

        # Construct base command based on profile
        cmd = ["nmap"]
        
        profiles = {
            "fast": ["-F", "-T4"],
            "safe": ["-sS", "-sV", "--top-ports", "1000", "-T3"],
            "version": ["-sV", "-sC", "-T3"],
            "full": ["-p-", "-sV", "-T3"]
        }
        
        selected_args = profiles.get(scan_type, profiles["safe"])
        cmd.extend(selected_args)
        
        # Add extra args if safe
        if extra_args:
            # Very basic allowlist for extra args to prevent abuse
            # Only allow flags starting with -
            safe_extras = []
            for arg in shlex.split(extra_args):
                if arg.startswith("-") and not any(c in arg for c in [";", "|", "&", "$", "`"]):
                    safe_extras.append(arg)
            cmd.extend(safe_extras)
            
        cmd.append(target)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600, # 10 mins timeout
                check=False
            )
            
            output = result.stdout
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"
            return output
            
        except subprocess.TimeoutExpired:
            return "Error: Nmap scan timed out."
        except Exception as e:
            return f"Error: {str(e)}"
