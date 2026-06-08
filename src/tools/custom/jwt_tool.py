"""
Custom jwt_tool - JWT Analysis and Attack Tool.
"""
from typing import Dict, Any, Optional
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry


@ToolRegistry.register
class JWTToolTool(BaseTool):
    """
    jwt_tool for JWT token analysis, testing, and exploitation.
    
    Profiles:
    - scan: Analyze and check for vulnerabilities
    - crack: Attempt to crack the secret
    - forge: Forge a new token (requires secret)
    """
    
    name = "jwt_tool"
    description = "Analyze, test, and exploit JWT tokens."
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "token": {
                            "type": "string",
                            "description": "JWT token to analyze"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["scan", "crack", "forge"],
                            "description": "Operation mode",
                            "default": "scan"
                        },
                        "wordlist": {
                            "type": "string",
                            "description": "Wordlist for cracking (mode=crack)"
                        },
                        "secret": {
                            "type": "string",
                            "description": "Known secret for forging (mode=forge)"
                        },
                        "target_url": {
                            "type": "string",
                            "description": "Target URL for testing the token"
                        }
                    },
                    "required": ["token"]
                }
            }
        }

    def run(
        self,
        token: str,
        mode: str = "scan",
        wordlist: Optional[str] = None,
        secret: Optional[str] = None,
        target_url: Optional[str] = None
    ) -> str:
        cmd = ["jwt_tool", token]
        
        if mode == "scan":
            cmd.append("-a")  # All tests
        elif mode == "crack":
            if wordlist:
                cmd += ["-C", "-d", wordlist]
            else:
                cmd += ["-C", "-d", "/usr/share/wordlists/rockyou.txt"]
        elif mode == "forge":
            if secret:
                cmd += ["-S", "hs256", "-p", secret]
            else:
                return "Error: Secret required for forge mode."

        if target_url:
            if any(char in target_url for char in [";", "|", "&", "$", "`"]):
                return "Error: Unsafe characters in target_url."
            cmd += ["-t", target_url]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600, check=False
            )
            return result.stdout or "JWT analysis complete."
        except subprocess.TimeoutExpired:
            return "Error: jwt_tool timed out."
        except Exception as e:
            return f"Error: {e}"
