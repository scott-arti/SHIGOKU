"""
Custom ShuffleDNS Tool - Mass DNS resolver and subdomain bruteforcer.
"""
from typing import Dict, Any, Optional
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class ShuffleDNSTool(BaseTool):
    """
    ShuffleDNS - Fast DNS resolver and subdomain bruteforcer.
    
    Profiles:
    - resolve: Resolve list of subdomains
    - bruteforce: Bruteforce with wordlist
    """
    
    name = "shuffledns"
    description = "Mass DNS resolution and subdomain bruteforcing."
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Target domain"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["resolve", "bruteforce"],
                            "description": "Operation mode",
                            "default": "resolve"
                        },
                        "wordlist": {
                            "type": "string",
                            "description": "Path to wordlist (for bruteforce mode)"
                        },
                        "resolver_list": {
                            "type": "string",
                            "description": "Path to resolver list"
                        }
                    },
                    "required": ["domain"]
                }
            }
        }

    def run(self, domain: str, mode: str = "resolve", 
            wordlist: Optional[str] = None, resolver_list: Optional[str] = None) -> str:
        
        # Default resolver list
        resolvers = resolver_list or "/usr/share/wordlists/resolvers.txt"
        
        cmd = ["shuffledns", "-d", domain, "-r", resolvers, "-silent"]
        
        if mode == "bruteforce":
            if not wordlist:
                return "Error: Wordlist required for bruteforce mode."
            # Sanitize wordlist path
            if any(c in wordlist for c in [";", "|", "&", "$", "`"]):
                return "Error: Unsafe characters in wordlist path."
            cmd += ["-w", wordlist]
        elif mode == "resolve":
            cmd += ["-o", "/tmp/shuffledns_resolved.txt"]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600, check=False
            )
            return result.stdout or "Resolution complete."
        except subprocess.TimeoutExpired:
            return "Error: DNS resolution timed out."
        except Exception as e:
            return f"Error: {e}"
