import subprocess
from typing import Dict, Any
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class LinuxCmd(BaseTool):
    """任意のLinuxコマンドを実行するツール"""
    name = "linux_cmd"
    
    # Internal Allowlist - Enhanced for VAPT
    ALLOW_LIST = [
        # File Operations
        "mkdir", "touch", "ls", "cat", "grep", "head", "tail", "wc", "find", "mv", "cp", "rm", "chmod",
        # Network Tools
        "curl", "wget", "ping", "dig", "whois", "nslookup", "host",
        # Development/Scripting
        "python", "python3", "git", "node", "npm", "go",
        # VAPT Tools (if called directly via shell)
        "nuclei", "httpx", "subfinder", "naabu", "notify", "sqlmap", "nmap", "hydra",
        "ffuf", "nikto", "commix", "tplmap", "wafw00f", "amass", "gau", "katana", "subjack",
        # System Info (for PoC)
        "whoami", "id", "uname", "hostname",
        # Utilities
        "jq", "awk", "sed", "echo", "base64", "openssl", "xargs", "tar", "unzip", "gzip"
    ]

    description = (
        f"Execute Linux shell commands. Allowed: {', '.join(ALLOW_LIST)}. "
        "NOTE: Do NOT use this tool for 'nuclei', 'nmap', 'ffuf', 'httpx'. "
        "Use the dedicated 'nuclei', 'nmap', 'ffuf' tools instead for better results."
    )
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": f"Shell command to execute. Must start with one of: {', '.join(self.ALLOW_LIST)}"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Command timeout in seconds (default: 30)",
                            "default": 30
                        }
                    },
                    "required": ["command"]
                }
            }
        }
    
    def run(self, command: str, timeout: int = 30) -> str:
        """
        Execute a shell command with timeout and error handling.
        
        Args:
            command: Shell command to execute
            timeout: Maximum execution time in seconds
            
        Returns:
            Command output (stdout + stderr)
        """
        
        # 1. Basic Token Validation
        command = command.strip()
        if not command:
            return "Error: Empty command"
            
        base_cmd = command.split()[0]
        
        # 2. Allowlist Check
        if base_cmd not in self.ALLOW_LIST:
             return (
                 f"🛡️ BLOCKED: '{base_cmd}' is not in the allowed command list.\n"
                 f"Allowed commands: {', '.join(self.ALLOW_LIST)}\n"
                 f"For specialized tools, please use the specific tool interface if available."
             )
        
        # 3. Execution
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd="/tmp"  # Restrict to /tmp for safety
            )
            
            output = result.stdout
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"
            
            if result.returncode != 0:
                output += f"\n[EXIT CODE: {result.returncode}]"
            
            return output
            
        except subprocess.TimeoutExpired:
            return f"Error: Command timed out after {timeout} seconds"
        except Exception as e:
            return f"Error executing command: {str(e)}"
