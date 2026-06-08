"""
Custom git-dumper Tool - Exposed .git Directory Extraction.
"""
from typing import Dict, Any
import subprocess
from src.tools.base import BaseTool
from src.tools import ToolRegistry


@ToolRegistry.register
class GitDumperTool(BaseTool):
    """
    git-dumper for extracting exposed .git directories from web servers.
    
    Use case: When a web server accidentally exposes /.git directory,
    this tool can reconstruct the entire repository.
    """
    
    name = "git_dumper"
    description = "Extract exposed .git directories from web servers."
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL (e.g., http://example.com/.git)"
                        },
                        "output_dir": {
                            "type": "string",
                            "description": "Output directory for extracted repo",
                            "default": "/workspace/git_dump"
                        }
                    },
                    "required": ["url"]
                }
            }
        }

    def run(self, url: str, output_dir: str = "/workspace/git_dump") -> str:
        # Ensure URL ends with /.git or /.git/
        if not url.rstrip("/").endswith(".git"):
            url = url.rstrip("/") + "/.git"
        
        cmd = [
            "python3", "/opt/git-dumper/git_dumper.py",
            url,
            output_dir
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600, check=False
            )
            output = result.stdout
            if result.returncode == 0:
                output += f"\n\nRepository extracted to: {output_dir}"
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"
            return output or "No .git directory found or extraction failed."
        except subprocess.TimeoutExpired:
            return "Error: git-dumper timed out."
        except Exception as e:
            return f"Error: {e}"
