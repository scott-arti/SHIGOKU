"""
Custom Sqlmap Tool - SQL Injection Automation.
"""
from typing import Dict, Any
import subprocess
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class SqlmapTool(BaseTool):
    """
    Sqlmap automation tool.
    """
    
    name = "sqlmap"
    description = "Detect and exploit SQL injection flaws using sqlmap."
    
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
                            "description": "Target URL to scan"
                        },
                        "risk": {
                            "type": "integer",
                            "description": "Risk of tests to perform (1-3)",
                            "default": 1
                        },
                        "level": {
                            "type": "integer",
                            "description": "Level of tests to perform (1-5)",
                            "default": 1
                        },
                        "dbs": {
                            "type": "boolean",
                            "description": "Enumerate DBMS databases",
                            "default": False
                        }
                    },
                    "required": ["url"]
                }
            }
        }

    def run(self, url: str, risk: int = 1, level: int = 1, dbs: bool = False) -> str:
        # Max limits
        risk = min(max(risk, 1), 3)
        level = min(max(level, 1), 5)
        
        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--risk", str(risk),
            "--level", str(level)
        ]
        
        if dbs:
            cmd.append("--dbs")
            
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600, 
                check=False
            )
            return result.stdout or "No output."
        except subprocess.TimeoutExpired:
            return "Error: Sqlmap timed out."
        except Exception as e:
            return f"Error: {str(e)}"
