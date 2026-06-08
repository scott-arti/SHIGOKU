"""
Custom race-the-web Tool - Race Condition Detection via External Tool.
"""
from typing import Dict, Any, Optional
import subprocess
import json
import tempfile
import os
from src.tools.base import BaseTool
from src.tools import ToolRegistry


@ToolRegistry.register
class RaceTheWebTool(BaseTool):
    """
    race-the-web (RTW) for detecting race conditions in web applications.
    
    Sends concurrent requests and compares response uniqueness to identify race conditions.
    Useful for: double-spending, coupon abuse, limit bypass testing.
    
    Profiles:
    - quick: 10 concurrent requests
    - standard: 50 concurrent requests  
    - aggressive: 100 concurrent requests
    """
    
    name = "race_the_web"
    description = "Detect race conditions by sending concurrent requests and comparing responses."
    
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
                            "description": "Target URL to test"
                        },
                        "method": {
                            "type": "string",
                            "enum": ["GET", "POST", "PUT", "DELETE"],
                            "description": "HTTP method",
                            "default": "GET"
                        },
                        "body": {
                            "type": "string",
                            "description": "Request body (for POST/PUT)"
                        },
                        "headers": {
                            "type": "object",
                            "description": "Custom headers as key-value pairs"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["quick", "standard", "aggressive"],
                            "description": "Concurrency level",
                            "default": "standard"
                        },
                        "cookies": {
                            "type": "string",
                            "description": "Cookie string to include"
                        }
                    },
                    "required": ["url"]
                }
            }
        }

    def run(
        self,
        url: str,
        method: str = "GET",
        body: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        mode: str = "standard",
        cookies: Optional[str] = None
    ) -> str:
        # Set concurrency based on mode
        concurrency_map = {"quick": 10, "standard": 50, "aggressive": 100}
        count = concurrency_map.get(mode, 50)
        
        # Build config for race-the-web
        config = {
            "count": count,
            "verbose": True,
            "targets": [
                {
                    "url": url,
                    "method": method,
                    "body": body or "",
                    "cookies": cookies or "",
                    "headers": headers or {}
                }
            ]
        }
        
        # Write config to temp file
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            json.dump(config, f)
            config_path = f.name
        
        try:
            cmd = ["race-the-web", config_path]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120, check=False
            )
            
            output = result.stdout
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"
            
            # Parse output for race condition indicators
            if "unique" in output.lower() or "different" in output.lower():
                output = "⚠️ POTENTIAL RACE CONDITION DETECTED\n\n" + output
            else:
                output = "✅ No race condition detected\n\n" + output
            
            return output or "No output from race-the-web."
            
        except subprocess.TimeoutExpired:
            return "Error: race-the-web timed out."
        except FileNotFoundError:
            return "Error: race-the-web not installed. Install with: go install github.com/TheHackerDev/race-the-web@latest"
        except Exception as e:
            return f"Error: {e}"
        finally:
            # Cleanup temp file
            if os.path.exists(config_path):
                os.unlink(config_path)
