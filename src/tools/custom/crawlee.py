"""
Custom Crawlee Tool - Powerful Web Scraper/Crawler (Node.js based).
Note: Requires Node.js and crawlee package installed.
This wrapper calls a pre-built crawlee script.
"""
from typing import Dict, Any
import subprocess
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class CrawleeTool(BaseTool):
    """
    Crawlee - Advanced web scraper with Playwright/Puppeteer support.
    Note: Requires a crawlee script at /usr/local/bin/crawlee-runner or custom path.
    """
    
    name = "crawlee"
    description = "Advanced web crawler with JS rendering (Node.js based)."
    
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
                            "description": "Start URL to crawl"
                        },
                        "max_pages": {
                            "type": "integer",
                            "description": "Maximum pages to crawl",
                            "default": 50
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["basic", "playwright"],
                            "default": "basic"
                        }
                    },
                    "required": ["url"]
                }
            }
        }

    def run(self, url: str, max_pages: int = 50, mode: str = "basic") -> str:
        if any(c in url for c in [";", "|", "&", "$", "`"]):
            return "Error: Unsafe characters."
        
        # This assumes a wrapper script exists. 
        # In production, you'd either call npx or a custom script.
        cmd = ["npx", "crawlee-cli", "run", "--url", url, "--max-requests", str(max_pages)]
        if mode == "playwright":
            cmd += ["--crawler-type", "playwright"]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200, check=False)
            return result.stdout or result.stderr or "Crawl complete."
        except FileNotFoundError:
            return "Error: Node.js/npx not installed or crawlee-cli not available."
        except Exception as e:
            return f"Error: {e}"
