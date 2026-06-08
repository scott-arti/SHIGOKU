"""
Custom SecretFinder Tool Integration.
"""
from typing import Dict, Any, Optional, List
import subprocess
import shlex
import logging
from src.tools.base import BaseTool
from src.tools import ToolRegistry

logger = logging.getLogger(__name__)

@ToolRegistry.register
class SecretFinderTool(BaseTool):
    """
    User's custom secretfinder tool integration.
    """
    
    name = "secret_finder"
    description = "Custom secret finder tool to scan for secrets with flexible argument support."
    
    # Update to use the new Antigravity SecretFinder tool
    TOOL_PYTHON = "/home/bbb/Documents/tools/SecretFinder/.venv/bin/python"
    TOOL_MODULE = "secretfinder.main"
    TOOL_DIR = "/home/bbb/Documents/tools/SecretFinder/src"

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
                            "description": "Target path, URL, or explicit file to scan"
                        },
                        "output_format": {
                            "type": "string",
                            "description": "Output format: 'cli', 'json', or 'html'",
                            "default": "json"
                        },
                        "extract_js": {
                            "type": "boolean",
                            "description": "Extract all JS links from page and scan them",
                            "default": False
                        },
                        "extra_args": {
                            "type": "string",
                            "description": "Additional arguments to pass to the tool"
                        }
                    },
                    "required": ["target"]
                }
            }
        }

    def run(
        self,
        target: str,
        output_format: str = "json",
        extract_js: bool = False,
        extra_args: Optional[str] = None,
        **kwargs
    ) -> Any:
        """
        Execute the custom secretfinder tool. Returns a parsed JSON object if format is json, otherwise returns string.
        """
        cmd = [self.TOOL_PYTHON, "-m", self.TOOL_MODULE, "-i", target, "-o", output_format]
        
        if extract_js:
            cmd.append("-e")
            
        if extra_args:
            args_list = shlex.split(extra_args)
            cmd += args_list
            
        logger.info("Executing: %s", ' '.join(cmd))
            
        import os
        env = os.environ.copy()
        env["PYTHONPATH"] = self.TOOL_DIR
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=300,
                env=env
            )
            
            output = result.stdout
            
            if output_format == "json":
                import json
                import re
                try:
                    # SecretFinder might append summary lines to stdout
                    # Try to extract just the JSON array or object
                    match = re.search(r'(\[.*\]|\{.*\})', output, re.DOTALL)
                    if match:
                        return json.loads(match.group(1))
                    return json.loads(output)
                except json.JSONDecodeError:
                    if result.stderr:
                        logger.error(f"[SecretFinder] Error: {result.stderr}")
                    return {"error": "Failed to parse JSON output", "raw": output}
                    
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"
                
            return output
            
        except FileNotFoundError:
            return f"Error: Python executable not found at {self.TOOL_PYTHON}. Please check the environment."
        except subprocess.TimeoutExpired:
            return "Error: Execution timed out."
    async def scan_text(self, text: str, url: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        文字列をインメモリでスキャン。subprocess を起動しないため高速。
        """
        import sys
        import os
        
        # ツールディレクトリを sys.path に追加して import 可能にする
        if self.TOOL_DIR not in sys.path:
            sys.path.append(self.TOOL_DIR)
            
        try:
            from secretfinder.core.scanner import scan_content
            # scan_content(content, url, ...)
            findings = scan_content(text, url or "memory://")
            
            # Finding (dataclass) を JSON シリアライズ可能な辞書に変換
            serializable_findings = []
            for f in findings:
                f_dict = {
                    "rule": f.rule_name,
                    "description": f.description,
                    "matched": f.matched,
                    "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    "confidence": f.confidence_score,
                    "line": f.line_number
                }
                serializable_findings.append(f_dict)
            return serializable_findings
        except Exception as e:
            logger.error("In-memory SecretFinder failed: %s", e)
            return []

    def _convert_finding_to_dict(self, finding: Any) -> Dict[str, Any]:
        """Convert a SecretFinder Finding object to a dict."""
        return {
            "rule": getattr(finding, "rule_name", "unknown"),
            "description": getattr(finding, "description", ""),
            "matched": getattr(finding, "matched", ""),
            "severity": str(getattr(finding, "severity", "UNKNOWN")),
            "confidence": getattr(finding, "confidence_score", 0),
            "line": getattr(finding, "line_number", 0)
        }
