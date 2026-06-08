"""
Custom Httpx Tool - Web Probe and Tech Detect.
Path: Controlled by src.config.settings.tool_httpx_path (default 'httpx')
"""
from typing import Dict, Any, Optional, List, Union
import shlex
import logging
from src.tools.base import BaseTool
from src.tools import ToolRegistry
from src.config import settings
from src.core.utils.batch_utils import create_batch_file
from src.core.security.safe_subprocess import safe_run, SecurityViolationError

logger = logging.getLogger(__name__)

@ToolRegistry.register
class HttpxTool(BaseTool):
    """
    HTTPX web probing tool.
    
    Profiles:
    - fast: Title and status code only
    - standard: Tech detect + Status + Title
    - stealth: Random agent + Delay
    """
    
    name = "httpx"
    description = "Run httpx to probe web servers and detect technologies."
    
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
                            "description": "Target URL, Host, or CIDR"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["fast", "standard", "stealth", "screenshot"],
                            "description": "Scan profile",
                            "default": "standard"
                        },
                        "extra_args": {
                            "type": "string",
                            "description": "Additional flags (sanitized)"
                        }
                    },
                    "required": ["target"]
                }
            }
        }

    def run(self, target: Any, mode: str = "standard", proxy: Optional[str] = None, headers: Optional[List[str]] = None, extra_args: Optional[str] = None) -> str:
        """Execute httpx (ProjectDiscovery Go version)."""
        
        # ターゲットがリストの場合はバッチ処理
        if isinstance(target, list):
            with create_batch_file(target) as batch_path:
                if not batch_path:
                    return "Error: No valid targets after scope check."
                return self._run_httpx(batch_path, mode, proxy, headers, extra_args, is_batch=True)
        else:
            # 既存のファイル入力対応
            is_file = False
            if isinstance(target, str) and (target.startswith("/") or target.endswith(".txt")):
                is_file = True
            return self._run_httpx(target, mode, proxy, headers, extra_args, is_batch=is_file)

    def _run_httpx(self, target: str, mode: str, proxy: Optional[str], headers: Optional[List[str]], extra_args: Optional[str], is_batch: bool) -> str:
        """実際の実行ロジック"""
        cmd = [settings.tool_httpx_path, "-json", "-silent"]
        
        if is_batch:
            cmd += ["-l", target]
        else:
            cmd += ["-u", target]
            
        # Proxy対応
        if proxy:
            cmd += ["-http-proxy", proxy]
            
        # Headers対応
        if headers:
            for h in headers:
                cmd += ["-H", h]

        if mode == "fast":
            cmd += ["-title", "-status-code", "-threads", "50"]
        elif mode == "standard":
            cmd += ["-title", "-status-code", "-tech-detect", "-follow-redirects"]
        elif mode == "stealth":
            cmd += ["-title", "-status-code", "-random-agent", "-delay", "1s"]
        elif mode == "screenshot":
            cmd += ["-screenshot", "-system-chrome"]

        if extra_args:
            cmd += shlex.split(extra_args)

        try:
            result = safe_run(
                cmd,
                capture_output=True,
                timeout=600,
                check=False
            )
            return result.stdout or "No live hosts found."
        except SecurityViolationError as e:
            return f"Security Error: {e}"
        except Exception as e:
            return f"Error: {str(e)}"
