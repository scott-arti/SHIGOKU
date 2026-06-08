"""
Custom Katana Tool - Next-gen Web Crawler by ProjectDiscovery.
"""
from typing import Dict, Any, Optional
import subprocess
import shlex
import logging
import time
from src.tools.base import BaseTool
from src.tools import ToolRegistry

logger = logging.getLogger(__name__)

@ToolRegistry.register
class KatanaTool(BaseTool):
    """
    Katana web crawler tool.
    
    Profiles:
    - fast: Quick passive crawl
    - standard: Balanced crawl with form filling
    - headless: Full headless browser crawl
    """
    
    name = "katana"
    description = "Advanced web crawler with headless browser support."
    
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
                            "description": "Target URL"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["fast", "standard", "headless"],
                            "description": "Crawl profile",
                            "default": "standard"
                        },
                        "extra_args": {
                            "type": "string",
                            "description": "Additional flags"
                        }
                    },
                    "required": ["target"]
                }
            }
        }

    def run(self, target: str, mode: str = "standard", proxy: Optional[str] = None, headers: Optional[list[str]] = None, cookies: Optional[str] = None, extra_args: Optional[str] = None) -> str:
        cmd = ["katana", "-jsonl", "-silent", "-form-extraction"]  # -jsonl for Katana v1.4.0+

        # ファイル入力対応
        if target.startswith("/") or target.endswith(".txt"):
            cmd += ["-list", target]
        else:
            cmd += ["-u", target]
        
        # Proxy対応
        if proxy:
            cmd += ["-proxy", proxy]
            
        # Headers対応
        if headers:
            for h in headers:
                cmd += ["-H", h]
        
        # Cookies対応
        if cookies:
            cmd += ["-H", f"Cookie: {cookies}"]

        # headers/cookies が渡されている場合は認証済みセッションとみなし、form-fill を無効化
        has_auth = bool(headers or cookies)
        
        if mode == "fast":
            cmd += ["-d", "1", "-c", "10", "-p", "10"]
        elif mode == "standard":
            cmd += ["-d", "3", "-c", "20", "-p", "20"]
            # 認証済みの場合は -automatic-form-fill を使用しない (セッション破壊を防ぐ)
            if not has_auth:
                cmd += ["-automatic-form-fill"]
        elif mode == "authenticated":
            # 認証済みセッション専用: Form Fill なし
            cmd += ["-d", "3", "-c", "20", "-p", "20"]
        elif mode == "headless":
            # headless モードでは -no-sandbox が必要
            # -jc (JS parsing), -jsluicy (Advanced JS analysis) を追加
            cmd += [
                "-headless", "-system-chrome", "-no-sandbox",
                "-jc", "-jsluice", "-xhr-extraction",
                "-ho", "--ignore-certificate-errors",
                "-d", "3", "-c", "20", "-p", "20"
            ]

        # Exclude logout/login URLs to prevent session invalidation and CSRF errors
        # -cos (crawl-out-scope) prevents crawling of matching patterns
        # security=medium 以上でログインフォームへの POST を防止 (CSRF トークンエラー回避)
        cmd += ["-cos", "(logout|signout|exit|log-out|login)"]

        if extra_args:
            if any(c in extra_args for c in [";", "|", "&", "$", "`"]):
                return "Error: Unsafe characters in extra_args."
            cmd += shlex.split(extra_args)

        try:
            logger.debug("Katana command: %s", " ".join(cmd))

            command_timeout_sec = 900
            heartbeat_interval_sec = 15
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            start_time = time.monotonic()
            stdout = ""
            stderr = ""
            while True:
                elapsed = time.monotonic() - start_time
                remaining = command_timeout_sec - elapsed
                if remaining <= 0:
                    process.kill()
                    process.communicate()
                    return "Error: Crawl timed out."

                wait_seconds = min(heartbeat_interval_sec, max(1, int(remaining)))
                try:
                    stdout, stderr = process.communicate(timeout=wait_seconds)
                    break
                except subprocess.TimeoutExpired:
                    logger.info(
                        "Katana heartbeat: running target=%s mode=%s elapsed=%ds",
                        target,
                        mode,
                        int(time.monotonic() - start_time),
                    )

            if stderr:
                logger.warning("Katana stderr: %s", stderr[:500])

            return stdout or ""
        except Exception as e:
            return f"Error: {e}"
