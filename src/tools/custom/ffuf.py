"""
Custom ffuf Tool - Enhanced version with AI, Fast mode, and Stealth features.
Path: /home/bbb/go/bin/ffuf
"""
from typing import Dict, Any, Optional
import subprocess
import shlex

from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class FfufTool(BaseTool):
    """
    カスタム改造版 ffuf を使用するツール。
    
    独自機能:
    - Fast Mode: valyala/fasthttp による高速化 (-runner-type fast)
    - AI Smart Prepend: URLからキーワード自動生成 (-ai)
    - AI Semantic Filter: Soft404をAI判定 (-ai)
    - UA Rotate: User-Agent ランダム化 (-ua-rotate)
    - IP Spoof: X-Forwarded-For 等にランダムIP (-spoof-ip)
    """
    
    name = "ffuf"
    description = """Fuzz URLs for hidden directories, files, or parameters using the enhanced ffuf tool.
    
Custom Features Available:
- Fast mode (-runner-type fast): 3.4x faster, 87% less memory
- AI mode (-ai): Auto-generate keywords from target URL & filter soft-404s
- UA rotation (-ua-rotate): Randomize User-Agent for WAF bypass
- IP spoofing (-spoof-ip): Add random X-Forwarded-For for WAF bypass

Use these features for bug bounty and penetration testing."""

    FFUF_PATH = "/home/bbb/Documents/tools/ffuf/ffuf"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # BaseTool は object 直属のため config を渡さない
        # 修正: バイナリが存在しない場合のフォールバック
        import os
        if not os.path.exists(self.FFUF_PATH):
            import shutil
            fallback = shutil.which("ffuf") or "/home/bbb/go/bin/ffuf"
            self.FFUF_PATH = fallback

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
                            "description": "Target URL with FUZZ keyword (e.g., http://target.com/FUZZ)"
                        },
                        "wordlist": {
                            "type": "string",
                            "description": "Path to wordlist file (e.g., /usr/share/seclists/Discovery/Web-Content/common.txt)"
                        },
                        "extensions": {
                            "type": "string",
                            "description": "File extensions to append (e.g., 'php,html,txt')"
                        },
                        "fast_mode": {
                            "type": "boolean",
                            "description": "Enable fast HTTP mode using valyala/fasthttp. 3x faster than standard mode. Recommended for large wordlists."
                        },
                        "ai_mode": {
                            "type": "boolean",
                            "description": "Enable AI features: smart keyword prepend (predicting technology stack) and semantic soft-404 filter."
                        },
                        "ai_provider": {
                            "type": "string",
                            "description": "AI provider: 'openai' (default) or custom provider name."
                        },
                        "ai_model": {
                            "type": "string",
                            "description": "AI model to use (e.g., 'gpt-4o', 'deepseek/deepseek-chat')."
                        },
                        "ai_endpoint": {
                            "type": "string",
                            "description": "Custom AI API endpoint."
                        },
                        "ua_rotate": {
                            "type": "boolean",
                            "description": "Enable automatic User-Agent rotation to bypass WAF/rate-limiting."
                        },
                        "spoof_ip": {
                            "type": "boolean",
                            "description": "Enable IP spoofing via X-Forwarded-For and other headers to bypass IP-based blocks."
                        },
                        "threads": {
                            "type": "integer",
                            "description": "Number of concurrent threads (default: 40). Increase for speed if target allowed."
                        },
                        "filter_code": {
                            "type": "string",
                            "description": "Filter out responses by status code (e.g., '404,403')."
                        },
                        "match_code": {
                            "type": "string",
                            "description": "Match responses by status code (e.g., '200,301,302,403')."
                        },
                        "extra_args": {
                            "type": "string",
                            "description": "Any additional FFUF arguments as a raw string."
                        }
                    },
                    "required": ["url", "wordlist"]
                }
            }
        }

    def _resolve_wordlist_path(self, requested_path: str) -> str:
        """
        Wordlistパスを環境に応じて自動解決
        
        検索順序:
        1. 指定パスそのまま
        2. /wordlists/ (Docker mount)
        3. /app/wordlists/ (Project local)
        4. ~/wordlists/ (User home)
        
        Args:
            requested_path: リクエストされたワードリストパス
            
        Returns:
            解決されたパス（見つからない場合は元のパスを返す）
        """
        from pathlib import Path
        
        # 1. 指定パスをそのまま試す
        if Path(requested_path).exists():
            return requested_path
        
        # ファイル名のみを取得
        filename = Path(requested_path).name
        
        # 検索候補
        candidates = [
            Path("/wordlists") / filename,  # Docker mount
            Path("/app/wordlists") / filename,  # Project local
            Path.home() / "wordlists" / filename,  # User home dir
            Path(__file__).parent.parent.parent.parent / "wordlists" / filename,  # Relative to project root
        ]
        
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        
        # 見つからない場合は元のパスを返す（エラーは実行時に発生）
        return requested_path

    def run(
        self,
        url: str,
        wordlist: str,
        extensions: Optional[str] = None,
        fast_mode: bool = False,
        ai_mode: bool = False,
        ai_provider: Optional[str] = None,
        ai_model: Optional[str] = None,
        ai_endpoint: Optional[str] = None,
        ua_rotate: bool = False,
        spoof_ip: bool = False,
        threads: Optional[int] = None,
        filter_code: Optional[str] = None,
        match_code: Optional[str] = None,
        extra_args: Optional[str] = None
    ) -> str:
        """Execute custom ffuf with specified options."""
        
        # Wordlistパスを解決
        wordlist = self._resolve_wordlist_path(wordlist)
        
        cmd = [self.FFUF_PATH, "-u", url, "-w", wordlist]
        
        # Extensions
        if extensions:
            cmd += ["-e", extensions]
        
        # Fast mode
        if fast_mode:
            cmd += ["-runner-type", "fast"]
        
        # AI mode
        if ai_mode:
            cmd.append("-ai")
            if ai_provider:
                cmd += ["-ai-provider", ai_provider]
            if ai_model:
                cmd += ["-ai-model", ai_model]
            if ai_endpoint:
                cmd += ["-ai-endpoint", ai_endpoint]
        
        # Stealth features
        if ua_rotate:
            cmd.append("-ua-rotate")
        if spoof_ip:
            cmd.append("-spoof-ip")
        
        # Performance
        if threads:
            cmd += ["-t", str(threads)]
        
        # Filters
        if filter_code:
            cmd += ["-fc", filter_code]
        if match_code:
            cmd += ["-mc", match_code]
        
        # Extra args
        if extra_args:
            cmd += shlex.split(extra_args)
        
        # Execute
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 min timeout
                check=False
            )
            output = result.stdout
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"
            return output if output else "No output from ffuf."
        except subprocess.TimeoutExpired:
            return "Error: ffuf timed out after 10 minutes."
        except FileNotFoundError:
            return f"Error: ffuf not found at {self.FFUF_PATH}"
        except Exception as e: # pylint: disable=broad-except
            return f"Error running ffuf: {str(e)}"
