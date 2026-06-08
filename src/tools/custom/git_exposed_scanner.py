"""
Git Exposed Scanner - .git ディレクトリ公開検出ツール

.git/config, .git/HEAD 等へのアクセス可否を確認し、
ソースコード漏洩の可能性を検出する。
"""
from typing import Dict, Any, List, Optional
import subprocess
import json
from src.tools.base import BaseTool
from src.tools import ToolRegistry


@ToolRegistry.register
class GitExposedScannerTool(BaseTool):
    """
    GitExposedScanner - .git ディレクトリ公開検出ツール
    
    既知の .git 関連パスへのアクセスを試行し、
    リポジトリ情報が公開されているかを検出する。
    検出した場合は git_dumper との連携を推奨。
    """
    
    name = "git_exposed_scanner"
    description = "Detect exposed .git directories on web servers. Non-destructive read-only scan."
    
    # チェック対象パス（優先度順）
    GIT_PATHS = [
        "/.git/config",
        "/.git/HEAD",
        "/.git/index",
        "/.git/objects/",
        "/.git/refs/heads/",
        "/.git/logs/HEAD",
        "/.git/COMMIT_EDITMSG",
        "/.git/description",
    ]
    
    # .git/config 内の典型的パターン
    GIT_CONFIG_PATTERNS = [
        "[core]",
        "[remote",
        "[branch",
        "repositoryformatversion",
    ]
    
    # .git/HEAD の典型的パターン
    GIT_HEAD_PATTERNS = [
        "ref: refs/heads/",
        "ref: refs/",
    ]

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
                            "description": "Target URL (e.g., https://example.com)"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Timeout per request in seconds",
                            "default": 10
                        },
                        "follow_redirects": {
                            "type": "boolean",
                            "description": "Follow HTTP redirects",
                            "default": False
                        }
                    },
                    "required": ["target"]
                }
            }
        }

    def run(
        self, 
        target: str = "", 
        timeout: int = 10,
        follow_redirects: bool = False,
        **kwargs
    ) -> str:
        """
        .git ディレクトリ公開をスキャン
        
        Args:
            target: ターゲットURL
            timeout: リクエストタイムアウト（秒）
            follow_redirects: リダイレクトを追跡するか
            
        Returns:
            JSON形式の検出結果
        """
        # 入力バリデーション
        if not target:
            return json.dumps({"error": "Target URL is required"})
        
        # URLサニタイズ
        target = target.rstrip("/")
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        
        # 危険な文字チェック
        if any(c in target for c in [";", "|", "&", "$", "`", "\n", "\r"]):
            return json.dumps({"error": "Unsafe characters in target URL"})
        
        timeout = min(max(timeout, 1), 60)  # 1-60秒に制限
        
        results: List[Dict[str, Any]] = []
        exposed = False
        
        for path in self.GIT_PATHS:
            url = f"{target}{path}"
            result = self._check_path(url, timeout, follow_redirects)
            
            if result["exposed"]:
                exposed = True
                results.append(result)
        
        # 結果サマリ
        summary = {
            "target": target,
            "exposed": exposed,
            "checked_paths": len(self.GIT_PATHS),
            "exposed_paths": [r["path"] for r in results if r["exposed"]],
            "details": results,
            "recommendation": (
                "CRITICAL: .git directory is exposed! "
                "Use git_dumper tool to extract and analyze the repository."
                if exposed else
                "No exposed .git directory detected."
            )
        }
        
        return json.dumps(summary, indent=2)

    def _check_path(
        self, 
        url: str, 
        timeout: int,
        follow_redirects: bool
    ) -> Dict[str, Any]:
        """
        単一パスをチェック
        """
        # httpx を使用（既存ツール）
        cmd = [
            "httpx",
            "-silent",
            "-no-color",
            "-timeout", str(timeout),
            "-status-code",
            "-content-length",
            "-content-type",
            "-title",
            "-u", url
        ]
        
        if not follow_redirects:
            cmd.append("-no-follow-redirects")
        
        path = url.split(url.rsplit("/", 1)[0])[-1] if "/" in url else url
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 5,
                check=False
            )
            
            output = result.stdout.strip()
            
            # httpx出力解析
            if not output:
                return {
                    "path": path,
                    "exposed": False,
                    "status": None,
                    "reason": "No response"
                }
            
            # ステータスコード抽出
            status_code = None
            content_length = None
            content_type = None
            
            parts = output.split()
            for i, part in enumerate(parts):
                if part.isdigit() and 100 <= int(part) <= 599:
                    status_code = int(part)
                    break
            
            # 200系レスポンスの場合、内容を確認
            if status_code and 200 <= status_code < 300:
                # 実際のコンテンツを取得して検証
                is_git_content = self._verify_git_content(url, path, timeout)
                
                return {
                    "path": path,
                    "exposed": is_git_content,
                    "status": status_code,
                    "reason": "Git content detected" if is_git_content else "200 but not git content"
                }
            
            return {
                "path": path,
                "exposed": False,
                "status": status_code,
                "reason": f"Non-200 status: {status_code}"
            }
            
        except subprocess.TimeoutExpired:
            return {
                "path": path,
                "exposed": False,
                "status": None,
                "reason": "Timeout"
            }
        except FileNotFoundError:
            return {
                "path": path,
                "exposed": False,
                "status": None,
                "reason": "httpx not installed"
            }
        except Exception as e:
            return {
                "path": path,
                "exposed": False,
                "status": None,
                "reason": f"Error: {str(e)}"
            }

    def _verify_git_content(
        self, 
        url: str, 
        path: str,
        timeout: int
    ) -> bool:
        """
        レスポンス内容が実際に .git コンテンツかを検証
        """
        try:
            # curl でコンテンツ取得（より信頼性が高い）
            cmd = [
                "curl",
                "-s",
                "-m", str(timeout),
                "--max-filesize", "1048576",  # 1MB制限
                url
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 5,
                check=False
            )
            
            content = result.stdout
            
            if not content:
                return False
            
            # パスに応じたパターンマッチ
            if "config" in path:
                return any(p in content for p in self.GIT_CONFIG_PATTERNS)
            
            if "HEAD" in path:
                return any(p in content for p in self.GIT_HEAD_PATTERNS)
            
            if "index" in path:
                # .git/index はバイナリだが、先頭に "DIRC" マジックバイトがある
                return content.startswith("DIRC") or b"DIRC" in content.encode("latin-1", errors="ignore")[:4]
            
            if "objects" in path or "refs" in path:
                # ディレクトリリスティングまたは403でもアクセス可能と判断
                return True
            
            if "COMMIT_EDITMSG" in path or "logs" in path:
                # コミットメッセージやログはテキスト
                return len(content) > 0 and "<!DOCTYPE" not in content.upper()
            
            # その他: HTMLでなければ git コンテンツの可能性
            return "<!DOCTYPE" not in content.upper() and "<html" not in content.lower()
            
        except Exception:
            return False
