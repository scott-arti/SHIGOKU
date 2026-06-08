"""
FfufAdapter: Ffufディレクトリ/ファイル発見アダプター実装

BaseExternalAdapterを継承した、型安全でセキュアなFfuf統合アダプター。
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base_external_adapter import BaseExternalAdapter, ToolInput, ToolResult, ToolStatus
from .binary_manager import BinaryManager
from .external_tool_executor import get_global_executor
from .external_tool_logger import get_logger

logger = logging.getLogger(__name__)


class FfufAdapter(BaseExternalAdapter):
    """Ffufディレクトリ/ファイル発見アダプター
    
    BaseExternalAdapterを継承し、型安全なインターフェースを提供。
    
    Example:
        adapter = FfufAdapter()
        result = await adapter.run_with_validation(
            ToolInput(
                target="https://example.com/FUZZ",
                options={"wordlist": "/path/to/wordlist.txt", "match_codes": "200,204,301"}
            )
        )
        if result.status == ToolStatus.SUCCESS:
            for finding in result.data:
                print(f"Found: {finding['url']} (Status: {finding['status']})")
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初期化
        
        Args:
            config: 設定辞書（オプション）
        """
        super().__init__("ffuf", config)
        self._binary_manager = BinaryManager()
        self._binary_path: Optional[Path] = None
    
    async def _ensure_binary(self) -> Path:
        """バイナリが利用可能であることを保証"""
        if self._binary_path is None:
            self._binary_path = await self._binary_manager.ensure_binary("ffuf")
        return self._binary_path
    
    def validate_inputs(self, input_data: ToolInput) -> Tuple[bool, Optional[str]]:
        """入力検証
        
        Ffuf特有の検証:
        - targetにFUZZキーワードが含まれるか
        - URL形式の確認
        - wordlistの存在確認（指定時）
        
        Args:
            input_data: 検証対象の入力
            
        Returns:
            Tuple[bool, Optional[str]]: (検証結果OKか, エラーメッセージ)
        """
        # targetの必須確認
        if not input_data.target:
            return False, "Target URL is required"
        
        # FUZZキーワードの必須チェック
        if "FUZZ" not in input_data.target:
            return False, f"Target must contain FUZZ keyword for replacement: {input_data.target}"
        
        # URL形式の簡易検証
        target = input_data.target
        if not (target.startswith("http://") or target.startswith("https://")):
            return False, f"Invalid URL format: {target}. Must start with http:// or https://"
        
        # wordlistの存在確認（指定時）
        options = input_data.options or {}
        if "wordlist" in options:
            wordlist_path = Path(options["wordlist"])
            if not wordlist_path.exists():
                return False, f"Wordlist not found: {wordlist_path}"
        
        # タイムアウト値の検証
        if input_data.timeout_seconds <= 0:
            return False, "Timeout must be positive"
        
        return True, None
    
    async def health_check(self) -> bool:
        """ヘルスチェック
        
        Ffufバイナリの存在確認と基本的な実行テスト。
        
        Returns:
            bool: Ffufが利用可能ならTrue
        """
        try:
            binary_path = await self._ensure_binary()
            
            # バージョン確認によるヘルスチェック
            proc = await asyncio.create_subprocess_exec(
                str(binary_path), "-V",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=10.0
            )
            
            if proc.returncode == 0:
                version = stdout.decode().strip()
                logger.debug(f"Ffuf health check OK: {version}")
                return True
            else:
                logger.warning(f"Ffuf health check failed: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Ffuf health check error: {e}")
            return False
    
    async def execute(self, input_data: ToolInput) -> ToolResult:
        """Ffufを実行し、ディレクトリ/ファイル発見結果を返却
        
        例外戦略: try-exceptブロックで全ての例外をキャッチし、
        ToolResultのstatusで表現すること。
        
        Args:
            input_data: 標準化された入力（ToolInput）
            
        Returns:
            ToolResult: 標準化された実行結果
        """
        import time
        
        start_time = time.time()
        cmd: List[str] = []
        
        try:
            binary_path = await self._ensure_binary()
            
            # オプション展開
            options = input_data.options or {}
            
            # デフォルトワードリスト設定
            wordlist = options.get("wordlist", "wordlists/common.txt")
            
            # Ffufコマンド構築
            cmd = [
                str(binary_path),
                "-u", input_data.target,
                "-w", str(wordlist),
                "-mc", options.get("match_codes", "200,204,301,302,307,401,403"),
                "-json",  # JSON出力
                "-s",     # サイレントモード（進捗非表示）
            ]
            
            # 追加オプション
            if "filter_codes" in options:
                cmd.extend(["-fc", str(options["filter_codes"])])
            
            if "threads" in options:
                cmd.extend(["-t", str(options["threads"])])
            
            if "rate" in options:
                cmd.extend(["-rate", str(options["rate"])])
            
            # ロガー取得
            tool_logger = get_logger(self.tool_name)
            tool_logger.debug_execution(cmd, None, {"target": input_data.target})
            
            # Ffuf実行
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=input_data.timeout_seconds
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                
                elapsed_ms = (time.time() - start_time) * 1000
                return ToolResult(
                    status=ToolStatus.TIMEOUT,
                    data=None,
                    execution_time_ms=elapsed_ms,
                    error_message=f"Ffuf execution timed out after {input_data.timeout_seconds}s",
                    raw_output=None
                )
            
            elapsed_ms = (time.time() - start_time) * 1000
            
            # 結果パース
            if proc.returncode == 0 or stdout:
                findings = self._parse_results(stdout.decode())
                
                result = ToolResult(
                    status=ToolStatus.SUCCESS,
                    data=findings,
                    execution_time_ms=elapsed_ms,
                    raw_output=stdout.decode()
                )
                
                # ロギング
                tool_logger.info_execution(cmd, result, {"target": input_data.target})
                
                return result
            else:
                stderr_text = stderr.decode() if stderr else "Unknown error"
                result = ToolResult(
                    status=ToolStatus.FAILURE,
                    data=None,
                    execution_time_ms=elapsed_ms,
                    error_message=f"Ffuf failed: {stderr_text}",
                    raw_output=stderr_text
                )
                
                # エラーロギング
                tool_logger.info_execution(cmd, result, {"target": input_data.target})
                
                return result
            
        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            logger.exception("Ffuf execution failed")
            
            # エラーロギング
            tool_logger = get_logger(self.tool_name)
            tool_logger.error_execution(cmd, e, {"target": input_data.target})
            
            return ToolResult(
                status=ToolStatus.ERROR,
                data=None,
                execution_time_ms=elapsed_ms,
                error_message=f"Ffuf execution error: {str(e)}",
                raw_output=str(e)
            )
    
    def _parse_results(self, output: str) -> List[Dict[str, Any]]:
        """FfufのJSON出力をパース
        
        Args:
            output: Ffufの標準出力（JSON Lines形式）
            
        Returns:
            List[Dict[str, Any]]: 統一フォーマットの検出結果リスト
        """
        findings: List[Dict[str, Any]] = []
        
        if not output or not output.strip():
            return findings
        
        try:
            # FfufはJSON Lines形式で出力（各行が独立したJSONオブジェクト）
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                
                try:
                    result = json.loads(line)
                    
                    # 検出結果を統一フォーマットに変換
                    finding = {
                        "type": "directory_or_file",
                        "url": result.get("url", ""),
                        "path": result.get("input", {}).get("FUZZ", ""),
                        "status": result.get("status", 0),
                        "length": result.get("length", 0),
                        "words": result.get("words", 0),
                        "lines": result.get("lines", 0),
                        "content_type": result.get("content_type", ""),
                        "redirect_location": result.get("redirectlocation", ""),
                        "raw": result  # 生データも保持
                    }
                    findings.append(finding)
                    
                except json.JSONDecodeError:
                    logger.debug(f"Skipping non-JSON line: {line[:100]}")
                    continue
                    
        except Exception as e:
            logger.error(f"Failed to parse Ffuf results: {e}")
        
        return findings
    
    def _is_interesting_status(self, status: int) -> bool:
        """興味深いステータスコードか判定
        
        Args:
            status: HTTPステータスコード
            
        Returns:
            bool: 興味深いならTrue
        """
        # 200, 204: OK
        # 301, 302, 307: リダイレクト
        # 401, 403: 認証/アクセス制御（興味深い）
        interesting_codes = {200, 204, 301, 302, 307, 401, 403}
        return status in interesting_codes
