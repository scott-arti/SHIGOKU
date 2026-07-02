"""
ArjunAdapter: Arjun HTTPパラメータ発見アダプター実装

BaseExternalAdapterを継承した、型安全でセキュアなArjun統合アダプター。
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base_external_adapter import BaseExternalAdapter, ToolInput, ToolResult, ToolStatus
from .binary_manager import BinaryManager
from .external_tool_logger import get_logger

logger = logging.getLogger(__name__)


class ArjunAdapter(BaseExternalAdapter):
    """Arjun HTTPパラメータ発見アダプター
    
    BaseExternalAdapterを継承し、型安全なインターフェースを提供。
    隠しHTTPパラメータの発見と検出を行う。
    
    Example:
        adapter = ArjunAdapter()
        result = await adapter.run_with_validation(
            ToolInput(
                target="https://example.com/search",
                options={"method": "GET", "wordlist": "/path/to/params.txt"}
            )
        )
        if result.status == ToolStatus.SUCCESS:
            for param in result.data:
                print(f"Found param: {param['param']} ({param['type']})")
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, mode: str = "bugbounty"):
        """初期化

        Args:
            config: 設定辞書（オプション）
            mode: 動作モード (bugbounty/ctf/vulntest)
        """
        super().__init__("arjun", config, mode=mode)
        self._binary_manager = BinaryManager()
        self._binary_path: Optional[Path] = None
    
    async def _ensure_binary(self) -> Path:
        """バイナリが利用可能であることを保証"""
        if self._binary_path is None:
            self._binary_path = await self._binary_manager.ensure_binary("arjun")
        return self._binary_path
    
    def validate_inputs(self, input_data: ToolInput) -> Tuple[bool, Optional[str]]:
        """入力検証
        
        Arjun特有の検証:
        - target URLの形式確認
        - HTTPメソッドの妥当性
        
        Args:
            input_data: 検証対象の入力
            
        Returns:
            Tuple[bool, Optional[str]]: (検証結果OKか, エラーメッセージ)
        """
        # targetの必須確認
        if not input_data.target:
            return False, "Target URL is required"
        
        # URL形式の簡易検証
        target = input_data.target
        if not (target.startswith("http://") or target.startswith("https://")):
            return False, f"Invalid URL format: {target}. Must start with http:// or https://"
        
        # メソッドの妥当性（指定時）
        options = input_data.options or {}
        if "method" in options:
            method = options["method"].upper()
            valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
            if method not in valid_methods:
                return False, f"Invalid HTTP method: {method}"
        
        # タイムアウト値の検証
        if input_data.timeout_seconds <= 0:
            return False, "Timeout must be positive"
        
        return True, None
    
    async def health_check(self) -> bool:
        """ヘルスチェック
        
        Arjunバイナリの存在確認と基本的な実行テスト。
        
        Returns:
            bool: Arjunが利用可能ならTrue
        """
        try:
            binary_path = await self._ensure_binary()
            
            # ヘルプ表示によるヘルスチェック
            proc = await asyncio.create_subprocess_exec(
                str(binary_path), "-h",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=10.0
            )
            
            if proc.returncode == 0 or "usage" in (stdout.decode() + stderr.decode()).lower():
                logger.debug("Arjun health check OK")
                return True
            else:
                logger.warning("Arjun health check failed")
                return False
                
        except Exception as e:
            logger.error(f"Arjun health check error: {e}")
            return False
    
    async def execute(self, input_data: ToolInput) -> ToolResult:
        """Arjunを実行し、パラメータ発見結果を返却
        
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
            
            # Arjunコマンド構築
            cmd = [
                str(binary_path),
                "-u", input_data.target,
                "-oJ", "-",  # JSON出力をstdout
            ]
            
            # HTTPメソッド
            method = options.get("method", "GET").upper()
            cmd.extend(["-m", method])
            
            # ワードリスト（指定時）
            if "wordlist" in options:
                cmd.extend(["-w", str(options["wordlist"])])
            
            # ヘッダー（指定時）
            if "headers" in options:
                for header in options["headers"]:
                    cmd.extend(["-H", str(header)])
            
            # クッキー（指定時）
            if "cookies" in options:
                cmd.extend(["-c", str(options["cookies"])])
            
            # タイムアウト（Arjun固有、秒）
            if "arjun_timeout" in options:
                cmd.extend(["-t", str(options["arjun_timeout"])])
            
            # ロガー取得
            tool_logger = get_logger(self.tool_name)
            tool_logger.debug_execution(cmd, None, {"target": input_data.target})
            
            # Arjun実行
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
                    error_message=f"Arjun execution timed out after {input_data.timeout_seconds}s",
                    raw_output=None
                )
            
            elapsed_ms = (time.time() - start_time) * 1000
            
            # 結果パース
            if stdout:
                findings = self._parse_json_results(stdout.decode())
                
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
                stderr_text = stderr.decode() if stderr else "No output from arjun"
                result = ToolResult(
                    status=ToolStatus.FAILURE,
                    data=None,
                    execution_time_ms=elapsed_ms,
                    error_message=f"Arjun failed: {stderr_text}",
                    raw_output=stderr_text
                )
                
                # エラーロギング
                tool_logger.info_execution(cmd, result, {"target": input_data.target})
                
                return result
            
        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            logger.exception("Arjun execution failed")
            
            # エラーロギング
            tool_logger = get_logger(self.tool_name)
            tool_logger.error_execution(cmd, e, {"target": input_data.target})
            
            return ToolResult(
                status=ToolStatus.ERROR,
                data=None,
                execution_time_ms=elapsed_ms,
                error_message=f"Arjun execution error: {str(e)}",
                raw_output=str(e)
            )
    
    def _parse_json_results(self, json_output: str) -> List[Dict[str, Any]]:
        """ArjunのJSON出力をパース
        
        Args:
            json_output: ArjunのJSON出力
            
        Returns:
            List[Dict[str, Any]]: 統一フォーマットのパラメータ結果リスト
        """
        findings: List[Dict[str, Any]] = []
        
        if not json_output or not json_output.strip():
            return findings
        
        try:
            # Arjunは単一のJSONオブジェクトを出力
            data = json.loads(json_output)
            
            # 結果がリストの場合
            if isinstance(data, list):
                for item in data:
                    finding = {
                        "type": "parameter",
                        "param": item.get("param", ""),
                        "url": item.get("url", ""),
                        "method": item.get("method", "GET"),
                        "status": item.get("status"),
                        "length": item.get("length"),
                        "error": item.get("error"),
                        "raw": item
                    }
                    findings.append(finding)
            
            # 結果が辞書の場合（単一結果）
            elif isinstance(data, dict):
                if "param" in data:
                    finding = {
                        "type": "parameter",
                        "param": data.get("param", ""),
                        "url": data.get("url", ""),
                        "method": data.get("method", "GET"),
                        "status": data.get("status"),
                        "length": data.get("length"),
                        "error": data.get("error"),
                        "raw": data
                    }
                    findings.append(finding)
            
            return findings
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Arjun JSON: {e}")
            return findings
        except Exception as e:
            logger.error(f"Error parsing Arjun results: {e}")
            return findings
