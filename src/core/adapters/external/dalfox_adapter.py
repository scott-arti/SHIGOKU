"""
DalFoxAdapter: DalFox XSSスキャナーのアダプター実装

BaseExternalAdapterを継承した、型安全でセキュアなDalFox統合アダプター。
"""

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base_external_adapter import BaseExternalAdapter, ToolInput, ToolResult, ToolStatus
from .binary_manager import BinaryManager
from .external_tool_logger import get_logger

logger = logging.getLogger(__name__)


class DalFoxAdapter(BaseExternalAdapter):
    """DalFox XSSスキャナー統合アダプター
    
    BaseExternalAdapterを継承し、型安全なインターフェースを提供。
    
    Example:
        adapter = DalFoxAdapter()
        result = await adapter.run_with_validation(
            ToolInput(target="https://example.com/search?q=test")
        )
        if result.status == ToolStatus.SUCCESS:
            for finding in result.data:
                print(f"XSS Found: {finding['param']} = {finding['payload']}")
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, mode: str = "bugbounty"):
        """初期化

        Args:
            config: 設定辞書（オプション）
            mode: 動作モード (bugbounty/ctf/vulntest)
        """
        super().__init__("dalfox", config, mode=mode)
        self.binary_manager = BinaryManager()
        self._binary_path: Optional[Path] = None
    
    async def _ensure_binary(self) -> Path:
        """バイナリが利用可能であることを保証"""
        if self._binary_path is None:
            self._binary_path = await self.binary_manager.ensure_binary("dalfox")
        return self._binary_path
    
    def validate_inputs(self, input_data: ToolInput) -> Tuple[bool, Optional[str]]:
        """入力検証
        
        DalFox特有の検証:
        - target URLの形式確認
        - 必須パラメータの存在確認
        
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
        
        # タイムアウト値の検証
        if input_data.timeout_seconds <= 0:
            return False, "Timeout must be positive"
        
        return True, None
    
    async def health_check(self) -> bool:
        """ヘルスチェック
        
        DalFoxバイナリの存在確認と基本的な実行テスト。
        
        Returns:
            bool: DalFoxが利用可能ならTrue
        """
        try:
            binary_path = await self._ensure_binary()
            
            # バージョン確認によるヘルスチェック
            proc = await asyncio.create_subprocess_exec(
                str(binary_path), "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=10.0
            )
            
            if proc.returncode == 0:
                version = stdout.decode().strip()
                logger.debug(f"DalFox health check OK: {version}")
                return True
            else:
                logger.warning(f"DalFox health check failed: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"DalFox health check error: {e}")
            return False
    
    async def execute(self, input_data: ToolInput) -> ToolResult:
        """DalFoxを実行し、XSSスキャン結果を返却
        
        例外戦略: try-exceptブロックで全ての例外をキャッチし、
        ToolResultのstatusで表現すること（BaseExternalAdapter設計原則）。
        
        Args:
            input_data: 標準化された入力（ToolInput）
            
        Returns:
            ToolResult: 標準化された実行結果
        """
        import time
        
        start_time = time.time()
        
        try:
            binary_path = await self._ensure_binary()
            
            # 一時ファイルを作成してURLを書き込む（DalFoxの都合）
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.txt',
                delete=False
            ) as tmp_file:
                tmp_file.write(input_data.target)
                target_file = tmp_file.name
            
            try:
                # DalFoxコマンド構築
                cmd = [
                    str(binary_path),
                    "file", target_file,
                    "--format", "json",
                    "--no-color",
                    "--silence"
                ]
                
                # 追加オプションがあれば展開
                if input_data.options:
                    for key, value in input_data.options.items():
                        cmd.extend([f"--{key}", str(value)])
                
                # ロガー取得
                tool_logger = get_logger(self.tool_name)
                
                # DalFox実行
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
                        error_message=f"DalFox execution timed out after {input_data.timeout_seconds}s",
                        raw_output=stderr.decode() if stderr else None
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
                    tool_logger.debug_execution(cmd, result, {"target": input_data.target})
                    
                    return result
                else:
                    stderr_text = stderr.decode() if stderr else "Unknown error"
                    result = ToolResult(
                        status=ToolStatus.FAILURE,
                        data=None,
                        execution_time_ms=elapsed_ms,
                        error_message=f"DalFox failed: {stderr_text}",
                        raw_output=stderr_text
                    )
                    
                    # エラーロギング
                    tool_logger.info_execution(cmd, result, {"target": input_data.target})
                    
                    return result
                
            finally:
                # 一時ファイル削除
                Path(target_file).unlink(missing_ok=True)
                
        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            logger.exception("DalFox execution failed")
            
            # エラーロギング
            tool_logger = get_logger(self.tool_name)
            tool_logger.error_execution(cmd, e, {"target": input_data.target})
            
            return ToolResult(
                status=ToolStatus.ERROR,
                data=None,
                execution_time_ms=elapsed_ms,
                error_message=f"DalFox execution error: {str(e)}",
                raw_output=str(e)
            )
    
    def _parse_results(self, output: str) -> List[Dict[str, Any]]:
        """DalFoxのJSON出力をパース
        
        Args:
            output: DalFoxの標準出力（JSON形式）
            
        Returns:
            List[Dict]: XSS検出結果のリスト
        """
        findings = []
        
        if not output or not output.strip():
            return findings
        
        try:
            # DalFoxはJSON Lines形式で出力
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                    
                try:
                    result = json.loads(line)
                    
                    # 検出結果を統一フォーマットに変換
                    finding = {
                        "type": "xss",
                        "param": result.get("param", ""),
                        "payload": result.get("payload", ""),
                        "url": result.get("url", ""),
                        "method": result.get("method", "GET"),
                        "severity": self._determine_severity(result),
                        "evidence": result.get("evidence", ""),
                        "raw": result  # 生データも保持
                    }
                    findings.append(finding)
                    
                except json.JSONDecodeError:
                    logger.debug(f"Skipping non-JSON line: {line[:100]}")
                    continue
                    
        except Exception as e:
            logger.error(f"Failed to parse DalFox results: {e}")
        
        return findings
    
    def _determine_severity(self, result: Dict[str, Any]) -> str:
        """検出結果から重大度を判定
        
        Args:
            result: DalFoxの検出結果
            
        Returns:
            str: 重大度（critical/high/medium/low/info）
        """
        # DalFoxの検出タイプに基づいて重大度を判定
        param = result.get("param", "").lower()
        payload = result.get("payload", "").lower()
        
        # 反射型XSSでポテンシャルパラメータ
        if result.get("type") == "reflected":
            if any(p in param for p in ["redirect", "url", "next", "return"]):
                return "high"
            if "script" in payload or "javascript:" in payload:
                return "critical"
            return "medium"
        
        # 保存型XSS
        if result.get("type") == "stored":
            return "critical"
        
        # DOM-based XSS
        if result.get("type") == "dom":
            return "high"
        
        return "medium"
