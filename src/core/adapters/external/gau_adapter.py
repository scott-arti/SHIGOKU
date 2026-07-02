"""
GauAdapter: Gau (GetAllUrls) URL発見アダプター実装

BaseExternalAdapterを継承した、型安全でセキュアなGau統合アダプター。
"""

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base_external_adapter import BaseExternalAdapter, ToolInput, ToolResult, ToolStatus
from .binary_manager import BinaryManager
from .external_tool_logger import get_logger

logger = logging.getLogger(__name__)


class GauAdapter(BaseExternalAdapter):
    """Gau (GetAllUrls) URL発見アダプター
    
    BaseExternalAdapterを継承し、型安全なインターフェースを提供。
    過去のアーカイブや既知のURLソースからURLを発見する。
    
    Example:
        adapter = GauAdapter()
        result = await adapter.run_with_validation(
            ToolInput(
                target="example.com",
                options={"providers": "wayback,otx,commoncrawl"}
            )
        )
        if result.status == ToolStatus.SUCCESS:
            for url in result.data:
                print(f"Found URL: {url['url']} (Source: {url['source']})")
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, mode: str = "bugbounty"):
        """初期化

        Args:
            config: 設定辞書（オプション）
            mode: 動作モード (bugbounty/ctf/vulntest)
        """
        super().__init__("gau", config, mode=mode)
        self._binary_manager = BinaryManager()
        self._binary_path: Optional[Path] = None
    
    async def _ensure_binary(self) -> Path:
        """バイナリが利用可能であることを保証"""
        if self._binary_path is None:
            self._binary_path = await self._binary_manager.ensure_binary("gau")
        return self._binary_path
    
    def validate_inputs(self, input_data: ToolInput) -> Tuple[bool, Optional[str]]:
        """入力検証
        
        Gau特有の検証:
        - targetドメインの形式確認
        - providersの妥当性（指定時）
        
        Args:
            input_data: 検証対象の入力
            
        Returns:
            Tuple[bool, Optional[str]]: (検証結果OKか, エラーメッセージ)
        """
        # targetの必須確認
        if not input_data.target:
            return False, "Target domain is required"
        
        target = input_data.target
        
        # URL形式の場合はドメイン部分を抽出
        if "://" in target:
            target = target.split("://")[1].split("/")[0].split(":")[0]
        
        # ドメインの簡易検証（空でなければOK）
        if not target or "." not in target:
            return False, f"Invalid domain: {target}"
        
        # providersの妥当性（指定時）
        options = input_data.options or {}
        if "providers" in options:
            valid_providers = {"wayback", "otx", "commoncrawl", "urlscan"}
            requested = set(options["providers"].split(","))
            invalid = requested - valid_providers
            if invalid:
                return False, f"Invalid providers: {', '.join(invalid)}. Valid: {', '.join(valid_providers)}"
        
        # タイムアウト値の検証
        if input_data.timeout_seconds <= 0:
            return False, "Timeout must be positive"
        
        return True, None
    
    async def health_check(self) -> bool:
        """ヘルスチェック
        
        Gauバイナリの存在確認と基本的な実行テスト。
        
        Returns:
            bool: Gauが利用可能ならTrue
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
                version = stdout.decode().strip()[:50]  # 先頭50文字のみ
                logger.debug(f"Gau health check OK: {version}")
                return True
            else:
                logger.warning("Gau health check failed")
                return False
                
        except Exception as e:
            logger.error(f"Gau health check error: {e}")
            return False
    
    async def execute(self, input_data: ToolInput) -> ToolResult:
        """Gauを実行し、URL発見結果を返却
        
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
            
            # ターゲットドメイン抽出（URLの場合）
            target = input_data.target
            if "://" in target:
                target = target.split("://")[1].split("/")[0].split(":")[0]
            
            # Gauコマンド構築
            cmd = [
                str(binary_path),
                target,
            ]
            
            # 出力形式（JSON）
            cmd.append("--json")
            
            # プロバイダー指定（指定時）
            if "providers" in options:
                cmd.extend(["--providers", str(options["providers"])])
            
            # スレッド数（指定時）
            if "threads" in options:
                cmd.extend(["--threads", str(options["threads"])])
            
            # 最大取得数（指定時）
            if "max_retrieve" in options:
                cmd.extend(["--retries", str(options["max_retrieve"])])
            
            # サブドメインを含める（指定時）
            if options.get("subs", False):
                cmd.append("--subs")
            
            # ロガー取得
            tool_logger = get_logger(self.tool_name)
            tool_logger.debug_execution(cmd, None, {"target": target})
            
            # Gau実行
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
                    error_message=f"Gau execution timed out after {input_data.timeout_seconds}s",
                    raw_output=None
                )
            
            elapsed_ms = (time.time() - start_time) * 1000
            
            # 結果パース
            if stdout:
                findings = self._parse_json_lines(stdout.decode())
                
                result = ToolResult(
                    status=ToolStatus.SUCCESS,
                    data=findings,
                    execution_time_ms=elapsed_ms,
                    raw_output=stdout.decode()
                )
                
                # ロギング
                tool_logger.info_execution(cmd, result, {"target": target})
                
                return result
            else:
                # Gauは結果がなくても成功する場合がある
                elapsed_ms = (time.time() - start_time) * 1000
                result = ToolResult(
                    status=ToolStatus.SUCCESS,
                    data=[],
                    execution_time_ms=elapsed_ms,
                    raw_output="",
                    error_message=None
                )
                
                # ログ出力
                tool_logger.info_execution(cmd, result, {"target": target})
                
                return result
            
        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            logger.exception("Gau execution failed")
            
            # エラーロギング
            tool_logger = get_logger(self.tool_name)
            tool_logger.error_execution(cmd, e, {"target": input_data.target})
            
            return ToolResult(
                status=ToolStatus.ERROR,
                data=None,
                execution_time_ms=elapsed_ms,
                error_message=f"Gau execution error: {str(e)}",
                raw_output=str(e)
            )
    
    def _parse_json_lines(self, output: str) -> List[Dict[str, Any]]:
        """GauのJSON Lines出力をパース
        
        Gauは各行がURLのJSONオブジェクトを出力。
        
        Args:
            output: Gauの標準出力（JSON Lines形式）
            
        Returns:
            List[Dict[str, Any]]: 統一フォーマットのURL結果リスト
        """
        findings: List[Dict[str, Any]] = []
        
        if not output or not output.strip():
            return findings
        
        try:
            import json
            
            # Gauは通常各行がURL文字列だが、--jsonでJSONオブジェクトを出力
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                
                try:
                    # JSONオブジェクトとしてパース試行
                    data = json.loads(line)
                    
                    finding = {
                        "type": "url",
                        "url": data.get("url", ""),
                        "source": data.get("source", "unknown"),
                        "host": data.get("host", ""),
                        "raw": data
                    }
                    findings.append(finding)
                    
                except json.JSONDecodeError:
                    # 単純なURL文字列の場合
                    finding = {
                        "type": "url",
                        "url": line.strip(),
                        "source": "unknown",
                        "raw": {"url": line.strip()}
                    }
                    findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Failed to parse Gau results: {e}")
        
        return findings
    
    def _categorize_url(self, url: str) -> str:
        """URLをカテゴリ別に分類
        
        Args:
            url: URL文字列
            
        Returns:
            str: カテゴリ名
        """
        url_lower = url.lower()
        
        # ファイル拡張子による分類
        if any(url_lower.endswith(ext) for ext in ['.js', '.jsx', '.ts', '.tsx']):
            return "javascript"
        elif any(url_lower.endswith(ext) for ext in ['.css', '.scss', '.less']):
            return "stylesheet"
        elif any(url_lower.endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico']):
            return "image"
        elif any(url_lower.endswith(ext) for ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx']):
            return "document"
        elif any(url_lower.endswith(ext) for ext in ['.json', '.xml']):
            return "data"
        elif 'api' in url_lower:
            return "api"
        elif any(x in url_lower for x in ['admin', 'dashboard', 'manage', 'config']):
            return "admin"
        else:
            return "page"
