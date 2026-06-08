"""
NmapAdapter: Nmapポートスキャンアダプター実装

BaseExternalAdapterを継承した、型安全でセキュアなNmap統合アダプター。
"""

import asyncio
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base_external_adapter import BaseExternalAdapter, ToolInput, ToolResult, ToolStatus
from .binary_manager import BinaryManager
from .external_tool_executor import get_global_executor
from .external_tool_logger import get_logger

logger = logging.getLogger(__name__)


class NmapAdapter(BaseExternalAdapter):
    """Nmapポートスキャンアダプター
    
    BaseExternalAdapterを継承し、型安全なインターフェースを提供。
    XML出力（-oX）をパースして構造化された結果を返却。
    
    Example:
        adapter = NmapAdapter()
        result = await adapter.run_with_validation(
            ToolInput(
                target="example.com",
                options={"ports": "80,443,8080", "scan_type": "syn"}
            )
        )
        if result.status == ToolStatus.SUCCESS:
            for port in result.data:
                print(f"Port {port['port']}/{port['protocol']}: {port['state']} ({port['service']})")
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初期化
        
        Args:
            config: 設定辞書（オプション）
        """
        super().__init__("nmap", config)
        self._binary_manager = BinaryManager()
        self._binary_path: Optional[Path] = None
    
    async def _ensure_binary(self) -> Path:
        """バイナリが利用可能であることを保証"""
        if self._binary_path is None:
            self._binary_path = await self._binary_manager.ensure_binary("nmap")
        return self._binary_path
    
    def validate_inputs(self, input_data: ToolInput) -> Tuple[bool, Optional[str]]:
        """入力検証
        
        Nmap特有の検証:
        - targetホスト/IPの確認
        - ポート範囲の妥当性
        
        Args:
            input_data: 検証対象の入力
            
        Returns:
            Tuple[bool, Optional[str]]: (検証結果OKか, エラーメッセージ)
        """
        # targetの必須確認
        if not input_data.target:
            return False, "Target host/IP is required"
        
        target = input_data.target
        
        # URL形式の場合はホスト部分を抽出
        if "://" in target:
            target = target.split("://")[1].split("/")[0].split(":")[0]
        
        # ホスト名/IPの簡易検証（空でなければOK）
        if not target:
            return False, "Invalid target format"
        
        # ポート範囲の検証（指定時）
        options = input_data.options or {}
        if "ports" in options:
            ports = options["ports"]
            # 簡易検証: 数字、カンマ、ハイフンのみ許可
            valid_chars = set("0123456789,-")
            if not all(c in valid_chars for c in str(ports)):
                return False, f"Invalid port format: {ports}"
        
        # タイムアウト値の検証
        if input_data.timeout_seconds <= 0:
            return False, "Timeout must be positive"
        
        return True, None
    
    async def health_check(self) -> bool:
        """ヘルスチェック
        
        Nmapバイナリの存在確認と基本的な実行テスト。
        
        Returns:
            bool: Nmapが利用可能ならTrue
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
                logger.debug(f"Nmap health check OK: {version}")
                return True
            else:
                logger.warning(f"Nmap health check failed")
                return False
                
        except Exception as e:
            logger.error(f"Nmap health check error: {e}")
            return False
    
    async def execute(self, input_data: ToolInput) -> ToolResult:
        """Nmapを実行し、ポートスキャン結果を返却
        
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
            
            # ターゲットホスト抽出（URLの場合）
            target = input_data.target
            if "://" in target:
                target = target.split("://")[1].split("/")[0].split(":")[0]
            
            # Nmapコマンド構築
            cmd = [
                str(binary_path),
                "-oX", "-",  # XML出力をstdout
                "-Pn",       # ホスト発見をスキップ（すべてオンラインと仮定）
            ]
            
            # ポート指定
            ports = options.get("ports", "1-1000")  # デフォルト1-1000
            cmd.extend(["-p", str(ports)])
            
            # スキャンタイプ
            scan_type = options.get("scan_type", "syn")
            if scan_type == "syn":
                cmd.append("-sS")
            elif scan_type == "connect":
                cmd.append("-sT")
            elif scan_type == "udp":
                cmd.append("-sU")
            
            # サービスバージョン検出
            if options.get("service_detection", True):
                cmd.append("-sV")
            
            # OS検出（root時のみ動作、エラー無視）
            if options.get("os_detection", False):
                cmd.append("-O")
            
            # スクリプトスキャン（指定時）
            if "script" in options:
                cmd.extend(["--script", str(options["script"])])
            
            # タイミングテンプレート（指定時）
            if "timing" in options:
                cmd.extend(["-T", str(options["timing"])])
            
            # ターゲット追加
            cmd.append(target)
            
            # ロガー取得
            tool_logger = get_logger(self.tool_name)
            tool_logger.debug_execution(cmd, None, {"target": target})
            
            # Nmap実行
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
                    error_message=f"Nmap execution timed out after {input_data.timeout_seconds}s",
                    raw_output=None
                )
            
            elapsed_ms = (time.time() - start_time) * 1000
            
            # 結果パース
            if stdout:
                findings = self._parse_xml_results(stdout.decode())
                
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
                stderr_text = stderr.decode() if stderr else "No output from nmap"
                result = ToolResult(
                    status=ToolStatus.FAILURE,
                    data=None,
                    execution_time_ms=elapsed_ms,
                    error_message=f"Nmap failed: {stderr_text}",
                    raw_output=stderr_text
                )
                
                # エラーロギング
                tool_logger.info_execution(cmd, result, {"target": target})
                
                return result
            
        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            logger.exception("Nmap execution failed")
            
            # エラーロギング
            tool_logger = get_logger(self.tool_name)
            tool_logger.error_execution(cmd, e, {"target": input_data.target})
            
            return ToolResult(
                status=ToolStatus.ERROR,
                data=None,
                execution_time_ms=elapsed_ms,
                error_message=f"Nmap execution error: {str(e)}",
                raw_output=str(e)
            )
    
    def _parse_xml_results(self, xml_output: str) -> List[Dict[str, Any]]:
        """NmapのXML出力をパース
        
        Args:
            xml_output: NmapのXML出力
            
        Returns:
            List[Dict[str, Any]]: 統一フォーマットのポート結果リスト
        """
        findings: List[Dict[str, Any]] = []
        
        if not xml_output or not xml_output.strip():
            return findings
        
        try:
            root = ET.fromstring(xml_output)
            
            # ホスト情報を取得
            for host in root.findall("host"):
                host_info = {
                    "address": "",
                    "hostnames": [],
                    "ports": []
                }
                
                # アドレス取得
                address_elem = host.find("address")
                if address_elem is not None:
                    host_info["address"] = address_elem.get("addr", "")
                
                # ホスト名取得
                hostnames_elem = host.find("hostnames")
                if hostnames_elem is not None:
                    for hostname in hostnames_elem.findall("hostname"):
                        host_info["hostnames"].append(hostname.get("name", ""))
                
                # ポート情報取得
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        port_info = {
                            "type": "port",
                            "port": int(port.get("portid", 0)),
                            "protocol": port.get("protocol", "tcp"),
                        }
                        
                        # ポート状態
                        state_elem = port.find("state")
                        if state_elem is not None:
                            port_info["state"] = state_elem.get("state", "unknown")
                            port_info["reason"] = state_elem.get("reason", "")
                        
                        # サービス情報
                        service_elem = port.find("service")
                        if service_elem is not None:
                            port_info["service"] = service_elem.get("name", "")
                            port_info["product"] = service_elem.get("product", "")
                            port_info["version"] = service_elem.get("version", "")
                            port_info["extrainfo"] = service_elem.get("extrainfo", "")
                        
                        # ホスト情報を追加
                        port_info["host"] = host_info["address"]
                        port_info["hostnames"] = host_info["hostnames"]
                        
                        findings.append(port_info)
                
                # OS検出情報（存在時）
                os_elem = host.find("os")
                if os_elem is not None:
                    os_match = os_elem.find("osmatch")
                    if os_match is not None:
                        findings.append({
                            "type": "os_detection",
                            "os_name": os_match.get("name", ""),
                            "os_accuracy": os_match.get("accuracy", ""),
                            "host": host_info["address"]
                        })
            
            return findings
            
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
            return findings
        except Exception as e:
            logger.error(f"Error parsing Nmap results: {e}")
            return findings
    
    def _is_open_port(self, port_info: Dict[str, Any]) -> bool:
        """ポートが開いているか判定
        
        Args:
            port_info: ポート情報
            
        Returns:
            bool: 開いているならTrue
        """
        return port_info.get("state") == "open"
