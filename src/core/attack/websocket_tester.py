"""
WebSocket Tester - WebSocket脆弱性テスター

ハイジャック/インジェクション検出
"""

import logging
import json
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class WSVulnType(Enum):
    """WebSocket脆弱性タイプ"""
    CSWSH = "cross_site_websocket_hijacking"  # Cross-Site WebSocket Hijacking
    INJECTION = "injection"
    MISSING_AUTH = "missing_authentication"
    MISSING_ORIGIN = "missing_origin_validation"
    SENSITIVE_DATA = "sensitive_data_exposure"


@dataclass
class WSTestResult:
    """WebSocketテスト結果"""
    url: str
    vuln_type: Optional[WSVulnType] = None
    vulnerable: bool = False
    origin_validated: bool = True
    auth_required: bool = True
    messages_captured: List[str] = field(default_factory=list)
    evidence: str = ""
    severity: str = "medium"


class WebSocketTester:
    """
    WebSocket脆弱性テスター
    
    機能:
    - CSWSH（Cross-Site WebSocket Hijacking）検出
    - Origin検証チェック
    - 認証チェック
    - メッセージインジェクション
    """
    
    # テスト用Origin
    TEST_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        "null",
    ]
    
    # インジェクションペイロード
    INJECTION_PAYLOADS = [
        '{"type":"admin","action":"getUsers"}',
        '{"__proto__":{"admin":true}}',
        '<script>alert(1)</script>',
        '{"$where":"sleep(5000)"}',
    ]
    
    def __init__(self):
        self.results: List[WSTestResult] = []
    
    def test(
        self,
        ws_url: str,
        origin: str = None,
        auth_token: str = None
    ) -> WSTestResult:
        """
        WebSocket脆弱性テスト
        
        Args:
            ws_url: WebSocket URL (ws:// or wss://)
            origin: 送信元Origin
            auth_token: 認証トークン
        """
        result = WSTestResult(url=ws_url)
        
        # Origin検証テスト
        origin_result = self._test_origin_validation(ws_url)
        if not origin_result:
            result.origin_validated = False
            result.vulnerable = True
            result.vuln_type = WSVulnType.CSWSH
            result.severity = "high"
            result.evidence = "Origin validation missing - CSWSH possible"
        
        # 認証テスト
        auth_result = self._test_auth(ws_url)
        if not auth_result:
            result.auth_required = False
            result.vulnerable = True
            result.vuln_type = WSVulnType.MISSING_AUTH
            result.evidence = "No authentication required"
        
        self.results.append(result)
        return result
    
    def test_cswsh(self, ws_url: str) -> WSTestResult:
        """
        Cross-Site WebSocket Hijacking テスト
        
        悪意あるOriginからの接続が許可されるかチェック
        """
        result = WSTestResult(url=ws_url)
        
        for origin in self.TEST_ORIGINS:
            connected = self._try_connect(ws_url, origin)
            if connected:
                result.vulnerable = True
                result.vuln_type = WSVulnType.CSWSH
                result.origin_validated = False
                result.severity = "high"
                result.evidence = f"Connection accepted from malicious origin: {origin}"
                break
        
        self.results.append(result)
        return result
    
    def test_injection(
        self,
        ws_url: str,
        message_handler: Callable = None
    ) -> WSTestResult:
        """
        メッセージインジェクションテスト
        
        Args:
            ws_url: WebSocket URL
            message_handler: レスポンス処理関数
        """
        result = WSTestResult(url=ws_url)
        
        for payload in self.INJECTION_PAYLOADS:
            response = self._send_message(ws_url, payload)
            if response:
                result.messages_captured.append(response)
                
                # エラーレスポンスでないなら脆弱性の可能性
                if "error" not in response.lower():
                    result.vulnerable = True
                    result.vuln_type = WSVulnType.INJECTION
                    result.evidence = f"Payload accepted: {payload[:50]}"
        
        self.results.append(result)
        return result
    
    def _test_origin_validation(self, ws_url: str) -> bool:
        """
        Origin検証テスト（プレースホルダー）
        """
        logger.info("Testing Origin validation for %s", ws_url)
        
        # プレースホルダー
        # import websocket
        # for origin in self.TEST_ORIGINS:
        #     try:
        #         ws = websocket.create_connection(ws_url, origin=origin)
        #         ws.close()
        #         return False  # 悪意あるOriginが許可された
        #     except:
        #         pass
        
        return True  # Origin検証あり（デフォルト）
    
    def _test_auth(self, ws_url: str) -> bool:
        """
        認証テスト（プレースホルダー）
        """
        logger.info("Testing authentication for %s", ws_url)
        
        # プレースホルダー
        # 認証なしで接続試行
        
        return True  # 認証必要（デフォルト）
    
    def _try_connect(self, ws_url: str, origin: str) -> bool:
        """
        接続試行（プレースホルダー）
        """
        logger.info("Trying to connect to %s with origin %s", ws_url, origin)
        return False
    
    def _send_message(self, ws_url: str, message: str) -> Optional[str]:
        """
        メッセージ送信（プレースホルダー）
        """
        logger.info("Sending message to %s: %s", ws_url, message[:30])
        return None
    
    def get_vulnerable(self) -> List[WSTestResult]:
        """脆弱と判定されたもの"""
        return [r for r in self.results if r.vulnerable]
    
    def get_summary(self) -> Dict:
        """サマリー"""
        by_type = {}
        for r in self.results:
            if r.vuln_type:
                by_type.setdefault(r.vuln_type.value, 0)
                by_type[r.vuln_type.value] += 1
        
        return {
            "total_tests": len(self.results),
            "vulnerable": len(self.get_vulnerable()),
            "by_type": by_type,
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"WebSocket Test: {summary['total_tests']} tests\n"
            f"Vulnerable: {summary['vulnerable']}\n"
            f"By type: {summary['by_type']}"
        )


def create_websocket_tester() -> WebSocketTester:
    """WebSocketTester作成ヘルパー"""
    return WebSocketTester()
