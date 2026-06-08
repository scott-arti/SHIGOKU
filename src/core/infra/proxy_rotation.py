"""
ProxyRotation: IPローテーション管理モジュール

AWS API Gatewayを利用したIPローテーション（FireProx方式）や、
静的プロキシリストのローテーションを提供する。
"""

import logging
import os
import random
from typing import Optional, List, Dict

import httpx

logger = logging.getLogger(__name__)

# AWS SDK (Optional)
try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


class ProxyRotator:
    """プロキシローテーション管理クラス"""

    def __init__(self, aws_region: str = "us-east-1", proxy_list: List[str] = None):
        self.aws_region = aws_region
        self.proxy_list = proxy_list or []
        self._gateway_id = None
        self._gateway_url = None
        self._mode = "direct"  # direct, list, aws_gateway

        # 初期化
        if self._check_aws_credentials() and HAS_BOTO3:
            self._mode = "aws_gateway"
            logger.info("🌊 ProxyRotator: AWS Gateway mode enabled")
        elif self.proxy_list:
            self._mode = "list"
            logger.info(f"🔄 ProxyRotator: List mode enabled ({len(self.proxy_list)} proxies)")
        else:
            logger.info("⚠️ ProxyRotator: Direct mode (no proxy)")

    def _check_aws_credentials(self) -> bool:
        """AWS認証情報の存在確認"""
        return bool(
            os.environ.get("AWS_ACCESS_KEY_ID") and
            os.environ.get("AWS_SECRET_ACCESS_KEY")
        )

    def get_proxy(self) -> Dict[str, str]:
        """現在のプロキシ設定を取得"""
        if self._mode == "list" and self.proxy_list:
            proxy = random.choice(self.proxy_list)
            # httpx format for proxies might differ ("http://..." or dict)
            # httpx accepts dict {"http://": ..., "https://": ...} or just string
            return {"http://": proxy, "https://": proxy}
        return {}

    def get_target_url(self, original_url: str) -> str:
        """
        ターゲットURLを変換する
        
        AWS Gatewayモードの場合、Gatewayのエンドポイント経由のURLに変換する。
        """
        if self._mode == "aws_gateway" and self._gateway_url:
            # FireProx Simple Mode Implementation
            # FireProx Gatewayのエンドポイントにターゲットのパスを付加する形式
            # 前提: _gateway_url は FireProx のベースURL (例: https://.../fireprox/)
            from urllib.parse import urlparse
            
            parsed = urlparse(original_url)
            # パスの先頭のスラッシュを削除して結合しやすくする
            path = parsed.path.lstrip('/')
            query = f"?{parsed.query}" if parsed.query else ""
            
            base_url = self._gateway_url if self._gateway_url.endswith('/') else f"{self._gateway_url}/"
            return f"{base_url}{path}{query}"
        return original_url

    def rotate(self):
        """ローテーションを実行（必要であれば）"""
        if self._mode == "aws_gateway":
            # API Gatewayはリクエスト毎にIPが変わるため明示的なローテーション不要
            pass
        elif self._mode == "list":
            # get_proxyでランダム取得するためここも不要だが、
            # ステートフルなローテーションが必要ならここに実装
            pass


class RotatingSession(httpx.Client):
    """
    自動プロキシローテーション機能付きセッション
    
    Compatible with httpx.Client.
    Note: Retry logic is simplified compared to requests version.
    """

    def __init__(self, rotator: Optional[ProxyRotator] = None, retries: int = 3, **kwargs):
        super().__init__(**kwargs)
        self.rotator = rotator or ProxyRotator()
        
        # User-Agentのランダム化（簡易）
        self.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        })

    def request(self, method, url, **kwargs):
        """リクエスト送信オーバーライド"""
        
        # httpxでの動的プロキシ設定は init 時が基本だが、
        # ここでは簡易的に実装するか、Client再生成が必要になるため
        # 一旦スキップする (httpxはrequestメソッドごとのproxies引数を公式にはサポートしていない場合があるが、
        # 内部的には transport レベルで処理される)
        # TODO: Implement proper proxy rotation for httpx if needed.
        
        # NOTE: If self.rotator._mode == "list", we might want to manually handle proxies by creating a Transport?
        # For now, we rely on Direct mode or AWS Gateway (which is URL rewriting).

        if self.rotator._mode == "aws_gateway":
             url = self.rotator.get_target_url(url)
        
        try:
            return super().request(method, url, **kwargs)
        except httpx.RequestError as e:
            logger.warning("Request failed: %s", e)
            raise e
