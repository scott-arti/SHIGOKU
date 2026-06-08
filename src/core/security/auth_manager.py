"""
Auth Manager - 認証マネージャー

複数認証方式対応
"""

import base64
import hashlib
import hmac
import logging
import time
from typing import Dict, Optional
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class AuthConfig:
    """認証設定"""
    auth_type: str = ""  # basic, cookie, bearer, api_key, oauth, aws_sig
    username: str = ""
    password: str = ""
    token: str = ""
    api_key: str = ""
    api_key_header: str = "X-API-Key"
    api_key_query: str = ""
    cookie: str = ""
    oauth_token: str = ""
    oauth_refresh_token: str = ""
    aws_access_key: str = ""
    aws_secret_key: str = ""
    aws_region: str = "us-east-1"
    aws_service: str = "execute-api"


class AuthManager:
    """
    認証マネージャー
    
    対応認証方式:
    - Basic Auth
    - Cookie
    - Bearer Token
    - API Key (Header/Query)
    - OAuth 2.0
    - AWS Signature v4
    """
    
    def __init__(self, config: AuthConfig = None):
        self.config = config or AuthConfig()
        self._oauth_expires_at: Optional[datetime] = None
    
    def get_headers(self) -> Dict[str, str]:
        """認証ヘッダー取得"""
        headers = {}
        
        if self.config.auth_type == "basic":
            headers.update(self._get_basic_auth_headers())
        elif self.config.auth_type == "bearer":
            headers.update(self._get_bearer_headers())
        elif self.config.auth_type == "api_key":
            headers.update(self._get_api_key_headers())
        elif self.config.auth_type == "cookie":
            headers.update(self._get_cookie_headers())
        elif self.config.auth_type == "oauth":
            headers.update(self._get_oauth_headers())
        
        return headers
    
    def get_query_params(self) -> Dict[str, str]:
        """認証クエリパラメータ取得"""
        params = {}
        
        if self.config.auth_type == "api_key" and self.config.api_key_query:
            params[self.config.api_key_query] = self.config.api_key
        
        return params
    
    def sign_aws_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        payload: str = ""
    ) -> Dict[str, str]:
        """
        AWS Signature v4でリクエストに署名
        
        Args:
            method: HTTPメソッド
            url: リクエストURL
            headers: 既存ヘッダー
            payload: リクエストボディ
        
        Returns:
            署名付きヘッダー
        """
        if self.config.auth_type != "aws_sig":
            return headers
        
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or "/"
        
        # 日時
        t = datetime.utcnow()
        amz_date = t.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = t.strftime("%Y%m%d")
        
        # ペイロードハッシュ
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()
        
        # 署名対象ヘッダー
        headers_to_sign = {
            "host": host,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
        }
        
        # Canonical Request作成
        signed_headers = ";".join(sorted(headers_to_sign.keys()))
        canonical_headers = "\n".join(
            f"{k}:{v}" for k, v in sorted(headers_to_sign.items())
        ) + "\n"
        
        canonical_request = "\n".join([
            method.upper(),
            path,
            "",  # クエリ文字列
            canonical_headers,
            signed_headers,
            payload_hash,
        ])
        
        # String to Sign作成
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = f"{date_stamp}/{self.config.aws_region}/{self.config.aws_service}/aws4_request"
        
        string_to_sign = "\n".join([
            algorithm,
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ])
        
        # 署名キー作成
        def sign(key, msg):
            return hmac.new(key, msg.encode(), hashlib.sha256).digest()
        
        k_date = sign(f"AWS4{self.config.aws_secret_key}".encode(), date_stamp)
        k_region = sign(k_date, self.config.aws_region)
        k_service = sign(k_region, self.config.aws_service)
        signing_key = sign(k_service, "aws4_request")
        
        # 署名
        signature = hmac.new(
            signing_key,
            string_to_sign.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Authorization ヘッダー
        authorization = (
            f"{algorithm} "
            f"Credential={self.config.aws_access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        )
        
        # ヘッダー更新
        result = headers.copy()
        result["Authorization"] = authorization
        result["x-amz-date"] = amz_date
        result["x-amz-content-sha256"] = payload_hash
        
        return result
    
    def _get_basic_auth_headers(self) -> Dict[str, str]:
        """Basic認証ヘッダー"""
        credentials = f"{self.config.username}:{self.config.password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return {"Authorization": f"Basic {encoded}"}
    
    def _get_bearer_headers(self) -> Dict[str, str]:
        """Bearerトークンヘッダー"""
        return {"Authorization": f"Bearer {self.config.token}"}
    
    def _get_api_key_headers(self) -> Dict[str, str]:
        """APIキーヘッダー"""
        if self.config.api_key_header:
            return {self.config.api_key_header: self.config.api_key}
        return {}
    
    def _get_cookie_headers(self) -> Dict[str, str]:
        """Cookieヘッダー"""
        return {"Cookie": self.config.cookie}
    
    def _get_oauth_headers(self) -> Dict[str, str]:
        """OAuth 2.0ヘッダー"""
        # トークン有効期限チェック
        if self._oauth_expires_at and datetime.now() >= self._oauth_expires_at:
            self._refresh_oauth_token()
        
        return {"Authorization": f"Bearer {self.config.oauth_token}"}
    
    def _refresh_oauth_token(self):
        """OAuthトークンリフレッシュ（プレースホルダー）"""
        if not self.config.oauth_refresh_token:
            logger.warning("OAuth refresh token not available")
            return
        
        logger.info("Refreshing OAuth token...")
        # 実際の実装ではトークンエンドポイントにリクエスト
        # response = requests.post(token_url, data={
        #     "grant_type": "refresh_token",
        #     "refresh_token": self.config.oauth_refresh_token,
        # })
        # self.config.oauth_token = response.json()["access_token"]
    
    def set_basic_auth(self, username: str, password: str):
        """Basic認証設定"""
        self.config.auth_type = "basic"
        self.config.username = username
        self.config.password = password
    
    def set_bearer_token(self, token: str):
        """Bearerトークン設定"""
        self.config.auth_type = "bearer"
        self.config.token = token
    
    def set_api_key(self, api_key: str, header: str = "X-API-Key", query: str = ""):
        """APIキー設定"""
        self.config.auth_type = "api_key"
        self.config.api_key = api_key
        self.config.api_key_header = header
        self.config.api_key_query = query
    
    def set_cookie(self, cookie: str):
        """Cookie設定"""
        self.config.auth_type = "cookie"
        self.config.cookie = cookie
    
    def set_oauth(self, access_token: str, refresh_token: str = "", expires_in: int = 3600):
        """OAuth 2.0設定"""
        self.config.auth_type = "oauth"
        self.config.oauth_token = access_token
        self.config.oauth_refresh_token = refresh_token
        if expires_in:
            self._oauth_expires_at = datetime.fromtimestamp(time.time() + expires_in)
    
    def set_aws_signature(self, access_key: str, secret_key: str, region: str = "us-east-1", service: str = "execute-api"):
        """AWS Signature v4設定"""
        self.config.auth_type = "aws_sig"
        self.config.aws_access_key = access_key
        self.config.aws_secret_key = secret_key
        self.config.aws_region = region
        self.config.aws_service = service
    
    def clear(self):
        """認証情報クリア"""
        self.config = AuthConfig()


def create_auth_manager(config: AuthConfig = None) -> AuthManager:
    """AuthManager作成ヘルパー"""
    return AuthManager(config)
