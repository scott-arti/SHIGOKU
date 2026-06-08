"""
Multi-Account Session Manager - マルチアカウントセッション管理

複数のユーザーアカウント（Attacker/Victim）のセッション情報を管理し、
IDOR クロステスト時に切り替えてリクエストを実行する。

Usage:
    manager = MultiAccountSessionManager(Path("sessions.json"))
    if manager.load_sessions():
        response = manager.make_request_as("victim", "GET", "https://example.com/api/users/me")
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class SessionConfig:
    """個別セッション設定"""
    name: str                          # "attacker" or "victim"
    auth_type: str                     # "cookie", "bearer", "basic", "api_key"
    credentials: dict = field(default_factory=dict)  # 認証情報
    
    def get_headers(self) -> dict[str, str]:
        """認証ヘッダーを生成"""
        headers = {}
        
        if self.auth_type == "cookie":
            cookie_value = self.credentials.get("cookie", "")
            if cookie_value:
                headers["Cookie"] = cookie_value
        
        elif self.auth_type == "bearer":
            token = self.credentials.get("token", "")
            if token:
                headers["Authorization"] = f"Bearer {token}"
        
        elif self.auth_type == "basic":
            import base64
            username = self.credentials.get("username", "")
            password = self.credentials.get("password", "")
            if username:
                encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"
        
        elif self.auth_type == "api_key":
            api_key = self.credentials.get("api_key", "")
            header_name = self.credentials.get("header_name", "X-API-Key")
            if api_key:
                headers[header_name] = api_key
        
        return headers


class SessionValidationError(Exception):
    """セッション設定のバリデーションエラー"""


class MultiAccountSessionManager:
    """
    マルチアカウントセッション管理
    
    sessions.json から複数のセッション情報を読み込み、
    指定したセッションでHTTPリクエストを実行する。
    
    セキュリティ考慮:
    - セッション情報はログに出力しない
    - メモリ上でのみ保持
    """
    
    REQUIRED_SESSIONS = ["attacker", "victim"]
    VALID_AUTH_TYPES = ["cookie", "bearer", "basic", "api_key"]
    
    def __init__(self, sessions_file: Path):
        """
        Args:
            sessions_file: sessions.json のパス
        """
        self.sessions_file = sessions_file
        self._sessions: dict[str, SessionConfig] = {}
        self._loaded = False
        self._request_timeout = 15
    
    def load_sessions(self) -> bool:
        """
        セッションファイルを読み込み、バリデーション
        
        Returns:
            True: 正常に読み込み完了
            False: 読み込みまたはバリデーション失敗
        """
        if not self.sessions_file.exists():
            logger.error("Sessions file not found: %s", self.sessions_file)
            return False
        
        try:
            with open(self.sessions_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            self._validate_and_parse(data)
            self._loaded = True
            logger.info("Loaded %d sessions from %s", len(self._sessions), self.sessions_file.name)
            return True
        except (json.JSONDecodeError, SessionValidationError) as e:
            logger.error("Failed to load sessions: %s", e)
            return False

    def _load_from_env(self) -> bool:
        """
        環境変数からセッション情報を読み込み (12-Factor App)
        SHIGOKU_ATTACKER_COOKIE / SHIGOKU_VICTIM_COOKIE
        """
        import os
        attacker_val = os.getenv("SHIGOKU_ATTACKER_COOKIE") or os.getenv("SHIGOKU_ATTACKER_TOKEN")
        victim_val = os.getenv("SHIGOKU_VICTIM_COOKIE") or os.getenv("SHIGOKU_VICTIM_TOKEN")
        
        if attacker_val and victim_val:
            try:
                # CookieかTokenかを簡易判定 (Basic等は現状サポート外)
                auth_type = "bearer" if "ey" in attacker_val[:10] else "cookie"
                cred_key = "token" if auth_type == "bearer" else "cookie"
                
                self._sessions["attacker"] = SessionConfig(
                    name="attacker",
                    auth_type=auth_type,
                    credentials={cred_key: attacker_val}
                )
                self._sessions["victim"] = SessionConfig(
                    name="victim",
                    auth_type=auth_type,
                    credentials={cred_key: victim_val}
                )
                self._loaded = True
                logger.info("Loaded sessions from environment variables")
                return True
            except Exception as e:
                logger.warning(f"Failed to load sessions from env: {e}")
        
        return False


            
        try:
            with open(self.sessions_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            self._validate_and_parse(data)
            self._loaded = True
            logger.info("Loaded %d sessions from %s", len(self._sessions), self.sessions_file.name)
            return True
            
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in sessions file: %s", e)
            return False
        except SessionValidationError as e:
            logger.error("Session validation failed: %s", e)
            return False
        except (IOError, OSError) as e:
            logger.error("Failed to load sessions: %s", e)
            return False
    
    def _validate_and_parse(self, data: dict[str, Any]) -> None:
        """
        セッションデータをバリデーションしてパース
        
        Raises:
            SessionValidationError: バリデーション失敗時
        """
        if not isinstance(data, dict):
            raise SessionValidationError("Root must be an object")
        
        sessions_list = data.get("sessions", [])
        if not isinstance(sessions_list, list):
            raise SessionValidationError("'sessions' must be an array")
        
        for session_data in sessions_list:
            self._validate_session(session_data)
            
            session = SessionConfig(
                name=session_data["name"],
                auth_type=session_data["auth_type"],
                credentials=session_data.get("credentials", {}),
            )
            self._sessions[session.name] = session
    
    def _validate_session(self, session_data: dict[str, Any]) -> None:
        """個別セッションのバリデーション"""
        if not isinstance(session_data, dict):
            raise SessionValidationError("Each session must be an object")
        
        name = session_data.get("name")
        if not name or not isinstance(name, str):
            raise SessionValidationError("Session 'name' is required and must be a string")
        
        auth_type = session_data.get("auth_type")
        if not auth_type or auth_type not in self.VALID_AUTH_TYPES:
            raise SessionValidationError(
                f"Session '{name}': 'auth_type' must be one of {self.VALID_AUTH_TYPES}"
            )
        
        credentials = session_data.get("credentials", {})
        if not isinstance(credentials, dict):
            raise SessionValidationError(f"Session '{name}': 'credentials' must be an object")
        
        # 認証タイプ別のバリデーション
        if auth_type == "cookie" and not credentials.get("cookie"):
            raise SessionValidationError(f"Session '{name}': 'cookie' credential required")
        elif auth_type == "bearer" and not credentials.get("token"):
            raise SessionValidationError(f"Session '{name}': 'token' credential required")
        elif auth_type == "basic" and not credentials.get("username"):
            raise SessionValidationError(f"Session '{name}': 'username' credential required")
        elif auth_type == "api_key" and not credentials.get("api_key"):
            raise SessionValidationError(f"Session '{name}': 'api_key' credential required")
    
    def get_session(self, name: str) -> Optional[SessionConfig]:
        """
        指定名のセッションを取得
        
        Args:
            name: セッション名 ("attacker" or "victim")
        
        Returns:
            SessionConfig or None
        """
        return self._sessions.get(name)
    
    def is_configured(self) -> bool:
        """
        必要なセッション（attacker, victim）が両方設定済みか確認
        
        Returns:
            True: 両方設定済み
        """
        return all(name in self._sessions for name in self.REQUIRED_SESSIONS)
    
    def make_request_as(
        self,
        session_name: str,
        method: str,
        url: str,
        headers: Optional[dict[str, str]] = None,
        body: Optional[str] = None,
        json_data: Optional[dict] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = False,  # M-5: デフォルトFalse（セキュリティテスト用）
    ) -> Optional[httpx.Response]:
        """
        指定セッションでリクエストを実行
        
        Args:
            session_name: 使用するセッション名
            method: HTTPメソッド
            url: リクエストURL
            headers: 追加ヘッダー（セッションヘッダーとマージ）
            body: リクエストボディ（文字列）
            json_data: JSONボディ
            timeout: タイムアウト秒数
        
        Returns:
            Response or None (エラー時)
        """
        session = self.get_session(session_name)
        if not session:
            logger.error("Session not found: %s", session_name)
            return None
        
        # ヘッダー構築（セッション認証 + 追加ヘッダー）
        request_headers = session.get_headers()
        if headers:
            request_headers.update(headers)
        
        try:
            response = httpx.request(
                method=method.upper(),
                url=url,
                headers=request_headers,
                data=body,
                json=json_data,
                timeout=timeout or self._request_timeout,
                follow_redirects=allow_redirects,  # M-5: パラメータで制御
            )
            # セッション情報はログに出力しない（セキュリティ）
            logger.debug(
                "Request as '%s': %s %s -> %d",
                session_name, method.upper(), url, response.status_code
            )
            return response
            
        except httpx.RequestError as e:
            logger.error("Request failed for session '%s': %s", session_name, e)
            return None
    
    def get_session_names(self) -> list[str]:
        """設定済みセッション名の一覧を取得"""
        return list(self._sessions.keys())
    
    def clear(self) -> None:
        """セッション情報をクリア（メモリから削除）"""
        self._sessions.clear()
        self._loaded = False


def create_session_manager(sessions_file: Path) -> Optional[MultiAccountSessionManager]:
    """
    セッションマネージャーを作成して読み込み
    
    Args:
        sessions_file: sessions.json のパス
    
    Returns:
        読み込み成功時は MultiAccountSessionManager、失敗時は None
    """
    manager = MultiAccountSessionManager(sessions_file)
    if manager.load_sessions():
        return manager
    return None
