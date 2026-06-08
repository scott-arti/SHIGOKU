"""
Tests for MultiAccountSessionManager
"""
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.core.security.multi_account_session import (
    MultiAccountSessionManager,
    SessionConfig,
    SessionValidationError,
    create_session_manager,
)


class TestSessionConfig:
    """SessionConfigのテスト"""

    def test_get_headers_cookie(self):
        """Cookie認証のヘッダー生成"""
        config = SessionConfig(
            name="test",
            auth_type="cookie",
            credentials={"cookie": "session=abc123; csrf=xyz"}
        )
        headers = config.get_headers()
        assert headers == {"Cookie": "session=abc123; csrf=xyz"}

    def test_get_headers_bearer(self):
        """Bearer トークン認証のヘッダー生成"""
        config = SessionConfig(
            name="test",
            auth_type="bearer",
            credentials={"token": "eyJhbGciOiJIUzI1NiJ9.test"}
        )
        headers = config.get_headers()
        assert headers == {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.test"}

    def test_get_headers_basic(self):
        """Basic認証のヘッダー生成"""
        config = SessionConfig(
            name="test",
            auth_type="basic",
            credentials={"username": "user", "password": "pass"}
        )
        headers = config.get_headers()
        # user:pass -> base64 -> dXNlcjpwYXNz
        assert headers["Authorization"] == "Basic dXNlcjpwYXNz"

    def test_get_headers_api_key(self):
        """APIキー認証のヘッダー生成"""
        config = SessionConfig(
            name="test",
            auth_type="api_key",
            credentials={"api_key": "my-api-key", "header_name": "X-Custom-Key"}
        )
        headers = config.get_headers()
        assert headers == {"X-Custom-Key": "my-api-key"}

    def test_get_headers_api_key_default_header(self):
        """APIキー認証のデフォルトヘッダー名"""
        config = SessionConfig(
            name="test",
            auth_type="api_key",
            credentials={"api_key": "my-api-key"}
        )
        headers = config.get_headers()
        assert headers == {"X-API-Key": "my-api-key"}


class TestMultiAccountSessionManager:
    """MultiAccountSessionManagerのテスト"""

    def _create_sessions_file(self, sessions_data: dict) -> Path:
        """テスト用セッションファイルを作成"""
        temp_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        )
        json.dump(sessions_data, temp_file)
        temp_file.close()
        return Path(temp_file.name)

    def test_load_valid_sessions(self):
        """正常なsessions.jsonを読み込めること"""
        sessions_data = {
            "sessions": [
                {
                    "name": "attacker",
                    "auth_type": "cookie",
                    "credentials": {"cookie": "attacker_session=abc"}
                },
                {
                    "name": "victim",
                    "auth_type": "cookie",
                    "credentials": {"cookie": "victim_session=xyz"}
                }
            ]
        }
        file_path = self._create_sessions_file(sessions_data)
        
        try:
            manager = MultiAccountSessionManager(file_path)
            result = manager.load_sessions()
            
            assert result is True
            assert manager.is_configured() is True
            assert "attacker" in manager.get_session_names()
            assert "victim" in manager.get_session_names()
        finally:
            file_path.unlink()

    def test_load_missing_file(self):
        """存在しないファイルでエラー"""
        manager = MultiAccountSessionManager(Path("/nonexistent/sessions.json"))
        result = manager.load_sessions()
        
        assert result is False
        assert manager.is_configured() is False

    def test_load_invalid_json(self):
        """不正なJSONでエラー"""
        temp_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        )
        temp_file.write("{ invalid json }")
        temp_file.close()
        file_path = Path(temp_file.name)
        
        try:
            manager = MultiAccountSessionManager(file_path)
            result = manager.load_sessions()
            
            assert result is False
        finally:
            file_path.unlink()

    def test_validation_missing_auth_type(self):
        """auth_type欠落でバリデーションエラー"""
        sessions_data = {
            "sessions": [
                {"name": "attacker", "credentials": {"cookie": "abc"}}
            ]
        }
        file_path = self._create_sessions_file(sessions_data)
        
        try:
            manager = MultiAccountSessionManager(file_path)
            result = manager.load_sessions()
            
            assert result is False
        finally:
            file_path.unlink()

    def test_validation_missing_credentials(self):
        """必須credentials欠落でバリデーションエラー"""
        sessions_data = {
            "sessions": [
                {"name": "attacker", "auth_type": "cookie", "credentials": {}}
            ]
        }
        file_path = self._create_sessions_file(sessions_data)
        
        try:
            manager = MultiAccountSessionManager(file_path)
            result = manager.load_sessions()
            
            assert result is False
        finally:
            file_path.unlink()

    def test_is_configured_partial(self):
        """片方のセッションのみではis_configured=False"""
        sessions_data = {
            "sessions": [
                {
                    "name": "attacker",
                    "auth_type": "cookie",
                    "credentials": {"cookie": "abc"}
                }
            ]
        }
        file_path = self._create_sessions_file(sessions_data)
        
        try:
            manager = MultiAccountSessionManager(file_path)
            manager.load_sessions()
            
            assert manager.is_configured() is False
        finally:
            file_path.unlink()

    @patch('src.core.security.multi_account_session.httpx.request')
    def test_make_request_as(self, mock_request):
        """指定セッションでリクエストを実行"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        
        sessions_data = {
            "sessions": [
                {
                    "name": "attacker",
                    "auth_type": "cookie",
                    "credentials": {"cookie": "attacker_session=abc"}
                },
                {
                    "name": "victim",
                    "auth_type": "bearer",
                    "credentials": {"token": "victim_token"}
                }
            ]
        }
        file_path = self._create_sessions_file(sessions_data)
        
        try:
            manager = MultiAccountSessionManager(file_path)
            manager.load_sessions()
            
            response = manager.make_request_as("attacker", "GET", "https://example.com/api")
            
            assert response is not None
            assert response.status_code == 200
            
            # リクエストヘッダーを確認
            call_kwargs = mock_request.call_args.kwargs
            assert call_kwargs["headers"]["Cookie"] == "attacker_session=abc"
        finally:
            file_path.unlink()

    def test_make_request_as_unknown_session(self):
        """未知のセッション名でNoneを返す"""
        sessions_data = {
            "sessions": [
                {
                    "name": "attacker",
                    "auth_type": "cookie",
                    "credentials": {"cookie": "abc"}
                }
            ]
        }
        file_path = self._create_sessions_file(sessions_data)
        
        try:
            manager = MultiAccountSessionManager(file_path)
            manager.load_sessions()
            
            response = manager.make_request_as("unknown", "GET", "https://example.com")
            
            assert response is None
        finally:
            file_path.unlink()

    def test_clear(self):
        """セッション情報がクリアされること"""
        sessions_data = {
            "sessions": [
                {
                    "name": "attacker",
                    "auth_type": "cookie",
                    "credentials": {"cookie": "abc"}
                }
            ]
        }
        file_path = self._create_sessions_file(sessions_data)
        
        try:
            manager = MultiAccountSessionManager(file_path)
            manager.load_sessions()
            
            assert len(manager.get_session_names()) == 1
            
            manager.clear()
            
            assert len(manager.get_session_names()) == 0
        finally:
            file_path.unlink()


class TestCreateSessionManager:
    """create_session_manager関数のテスト"""

    def test_create_success(self):
        """正常ファイルでSessionManagerが返る"""
        sessions_data = {
            "sessions": [
                {
                    "name": "attacker",
                    "auth_type": "cookie",
                    "credentials": {"cookie": "abc"}
                },
                {
                    "name": "victim",
                    "auth_type": "cookie",
                    "credentials": {"cookie": "xyz"}
                }
            ]
        }
        temp_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        )
        json.dump(sessions_data, temp_file)
        temp_file.close()
        file_path = Path(temp_file.name)
        
        try:
            manager = create_session_manager(file_path)
            
            assert manager is not None
            assert manager.is_configured() is True
        finally:
            file_path.unlink()

    def test_create_failure(self):
        """読み込み失敗でNoneが返る"""
        manager = create_session_manager(Path("/nonexistent/sessions.json"))
        
        assert manager is None
