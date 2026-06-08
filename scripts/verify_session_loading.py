import asyncio
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
import os
import shutil

from src.core.config.settings import Settings, UserSessionConfig, MultiSessionSettings
from src.core.workspace.shared_workspace import SharedWorkspace
from src.core.workspace.session_loader import SessionLoader
from src.core.models.url_context import RichUrlContext

class TestSessionLoading(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.test_root = Path("./tmp_test_workspace")
        if self.test_root.exists():
            shutil.rmtree(self.test_root)
        self.workspace = SharedWorkspace(workspace_root=str(self.test_root))

    def tearDown(self):
        if self.test_root.exists():
            shutil.rmtree(self.test_root)

    async def test_load_from_config(self):
        """YAML設定からのロードを検証"""
        settings = MagicMock(spec=Settings)
        settings.multi_session = MultiSessionSettings(
            enabled=True,
            sessions=[
                UserSessionConfig(role="admin", headers={"Authorization": "Bearer admin-token"}),
                UserSessionConfig(role="user", headers={"Authorization": "Bearer user-token"}, cookies="sess=123")
            ]
        )
        
        count = await SessionLoader.load_from_config(self.workspace, settings)
        self.assertEqual(count, 2)
        
        sessions = self.workspace.get_user_sessions()
        self.assertIn("admin", sessions)
        self.assertIn("user", sessions)
        self.assertEqual(sessions["admin"]["headers"]["Authorization"], "Bearer admin-token")
        self.assertEqual(sessions["user"]["cookies"], "sess=123")
        # Register logic: cookies=session_cfg.cookies.
        # UserSessionConfig.cookies exists.

    @patch("src.core.agents.specialized.caido_sitemap_agent.CaidoSitemapAgent.fetch_recent_requests")
    async def test_load_from_caido(self, mock_fetch):
        """Caidoからの抽出を検証"""
        # Mock data: 3 requests, 2 unique auth contexts
        mock_fetch.return_value = [
            RichUrlContext(url="http://a.com/1", auth_context={"Authorization": "Token A"}),
            RichUrlContext(url="http://a.com/2", auth_context={"Authorization": "Token A"}), # Duplicate
            RichUrlContext(url="http://a.com/3", auth_context={"Authorization": "Token B", "Cookie": "c=1"}),
            RichUrlContext(url="http://a.com/4", auth_context={}) # No auth
        ]
        
        count = await SessionLoader.load_from_caido(self.workspace, domain="a.com")
        self.assertEqual(count, 2)
        
        sessions = self.workspace.get_user_sessions()
        self.assertEqual(len(sessions), 2)
        self.assertIn("caido_session_1", sessions)
        self.assertIn("caido_session_2", sessions)

    def test_log_masking(self):
        """ログマスキングが機能しているか（目視確認用のログ出力をトリガー）"""
        # register_user_session を直接呼んでログを確認
        with self.assertLogs('src.core.workspace.shared_workspace', level='INFO') as cm:
            self.workspace.register_user_session(
                role="test_mask",
                headers={"Authorization": "SECRET_TOKEN", "X-Normal": "Public"},
                cookies="sensitive_cookie_data"
            )
            # ログメッセージに SECRET_TOKEN が含まれていないことを確認
            log_output = "".join(cm.output)
            self.assertIn("Registered user session for role: test_mask", log_output)
            self.assertNotIn("SECRET_TOKEN", log_output)
            self.assertNotIn("sensitive_cookie_data", log_output)
            print(f"\n[Masking Test Log Output]: {log_output}")

if __name__ == "__main__":
    unittest.main()
