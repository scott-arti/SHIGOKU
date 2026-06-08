import pytest
import subprocess
from unittest.mock import MagicMock, patch
from pathlib import Path
from src.tools.custom.katana import KatanaTool
from src.tools.custom.httpx import HttpxTool
from src.recon.pipeline import ReconPipeline

class TestAuthHeaderInjection:
    @patch("src.tools.custom.katana.subprocess.Popen")
    def test_katana_emits_heartbeat_during_long_run(self, mock_popen, caplog):
        """Verify KatanaTool emits heartbeat logs while crawl is still running."""
        tool = KatanaTool()

        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = [
            subprocess.TimeoutExpired(cmd=["katana"], timeout=15),
            ("{\\\"url\\\":\\\"http://example.com\\\"}\\n", ""),
        ]
        mock_popen.return_value = mock_proc

        caplog.set_level("INFO")
        result = tool.run("http://example.com", mode="standard")

        assert "example.com" in result
        assert any("Katana heartbeat" in record.message for record in caplog.records)

    @patch("src.tools.custom.katana.subprocess.Popen")
    def test_katana_auth_headers(self, mock_popen):
        """Verify KatanaTool accepts and injects headers"""
        tool = KatanaTool()
        headers = ["Cookie: session=123"]

        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("", "")
        mock_popen.return_value = mock_proc
        
        tool.run("example.com", headers=headers)
        
        args, _ = mock_popen.call_args
        cmd_list = args[0]
        
        assert "-H" in cmd_list
        # Check that the header follows -H
        h_index = cmd_list.index("-H")
        assert cmd_list[h_index + 1] == "Cookie: session=123"
    
    @patch("src.tools.custom.httpx.safe_run")
    def test_httpx_auth_headers(self, mock_run):
        """Verify HttpxTool accepts and injects headers"""
        tool = HttpxTool()
        headers = ["Cookie: session=abc"]
        
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        
        tool.run("example.com", headers=headers)
        
        args, _ = mock_run.call_args
        cmd_list = args[0]
        
        assert "-H" in cmd_list
        h_index = cmd_list.index("-H")
        assert cmd_list[h_index + 1] == "Cookie: session=abc"

    def test_pipeline_cookie_extraction(self):
        """Verify ReconPipeline extracts cookies from MC context"""
        # Mock MC and Context
        mock_mc = MagicMock()
        mock_mc.context.target_info = {"cookies": "key=value"}
        
        pipeline = ReconPipeline(
            config={},
            project_manager=MagicMock(),
            target="example.com",
            master_conductor=mock_mc,
            workspace_root=Path("/tmp")
        )
        header = pipeline._get_cookie_header()
        
        assert header == "Cookie: key=value"

    def test_pipeline_cookie_extraction_none(self):
        """Verify ReconPipeline handles missing cookies correctly"""
        mock_mc = MagicMock()
        mock_mc.context.target_info = {} # No cookies
        
        pipeline = ReconPipeline(
            config={},
            project_manager=MagicMock(),
            target="example.com",
            master_conductor=mock_mc,
            workspace_root=Path("/tmp")
        )
        header = pipeline._get_cookie_header()
        
        assert header is None

    def test_pipeline_context_auth_headers_include_bearer_and_cookie(self):
        """Verify ReconPipeline composes auth headers from context cookies/bearer/custom headers."""
        mock_mc = MagicMock()
        mock_mc.context.target_info = {
            "cookies": "session=abc",
            "bearer_token": "jwt-token",
            "auth_headers": {"X-Tenant": "acme"},
        }

        pipeline = ReconPipeline(
            config={},
            project_manager=MagicMock(),
            target="example.com",
            master_conductor=mock_mc,
            workspace_root=Path("/tmp")
        )
        headers = pipeline._get_context_auth_headers()
        header_lines = pipeline._get_auth_header_lines()

        assert headers["Cookie"] == "session=abc"
        assert headers["Authorization"] == "Bearer jwt-token"
        assert headers["X-Tenant"] == "acme"
        assert "Cookie: session=abc" in header_lines
        assert "Authorization: Bearer jwt-token" in header_lines
