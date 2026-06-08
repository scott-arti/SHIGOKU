import pytest
import os
import json
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime

from src.core.models.finding import Finding, Severity, VulnType
from src.core.export.platform_sync import PlatformSyncClient, PlatformType
from src.core.infra.network_client import NetworkResponse


@pytest.fixture
def mock_network_client():
    client = MagicMock()
    
    # モックリスポンスのセットアップ
    mock_resp = MagicMock(spec=NetworkResponse)
    mock_resp.is_success = True
    mock_resp.status = 200
    mock_resp.json.return_value = {"data": {"id": "12345"}, "id": "sub_67890"}
    
    client.request = AsyncMock(return_value=mock_resp)
    return client

@pytest.fixture
def sample_finding():
    return Finding(
        title="Test XSS vulnerability",
        description="Found Reflected XSS on search page",
        severity=Severity.HIGH,
        vuln_type=VulnType.XSS,
        target_url="https://example.com/search?q=<script>alert(1)</script>",
        cwe_id="79",
        cvss_score=7.5,
        discovered_at=datetime.utcnow(),
        source_agent="TestAgent",
        additional_info={"remediation_status": "NEW"}
    )

class TestPlatformSyncClient:

    @patch.dict(os.environ, {"H1_API_KEY": "test_key", "H1_API_USER": "test_user"})
    def test_is_configured_h1(self):
        client = PlatformSyncClient(PlatformType.HACKERONE)
        assert client.is_configured()

    @patch.dict(os.environ, {"BUGCROWD_API_KEY": "test_bc_key"})
    def test_is_configured_bugcrowd(self):
        client = PlatformSyncClient(PlatformType.BUGCROWD)
        assert client.is_configured()

    def test_not_configured_when_missing_creds(self):
        with patch.dict(os.environ, {}, clear=True):
            client = PlatformSyncClient(PlatformType.HACKERONE)
            assert not client.is_configured()

    @pytest.mark.asyncio
    @patch.dict(os.environ, {"H1_API_KEY": "test_key", "H1_API_USER": "test_user"})
    async def test_sync_to_hackerone_success(self, mock_network_client, sample_finding):
        client = PlatformSyncClient(PlatformType.HACKERONE, network_client=mock_network_client)
        
        report_id = await client.sync_finding(sample_finding, "program_123")
        
        assert report_id == "12345"
        mock_network_client.request.assert_called_once()
        args, kwargs = mock_network_client.request.call_args
        assert args[0] == "POST"
        assert "api.hackerone.com" in args[1]
        assert "Authorization" in kwargs["headers"]
        assert kwargs["json"]["data"]["attributes"]["title"] == sample_finding.title

    @pytest.mark.asyncio
    @patch.dict(os.environ, {"BUGCROWD_API_KEY": "test_bc_key"})
    async def test_sync_to_bugcrowd_success(self, mock_network_client, sample_finding):
        client = PlatformSyncClient(PlatformType.BUGCROWD, network_client=mock_network_client)
        
        submission_id = await client.sync_finding(sample_finding, "bc_prog_456")
        
        assert submission_id == "sub_67890"
        mock_network_client.request.assert_called_once()
        args, kwargs = mock_network_client.request.call_args
        assert args[0] == "POST"
        assert "api.bugcrowd.com" in args[1]
        assert kwargs["headers"]["Authorization"] == "Token test_bc_key"
        assert kwargs["json"]["submission"]["title"] == sample_finding.title

    @pytest.mark.asyncio
    @patch.dict(os.environ, {"H1_API_KEY": "test_key", "H1_API_USER": "test_user"})
    async def test_no_sync_when_rejected(self, mock_network_client, sample_finding):
        client = PlatformSyncClient(PlatformType.HACKERONE, network_client=mock_network_client)
        sample_finding.additional_info["remediation_status"] = "REJECTED"
        
        report_id = await client.sync_finding(sample_finding, "program_123")
        
        assert report_id is None
        mock_network_client.request.assert_not_called()
