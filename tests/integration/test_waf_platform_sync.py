import pytest
import os
from datetime import datetime
from unittest.mock import MagicMock, AsyncMock, patch
from aiohttp.client_reqrep import ClientResponse
from multidict import CIMultiDict

from src.core.infra.network_client import AsyncNetworkClient
from src.core.attack.waf_mutator import WAFPayloadMutator
from src.core.export.platform_sync import PlatformSyncClient, PlatformType
from src.core.models.finding import Finding, Severity, VulnType
from src.core.infra.event_bus import get_event_bus

class MockResponse:
    def __init__(self, status, text, headers):
        self.status = status
        self._text = text
        self.headers = CIMultiDict(headers)
        self.cookies = {}
        self.url = "http://example.com/api?id=1"
        
    async def text(self, *args, **kwargs):
        return self._text
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc, tb):
        pass

@pytest.mark.asyncio
async def test_waf_bypass_integration():
    """WAFバイパスとネットワーククライアントの結合テスト"""
    client = AsyncNetworkClient()
    
    # モックの作成
    with patch("aiohttp.ClientSession.request") as mock_request:
        # 最初のリクエストは403、2回目は200を返す
        mock_request.side_effect = [
            MockResponse(403, "blocked", {"Server": "WAF"}),
            MockResponse(200, "success", {"Content-Type": "text/html"})
        ]
        
        response = await client.request(
            "GET", 
            "http://example.com/api?id=1",
            auto_waf_bypass=True,
            use_proxy=False
        )
        
        # WAFバイパスが機能して2回目のリクエスト(200)が返ってくること
        assert response.status == 200
        assert response.text == "success"
        # 2回リクエストが送られたことを確認
        assert mock_request.call_count == 2
        
import os
@pytest.mark.asyncio
@patch.dict(os.environ, {"H1_API_KEY": "test_key", "H1_API_USER": "test_user"})
async def test_platform_sync_integration():
    """PlatformSyncとEventBusの結合テスト"""
    sync_client = PlatformSyncClient(PlatformType.HACKERONE)
    event_bus = get_event_bus()
    
    # 実際のリクエストをモック
    with patch.object(sync_client._network_client, "request") as mock_request:
        mock_response = MagicMock()
        mock_response.is_success = True
        mock_response.status = 200
        mock_response.json.return_value = {"data": {"id": "h1_123"}}
        mock_request.return_value = mock_response
        
        finding = Finding(
            title="Test Vuln",
            description="Test integration",
            severity=Severity.HIGH,
            vuln_type=VulnType.XSS,
            target_url="http://example.com/vuln",
            discovered_at=datetime.utcnow(),
            source_agent="IntegrationTest"
        )
        
        # HackerOneへの送信テスト
        result_id = await sync_client.sync_finding(finding, PlatformType.HACKERONE)
        
        # APIが呼ばれてIDが返ること
        assert mock_request.called
        assert result_id == "h1_123"
