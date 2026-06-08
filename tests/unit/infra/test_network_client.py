
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from aiohttp import ClientError

from src.core.infra.network_client import (
    AsyncNetworkClient,
    NetworkResponse,
    create_network_client,
)
from src.core.infra.proxy_manager import ProxyChainManager


class MockResponse:
    def __init__(self, text='{"success": true}', status=200):
        self._text = text
        self.status = status
        self.headers = {"Content-Type": "application/json"}
        self.url = "http://test.com"
        self.cookies = MagicMock()
        self.cookies.items.return_value = []
        
    async def text(self, errors=None):
        return self._text
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

@pytest.fixture
def mock_session():
    session = MagicMock()
    session.close = AsyncMock()
    session.request.return_value = MockResponse()
    session.closed = False
    return session

class TestAsyncNetworkClient:
    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_simple_request(self, mock_proxy_check, mock_start, mock_session):
        client = AsyncNetworkClient()
        client._session = mock_session
        
        resp = await client.request("GET", "http://test.com", use_proxy=False, use_cache=False)
        
        assert resp.status == 200
        assert resp.body == '{"success": true}'
        assert mock_session.request.called

    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_proxy_usage(self, mock_proxy_check, mock_start, mock_session):
        proxy_manager = MagicMock(spec=ProxyChainManager)
        proxy_manager.get_proxy.return_value = "http://p1"
        client = AsyncNetworkClient(proxy_manager=proxy_manager)
        client._session = mock_session
        
        await client.request("GET", "http://test.com", use_proxy=True, use_cache=False)
        
        # Check if proxy was passed to aiohttp
        assert mock_session.request.called
        _, kwargs = mock_session.request.call_args
        assert kwargs["proxy"] == "http://p1"

    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_retry_on_500(self, mock_proxy_check, mock_start, mock_session):
        mock_session.request.side_effect = [
            MockResponse(text="Error", status=500),
            MockResponse(text="OK", status=200)
        ]
        client = AsyncNetworkClient()
        client._session = mock_session
        
        resp = await client.request("GET", "http://test.com", retries=2, use_proxy=False, use_cache=False)
        
        assert resp.status == 200
        assert resp.body == "OK"
        assert mock_session.request.call_count == 2

    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_retry_on_connection_error(self, mock_proxy_check, mock_start, mock_session):
        mock_session.request.side_effect = [
            ClientError("ConnErr"),
            MockResponse(text="OK", status=200)
        ]
        client = AsyncNetworkClient()
        client._session = mock_session
        
        resp = await client.request("GET", "http://test.com", retries=2, use_proxy=False, use_cache=False)
        
        assert resp.status == 200
        assert mock_session.request.call_count == 2

    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_proxy_rotation_on_retry(self, mock_proxy_check, mock_start, mock_session):
        proxy_manager = MagicMock(spec=ProxyChainManager)
        proxy_manager.get_proxy.side_effect = ["http://p1", "http://p2"]
        client = AsyncNetworkClient(proxy_manager=proxy_manager)
        client._session = mock_session
        
        mock_session.request.side_effect = [
            MockResponse(text="Error", status=500),
            MockResponse(text="OK", status=200)
        ]
        
        await client.request("GET", "http://test.com", retries=2, use_proxy=True, use_cache=False)
        
        calls = mock_session.request.call_args_list
        assert len(calls) == 2
        assert calls[0].kwargs["proxy"] == "http://p1"
        assert calls[1].kwargs["proxy"] == "http://p2"

    @pytest.mark.asyncio
    async def test_context_manager(self):
        with patch('aiohttp.ClientSession') as MockSession:
            mock_instance = MockSession.return_value
            mock_instance.close = AsyncMock()
            
            async with AsyncNetworkClient() as client:
                pass


    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_auto_waf_bypass(self, mock_proxy_check, mock_start, mock_session):
        client = AsyncNetworkClient()
        client._session = mock_session
        
        # 1回目は403(WAFブロック)、2回目は200を返すモック
        mock_session.request.side_effect = [
            MockResponse(text="Blocked by WAF", status=403),
            MockResponse(text="OK", status=200)
        ]
        
        # 元のパラメータ
        params = {"q": "SELECT * FROM users"}
        
        # リクエスト実行 (auto_waf_bypass=True)
        resp = await client.request(
            "GET", "http://test.com", 
            params=params, 
            retries=1, 
            use_proxy=False, 
            use_cache=False,
            auto_waf_bypass=True
        )
        
        assert resp.status == 200
        assert mock_session.request.call_count == 2
        
        # 1回目の呼び出し
        call1_kwargs = mock_session.request.call_args_list[0].kwargs
        assert call1_kwargs["params"]["q"] == "SELECT * FROM users"
        
        # 2回目の呼び出し（変異されているため元の文字列ではないはず）
        call2_kwargs = mock_session.request.call_args_list[1].kwargs
        assert call2_kwargs["params"]["q"] != "SELECT * FROM users"
