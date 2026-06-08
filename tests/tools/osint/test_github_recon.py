
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.tools.osint.github_recon import GitHubClient

@pytest.mark.asyncio
async def test_github_client_init():
    client = GitHubClient(token="test_token")
    assert client.token == "test_token"
    assert client.network_client is None

    mock_nc = AsyncMock()
    client_with_nc = GitHubClient(token="test_token", network_client=mock_nc)
    assert client_with_nc.network_client == mock_nc

@pytest.mark.asyncio
async def test_search_org_repos_with_network_client():
    mock_nc = AsyncMock()
    
    # Mock NetworkResponse
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.status_code = 200
    mock_resp.json.return_value = [{"name": "repo1"}]
    mock_resp.text = '[{"name": "repo1"}]'
    
    mock_nc.request.return_value = mock_resp
    
    client = GitHubClient(token="test_token", network_client=mock_nc)
    repos = await client.search_org_repos("test_org")
    
    assert repos == [{"name": "repo1"}]
    mock_nc.request.assert_called_once()
    args, kwargs = mock_nc.request.call_args
    assert args[0] == "GET"
    assert "users/test_org/repos" in args[1]
    assert kwargs["use_proxy"] is True

@pytest.mark.asyncio
async def test_search_org_repos_fallback():
    # Mock aiohttp.ClientSession
    with patch("aiohttp.ClientSession") as mock_session_cls:
        mock_session_instance = MagicMock()
        
        # Helper to make an async context manager
        class AsyncContextManager:
            def __init__(self, return_value):
                self.return_value = return_value
            async def __aenter__(self):
                return self.return_value
            async def __aexit__(self, exc_type, exc, tb):
                pass
        
        # Setup Session Context
        mock_session_cls.return_value = AsyncContextManager(mock_session_instance)
        
        # Setup Response
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value='[{"name": "repo1"}]')
        
        # Setup GET Context
        mock_session_instance.get.return_value = AsyncContextManager(mock_resp)
        
        client = GitHubClient(token="test_token")
        repos = await client.search_org_repos("test_org")
        
        assert repos == [{"name": "repo1"}]
        mock_session_instance.get.assert_called()

@pytest.mark.asyncio
async def test_search_org_repos_404_retry_with_nc():
    mock_nc = AsyncMock()
    
    # First response: 404
    resp1 = MagicMock()
    resp1.status = 404
    resp1.status_code = 404
    
    # Second response: 200
    resp2 = MagicMock()
    resp2.status = 200
    resp2.status_code = 200
    resp2.json.return_value = [{"name": "org_repo"}]
    
    mock_nc.request.side_effect = [resp1, resp2]
    
    client = GitHubClient(token="test_token", network_client=mock_nc)
    repos = await client.search_org_repos("test_org")
    
    assert repos == [{"name": "org_repo"}]
    assert mock_nc.request.call_count == 2
    args1, _ = mock_nc.request.call_args_list[0]
    args2, _ = mock_nc.request.call_args_list[1]
    assert "users/test_org/repos" in args1[1]
    assert "orgs/test_org/repos" in args2[1]
