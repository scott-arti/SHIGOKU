
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from src.core.security.request_guard import RequestGuard, reset_request_guard

@pytest.fixture
def mock_hitl():
    return AsyncMock(return_value=True)

@pytest.fixture
def guard(mock_hitl):
    reset_request_guard()
    return RequestGuard(mode="bugbounty", hitl_callback=mock_hitl)

@pytest.mark.asyncio
async def test_get_is_always_allowed(guard, mock_hitl):
    assert await guard.check("GET", "http://example.com/api/test") is True
    assert mock_hitl.call_count == 0

@pytest.mark.asyncio
async def test_post_requires_approval(guard, mock_hitl):
    # 初回呼び出し
    assert await guard.check("POST", "http://example.com/api/data") is True
    assert mock_hitl.call_count == 1
    
    # 2回目はキャッシュされるはず
    assert await guard.check("POST", "http://example.com/api/data") is True
    assert mock_hitl.call_count == 1

@pytest.mark.asyncio
async def test_path_normalization(guard, mock_hitl):
    # ID付きURL
    assert await guard.check("POST", "http://example.com/api/users/123") is True
    assert mock_hitl.call_count == 1
    
    # 違うIDでも正規化されていればキャッシュヒットするはず
    assert await guard.check("POST", "http://example.com/api/users/456") is True
    assert mock_hitl.call_count == 1
    
    # UUID
    uuid_url = "http://example.com/api/items/550e8400-e29b-41d4-a716-446655440000"
    assert await guard.check("PUT", uuid_url) is True
    assert mock_hitl.call_count == 2
    
    # 違うUUID
    uuid_url2 = "http://example.com/api/items/a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
    assert await guard.check("PUT", uuid_url2) is True
    assert mock_hitl.call_count == 2

@pytest.mark.asyncio
async def test_user_denial(guard, mock_hitl):
    mock_hitl.return_value = False
    
    assert await guard.check("DELETE", "http://example.com/api/secret") is False
    assert mock_hitl.call_count == 1
    
    # 拒否もキャッシュされる
    assert await guard.check("DELETE", "http://example.com/api/secret") is False
    assert mock_hitl.call_count == 1

@pytest.mark.asyncio
async def test_ctf_mode_auto_approval():
    reset_request_guard()
    ctf_guard = RequestGuard(mode="ctf")
    
    assert await ctf_guard.check("POST", "http://anywhere.com") is True
    # コールバックがなくても通過するはず
