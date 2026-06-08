
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from src.core.infra.smart_request import SmartRequest

@pytest.mark.asyncio
async def test_smart_request_retry():
    mock_client = AsyncMock()
    # Simulate 429 then 200
    resp_429 = MagicMock(status=429)
    resp_200 = MagicMock(status=200, headers={}, body="OK")
    
    mock_client.request.side_effect = [resp_429, resp_200]
    
    smart_req = SmartRequest(mock_client)
    # Monkeypatch sleep to be fast
    with pytest.MonkeyPatch.context() as m:
        m.setattr(asyncio, "sleep", AsyncMock())
        result = await smart_req.request("GET", "http://example.com")
    
    assert result["status"] == 200
    assert mock_client.request.call_count == 2

@pytest.mark.asyncio
async def test_smart_request_waf():
    mock_client = AsyncMock()
    # Simulate 403 with WAF body
    resp_403 = MagicMock(status=403, headers={}, body="<h1>Blocked by WAF</h1>")
    mock_client.request.return_value = resp_403
    
    smart_req = SmartRequest(mock_client)
    result = await smart_req.request("GET", "http://example.com")
    
    assert result["status"] == 403
    assert result["waf_suspected"] is True
    assert result["waf_confirmed"] is True

@pytest.mark.asyncio
async def test_smart_request_diff():
    mock_client = AsyncMock()
    
    # Baseline
    resp_base = MagicMock(status=200, headers={}, body="Line1\nLine2\nLine3")
    mock_client.request.return_value = resp_base
    smart_req = SmartRequest(mock_client)
    
    res1 = await smart_req.request("GET", "http://base")
    assert "Baseline" in res1["diff"]
    
    # Changed response
    resp_new = MagicMock(status=200, headers={}, body="Line1\nLine2_Changed\nLine3")
    mock_client.request.return_value = resp_new
    
    res2 = await smart_req.request("GET", "http://new")
    assert "Line2_Changed" in res2["diff"]
