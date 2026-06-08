import pytest
from unittest.mock import AsyncMock, MagicMock
from src.core.agents.swarm.injection.smart_xss import SmartXSSHunter

@pytest.fixture
def mock_llm():
    llm = MagicMock()
    llm.agenerate = AsyncMock()
    return llm

@pytest.mark.asyncio
async def test_xss_reflection_detection(mock_llm):
    hunter = SmartXSSHunter()
    hunter.llm = mock_llm
    
    url = "http://example.com/search"
    payload = "<script>alert(1)</script>"
    
    # 1. 反射がある場合
    # SmartXSSHunter._send_request 内で self.smart_client.request を呼んでいることを想定
    hunter.smart_client = AsyncMock()
    hunter.smart_client.request.return_value = {
        "status": 200, 
        "body": f"<html><body>Search results for: {payload}</body></html>",
        "headers": {}
    }
    
    # クラスの内部メソッドを直接テスト
    result = await hunter._send_request(payload)
    
    assert result["status"] == 200
    assert result["diff"] == "reflected"
    assert payload.lower() in result["body_snippet"].lower()

@pytest.mark.asyncio
async def test_xss_no_reflection(mock_llm):
    hunter = SmartXSSHunter()
    hunter.llm = mock_llm
    
    url = "http://example.com/search"
    payload = "<script>alert(1)</script>"
    
    # 2. 反射がない場合
    hunter.smart_client = AsyncMock()
    hunter.smart_client.request.return_value = {
        "status": 200, 
        "body": "<html><body>No results found.</body></html>",
        "headers": {}
    }
    
    result = await hunter._send_request(payload)
    
    assert result["status"] == 200
    assert result["diff"] == "normal"
    assert payload.lower() not in result["body_snippet"].lower()


@pytest.mark.asyncio
async def test_validate_dom_runtime_xss_prefers_browser_pool(monkeypatch):
    hunter = SmartXSSHunter()

    class _DummyResult:
        executed = True

    class _DummyVerifier:
        async def verify(self, url, parameter, payload, *, dialog_timeout=3.0):
            return _DummyResult()

        async def close(self):
            return None

    import src.core.detection.browser_pool as browser_pool_module
    monkeypatch.setattr(browser_pool_module, "BrowserPoolXSSVerifier", _DummyVerifier)

    executed = await hunter._validate_dom_runtime_xss(
        "http://example.com/#/search",
        "<img src=x onerror=alert(1)>",
        "",
        param_name="q",
    )

    assert executed is True
