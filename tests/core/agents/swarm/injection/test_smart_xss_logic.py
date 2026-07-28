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
    hunter.context = {
        "param": "q",
        "target": url,
        "method": "GET",
        "params": {"q": "test"},
        "auth_headers": {},
        "content_type": "",
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
    hunter.context = {
        "param": "q",
        "target": url,
        "method": "GET",
        "params": {"q": "test"},
        "auth_headers": {},
        "content_type": "",
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


@pytest.mark.asyncio
async def test_xss_finding_carries_browser_execution_and_poc_metadata(monkeypatch):
    hunter = SmartXSSHunter(config={"model": "test-model", "mode": "ctf"})

    async def fake_run_as_tool(url, params):
        return {
            "vulnerable": True,
            "reflection_observed": True,
            "evidence": "browser dialog observed",
            "param": "name",
            "tested_params": ["name"],
            "payloads_used": ["<img src=x onerror=alert(1)>"],
            "description": "XSS detected.",
            "browser_execution": {
                "dialog_observed": True,
                "executor": "playwright",
                "execution_token": "shigoku-xss",
                "test_url": "http://example.com/search?name=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E",
            },
            "poc_request": (
                "GET /search?name=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E HTTP/1.1\n"
                "Host: example.com"
            ),
            "poc_response": "HTTP/1.1 200\n\n<html>browser dialog observed</html>",
        }

    monkeypatch.setattr(hunter, "run_as_tool", fake_run_as_tool)

    finding = (await hunter.execute(
        MagicMock(
            target="http://example.com/search",
            params={"name": "test"},
        )
    ))[0]

    assert finding.additional_info["browser_execution"]["dialog_observed"] is True
    assert "%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E" in finding.additional_info["poc_request"]
    assert finding.evidence.request_url == "http://example.com/search?name=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E"


@pytest.mark.asyncio
async def test_dom_xss_finding_rewrites_poc_request_to_browser_test_url(monkeypatch):
    hunter = SmartXSSHunter(config={"model": "test-model", "mode": "ctf"})

    async def fake_run_as_tool(url, params):
        return {
            "vulnerable": True,
            "reflection_observed": True,
            "evidence": "DOM mutation observed",
            "param": "default",
            "tested_params": ["default"],
            "payloads_used": ["<script>alert(1)</script>"],
            "description": "DOM XSS detected.",
            "browser_execution": {
                "dom_mutation_observed": True,
                "executor": "playwright",
                "event": "dom_sink_reflection",
                "variant": "dom",
                "parameter": "default",
                "payload": "<script>alert(1)</script>",
                "test_url": (
                    "http://example.com/vulnerabilities/xss_d/"
                    "?default=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
                    "#<script>alert(1)</script>"
                ),
            },
            "poc_request": (
                "GET /vulnerabilities/xss_d/?default=javascript%3Aalert%281%29 HTTP/1.1\n"
                "Host: example.com"
            ),
            "poc_response": "HTTP/1.1 200\n\n<html>DOM mutation observed</html>",
        }

    monkeypatch.setattr(hunter, "run_as_tool", fake_run_as_tool)

    finding = (await hunter.execute(
        MagicMock(
            target="http://example.com/vulnerabilities/xss_d/",
            params={"default": "English"},
        )
    ))[0]

    assert "default=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" in finding.additional_info["poc_request"]
    assert "javascript%3Aalert%281%29" not in finding.additional_info["poc_request"]
    assert finding.evidence.request_url.startswith("http://example.com/vulnerabilities/xss_d/?default=%3Cscript")


@pytest.mark.asyncio
async def test_validate_reflected_runtime_xss_uses_playwright_fallback(monkeypatch):
    hunter = SmartXSSHunter()

    class _StaticReflectionResult:
        executed = True
        evidence = {"method": "static_reflection"}
        parameter = "name"
        payload = "<img src=x onerror=alert(1)>"
        url = "http://example.com/search?name=original"

    class _StaticReflectionVerifier:
        async def verify(self, url, parameter, payload, *, dialog_timeout=3.0):
            return _StaticReflectionResult()

        async def close(self):
            return None

    class _FallbackPlaywrightValidator:
        is_available = True

        def __init__(self):
            self._browser_args = []

        async def validate_xss(self, url, timeout=10.0, cookies=None):
            self.__class__.seen_url = url
            self.__class__.seen_cookies = cookies
            return True

    import src.core.detection.browser_pool as browser_pool_module
    import src.tools.browser.playwright_validator as playwright_validator_module

    monkeypatch.setattr(browser_pool_module, "BrowserPoolXSSVerifier", _StaticReflectionVerifier)
    monkeypatch.setattr(playwright_validator_module, "PlaywrightValidator", _FallbackPlaywrightValidator)

    executed = await hunter._validate_reflected_runtime_xss(
        "http://example.com/search?name=original",
        "<img src=x onerror=alert(1)>",
        "name",
        cookies_str="PHPSESSID=abc123",
    )

    assert executed is True
    assert "name=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E" in _FallbackPlaywrightValidator.seen_url
    assert _FallbackPlaywrightValidator.seen_cookies == [
        {"name": "PHPSESSID", "value": "abc123", "domain": "example.com", "path": "/"}
    ]
    assert hunter._browser_execution_evidence["executor"] == "playwright"
    assert hunter._browser_execution_evidence["variant"] == "reflected"
