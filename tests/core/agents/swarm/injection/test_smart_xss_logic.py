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


# ---------------------------------------------------------------------------
# SGK-2026-0456: DOM XSS の発火経路をフラグメント（hash）へ拡張
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_validate_dom_runtime_xss_builds_product_independent_fragment_candidates(monkeypatch):
    """T1: サーバ側 URL の path+query から製品非依存で #/<path>?<query-with-payload> を生成する。"""
    hunter = SmartXSSHunter()

    class _NotExecutedResult:
        executed = False

    class _NotExecutedVerifier:
        async def verify(self, url, parameter, payload, *, dialog_timeout=3.0):
            return _NotExecutedResult()

        async def close(self):
            return None

    class _RecordingValidator:
        is_available = True
        seen_urls = []

        def __init__(self):
            self._browser_args = []

        async def validate_xss(self, url, timeout=10.0, cookies=None):
            _RecordingValidator.seen_urls.append(url)
            return False

    import src.core.detection.browser_pool as browser_pool_module
    import src.tools.browser.playwright_validator as playwright_validator_module
    import playwright.async_api as playwright_async_api

    monkeypatch.setattr(browser_pool_module, "BrowserPoolXSSVerifier", _NotExecutedVerifier)
    monkeypatch.setattr(playwright_validator_module, "PlaywrightValidator", _RecordingValidator)

    def _raise_no_playwright(*args, **kwargs):
        raise RuntimeError("playwright disabled in test")

    monkeypatch.setattr(playwright_async_api, "async_playwright", _raise_no_playwright)

    from urllib.parse import urlsplit, parse_qs

    # ルート1: /search?q=test&name=x + param=name → #/search?q=test&name=<payload>
    _RecordingValidator.seen_urls = []
    executed = await hunter._validate_dom_runtime_xss(
        "http://example.com/search?q=test&name=x",
        "<img src=x onerror=alert(1)>",
        "",
        param_name="name",
    )
    assert executed is False

    fragment_urls = [
        u for u in _RecordingValidator.seen_urls
        if u.startswith("http://example.com/#/")
    ]
    assert fragment_urls, f"no fragment candidate generated: {_RecordingValidator.seen_urls}"
    frag = urlsplit(fragment_urls[0]).fragment
    frag_path, _, frag_query = frag.partition("?")
    assert frag_path == "/search"
    frag_params = parse_qs(frag_query)
    assert frag_params.get("q") == ["test"]
    assert any("<img src=x onerror=alert(1)>" in v for v in frag_params.get("name", []))

    # ルート2: 別ルート /foo/bar?x=1 + param=x → #/foo/bar?x=<payload>（製品非依存）
    _RecordingValidator.seen_urls = []
    executed2 = await hunter._validate_dom_runtime_xss(
        "http://example.com/foo/bar?x=1",
        "<img src=x onerror=alert(1)>",
        "",
        param_name="x",
    )
    assert executed2 is False

    fragment_urls2 = [
        u for u in _RecordingValidator.seen_urls
        if u.startswith("http://example.com/#/")
    ]
    assert fragment_urls2, f"no fragment candidate generated: {_RecordingValidator.seen_urls}"
    frag2 = urlsplit(fragment_urls2[0]).fragment
    assert frag2.startswith("/foo/bar?x=")
    frag2_params = parse_qs(frag2.partition("?")[2])
    assert any("<img src=x onerror=alert(1)>" in v for v in frag2_params.get("x", []))


@pytest.mark.asyncio
async def test_validate_dom_runtime_xss_dialog_sets_dialog_observed(monkeypatch):
    """T2a: フラグメント URL で dialog が発火した場合のみ dialog_observed=True になる。"""
    hunter = SmartXSSHunter()

    class _NotExecutedResult:
        executed = False

    class _NotExecutedVerifier:
        async def verify(self, url, parameter, payload, *, dialog_timeout=3.0):
            return _NotExecutedResult()

        async def close(self):
            return None

    class _FiringValidator:
        is_available = True

        def __init__(self):
            self._browser_args = []
            self._last_observation_logs = []

        async def validate_xss(self, url, timeout=10.0, cookies=None):
            return True

    import src.core.detection.browser_pool as browser_pool_module
    import src.tools.browser.playwright_validator as playwright_validator_module

    monkeypatch.setattr(browser_pool_module, "BrowserPoolXSSVerifier", _NotExecutedVerifier)
    monkeypatch.setattr(playwright_validator_module, "PlaywrightValidator", _FiringValidator)

    executed = await hunter._validate_dom_runtime_xss(
        "http://example.com/search?q=test&name=x",
        "<img src=x onerror=alert(1)>",
        "",
        param_name="name",
    )

    assert executed is True
    assert hunter._browser_execution_evidence["dialog_observed"] is True
    assert hunter._browser_execution_evidence["test_url"].startswith("http://example.com/#/search?")


@pytest.mark.asyncio
async def test_validate_dom_runtime_xss_no_dialog_leaves_evidence_empty(monkeypatch):
    """T2b: 非発火時は dialog_observed も dom_mutation_observed も付加しない（偽陽性なし）。"""
    hunter = SmartXSSHunter()

    class _NotExecutedResult:
        executed = False

    class _NotExecutedVerifier:
        async def verify(self, url, parameter, payload, *, dialog_timeout=3.0):
            return _NotExecutedResult()

        async def close(self):
            return None

    class _QuietValidator:
        is_available = True

        def __init__(self):
            self._browser_args = []

        async def validate_xss(self, url, timeout=10.0, cookies=None):
            return False

    import src.core.detection.browser_pool as browser_pool_module
    import src.tools.browser.playwright_validator as playwright_validator_module
    import playwright.async_api as playwright_async_api

    monkeypatch.setattr(browser_pool_module, "BrowserPoolXSSVerifier", _NotExecutedVerifier)
    monkeypatch.setattr(playwright_validator_module, "PlaywrightValidator", _QuietValidator)

    def _raise_no_playwright(*args, **kwargs):
        raise RuntimeError("playwright disabled in test")

    monkeypatch.setattr(playwright_async_api, "async_playwright", _raise_no_playwright)

    executed = await hunter._validate_dom_runtime_xss(
        "http://example.com/search?q=test&name=x",
        "<img src=x onerror=alert(1)>",
        "",
        param_name="name",
    )

    assert executed is False
    assert hunter._browser_execution_evidence == {}


@pytest.mark.asyncio
async def test_dom_mutation_weak_evidence_does_not_break_param_loop_until_dialog(monkeypatch):
    """T3: 弱い証拠（DOM mutation のみ）では param ループを打ち切らず、
    dialog 発火 param で break する（_validate_dom_runtime_xss の呼び出し回数で検証）。"""
    hunter = SmartXSSHunter()

    import src.core.agents.swarm.injection.smart_xss as smart_xss_module
    monkeypatch.setattr(
        smart_xss_module,
        "_fetch_and_parse_form",
        AsyncMock(return_value=[]),
    )

    async def _no_reflection_send_request(payload):
        return {"status": 200, "diff": "normal", "body_snippet": "ok"}

    monkeypatch.setattr(hunter, "_send_request", _no_reflection_send_request)
    monkeypatch.setattr(
        hunter,
        "run_loop",
        AsyncMock(return_value={"status": "completed", "reason": "no_xss", "param": ""}),
    )
    monkeypatch.setattr(
        hunter,
        "_should_attempt_dom_browser_validation",
        lambda target, param_name: True,
    )

    calls = []

    async def _fake_validate_dom(target, payload, cookies_str, param_name="default"):
        calls.append((param_name, payload))
        if len(calls) == 4:
            # 4 回目（param "q" の最初の payload）で実 dialog 発火
            hunter._browser_execution_evidence = {
                "dialog_observed": True,
                "executor": "playwright",
                "event": "dom_runtime_execution",
                "variant": "dom",
                "parameter": param_name,
                "payload": payload,
                "test_url": "http://example.com/#/search?q=test&name=x",
            }
        else:
            hunter._browser_execution_evidence = {
                "dom_mutation_observed": True,
                "executor": "playwright",
                "event": "dom_sink_reflection",
                "variant": "dom",
                "parameter": param_name,
                "payload": payload,
                "test_url": "http://example.com/#/search?q=test&name=x",
            }
        return True

    monkeypatch.setattr(hunter, "_validate_dom_runtime_xss", _fake_validate_dom)

    result = await hunter.run_as_tool(
        "http://example.com/search?q=test&name=x",
        {"name": "1", "q": "test"},
    )

    # param "name" では mutation のみ（3 payload）→ break されない。
    # param "q" の 1 回目の payload で dialog 発火 → そこで param ループ break。
    assert len(calls) == 4
    assert calls[0][0] == "name"
    assert calls[3][0] == "q"
    assert result["vulnerable"] is True
    assert result["browser_execution"]["dialog_observed"] is True
    assert result["loop_result"]["reason"] == "dom_runtime_fragment_execution"


@pytest.mark.asyncio
async def test_dom_mutation_only_evidence_adopted_after_all_params(monkeypatch):
    """T3: 全 param で dialog が発火しなかった場合のみ、最良の DOM mutation 結果を採用
    （vulnerable=True・dialog_observed は付けない＝偽陽性なし）。"""
    hunter = SmartXSSHunter()

    import src.core.agents.swarm.injection.smart_xss as smart_xss_module
    monkeypatch.setattr(
        smart_xss_module,
        "_fetch_and_parse_form",
        AsyncMock(return_value=[]),
    )

    async def _no_reflection_send_request(payload):
        return {"status": 200, "diff": "normal", "body_snippet": "ok"}

    monkeypatch.setattr(hunter, "_send_request", _no_reflection_send_request)
    monkeypatch.setattr(
        hunter,
        "run_loop",
        AsyncMock(return_value={"status": "completed", "reason": "no_xss", "param": ""}),
    )
    monkeypatch.setattr(
        hunter,
        "_should_attempt_dom_browser_validation",
        lambda target, param_name: True,
    )

    calls = []

    async def _fake_validate_dom_mutation_only(target, payload, cookies_str, param_name="default"):
        calls.append((param_name, payload))
        hunter._browser_execution_evidence = {
            "dom_mutation_observed": True,
            "executor": "playwright",
            "event": "dom_sink_reflection",
            "variant": "dom",
            "parameter": param_name,
            "payload": payload,
            "test_url": "http://example.com/#/search?q=test&name=x",
        }
        return True

    monkeypatch.setattr(hunter, "_validate_dom_runtime_xss", _fake_validate_dom_mutation_only)

    result = await hunter.run_as_tool(
        "http://example.com/search?q=test&name=x",
        {"name": "1", "q": "test"},
    )

    # 弱い証拠では break しない → 2 param × 3 payload の全 6 回呼ばれる
    assert len(calls) == 6
    assert {p for p, _ in calls} == {"name", "q"}
    assert result["vulnerable"] is True
    assert result["reflection_observed"] is True
    assert result["browser_execution"]["dom_mutation_observed"] is True
    assert "dialog_observed" not in result["browser_execution"]
    assert result["loop_result"]["reason"] == "dom_runtime_fragment_mutation"
    assert "DOM sink-like reflection observed via fragment payload" in result["evidence"]
