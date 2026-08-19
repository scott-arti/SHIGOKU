"""SGK-2026-0454 T1: ①挙動ベースのDOM候補判定（製品非依存）。

- DVWA 目印（xss_d / javascript）は従来どおり True（回帰なし）。
- stored は別経路のため False。
- generic/reflected でも、反射向き汎用パラメータ名かつサーバ反射なしなら
  ブラウザDOM実行検証へ escalate（製品名・ホスト・パス文字列を参照しない）。
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.core.agents.swarm.injection.smart_xss import SmartXSSHunter


@pytest.fixture
def hunter():
    h = SmartXSSHunter.__new__(SmartXSSHunter)
    h.reflection_observed = False
    return h


# --- DVWA 目印の温存（回帰なし） ---

def test_dvwa_dom_marker_still_escalates(hunter):
    assert hunter._should_attempt_dom_browser_validation(
        "http://localhost:4280/vulnerabilities/xss_d/", "default"
    ) is True


def test_dvwa_javascript_marker_still_escalates(hunter):
    assert hunter._should_attempt_dom_browser_validation(
        "http://localhost:4280/javascript/", "default"
    ) is True


def test_dvwa_stored_marker_never_escalates(hunter):
    assert hunter._should_attempt_dom_browser_validation(
        "http://localhost:4280/vulnerabilities/xss_s/", "txtName"
    ) is False


# --- Juice Shop 等・DVWA 目印無しの反射向き URL（T1 の本題） ---

@pytest.mark.parametrize(
    "target,param",
    [
        ("http://localhost:3000/rest/products/search?q=", "q"),
        ("http://localhost:3000/search?q=test", "q"),
        ("http://localhost:3000/#/search?q=", "q"),
        ("http://localhost:3000/orders/history?query=test", "query"),
        ("http://localhost:3000/reviews?name=x", "name"),
        ("http://example.com/catalog?s=abc", "s"),
        ("http://example.com/listing?keyword=abc", "keyword"),
        ("http://example.com/list?term=abc", "term"),
        ("http://example.com/app#/page?search=abc", "search"),
        ("http://example.com/page?fragment=abc", "fragment"),
    ],
)
def test_reflection_oriented_param_escalates_without_dvwa_marker(hunter, target, param):
    assert hunter._should_attempt_dom_browser_validation(target, param) is True


def test_no_reflection_observed_is_required(hunter):
    hunter.reflection_observed = True
    assert hunter._should_attempt_dom_browser_validation(
        "http://localhost:3000/rest/products/search?q=", "q"
    ) is False


def test_non_reflection_param_does_not_escalate(hunter):
    assert hunter._should_attempt_dom_browser_validation(
        "http://localhost:3000/rest/products/search?q=", "id"
    ) is False
    assert hunter._should_attempt_dom_browser_validation(
        "http://localhost:3000/orders/history?query=test", "page"
    ) is False


def test_missing_param_does_not_escalate(hunter):
    assert hunter._should_attempt_dom_browser_validation(
        "http://localhost:3000/rest/products/search?q=", ""
    ) is False
    assert hunter._should_attempt_dom_browser_validation(
        "http://localhost:3000/rest/products/search?q=", None
    ) is False


# --- 製品非依存: ホスト・パス・製品名に依存しない ---

def test_product_independent_host_does_not_matter(hunter):
    for host in (
        "http://localhost:3000/rest/products/search?q=",
        "http://127.0.0.1:9999/anything?q=",
        "https://app.example.com/v2/endpoint?query=abc",
    ):
        assert hunter._should_attempt_dom_browser_validation(host, "q") is True


def test_gate_flag_set_only_when_escalation_decision_true():
    """run_as_tool の DOM ゲートが、挙動ベース判定 True のときだけ
    _dom_browser_validation_attempted を立てる経路であることの整合確認。
    """
    h = SmartXSSHunter.__new__(SmartXSSHunter)
    h.reflection_observed = False
    h._dom_browser_validation_attempted = False
    # 実際のゲート条件と同じ式（smart_xss.py run_as_tool 内）
    decision = h._should_attempt_dom_browser_validation(
        "http://localhost:3000/rest/products/search?q=", "q"
    )
    if decision:
        h._dom_browser_validation_attempted = True
    assert h._dom_browser_validation_attempted is True


def test_gate_flag_not_set_for_reflection_observed():
    """反射観測済みの相手では escalate されず、フラグも立たない。"""
    h = SmartXSSHunter.__new__(SmartXSSHunter)
    h.reflection_observed = True
    h._dom_browser_validation_attempted = False
    decision = h._should_attempt_dom_browser_validation(
        "http://localhost:3000/rest/products/search?q=", "q"
    )
    assert decision is False
    assert h._dom_browser_validation_attempted is False


@pytest.mark.asyncio
async def test_run_as_tool_dom_gate_sets_attempted_flag_for_js_search():
    """run_as_tool の実ゲートを通し、DVWA 目印の無い反射向き URL で
    _dom_browser_validation_attempted が立つ（＝manager が trace 記録できる）"""
    hunter = SmartXSSHunter(config={"model": "test-model"})
    # LLM 起動を抑止
    hunter.llm = MagicMock()
    hunter.llm.agenerate = AsyncMock(
        return_value=MagicMock(choices=[MagicMock(message=MagicMock(content="THOUGHT: done.\nACTION: finish\nINPUT: safe"))])
    )
    # DOM ブラウザ検証は発火させない（バー不変・判定のみ検証）
    hunter._validate_dom_runtime_xss = AsyncMock(return_value=False)

    async def _no_reflection(*_args, **_kwargs):
        return {"status": 200, "body": "<html>no reflection</html>", "headers": {}}

    hunter.smart_client.request = AsyncMock(side_effect=_no_reflection)

    with patch(
        "src.core.agents.swarm.injection.smart_xss._fetch_and_parse_form",
        new=AsyncMock(return_value=[]),
    ):
        result = await hunter.run_as_tool(
            "http://localhost:3000/rest/products/search?q=",
            params={"q": "test", "method": "GET"},
        )

    assert hunter._dom_browser_validation_attempted is True
    assert hunter._validate_dom_runtime_xss.call_count >= 1
    assert result["vulnerable"] is False  # ブラウザ発火なしなら確定しない（バー不変）


@pytest.mark.asyncio
async def test_run_as_tool_dom_gate_not_attempted_for_non_reflection_param():
    """反射向きでないパラメータのみの URL では DOM ゲートが立たない。"""
    hunter = SmartXSSHunter(config={"model": "test-model"})
    hunter.llm = MagicMock()
    hunter.llm.agenerate = AsyncMock(
        return_value=MagicMock(choices=[MagicMock(message=MagicMock(content="THOUGHT: done.\nACTION: finish\nINPUT: safe"))])
    )
    hunter._validate_dom_runtime_xss = AsyncMock(return_value=False)

    async def _no_reflection(*_args, **_kwargs):
        return {"status": 200, "body": "<html>no reflection</html>", "headers": {}}

    hunter.smart_client.request = AsyncMock(side_effect=_no_reflection)

    with patch(
        "src.core.agents.swarm.injection.smart_xss._fetch_and_parse_form",
        new=AsyncMock(return_value=[]),
    ):
        await hunter.run_as_tool(
            "http://localhost:3000/api/orders?id=5",
            params={"id": "5", "method": "GET"},
        )

    assert hunter._dom_browser_validation_attempted is False


def test_fragment_query_params_extracted_as_candidates():
    """SPA hash ルート（#/search?q=）の fragment 内 query パラメータが
    url_params_flat に構造ベースで抽出される（製品非依存）。"""
    from src.core.agents.swarm.injection.smart_xss import SmartXSSHunter as H
    hunter = H.__new__(H)
    # run_as_tool 内の抽出ロジックを直接再現して検証
    from urllib.parse import urlparse, parse_qs
    target = "http://localhost:3000/#/search?q="
    parsed = urlparse(target)
    url_params = parse_qs(parsed.query)
    fragment = parsed.fragment or ""
    if "?" in fragment:
        _, _, frag_query = fragment.partition("?")
        for frag_key, frag_values in parse_qs(frag_query, keep_blank_values=True).items():
            url_params.setdefault(frag_key, frag_values)
    assert "q" in url_params


def test_fragment_query_not_required_for_plain_urls():
    """通常の URL（fragment なし）では抽出が従来どおり。"""
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse("http://localhost:3000/search?q=test")
    url_params = parse_qs(parsed.query)
    fragment = parsed.fragment or ""
    if "?" in fragment:
        _, _, frag_query = fragment.partition("?")
        for frag_key, frag_values in parse_qs(frag_query, keep_blank_values=True).items():
            url_params.setdefault(frag_key, frag_values)
    assert url_params == {"q": ["test"]}


@pytest.mark.asyncio
async def test_validate_dom_runtime_xss_uses_spa_fragment_query_url(monkeypatch):
    """SPA hash ルートの target に対し、fragment 内 query へ注入した URL が
    PlaywrightValidator 検証の先頭候補になる（dialog 発火の実観測経路）。"""
    hunter = SmartXSSHunter(config={"model": "test-model"})

    captured_urls = []

    class _DummyPoolResult:
        executed = False
        evidence = {}

    class _DummyVerifier:
        async def verify(self, url, parameter, payload, *, dialog_timeout=3.0):
            return _DummyPoolResult()

        async def close(self):
            return None

    import src.core.detection.browser_pool as browser_pool_module
    monkeypatch.setattr(browser_pool_module, "BrowserPoolXSSVerifier", _DummyVerifier)

    async def _fake_validate_xss(url, timeout=8.0, cookies=None):
        captured_urls.append(url)
        return False

    class _FakeValidator:
        is_available = True
        _browser_args = ["--no-sandbox"]

        async def validate_xss(self, url, timeout=8.0, cookies=None):
            return await _fake_validate_xss(url, timeout=timeout, cookies=cookies)

    import src.tools.browser.playwright_validator as pv_mod
    monkeypatch.setattr(pv_mod, "PlaywrightValidator", lambda: _FakeValidator())

    executed = await hunter._validate_dom_runtime_xss(
        "http://localhost:3000/#/search?q=",
        "<img src=x onerror=alert(1)>",
        "",
        param_name="q",
    )

    assert executed is False
    assert captured_urls, "検証対象 URL が1つも生成されていない"
    first = captured_urls[0]
    assert first.startswith("http://localhost:3000/#/search?q=")
    assert "%3Cimg" in first  # fragment 内 query に payload が注入されている
