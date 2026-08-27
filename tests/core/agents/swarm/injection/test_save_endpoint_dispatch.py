"""
SGK-2026-0459 T2 (C1b / C2 / D2): dispatch 結線 + 偽陽性回帰。

- 捕捉した保存 sink（save_endpoints）が挙動ベースで 0458 起動ゲートへ
  適合する形で渡る（method / candidate_params / revisit_candidates 供給）。
- 発火時のみ variant="stored" / dialog_observed=true を生成（fail-closed）。
- 複数マーカー混在時に他マーカーの反射を自マーカーと誤紐付けしない
  （同一文字列一致のみで紐付け）回帰。

対象:
- src/core/agents/swarm/injection/manager.py
  _match_save_endpoint / _collect_discovery_revisit_urls /
  _same_origin_revisit_candidates（discovery 在庫の合流）
- src/core/agents/swarm/injection/smart_xss.py
  起動ゲートの verb 拡張（POST/PUT/PATCH）+ stored 発火
- src/tools/custom/playwright_recon.py _derive_save_endpoints（マーカー照合）

製品非依存: 対象 URL は stub のみ。判断は urlparse 構造比較と文字列一致のみ。
"""

import re
from unittest.mock import AsyncMock

import pytest

from src.core.agents.swarm.injection.manager import (
    InjectionManagerAgent,
    _collect_discovery_revisit_urls,
    _match_save_endpoint,
)
from src.core.agents.swarm.injection.smart_xss import SmartXSSHunter
from src.tools.custom.playwright_recon import PlaywrightCrawler

MARKER_RE = re.compile(r"sgk[0-9a-fA-F]{8}")
XSS_PAYLOAD = "<img src=x onerror=alert(1)>"

SAVE_URL = "http://example.com/api/save"
SAVE_URL_WITH_QUERY = "http://example.com/api/save?locale=en&format=json"
REVISIT_CANDIDATES = [
    "http://example.com/items",
    "http://example.com/list",
]

STORE_PARAMS = {
    "method": "PUT",
    "content_type": "json",
    "body": {"message": "hello"},
    "candidate_params": ["message"],
    "revisit_candidates": REVISIT_CANDIDATES,
}


# ---------------------------------------------------------------------------
# 1) モジュールヘルパー: 構造的 URL 照合 + discovery 再訪候補の収集
# ---------------------------------------------------------------------------


def test_match_save_endpoint_structural_equality():
    """query/fragment 差異を許容する構造的照合（scheme+netloc+path）。"""
    eps = [
        {"url": "http://example.com/api/save", "method": "PUT",
         "fields": ["message"], "marker": "sgk12345678"},
    ]
    assert _match_save_endpoint(SAVE_URL, eps) == eps[0]
    # query が付いていても一致（保存 API の書き込み URL はクエリ差異許容）
    assert _match_save_endpoint(SAVE_URL_WITH_QUERY, eps) == eps[0]
    # path が異なれば不一致
    assert _match_save_endpoint("http://example.com/api/other", eps) is None
    # 別ホストは不一致
    assert _match_save_endpoint("http://evil.example.com/api/save", eps) is None
    # 空入力は None
    assert _match_save_endpoint("", eps) is None
    assert _match_save_endpoint(SAVE_URL, []) is None


def test_collect_discovery_revisit_urls_bounded_dedup():
    """url / revisit_urls / source_page を http/https のみ・重複排除・上限で収集。"""
    eps = [
        {
            "url": "http://example.com/api/save",
            "revisit_urls": ["http://example.com/items", "http://example.com/items"],
            "source_page": "http://example.com/",
        },
        {
            "url": "http://example.com/api/comments",
            "revisit_urls": ["http://example.com/topics"],
            "source_page": "http://example.com/",
        },
        {"url": "ftp://example.com/x", "source_page": ""},
        "not-a-dict",
        None,
    ]
    urls = _collect_discovery_revisit_urls(eps, limit=10)
    assert urls[0] == "http://example.com/api/save"
    assert urls.count("http://example.com/items") == 1  # dedup
    assert "http://example.com/topics" in urls
    assert all(u.startswith("http") for u in urls)
    assert len(urls) == 5

    # limit で打ち切られる
    many = [
        {"url": f"http://example.com/api/{i}", "revisit_urls": [], "source_page": ""}
        for i in range(20)
    ]
    assert len(_collect_discovery_revisit_urls(many, limit=3)) == 3


def test_same_origin_revisit_candidates_merges_discovery_inventory():
    """_same_origin_revisit_candidates が discovery 在庫（save_endpoints 由来の
    再訪候補）を同一オリジン構造比較で合流させる。供給元は不変で url_results
    自己履歴と併用。"""
    mgr = InjectionManagerAgent.__new__(InjectionManagerAgent)
    mgr.current_context = {
        "url_results": [
            {"url": "http://example.com/self-scan", "vuln_type": "xss"},
        ],
        "discovery_revisit_urls": [
            "http://example.com/api/save",
            "http://example.com/items",
            "http://other.example.com/foreign",  # 別オリジンは除外
        ],
    }
    candidates = mgr._same_origin_revisit_candidates(SAVE_URL)
    assert "http://example.com/api/save" in candidates
    assert "http://example.com/items" in candidates
    assert "http://example.com/self-scan" in candidates
    assert "http://other.example.com/foreign" not in candidates


# ---------------------------------------------------------------------------
# 2) smart_xss 起動ゲート: verb 拡張（POST/PUT/PATCH）と GET 不発
# ---------------------------------------------------------------------------


def _extract_marker(body):
    if isinstance(body, dict):
        for value in body.values():
            if isinstance(value, str) and MARKER_RE.fullmatch(value):
                return value
    elif isinstance(body, str):
        match = MARKER_RE.search(body)
        if match:
            return match.group(0)
    return None


def _make_stored_sink_mock(marker_at="http://example.com/list"):
    calls = []
    marker_holder: dict = {"value": None}

    async def fake_request(method, url, **kwargs):
        calls.append((method.upper(), url, kwargs))
        if method.upper() in ("POST", "PUT", "PATCH"):
            body = kwargs.get("json")
            if body is None:
                body = kwargs.get("data")
            marker = _extract_marker(body)
            if marker is not None:
                marker_holder["value"] = marker
            return {"status": 200, "body": '{"status":"ok"}'}
        marker = marker_holder.get("value") or ""
        if marker_at and url == marker_at and marker:
            return {"status": 200, "body": f"<html><div class='entry'>{marker}</div></html>"}
        return {"status": 200, "body": "<html>no marker</html>"}

    return fake_request, calls


def _make_validator_stub(fires):
    class _StubPlaywrightValidator:
        is_available = True

        def __init__(self):
            self._browser_args = []

        async def validate_xss(self, url, timeout=10.0, cookies=None):
            return fires

    return _StubPlaywrightValidator


def _setup_hunter(monkeypatch, request_side_effect):
    import src.core.agents.swarm.injection.smart_xss as smart_xss_module

    monkeypatch.setattr(
        smart_xss_module,
        "_fetch_and_parse_form",
        AsyncMock(return_value=[]),
    )
    hunter = SmartXSSHunter()
    hunter.smart_client.request = AsyncMock(side_effect=request_side_effect)
    monkeypatch.setattr(
        hunter,
        "_should_attempt_dom_browser_validation",
        lambda target, param_name: False,
    )
    monkeypatch.setattr(
        hunter,
        "run_loop",
        AsyncMock(return_value={"status": "completed", "reason": "no_xss", "param": ""}),
    )
    return hunter


def _patch_playwright_validator(monkeypatch, fires):
    import src.tools.browser.playwright_validator as playwright_validator_module

    monkeypatch.setattr(
        playwright_validator_module,
        "PlaywrightValidator",
        _make_validator_stub(fires),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("verb", ["PUT", "PATCH"])
async def test_non_get_verb_fires_stored_gate(monkeypatch, verb):
    """起動ゲートの verb 拡張: PUT / PATCH でも stored 再訪検証が発火し、
    ブラウザ発火時のみ variant="stored" / dialog_observed=true を生成。"""
    fake_request, calls = _make_stored_sink_mock()
    hunter = _setup_hunter(monkeypatch, fake_request)
    _patch_playwright_validator(monkeypatch, fires=True)

    params = dict(STORE_PARAMS)
    params["method"] = verb
    result = await hunter.run_as_tool(SAVE_URL, params)

    assert result["vulnerable"] is True
    browser_execution = result["browser_execution"]
    assert browser_execution["variant"] == "stored"
    assert browser_execution["event"] == "stored_revisit_browser_execution"
    assert browser_execution["dialog_observed"] is True
    assert result["loop_result"]["reason"] == "stored_revisit_browser_execution"
    # 検証本体はマーカー方式（verb 非依存）で、内部は POST で往復する（不変）。
    # 起動ゲート拡張で非GET verb でも stored 経路へ「入った」ことを観測する。
    marker_posts = [c for c in calls if c[0] == "POST"]
    assert len(marker_posts) == 2, f"{verb} ゲート経由で stored 往復（POST 2回）が走るべき"


@pytest.mark.asyncio
@pytest.mark.parametrize("verb", ["POST", "PUT", "PATCH"])
async def test_stored_gate_no_fire_leaves_no_evidence(monkeypatch, verb):
    """マーカーは反射するがブラウザ非発火なら stored 証拠を付けない
    （variant/dialog_observed を捏造しない fail-closed）。"""
    fake_request, _ = _make_stored_sink_mock()
    hunter = _setup_hunter(monkeypatch, fake_request)
    _patch_playwright_validator(monkeypatch, fires=False)

    params = dict(STORE_PARAMS)
    params["method"] = verb
    result = await hunter.run_as_tool(SAVE_URL, params)

    assert result["vulnerable"] is False
    assert result["browser_execution"] == {}
    assert result["evidence"] == ""


@pytest.mark.asyncio
async def test_get_verb_does_not_fire_stored_gate(monkeypatch):
    """GET（既定挙動）は stored ゲートに入らない（verb 拡張は非GETのみ・回帰）。"""
    fake_request, _ = _make_stored_sink_mock()
    hunter = _setup_hunter(monkeypatch, fake_request)
    _patch_playwright_validator(monkeypatch, fires=True)

    hunter._attempt_stored_revisit_validation = AsyncMock(return_value=False)

    params = dict(STORE_PARAMS)
    params["method"] = "GET"
    result = await hunter.run_as_tool(SAVE_URL, params)

    assert hunter._attempt_stored_revisit_validation.await_count == 0
    assert result["vulnerable"] is False


@pytest.mark.asyncio
async def test_stored_gate_requires_revisit_candidates(monkeypatch):
    """revisit_candidates 無しでは PUT でも stored ゲートに入らない（回帰）。"""
    fake_request, _ = _make_stored_sink_mock()
    hunter = _setup_hunter(monkeypatch, fake_request)
    _patch_playwright_validator(monkeypatch, fires=True)

    hunter._attempt_stored_revisit_validation = AsyncMock(return_value=False)

    params = dict(STORE_PARAMS)
    params.pop("revisit_candidates")
    result = await hunter.run_as_tool(SAVE_URL, params)

    assert hunter._attempt_stored_revisit_validation.await_count == 0
    assert result["vulnerable"] is False


# ---------------------------------------------------------------------------
# 3) 複数マーカー混在: 他マーカーの反射を自マーカーと誤紐付けしない
# ---------------------------------------------------------------------------


def test_derive_save_endpoints_no_cross_marker_mislink():
    """書き込み本文に含まれるマーカーが「自マーカーの文字列一致」でのみ紐付き、
    他マーカー（同一由来でなくても）を自マーカーへ誤紐付けしない。"""
    crawler = PlaywrightCrawler()
    marker_a = "sgkaaaaaaaa"
    marker_b = "sgkbbbbbbbb"
    results = {
        "urls": {"http://example.com/items", "http://example.com/list"},
        "marker_records": [
            {"marker": marker_a, "fields": ["message"], "source_page": "http://example.com/"},
            {"marker": marker_b, "fields": ["comment"], "source_page": "http://example.com/"},
        ],
        "write_requests": [
            # A 由来の書き込み: 本文に marker_a のみ
            {"url": "http://example.com/api/save", "method": "POST",
             "post_data": f"message={marker_a}&author=t",
             "content_type": "application/x-www-form-urlencoded"},
            # B 由来の書き込み: 本文に marker_b のみ
            {"url": "http://example.com/api/comments", "method": "POST",
             "post_data": f"comment={marker_b}",
             "content_type": "application/x-www-form-urlencoded"},
        ],
    }
    eps = crawler._derive_save_endpoints(results, "http://example.com/", max_writes=5)
    by_url = {ep["url"]: ep for ep in eps}
    assert by_url["http://example.com/api/save"]["marker"] == marker_a
    assert by_url["http://example.com/api/comments"]["marker"] == marker_b
    # 混在: 同一書き込みに両マーカーが入っても dedupe は (url, method) 単位で自マーカーを保持
    results2 = {
        "urls": set(),
        "marker_records": [
            {"marker": marker_a, "fields": ["message"], "source_page": "http://example.com/"},
            {"marker": marker_b, "fields": ["comment"], "source_page": "http://example.com/"},
        ],
        "write_requests": [
            {"url": "http://example.com/api/save", "method": "POST",
             "post_data": f"message={marker_a}&comment={marker_b}",
             "content_type": "application/x-www-form-urlencoded"},
        ],
    }
    eps2 = crawler._derive_save_endpoints(results2, "http://example.com/", max_writes=5)
    assert len(eps2) == 1
    assert eps2[0]["marker"] == marker_a
