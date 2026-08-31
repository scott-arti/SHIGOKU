"""
SGK-2026-0458: SmartXSSHunter stored revisit path の回帰テスト。

並行実装中の SGK-2026-0458（stored revisit 経路）の想定インターフェースに従う：
- `_attempt_stored_revisit_validation(param_name)` が保存sinkへ良性マーカー
  （sgk + 8hex）を POST し、revisit_candidates を GET スイープして反射 URL を
  特定し、実ペイロードを再 POST した上でブラウザ実行を検証する。
- `run_as_tool` の per-param ループは、method == POST かつ
  revisit_candidates が truthy かつ reflection_url が無い場合のみ、最初の
  param で当該メソッドを呼び、True なら "stored_revisit_browser_execution" で
  break する。

製品非依存・特定ルート非依存（対象 URL は http://example.com/... の stub のみ）。
"""

import re
from typing import Dict, Optional

import pytest
from unittest.mock import AsyncMock

from src.core.agents.swarm.injection.smart_xss import SmartXSSHunter

MARKER_RE = re.compile(r"sgk[0-9a-fA-F]{8}")
XSS_PAYLOAD = "<img src=x onerror=alert(1)>"

SAVE_URL = "http://example.com/api/save"
REVISIT_CANDIDATES = [
    "http://example.com/items",
    "http://example.com/list",
    "http://example.com/search",
]

STORE_PARAMS = {
    "method": "POST",
    "content_type": "json",
    "body": {"message": "hello"},
    "revisit_candidates": REVISIT_CANDIDATES,
}


def _extract_marker(body):
    """POST body（json= or data=）から良性マーカー（sgk + 8hex）を抽出する。"""
    if isinstance(body, dict):
        for value in body.values():
            if isinstance(value, str) and MARKER_RE.fullmatch(value):
                return value
    elif isinstance(body, str):
        match = MARKER_RE.search(body)
        if match:
            return match.group(0)
    return None


def _make_stored_sink_mock(marker_at: Optional[str] = "http://example.com/list"):
    """保存sinkのモック。

    - POST: マーカーを記録し、マーカー非反射の JSON 応答を返す
    - GET: marker_at の URL のみマーカーを反射する HTML を返す（他は非反射）
    marker_at=None の場合は全 GET が非反射。
    """
    calls = []
    marker_holder: Dict[str, Optional[str]] = {"value": None}

    async def fake_request(method, url, **kwargs):
        calls.append((method.upper(), url, kwargs))
        if method.upper() == "POST":
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
    """PlaywrightValidator のテスト用スタブ（ブラウザ起動を回避）。

    `_validate_stored_runtime_xss` はモジュール内で `PlaywrightValidator()`
    を生成するため、クラスごと monkeypatch する。
    """

    class _StubPlaywrightValidator:
        is_available = True

        def __init__(self):
            self._browser_args = []

        async def validate_xss(self, url, timeout=10.0, cookies=None):
            return fires

    return _StubPlaywrightValidator


def _patch_playwright_validator(monkeypatch, fires):
    import src.tools.browser.playwright_validator as playwright_validator_module

    monkeypatch.setattr(
        playwright_validator_module,
        "PlaywrightValidator",
        _make_validator_stub(fires),
    )


def _setup_hunter(monkeypatch, request_side_effect):
    """共通セットアップ。

    - `_fetch_and_parse_form` を空リスト返却で patch（HTML フォーム解析を無効化）
    - smart_client.request を side_effect モックへ差し替え
    - 非決定的な DOM ブラウザ検証・LLM ループを無効化し、
      stored revisit 経路のみを検証対象にする
    """
    import src.core.agents.swarm.injection.smart_xss as smart_xss_module

    monkeypatch.setattr(
        smart_xss_module,
        "_fetch_and_parse_form",
        AsyncMock(return_value=[]),
    )
    hunter = SmartXSSHunter()
    hunter.smart_client.request = AsyncMock(side_effect=request_side_effect)
    # T3 と同様、非決定的なブラウザ検証（DOM 経路）を発火させない
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


# ---------------------------------------------------------------------------
# T1: 保存sink発見 → 入口③（発火時・stored finding）
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stored_revisit_marker_sweep_fires_browser_execution(monkeypatch):
    """保存sink にマーカーを保存 → 在庫スイープで反射 URL を発見 →
    実ペイロード再 POST → ブラウザ実行（dialog）で stored finding になる。"""
    fake_request, calls = _make_stored_sink_mock()
    hunter = _setup_hunter(monkeypatch, fake_request)
    _patch_playwright_validator(monkeypatch, fires=True)

    result = await hunter.run_as_tool(SAVE_URL, dict(STORE_PARAMS))

    # stored finding 本体
    assert result["vulnerable"] is True
    assert result["reflection_observed"] is True
    assert result["evidence"], "stored finding には evidence が付くべき"

    # ブラウザ実行証拠（_validate_stored_runtime_xss が設定）
    browser_execution = result["browser_execution"]
    assert browser_execution["variant"] == "stored"
    assert browser_execution["event"] == "stored_revisit_browser_execution"
    assert browser_execution["dialog_observed"] is True
    assert browser_execution["test_url"] == "http://example.com/list"
    assert browser_execution["payload"] == XSS_PAYLOAD

    # ループは stored_revisit_browser_execution で break
    assert result["loop_result"]["reason"] == "stored_revisit_browser_execution"

    # reflection_url が context に記録されている
    assert hunter.context["reflection_url"] == "http://example.com/list"

    # POST はマーカー用 + 実ペイロード用の計2回
    post_calls = [c for c in calls if c[0] == "POST"]
    assert len(post_calls) == 2

    # GET スイープは items（非反射）→ list（反射）で停止
    get_calls = [c for c in calls if c[0] == "GET"]
    assert [c[1] for c in get_calls] == [
        "http://example.com/items",
        "http://example.com/list",
    ]

    # 実ペイロードが同じ欄へ再 POST されている
    second_post_body = post_calls[1][2].get("json")
    if second_post_body is None:
        second_post_body = post_calls[1][2].get("data")
    assert XSS_PAYLOAD in str(second_post_body)


# ---------------------------------------------------------------------------
# T2: 非発火（マーカー反射のみ）では stored 証拠を付けない（偽陽性回帰）
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stored_revisit_no_browser_fire_leaves_no_evidence(monkeypatch):
    """マーカーは保存・反射されるが、実ペイロードがブラウザで発火しない場合、
    stored 証拠（browser_execution）を付けず fail-closed する。"""
    fake_request, _ = _make_stored_sink_mock()
    hunter = _setup_hunter(monkeypatch, fake_request)
    _patch_playwright_validator(monkeypatch, fires=False)

    result = await hunter.run_as_tool(SAVE_URL, dict(STORE_PARAMS))

    assert result["vulnerable"] is False
    assert result["browser_execution"] == {}
    assert result["evidence"] == ""


# ---------------------------------------------------------------------------
# T2b: 在庫スイープで反射なし → False
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stored_revisit_no_reflection_in_sweep_returns_false(monkeypatch):
    """GET スイープでマーカーが一切反射しない場合、実ペイロードの再 POST や
    ブラウザ検証は行われず fail-closed する。"""
    fake_request, calls = _make_stored_sink_mock(marker_at=None)
    hunter = _setup_hunter(monkeypatch, fake_request)
    _patch_playwright_validator(monkeypatch, fires=True)

    result = await hunter.run_as_tool(SAVE_URL, dict(STORE_PARAMS))

    assert result["vulnerable"] is False
    assert result["browser_execution"] == {}
    assert result["evidence"] == ""

    # マーカー POST の1回のみ（実ペイロード再 POST なし）
    post_calls = [c for c in calls if c[0] == "POST"]
    assert len(post_calls) == 1

    # スイープは候補3件すべて走査（反射なし）
    get_calls = [c for c in calls if c[0] == "GET"]
    assert [c[1] for c in get_calls] == REVISIT_CANDIDATES


# ---------------------------------------------------------------------------
# T2c: GET-only 強制（ReadonlyEnforcedError）で fail-closed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stored_revisit_readonly_enforced_fails_closed(monkeypatch):
    """POST が ReadonlyEnforcedError でブロックされる環境（GET-only）では、
    マーカー保存も実ペイロード再 POST も行われず、証拠を捏造しない。"""
    from src.core.infra.network_client import ReadonlyEnforcedError

    async def fake_readonly_request(method, url, **kwargs):
        if method.upper() == "POST":
            raise ReadonlyEnforcedError("blocked")
        return {"status": 200, "body": "<html>no marker</html>"}

    hunter = _setup_hunter(monkeypatch, fake_readonly_request)
    _patch_playwright_validator(monkeypatch, fires=True)

    result = await hunter.run_as_tool(SAVE_URL, dict(STORE_PARAMS))

    assert result["vulnerable"] is False
    assert result["browser_execution"] == {}
    assert result["evidence"] == ""


# ---------------------------------------------------------------------------
# T3（ゲート回帰）: revisit_candidates が無ければ stored 経路は呼ばれない
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stored_revisit_not_attempted_without_candidates(monkeypatch):
    """revisit_candidates が無い場合は _attempt_stored_revisit_validation が
    呼ばれない（ゲート回帰）。run_loop と DOM ブラウザ検証はモックで
    完走させる。"""
    fake_request, _ = _make_stored_sink_mock()
    hunter = _setup_hunter(monkeypatch, fake_request)
    _patch_playwright_validator(monkeypatch, fires=True)

    hunter._attempt_stored_revisit_validation = AsyncMock(return_value=False)

    params = {
        "method": "POST",
        "content_type": "json",
        "body": {"message": "hello"},
    }
    result = await hunter.run_as_tool(SAVE_URL, params)

    assert hunter._attempt_stored_revisit_validation.await_count == 0
    assert result["vulnerable"] is False


# ---------------------------------------------------------------------------
# T4（SGK-2026-0463）: marker POST は allow_redirects=False で送られる
# ---------------------------------------------------------------------------

def _make_redirect_sink_mock(marker_at: Optional[str] = "http://example.com/list"):
    """3xx 保存sink のモック（SGK-2026-0463）。

    - POST: マーカーを記録し、**303**（marker 非反射）を返す（練習台5008 の
      `redirect("/", code=303)` 設計の模倣。追従した場合 GET / が保存済み
      marker を描画する想定）
    - GET: marker_at の URL のみマーカーを反射する HTML を返す（他は非反射）
    """
    calls = []
    marker_holder: Dict[str, Optional[str]] = {"value": None}

    async def fake_request(method, url, **kwargs):
        calls.append((method.upper(), url, kwargs))
        if method.upper() == "POST":
            body = kwargs.get("json")
            if body is None:
                body = kwargs.get("data")
            marker = _extract_marker(body)
            if marker is not None:
                marker_holder["value"] = marker
            return {"status": 303, "body": ""}
        marker = marker_holder.get("value") or ""
        if marker_at and url == marker_at and marker:
            return {"status": 200, "body": f"<html><div class='entry'>{marker}</div></html>"}
        return {"status": 200, "body": "<html>no marker</html>"}

    return fake_request, calls


@pytest.mark.asyncio
async def test_stored_revisit_marker_post_uses_allow_redirects_false(monkeypatch):
    """marker POST は allow_redirects=False で送信される（SGK-2026-0463）。

    3xx 追従（aiohttp 既定 True）だと実効本文 = リダイレクト先ページが保存済み
    marker を描画し、marker 早期リターンが誤発火するため。fire POST（実
    payload 再保存）は従来どおり追従可のまま（allow_redirects 指定なし）。"""
    fake_request, calls = _make_stored_sink_mock()
    hunter = _setup_hunter(monkeypatch, fake_request)
    _patch_playwright_validator(monkeypatch, fires=True)

    result = await hunter.run_as_tool(SAVE_URL, dict(STORE_PARAMS))
    assert result["vulnerable"] is True

    post_calls = [c for c in calls if c[0] == "POST"]
    assert len(post_calls) == 2
    # marker POST（1回目）のみ allow_redirects=False
    assert post_calls[0][2].get("allow_redirects") is False
    # fire POST（2回目）は現状維持（allow_redirects 指定なし）
    assert "allow_redirects" not in post_calls[1][2]


# ---------------------------------------------------------------------------
# T5（SGK-2026-0463）: 3xx 保存sink では marker 早期リターンせずスイープへ
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stored_revisit_303_sink_proceeds_to_sweep(monkeypatch):
    """POST が 303（marker 非反射）を返す保存sink では、marker 早期リターン
    せず revisit スイープへ進み、反射 URL 発見 → 実 payload 保存 → dialog
    観測で stored finding になる（練習台5008 シナリオの単体再現）。"""
    fake_request, calls = _make_redirect_sink_mock()
    hunter = _setup_hunter(monkeypatch, fake_request)
    _patch_playwright_validator(monkeypatch, fires=True)

    result = await hunter.run_as_tool(SAVE_URL, dict(STORE_PARAMS))

    assert result["vulnerable"] is True
    assert result["reflection_observed"] is True

    browser_execution = result["browser_execution"]
    assert browser_execution["variant"] == "stored"
    assert browser_execution["event"] == "stored_revisit_browser_execution"
    assert browser_execution["dialog_observed"] is True
    assert browser_execution["test_url"] == "http://example.com/list"

    assert hunter.context["reflection_url"] == "http://example.com/list"

    # marker POST は allow_redirects=False で送られている
    post_calls = [c for c in calls if c[0] == "POST"]
    assert len(post_calls) == 2
    assert post_calls[0][2].get("allow_redirects") is False

    # スイープへ進んでいる（GET 呼び出しあり・反射 URL で停止）
    get_calls = [c for c in calls if c[0] == "GET"]
    assert [c[1] for c in get_calls] == [
        "http://example.com/items",
        "http://example.com/list",
    ]


# ---------------------------------------------------------------------------
# T6（SGK-2026-0463）: 200 で marker を反射する sink は従来どおり早期リターン
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stored_revisit_200_reflecting_sink_early_returns(monkeypatch):
    """POST 応答 200 自体に marker が反射する sink では従来どおり marker
    早期リターン（False）し、スイープ・実 payload 保存を行わない（退行なし・
    fail-closed）。"""
    calls = []

    async def fake_request(method, url, **kwargs):
        calls.append((method.upper(), url, kwargs))
        if method.upper() == "POST":
            body = kwargs.get("json")
            if body is None:
                body = kwargs.get("data")
            marker = _extract_marker(body)
            if marker is not None:
                return {"status": 200, "body": f"<html><div>{marker}</div></html>"}
        return {"status": 200, "body": "<html>no marker</html>"}

    hunter = _setup_hunter(monkeypatch, fake_request)
    _patch_playwright_validator(monkeypatch, fires=True)

    result = await hunter.run_as_tool(SAVE_URL, dict(STORE_PARAMS))

    # 早期リターン → stored 経路は走らず、委譲（run_loop モック経由）で fail-closed
    assert result["vulnerable"] is False
    assert result["browser_execution"] == {}
    assert result["evidence"] == ""

    post_calls = [c for c in calls if c[0] == "POST"]
    assert len(post_calls) == 1  # marker POST のみ（実 payload 再保存なし）
    get_calls = [c for c in calls if c[0] == "GET"]
    assert len(get_calls) == 0  # スイープなし
    assert hunter.context.get("reflection_url") is None
