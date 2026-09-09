"""
SGK-2026-0479: SmartXSSHunter の nonce 往復（round-trip）実行証拠の単体テスト。

反射/DOM 型 XSS の実ブラウザ発火が「自己申告に見える要約」でなく、攻撃者側が選んだ
乱数（nonce）がブラウザの dialog message にそのまま返ることを生の実行証拠として
記録できることを検証する。製品非依存 fixture のみ（target.example / 汎用 XSS
ペイロード）。ブラウザ実物は起動しない（CI 非依存・単体で完結）。
"""
import re

import pytest
from unittest.mock import AsyncMock, MagicMock

from types import SimpleNamespace

from src.core.agents.swarm.injection.smart_xss import SmartXSSHunter

NONCE_RE = re.compile(r"^sgk[0-9a-f]{12}$")


def _nonce_payload(nonce: str) -> str:
    return f"<img src=x onerror=alert('{nonce}')>"


# ---------------------------------------------------------------------------
# (d) nonce 生成ヘルパー: 毎回異なる英数字のみの値（製品非依存接頭辞 sgk）
# ---------------------------------------------------------------------------

def test_generate_xss_nonce_unique_and_alphanumeric():
    hunter = SmartXSSHunter()
    first = hunter._generate_xss_nonce()
    second = hunter._generate_xss_nonce()
    assert NONCE_RE.fullmatch(first)
    assert NONCE_RE.fullmatch(second)
    assert first.isalnum()
    assert first != second
    # __init__ 時点の初期値は空（param ループ開始時に生成される）
    assert hunter._current_xss_nonce == ""


# ---------------------------------------------------------------------------
# (a)(b) browser_pool 経路 _record_browser_verification_result の往復記録
# ---------------------------------------------------------------------------

def _make_pool_result(dialog_message, parameter="q", url="http://target.example/page"):
    return SimpleNamespace(
        url=url,
        parameter=parameter,
        payload=_nonce_payload(dialog_message) if dialog_message else "<img src=x onerror=alert('x')>",
        executed=True,
        evidence={
            "dialog_message": dialog_message,
            "test_url": "http://target.example/page?q=%3Cimg%20src%3Dx%3E",
        },
    )


def test_record_browser_verification_result_nonce_match():
    hunter = SmartXSSHunter()
    nonce = hunter._generate_xss_nonce()
    hunter._current_xss_nonce = nonce

    recorded = hunter._record_browser_verification_result(
        _make_pool_result(dialog_message=nonce),
        variant="dom",
        event="dom_runtime_execution",
    )

    assert recorded is True
    evidence = hunter._browser_execution_evidence
    assert evidence["dialog_observed"] is True
    assert evidence["executor"] == "browser_pool"
    assert evidence["nonce"] == nonce
    assert evidence["observed_dialog_message"] == nonce
    assert evidence["nonce_match"] is True


def test_record_browser_verification_result_nonce_mismatch_is_false():
    """dialog message が注入 nonce と一致しないとき nonce_match=False（捏造しない）。"""
    hunter = SmartXSSHunter()
    nonce = hunter._generate_xss_nonce()
    hunter._current_xss_nonce = nonce

    recorded = hunter._record_browser_verification_result(
        _make_pool_result(dialog_message="unrelated-message"),
        variant="reflected",
        event="reflected_browser_execution",
    )

    assert recorded is True
    evidence = hunter._browser_execution_evidence
    assert evidence["nonce"] == nonce
    assert evidence["observed_dialog_message"] == "unrelated-message"
    assert evidence["nonce_match"] is False


def test_record_browser_verification_result_empty_nonce_is_false():
    """nonce 未設定（空）でも nonce_match を捏造しない（fail-closed）。"""
    hunter = SmartXSSHunter()
    assert hunter._current_xss_nonce == ""

    recorded = hunter._record_browser_verification_result(
        _make_pool_result(dialog_message=None),
        variant="dom",
        event="dom_runtime_execution",
    )

    assert recorded is True
    evidence = hunter._browser_execution_evidence
    assert evidence["nonce"] == ""
    assert evidence["nonce_match"] is False


# ---------------------------------------------------------------------------
# (c) _build_browser_execution_poc_response の往復行
# ---------------------------------------------------------------------------

def test_build_browser_execution_poc_response_includes_roundtrip_lines():
    hunter = SmartXSSHunter()
    nonce = "sgk" + "ab" * 6  # 12 hex
    out = hunter._build_browser_execution_poc_response(
        test_url="http://target.example/#/search?q=test",
        observation_logs=[
            {"type": "dialog", "dialog_type": "alert", "message": nonce},
        ],
        nonce=nonce,
        observed_message=nonce,
        nonce_match=True,
    )
    assert "[Browser runtime observation]" in out
    assert "url: http://target.example/#/search?q=test" in out
    assert "[Runtime execution proof (nonce round-trip)]" in out
    assert f"injected_nonce: {nonce}" in out
    assert f"observed_dialog_message: {nonce}" in out
    assert "nonce_match: true" in out


def test_build_browser_execution_poc_response_legacy_when_nonce_empty():
    """nonce が空なら従来どおり観測ログのみ（後方互換・往復行なし）。"""
    out = SmartXSSHunter._build_browser_execution_poc_response(
        test_url="http://target.example/#/search?q=test",
        observation_logs=[{"type": "dialog", "dialog_type": "alert", "message": "1"}],
    )
    assert "dialog=alert message=1" in out
    assert "[Runtime execution proof (nonce round-trip)]" not in out
    assert "injected_nonce:" not in out


# ---------------------------------------------------------------------------
# playwright フォールバック経路（dom / reflected / stored）の往復記録
# ---------------------------------------------------------------------------

class _NotExecutedPoolResult:
    executed = False


class _NotExecutedPoolVerifier:
    async def verify(self, url, parameter, payload, *, dialog_timeout=3.0):
        return _NotExecutedPoolResult()

    async def close(self):
        return None


class _FiringValidatorWithDialog:
    """PlaywrightValidator のテスト用スタブ。

    validate_xss は必ず True（発火）を返し、クラス変数 message が設定されていれば
    _last_observation_logs に dialog ログ（message=message）を積む。
    """
    is_available = True
    message = ""

    def __init__(self):
        self._browser_args = []
        self._last_observation_logs = []
        if self.message:
            self._last_observation_logs = [
                {"type": "dialog", "dialog_type": "alert", "message": self.message},
            ]

    async def validate_xss(self, url, timeout=10.0, cookies=None):
        return True


def _patch_firing_validator(monkeypatch, message):
    """PlaywrightValidator を dialog message=message で発火するスタブへ差し替える。"""
    _FiringValidatorWithDialog.message = message
    import src.tools.browser.playwright_validator as playwright_validator_module
    monkeypatch.setattr(playwright_validator_module, "PlaywrightValidator", _FiringValidatorWithDialog)


@pytest.mark.asyncio
async def test_validate_dom_runtime_xss_playwright_records_nonce_roundtrip(monkeypatch):
    """dom playwright フォールバック: dialog message == nonce で往復記録 + poc_response 往復行。"""
    hunter = SmartXSSHunter()
    nonce = hunter._generate_xss_nonce()
    hunter._current_xss_nonce = nonce

    import src.core.detection.browser_pool as browser_pool_module
    monkeypatch.setattr(browser_pool_module, "BrowserPoolXSSVerifier", _NotExecutedPoolVerifier)
    _patch_firing_validator(monkeypatch, nonce)

    executed = await hunter._validate_dom_runtime_xss(
        "http://example.com/search?q=test",
        _nonce_payload(nonce),
        "",
        param_name="q",
    )

    assert executed is True
    evidence = hunter._browser_execution_evidence
    assert evidence["executor"] == "playwright"
    assert evidence["dialog_observed"] is True
    assert evidence["nonce"] == nonce
    assert evidence["observed_dialog_message"] == nonce
    assert evidence["nonce_match"] is True
    assert f"injected_nonce: {nonce}" in hunter._last_poc_response
    assert "nonce_match: true" in hunter._last_poc_response


@pytest.mark.asyncio
async def test_validate_reflected_runtime_xss_playwright_records_nonce_roundtrip(monkeypatch):
    """reflected playwright フォールバック: dialog message == nonce で往復記録。"""
    hunter = SmartXSSHunter()
    nonce = hunter._generate_xss_nonce()
    hunter._current_xss_nonce = nonce

    import src.core.detection.browser_pool as browser_pool_module
    monkeypatch.setattr(browser_pool_module, "BrowserPoolXSSVerifier", _NotExecutedPoolVerifier)
    _patch_firing_validator(monkeypatch, nonce)

    executed = await hunter._validate_reflected_runtime_xss(
        "http://example.com/search?q=1",
        _nonce_payload(nonce),
        "q",
        cookies_str="",
    )

    assert executed is True
    evidence = hunter._browser_execution_evidence
    assert evidence["executor"] == "playwright"
    assert evidence["variant"] == "reflected"
    assert evidence["nonce"] == nonce
    assert evidence["observed_dialog_message"] == nonce
    assert evidence["nonce_match"] is True


@pytest.mark.asyncio
async def test_validate_stored_runtime_xss_playwright_records_nonce_roundtrip(monkeypatch):
    """stored playwright フォールバック: dialog message == nonce で往復記録。"""
    hunter = SmartXSSHunter()
    nonce = hunter._generate_xss_nonce()
    hunter._current_xss_nonce = nonce

    _patch_firing_validator(monkeypatch, nonce)

    executed = await hunter._validate_stored_runtime_xss(
        "http://example.com/items/1",
        _nonce_payload(nonce),
        "",
        "message",
    )

    assert executed is True
    evidence = hunter._browser_execution_evidence
    assert evidence["executor"] == "playwright"
    assert evidence["variant"] == "stored"
    assert evidence["nonce"] == nonce
    assert evidence["observed_dialog_message"] == nonce
    assert evidence["nonce_match"] is True
    assert hunter._stored_xss_revisit_evidence["revisit_url"] == "http://example.com/items/1"


@pytest.mark.asyncio
async def test_validate_reflected_runtime_xss_playwright_mismatch_is_false(monkeypatch):
    """reflected 経路で dialog message が nonce と一致しない場合は nonce_match=False。"""
    hunter = SmartXSSHunter()
    nonce = hunter._generate_xss_nonce()
    hunter._current_xss_nonce = nonce

    import src.core.detection.browser_pool as browser_pool_module
    monkeypatch.setattr(browser_pool_module, "BrowserPoolXSSVerifier", _NotExecutedPoolVerifier)
    _patch_firing_validator(monkeypatch, "someone-else-message")

    executed = await hunter._validate_reflected_runtime_xss(
        "http://example.com/search?q=1",
        _nonce_payload(nonce),
        "q",
        cookies_str="",
    )

    assert executed is True
    evidence = hunter._browser_execution_evidence
    assert evidence["nonce"] == nonce
    assert evidence["observed_dialog_message"] == "someone-else-message"
    assert evidence["nonce_match"] is False


# ---------------------------------------------------------------------------
# (e) 回帰: nonce 入りペイロードでも本文反射（deterministic precheck）は成立する
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_as_tool_deterministic_precheck_reflects_nonce_payload(monkeypatch):
    """本文反射経路が nonce 入りペイロードでも成立（payload 全体反射で判定のため）。"""
    import src.core.agents.swarm.injection.smart_xss as smart_xss_module
    from urllib.parse import urlparse, parse_qs

    monkeypatch.setattr(smart_xss_module, "_fetch_and_parse_form", AsyncMock(return_value=[]))
    hunter = SmartXSSHunter(config={"mode": "ctf"})

    async def _echo_request(_method, target_url, **_kwargs):
        query = parse_qs(urlparse(target_url).query)
        reflected = ""
        if query:
            reflected = (query.get(next(iter(query.keys()))) or [""])[0]
        return {"status": 200, "body": f"<html>{reflected}</html>", "headers": {}}

    hunter.smart_client.request = AsyncMock(side_effect=_echo_request)

    captured = {}

    async def _fake_reflected_runtime(target, payload, param_name, cookies_str=""):
        captured["payload"] = payload
        captured["param"] = param_name
        return True

    monkeypatch.setattr(hunter, "_validate_reflected_runtime_xss", _fake_reflected_runtime)
    monkeypatch.setattr(hunter, "_should_attempt_dom_browser_validation", lambda target, param: False)
    monkeypatch.setattr(
        hunter,
        "run_loop",
        AsyncMock(return_value={"status": "completed", "reason": "no_xss", "param": ""}),
    )

    result = await hunter.run_as_tool(
        "http://example.com/search?q=probe",
        {"param": "q", "payload": "probe", "method": "GET"},
    )

    assert result["vulnerable"] is True
    assert result["reflection_observed"] is True
    assert result["evidence"], "reflection evidence must still be recorded"
    nonce = hunter._current_xss_nonce
    assert NONCE_RE.fullmatch(nonce)
    # 最初の deterministic payload（<script> 系）が nonce 入りで反射検出された
    assert captured["payload"] == f"\"><script>alert('{nonce}')</script>"


# ---------------------------------------------------------------------------
# execute(): evidence.response_body へ往復の生事実を記録（fail-closed 維持）
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_execute_response_body_records_nonce_roundtrip_raw_facts(monkeypatch):
    """dialog 発火 finding では response_body が nonce 往復の生記録になる。"""
    hunter = SmartXSSHunter(config={"mode": "ctf"})
    nonce = hunter._generate_xss_nonce()
    payload = _nonce_payload(nonce)

    async def fake_run_as_tool(url, params):
        return {
            "vulnerable": True,
            "reflection_observed": True,
            "evidence": "DOM runtime execution observed via fragment payload",
            "param": "q",
            "tested_params": ["q"],
            "payloads_used": [payload],
            "description": "XSS detected.",
            "browser_execution": {
                "dialog_observed": True,
                "executor": "playwright",
                "event": "dom_runtime_execution",
                "variant": "dom",
                "parameter": "q",
                "payload": payload,
                "test_url": "http://example.com/#/search?q=test",
                "nonce": nonce,
                "observed_dialog_message": nonce,
                "nonce_match": True,
            },
            "poc_request": "GET /search HTTP/1.1\nHost: example.com",
            "poc_response": "HTTP/1.1 200\n\nok",
        }

    monkeypatch.setattr(hunter, "run_as_tool", fake_run_as_tool)

    finding = (await hunter.execute(
        MagicMock(target="http://example.com/search?q=probe", params={"q": "probe"})
    ))[0]

    assert finding.evidence.response_status == 200
    body = finding.evidence.response_body
    assert "[XSS runtime execution]" in body
    assert "test_url=http://example.com/#/search?q=test" in body
    assert f"injected_nonce={nonce}" in body
    assert f"observed_dialog_message={nonce}" in body
    assert "nonce_match=True" in body


@pytest.mark.asyncio
async def test_execute_response_body_fail_closed_without_dialog(monkeypatch):
    """dialog 非観測（または browser_execution 無し）なら response_body は要約のまま。"""
    hunter = SmartXSSHunter(config={"mode": "ctf"})

    async def fake_run_as_tool(url, params):
        return {
            "vulnerable": True,
            "reflection_observed": True,
            "evidence": "Payload reflected without encoding",
            "param": "q",
            "tested_params": ["q"],
            "payloads_used": ["<img src=x onerror=alert('sgkdeadbeef0000')>"],
            "description": "XSS detected.",
            "browser_execution": {},
            "poc_request": "GET /search HTTP/1.1\nHost: example.com",
            "poc_response": "HTTP/1.1 200\n\nok",
        }

    monkeypatch.setattr(hunter, "run_as_tool", fake_run_as_tool)

    finding = (await hunter.execute(
        MagicMock(target="http://example.com/search?q=probe", params={"q": "probe"})
    ))[0]

    assert finding.evidence.response_status == 0
    assert finding.evidence.response_body == "Payload reflected without encoding"
    assert "[XSS runtime execution]" not in finding.evidence.response_body
