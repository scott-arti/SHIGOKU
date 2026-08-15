"""
SGK-2026-0451 STEP 2/3: SmartSQLiHunter 発火経路（決定論的 error-based 発火）の単体テスト

- メタ/ノイズ除外 + URL 実在クエリ優先の汎用 candidate 選定（フラグ ON）
- 既定 OFF は従来の candidate 順序・戻り値を維持（バイト等価）
- 発火プローブ送信で probe_sent=True・poc_request/poc_response 記録・sql_error marker
- sql_error 観測時の候補 finding 生成（execute）— フラグ ON のみ
- decide() への probe observation 反映
- manager 記録配線（run_sqli_hunter が probe_sent/probe_request_raw/probe_response_raw を返す）
"""
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter

# monkeypatch 前に本来の get_settings を捕捉（再帰回避）
import src.core.config.settings as _settings_mod  # noqa: E402

_ORIG_GET_SETTINGS = _settings_mod.get_settings


def _settings_flag(flag: bool):
    """get_settings() のモンキーパッチ用: 実 settings を維持しつつ
    sqli_firing_path_enabled のみ上書きする（LLMClient 等の他フィールド参照を壊さない）。"""
    from types import SimpleNamespace

    real = _ORIG_GET_SETTINGS()
    return SimpleNamespace(
        sqli_firing_path_enabled=flag,
        llm=getattr(real, "llm", None),
    )


def _make_hunter() -> SmartSQLiHunter:
    hunter = SmartSQLiHunter(config={"mode": "vulntest"})
    hunter.llm = MagicMock()
    return hunter


# --- candidate 選定 ---


def test_prioritize_candidate_params_excludes_meta_and_noise_and_prioritizes_url_query():
    """フラグ ON: url_evidence/detection_mode/EIO/transport が除外され、
    その URL のクエリに実在するパラメータが先頭に来る（汎用・名前決め打ちなし）。"""
    hunter = _make_hunter()
    payload_params = {
        "method": "GET",
        "url_evidence": {"params": [{"name": "q"}]},
        "detection_mode": "phase1",
        "EIO": "4",
        "transport": "polling",
        "t": "abc",
        "name": "1",
        "q": "1",
        "query": "1",
        "data": "1",
    }
    url_params_flat = {"q": "test"}  # /search?q=test 相当
    candidates = hunter._prioritize_candidate_params_generic(payload_params, url_params_flat)

    assert "url_evidence" not in candidates
    assert "detection_mode" not in candidates
    assert "EIO" not in candidates
    assert "transport" not in candidates
    assert "method" not in candidates
    # この URL のクエリ実在パラメータ優先（q 決め打ちでなく汎用ルールの帰結）
    assert candidates[0] == "q"
    assert set(candidates) <= {"t", "name", "q", "query", "data"}
    assert len(candidates) <= hunter.MAX_PARAMS_TO_TEST


def test_prioritize_candidate_params_empty_value_url_param_still_first():
    """?q= のように空値の実在クエリパラメータも URL 実在として先頭に来る（汎用ルール）。"""
    hunter = _make_hunter()
    payload_params = {
        "EIO": "4",
        "transport": "polling",
        "t": "abc",
        "name": "1",
        "q": "",
        "query": "1",
        "data": "1",
    }
    # run_as_tool の fire 分岐と同じ keep_blank_values パースを再現
    from urllib.parse import parse_qs, urlparse

    parsed = urlparse("http://x/rest/products/search?q=")
    fire_url_params = parse_qs(parsed.query, keep_blank_values=True)
    fire_url_params_flat = {k: (v[0] if v else "") for k, v in fire_url_params.items()}
    assert fire_url_params_flat == {"q": ""}

    candidates = hunter._prioritize_candidate_params_generic(payload_params, fire_url_params_flat)
    assert candidates[0] == "q"
    assert "EIO" not in candidates
    assert "transport" not in candidates


def test_candidate_order_default_off_is_legacy():
    """既定 OFF: candidate 順序は従来どおり（メタ混入・ノイズ混入・順序不変）＝バイト等価。"""
    hunter = _make_hunter()
    payload_params = {
        "url_evidence": {},
        "detection_mode": "phase1",
        "EIO": "4",
        "transport": "polling",
        "q": "1",
    }
    legacy = [
        name for name in list(payload_params.keys())
        if not hunter._is_excluded_param(name) and not hunter._is_non_attack_param(name)
    ][:hunter.MAX_PARAMS_TO_TEST] if payload_params else []
    assert legacy == ["url_evidence", "detection_mode", "EIO", "transport", "q"]


# --- 発火プローブ ---


def _obs(status=200, diff="syntax", body="SQL syntax error near", error_type="syntax"):
    return {
        "status": status,
        "diff": diff,
        "body_snippet": body,
        "elapsed_seconds": 0.01,
        "db_detection": {"type": "sqlite", "confidence": 0.5, "patterns": []},
        "error_classification": {"type": error_type, "severity": "high", "details": "Syntax error detected"},
        "poc_request": "GET /search?q=1' HTTP/1.1\nHost: x",
        "poc_response": "HTTP/1.1 200\n\n" + body,
    }


@pytest.mark.asyncio
async def test_fire_error_based_probe_sends_and_records():
    """発火プローブが _send_request 経由で送信され probe_sent/poc/sql_error が記録される。"""
    hunter = _make_hunter()
    hunter.context = {"param": "q", "target": "http://x/search?q=1", "method": "GET", "params": {"q": "1"}}
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        return _obs()

    hunter._send_request = fake_send
    hunter._probe_sent = False
    observation = await hunter._fire_error_based_probe("q", "1")

    assert len(calls) == 2
    assert calls[0] == "q=1'"
    assert calls[1] == 'q=1"'
    assert hunter._probe_sent is True
    # 発火 payload が used_payloads に記録される（0449 充填の payload 要件）
    assert hunter.used_payloads == ["q=1'", 'q=1"']
    assert hunter._last_poc_request == "GET /search?q=1' HTTP/1.1\nHost: x"
    assert hunter._last_poc_response.startswith("HTTP/1.1 200")
    assert hunter._sql_error_observed is True
    assert hunter._sql_error_evidence["error_type"] == "syntax"
    assert hunter._sql_error_evidence["payload"] in {"q=1'", 'q=1"'}
    assert "ErrorType=syntax" in observation


@pytest.mark.asyncio
async def test_fire_probe_normal_response_no_false_marker():
    """正常応答では sql_error marker が立たない（誤検出ゼロ）。"""
    hunter = _make_hunter()
    hunter.context = {"param": "q", "target": "http://x/search?q=1", "method": "GET", "params": {"q": "1"}}

    async def fake_send(payload):
        return {
            "status": 200, "diff": "normal", "body_snippet": "ok", "elapsed_seconds": 0.01,
            "error_classification": {"type": "none"},
            "poc_request": "GET /search?q=1 HTTP/1.1\nHost: x",
            "poc_response": "HTTP/1.1 200\n\nok",
        }

    hunter._send_request = fake_send
    hunter._probe_sent = False
    observation = await hunter._fire_error_based_probe("q", "1")

    assert hunter._sql_error_observed is False
    assert "ErrorType=none" in observation


# --- run_as_tool 統合（フラグ ON/OFF）---


@pytest.mark.asyncio
async def test_run_as_tool_fire_path_surfaces_probe_fields(monkeypatch):
    """フラグ ON: run_as_tool が probe_sent/probe_request_raw/probe_response_raw を返し、
    実パラメータへ発火プローブが送られる（LLM が即 finish でも発火は保証される）。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True))
    import src.core.agents.swarm.injection.smart_sqli as mod
    monkeypatch.setattr(mod, "_fetch_and_parse_form", AsyncMock(return_value=[]))

    hunter = _make_hunter()
    hunter._send_request = AsyncMock(return_value=_obs())
    # LLM ループは即 finish（request を選ばない）でも発火は保証される
    async def fake_run_loop(ctx):
        return {"status": "completed", "turns": 1}
    hunter.run_loop = fake_run_loop

    result = await hunter.run_as_tool(
        "http://x/search?q=test",
        {
            "_auth": {"auth_headers": {}, "cookies": ""},
            "method": "GET",
            "forms": [],
            "url_evidence": {},
            "detection_mode": "phase1",
            "EIO": "4",
            "transport": "polling",
            "t": "abc",
            "name": "1",
            "q": "1",
            "query": "1",
            "data": "1",
        },
    )

    assert result["probe_sent"] is True
    assert result["probe_request_raw"]
    assert result["probe_response_raw"]
    assert result["sql_error_observed"] is True
    assert "EIO" not in result["tested_params"]
    assert "transport" not in result["tested_params"]
    assert "url_evidence" not in result["tested_params"]
    assert "detection_mode" not in result["tested_params"]
    assert result["tested_params"][0] == "q"  # URL クエリ実在パラメータ優先


@pytest.mark.asyncio
async def test_run_as_tool_default_off_no_new_keys(monkeypatch):
    """既定 OFF: run_as_tool 戻り値に新キーが追加されず、従来の候補順序を維持（バイト等価）。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(False))
    import src.core.agents.swarm.injection.smart_sqli as mod
    monkeypatch.setattr(mod, "_fetch_and_parse_form", AsyncMock(return_value=[]))

    hunter = _make_hunter()
    hunter._send_request = AsyncMock(return_value=_obs())

    async def fake_run_loop(ctx):
        return {"status": "completed", "turns": 1}
    hunter.run_loop = fake_run_loop

    result = await hunter.run_as_tool(
        "http://x/search?q=test",
        {
            "_auth": {"auth_headers": {}, "cookies": ""},
            "method": "GET",
            "forms": [],
            "url_evidence": {},
            "detection_mode": "phase1",
            "EIO": "4",
            "transport": "polling",
            "t": "abc",
            "name": "1",
            "q": "1",
        },
    )

    assert "probe_sent" not in result
    assert "probe_request_raw" not in result
    assert "probe_response_raw" not in result
    # 従来どおりメタ/ノイズが候補に残る（挙動不変）
    assert "url_evidence" in result["tested_params"]
    assert "EIO" in result["tested_params"]


# --- execute: sql_error 観測時の候補生成 ---


def _task(url="http://x/search?q=test"):
    return Task(id="t1", name="SQLi Check", target=url, params={}, tags=["sqli"])


def _fire_result():
    return {
        "vulnerable": False,
        "evidence": "",
        "param": "q",
        "tested_params": ["q"],
        "payloads_used": ["q=1'"],
        "description": "No SQL Injection detected.",
        "loop_result": {"status": "completed"},
        "blind_correlation": {},
        "sql_error_observed": True,
        "sql_error_evidence": {
            "error_type": "syntax",
            "details": "Syntax error detected",
            "body_snippet": "SQL syntax error near",
        },
        "response_differential": {
            "attack_status": 200,
            "attack_body_snippet": "SQL syntax error near",
            "diff_type": "syntax",
        },
        "poc_request": "GET /search?q=1' HTTP/1.1\nHost: x",
        "poc_response": "HTTP/1.1 200\n\nSQL syntax error near",
    }


@pytest.mark.asyncio
async def test_execute_sql_error_fire_generates_finding(monkeypatch):
    """フラグ ON: LLM が finish を選んでも sql_error 観測+poc 記録で候補 finding が生成される。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True))
    hunter = _make_hunter()
    hunter.run_as_tool = AsyncMock(return_value=_fire_result())

    findings = await hunter.execute(_task())

    assert len(findings) == 1
    f = findings[0]
    assert f.description == "SQL Injection detected (error-based)."
    assert "SQL error observed" in f.evidence.response_body
    assert f.additional_info["poc_request"].startswith("GET")
    assert f.additional_info["sql_error_observed"] is True
    assert f.additional_info["parameter"] == "q"


@pytest.mark.asyncio
async def test_execute_default_off_no_finding_without_vulnerable(monkeypatch):
    """既定 OFF: sql_error 観測+poc 記録があっても vulnerable でなければ finding を出さない（バイト等価）。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(False))
    hunter = _make_hunter()
    hunter.run_as_tool = AsyncMock(return_value=_fire_result())

    findings = await hunter.execute(_task())

    assert findings == []


# --- decide: probe observation 反映 ---


@pytest.mark.asyncio
async def test_decide_includes_probe_observation(monkeypatch):
    """フラグ ON 経路: decide() の prompt に Pre-probe observation が含まれる。"""
    hunter = _make_hunter()
    hunter.context = {
        "target": "http://x/search?q=test", "param": "q", "method": "GET",
        "params": {"q": "1"}, "auth_headers": {}, "cookies": "", "forms": [],
        "probe_observation": "Probe 'q=1\\'': Status=200, Diff=syntax, ErrorType=syntax, Body=SQL syntax",
    }
    msg = MagicMock()
    msg.tool_calls = []
    msg.content = "THOUGHT: x\nACTION: finish\nINPUT: safe"
    resp = MagicMock()
    resp.choices = [MagicMock(message=msg)]
    hunter.llm.agenerate = AsyncMock(return_value=resp)

    _, action, _ = await hunter.decide(1)

    prompt = hunter.llm.agenerate.call_args.args[0][1]["content"]
    assert action == "finish"
    assert "Pre-probe observation:" in prompt
    assert "ErrorType=syntax" in prompt


@pytest.mark.asyncio
async def test_decide_no_probe_observation_default(monkeypatch):
    """probe_observation が無い場合（既定）は prompt に Pre-probe ブロックが現れない（バイト等価）。"""
    hunter = _make_hunter()
    hunter.context = {
        "target": "http://x/search?q=test", "param": "q", "method": "GET",
        "params": {"q": "1"}, "auth_headers": {}, "cookies": "", "forms": [],
    }
    msg = MagicMock()
    msg.tool_calls = []
    msg.content = "THOUGHT: x\nACTION: finish\nINPUT: safe"
    resp = MagicMock()
    resp.choices = [MagicMock(message=msg)]
    hunter.llm.agenerate = AsyncMock(return_value=resp)

    _, action, _ = await hunter.decide(1)

    prompt = hunter.llm.agenerate.call_args.args[0][1]["content"]
    assert "Pre-probe observation:" not in prompt


# --- manager 記録配線 ---


def _make_manager() -> InjectionManagerAgent:
    m = InjectionManagerAgent.__new__(InjectionManagerAgent)
    m.current_context = {"params": {}, "auth_headers": {}, "findings": []}
    m._phase2_detection_mode = "phase2"
    stub = MagicMock()
    stub.execute_with_retry = AsyncMock(return_value=[])
    stub.last_tested_params = []
    stub.last_blind_correlation = {}
    stub._last_probe_sent = True
    stub._last_poc_request = "GET /search?q=1' HTTP/1.1\nHost: x"
    stub._last_poc_response = "HTTP/1.1 200\n\nSQL syntax error"
    m.specialists = {"sqli": stub}
    return m


@pytest.mark.asyncio
async def test_run_sqli_hunter_surfaces_probe_fields(monkeypatch):
    """フラグ ON: run_sqli_hunter が probe_sent/probe_request_raw/probe_response_raw を返す（記録配線）。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True))
    m = _make_manager()

    result = await m.run_sqli_hunter(url="http://x/search?q=test", params={})

    assert result["probe_sent"] is True
    assert result["probe_request_raw"].startswith("GET")
    assert result["probe_response_raw"].startswith("HTTP")


@pytest.mark.asyncio
async def test_run_sqli_hunter_default_off_probe_fields_none(monkeypatch):
    """既定 OFF: probe 系は None/'' のまま（バイト等価）。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(False))
    m = _make_manager()

    result = await m.run_sqli_hunter(url="http://x/search?q=test", params={})

    assert result["probe_sent"] is None
    assert result["probe_request_raw"] == ""
    assert result["probe_response_raw"] == ""
