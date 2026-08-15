"""
SGK-2026-0450 STEP 2: smart_sqli tool-calling decide の単体テスト

- tool_calls から request(payload) / finish(summary) を返す
- tool_calls が無い場合の Free-text フォールバック
- 既定 OFF（オプトインなし）は既存 regex パスを維持（バイト等価）
"""
import json

import pytest
from unittest.mock import MagicMock, AsyncMock

from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter


def _make_hunter() -> SmartSQLiHunter:
    hunter = SmartSQLiHunter(config={"model": "test-model"})
    hunter.context = {
        "target": "http://example.com/rest/products/search?q=",
        "param": "q",
        "method": "GET",
        "params": {"q": "1"},
        "auth_headers": {},
        "cookies": "",
        "forms": [],
    }
    hunter.llm = MagicMock()
    return hunter


def _make_response_with_tool_call(name: str, args: dict, content: str = ""):
    tc = MagicMock()
    tc.id = "call_1"
    tc.function.name = name
    tc.function.arguments = json.dumps(args)
    msg = MagicMock()
    msg.tool_calls = [tc]
    msg.content = content
    resp = MagicMock()
    resp.choices = [MagicMock(message=msg)]
    return resp


@pytest.mark.asyncio
async def test_decide_tool_calling_request_payload(monkeypatch):
    """tool-calling 有効時: request ツール呼び出しから (thought, 'request', payload) を返す。"""
    hunter = _make_hunter()
    hunter.context["tool_calling"] = True
    hunter.llm.agenerate = AsyncMock(
        return_value=_make_response_with_tool_call("request", {"payload": "' OR 1=1--"})
    )

    thought, action, action_input = await hunter.decide(1)

    assert action == "request"
    assert action_input == "' OR 1=1--"
    # tools スキーマ付きで呼ばれている
    call_kwargs = hunter.llm.agenerate.call_args
    assert call_kwargs.kwargs.get("tool_loop") is False
    tools = call_kwargs.kwargs.get("tools", [])
    assert [t["function"]["name"] for t in tools] == ["request", "finish"]
    # payload は自由文字列（型は string）
    req = tools[0]["function"]
    assert req["parameters"]["properties"]["payload"]["type"] == "string"


@pytest.mark.asyncio
async def test_decide_tool_calling_finish_summary():
    """tool-calling 有効時: finish ツール呼び出しから (thought, 'finish', summary) を返す。"""
    hunter = _make_hunter()
    hunter.context["tool_calling"] = True
    hunter.llm.agenerate = AsyncMock(
        return_value=_make_response_with_tool_call("finish", {"summary": "safe"})
    )

    thought, action, action_input = await hunter.decide(1)

    assert action == "finish"
    assert action_input == "safe"


@pytest.mark.asyncio
async def test_decide_tool_calling_no_tool_calls_falls_back_to_regex():
    """tool-calling 有効でも tool_calls が無い場合は既存 regex パスにフォールバックする。"""
    hunter = _make_hunter()
    hunter.context["tool_calling"] = True
    msg = MagicMock()
    msg.tool_calls = []
    msg.content = "THOUGHT: Try error-based payload.\nACTION: request\nINPUT: '"
    resp = MagicMock()
    resp.choices = [MagicMock(message=msg)]
    hunter.llm.agenerate = AsyncMock(return_value=resp)

    thought, action, action_input = await hunter.decide(1)

    assert action == "request"
    assert action_input == "'"


@pytest.mark.asyncio
async def test_decide_tool_calling_empty_payload_falls_back():
    """request ツール呼び出しでも payload が空ならフォールバック（fail-closed）。"""
    hunter = _make_hunter()
    hunter.context["tool_calling"] = True
    hunter.llm.agenerate = AsyncMock(
        return_value=_make_response_with_tool_call("request", {"payload": ""})
    )

    thought, action, action_input = await hunter.decide(1)

    # フォールバック（content が空 → finish 強制）
    assert action == "finish"


@pytest.mark.asyncio
async def test_decide_default_path_keeps_regex_behavior():
    """既定（tool_calling オプトインなし）: 既存 regex パスで THOUGHT/ACTION/INPUT を解釈する。"""
    hunter = _make_hunter()
    msg = MagicMock()
    msg.tool_calls = []
    msg.content = "THOUGHT: Try union payload.\nACTION: request\nINPUT: ' UNION SELECT 1--"
    resp = MagicMock()
    resp.choices = [MagicMock(message=msg)]
    hunter.llm.agenerate = AsyncMock(return_value=resp)

    thought, action, action_input = await hunter.decide(1)

    assert action == "request"
    assert action_input == "' UNION SELECT 1--"
    # 既定パスは tools を渡さない
    call_kwargs = hunter.llm.agenerate.call_args
    assert "tools" not in call_kwargs.kwargs
    assert call_kwargs.kwargs.get("tool_loop") is None
