"""
SGK-2026-0450 STEP 2: base_manager tool-calling 経路の単体テスト

- 型付きスキーマの機械生成（_build_tool_schemas）
- tool_calls からの実行（_handle_tool_calls）
- 無効引数 fail-closed
- 重複排除ガード（同一 (action, target, params) の再実行抑止）
- 既定 OFF のバイト等価性（既存 Free-text パスが tools なしで動く）
"""
import json

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.base_manager import BaseManagerAgent


def _make_manager() -> BaseManagerAgent:
    manager = BaseManagerAgent(config={"model": "test-model"})
    manager.current_context = {
        "target": "http://example.com/rest/products/search?q=",
        "params": {},
        "auth_headers": {},
        "findings": [],
    }
    # dispatch() 内で初期化される属性（_handle_tool_calls を直接呼ぶテスト用）
    manager.total_tools_executed = 0
    manager._executed_actions = set()
    manager._use_dedup_guard = False
    return manager


def _make_tool_call(name: str, args: dict, call_id: str = "call_1"):
    tc = MagicMock()
    tc.id = call_id
    tc.function.name = name
    tc.function.arguments = json.dumps(args)
    return tc


def _make_response(tool_calls=None, content=None):
    msg = MagicMock()
    msg.tool_calls = tool_calls or []
    msg.content = content
    resp = MagicMock()
    resp.choices = [MagicMock(message=msg)]
    return resp


@pytest.mark.asyncio
async def test_build_tool_schemas_generates_typed_schema():
    """_build_tool_schemas が inspect.signature から型付きスキーマを機械生成する。"""
    manager = _make_manager()

    async def fake_hunter(url: str, params: dict = None, quick_mode: bool = False, **_kwargs):
        return {"success": True}

    manager.register_tool("run_sqli_hunter", fake_hunter, "SQLi scan desc")

    schemas = manager._build_tool_schemas()
    assert len(schemas) == 1
    fn = schemas[0]["function"]
    assert fn["name"] == "run_sqli_hunter"
    assert fn["description"] == "SQLi scan desc"
    params = fn["parameters"]
    assert params["type"] == "object"
    assert params["properties"]["url"]["type"] == "string"
    assert params["properties"]["params"]["type"] == "object"
    assert params["properties"]["quick_mode"]["type"] == "boolean"
    assert params["required"] == ["url"]


@pytest.mark.asyncio
async def test_handle_tool_calls_executes_from_structured_args():
    """tool_calls から名前・引数を取り出して実行し、history に tool メッセージを追加する。"""
    manager = _make_manager()
    executed = []

    async def fake_hunter(url: str, params: dict = None, **_kwargs):
        executed.append((url, params))
        return {"success": True, "findings_count": 0}

    manager.register_tool("run_sqli_hunter", fake_hunter, "desc")
    execution_log = []

    result = await manager._handle_tool_calls(
        [_make_tool_call("run_sqli_hunter", {"url": "http://example.com/rest/products/search?q="})],
        turn=1,
        execution_log=execution_log,
    )

    assert result is False  # payout 停止なし
    assert len(executed) == 1
    assert manager.total_tools_executed == 1
    assert len(execution_log) == 1
    assert execution_log[0]["action"] == "run_sqli_hunter"
    tool_msgs = [m for m in manager.history if m.get("role") == "tool"]
    assert len(tool_msgs) == 1
    assert "Observation:" in tool_msgs[0]["content"]


@pytest.mark.asyncio
async def test_handle_tool_calls_invalid_args_fail_closed():
    """無効な tool 引数（非 JSON）は fail-closed でスキップされる（実行されない）。"""
    manager = _make_manager()
    executed = []

    async def fake_hunter(url: str, **_kwargs):
        executed.append(url)
        return {"success": True}

    manager.register_tool("run_sqli_hunter", fake_hunter, "desc")

    tc = MagicMock()
    tc.id = "call_bad"
    tc.function.name = "run_sqli_hunter"
    tc.function.arguments = "not-json{{{"
    execution_log = []

    result = await manager._handle_tool_calls([tc], turn=1, execution_log=execution_log)

    assert result is False
    assert len(executed) == 0  # 実行されない
    assert manager.total_tools_executed == 0
    assert len(execution_log) == 1
    assert "warning" in execution_log[0]["type"]
    tool_msgs = [m for m in manager.history if m.get("role") == "tool"]
    assert len(tool_msgs) == 1
    assert "invalid tool arguments" in tool_msgs[0]["content"]


@pytest.mark.asyncio
async def test_handle_tool_calls_unknown_tool_fail_closed():
    """未知ツール名は _execute_tool の ValueError によりエラー観察に落ちる（fail-closed）。"""
    manager = _make_manager()
    execution_log = []

    result = await manager._handle_tool_calls(
        [_make_tool_call("no_such_tool", {"url": "http://example.com"})],
        turn=1,
        execution_log=execution_log,
    )

    assert result is False
    tool_msgs = [m for m in manager.history if m.get("role") == "tool"]
    assert len(tool_msgs) == 1
    assert "failed" in tool_msgs[0]["content"].lower()


@pytest.mark.asyncio
async def test_dedup_guard_blocks_same_action_target_params():
    """重複排除ガード: 同一 (action, 正規化URL, params) の再実行を抑止し前進させる。"""
    manager = _make_manager()
    manager._use_dedup_guard = True
    manager._executed_actions = set()
    executed = []

    async def fake_hunter(url: str, params: dict = None, **_kwargs):
        executed.append((url, params))
        return {"success": True, "findings_count": 0}

    manager.register_tool("run_sqli_hunter", fake_hunter, "desc")
    execution_log = []
    tc1 = _make_tool_call("run_sqli_hunter", {"url": "http://example.com/a?q=1&p=2"}, call_id="c1")
    tc2 = _make_tool_call("run_sqli_hunter", {"url": "http://example.com/a?p=2&q=1"}, call_id="c2")  # クエリ順のみ異なる = 同一

    await manager._handle_tool_calls([tc1], turn=1, execution_log=execution_log)
    await manager._handle_tool_calls([tc2], turn=2, execution_log=execution_log)

    assert len(executed) == 1  # 2回目は抑止
    tool_msgs = [m for m in manager.history if m.get("role") == "tool"]
    assert len(tool_msgs) == 2
    assert "already executed" in tool_msgs[1]["content"]
    assert execution_log[1].get("dedupe_skipped") is True


@pytest.mark.asyncio
async def test_dedup_guard_allows_different_params():
    """重複排除ガード: params が異なれば別手として許可（適応幅を狭めない）。"""
    manager = _make_manager()
    manager._use_dedup_guard = True
    manager._executed_actions = set()
    executed = []

    async def fake_hunter(url: str, params: dict = None, **_kwargs):
        executed.append((url, params))
        return {"success": True, "findings_count": 0}

    manager.register_tool("run_sqli_hunter", fake_hunter, "desc")
    execution_log = []

    await manager._handle_tool_calls(
        [_make_tool_call("run_sqli_hunter", {"url": "http://example.com/a", "params": {"q": "1"}}, call_id="c1")],
        turn=1, execution_log=execution_log,
    )
    await manager._handle_tool_calls(
        [_make_tool_call("run_sqli_hunter", {"url": "http://example.com/a", "params": {"q": "2"}}, call_id="c2")],
        turn=2, execution_log=execution_log,
    )

    assert len(executed) == 2  # params 違いは実行される
    assert not any(m.get("role") == "tool" and "already executed" in m.get("content", "") for m in manager.history)


def test_normalize_target_url_query_sort_and_fragment():
    """_normalize_target_url: クエリソート・フラグメント除去・小文字化。"""
    manager = _make_manager()
    norm = manager._normalize_target_url("HTTP://Example.COM:8080/a?b=2&a=1#frag")
    assert norm == "http://example.com:8080/a?a=1&b=2"


def test_normalize_target_url_missing_scheme_raises():
    """_normalize_target_url: scheme 欠落は ValueError。"""
    manager = _make_manager()
    with pytest.raises(ValueError):
        manager._normalize_target_url("example.com/a")


def test_action_fingerprint_ignores_injection_meta():
    """_action_fingerprint: _auth 等の注入メタは fingerprint から除外される。"""
    manager = _make_manager()
    fp1 = manager._action_fingerprint(
        "run_sqli_hunter", {"url": "http://example.com/a", "params": {"q": "1", "_auth": {"x": 1}}}
    )
    fp2 = manager._action_fingerprint(
        "run_sqli_hunter", {"url": "http://example.com/a", "params": {"q": "1"}}
    )
    assert fp1 == fp2


@pytest.mark.asyncio
async def test_dispatch_tool_calling_path_uses_tools_and_executes():
    """dispatch: tool_calling オプトイン ON で tools を渡して呼び、tool_calls から実行する。"""
    manager = _make_manager()
    executed = []

    async def fake_hunter(url: str, **_kwargs):
        executed.append(url)
        return {"success": True, "findings_count": 0}

    manager.register_tool("run_sqli_hunter", fake_hunter, "desc")

    mock_llm = MagicMock()
    resp1 = _make_response(
        tool_calls=[_make_tool_call("run_sqli_hunter", {"url": "http://example.com/a"}, call_id="c1")],
        content=None,
    )
    resp2 = _make_response(tool_calls=None, content="Final Answer: done")
    mock_llm.agenerate = AsyncMock(side_effect=[resp1, resp2])
    manager.set_llm_client(mock_llm)

    task = Task(
        id="t1", name="test", target="http://example.com/a",
        params={"tool_calling": True, "dedup_guard": False},
    )
    result = await manager.dispatch(task)

    assert result.status == "success"
    assert len(executed) == 1
    # tools 付きで agenerate が呼ばれた
    call_kwargs = mock_llm.agenerate.call_args_list[0]
    assert "tools" in call_kwargs.kwargs
    assert call_kwargs.kwargs.get("tool_loop") is False
    assert call_kwargs.kwargs["tools"][0]["function"]["name"] == "run_sqli_hunter"


@pytest.mark.asyncio
async def test_dispatch_default_path_is_byte_equivalent():
    """dispatch: 既定（オプトイン OFF）は既存 Free-text パスが tools なしで動く（バイト等価）。"""
    manager = _make_manager()

    async def fake_hunter(url: str, **_kwargs):
        return {"success": True, "findings_count": 0}

    manager.register_tool("run_sqli_hunter", fake_hunter, "desc")

    mock_llm = MagicMock()
    resp1 = _make_response(
        tool_calls=[_make_tool_call("run_sqli_hunter", {"url": "http://example.com/a"}, call_id="c1")],
        content=None,
    )
    # tool_calls を返しても（モック上）既定パスでは無視され、Action: 行の Free-text で解釈する
    resp2 = _make_response(tool_calls=None, content='Action: run_sqli_hunter({"url": "http://example.com/a"})')
    resp3 = _make_response(tool_calls=None, content="Final Answer: done")
    mock_llm.agenerate = AsyncMock(side_effect=[resp1, resp2, resp3])
    manager.set_llm_client(mock_llm)

    task = Task(id="t1", name="test", target="http://example.com/a")  # オプトインなし
    result = await manager.dispatch(task)

    assert result.status == "success"
    call_kwargs = mock_llm.agenerate.call_args_list[0]
    assert "tools" not in call_kwargs.kwargs  # tools を渡さない
    assert call_kwargs.kwargs.get("tool_loop") is None  # tool_loop も渡さない
