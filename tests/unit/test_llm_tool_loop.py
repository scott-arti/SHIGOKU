"""
SGK-2026-0450 STEP 2: LLMClient tool_loop モードの単体テスト

- tool_loop=False: tool_calls を含む最初の生応答をそのまま返す（ダミー実行・キャッシュなし）
- tool_loop=True（既定）: 現行のダミー実行ループ・キャッシュ挙動を維持（バイト等価）
"""
import json

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from src.core.models.llm import LLMClient


def _make_tool_call(name: str, args: dict, call_id: str = "call_1"):
    tc = MagicMock()
    tc.id = call_id
    tc.function.name = name
    tc.function.arguments = json.dumps(args)
    return tc


def _make_response(tool_calls=None, content="ok"):
    msg = MagicMock()
    msg.tool_calls = tool_calls or []
    msg.content = content
    resp = MagicMock()
    resp.choices = [MagicMock(message=msg)]
    resp.dict.return_value = {"choices": [{"message": {"content": content}}]}
    return resp


@pytest.fixture
def client():
    return LLMClient(role="swarm_manager")


@pytest.mark.asyncio
async def test_agenerate_tool_loop_false_returns_raw_tool_calls(client):
    """tool_loop=False: tool_calls を含む最初の応答をそのまま返し、追加ラウンド・ダミー実行しない。"""
    resp = _make_response(tool_calls=[_make_tool_call("run_sqli_hunter", {"url": "http://x"})])
    with patch.object(client, "_acompletion_with_retry", new_callable=AsyncMock) as mock_comp:
        mock_comp.return_value = resp
        out = await client.agenerate(
            [{"role": "user", "content": "hi"}],
            tools=[{"type": "function", "function": {"name": "run_sqli_hunter", "parameters": {}}}],
            tool_loop=False,
        )

    assert out is resp  # そのまま返る
    mock_comp.assert_awaited_once()  # 1ラウンドのみ


@pytest.mark.asyncio
async def test_agenerate_tool_loop_false_skips_cache(client):
    """tool_loop=False: キャッシュの読み書きをスキップする。"""
    resp = _make_response(tool_calls=[_make_tool_call("run_sqli_hunter", {"url": "http://x"})])
    with patch.object(client, "_acompletion_with_retry", new_callable=AsyncMock) as mock_comp:
        mock_comp.return_value = resp
        with patch("src.core.models.llm.get_cache") as mock_cache_getter:
            mock_cache = MagicMock()
            mock_cache.get = AsyncMock(return_value=None)
            mock_cache.set = AsyncMock()
            mock_cache_getter.return_value = mock_cache

            await client.agenerate(
                [{"role": "user", "content": "hi"}],
                tools=[{"type": "function", "function": {"name": "run_sqli_hunter", "parameters": {}}}],
                tool_loop=False,
            )

    mock_cache.get.assert_not_awaited()  # 読み込みスキップ
    mock_cache.set.assert_not_awaited()  # 書き込みスキップ


@pytest.mark.asyncio
async def test_agenerate_tool_loop_true_keeps_dummy_loop(client):
    """tool_loop=True（既定）: 現行のダミー実行ループを維持（tool_calls 後に追加ラウンドへ）。"""
    resp1 = _make_response(tool_calls=[_make_tool_call("run_sqli_hunter", {"url": "http://x"})], content=None)
    resp2 = _make_response(tool_calls=[], content="final")
    with patch.object(client, "_acompletion_with_retry", new_callable=AsyncMock) as mock_comp:
        mock_comp.side_effect = [resp1, resp2]
        with patch("src.core.models.llm.get_cache") as mock_cache_getter:
            mock_cache = MagicMock()
            mock_cache.get = AsyncMock(return_value=None)
            mock_cache.set = AsyncMock()
            mock_cache_getter.return_value = mock_cache

            out = await client.agenerate(
                [{"role": "user", "content": "hi"}],
                tools=[{"type": "function", "function": {"name": "run_sqli_hunter", "parameters": {}}}],
            )

    assert mock_comp.await_count == 2  # ダミー実行後にもう1ラウンド
    assert out.choices[0].message.content == "final"


def test_generate_tool_loop_false_returns_raw_tool_calls(client):
    """generate（同期）: tool_loop=False は tool_calls を含む最初の応答をそのまま返す。"""
    resp = _make_response(tool_calls=[_make_tool_call("run_sqli_hunter", {"url": "http://x"})])
    with patch.object(client, "_completion_with_retry") as mock_comp:
        mock_comp.return_value = resp
        with patch("src.core.models.llm.get_cache") as mock_cache_getter:
            mock_cache = MagicMock()
            mock_cache.get = MagicMock(return_value=None)
            mock_cache.set = MagicMock()
            mock_cache_getter.return_value = mock_cache

            out = client.generate(
                [{"role": "user", "content": "hi"}],
                tools=[{"type": "function", "function": {"name": "run_sqli_hunter", "parameters": {}}}],
                tool_loop=False,
            )

    assert out is resp
    mock_comp.assert_called_once()
    mock_cache.get.assert_not_called()
    mock_cache.set.assert_not_called()
