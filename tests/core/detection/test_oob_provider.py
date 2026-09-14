"""SGK-2026-0494: LocalOOBProvider（自前ローカル HTTP OOB 受信）の実自己コールバック検証。
new_callback で発行した URL を実際に GET すると、poll がその token の interaction を返す。
製品非依存・実ネット依存なし（localhost の自前受信器のみ）。"""

import asyncio
import urllib.request

from src.core.detection.oob_provider import LocalOOBProvider, OOBProvider

_PORT = 13402


def test_local_provider_conforms_to_protocol():
    assert isinstance(LocalOOBProvider(), OOBProvider)


def test_new_callback_format_and_token_in_url():
    p = LocalOOBProvider(port=_PORT)
    url, token = p.new_callback()
    assert token and token in url
    assert url.startswith("http://")


def test_callback_base_override_for_reachability():
    p = LocalOOBProvider(port=_PORT, callback_base="http://172.17.0.1:13402")
    url, token = p.new_callback()
    assert url == f"http://172.17.0.1:13402/callback/{token}"


def test_real_self_callback_is_observed():
    async def _run():
        provider = LocalOOBProvider(port=_PORT)
        await provider.start()
        try:
            url, token = provider.new_callback()
            # 実際にコールバック URL を叩く（標的の外向き取得を模擬）。
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, lambda: urllib.request.urlopen(url, timeout=5).read()
            )
            interaction = await provider.poll(token, timeout=5.0)
            return token, interaction
        finally:
            await provider.stop()

    token, interaction = asyncio.run(_run())
    assert isinstance(interaction, dict)
    assert token in str(interaction.get("path") or "")


def test_poll_returns_none_when_no_callback():
    async def _run():
        provider = LocalOOBProvider(port=_PORT + 1)
        await provider.start()
        try:
            _url, token = provider.new_callback()
            return await provider.poll(token, timeout=1.0)
        finally:
            await provider.stop()

    assert asyncio.run(_run()) is None
