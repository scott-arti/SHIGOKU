
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from aiohttp import ClientError

from src.core.infra.network_client import (
    AsyncNetworkClient,
    NetworkResponse,
    create_network_client,
)
from src.core.infra.proxy_manager import ProxyChainManager


class MockResponse:
    def __init__(self, text='{"success": true}', status=200):
        self._text = text
        self.status = status
        self.headers = {"Content-Type": "application/json"}
        self.url = "http://test.com"
        self.cookies = MagicMock()
        self.cookies.items.return_value = []
        
    async def text(self, errors=None):
        return self._text
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

@pytest.fixture
def mock_session():
    session = MagicMock()
    session.close = AsyncMock()
    session.request.return_value = MockResponse()
    session.closed = False
    return session

class TestAsyncNetworkClient:
    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_simple_request(self, mock_proxy_check, mock_start, mock_session):
        client = AsyncNetworkClient()
        client._session = mock_session
        
        resp = await client.request("GET", "http://test.com", use_proxy=False, use_cache=False)
        
        assert resp.status == 200
        assert resp.body == '{"success": true}'
        assert mock_session.request.called

    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_proxy_usage(self, mock_proxy_check, mock_start, mock_session):
        proxy_manager = MagicMock(spec=ProxyChainManager)
        proxy_manager.get_proxy.return_value = "http://p1"
        client = AsyncNetworkClient(proxy_manager=proxy_manager)
        client._session = mock_session
        
        await client.request("GET", "http://test.com", use_proxy=True, use_cache=False)
        
        # Check if proxy was passed to aiohttp
        assert mock_session.request.called
        _, kwargs = mock_session.request.call_args
        assert kwargs["proxy"] == "http://p1"

    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_retry_on_500(self, mock_proxy_check, mock_start, mock_session):
        mock_session.request.side_effect = [
            MockResponse(text="Error", status=500),
            MockResponse(text="OK", status=200)
        ]
        client = AsyncNetworkClient()
        client._session = mock_session
        
        resp = await client.request("GET", "http://test.com", retries=2, use_proxy=False, use_cache=False)
        
        assert resp.status == 200
        assert resp.body == "OK"
        assert mock_session.request.call_count == 2

    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_retry_on_connection_error(self, mock_proxy_check, mock_start, mock_session):
        mock_session.request.side_effect = [
            ClientError("ConnErr"),
            MockResponse(text="OK", status=200)
        ]
        client = AsyncNetworkClient()
        client._session = mock_session
        
        resp = await client.request("GET", "http://test.com", retries=2, use_proxy=False, use_cache=False)
        
        assert resp.status == 200
        assert mock_session.request.call_count == 2

    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_proxy_rotation_on_retry(self, mock_proxy_check, mock_start, mock_session):
        proxy_manager = MagicMock(spec=ProxyChainManager)
        proxy_manager.get_proxy.side_effect = ["http://p1", "http://p2"]
        client = AsyncNetworkClient(proxy_manager=proxy_manager)
        client._session = mock_session
        
        mock_session.request.side_effect = [
            MockResponse(text="Error", status=500),
            MockResponse(text="OK", status=200)
        ]
        
        await client.request("GET", "http://test.com", retries=2, use_proxy=True, use_cache=False)
        
        calls = mock_session.request.call_args_list
        assert len(calls) == 2
        assert calls[0].kwargs["proxy"] == "http://p1"
        assert calls[1].kwargs["proxy"] == "http://p2"

    @pytest.mark.asyncio
    async def test_context_manager(self):
        with patch('aiohttp.ClientSession') as MockSession:
            mock_instance = MockSession.return_value
            mock_instance.close = AsyncMock()
            
            async with AsyncNetworkClient() as client:
                pass


    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_auto_waf_bypass(self, mock_proxy_check, mock_start, mock_session):
        client = AsyncNetworkClient()
        client._session = mock_session
        
        # 1回目は403(WAFブロック)、2回目は200を返すモック
        mock_session.request.side_effect = [
            MockResponse(text="Blocked by WAF", status=403),
            MockResponse(text="OK", status=200)
        ]
        
        # 元のパラメータ
        params = {"q": "SELECT * FROM users"}
        
        # リクエスト実行 (auto_waf_bypass=True)
        resp = await client.request(
            "GET", "http://test.com", 
            params=params, 
            retries=1, 
            use_proxy=False, 
            use_cache=False,
            auto_waf_bypass=True
        )
        
        assert resp.status == 200
        assert mock_session.request.call_count == 2
        
        # 1回目の呼び出し
        call1_kwargs = mock_session.request.call_args_list[0].kwargs
        assert call1_kwargs["params"]["q"] == "SELECT * FROM users"
        
        # 2回目の呼び出し（変異されているため元の文字列ではないはず）
        call2_kwargs = mock_session.request.call_args_list[1].kwargs
        assert call2_kwargs["params"]["q"] != "SELECT * FROM users"


class TestLogSafeUrl:
    """SGK-2026-0439: ``log_safe_url`` masks the request url in EVERY
    request-lifecycle log line (restored values never reach logs).

    ``mode="ctf"`` skips the compiled-guard enforcement so these tests are
    deterministic in isolation (the guard context is a full-suite state).
    """

    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_request_logs_use_safe_url_when_provided(self, mock_proxy_check, mock_start, mock_session, caplog):
        import logging

        client = AsyncNetworkClient(mode="ctf")
        client._session = mock_session
        caplog.set_level(logging.DEBUG, logger="src.core.infra.network_client")

        await client.request(
            "GET", "http://test.com/records/42?name=x",
            use_proxy=False, use_cache=False,
            log_safe_url="http://test.com/records/42?name=[MASKED]",
        )

        assert "Requesting GET http://test.com/records/42?name=[MASKED]" in caplog.text
        assert "?name=x" not in caplog.text

    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_cache_hit_log_uses_safe_url(self, mock_proxy_check, mock_start, mock_session, caplog):
        import logging

        client = AsyncNetworkClient(mode="ctf")
        client._session = mock_session
        client._cache = MagicMock()
        client._cache.get = AsyncMock(return_value={
            "status": 200,
            "headers": {},
            "body": "cached",
            "elapsed": 0.0,
            "url": "http://test.com/records/42",
            "proxy_used": None,
            "cookies": {},
        })
        caplog.set_level(logging.DEBUG, logger="src.core.infra.network_client")

        resp = await client.request(
            "GET", "http://test.com/records/42?name=x",
            use_proxy=False, use_cache=True,
            log_safe_url="http://test.com/records/42?name=[MASKED]",
        )

        assert "Cache hit for http://test.com/records/42?name=[MASKED]" in caplog.text
        assert "?name=x" not in caplog.text
        assert resp.body == "cached"

    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_retry_and_waf_warnings_use_safe_url(self, mock_proxy_check, mock_start, mock_session, caplog):
        import logging

        mock_session.request.side_effect = [
            MockResponse(text="Error", status=500),
            MockResponse(text="Blocked", status=403),
            MockResponse(text="OK", status=200),
        ]
        client = AsyncNetworkClient(mode="ctf")
        client._session = mock_session
        caplog.set_level(logging.WARNING, logger="src.core.infra.network_client")

        await client.request(
            "GET", "http://test.com/records/42?name=x",
            retries=2, use_proxy=False, use_cache=False, auto_waf_bypass=True,
            log_safe_url="http://test.com/records/42?name=[MASKED]",
        )

        assert "Request failed (500) on attempt 1/3 for http://test.com/records/42?name=[MASKED]" in caplog.text
        assert "WAF Block detected (403) on attempt 2/3 for http://test.com/records/42?name=[MASKED]" in caplog.text
        assert "?name=x" not in caplog.text

    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_raw_url_logged_when_log_safe_url_omitted(self, mock_proxy_check, mock_start, mock_session, caplog):
        """Existing behavior unchanged: callers that do not pass
        ``log_safe_url`` keep logging the actual url."""
        import logging

        client = AsyncNetworkClient(mode="ctf")
        client._session = mock_session
        caplog.set_level(logging.DEBUG, logger="src.core.infra.network_client")

        await client.request(
            "GET", "http://test.com/records/42?name=x",
            use_proxy=False, use_cache=False,
        )

        assert "Requesting GET http://test.com/records/42?name=x" in caplog.text

    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_session_expired_payload_has_raw_and_log_safe_url(self, mock_proxy_check, mock_start, mock_session):
        """SGK-2026-0439: a 401 response emits SESSION_EXPIRED with BOTH the
        raw ``url`` (reauth contract keys on it, SGK-2026-0280) and the
        additive ``log_safe_url`` for log/ledger surfaces."""
        from src.core.infra.event_bus import EventType

        fake_bus = MagicMock()
        client = AsyncNetworkClient(mode="ctf", event_bus=fake_bus)
        client._session = mock_session
        mock_session.request.return_value = MockResponse(text="Unauthorized", status=401)

        await client.request(
            "GET", "http://test.com/records/42?name=x",
            use_proxy=False, use_cache=False,
            log_safe_url="http://test.com/records/42?name=[MASKED]",
        )

        assert fake_bus.emit_sync.called
        emitted = fake_bus.emit_sync.call_args[0][0]
        assert emitted.type == EventType.SESSION_EXPIRED
        assert emitted.payload["url"] == "http://test.com/records/42?name=x"
        assert emitted.payload["log_safe_url"] == "http://test.com/records/42?name=[MASKED]"

    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_session_expired_log_safe_url_falls_back_to_raw(self, mock_proxy_check, mock_start, mock_session):
        """Backward compatible: callers that omit ``log_safe_url`` emit
        ``log_safe_url`` equal to the raw url (existing semantics unchanged)."""
        from src.core.infra.event_bus import EventType

        fake_bus = MagicMock()
        client = AsyncNetworkClient(mode="ctf", event_bus=fake_bus)
        client._session = mock_session
        mock_session.request.return_value = MockResponse(text="Unauthorized", status=401)

        await client.request(
            "GET", "http://test.com/records/42?name=x",
            use_proxy=False, use_cache=False,
        )

        emitted = fake_bus.emit_sync.call_args[0][0]
        assert emitted.type == EventType.SESSION_EXPIRED
        assert emitted.payload["url"] == "http://test.com/records/42?name=x"
        assert emitted.payload["log_safe_url"] == "http://test.com/records/42?name=x"


# ---------------------------------------------------------------------------
# SGK-2026-0447 B4: sealed-run GET-only network-boundary enforcement
# ---------------------------------------------------------------------------


# Additive import for the GET-only enforcement tests only (existing imports
# above are left untouched).
from src.core.infra.network_client import ReadonlyEnforcedError  # noqa: E402


class TestSealedRunGetOnlyEnforcement:
    """Sealed-run GET-only enforcement at the AsyncNetworkClient boundary.

    When ``settings.sealed_run_get_only`` is on, every non-GET/HEAD send on
    the proxied TARGET path (``use_proxy=True``) is blocked BEFORE any
    network I/O (aiohttp session.request must not be called).  The Caido
    control plane (``use_proxy=False``: preflight identity / caido_auth /
    caido_sitemap) is exempt.  Default off keeps existing runs byte-identical.
    """

    @staticmethod
    def _settings_mock(sealed: bool) -> MagicMock:
        s = MagicMock()
        s.sealed_run_get_only = sealed
        return s

    @pytest.mark.asyncio
    @pytest.mark.parametrize("method", ["PATCH", "POST", "PUT"])
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_non_get_blocked_when_flag_on(self, mock_proxy_check, mock_start, mock_session, method):
        """(a) Flag ON + use_proxy=True (target attack path): PATCH/POST/PUT
        raise ReadonlyEnforcedError and no network send happens."""
        with patch(
            "src.core.config.settings.get_settings",
            return_value=self._settings_mock(True),
        ):
            client = AsyncNetworkClient(mode="ctf")
            client._session = mock_session

            with pytest.raises(ReadonlyEnforcedError) as exc_info:
                await client.request(
                    method, "http://test.com", use_proxy=True, use_cache=False
                )

            assert exc_info.value.reason_code == "READONLY_GET_ONLY_ENFORCED"
            mock_session.request.assert_not_called()

    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_post_allowed_when_flag_on_without_proxy(self, mock_proxy_check, mock_start, mock_session):
        """(a2) Flag ON + use_proxy=False (Caido control plane: preflight
        identity / caido_auth / caido_sitemap) is NOT blocked — POST reaches
        aiohttp normally."""
        with patch(
            "src.core.config.settings.get_settings",
            return_value=self._settings_mock(True),
        ):
            client = AsyncNetworkClient(mode="ctf")
            client._session = mock_session

            resp = await client.request(
                "POST", "http://test.com", use_proxy=False, use_cache=False
            )

            assert resp.status == 200
            assert mock_session.request.called

    @pytest.mark.asyncio
    @pytest.mark.parametrize("method", ["GET", "HEAD"])
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_get_head_allowed_when_flag_on(self, mock_proxy_check, mock_start, mock_session, method):
        """(b) Flag ON: GET/HEAD still go through normally."""
        with patch(
            "src.core.config.settings.get_settings",
            return_value=self._settings_mock(True),
        ):
            client = AsyncNetworkClient(mode="ctf")
            client._session = mock_session

            resp = await client.request(
                method, "http://test.com", use_proxy=False, use_cache=False
            )

            assert resp.status == 200
            assert mock_session.request.called

    @pytest.mark.asyncio
    @patch("src.core.infra.network_client.AsyncNetworkClient.start", new_callable=AsyncMock)
    @patch("src.core.infra.network_client.AsyncNetworkClient._check_proxy_reachable", return_value=True)
    async def test_patch_allowed_when_flag_off(self, mock_proxy_check, mock_start, mock_session):
        """(c) Flag OFF (default): PATCH sends exactly as before (no
        regression / byte-identical behavior)."""
        with patch(
            "src.core.config.settings.get_settings",
            return_value=self._settings_mock(False),
        ):
            client = AsyncNetworkClient(mode="ctf")
            client._session = mock_session

            resp = await client.request(
                "PATCH", "http://test.com", use_proxy=False, use_cache=False
            )

            assert resp.status == 200
            assert mock_session.request.called
