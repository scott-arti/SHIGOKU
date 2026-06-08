import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.agents.swarm.injection.manager_internal.admin_check import run_admin_check


class TestAdminCheckUnit:
    """run_admin_check 抽出関数の単体テスト。"""

    def _build_resp(self, status, body):
        class _Resp:
            def __init__(self, status, body):
                self.status = status
                self._body = body
                self.headers = {}
            async def text(self):
                return self._body
            async def __aenter__(self):
                return self
            async def __aexit__(self, *a):
                pass
        return _Resp(status, body)

    def _build_session(self, responses):
        it = iter(responses)

        def _req(*a, **kw):
            return next(it)

        session = MagicMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=None)
        session.request = _req
        return session

    @pytest.mark.asyncio
    async def test_non_admin_path_returns_early(self) -> None:
        result = await run_admin_check(
            url="http://example.com/api/health",
            params={},
            findings_sink=[],
        )
        assert result["findings_count"] == 0
        assert result["tested_params"] == []
        assert result["findings_list"] == []

    @pytest.mark.asyncio
    async def test_not_rest_admin_prefix_returns_early(self) -> None:
        result = await run_admin_check(
            url="http://example.com/admin/users",
            params={},
            findings_sink=[],
        )
        assert result["findings_count"] == 0

    @pytest.mark.asyncio
    async def test_all_404_no_findings(self) -> None:
        responses = [self._build_resp(404, "Not Found") for _ in range(8)]
        session = self._build_session(responses)

        with patch("aiohttp.ClientSession", return_value=session):
            result = await run_admin_check(
                url="http://example.com/rest/admin/config",
                params={},
                findings_sink=[],
            )

        assert result["findings_count"] == 0
        assert result["tested_params"] == ["authorization"]

    @pytest.mark.asyncio
    async def test_200_with_application_creates_finding(self) -> None:
        body = "application configuration settings data test" * 5
        responses = [self._build_resp(200, body) for _ in range(8)]
        session = self._build_session(responses)
        sink: list = []

        with patch("aiohttp.ClientSession", return_value=session):
            result = await run_admin_check(
                url="http://example.com/rest/admin/config",
                params={"auth_headers": {"Authorization": "Bearer x"}},
                findings_sink=sink,
            )

        assert result["findings_count"] >= 1
        assert "authorization" in result["tested_params"]
        assert len(sink) >= 1

    @pytest.mark.asyncio
    async def test_write_method_success_creates_finding(self) -> None:
        responses = []
        for _ in range(4):
            responses.append(self._build_resp(401, '{"error":"auth"}'))
        for _ in range(4):
            responses.append(self._build_resp(201, "created"))
        session = self._build_session(responses)
        sink: list = []

        with patch("aiohttp.ClientSession", return_value=session):
            result = await run_admin_check(
                url="http://example.com/rest/admin/config",
                params={},
                findings_sink=sink,
            )

        assert result["findings_count"] > 0
        assert len(sink) > 0

    @pytest.mark.asyncio
    async def test_delete_creates_critical_severity(self) -> None:
        responses = []
        for _ in range(2):
            responses.append(self._build_resp(401, '{"error":"auth"}'))
        for _ in range(2):
            responses.append(self._build_resp(401, '{"error":"auth"}'))
        for _ in range(2):
            responses.append(self._build_resp(401, '{"error":"auth"}'))
        for _ in range(2):
            responses.append(self._build_resp(204, ""))
        session = self._build_session(responses)
        sink: list = []

        with patch("aiohttp.ClientSession", return_value=session):
            result = await run_admin_check(
                url="http://example.com/rest/admin/config",
                params={},
                findings_sink=sink,
            )

        assert result["findings_count"] > 0
        assert sink[0].severity.name == "CRITICAL"

    @pytest.mark.asyncio
    async def test_timeout_handled_gracefully(self) -> None:
        async def _timeout():
            raise asyncio.TimeoutError()

        responses = []
        for _ in range(8):
            r = self._build_resp(200, "ok")
            r.text = _timeout
            responses.append(r)
        session = self._build_session(responses)
        sink: list = []

        with patch("aiohttp.ClientSession", return_value=session):
            result = await run_admin_check(
                url="http://example.com/rest/admin/config",
                params={},
                findings_sink=sink,
            )

        assert result["findings_count"] == 0
        assert result["tested_params"] == ["authorization"]
        assert sink == []

    @pytest.mark.asyncio
    async def test_role_escalation_modifies_url(self) -> None:
        captured_urls = []

        def _capture_req(method, target_url, **kw):
            captured_urls.append(target_url)
            return self._build_resp(403, "forbidden")

        session = MagicMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=None)
        session.request = _capture_req

        with patch("aiohttp.ClientSession", return_value=session):
            await run_admin_check(
                url="http://example.com/rest/admin/config",
                params={},
                findings_sink=[],
            )

        role_urls = [u for u in captured_urls if "role=admin" in u]
        assert len(role_urls) >= 4
