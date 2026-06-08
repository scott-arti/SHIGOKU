import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.agents.swarm.injection.manager import InjectionManagerAgent


class TestRunAdminCheckCharacter:
    """run_admin_check の外側挙動を固定するキャラクターテスト。

    抽出時に実バグ2件（target→target_url, title欠落）を修正。
    """

    @pytest.fixture
    def agent(self) -> InjectionManagerAgent:
        agent = InjectionManagerAgent(config={"model": "test-model"})
        agent.current_context = {"findings": []}
        return agent

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
    async def test_non_admin_path_returns_early(self, agent: InjectionManagerAgent) -> None:
        result = await agent.run_admin_check(
            url="http://example.com/api/health",
            params={},
        )
        assert result["findings_count"] == 0
        assert result["tested_params"] == []
        assert result["findings_list"] == []

    @pytest.mark.asyncio
    async def test_admin_path_non_prefix_returns_early(self, agent: InjectionManagerAgent) -> None:
        result = await agent.run_admin_check(
            url="http://example.com/admin/users",
            params={},
        )
        assert result["findings_count"] == 0

    @pytest.mark.asyncio
    async def test_admin_path_404_all_no_findings(self, agent: InjectionManagerAgent) -> None:
        responses = [self._build_resp(404, "Not Found") for _ in range(8)]
        session = self._build_session(responses)

        with patch("aiohttp.ClientSession", return_value=session):
            result = await agent.run_admin_check(
                url="http://example.com/rest/admin/config",
                params={},
            )

        assert result["findings_count"] == 0
        assert result["tested_params"] == ["authorization"]

    @pytest.mark.asyncio
    async def test_admin_path_200_with_application_creates_finding(self, agent: InjectionManagerAgent) -> None:
        body = "application configuration settings data test" * 5
        responses = [self._build_resp(200, body) for _ in range(8)]
        session = self._build_session(responses)

        with patch("aiohttp.ClientSession", return_value=session):
            result = await agent.run_admin_check(
                url="http://example.com/rest/admin/config",
                params={"auth_headers": {"Authorization": "Bearer x"}},
            )

        assert result["findings_count"] >= 1
        assert "authorization" in result["tested_params"]
        assert len(agent.current_context["findings"]) >= 1

    @pytest.mark.asyncio
    async def test_admin_path_timeout_handled_gracefully(self, agent: InjectionManagerAgent) -> None:
        async def _timeout():
            raise asyncio.TimeoutError()

        responses = []
        for _ in range(8):
            r = self._build_resp(200, "ok")
            r.text = _timeout
            responses.append(r)
        session = self._build_session(responses)

        with patch("aiohttp.ClientSession", return_value=session):
            result = await agent.run_admin_check(
                url="http://example.com/rest/admin/config",
                params={},
            )

        assert result["findings_count"] == 0
        assert result["tested_params"] == ["authorization"]
