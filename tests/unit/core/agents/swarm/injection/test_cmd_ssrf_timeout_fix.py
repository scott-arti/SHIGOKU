"""Unit tests for cmd_ssrf timeout fixes.

Covers:
- _collect_recent_tested_params cmd_ssrf branch
- PER_URL_TIMEOUT_BY_TYPE["cmd_ssrf"] == 300
- _run_cmd_deterministic_precheck timeout wrapper
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Test 1: _collect_recent_tested_params cmd_ssrf branch
# ---------------------------------------------------------------------------

class TestCollectRecentTestedParamsCmdSSRF:
    def test_cmd_ssrf_branch_returns_params(self):
        """Verify cmd_ssrf branch reads from specialist.last_tested_params."""
        from src.core.agents.swarm.injection.manager import InjectionManagerAgent

        manager = InjectionManagerAgent()

        # Set up a mock specialist with last_tested_params
        mock_specialist = MagicMock()
        mock_specialist.last_tested_params = ["ip", "target", "cmd"]
        manager.specialists["cmd_ssrf"] = mock_specialist

        result = manager._collect_recent_tested_params("cmd_ssrf")
        assert result == ["ip", "target", "cmd"]

    def test_cmd_ssrf_branch_no_specialist_returns_empty(self):
        """When cmd_ssrf specialist not registered, returns []."""
        from src.core.agents.swarm.injection.manager import InjectionManagerAgent

        manager = InjectionManagerAgent()
        # No specialist registered for cmd_ssrf
        result = manager._collect_recent_tested_params("cmd_ssrf")
        assert result == []

    def test_cmd_ssrf_branch_empty_params_returns_empty(self):
        """When last_tested_params is empty, returns []."""
        from src.core.agents.swarm.injection.manager import InjectionManagerAgent

        manager = InjectionManagerAgent()
        mock_specialist = MagicMock()
        mock_specialist.last_tested_params = []
        manager.specialists["cmd_ssrf"] = mock_specialist

        result = manager._collect_recent_tested_params("cmd_ssrf")
        assert result == []

    def test_sqli_branch_still_works(self):
        """Regression: sqli branch still combines sqli + xss params."""
        from src.core.agents.swarm.injection.manager import InjectionManagerAgent

        manager = InjectionManagerAgent()
        manager.specialists["sqli"] = MagicMock(last_tested_params=["id", "user"])
        manager.specialists["xss"] = MagicMock(last_tested_params=["q", "search"])

        result = manager._collect_recent_tested_params("sqli")
        # sqli branch merges sqli + xss
        assert "id" in result
        assert "user" in result
        assert "q" in result
        assert "search" in result


# ---------------------------------------------------------------------------
# Test 2: PER_URL_TIMEOUT_BY_TYPE["cmd_ssrf"] == 300
# ---------------------------------------------------------------------------

class TestPerUrlTimeoutCmdSSRF:
    def test_cmd_ssrf_timeout_is_300(self):
        from src.core.agents.swarm.injection.manager import InjectionManagerAgent

        assert InjectionManagerAgent.PER_URL_TIMEOUT_BY_TYPE["cmd_ssrf"] == 300

    def test_other_timeouts_unchanged(self):
        from src.core.agents.swarm.injection.manager import InjectionManagerAgent

        t = InjectionManagerAgent.PER_URL_TIMEOUT_BY_TYPE
        assert t["sqli"] == 180
        assert t["xss"] == 210
        assert t["lfi"] == 120
        assert t["ssrf"] == 180


# ---------------------------------------------------------------------------
# Test 3: precheck timeout wrapper
# ---------------------------------------------------------------------------

FORM_HARVESTER_PATH = (
    "src.core.agents.swarm.injection.smart_cmd_ssrf._fetch_and_parse_form"
)


class TestPrecheckTimeoutWrapper:
    @staticmethod
    async def _fake_precheck(_params: list) -> dict:
        return {"confirmed": False}

    @pytest.mark.asyncio
    async def test_precheck_timeout_catches_TimeoutError(self):
        """When asyncio.wait_for raises TimeoutError, precheck returns
        {'confirmed': False} instead of propagating the exception."""
        from src.core.agents.swarm.injection.smart_cmd_ssrf import SmartCmdSSRFHunter

        hunter = SmartCmdSSRFHunter()

        hunter._build_auth_headers = MagicMock(return_value={})
        hunter._extract_execution_profile = MagicMock(return_value={})
        hunter._is_attack_param = MagicMock(return_value=True)
        hunter.last_tested_params = []

        # Patch wait_for to raise TimeoutError immediately
        with patch(FORM_HARVESTER_PATH, AsyncMock(return_value=[])), \
             patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
            result = await hunter.run_as_tool(
                "http://127.0.0.1/vulns/exec/",
                {"ip": "127.0.0.1", "method": "GET", "_auth": {}},
            )

        # Timeout should NOT crash the function; result indicates no vuln found
        assert result.get("vulnerable") is False

    @pytest.mark.asyncio
    async def test_precheck_timeout_uses_60s(self):
        """Verify asyncio.wait_for is called with timeout=60."""
        from src.core.agents.swarm.injection.smart_cmd_ssrf import SmartCmdSSRFHunter

        hunter = SmartCmdSSRFHunter()

        hunter._build_auth_headers = MagicMock(return_value={})
        hunter._extract_execution_profile = MagicMock(return_value={})
        hunter._is_attack_param = MagicMock(return_value=True)
        hunter.last_tested_params = []

        # Use a real asyncio.wait_for wrapper that records the timeout value
        captured_timeout = []

        async def _fake_wait_for(coro, **kwargs):
            captured_timeout.append(kwargs.get("timeout"))
            return await coro

        with patch(FORM_HARVESTER_PATH, AsyncMock(return_value=[])), \
             patch("asyncio.wait_for", side_effect=_fake_wait_for), \
             patch.object(
                hunter,
                "_run_cmd_deterministic_precheck",
                new=AsyncMock(return_value={"confirmed": False}),
            ):
            await hunter.run_as_tool(
                "http://127.0.0.1/vulns/exec/",
                {"ip": "127.0.0.1", "method": "GET", "_auth": {}},
            )

        assert len(captured_timeout) == 1
        assert captured_timeout[0] == 60

    @pytest.mark.asyncio
    async def test_precheck_completes_normally_when_fast(self):
        """When precheck completes quickly, result is used normally."""
        from src.core.agents.swarm.injection.smart_cmd_ssrf import SmartCmdSSRFHunter

        hunter = SmartCmdSSRFHunter()

        hunter._build_auth_headers = MagicMock(return_value={})
        hunter._extract_execution_profile = MagicMock(return_value={})
        hunter._is_attack_param = MagicMock(return_value=True)
        hunter.last_tested_params = []

        with patch(FORM_HARVESTER_PATH, AsyncMock(return_value=[])), \
             patch.object(
                hunter,
                "_run_cmd_deterministic_precheck",
                side_effect=self._fake_precheck,
            ):
            result = await hunter.run_as_tool(
                "http://127.0.0.1/vulns/exec/",
                {"ip": "127.0.0.1", "method": "GET", "_auth": {}},
            )

        assert result.get("vulnerable") is False
