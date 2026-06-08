import socket
import time
from urllib.parse import parse_qsl, urlparse
from unittest.mock import AsyncMock, patch

import pytest

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.smart_ssrf import SmartSSRFHunter
from src.core.attack.ssrf_tester import SSRFResult, SSRFPayloadType, SSRFTester
from src.core.models.finding import Severity, VulnType


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _ssrf_result(**kwargs) -> SSRFResult:
    base = dict(
        url="http://target.test/fetch",
        parameter="url",
        payload="http://169.254.169.254/latest/meta-data/",
        payload_type=SSRFPayloadType.CLOUD_METADATA,
        vulnerable=True,
        response_code=200,
        response_length=120,
        evidence="ami-id: i-123",
        severity="high",
        matched_variant="169.254.169.254",
        matched_variant_source="bypass_variant",
    )
    base.update(kwargs)
    return SSRFResult(**base)


@pytest.fixture(scope="module")
def ssrf_server():
    from tests.helpers.ssrf_flask_target import start_ssrf_server, FLASK_PORT

    start_ssrf_server(FLASK_PORT)
    if not _wait_for_port("127.0.0.1", FLASK_PORT):
        pytest.skip("SSRF Flask target failed to start")
    yield f"http://127.0.0.1:{FLASK_PORT}"


class TestSmartSSRFHunterUnit:
    @pytest.mark.asyncio
    async def test_execute_returns_finding_when_vulnerable(self):
        hunter = SmartSSRFHunter()
        with patch.object(SSRFTester, "scan_async", new=AsyncMock(return_value=[_ssrf_result()])):
            task = Task(id="t1", name="ssrf", target="http://target.test/fetch?url=x", params={"url": "x"})
            findings = await hunter.execute(task)
        assert len(findings) == 1
        assert findings[0].vuln_type == VulnType.SSRF
        assert findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_execute_returns_empty_when_safe(self):
        hunter = SmartSSRFHunter()
        with patch.object(SSRFTester, "scan_async", new=AsyncMock(return_value=[])):
            task = Task(id="t2", name="ssrf", target="http://target.test/safe", params={})
            findings = await hunter.execute(task)
        assert findings == []

    @pytest.mark.asyncio
    async def test_run_as_tool_shape(self):
        hunter = SmartSSRFHunter()
        with patch.object(SSRFTester, "scan_async", new=AsyncMock(return_value=[_ssrf_result()])):
            result = await hunter.run_as_tool("http://target.test/fetch?url=x", {"url": "x"})
        for key in ("vulnerable", "findings_count", "tested_params", "payload_type", "payload", "evidence", "response_code", "matched_variant", "matched_variant_source"):
            assert key in result

    @pytest.mark.asyncio
    async def test_finding_has_poc_fields(self):
        hunter = SmartSSRFHunter()
        with patch.object(SSRFTester, "scan_async", new=AsyncMock(return_value=[_ssrf_result()])):
            task = Task(id="t3", name="ssrf", target="http://target.test/fetch?url=x", params={"url": "x"})
            findings = await hunter.execute(task)
        info = findings[0].additional_info
        assert "poc_request" in info and "poc_response" in info and "poc_html" in info
        assert info.get("matched_variant") != ""

    @pytest.mark.asyncio
    async def test_run_as_tool_applies_safe_variation_headers(self):
        hunter = SmartSSRFHunter()
        captured = {}

        async def _capture_scan(self, url, parameters, auth_headers=None):
            captured["auth_headers"] = dict(self.auth_headers)
            return [_ssrf_result()]

        with patch.object(SSRFTester, "scan_async", new=_capture_scan):
            result = await hunter.run_as_tool(
                "http://target.test/fetch?url=x",
                {
                    "url": "x",
                    "_auth": {"auth_headers": {"Authorization": "Bearer test"}},
                    "safe_variations": [
                        {
                            "mutation_type": "encode",
                            "headers": {"X-Forwarded-For": "127.0.0.1"},
                        }
                    ],
                },
            )

        assert captured["auth_headers"]["Authorization"] == "Bearer test"
        assert captured["auth_headers"]["X-Forwarded-For"] == "127.0.0.1"
        assert result["execution_profile"]["applied_mutation_types"] == ["encode"]

    @pytest.mark.asyncio
    async def test_execute_carries_execution_profile_into_finding(self):
        hunter = SmartSSRFHunter()
        with patch.object(SSRFTester, "scan_async", new=AsyncMock(return_value=[_ssrf_result()])):
            task = Task(
                id="t4",
                name="ssrf",
                target="http://target.test/fetch?url=x",
                params={
                    "url": "x",
                    "race_profile": {"mode": "burst", "order_permutations": 2},
                    "safe_variations": [
                        {"mutation_type": "encode", "headers": {"X-Forwarded-For": "127.0.0.1"}}
                    ],
                },
            )
            findings = await hunter.execute(task)

        profile = findings[0].additional_info.get("execution_profile", {})
        assert profile["race_profile"]["mode"] == "burst"
        assert profile["applied_mutation_types"] == ["encode"]

    @pytest.mark.asyncio
    async def test_run_as_tool_interval_profile_retries_with_reordered_parameters(self):
        hunter = SmartSSRFHunter()
        captured_parameters = []

        async def _capture_scan(self, url, parameters, auth_headers=None):
            captured_parameters.append(list(parameters))
            if len(captured_parameters) == 1:
                return []
            return [_ssrf_result(parameter=parameters[0])]

        with (
            patch.object(SSRFTester, "scan_async", new=_capture_scan),
            patch("asyncio.sleep", new=AsyncMock()) as sleep_mock,
        ):
            result = await hunter.run_as_tool(
                "http://target.test/fetch?url=x&next=/home",
                {
                    "url": "x",
                    "next": "/home",
                    "race_profile": {"mode": "interval", "interval": 0.05, "order_permutations": 2},
                },
            )

        assert result["vulnerable"] is True
        assert result["race_attempts"] == 2
        assert sleep_mock.await_count == 1
        assert captured_parameters[0][0] == "url"
        assert captured_parameters[1][0] == "next"

    @pytest.mark.asyncio
    async def test_run_as_tool_burst_profile_stops_on_first_match_without_sleep(self):
        hunter = SmartSSRFHunter()
        captured_parameters = []

        async def _capture_scan(self, url, parameters, auth_headers=None):
            captured_parameters.append(list(parameters))
            return [_ssrf_result(parameter=parameters[0])]

        with (
            patch.object(SSRFTester, "scan_async", new=_capture_scan),
            patch("asyncio.sleep", new=AsyncMock()) as sleep_mock,
        ):
            result = await hunter.run_as_tool(
                "http://target.test/fetch?url=x&next=/home",
                {
                    "url": "x",
                    "next": "/home",
                    "race_profile": {"mode": "burst", "burst": 3, "order_permutations": 3},
                },
            )

        assert result["vulnerable"] is True
        assert result["race_attempts"] == 1
        assert len(captured_parameters) == 1
        assert sleep_mock.await_count == 0


@pytest.mark.integration
class TestSmartSSRFHunterIntegration:
    @pytest.mark.asyncio
    async def test_ssrf_scanner_detects_cloud_metadata_indicator(self, ssrf_server):
        hunter = SmartSSRFHunter()
        result = await hunter.run_as_tool(f"{ssrf_server}/fetch?url=x", {"url": "x"})
        assert result["vulnerable"] is True
        assert result["findings_count"] >= 1

    @pytest.mark.asyncio
    async def test_ssrf_scanner_no_false_positive_on_safe(self, ssrf_server):
        hunter = SmartSSRFHunter()
        result = await hunter.run_as_tool(f"{ssrf_server}/safe", {})
        assert result["vulnerable"] is False
