from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qsl, urlparse

import pytest

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.smart_cmd_ssrf import SmartCmdSSRFHunter


class TestSmartCmdSsrfMetadata:
    @pytest.mark.asyncio
    async def test_run_as_tool_applies_safe_variation_headers(self):
        hunter = SmartCmdSSRFHunter(config={"model": "test-model"})

        with (
            patch(
                "src.core.agents.swarm.injection.smart_cmd_ssrf._fetch_and_parse_form",
                new=AsyncMock(return_value=[]),
            ),
            patch.object(
                SmartCmdSSRFHunter,
                "_run_cmd_deterministic_precheck",
                new=AsyncMock(return_value={"confirmed": False}),
            ),
            patch.object(
                SmartCmdSSRFHunter,
                "run_loop",
                new=AsyncMock(return_value={"status": "safe"}),
            ),
        ):
            result = await hunter.run_as_tool(
                "http://target.test/ping?host=1",
                {
                    "host": "1",
                    "_auth": {"auth_headers": {"Authorization": "Bearer test"}},
                    "safe_variations": [
                        {
                            "mutation_type": "encode",
                            "headers": {"X-Forwarded-For": "127.0.0.1"},
                        }
                    ],
                    "race_profile": {"mode": "burst", "order_permutations": 2},
                },
            )

        assert hunter.context["auth_headers"]["Authorization"] == "Bearer test"
        assert hunter.context["auth_headers"]["X-Forwarded-For"] == "127.0.0.1"
        assert result["execution_profile"]["race_profile"]["mode"] == "burst"
        assert result["execution_profile"]["applied_mutation_types"] == ["encode"]

    @pytest.mark.asyncio
    async def test_execute_carries_execution_profile_into_finding(self):
        hunter = SmartCmdSSRFHunter(config={"model": "test-model"})
        task = Task(
            id="cmd-meta",
            name="cmd-meta",
            target="http://target.test/ping?host=1",
            params={
                "host": "1",
                "race_profile": {"mode": "interval", "order_permutations": 1},
                "safe_variations": [
                    {
                        "mutation_type": "case",
                        "headers": {"X-Originating-IP": "127.0.0.1"},
                    }
                ],
            },
        )

        with patch.object(
            SmartCmdSSRFHunter,
            "run_as_tool",
            new=AsyncMock(
                return_value={
                    "vulnerable": True,
                    "param": "host",
                    "tested_params": ["host"],
                    "payloads_used": ["127.0.0.1|id"],
                    "blind_correlation": {},
                    "description": "detected",
                    "vuln_type": "cmd",
                    "execution_profile": {
                        "race_profile": {"mode": "interval", "order_permutations": 1},
                        "applied_mutation_types": ["case"],
                        "applied_header_keys": ["X-Originating-IP"],
                    },
                }
            ),
        ):
            findings = await hunter.execute(task)

        profile = findings[0].additional_info.get("execution_profile", {})
        assert profile["race_profile"]["mode"] == "interval"
        assert profile["applied_mutation_types"] == ["case"]

    @pytest.mark.asyncio
    async def test_send_request_interval_profile_retries_with_param_reordering(self):
        hunter = SmartCmdSSRFHunter(config={"model": "test-model"})
        hunter.context = {
            "target": "http://target.test/ping?host=1&next=/home",
            "param": "host",
            "method": "GET",
            "params": {"host": "1", "next": "/home"},
            "auth_headers": {},
            "execution_profile": {
                "race_profile": {
                    "mode": "interval",
                    "interval": 0.05,
                    "order_permutations": 2,
                }
            },
        }

        requested_urls = []

        async def _fake_request(method, url, headers=None, timeout=None, data=None):
            requested_urls.append(url)
            if len(requested_urls) == 1:
                return {"status": 200, "body": "normal page"}
            return {"status": 200, "body": "metadata aws 169.254"}

        hunter.smart_client.request = AsyncMock(side_effect=_fake_request)

        with patch("src.core.agents.swarm.injection.smart_cmd_ssrf.asyncio.sleep", new=AsyncMock()) as sleep_mock:
            result = await hunter._send_request("PAYLOAD")

        assert result["diff"] == "ssrf_found"
        assert result["race_attempts"] == 2
        assert sleep_mock.await_count == 1
        first_query = parse_qsl(urlparse(requested_urls[0]).query, keep_blank_values=True)
        second_query = parse_qsl(urlparse(requested_urls[1]).query, keep_blank_values=True)
        assert first_query[0][0] == "host"
        assert second_query[0][0] == "next"

    @pytest.mark.asyncio
    async def test_send_request_burst_profile_stops_on_first_match_without_sleep(self):
        hunter = SmartCmdSSRFHunter(config={"model": "test-model"})
        hunter.context = {
            "target": "http://target.test/ping?host=1&next=/home",
            "param": "host",
            "method": "GET",
            "params": {"host": "1", "next": "/home"},
            "auth_headers": {},
            "execution_profile": {
                "race_profile": {
                    "mode": "burst",
                    "burst": 3,
                    "order_permutations": 3,
                }
            },
        }

        hunter.smart_client.request = AsyncMock(return_value={"status": 200, "body": "uid=1000(www-data)"})

        with patch("src.core.agents.swarm.injection.smart_cmd_ssrf.asyncio.sleep", new=AsyncMock()) as sleep_mock:
            result = await hunter._send_request("PAYLOAD")

        assert result["diff"] == "cmd_injection_found"
        assert result["race_attempts"] == 1
        assert sleep_mock.await_count == 0
