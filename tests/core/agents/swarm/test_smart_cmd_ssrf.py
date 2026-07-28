import pytest
from unittest.mock import AsyncMock, patch

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.smart_cmd_ssrf import SmartCmdSSRFHunter


@pytest.mark.asyncio
async def test_execute_returns_finding_with_metadata_when_vulnerable():
    hunter = SmartCmdSSRFHunter(config={"model": "test-model"})
    hunter.run_as_tool = AsyncMock(return_value={
        "vulnerable": True,
        "vuln_type": "cmd",
        "param": "cmd",
        "description": "Command Injection/SSRF detected.",
        "evidence": "uid=0(root)",
        "payloads_used": ["; id", "; sleep 5"],
        "blind_correlation": {
            "time_based": {"confirmed": True, "observed_latency_seconds": 5.0},
            "oob": {"confirmed": False, "hits": []},
            "correlated": False,
        },
        "command_execution_evidence": {
            "timing_confirmed": True,
            "payload_latency_seconds": 5.0,
        },
        "delivery_evidence": {
            "request_method": "GET",
            "request_url": "http://example.com/api?cmd=%3B+sleep+5",
            "response_status": 200,
            "response_body": "ok",
            "poc_request": "GET /api?cmd=%3B+sleep+5 HTTP/1.1\nHost: example.com",
            "poc_response": "HTTP/1.1 200\n\nok",
            "delivered": True,
        },
    })

    task = Task(id="cmd-vuln", name="cmd", target="http://example.com/api?cmd=test", params={"cmd": "test"})
    findings = await hunter.execute(task)

    assert len(findings) == 1
    assert findings[0].vuln_type.value == "os_command_injection"
    assert findings[0].additional_info.get("tested_params") == ["cmd"]
    assert findings[0].additional_info.get("blind_correlation", {}).get("time_based", {}).get("confirmed") is True
    assert findings[0].additional_info.get("command_execution_evidence", {}).get("timing_confirmed") is True
    assert findings[0].additional_info.get("poc_request", "").startswith("GET /api")


@pytest.mark.asyncio
async def test_execute_returns_empty_when_safe():
    hunter = SmartCmdSSRFHunter(config={"model": "test-model"})
    hunter.run_as_tool = AsyncMock(return_value={"vulnerable": False, "description": "No issues"})

    task = Task(id="cmd-safe", name="cmd", target="http://example.com/api?cmd=test", params={"cmd": "test"})
    findings = await hunter.execute(task)

    assert findings == []


@pytest.mark.asyncio
async def test_execute_timeout_preserves_untested_command_parameter_metadata():
    """timeout は安全判定ではなく、候補parameter付きの未判定として残す。"""
    hunter = SmartCmdSSRFHunter(config={"model": "test-model"})

    async def never_returns(*_args, **_kwargs):
        await __import__("asyncio").sleep(60)

    hunter.run_as_tool = never_returns

    task = Task(id="cmd-timeout", name="cmd", target="http://example.com/vulnerabilities/exec/", params={})
    hunter_timeout = 0.01
    original_wait_for = __import__("asyncio").wait_for

    async def short_wait_for(awaitable, timeout):
        return await original_wait_for(awaitable, timeout=hunter_timeout)

    from unittest.mock import patch
    with patch("src.core.agents.swarm.injection.smart_cmd_ssrf.asyncio.wait_for", side_effect=short_wait_for):
        findings = await hunter.execute(task, quick_mode=True)

    assert findings == []
    assert hunter.last_tested_params == ["ip", "host", "cmd", "command"]
    assert hunter.last_delivery_evidence["delivery_state"] == "timeout"
    assert hunter.last_delivery_evidence["reason_code"] == "probe_timeout"


@pytest.mark.asyncio
async def test_run_as_tool_prioritizes_exec_candidates_and_keeps_delivery_evidence():
    """関連のない発見済みパラメータより、対象画面の候補を先に実送信する。"""
    hunter = SmartCmdSSRFHunter(config={"model": "test-model"})

    async def fake_send(payload):
        return {
            "status": 200,
            "diff": "cmd_injection_found" if payload == "127.0.0.1&&id" else "normal",
            "body_snippet": "uid=33(www-data)" if payload == "127.0.0.1&&id" else "ping output",
            "request_method": "GET",
            "request_url": f"http://target.test/vulnerabilities/exec/?ip={payload}",
            "poc_request": f"GET /vulnerabilities/exec/?ip={payload} HTTP/1.1",
            "poc_response": "HTTP/1.1 200\n\nuid=33(www-data)",
            "content_type": "text/html",
            "body_length": 17,
            "elapsed_seconds": 0.01,
        }

    hunter._send_request = fake_send

    from unittest.mock import AsyncMock, patch
    with patch(
        "src.core.agents.swarm.injection.smart_cmd_ssrf._fetch_and_parse_form",
        new=AsyncMock(return_value=[]),
    ):
        result = await hunter.run_as_tool(
            "http://target.test/vulnerabilities/exec/",
            {"page": "x", "redirect": "x", "id": "1", "doc": "x", "security": "medium"},
        )

    assert result["vulnerable"] is True
    assert result["tested_params"][:4] == ["ip", "host", "cmd", "command"]
    assert result["delivery_evidence"]["request_url"].startswith(
        "http://target.test/vulnerabilities/exec/?ip="
    )
    assert result["delivery_evidence"]["response_status"] == 200
    assert result["delivery_evidence"]["delivered"] is True


@pytest.mark.asyncio
async def test_run_as_tool_uses_observed_form_fields_as_the_post_body_contract():
    """実フォームが取れた場合、上流の候補値をPoC本文へ混入させない。"""
    hunter = SmartCmdSSRFHunter(config={"model": "test-model"})
    observed_context = {}

    async def capture_precheck(_tested_params):
        observed_context.update(hunter.context)
        return {"confirmed": False}

    hunter.run_loop = AsyncMock(return_value={"status": "safe"})
    with (
        patch(
            "src.core.agents.swarm.injection.smart_cmd_ssrf._fetch_and_parse_form",
            new=AsyncMock(return_value=[{
                "method": "POST",
                "inputs": [
                    {"name": "ip", "value": "127.0.0.1"},
                    {"name": "Submit", "value": "Submit"},
                ],
            }]),
        ),
        patch.object(
            SmartCmdSSRFHunter,
            "_run_cmd_deterministic_precheck",
            new=AsyncMock(side_effect=capture_precheck),
        ),
    ):
        result = await hunter.run_as_tool(
            "http://target.test/command/",
            {"page": "1", "redirect": "next", "id": "7", "ip": "stale"},
        )

    assert result["tested_params"] == ["ip"]
    assert observed_context["method"] == "POST"
    assert observed_context["params"] == {"ip": "127.0.0.1", "Submit": "Submit"}


@pytest.mark.asyncio
async def test_run_as_tool_stops_when_execution_safeguard_blocks_post_delivery():
    """HITL未承認のPOSTはLLMの再試行に進まず、未判定理由を返す。"""
    hunter = SmartCmdSSRFHunter(config={"model": "test-model"})
    hunter._send_request = AsyncMock(return_value={
        "status": 0,
        "diff": "blocked",
        "body_snippet": "Blocked: Blocked by ExecutionSafeguard: hitl_endpoint_denied",
        "request_method": "POST",
        "request_url": "http://target.test/vulnerabilities/exec/",
        "poc_request": "POST /vulnerabilities/exec/ HTTP/1.1",
        "poc_response": "HTTP/1.1 0",
        "content_type": "",
        "body_length": 0,
        "elapsed_seconds": 0.01,
    })
    hunter.run_loop = AsyncMock(return_value={"status": "should_not_run"})

    with patch(
        "src.core.agents.swarm.injection.smart_cmd_ssrf._fetch_and_parse_form",
        new=AsyncMock(return_value=[{"method": "POST", "inputs": [{"name": "ip", "value": ""}]}]),
    ):
        result = await hunter.run_as_tool(
            "http://target.test/vulnerabilities/exec/",
            {},
        )

    assert result["vulnerable"] is False
    assert result["reason_code"] == "hitl_endpoint_denied"
    assert result["delivery_evidence"]["request_method"] == "POST"
    assert result["delivery_evidence"]["delivered"] is False
    hunter.run_loop.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_as_tool_initializes_tested_params_and_blind_correlation():
    hunter = SmartCmdSSRFHunter(config={"model": "test-model"})
    hunter.run_loop = AsyncMock(return_value={"status": "done"})

    result = await hunter.run_as_tool("http://example.com/fetch?url=a", params={"url": "a"})

    assert result["tested_params"] == ["url"]
    assert "blind_correlation" in result
    assert result["blind_correlation"]["time_based"]["confirmed"] is False


def test_record_blind_signal_confirms_time_based_delay():
    hunter = SmartCmdSSRFHunter(config={"model": "test-model"})
    hunter.blind_correlation = {
        "time_based": {"confirmed": False},
        "oob": {"confirmed": False, "hits": []},
        "correlated": False,
    }

    hunter._record_blind_signal("; sleep 5", {"elapsed_seconds": 5.4})

    assert hunter.blind_correlation["time_based"]["confirmed"] is True
    assert hunter.blind_correlation["time_based"]["observed_latency_seconds"] == 5.4


@pytest.mark.asyncio
async def test_cmd_deterministic_timing_precheck_records_three_series_samples():
    hunter = SmartCmdSSRFHunter(config={"model": "test-model", "mode": "ctf"})
    hunter.context = {
        "target": "http://example.com/vulnerabilities/exec/?ip=127.0.0.1",
        "param": "ip",
        "method": "GET",
        "params": {"ip": "127.0.0.1"},
        "auth_headers": {},
        "execution_profile": {},
    }

    async def fake_send(payload: str):
        if "sleep" in payload:
            return {
                "status": 200,
                "diff": "normal",
                "body_snippet": "ping output",
                "elapsed_seconds": 6.1,
                "request_method": "GET",
                "request_url": "http://example.com/vulnerabilities/exec/?ip=127.0.0.1%3Bsleep+3",
                "poc_request": "GET /vulnerabilities/exec/?ip=127.0.0.1%3Bsleep+3 HTTP/1.1\nHost: example.com",
                "poc_response": "HTTP/1.1 200\n\nping output",
                "body_length": 11,
            }
        return {
            "status": 200,
            "diff": "normal",
            "body_snippet": "ping output",
            "elapsed_seconds": 3.0,
            "request_method": "GET",
            "request_url": "http://example.com/vulnerabilities/exec/?ip=127.0.0.1",
            "poc_request": "GET /vulnerabilities/exec/?ip=127.0.0.1 HTTP/1.1\nHost: example.com",
            "poc_response": "HTTP/1.1 200\n\nping output",
            "body_length": 11,
        }

    hunter._send_request = fake_send

    result = await hunter._run_cmd_deterministic_precheck(["ip"])

    assert result["confirmed"] is True
    timing_samples = result["blind_correlation"]["timing_samples"]
    assert len(timing_samples["baseline"]) == 3
    assert len(timing_samples["sleep"]) == 3
    assert len(timing_samples["inverse_condition"]) == 1
    assert result["command_execution_evidence"]["timing_confirmed"] is True
    assert result["delivery_evidence"]["poc_request"].startswith("GET /vulnerabilities/exec/")


def test_record_dns_signal_confirms_dns_and_updates_hits():
    hunter = SmartCmdSSRFHunter(config={"model": "test-model"})
    hunter.blind_correlation = {
        "time_based": {"confirmed": False},
        "oob": {"confirmed": False, "hits": []},
        "dns": {"confirmed": False, "hits": []},
        "correlated": False,
    }

    hunter._record_dns_signal(
        "http://127.0.0.1.nip.io/",
        {"status": 200, "diff": "ssrf_found", "body_snippet": "metadata proxy"},
    )

    assert hunter.blind_correlation["dns"]["confirmed"] is True
    assert hunter.blind_correlation["dns"]["hits"]


def test_recompute_blind_correlation_uses_two_of_three():
    hunter = SmartCmdSSRFHunter(config={"model": "test-model"})
    hunter.blind_correlation = {
        "time_based": {"confirmed": True},
        "oob": {"confirmed": False, "hits": []},
        "dns": {"confirmed": True, "hits": [{"payload": "http://127.0.0.1.nip.io/"}]},
        "correlated": False,
    }

    hunter._recompute_blind_correlation()

    assert hunter.blind_correlation["correlated"] is True
