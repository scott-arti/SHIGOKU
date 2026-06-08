import pytest
from unittest.mock import AsyncMock

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
    })

    task = Task(id="cmd-vuln", name="cmd", target="http://example.com/api?cmd=test", params={"cmd": "test"})
    findings = await hunter.execute(task)

    assert len(findings) == 1
    assert findings[0].vuln_type.value == "os_command_injection"
    assert findings[0].additional_info.get("tested_params") == ["cmd"]
    assert findings[0].additional_info.get("blind_correlation", {}).get("time_based", {}).get("confirmed") is True


@pytest.mark.asyncio
async def test_execute_returns_empty_when_safe():
    hunter = SmartCmdSSRFHunter(config={"model": "test-model"})
    hunter.run_as_tool = AsyncMock(return_value={"vulnerable": False, "description": "No issues"})

    task = Task(id="cmd-safe", name="cmd", target="http://example.com/api?cmd=test", params={"cmd": "test"})
    findings = await hunter.execute(task)

    assert findings == []


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
