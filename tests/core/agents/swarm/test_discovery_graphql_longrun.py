import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from src.core.agents.swarm.discovery.graphql import GraphQLNavigator


@pytest.mark.asyncio
async def test_longrun_500_success_keeps_runtime_state_healthy():
    nav = GraphQLNavigator(config={"graphql_probe_qps_limit": 100000})
    fake_result = SimpleNamespace(
        introspection_enabled=False,
        graphiql_enabled=False,
        field_suggestions_enabled=False,
        schema=None,
    )
    with patch("src.core.agents.swarm.discovery.graphql.GraphQLAnalyzer.analyze_async", new_callable=AsyncMock) as mock_analyze:
        mock_analyze.return_value = fake_result
        for _ in range(500):
            out = await nav.run_as_tool("http://steady.example/graphql")
            assert out["error_code"] is None

    assert nav._inflight == 0
    assert "steady.example" not in nav._host_failures
    assert "steady.example" not in nav._host_quarantine_until


@pytest.mark.asyncio
async def test_longrun_mixed_hosts_backpressure_and_quarantine_signals():
    nav = GraphQLNavigator(
        config={
            "graphql_probe_parallel_limit": 1,
            "graphql_probe_queue_limit": 0,
            "graphql_probe_qps_limit": 100000,
            "graphql_probe_circuit_breaker_threshold": 1,
            "graphql_probe_quarantine_seconds": 120,
        }
    )
    nav._inflight = 1
    blocked = await nav.run_as_tool("http://slow.example/graphql")
    nav._inflight = 0
    nav._host_failures["bad.example"] = 1
    nav._host_quarantine_until["bad.example"] = 10**12
    quarantined = await nav.run_as_tool("http://bad.example/graphql")

    assert blocked["internal_error_detail"] == "backpressure_rejected"
    assert quarantined["internal_error_detail"] == "host_quarantined"


@pytest.mark.asyncio
async def test_longrun_half_open_recovery_path():
    nav = GraphQLNavigator(config={"graphql_probe_qps_limit": 100000})
    host = "recover.example"
    nav._host_failures[host] = 3
    nav._host_quarantine_until[host] = 1.0
    fake_result = SimpleNamespace(
        introspection_enabled=True,
        graphiql_enabled=False,
        field_suggestions_enabled=False,
        schema=None,
    )
    with patch("src.core.agents.swarm.discovery.graphql.GraphQLAnalyzer.analyze_async", new_callable=AsyncMock) as mock_analyze:
        mock_analyze.return_value = fake_result
        out = await nav.run_as_tool("http://recover.example/graphql")
    assert out["error_code"] is None
    assert host not in nav._host_quarantine_until
