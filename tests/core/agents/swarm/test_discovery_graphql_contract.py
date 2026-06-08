import pytest
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from src.core.agents.swarm.discovery.graphql import GraphQLNavigator
from src.core.agents.swarm.discovery.graphql import GRAPHQL_PROBE_EVENT_REQUIRED_KEYS
from src.core.agents.swarm.discovery.graphql import GRAPHQL_RUNTIME_CONTROL_POLICY_EVENT
from src.core.agents.swarm.discovery.graphql import GRAPHQL_RUNTIME_CONTROL_POLICY_REQUIRED_KEYS
from src.core.agents.swarm.discovery.graphql import GRAPHQL_RUNTIME_CONTROL_SHADOW_DIFF_EVENT
from src.core.agents.swarm.discovery.graphql import GRAPHQL_RUNTIME_CONTROL_SHADOW_DIFF_REQUIRED_KEYS
from src.core.agents.swarm.discovery.manager import DiscoveryManagerAgent
from src.core.agents.swarm.runtime_control_backend import RuntimeControlBackendUnavailable


@pytest.mark.asyncio
async def test_graphql_navigator_returns_contract_shape():
    nav = GraphQLNavigator(config={})
    fake_result = SimpleNamespace(
        introspection_enabled=True,
        graphiql_enabled=False,
        field_suggestions_enabled=True,
        schema=SimpleNamespace(query_type="Query", mutation_type="Mutation", types=[]),
    )
    with patch("src.core.agents.swarm.discovery.graphql.GraphQLAnalyzer.analyze_async", new_callable=AsyncMock) as mock_analyze:
        mock_analyze.return_value = fake_result
        result = await nav.run_as_tool("http://example.test/graphql")

    assert result["contract_version"] == "1.0.0"
    assert result["introspection_enabled"] is True
    assert result["field_suggestions_enabled"] is True
    assert isinstance(result["evidence"], list)
    assert "latency_ms" in result
    assert "error_code" in result
    assert result["error_policy_version"] == "1"


@pytest.mark.asyncio
async def test_graphql_navigator_backpressure_rejection():
    nav = GraphQLNavigator(config={"graphql_probe_parallel_limit": 1, "graphql_probe_queue_limit": 0})
    nav._inflight = 1
    try:
        result = await nav.run_as_tool("http://example.test/graphql")
    finally:
        nav._inflight = 0
    assert result["error_code"] == "connection_error"
    assert result["internal_error_detail"] == "backpressure_rejected"
    assert result["internal_error_category"] == "capacity_control"


@pytest.mark.asyncio
async def test_graphql_navigator_host_quarantine_rejection():
    nav = GraphQLNavigator(
        config={
            "graphql_probe_circuit_breaker_threshold": 1,
            "graphql_probe_quarantine_seconds": 60,
        }
    )
    nav._host_failures["example.test"] = 1
    nav._host_quarantine_until["example.test"] = 10**12
    try:
        result = await nav.run_as_tool("http://example.test/graphql")
    finally:
        nav._host_failures.pop("example.test", None)
        nav._host_quarantine_until.pop("example.test", None)
    assert result["error_code"] == "connection_error"
    assert result["internal_error_detail"] == "host_quarantined"
    assert result["internal_error_category"] == "host_health"


@pytest.mark.asyncio
async def test_graphql_navigator_half_open_success_clears_quarantine():
    nav = GraphQLNavigator(config={})
    host = "example.test"
    nav._host_quarantine_until[host] = 0.000001
    nav._host_failures[host] = 3
    fake_result = SimpleNamespace(
        introspection_enabled=True,
        graphiql_enabled=False,
        field_suggestions_enabled=False,
        schema=None,
    )
    with patch("src.core.agents.swarm.discovery.graphql.GraphQLAnalyzer.analyze_async", new_callable=AsyncMock) as mock_analyze:
        mock_analyze.return_value = fake_result
        result = await nav.run_as_tool("http://example.test/graphql")
    assert result["error_code"] is None
    assert host not in nav._host_quarantine_until
    assert host not in nav._host_failures


@pytest.mark.asyncio
async def test_discovery_manager_normalizes_graphql_result():
    manager = DiscoveryManagerAgent(config={"model": "test-model"})
    fake_result = {"introspection_enabled": True, "internal_error_category": "capacity_control"}
    with patch("src.core.agents.swarm.discovery.graphql.GraphQLNavigator.run_as_tool", new_callable=AsyncMock) as mock_tool:
        mock_tool.return_value = fake_result
        result = await manager.run_graphql_navigator("http://example.test/graphql")
    assert result["contract_version"] == "1.0.0"
    assert result["introspection_enabled"] is True
    assert result["graphiql_enabled"] is False
    assert isinstance(result["evidence"], list)
    assert result["error_policy_version"] == "1"
    assert "internal_error_category" in result


@pytest.mark.asyncio
async def test_graphql_probe_event_schema_has_required_keys(caplog):
    nav = GraphQLNavigator(config={})
    fake_result = SimpleNamespace(
        introspection_enabled=True,
        graphiql_enabled=False,
        field_suggestions_enabled=False,
        schema=None,
    )
    with patch("src.core.agents.swarm.discovery.graphql.GraphQLAnalyzer.analyze_async", new_callable=AsyncMock) as mock_analyze:
        mock_analyze.return_value = fake_result
        with caplog.at_level("INFO"):
            await nav.run_as_tool("http://example.test/graphql")
    payload = None
    for rec in caplog.records:
        msg = rec.getMessage()
        if msg.startswith("[graphql_probe_event] "):
            payload = json.loads(msg.replace("[graphql_probe_event] ", "", 1))
            break
    assert payload is not None
    for key in GRAPHQL_PROBE_EVENT_REQUIRED_KEYS:
        assert key in payload


@pytest.mark.asyncio
async def test_load_like_scenario_mixed_hosts_controls_backpressure_and_quarantine():
    nav = GraphQLNavigator(
        config={
            "graphql_probe_parallel_limit": 1,
            "graphql_probe_queue_limit": 0,
            "graphql_probe_circuit_breaker_threshold": 1,
            "graphql_probe_quarantine_seconds": 60,
        }
    )
    # backpressure branch
    nav._inflight = 1
    r1 = await nav.run_as_tool("http://slow.example/graphql")
    nav._inflight = 0
    assert r1["internal_error_detail"] == "backpressure_rejected"
    # quarantine branch
    nav._host_failures["fail.example"] = 1
    nav._host_quarantine_until["fail.example"] = 10**12
    r2 = await nav.run_as_tool("http://fail.example/graphql")
    assert r2["internal_error_detail"] == "host_quarantined"


@pytest.mark.asyncio
async def test_half_open_each_host_independent():
    """バグ②修正確認: 各ホストは独立してhalf-open試行を得られる（oldest優先ロジック削除）"""
    nav = GraphQLNavigator(config={})
    nav._host_quarantine_until["host_a.example"] = 1.0
    nav._host_quarantine_until["host_b.example"] = 2.0
    nav._host_failures["host_a.example"] = 3
    nav._host_failures["host_b.example"] = 3
    r_a = await nav._host_admission("http://host_a.example/graphql")
    r_b = await nav._host_admission("http://host_b.example/graphql")
    assert r_a["allowed"] is True
    assert r_a["half_open_trial"] is True
    assert r_b["allowed"] is True
    assert r_b["half_open_trial"] is True


@pytest.mark.asyncio
async def test_half_open_inflight_blocks_second_attempt():
    """同一ホストが half_open_inflight 中は2回目が拒否される"""
    nav = GraphQLNavigator(config={})
    nav._host_quarantine_until["busy.example"] = 1.0
    nav._host_failures["busy.example"] = 3
    r1 = await nav._host_admission("http://busy.example/graphql")
    assert r1["allowed"] is True
    assert r1["half_open_trial"] is True
    r2 = await nav._host_admission("http://busy.example/graphql")
    assert r2["allowed"] is False


@pytest.mark.asyncio
async def test_long_run_state_does_not_leak():
    nav = GraphQLNavigator(config={})
    fake_result = SimpleNamespace(
        introspection_enabled=False,
        graphiql_enabled=False,
        field_suggestions_enabled=False,
        schema=None,
    )
    with patch("src.core.agents.swarm.discovery.graphql.GraphQLAnalyzer.analyze_async", new_callable=AsyncMock) as mock_analyze:
        mock_analyze.return_value = fake_result
        for _ in range(100):
            out = await nav.run_as_tool("http://steady.example/graphql")
            assert out["error_code"] is None
    assert nav._inflight == 0
    assert "steady.example" not in nav._host_failures
    assert "steady.example" not in nav._host_quarantine_until


@pytest.mark.asyncio
async def test_runtime_control_backend_fail_safe_rejects_request():
    nav = GraphQLNavigator(config={"graphql_probe_backend_unavailable_policy": "fail_safe"})
    nav._control_backend.admit = AsyncMock(side_effect=RuntimeControlBackendUnavailable("boom"))  # type: ignore[attr-defined]
    result = await nav.run_as_tool("http://example.test/graphql")
    assert result["error_code"] == "connection_error"
    assert result["internal_error_detail"] == "not_tested_runtime_control_fail_safe"
    assert result["internal_error_category"] == "capacity_control"


@pytest.mark.asyncio
async def test_runtime_control_backend_fail_open_allows_probe():
    nav = GraphQLNavigator(config={"graphql_probe_backend_unavailable_policy": "fail_open"})
    nav._control_backend.admit = AsyncMock(side_effect=RuntimeControlBackendUnavailable("boom"))  # type: ignore[attr-defined]
    fake_result = SimpleNamespace(
        introspection_enabled=False,
        graphiql_enabled=False,
        field_suggestions_enabled=False,
        schema=None,
    )
    with patch("src.core.agents.swarm.discovery.graphql.GraphQLAnalyzer.analyze_async", new_callable=AsyncMock) as mock_analyze:
        mock_analyze.return_value = fake_result
        result = await nav.run_as_tool("http://example.test/graphql")
    assert result["error_code"] is None


@pytest.mark.asyncio
async def test_runtime_control_backend_fail_open_ttl_expires_to_fail_safe():
    nav = GraphQLNavigator(
        config={
            "graphql_probe_backend_unavailable_policy": "fail_open",
            "graphql_probe_fail_open_ttl_seconds": 60,
        }
    )
    nav._fail_open_started_at = time.time() - 120
    nav._control_backend.admit = AsyncMock(side_effect=RuntimeControlBackendUnavailable("boom"))  # type: ignore[attr-defined]
    result = await nav.run_as_tool("http://example.test/graphql")
    assert result["error_code"] == "connection_error"
    assert result["internal_error_detail"] == "not_tested_runtime_control_fail_safe"


@pytest.mark.asyncio
async def test_runtime_control_policy_event_emitted_on_backend_unavailable(caplog):
    nav = GraphQLNavigator(
        config={
            "graphql_probe_backend_unavailable_policy": "fail_open",
            "graphql_probe_fail_open_ttl_seconds": 60,
        }
    )
    nav._control_backend.admit = AsyncMock(side_effect=RuntimeControlBackendUnavailable("boom"))  # type: ignore[attr-defined]
    with caplog.at_level("INFO"):
        await nav.run_as_tool("http://example.test/graphql")
    payload_line = None
    for rec in caplog.records:
        msg = rec.getMessage()
        if msg.startswith("[graphql_probe_event] ") and GRAPHQL_RUNTIME_CONTROL_POLICY_EVENT in msg:
            payload_line = msg
            break
    assert payload_line is not None
    payload = json.loads(payload_line.replace("[graphql_probe_event] ", "", 1))
    for key in GRAPHQL_RUNTIME_CONTROL_POLICY_REQUIRED_KEYS:
        assert key in payload


@pytest.mark.asyncio
async def test_shadow_diff_event_schema_emitted_when_enabled(caplog):
    nav = GraphQLNavigator(config={"graphql_probe_shadow_mode_enabled": True})
    fake_result = SimpleNamespace(
        introspection_enabled=False,
        graphiql_enabled=False,
        field_suggestions_enabled=False,
        schema=None,
    )
    with patch("src.core.agents.swarm.discovery.graphql.GraphQLAnalyzer.analyze_async", new_callable=AsyncMock) as mock_analyze:
        mock_analyze.return_value = fake_result
        with caplog.at_level("INFO"):
            await nav.run_as_tool("http://example.test/graphql")
    payload_line = None
    for rec in caplog.records:
        msg = rec.getMessage()
        if msg.startswith("[graphql_probe_event] ") and GRAPHQL_RUNTIME_CONTROL_SHADOW_DIFF_EVENT in msg:
            payload_line = msg
            break
    assert payload_line is not None
    payload = json.loads(payload_line.replace("[graphql_probe_event] ", "", 1))
    for key in GRAPHQL_RUNTIME_CONTROL_SHADOW_DIFF_REQUIRED_KEYS:
        assert key in payload
    assert payload.get("diff_class") == "same"


def test_missing_threshold_config_rejected():
    with pytest.raises(ValueError):
        GraphQLNavigator(config={"graphql_probe_runtime_control_backend_error_rate_warn_threshold": None})


class _FakeRedis:
    _kv = {}
    _z = {}

    @classmethod
    def reset(cls):
        cls._kv = {}
        cls._z = {}

    @classmethod
    def from_url(cls, _url, decode_responses=True):  # noqa: ARG003
        return cls()

    async def incr(self, key):
        cur = int(self._kv.get(key, "0"))
        cur += 1
        self._kv[key] = str(cur)
        return cur

    async def decr(self, key):
        cur = int(self._kv.get(key, "0"))
        cur -= 1
        self._kv[key] = str(cur)
        return cur

    async def expire(self, key, ttl):  # noqa: ARG002
        return 1

    async def set(self, key, value, ex=None, nx=False):  # noqa: ARG002
        if nx and key in self._kv:
            return False
        self._kv[key] = str(value)
        return True

    async def get(self, key):
        return self._kv.get(key)

    async def delete(self, *keys):
        n = 0
        for key in keys:
            if key in self._kv:
                del self._kv[key]
                n += 1
            if key in self._z:
                del self._z[key]
                n += 1
        return n

    async def zremrangebyscore(self, key, min_score, max_score):  # noqa: ARG002
        entries = self._z.get(key, [])
        mx = float(max_score)
        kept = [(m, s) for m, s in entries if s > mx]
        self._z[key] = kept
        return 1

    async def zcard(self, key):
        return len(self._z.get(key, []))

    async def zadd(self, key, mapping):
        entries = self._z.setdefault(key, [])
        for member, score in mapping.items():
            entries.append((member, float(score)))
        entries.sort(key=lambda x: x[1])
        return len(mapping)

    async def zrange(self, key, start, end, withscores=False):  # noqa: ARG002
        entries = self._z.get(key, [])
        if not entries:
            return []
        picked = entries[start : end + 1]
        if withscores:
            return picked
        return [m for m, _ in picked]


@pytest.mark.asyncio
async def test_redis_backend_shares_backpressure_across_instances():
    import redis.asyncio as redis_async

    _FakeRedis.reset()
    with patch.object(redis_async.Redis, "from_url", side_effect=_FakeRedis.from_url):
        cfg = {
            "graphql_probe_runtime_control_backend": "redis",
            "graphql_probe_runtime_control_redis_url": "redis://unit-test",
            "graphql_probe_parallel_limit": 1,
            "graphql_probe_queue_limit": 0,
            "graphql_probe_backend_unavailable_policy": "fail_safe",
        }
        nav_a = GraphQLNavigator(config=cfg)
        nav_b = GraphQLNavigator(config=cfg)
        admitted = await nav_a._admit()
        assert admitted is True
        try:
            result = await nav_b.run_as_tool("http://example.test/graphql")
            assert result["internal_error_detail"] == "backpressure_rejected"
        finally:
            await nav_a._release()


@pytest.mark.asyncio
async def test_redis_backend_half_open_single_trial_across_instances():
    import redis.asyncio as redis_async

    _FakeRedis.reset()
    with patch.object(redis_async.Redis, "from_url", side_effect=_FakeRedis.from_url):
        cfg = {
            "graphql_probe_runtime_control_backend": "redis",
            "graphql_probe_runtime_control_redis_url": "redis://unit-test",
            "graphql_probe_backend_unavailable_policy": "fail_safe",
        }
        nav_a = GraphQLNavigator(config=cfg)
        nav_b = GraphQLNavigator(config=cfg)
        host = "shared.example"
        until_key = nav_a._control_backend._host_key(host, "quarantine_until")  # type: ignore[attr-defined]
        client = await nav_a._control_backend._get_client()  # type: ignore[attr-defined]
        await client.set(until_key, str(time.time() - 0.2), ex=60)

        a = await nav_a._host_admission(f"http://{host}/graphql")
        b = await nav_b._host_admission(f"http://{host}/graphql")
        assert a["allowed"] is True and a["half_open_trial"] is True
        assert b["allowed"] is False and b["half_open_trial"] is False
