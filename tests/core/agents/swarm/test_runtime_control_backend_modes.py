import pytest

from src.core.agents.swarm.runtime_control_backend import (
    RedisRuntimeControlBackend,
    RuntimeControlBackendUnavailable,
)


class _DummySentinel:
    def __init__(self, sentinels, **kwargs):  # noqa: ARG002
        self.sentinels = sentinels

    def master_for(self, service_name, **kwargs):  # noqa: ARG002
        return {"kind": "sentinel", "service_name": service_name}


class _DummyCluster:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


@pytest.mark.asyncio
async def test_redis_backend_sentinel_mode_builds_client(monkeypatch):
    import redis.asyncio.sentinel as sentinel_mod

    monkeypatch.setattr(sentinel_mod, "Sentinel", _DummySentinel)
    backend = RedisRuntimeControlBackend(
        redis_url=None,
        mode="sentinel",
        sentinel_nodes=["127.0.0.1:26379"],
        sentinel_service_name="mymaster",
    )
    client = await backend._get_client()
    assert isinstance(client, dict)
    assert client["kind"] == "sentinel"
    assert client["service_name"] == "mymaster"


@pytest.mark.asyncio
async def test_redis_backend_cluster_mode_builds_client(monkeypatch):
    import redis.asyncio.cluster as cluster_mod

    monkeypatch.setattr(cluster_mod, "RedisCluster", _DummyCluster)
    backend = RedisRuntimeControlBackend(
        redis_url=None,
        mode="cluster",
        cluster_nodes=["127.0.0.1:6379", "127.0.0.1:6380"],
    )
    client = await backend._get_client()
    assert isinstance(client, _DummyCluster)
    assert "startup_nodes" in client.kwargs
    assert len(client.kwargs["startup_nodes"]) == 2


@pytest.mark.asyncio
async def test_redis_backend_sentinel_invalid_config():
    backend = RedisRuntimeControlBackend(
        redis_url=None,
        mode="sentinel",
        sentinel_nodes=[],
        sentinel_service_name=None,
    )
    with pytest.raises(RuntimeControlBackendUnavailable):
        await backend._get_client()
