import asyncio
import multiprocessing as mp
import os
import subprocess
import time
import uuid

import pytest

from src.core.agents.swarm.discovery.graphql import GraphQLNavigator


def _worker_try_admit(redis_url: str, namespace: str, q: mp.Queue) -> None:
    async def _run() -> None:
        nav = GraphQLNavigator(
            config={
                "graphql_probe_runtime_control_backend": "redis",
                "graphql_probe_runtime_control_redis_url": redis_url,
                "graphql_probe_runtime_control_redis_namespace": namespace,
                "graphql_probe_parallel_limit": 1,
                "graphql_probe_queue_limit": 0,
                "graphql_probe_backend_unavailable_policy": "fail_safe",
            }
        )
        admitted = await nav._admit()
        q.put(admitted)

    asyncio.run(_run())


def _worker_host_admission(redis_url: str, namespace: str, host: str, q: mp.Queue) -> None:
    async def _run() -> None:
        nav = GraphQLNavigator(
            config={
                "graphql_probe_runtime_control_backend": "redis",
                "graphql_probe_runtime_control_redis_url": redis_url,
                "graphql_probe_runtime_control_redis_namespace": namespace,
                "graphql_probe_backend_unavailable_policy": "fail_safe",
            }
        )
        result = await nav._host_admission(f"http://{host}/graphql")
        q.put(result)

    asyncio.run(_run())


def _docker_available() -> bool:
    return subprocess.run(["docker", "version"], capture_output=True).returncode == 0


@pytest.mark.integration
@pytest.mark.skipif(not _docker_available(), reason="docker daemon unavailable")
def test_redis_e2e_multiprocess_runtime_control():
    container = f"shigoku-redis-e2e-{uuid.uuid4().hex[:8]}"
    host_port = "6389"
    redis_url = f"redis://127.0.0.1:{host_port}/0"
    run = subprocess.run(
        ["docker", "run", "--rm", "-d", "--name", container, "-p", f"{host_port}:6379", "redis:7-alpine"],
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stderr
    try:
        # Wait until Redis is ready.
        for _ in range(40):
            ping = subprocess.run(
                ["docker", "exec", container, "redis-cli", "PING"],
                capture_output=True,
                text=True,
            )
            if ping.returncode == 0 and "PONG" in ping.stdout:
                break
            time.sleep(0.25)
        else:
            raise AssertionError("redis readiness check failed")

        # Backpressure shared across 2 processes.
        ns1 = f"shigoku:e2e:bp:{uuid.uuid4().hex}"
        q1: mp.Queue = mp.Queue()
        q2: mp.Queue = mp.Queue()
        p1 = mp.Process(target=_worker_try_admit, args=(redis_url, ns1, q1))
        p2 = mp.Process(target=_worker_try_admit, args=(redis_url, ns1, q2))
        p1.start()
        p1.join(timeout=20)
        assert p1.exitcode == 0
        first = q1.get(timeout=5)
        assert first is True

        p2.start()
        p2.join(timeout=20)
        assert p2.exitcode == 0
        second = q2.get(timeout=5)
        assert second is False

        # Half-open trial is single-flight per host across 2 processes.
        host = "e2e-shared.example"
        ns2 = f"shigoku:e2e:ho:{uuid.uuid4().hex}"
        prep = GraphQLNavigator(
            config={
                "graphql_probe_runtime_control_backend": "redis",
                "graphql_probe_runtime_control_redis_url": redis_url,
                "graphql_probe_runtime_control_redis_namespace": ns2,
            }
        )
        backend = prep._control_backend
        until_key = backend._host_key(host, "quarantine_until")

        async def _set_until() -> None:
            client = await backend._get_client()
            await client.set(until_key, str(time.time() - 0.2), ex=60)

        asyncio.run(_set_until())

        qa: mp.Queue = mp.Queue()
        qb: mp.Queue = mp.Queue()
        pa = mp.Process(target=_worker_host_admission, args=(redis_url, ns2, host, qa))
        pb = mp.Process(target=_worker_host_admission, args=(redis_url, ns2, host, qb))
        pa.start()
        pb.start()
        pa.join(timeout=20)
        pb.join(timeout=20)
        assert pa.exitcode == 0 and pb.exitcode == 0
        ra = qa.get(timeout=5)
        rb = qb.get(timeout=5)

        allowed_count = int(bool(ra.get("allowed"))) + int(bool(rb.get("allowed")))
        half_open_count = int(bool(ra.get("half_open_trial"))) + int(bool(rb.get("half_open_trial")))
        assert allowed_count == 1
        assert half_open_count == 1
    finally:
        subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@pytest.mark.integration
@pytest.mark.skipif(not _docker_available(), reason="docker daemon unavailable")
@pytest.mark.asyncio
async def test_redis_outage_fail_safe_rejects():
    container = f"shigoku-redis-outage-{uuid.uuid4().hex[:8]}"
    host_port = "6390"
    redis_url = f"redis://127.0.0.1:{host_port}/0"
    run = subprocess.run(
        ["docker", "run", "--rm", "-d", "--name", container, "-p", f"{host_port}:6379", "redis:7-alpine"],
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stderr
    try:
        nav = GraphQLNavigator(
            config={
                "graphql_probe_runtime_control_backend": "redis",
                "graphql_probe_runtime_control_redis_url": redis_url,
                "graphql_probe_backend_unavailable_policy": "fail_safe",
            }
        )
        subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await asyncio.sleep(0.2)
        result = await nav.run_as_tool("http://example.test/graphql")
        assert result["error_code"] == "connection_error"
        assert "runtime_control_backend_unavailable_fail_safe" in str(result["internal_error_detail"])
    finally:
        subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@pytest.mark.integration
@pytest.mark.skipif(not _docker_available(), reason="docker daemon unavailable")
@pytest.mark.asyncio
async def test_redis_outage_fail_open_then_ttl_to_fail_safe():
    container = f"shigoku-redis-outage-{uuid.uuid4().hex[:8]}"
    host_port = "6391"
    redis_url = f"redis://127.0.0.1:{host_port}/0"
    run = subprocess.run(
        ["docker", "run", "--rm", "-d", "--name", container, "-p", f"{host_port}:6379", "redis:7-alpine"],
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stderr
    try:
        nav = GraphQLNavigator(
            config={
                "graphql_probe_runtime_control_backend": "redis",
                "graphql_probe_runtime_control_redis_url": redis_url,
                "graphql_probe_backend_unavailable_policy": "fail_open",
                "graphql_probe_fail_open_ttl_seconds": 1,
            }
        )
        subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await asyncio.sleep(0.2)
        first = await nav.run_as_tool("http://example.test/graphql")
        assert first["error_code"] is None
        await asyncio.sleep(1.2)
        second = await nav.run_as_tool("http://example.test/graphql")
        assert second["error_code"] == "connection_error"
        assert second["internal_error_detail"] == "runtime_control_backend_unavailable_fail_safe_ttl"
    finally:
        subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@pytest.mark.integration
@pytest.mark.skipif(not _docker_available(), reason="docker daemon unavailable")
@pytest.mark.asyncio
async def test_redis_failover_like_restart_continuous_requests():
    """
    Failover相当試験:
    - 連続リクエスト中にRedisを再起動（停止->復帰）し、
      runtime control backend障害中でも処理継続し、復帰後も継続できることを確認する。
    """
    container = f"shigoku-redis-failover-like-{uuid.uuid4().hex[:8]}"
    host_port = "6392"
    redis_url = f"redis://127.0.0.1:{host_port}/0"
    run = subprocess.run(
        ["docker", "run", "--rm", "-d", "--name", container, "-p", f"{host_port}:6379", "redis:7-alpine"],
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stderr
    try:
        nav = GraphQLNavigator(
            config={
                "graphql_probe_runtime_control_backend": "redis",
                "graphql_probe_runtime_control_redis_url": redis_url,
                "graphql_probe_backend_unavailable_policy": "fail_open",
                "graphql_probe_fail_open_ttl_seconds": 1800,
            }
        )

        # warmup
        r1 = await nav.run_as_tool("http://example.test/graphql")
        assert r1["error_code"] is None

        # failover-like outage: redis restart during continuous requests
        subprocess.run(["docker", "restart", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        results = []
        for _ in range(12):
            out = await nav.run_as_tool("http://example.test/graphql")
            results.append(out)
            await asyncio.sleep(0.15)

        # Recoverability check: eventually returns to normal path (still no hard failure response).
        assert any(r.get("error_code") is None for r in results)
        # During restart window backend may be unavailable, but fail_open keeps contract non-fatal.
        assert all(r.get("error_code") in (None, "connection_error", "invalid_response", "http_error", "timeout") for r in results)
    finally:
        subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
