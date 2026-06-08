from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol

from urllib.parse import quote


class RuntimeControlBackend(Protocol):
    async def admit(self, parallel_limit: int, queue_limit: int) -> bool: ...
    async def release(self) -> None: ...
    async def acquire_qps_slot(self, qps_limit: int) -> None: ...
    async def host_admission(self, host: str) -> Dict[str, Any]: ...
    async def record_outcome(
        self,
        host: str,
        success: bool,
        half_open_trial: bool,
        circuit_breaker_threshold: int,
        quarantine_seconds: float,
    ) -> None: ...


class RuntimeControlBackendUnavailable(RuntimeError):
    pass


@dataclass
class InMemoryRuntimeControlBackend:
    inflight: int = 0

    def __post_init__(self) -> None:
        self._lock = asyncio.Lock()
        self.qps_timestamps: List[float] = []
        self.host_failures: Dict[str, int] = {}
        self.host_quarantine_until: Dict[str, float] = {}
        self.host_half_open_inflight: Dict[str, bool] = {}

    async def admit(self, parallel_limit: int, queue_limit: int) -> bool:
        async with self._lock:
            cap = parallel_limit + queue_limit
            if self.inflight >= cap:
                return False
            self.inflight += 1
            return True

    async def release(self) -> None:
        async with self._lock:
            self.inflight = max(0, self.inflight - 1)

    async def acquire_qps_slot(self, qps_limit: int) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                self.qps_timestamps = [t for t in self.qps_timestamps if now - t < 1.0]
                if len(self.qps_timestamps) < qps_limit:
                    self.qps_timestamps.append(now)
                    return
                sleep_for = max(0.01, 1.0 - (now - min(self.qps_timestamps)))
            await asyncio.sleep(sleep_for)

    async def host_admission(self, host: str) -> Dict[str, Any]:
        now = time.monotonic()
        async with self._lock:
            until = self.host_quarantine_until.get(host, 0.0)
            if until > now:
                return {"allowed": False, "detail": "host_quarantined", "host": host, "half_open_trial": False}
            if until > 0.0 and self.host_half_open_inflight.get(host, False):
                return {"allowed": False, "detail": "host_quarantined", "host": host, "half_open_trial": False}
            if until > 0.0 and not self.host_half_open_inflight.get(host, False):
                self.host_half_open_inflight[host] = True
                return {"allowed": True, "detail": "half_open_trial", "host": host, "half_open_trial": True}
            return {"allowed": True, "detail": "admitted", "host": host, "half_open_trial": False}

    async def record_outcome(
        self,
        host: str,
        success: bool,
        half_open_trial: bool,
        circuit_breaker_threshold: int,
        quarantine_seconds: float,
    ) -> None:
        now = time.monotonic()
        async with self._lock:
            if success:
                self.host_failures.pop(host, None)
                self.host_quarantine_until.pop(host, None)
                self.host_half_open_inflight.pop(host, None)
                return
            failures = self.host_failures.get(host, 0) + 1
            self.host_failures[host] = failures
            if failures >= circuit_breaker_threshold:
                self.host_quarantine_until[host] = now + quarantine_seconds
            if half_open_trial:
                self.host_half_open_inflight.pop(host, None)


class RedisRuntimeControlBackend:
    def __init__(
        self,
        redis_url: Optional[str] = None,
        namespace: str = "shigoku:runtime-control:graphql",
        mode: str = "standalone",
        sentinel_nodes: Optional[List[str]] = None,
        sentinel_service_name: Optional[str] = None,
        cluster_nodes: Optional[List[str]] = None,
    ):
        self._redis_url = redis_url
        self._namespace = namespace
        self._mode = mode
        self._sentinel_nodes = sentinel_nodes or []
        self._sentinel_service_name = sentinel_service_name
        self._cluster_nodes = cluster_nodes or []
        self._client = None
        self._clock_skew_guard_seconds = 1.0

    @staticmethod
    def _parse_nodes(raw_nodes: List[str]) -> List[tuple[str, int]]:
        nodes: List[tuple[str, int]] = []
        for raw in raw_nodes:
            host, sep, port = str(raw).partition(":")
            if not sep:
                continue
            try:
                nodes.append((host.strip(), int(port.strip())))
            except ValueError:
                continue
        return nodes

    async def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            from redis.asyncio import Redis  # type: ignore
            from redis.asyncio.cluster import RedisCluster  # type: ignore
            from redis.asyncio.sentinel import Sentinel  # type: ignore
            from redis.cluster import ClusterNode  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeControlBackendUnavailable(f"redis_import_failed:{exc}") from exc
        try:
            if self._mode == "sentinel":
                nodes = self._parse_nodes(self._sentinel_nodes)
                if not nodes or not self._sentinel_service_name:
                    raise RuntimeControlBackendUnavailable("redis_sentinel_config_invalid")
                sentinel = Sentinel(nodes, decode_responses=True)
                self._client = sentinel.master_for(self._sentinel_service_name, decode_responses=True)
            elif self._mode == "cluster":
                nodes = self._parse_nodes(self._cluster_nodes)
                if not nodes:
                    raise RuntimeControlBackendUnavailable("redis_cluster_config_invalid")
                startup_nodes = [ClusterNode(host=h, port=p) for h, p in nodes]
                self._client = RedisCluster(startup_nodes=startup_nodes, decode_responses=True)
            else:
                if not self._redis_url:
                    raise RuntimeControlBackendUnavailable("redis_url_missing")
                self._client = Redis.from_url(self._redis_url, decode_responses=True)
        except RuntimeControlBackendUnavailable:
            raise
        except Exception as exc:
            raise RuntimeControlBackendUnavailable(f"redis_client_init_failed:{exc}") from exc
        return self._client

    def _k(self, suffix: str) -> str:
        return f"{self._namespace}:{suffix}"

    def _host_key(self, host: str, suffix: str) -> str:
        return f"{self._namespace}:host:{quote(host, safe='')}:{suffix}"

    async def admit(self, parallel_limit: int, queue_limit: int) -> bool:
        cap = parallel_limit + queue_limit
        client = await self._get_client()
        key = self._k("inflight")
        try:
            current = await client.incr(key)
            if int(current) <= cap:
                await client.expire(key, 3600)
                return True
            await client.decr(key)
            return False
        except Exception as exc:
            raise RuntimeControlBackendUnavailable(f"redis_admit_failed:{exc}") from exc

    async def release(self) -> None:
        client = await self._get_client()
        key = self._k("inflight")
        try:
            current = await client.decr(key)
            if int(current) < 0:
                await client.set(key, 0, ex=3600)
        except Exception as exc:
            raise RuntimeControlBackendUnavailable(f"redis_release_failed:{exc}") from exc

    async def acquire_qps_slot(self, qps_limit: int) -> None:
        client = await self._get_client()
        key = self._k("qps")
        while True:
            now = time.time()
            try:
                await client.zremrangebyscore(key, "-inf", now - 1.0)
                count = int(await client.zcard(key))
                if count < qps_limit:
                    member = f"{now}:{time.monotonic_ns()}"
                    await client.zadd(key, {member: now})
                    await client.expire(key, 120)
                    return
                oldest = await client.zrange(key, 0, 0, withscores=True)
                if not oldest:
                    await asyncio.sleep(0.01)
                    continue
                sleep_for = max(0.01, 1.0 - (now - float(oldest[0][1])))
            except Exception as exc:
                raise RuntimeControlBackendUnavailable(f"redis_qps_failed:{exc}") from exc
            await asyncio.sleep(sleep_for)

    async def host_admission(self, host: str) -> Dict[str, Any]:
        client = await self._get_client()
        key_until = self._host_key(host, "quarantine_until")
        key_half_open = self._host_key(host, "half_open_inflight")
        now = time.time()
        try:
            raw_until = await client.get(key_until)
            until = float(raw_until) if raw_until is not None else 0.0
            if until > (now + self._clock_skew_guard_seconds):
                return {"allowed": False, "detail": "host_quarantined", "host": host, "half_open_trial": False}
            if until > 0.0:
                acquired = await client.set(key_half_open, "1", nx=True, ex=300)
                if acquired:
                    return {"allowed": True, "detail": "half_open_trial", "host": host, "half_open_trial": True}
                return {"allowed": False, "detail": "host_quarantined", "host": host, "half_open_trial": False}
            return {"allowed": True, "detail": "admitted", "host": host, "half_open_trial": False}
        except Exception as exc:
            raise RuntimeControlBackendUnavailable(f"redis_host_admission_failed:{exc}") from exc

    async def record_outcome(
        self,
        host: str,
        success: bool,
        half_open_trial: bool,
        circuit_breaker_threshold: int,
        quarantine_seconds: float,
    ) -> None:
        client = await self._get_client()
        key_fail = self._host_key(host, "failures")
        key_until = self._host_key(host, "quarantine_until")
        key_half_open = self._host_key(host, "half_open_inflight")
        try:
            if success:
                await client.delete(key_fail, key_until, key_half_open)
                return
            failures = int(await client.incr(key_fail))
            await client.expire(key_fail, max(60, int(quarantine_seconds * 10)))
            if failures >= circuit_breaker_threshold:
                quarantine_until = time.time() + quarantine_seconds
                await client.set(key_until, str(quarantine_until), ex=max(60, int(quarantine_seconds * 4)))
            if half_open_trial:
                await client.delete(key_half_open)
        except Exception as exc:
            raise RuntimeControlBackendUnavailable(f"redis_record_outcome_failed:{exc}") from exc
