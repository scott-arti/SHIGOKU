"""
Async Connection Pool for SHIGOKU
Elegant resource management with semaphore-based flow control
"""
from __future__ import annotations
import asyncio
import aiohttp
import logging
from typing import Optional, Dict, Any, AsyncContextManager
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from time import time

logger = logging.getLogger(__name__)


@dataclass
class PoolStats:
    """Real-time pool statistics"""
    active_connections: int = 0
    waiting_requests: int = 0
    total_requests: int = 0
    peak_connections: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "active_connections": self.active_connections,
            "waiting_requests": self.waiting_requests,
            "total_requests": self.total_requests,
            "peak_connections": self.peak_connections,
        }


class ConnectionPool:
    """
    Elegant async connection pool with:
    - Semaphore-based flow control (FD management)
    - Connection reuse and health checks
    - Per-host connection limits
    - Metrics and observability
    """
    
    def __init__(
        self,
        max_connections: int = 100,
        max_connections_per_host: int = 10,
        connection_timeout: float = 30.0,
        keepalive_timeout: float = 60.0,
    ):
        self._max_connections = max_connections
        self._max_per_host = max_connections_per_host
        self._connection_timeout = connection_timeout
        self._keepalive_timeout = keepalive_timeout
        
        # Global semaphore for total connection limit
        self._semaphore = asyncio.Semaphore(max_connections)
        
        # Per-host semaphores
        self._host_semaphores: Dict[str, asyncio.Semaphore] = {}
        self._host_lock = asyncio.Lock()
        
        # Session management
        self._session: Optional[aiohttp.ClientSession] = None
        self._connector: Optional[aiohttp.TCPConnector] = None
        
        # Statistics
        self._stats = PoolStats()
        self._stats_lock = asyncio.Lock()
        
        # Health tracking
        self._last_used: Dict[str, float] = {}
    
    async def initialize(self):
        """Initialize the connection pool"""
        if self._session is not None:
            return
        
        self._connector = aiohttp.TCPConnector(
            limit=self._max_connections,
            limit_per_host=self._max_per_host,
            ttl_dns_cache=300,
            use_dns_cache=True,
            keepalive_timeout=self._keepalive_timeout,
        )
        
        timeout = aiohttp.ClientTimeout(total=self._connection_timeout)
        self._session = aiohttp.ClientSession(
            connector=self._connector,
            timeout=timeout,
        )
        
        logger.info(
            f"Connection pool initialized: "
            f"max={self._max_connections}, per_host={self._max_per_host}"
        )
    
    async def close(self):
        """Gracefully close all connections"""
        if self._session:
            await self._session.close()
            self._session = None
        if self._connector:
            await self._connector.close()
            self._connector = None
        logger.info("Connection pool closed")
    
    @asynccontextmanager
    async def acquire(
        self, 
        host: Optional[str] = None
    ) -> AsyncContextManager[aiohttp.ClientSession]:
        """
        Acquire a connection from the pool
        
        Args:
            host: Target host for per-host limiting
        
        Usage:
            async with pool.acquire("example.com") as session:
                async with session.get(url) as resp:
                    ...
        """
        await self.initialize()
        
        host_semaphore = await self._get_host_semaphore(host) if host else None
        
        # Track waiting
        async with self._stats_lock:
            self._stats.waiting_requests += 1
        
        try:
            # Acquire global permit
            async with self._semaphore:
                # Acquire host-specific permit if needed
                if host_semaphore:
                    async with host_semaphore:
                        yield await self._acquire_session(host)
                else:
                    yield await self._acquire_session(host)
        finally:
            async with self._stats_lock:
                self._stats.waiting_requests -= 1
    
    async def _acquire_session(self, host: Optional[str]) -> aiohttp.ClientSession:
        """Internal session acquisition with stats"""
        async with self._stats_lock:
            self._stats.active_connections += 1
            self._stats.total_requests += 1
            self._stats.peak_connections = max(
                self._stats.peak_connections,
                self._stats.active_connections
            )
        
        if host:
            self._last_used[host] = time()
        
        return self._session
    
    async def _get_host_semaphore(
        self, 
        host: str
    ) -> asyncio.Semaphore:
        """Get or create per-host semaphore"""
        async with self._host_lock:
            if host not in self._host_semaphores:
                self._host_semaphores[host] = asyncio.Semaphore(
                    self._max_per_host
                )
            return self._host_semaphores[host]
    
    def release(self):
        """Release a connection back to the pool"""
        # Semaphore handles release automatically on context exit
        pass
    
    async def get_stats(self) -> PoolStats:
        """Get current pool statistics"""
        async with self._stats_lock:
            return PoolStats(
                active_connections=self._stats.active_connections,
                waiting_requests=self._stats.waiting_requests,
                total_requests=self._stats.total_requests,
                peak_connections=self._stats.peak_connections,
            )
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the pool"""
        stats = await self.get_stats()
        
        # Check for stale connections
        now = time()
        stale_hosts = [
            host for host, last in self._last_used.items()
            if now - last > self._keepalive_timeout * 2
        ]
        
        return {
            "status": "healthy" if stats.active_connections < self._max_connections else "busy",
            "stats": stats.to_dict(),
            "stale_hosts": len(stale_hosts),
            "utilization": stats.active_connections / self._max_connections,
        }


# Singleton instance management
_pool_instance: Optional[ConnectionPool] = None


def get_connection_pool(
    max_connections: int = 100,
    max_per_host: int = 10,
) -> ConnectionPool:
    """Get or create global connection pool"""
    global _pool_instance
    if _pool_instance is None:
        _pool_instance = ConnectionPool(
            max_connections=max_connections,
            max_connections_per_host=max_per_host,
        )
    return _pool_instance


def reset_connection_pool():
    """Reset global pool (for testing)"""
    global _pool_instance
    _pool_instance = None
