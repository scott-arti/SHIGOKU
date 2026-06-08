"""
Infrastructure Layer for SHIGOKU Phase D
Elegant integration of DI Container, Connection Pool, and Resource Management
"""
from __future__ import annotations
import asyncio
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass

from .di_container import DIContainer, get_container
from .connection_pool import ConnectionPool, get_connection_pool

logger = logging.getLogger(__name__)


@dataclass
class InfrastructureConfig:
    """Configuration for infrastructure layer"""
    # Connection Pool
    max_connections: int = 100
    max_connections_per_host: int = 10
    connection_timeout: float = 30.0
    
    # Auth
    token_refresh_buffer: float = 60.0  # Refresh 60s before expiry
    
    # DNS
    dns_cache_ttl: int = 300


class InfrastructureLayer:
    """
    ┌─────────────────────────────────────────┐
    │  DI Container (Architect requirement)   │
    │  - Service registration & resolution    │
    │  - Lifecycle management                 │
    ├─────────────────────────────────────────┤
    │  Resource Manager (SRE requirement)       │
    │  - ConnectionPool (FD management)       │
    │  - DNS Cache (TTL management)             │
    ├─────────────────────────────────────────┤
    │  Auth Manager (Architect requirement)     │
    │  - Token refresh with lock              │
    │  - Race condition prevention            │
    └─────────────────────────────────────────┘
    """
    
    def __init__(self, config: Optional[InfrastructureConfig] = None):
        self.config = config or InfrastructureConfig()
        
        # Components
        self._container = get_container()
        self._connection_pool = get_connection_pool(
            max_connections=self.config.max_connections,
            max_per_host=self.config.max_connections_per_host,
        )
        
        # Token management
        self._token_lock = asyncio.Lock()
        self._current_token: Optional[str] = None
        self._token_expiry: float = 0.0
        
        self._initialized = False
    
    async def initialize(self):
        """Initialize all infrastructure components"""
        if self._initialized:
            return
        
        # Initialize connection pool
        await self._connection_pool.initialize()
        
        # Register core services in DI container
        self._register_core_services()
        
        self._initialized = True
        logger.info("Infrastructure layer initialized")
    
    async def shutdown(self):
        """Graceful shutdown"""
        await self._connection_pool.close()
        logger.info("Infrastructure layer shutdown")
    
    def _register_core_services(self):
        """Register core infrastructure services in DI"""
        # Register connection pool
        self._container.register_instance(ConnectionPool, self._connection_pool)
        
        # Register self for access to auth management
        self._container.register_instance(InfrastructureLayer, self)
    
    @property
    def di_container(self) -> DIContainer:
        """Access DI container"""
        return self._container
    
    @property
    def connection_pool(self) -> ConnectionPool:
        """Access connection pool"""
        return self._connection_pool
    
    async def get_token(self) -> Optional[str]:
        """
        Get current auth token with automatic refresh
        Thread-safe with lock to prevent race conditions
        """
        async with self._token_lock:
            now = asyncio.get_event_loop().time()
            
            # Check if token needs refresh
            if now >= self._token_expiry - self.config.token_refresh_buffer:
                await self._refresh_token()
            
            return self._current_token
    
    async def _refresh_token(self):
        """Internal token refresh (called with lock held)"""
        try:
            # Token refresh implementation
            # This would call the actual auth service
            new_token = await self._perform_token_refresh()
            
            self._current_token = new_token
            # Assume 1 hour expiry if not provided
            self._token_expiry = asyncio.get_event_loop().time() + 3600
            
            logger.debug("Token refreshed successfully")
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise
    
    async def _perform_token_refresh(self) -> str:
        """
        Perform actual token refresh
        Subclasses or config can override this
        """
        # Placeholder - actual implementation depends on auth provider
        # Could be JWT refresh, OAuth, etc.
        return "refreshed_token_placeholder"
    
    async def set_token(self, token: str, expires_in: float = 3600):
        """
        Set a new token externally
        Useful for initial auth or token injection
        """
        async with self._token_lock:
            self._current_token = token
            self._token_expiry = asyncio.get_event_loop().time() + expires_in
    
    async def health_check(self) -> Dict[str, Any]:
        """Health check of all infrastructure components"""
        pool_health = await self._connection_pool.health_check()
        
        return {
            "status": "healthy" if pool_health["status"] != "error" else "degraded",
            "connection_pool": pool_health,
            "di_container": {
                "registered_services": len(self._container._registrations),
                "singletons": len(self._container._singletons),
            },
            "token_status": "valid" if self._current_token else "none",
        }


# Global instance management
_infrastructure_layer: Optional[InfrastructureLayer] = None


def get_infrastructure_layer(
    config: Optional[InfrastructureConfig] = None
) -> InfrastructureLayer:
    """Get or create global infrastructure layer"""
    global _infrastructure_layer
    if _infrastructure_layer is None:
        _infrastructure_layer = InfrastructureLayer(config)
    return _infrastructure_layer


def reset_infrastructure_layer():
    """Reset global layer (for testing)"""
    global _infrastructure_layer
    _infrastructure_layer = None
