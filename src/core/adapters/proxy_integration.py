"""
Proxy Integration for SHIGOKU Phase D
Elegant Caido/HTTP Proxy integration for reproduction
"""
from __future__ import annotations
import asyncio
import json
import logging
from typing import Dict, Any, Optional, Protocol
from dataclasses import dataclass
from abc import ABC, abstractmethod
import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class ProxyRequest:
    """Request to send through proxy"""
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
        }


@dataclass
class ProxyResponse:
    """Response from proxy"""
    status_code: int
    headers: Dict[str, str]
    body: str
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProxyResponse":
        return cls(
            status_code=data.get("status_code", 0),
            headers=data.get("headers", {}),
            body=data.get("body", "")
        )


class ProxyIntegration(ABC):
    """Abstract base for proxy integrations"""
    
    @abstractmethod
    async def send_request(self, request: ProxyRequest) -> ProxyResponse:
        """Send request through proxy"""
        pass
    
    @abstractmethod
    async def replay_finding(
        self,
        finding: Dict[str, Any],
        modifications: Optional[Dict[str, Any]] = None
    ) -> ProxyResponse:
        """Replay a finding for manual verification"""
        pass


class CaidoIntegration(ProxyIntegration):
    """
    Caido proxy integration
    
    Features:
    - HTTP API integration with Caido
    - Request replay
    - Request modification before replay
    """
    
    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_token: Optional[str] = None
    ):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session"""
        if self._session is None:
            headers = {}
            if self.api_token:
                headers["Authorization"] = f"Bearer {self.api_token}"
            
            self._session = aiohttp.ClientSession(
                base_url=self.base_url,
                headers=headers
            )
        return self._session
    
    async def send_request(self, request: ProxyRequest) -> ProxyResponse:
        """Send request through Caido proxy"""
        session = await self._get_session()
        
        # Convert to Caido API format
        caido_request = {
            "method": request.method,
            "url": request.url,
            "headers": [
                {"name": k, "value": v}
                for k, v in request.headers.items()
            ],
            "body": request.body or ""
        }
        
        try:
            async with session.post(
                "/api/send",
                json=caido_request
            ) as response:
                data = await response.json()
                
                return ProxyResponse(
                    status_code=data.get("status", 0),
                    headers=self._parse_headers(data.get("headers", [])),
                    body=data.get("body", "")
                )
        except Exception as e:
            logger.error(f"Caido request failed: {e}")
            raise
    
    def _parse_headers(self, headers_list: list) -> Dict[str, str]:
        """Parse Caido header format"""
        return {
            h["name"]: h["value"]
            for h in headers_list
        }
    
    async def replay_finding(
        self,
        finding: Dict[str, Any],
        modifications: Optional[Dict[str, Any]] = None
    ) -> ProxyResponse:
        """
        Replay a finding through Caido
        
        Args:
            finding: Finding dict with request details
            modifications: Optional modifications to apply
                e.g., {"payload": "modified payload"}
        
        Returns:
            ProxyResponse from replay
        """
        # Extract request details from finding
        method = finding.get("method", "GET")
        url = finding.get("url", "")
        headers = finding.get("headers", {})
        body = finding.get("body")
        
        # Apply modifications
        if modifications:
            if "payload" in modifications:
                # Modify body or query parameter
                body = modifications["payload"]
            if "url" in modifications:
                url = modifications["url"]
        
        request = ProxyRequest(
            method=method,
            url=url,
            headers=headers,
            body=body
        )
        
        return await self.send_request(request)
    
    async def send_to_repeater(
        self,
        request: ProxyRequest,
        tab_name: Optional[str] = None
    ) -> str:
        """
        Send request to Caido Repeater for manual testing
        
        Returns:
            Repeater tab ID
        """
        session = await self._get_session()
        
        caido_request = {
            "method": request.method,
            "url": request.url,
            "headers": [
                {"name": k, "value": v}
                for k, v in request.headers.items()
            ],
            "body": request.body or "",
            "tab_name": tab_name or f"SHIGOKU-{request.url[:30]}"
        }
        
        try:
            async with session.post(
                "/api/repeater/send",
                json=caido_request
            ) as response:
                data = await response.json()
                tab_id = data.get("tab_id", "")
                logger.info(f"Request sent to Caido Repeater: {tab_id}")
                return tab_id
        except Exception as e:
            logger.error(f"Failed to send to repeater: {e}")
            raise
    
    async def close(self):
        """Cleanup session"""
        if self._session:
            await self._session.close()
            self._session = None


class BurpIntegration(ProxyIntegration):
    """
    Burp Suite integration placeholder
    
    Would implement Burp's REST API or extension-based integration
    """
    
    def __init__(self, base_url: str = "http://localhost:1337"):
        self.base_url = base_url
        logger.warning("Burp integration is a placeholder")
    
    async def send_request(self, request: ProxyRequest) -> ProxyResponse:
        """Placeholder implementation"""
        logger.warning("Burp send_request not implemented")
        return ProxyResponse(
            status_code=0,
            headers={},
            body="Not implemented"
        )
    
    async def replay_finding(
        self,
        finding: Dict[str, Any],
        modifications: Optional[Dict[str, Any]] = None
    ) -> ProxyResponse:
        """Placeholder implementation"""
        logger.warning("Burp replay_finding not implemented")
        return ProxyResponse(
            status_code=0,
            headers={},
            body="Not implemented"
        )


class ProxyManager:
    """
    Central proxy management
    
    - Auto-detect available proxies
    - Fallback chain
    - Request routing
    """
    
    def __init__(self):
        self._proxies: Dict[str, ProxyIntegration] = {}
        self._preferred: Optional[str] = None
    
    def register(
        self, 
        name: str, 
        proxy: ProxyIntegration,
        preferred: bool = False
    ):
        """Register a proxy integration"""
        self._proxies[name] = proxy
        
        if preferred or self._preferred is None:
            self._preferred = name
        
        logger.info(f"Registered proxy: {name}")
    
    def get_proxy(self, name: Optional[str] = None) -> ProxyIntegration:
        """Get proxy by name or preferred"""
        if name:
            if name not in self._proxies:
                raise KeyError(f"Unknown proxy: {name}")
            return self._proxies[name]
        
        if self._preferred is None:
            raise RuntimeError("No proxy registered")
        
        return self._proxies[self._preferred]
    
    async def auto_detect(self):
        """Auto-detect available proxies"""
        # Try Caido
        try:
            caido = CaidoIntegration()
            # Test connection
            await caido._get_session()
            self.register("caido", caido, preferred=True)
            logger.info("Auto-detected Caido proxy")
        except Exception:
            logger.debug("Caido not available")
        
        # Add more auto-detection here (Burp, etc.)
    
    async def send_finding_to_proxy(
        self,
        finding: Dict[str, Any],
        proxy_name: Optional[str] = None
    ) -> str:
        """
        Send finding to proxy for manual verification
        
        Returns:
            Proxy-specific reference (tab ID, etc.)
        """
        proxy = self.get_proxy(proxy_name)
        
        request = ProxyRequest(
            method=finding.get("method", "GET"),
            url=finding.get("url", ""),
            headers=finding.get("headers", {}),
            body=finding.get("body")
        )
        
        # If Caido, send to repeater
        if isinstance(proxy, CaidoIntegration):
            return await proxy.send_to_repeater(
                request,
                tab_name=finding.get("type", "unknown")
            )
        
        # Generic: just send request
        await proxy.send_request(request)
        return "sent"


# Convenience functions

async def create_proxy_manager() -> ProxyManager:
    """
    Create proxy manager with auto-detection
    
    Usage:
        proxy_mgr = await create_proxy_manager()
        
        # Send finding to proxy
        ref = await proxy_mgr.send_finding_to_proxy(finding)
    """
    manager = ProxyManager()
    await manager.auto_detect()
    return manager


# Global instance
_proxy_manager: Optional[ProxyManager] = None


async def get_proxy_manager() -> ProxyManager:
    """Get or create global proxy manager"""
    global _proxy_manager
    if _proxy_manager is None:
        _proxy_manager = await create_proxy_manager()
    return _proxy_manager
