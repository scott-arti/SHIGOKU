
import logging
from typing import List, Dict, Any, Optional

try:
    from bbot.core.helpers.interactsh import InteractshClient
except ImportError:
    # フォールバック（未インストール時は warning）
    InteractshClient = None

logger = logging.getLogger(__name__)

class InteractshOOBClient:
    """
    Interactsh Protocol wrapper for OOB (Out-of-Band) detection.
    Uses BBOT's helper to register and poll interactions.
    """
    
    def __init__(self, server_url: str = "https://interactsh.com", token: Optional[str] = None):
        self.server_url = server_url
        self.token = token
        self.client: Optional[InteractshClient] = None
        self.correlation_id: Optional[str] = None
        self.domain: Optional[str] = None

    async def register(self) -> str:
        """
        Register a new session and return the unique OOB domain.
        Example return: "cxxxxxx.oast.pro"
        """
        if InteractshClient is None:
            logger.warning("BBOT interactsh module is not available. OOB functionality disabled.")
            return "error.oob.internal"
            
        try:
            self.client = InteractshClient()
            # Note: BBOT's register is typically sync but depends on the version. 
            # Looking at the latest implementation patterns.
            self.domain = await self.client.register()
            logger.info("Registered Interactsh domain: %s", self.domain)
            return self.domain
        except Exception as e: # pylint: disable=broad-except
            logger.error("Failed to register Interactsh: %s", e)
            return "error.oob.internal"

    async def poll(self) -> List[Dict[str, Any]]:
        """
        Poll for new interactions.
        Returns a list of interaction records.
        """
        if not self.client:
            return []
            
        try:
            interactions = await self.client.poll()
            if interactions:
                logger.info("Received %d interactions on %s", len(interactions), self.domain)
            return interactions
        except Exception as e: # pylint: disable=broad-except
            logger.error("Error polling Interactsh on %s: %s", self.domain, e)
            return []

    def generate_payload(self, template: str) -> str:
        """
        Replace {{OOB_DOMAIN}} in template with the registered domain.
        """
        if not self.domain:
            return template
        import re
        return re.sub(r'\{\{OOB_DOMAIN\}\}', self.domain, template, flags=re.IGNORECASE)

    async def close(self):
        """Cleanup session."""
        if self.client:
            # BBOT helper usually handles cleanup or doesn't keep persistent socket
            pass
