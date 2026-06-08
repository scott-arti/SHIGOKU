
import logging
from typing import Optional, Dict, Any, List
from src.core.agents.base_agent import BaseAgent
from src.tools.browser.playwright_validator import PlaywrightValidator

logger = logging.getLogger(__name__)

class XSSVerifier(BaseAgent):
    """
    XSS Verification Agent using Headless Browser (Playwright).
    
    Verifies suspected XSS vulnerabilities by actually rendering the page
    and detecting alert() dialogs or other XSS indicators.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.validator = PlaywrightValidator()

    async def verify(self, url: str) -> bool:
        """
        Verifies if the given URL triggers XSS in a headless browser.
        """
        if not self.validator.is_available:
            logger.warning("[XSSVerifier] Playwright is not available. Skipping verification.")
            return False
            
        logger.info(f"[XSSVerifier] Verifying XSS for: {url}")
        try:
            is_triggered = await self.validator.validate_xss(url)
            if is_triggered:
                logger.info(f"[XSSVerifier] XSS CONFIRMED for: {url}")
                return True
            else:
                logger.debug(f"[XSSVerifier] XSS not triggered for: {url}")
                return False
        except Exception as e:
            logger.error(f"[XSSVerifier] Error during verification: {e}")
            return False
