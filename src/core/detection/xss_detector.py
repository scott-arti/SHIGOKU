"""
XSS Detection Engine for SHIGOKU Phase D
Elegant browser pool with memory leak prevention
"""
from __future__ import annotations
import asyncio
import logging
from typing import Optional, Dict, Callable
from dataclasses import dataclass
from contextlib import asynccontextmanager

# Optional import - gracefully handle if playwright not installed
try:
    from playwright.async_api import async_playwright, Browser
except ImportError:
    async_playwright = None
    Browser = None

logger = logging.getLogger(__name__)


@dataclass
class XSSFinding:
    """XSS vulnerability finding"""
    type: str  # "reflected" or "dom"
    target: str
    endpoint: str
    param: str
    payload: str
    evidence: str
    confidence: float
    browser_confirmed: bool = False


class BrowserPool:
    """
    Elegant browser pool management:
    - Pre-launched browser instances for reduced startup time
    - Memory leak prevention: restart after N requests
    - Async-safe acquire/release
    """
    
    def __init__(
        self, 
        size: int = 5,
        max_requests_per_browser: int = 100,
        headless: bool = True
    ):
        self.size = size
        self.max_requests = max_requests_per_browser
        self.headless = headless
        
        self._pool: asyncio.Queue[Browser] = asyncio.Queue()
        self._request_counts: Dict[int, int] = {}
        self._playwright = None
        self._initialized = False
        self._lock = asyncio.Lock()
    
    async def initialize(self):
        """Initialize browser pool"""
        if self._initialized:
            return
        
        if async_playwright is None:
            raise ImportError(
                "playwright is required for XSS detection. "
                "Install with: pip install playwright && playwright install chromium"
            )
        
        self._playwright = await async_playwright().start()
        
        # Launch initial browsers
        for _ in range(self.size):
            browser = await self._launch_browser()
            await self._pool.put(browser)
            self._request_counts[id(browser)] = 0
        
        self._initialized = True
        logger.info(f"Browser pool initialized: {self.size} browsers")
    
    async def _launch_browser(self) -> Browser:
        """Launch a new browser instance"""
        chromium = self._playwright.chromium
        
        # Memory-stable chromium options
        browser = await chromium.launch(
            headless=self.headless,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-web-security",
                "--disable-features=IsolateOrigins,site-per-process",
            ]
        )
        
        return browser
    
    @asynccontextmanager
    async def acquire(self):
        """
        Acquire browser from pool with automatic restart
        
        Usage:
            async with browser_pool.acquire() as browser:
                page = await browser.new_page()
                ...
        """
        await self.initialize()
        
        browser = await self._pool.get()
        browser_id = id(browser)
        
        try:
            # Check if browser needs restart (memory leak prevention)
            if self._request_counts[browser_id] >= self.max_requests:
                logger.info(f"Restarting browser {browser_id} after {self.max_requests} requests")
                await browser.close()
                browser = await self._launch_browser()
                browser_id = id(browser)
                self._request_counts[browser_id] = 0
            
            self._request_counts[browser_id] += 1
            yield browser
            
        finally:
            await self._pool.put(browser)
    
    async def close(self):
        """Close all browsers and cleanup"""
        if not self._initialized:
            return
        
        # Close all browsers in pool
        while not self._pool.empty():
            try:
                browser = self._pool.get_nowait()
                await browser.close()
            except asyncio.QueueEmpty:
                break
        
        if self._playwright:
            await self._playwright.stop()
        
        self._initialized = False
        logger.info("Browser pool closed")


class XSSDetectionEngine:
    """
    XSS detection with browser-based confirmation
    - Reflected XSS: Check if payload appears in response
    - DOM XSS: Browser execution confirmation
    """
    
    def __init__(self, browser_pool: Optional[BrowserPool] = None):
        self.browser_pool = browser_pool or BrowserPool()
        self._confirmed_payloads: set = set()
    
    async def detect_reflected_xss(
        self,
        url: str,
        param: str,
        payload: str,
        response_text: str
    ) -> Optional[XSSFinding]:
        """
        Detect reflected XSS by checking if payload appears in response
        """
        # Simple check: is payload reflected?
        if payload not in response_text:
            return None
        
        # More sophisticated: check if payload is executable
        # (would need HTML parsing to check context)
        
        return XSSFinding(
            type="reflected",
            target=url,
            endpoint=url,
            param=param,
            payload=payload,
            evidence=f"Payload reflected in response: {payload[:100]}",
            confidence=0.7,
            browser_confirmed=False
        )
    
    async def detect_dom_xss(
        self,
        url: str,
        param: str,
        payload: str,
        confirmation_callback: Optional[Callable] = None
    ) -> Optional[XSSFinding]:
        """
        Detect DOM XSS using browser execution
        
        Confirms XSS by checking if JavaScript executes in browser
        """
        async with self.browser_pool.acquire() as browser:
            page = await browser.new_page()
            
            try:
                # Inject detection hook
                await page.add_init_script("""
                    window.__xss_detected = false;
                    window.__xss_payload = null;
                    
                    // Hook common XSS sinks
                    document.originalWrite = document.write;
                    document.write = function(content) {
                        window.__xss_detected = true;
                        window.__xss_payload = content;
                        return document.originalWrite(content);
                    };
                    
                    // Hook eval
                    window.originalEval = window.eval;
                    window.eval = function(code) {
                        window.__xss_detected = true;
                        window.__xss_payload = code;
                        return window.originalEval(code);
                    };
                """)
                
                # Navigate to URL with payload
                payload_url = f"{url}?{param}={payload}"
                await page.goto(payload_url)
                
                # Wait a moment for JavaScript execution
                await asyncio.sleep(0.5)
                
                # Check if XSS was detected
                xss_detected = await page.evaluate("window.__xss_detected")
                
                if xss_detected:
                    xss_payload = await page.evaluate("window.__xss_payload")
                    
                    return XSSFinding(
                        type="dom",
                        target=url,
                        endpoint=url,
                        param=param,
                        payload=payload,
                        evidence=f"JavaScript executed: {xss_payload[:200]}",
                        confidence=0.95,
                        browser_confirmed=True
                    )
                
                return None
                
            finally:
                await page.close()
    
    async def close(self):
        """Cleanup resources"""
        await self.browser_pool.close()


# Convenience functions

async def create_xss_detector() -> XSSDetectionEngine:
    """Create XSS detector with default browser pool"""
    pool = BrowserPool(size=5, max_requests_per_browser=100)
    await pool.initialize()
    return XSSDetectionEngine(pool)


# Global instance
_xss_detector: Optional[XSSDetectionEngine] = None


async def get_xss_detector() -> XSSDetectionEngine:
    """Get or create global XSS detector"""
    global _xss_detector
    if _xss_detector is None:
        _xss_detector = await create_xss_detector()
    return _xss_detector
