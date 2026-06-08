"""
Behavioral MockWAF for SHIGOKU Phase D
Elegant WAF simulation with real-world behavior collection
"""
from __future__ import annotations
import asyncio
import time
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


@dataclass
class WAFBehavior:
    """Single WAF behavior observation"""
    payload: str
    blocked: bool
    block_type: str  # "waf", "rate_limit", "challenge"
    challenge_presented: bool
    response_time: float
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class WAFBehaviorProfile:
    """Collected WAF behavior profile"""
    waf_type: str  # "cloudflare", "aws", "akamai", etc.
    behaviors: List[WAFBehavior] = field(default_factory=list)
    collected_at: datetime = field(default_factory=datetime.utcnow)
    
    def get_block_rate(self) -> float:
        """Calculate observed block rate"""
        if not self.behaviors:
            return 0.0
        blocked = sum(1 for b in self.behaviors if b.blocked)
        return blocked / len(self.behaviors)
    
    def get_avg_response_time(self) -> float:
        """Calculate average response time"""
        if not self.behaviors:
            return 0.0
        return sum(b.response_time for b in self.behaviors) / len(self.behaviors)


class WAFBehaviorCollector(ABC):
    """Abstract base for WAF behavior collection"""
    
    @abstractmethod
    async def collect(
        self, 
        test_payloads: List[str],
        target_url: str
    ) -> WAFBehaviorProfile:
        """Collect WAF behavior by sending test payloads"""
        pass


class ThrottledWAFBehaviorCollector(WAFBehaviorCollector):
    """
    Throttled WAF behavior collector
    
    Features:
    - Rate limiting (5 second interval)
    - Error handling for WAF blocks
    - Real-world behavior collection
    """
    
    def __init__(
        self,
        min_interval: float = 5.0,  # 5 seconds between requests
        max_retries: int = 3
    ):
        self.min_interval = min_interval
        self.max_retries = max_retries
        self._last_request_time = 0.0
        self._lock = asyncio.Lock()
    
    async def collect(
        self,
        test_payloads: List[str],
        target_url: str
    ) -> WAFBehaviorProfile:
        """
        Collect WAF behavior with throttling
        
        Args:
            test_payloads: List of payloads to test
            target_url: Target URL with WAF
        
        Returns:
            WAFBehaviorProfile with collected behaviors
        """
        import aiohttp
        
        behaviors = []
        
        for payload in test_payloads:
            async with self._lock:
                # Enforce rate limit
                elapsed = time.time() - self._last_request_time
                if elapsed < self.min_interval:
                    wait_time = self.min_interval - elapsed
                    logger.debug(f"Rate limiting: waiting {wait_time:.1f}s")
                    await asyncio.sleep(wait_time)
                
                try:
                    behavior = await self._send_test_payload(
                        target_url, payload
                    )
                    behaviors.append(behavior)
                    
                except WAFBlockError:
                    logger.warning(f"WAF blocked during collection for payload: {payload[:50]}")
                    # Record the block
                    behaviors.append(WAFBehavior(
                        payload=payload,
                        blocked=True,
                        block_type="waf",
                        challenge_presented=False,
                        response_time=0.0
                    ))
                
                except Exception as e:
                    logger.error(f"Collection error: {e}")
                
                finally:
                    self._last_request_time = time.time()
        
        return WAFBehaviorProfile(
            waf_type="detected",
            behaviors=behaviors
        )
    
    async def _send_test_payload(
        self,
        target_url: str,
        payload: str
    ) -> WAFBehavior:
        """Send single test payload and observe behavior"""
        import aiohttp
        
        # Add payload to URL
        test_url = f"{target_url}?test={payload}"
        
        start_time = time.time()
        
        async with aiohttp.ClientSession() as session:
            async with session.get(test_url) as response:
                elapsed = time.time() - start_time
                
                # Determine if blocked
                blocked = response.status in (403, 406, 429)
                challenge = "cf-challenge" in await response.text()
                
                return WAFBehavior(
                    payload=payload,
                    blocked=blocked,
                    block_type=self._classify_block(response.status),
                    challenge_presented=challenge,
                    response_time=elapsed
                )
    
    def _classify_block(self, status: int) -> str:
        """Classify block type from HTTP status"""
        if status == 403:
            return "waf"
        elif status == 429:
            return "rate_limit"
        elif status == 406:
            return "challenge"
        return "none"


class WAFBlockError(Exception):
    """Raised when WAF blocks test during collection"""
    pass


class BehavioralMockWAF:
    """
    Behavioral MockWAF based on real-world observations
    
    Features:
    - ML-based block prediction (placeholder for actual ML)
    - Rule-based fallback
    - Periodic updates from real WAF
    """
    
    def __init__(
        self,
        behavior_profile: Optional[WAFBehaviorProfile] = None,
        collector: Optional[ThrottledWAFBehaviorCollector] = None
    ):
        self.profile = behavior_profile
        self.collector = collector or ThrottledWAFBehaviorCollector()
        self._block_patterns: List[str] = []
        self._update_task: Optional[asyncio.Task] = None
        
        if behavior_profile:
            self._update_patterns()
    
    def _update_patterns(self):
        """Extract block patterns from behavior profile"""
        if not self.profile:
            return
        
        # Extract payloads that were blocked
        blocked_payloads = [
            b.payload for b in self.profile.behaviors
            if b.blocked
        ]
        
        # Simple pattern extraction (keywords, etc.)
        # In real implementation, this would use ML
        self._block_patterns = self._extract_patterns(blocked_payloads)
    
    def _extract_patterns(self, payloads: List[str]) -> List[str]:
        """Extract common patterns from blocked payloads"""
        # Simplified: look for common SQLi/XSS keywords
        keywords = [
            "union", "select", "insert", "delete", "drop",
            "script", "alert", "onerror", "javascript",
            "../../", "../..", "..\\..",
        ]
        
        found = []
        for kw in keywords:
            if any(kw.lower() in p.lower() for p in payloads):
                found.append(kw)
        
        return found
    
    def predict_block(self, payload: str) -> tuple[bool, float]:
        """
        Predict if payload would be blocked
        
        Returns:
            (would_block, confidence)
        """
        if not self._block_patterns:
            return False, 0.0
        
        # Simple rule-based prediction
        # In real implementation, this would use trained classifier
        matches = sum(1 for p in self._block_patterns if p.lower() in payload.lower())
        
        if matches == 0:
            return False, 0.9
        
        # More matches = higher block probability
        confidence = min(0.5 + (matches * 0.1), 0.95)
        return True, confidence
    
    async def simulate_request(
        self,
        payload: str,
        base_response_time: float = 0.1
    ) -> Dict[str, Any]:
        """
        Simulate WAF response to request
        
        Returns simulated response similar to real WAF
        """
        would_block, confidence = self.predict_block(payload)
        
        if would_block and confidence > 0.7:
            # Simulate block
            return {
                "blocked": True,
                "status_code": 403,
                "response_time": base_response_time * 0.5,  # Fast block
                "confidence": confidence,
                "rule_matched": "behavioral_prediction"
            }
        
        # Simulate pass-through
        return {
            "blocked": False,
            "status_code": 200,
            "response_time": base_response_time * (1 + confidence),
            "confidence": confidence,
            "rule_matched": None
        }
    
    async def start_periodic_update(
        self,
        target_url: str,
        test_payloads: List[str],
        interval_hours: int = 24
    ):
        """
        Start periodic update of behavior profile
        
        Collects fresh WAF behavior data periodically
        """
        async def update_loop():
            while True:
                try:
                    await asyncio.sleep(interval_hours * 3600)
                    
                    logger.info("Starting periodic WAF behavior update")
                    
                    new_profile = await self.collector.collect(
                        test_payloads, target_url
                    )
                    
                    self.profile = new_profile
                    self._update_patterns()
                    
                    logger.info("WAF behavior profile updated")
                    
                except WAFBlockError:
                    logger.warning("WAF blocked during update - skipping this cycle")
                except Exception as e:
                    logger.error(f"Periodic update error: {e}")
        
        self._update_task = asyncio.create_task(update_loop())
    
    async def stop_periodic_update(self):
        """Stop periodic updates"""
        if self._update_task:
            self._update_task.cancel()
            try:
                await self._update_task
            except asyncio.CancelledError:
                pass


class BinarySearchParamDiscovery:
    """
    Binary search for array index parameter discovery
    
    Reduces requests from N to log2(N)
    Example: 100 indices -> 7 requests
    """
    
    async def discover_valid_indices(
        self,
        base_param: str,
        test_function: callable,
        max_index: int = 100
    ) -> List[int]:
        """
        Discover valid array indices using binary search
        
        Args:
            base_param: Base parameter name (e.g., "items")
            test_function: Async function(index) -> bool (True if index valid)
            max_index: Maximum index to search
        
        Returns:
            List of valid indices
        """
        valid_indices = []
        
        # Binary search to find upper bound
        low, high = 0, max_index
        
        while low < high:
            mid = (low + high) // 2
            
            param_name = f"{base_param}[{mid}]"
            is_valid = await test_function(param_name)
            
            if is_valid:
                valid_indices.append(mid)
                # Look for more valid indices above
                low = mid + 1
            else:
                # Index not valid, look below
                high = mid
        
        # Sort and return
        return sorted(valid_indices)
    
    async def discover_with_exponential_probe(
        self,
        base_param: str,
        test_function: callable
    ) -> List[int]:
        """
        Discover indices using exponential probing then binary search
        
        More efficient when valid indices are sparse
        """
        # First, find rough upper bound with exponential probe
        bound = 1
        while await test_function(f"{base_param}[{bound}]"):
            bound *= 2
            if bound > 10000:  # Safety limit
                break
        
        # Then binary search within [bound/2, bound]
        return await self.discover_valid_indices(
            base_param, test_function, bound
        )


# Convenience functions

async def create_behavioral_mock_waf(
    target_url: str,
    test_payloads: Optional[List[str]] = None
) -> BehavioralMockWAF:
    """
    Create behavioral MockWAF with initial data collection
    
    Usage:
        mock_waf = await create_behavioral_mock_waf("https://example.com")
        prediction = mock_waf.predict_block("' OR 1=1 --")
    """
    collector = ThrottledWAFBehaviorCollector()
    
    default_payloads = test_payloads or [
        "test",
        "'",
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
    ]
    
    # Initial collection
    profile = await collector.collect(default_payloads, target_url)
    
    mock = BehavioralMockWAF(profile, collector)
    
    # Start periodic updates
    await mock.start_periodic_update(target_url, default_payloads)
    
    return mock
