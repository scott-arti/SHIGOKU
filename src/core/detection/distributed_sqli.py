"""
Distributed SQLi Guesser for SHIGOKU Phase D
Header correlation-based detection for microservice SQLi
"""
from __future__ import annotations
import asyncio
import uuid
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class DistributedSQLiHint:
    """
    Hint for potential distributed SQLi
    
    AI analyzes header correlation between services.
    Human confirms by manual testing.
    """
    correlation_id: str
    entry_point: str
    affected_endpoint: str
    correlation_method: str  # "header_correlation"
    confidence: str  # "medium" - estimation-based
    evidence: str
    requires_human_verification: bool = True  # Always requires confirmation
    
    # Suggested verification
    verification_steps: List[str] = field(default_factory=list)
    
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "entry_point": self.entry_point,
            "affected_endpoint": self.affected_endpoint,
            "correlation_method": self.correlation_method,
            "confidence": self.confidence,
            "evidence": self.evidence[:500],
            "requires_human_verification": self.requires_human_verification,
            "verification_steps": self.verification_steps,
        }


@dataclass
class HeaderInjection:
    """Header-based injection attempt"""
    correlation_id: str
    headers: Dict[str, str]
    payload: str
    timestamp: str


class DistributedSQLiGuesser:
    """
    Guess distributed SQLi via HTTP header correlation
    
    DESIGN PRINCIPLE:
    - Microservice architectures may pass data via headers
    - SQLi in one service can affect another via header propagation
    - AI estimates correlation, human confirms
    
    Method: Inject unique correlation ID via headers
            Check if ID appears in other endpoints' responses
    """
    
    def __init__(self, http_client=None):
        self.http_client = http_client
        self._active_correlations: Dict[str, HeaderInjection] = {}
        self._discovered_hints: List[DistributedSQLiHint] = []
    
    async def analyze_header_correlation(
        self,
        entry_endpoint: str,
        potential_targets: List[str],
        headers_to_test: Optional[List[str]] = None
    ) -> List[DistributedSQLiHint]:
        """
        Analyze distributed SQLi potential via header correlation
        
        Args:
            entry_endpoint: Endpoint to inject correlation ID
            potential_targets: Other endpoints to check for correlation
            headers_to_test: Headers to inject (default: common propagation headers)
        
        Returns:
            List of hints requiring human verification
        """
        hints = []
        
        # Generate unique correlation ID
        correlation_id = f"dist-{uuid.uuid4().hex[:8]}"
        
        # Default headers that commonly propagate between services
        default_headers = [
            "X-Request-ID",
            "X-Correlation-ID",
            "X-Trace-ID",
            "X-Session-ID",
            "X-User-ID",
        ]
        
        test_headers = headers_to_test or default_headers
        
        # Inject correlation ID via headers
        for header_name in test_headers:
            injection_headers = {
                header_name: correlation_id,
                "X-Shigoku-Test": "distributed-sqli-check"
            }
            
            try:
                # Send request with injected header
                await self._send_with_headers(entry_endpoint, injection_headers)
                
                # Record injection
                injection = HeaderInjection(
                    correlation_id=correlation_id,
                    headers=injection_headers,
                    payload=f"{header_name}: {correlation_id}",
                    timestamp=datetime.utcnow().isoformat()
                )
                self._active_correlations[correlation_id] = injection
                
                # Check other endpoints for correlation ID
                for target in potential_targets:
                    hint = await self._check_for_correlation(
                        correlation_id, entry_endpoint, target
                    )
                    
                    if hint:
                        hints.append(hint)
                        self._discovered_hints.append(hint)
                
            except Exception as e:
                logger.warning(f"Header injection failed for {header_name}: {e}")
        
        return hints
    
    async def _send_with_headers(
        self,
        endpoint: str,
        headers: Dict[str, str]
    ):
        """Send request with custom headers"""
        # Placeholder: real implementation would use HTTP client
        logger.debug(f"Sending to {endpoint} with headers: {list(headers.keys())}")
    
    async def _check_for_correlation(
        self,
        correlation_id: str,
        entry_point: str,
        target_endpoint: str
    ) -> Optional[DistributedSQLiHint]:
        """
        Check if correlation ID appears in target endpoint response
        
        If found, suggests data propagation between services
        """
        try:
            # Poll target endpoint
            response = await self._poll_endpoint(target_endpoint)
            
            # Check if correlation ID appears in response
            if correlation_id in response:
                # Evidence of header propagation found
                return DistributedSQLiHint(
                    correlation_id=correlation_id,
                    entry_point=entry_point,
                    affected_endpoint=target_endpoint,
                    correlation_method="header_correlation",
                    confidence="medium",
                    evidence=f"Correlation ID '{correlation_id}' found in response from {target_endpoint}",
                    requires_human_verification=True,
                    verification_steps=[
                        f"1. Inject SQL payload via header to {entry_point}",
                        f"2. Check if SQL error appears in {target_endpoint}",
                        f"3. Verify with time-based payload if possible",
                        f"4. Check logs for cross-service query execution"
                    ]
                )
            
        except Exception as e:
            logger.debug(f"Correlation check failed: {e}")
        
        return None
    
    async def _poll_endpoint(self, endpoint: str) -> str:
        """Poll endpoint and return response"""
        # Placeholder: real implementation would use HTTP client
        return ""
    
    async def verify_with_sqli_payload(
        self,
        hint: DistributedSQLiHint,
        payload: str = "' OR '1'='1"
    ) -> Dict[str, Any]:
        """
        Verify distributed SQLi with actual payload
        
        HUMAN VERIFICATION REQUIRED:
        This actually attempts SQL injection and should only
        be run with explicit human approval.
        """
        logger.warning(
            f"Attempting distributed SQLi verification: {hint.correlation_id}. "
            "Ensure proper authorization before proceeding."
        )
        
        # Re-inject with SQL payload
        injection_headers = {
            "X-Request-ID": payload,
        }
        
        try:
            await self._send_with_headers(hint.entry_point, injection_headers)
            
            # Check target for SQL error indicators
            response = await self._poll_endpoint(hint.affected_endpoint)
            
            sql_error_indicators = [
                "sql", "mysql", "postgresql", "oracle", "sqlite",
                "syntax error", "unexpected", "near",
            ]
            
            found_indicators = [
                ind for ind in sql_error_indicators
                if ind.lower() in response.lower()
            ]
            
            return {
                "verified": len(found_indicators) > 0,
                "indicators_found": found_indicators,
                "evidence": response[:500] if found_indicators else None,
                "note": "Human confirmation still required for bounty submission"
            }
            
        except Exception as e:
            return {
                "verified": False,
                "error": str(e)
            }
    
    def get_hints_for_endpoint(self, endpoint: str) -> List[DistributedSQLiHint]:
        """Get all hints involving specific endpoint"""
        return [
            h for h in self._discovered_hints
            if h.entry_point == endpoint or h.affected_endpoint == endpoint
        ]
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate report of discovered distributed SQLi candidates"""
        return {
            "total_hints": len(self._discovered_hints),
            "by_confidence": {
                "medium": len([h for h in self._discovered_hints if h.confidence == "medium"]),
            },
            "hints": [h.to_dict() for h in self._discovered_hints],
            "disclaimer": (
                "All hints require human verification. "
                "Automated verification requires explicit authorization."
            )
        }


class HeaderCorrelationDetector:
    """
    Alternative implementation with simplified interface
    """
    
    async def detect_distributed_sqli(
        self,
        entry_endpoint: str,
        max_index: int = 100
    ) -> List[DistributedSQLiHint]:
        """
        Detect distributed SQLi via header correlation
        
        Simplified interface for common use case
        """
        guesser = DistributedSQLiGuesser()
        
        # Generate potential target endpoints from entry point
        potential_targets = self._derive_targets(entry_endpoint)
        
        return await guesser.analyze_header_correlation(
            entry_endpoint,
            potential_targets
        )
    
    def _derive_targets(self, entry_endpoint: str) -> List[str]:
        """Derive potential target endpoints from entry point"""
        # Simplified: return variations
        base = entry_endpoint.rstrip("/")
        
        return [
            f"{base}/view",
            f"{base}/detail",
            f"{base}/status",
            f"{base}/result",
        ]


# Convenience functions

async def check_distributed_sqli(
    entry_endpoint: str,
    target_endpoints: Optional[List[str]] = None
) -> List[DistributedSQLiHint]:
    """
    Check for distributed SQLi via header correlation
    
    Usage:
        hints = await check_distributed_sqli("/api/users")
        for hint in hints:
            print(f"Potential distributed SQLi: {hint.affected_endpoint}")
            print(f"Verification steps: {hint.verification_steps}")
    """
    guesser = DistributedSQLiGuesser()
    
    targets = target_endpoints or []
    
    return await guesser.analyze_header_correlation(
        entry_endpoint,
        targets
    )
