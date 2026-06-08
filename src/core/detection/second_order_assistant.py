"""
Second-Order SQLi Assistant for SHIGOKU Phase D
Human-assisted detection: AI identifies candidates, human confirms
"""
from __future__ import annotations
import asyncio
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class SecondOrderConfidence(str, Enum):
    """Confidence levels for Second-Order hints"""
    HIGH = "high"      # Strong indicators present
    MEDIUM = "medium"  # Some indicators present
    LOW = "low"        # Weak indicators


@dataclass
class ManualTestStep:
    """Step for manual testing"""
    step_number: int
    description: str
    action: str
    expected_result: str
    verification_method: str


@dataclass
class SecondOrderHint:
    """
    AI-generated hint for Second-Order SQLi
    
    AI role: Identify candidates, suggest tests, monitor
    Human role: Execute tests, make final judgment
    """
    correlation_id: str
    confidence: SecondOrderConfidence
    reasoning: str
    
    # Storage endpoint (injection point)
    storage_endpoint: str
    storage_method: str
    storage_param: str
    
    # Potential display endpoints
    potential_display_endpoints: List[str]
    
    # Suggested manual tests
    suggested_manual_tests: List[ManualTestStep]
    
    # AI assistance offered
    ai_assistance_offered: List[str] = field(default_factory=list)
    
    # Monitoring
    monitoring_recommended: bool = True
    monitoring_duration_seconds: int = 300
    
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "confidence": self.confidence.value,
            "reasoning": self.reasoning,
            "storage_endpoint": self.storage_endpoint,
            "potential_display_endpoints": self.potential_display_endpoints,
            "suggested_tests": [
                {
                    "step": t.step_number,
                    "description": t.description,
                    "action": t.action,
                    "expected": t.expected_result,
                    "verify": t.verification_method,
                }
                for t in self.suggested_manual_tests
            ],
            "ai_assistance": self.ai_assistance_offered,
            "monitoring": {
                "recommended": self.monitoring_recommended,
                "duration_seconds": self.monitoring_duration_seconds,
            },
        }


@dataclass
class MonitoringObservation:
    """Observation during Second-Order monitoring"""
    timestamp: float
    endpoint: str
    evidence: str
    confidence: str  # "high" or "medium"


@dataclass
class MonitoringResult:
    """Result of Second-Order monitoring session"""
    correlation_id: str
    observations: List[MonitoringObservation]
    duration_seconds: float
    summary: str
    
    @property
    def has_suspicious_activity(self) -> bool:
        return len(self.observations) > 0


class SecondOrderAssistant:
    """
    Human-assisted Second-Order SQLi detection
    
    DESIGN PRINCIPLE:
    - Second-Order SQLi cannot be reliably automated
    - AI assists with: candidate identification, monitoring, evidence correlation
    - Human executes: actual testing, final judgment
    
    Workflow:
    1. AI analyzes endpoint for Second-Order indicators
    2. AI generates hint with suggested manual tests
    3. Human executes manual tests
    4. AI monitors for delayed effects
    5. AI correlates observations with human
    """
    
    def __init__(self, http_client=None):
        self.http_client = http_client
        self._active_hints: Dict[str, SecondOrderHint] = {}
        self._monitoring_tasks: Dict[str, asyncio.Task] = {}
    
    async def analyze_potential_second_order(
        self,
        finding: Dict[str, Any]
    ) -> Optional[SecondOrderHint]:
        """
        Analyze if finding is a potential Second-Order SQLi candidate
        
        AI analyzes:
        - Is it a storage endpoint (POST/PUT)?
        - Does it save user input?
        - Are there potential display endpoints?
        """
        endpoint = finding.get("endpoint", "")
        method = finding.get("method", "GET").upper()
        param = finding.get("param", "")
        
        # Analyze storage indicators
        storage_indicators = self._analyze_storage_indicators(
            endpoint, method, finding
        )
        
        if not storage_indicators["is_likely_storage"]:
            return None  # Not a storage endpoint
        
        # Find potential display endpoints
        display_endpoints = await self._find_potential_display_endpoints(
            finding.get("target", ""),
            param
        )
        
        if not display_endpoints:
            return None  # No display endpoints found
        
        # Calculate confidence
        confidence = self._calculate_confidence(storage_indicators)
        
        # Generate correlation ID
        correlation_id = f"so-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{endpoint[:20]}"
        
        # Create hint
        hint = SecondOrderHint(
            correlation_id=correlation_id,
            confidence=confidence,
            reasoning=self._format_reasoning(finding, storage_indicators, display_endpoints),
            storage_endpoint=endpoint,
            storage_method=method,
            storage_param=param,
            potential_display_endpoints=display_endpoints[:5],  # Limit to 5
            suggested_manual_tests=self._generate_manual_tests(
                endpoint, method, param, display_endpoints
            ),
            ai_assistance_offered=[
                "Auto-poll display endpoints every 30 seconds",
                "Detect response changes vs baseline",
                "Monitor for OOB callbacks",
                "Alert on suspicious patterns"
            ],
            monitoring_recommended=True,
            monitoring_duration_seconds=300,  # 5 minutes
        )
        
        self._active_hints[correlation_id] = hint
        
        logger.info(f"Generated Second-Order hint: {correlation_id} ({confidence.value})")
        
        return hint
    
    def _analyze_storage_indicators(
        self,
        endpoint: str,
        method: str,
        finding: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze if endpoint is likely a storage endpoint"""
        indicators = {
            "is_likely_storage": False,
            "indicators_found": [],
            "score": 0,
        }
        
        # Check HTTP method
        if method in ["POST", "PUT", "PATCH"]:
            indicators["indicators_found"].append("write_method")
            indicators["score"] += 2
        
        # Check endpoint path
        storage_keywords = [
            "save", "create", "update", "store", "add", "edit",
            "submit", "post", "put", "write"
        ]
        
        endpoint_lower = endpoint.lower()
        for keyword in storage_keywords:
            if keyword in endpoint_lower:
                indicators["indicators_found"].append(f"path_keyword:{keyword}")
                indicators["score"] += 1
        
        # Check if endpoint returns success message
        response = finding.get("response", "")
        success_indicators = ["saved", "created", "success", "added", "updated"]
        for indicator in success_indicators:
            if indicator in response.lower():
                indicators["indicators_found"].append(f"success_indicator:{indicator}")
                indicators["score"] += 2
        
        # Determine likelihood
        if indicators["score"] >= 3:
            indicators["is_likely_storage"] = True
        
        return indicators
    
    async def _find_potential_display_endpoints(
        self,
        target: str,
        saved_param: str
    ) -> List[str]:
        """
        Find potential display endpoints where saved data might appear
        
        Heuristics:
        - Pages with "view", "show", "get", "read" in path
        - Pages with "id" parameter
        - Dashboard, profile, history pages
        """
        # Simplified: return common patterns
        # Real implementation would crawl and analyze
        
        potential = [
            f"{target}/view",
            f"{target}/show",
            f"{target}/dashboard",
            f"{target}/profile",
            f"{target}/history",
            f"{target}/list",
        ]
        
        return potential
    
    def _calculate_confidence(
        self,
        storage_indicators: Dict[str, Any]
    ) -> SecondOrderConfidence:
        """Calculate confidence level based on indicators"""
        score = storage_indicators.get("score", 0)
        
        if score >= 5:
            return SecondOrderConfidence.HIGH
        elif score >= 3:
            return SecondOrderConfidence.MEDIUM
        else:
            return SecondOrderConfidence.LOW
    
    def _format_reasoning(
        self,
        finding: Dict[str, Any],
        storage_indicators: Dict[str, Any],
        display_endpoints: List[str]
    ) -> str:
        """Format reasoning for human reviewer"""
        indicators = ", ".join(storage_indicators.get("indicators_found", []))
        
        return (
            f"Storage endpoint detected with indicators: {indicators}. "
            f"Found {len(display_endpoints)} potential display endpoints. "
            f"Second-Order SQLi possible if injected data is later retrieved."
        )
    
    def _generate_manual_tests(
        self,
        storage_endpoint: str,
        method: str,
        param: str,
        display_endpoints: List[str]
    ) -> List[ManualTestStep]:
        """Generate suggested manual test steps"""
        
        tests = [
            ManualTestStep(
                step_number=1,
                description="Inject Second-Order payload to storage endpoint",
                action=f"{method} {storage_endpoint} with {param}='; WAITFOR DELAY '0:0:5'--",
                expected_result="Request succeeds, payload stored",
                verification_method="Check for success response (200 OK)"
            ),
            ManualTestStep(
                step_number=2,
                description="Access potential display endpoint immediately",
                action=f"GET {display_endpoints[0] if display_endpoints else '/view'}",
                expected_result="Response may or may not show delay",
                verification_method="Measure response time (should be normal)"
            ),
            ManualTestStep(
                step_number=3,
                description="Wait for potential delayed processing",
                action="Wait 30 seconds to 5 minutes",
                expected_result="Background job may process stored data",
                verification_method="Use AI monitoring or manual recheck"
            ),
            ManualTestStep(
                step_number=4,
                description="Re-access display endpoint",
                action=f"GET {display_endpoints[0] if display_endpoints else '/view'}",
                expected_result="If Second-Order exists: 5+ second delay observed",
                verification_method="Compare response time to baseline"
            ),
        ]
        
        return tests
    
    async def monitor_for_second_order(
        self,
        hint: SecondOrderHint,
        human_callback: Optional[callable] = None
    ) -> MonitoringResult:
        """
        Monitor for Second-Order effects
        
        AI monitors while human is testing:
        - Poll display endpoints
        - Detect response time changes
        - Look for payload traces
        """
        correlation_id = hint.correlation_id
        start_time = asyncio.get_event_loop().time()
        observations: List[MonitoringObservation] = []
        
        logger.info(f"Starting Second-Order monitoring: {correlation_id}")
        
        end_time = start_time + hint.monitoring_duration_seconds
        
        while asyncio.get_event_loop().time() < end_time:
            for endpoint in hint.potential_display_endpoints:
                try:
                    # Poll endpoint
                    response = await self._poll_endpoint(endpoint)
                    
                    # Check for payload traces
                    if self._payload_traces_found(response, hint.storage_param):
                        obs = MonitoringObservation(
                            timestamp=asyncio.get_event_loop().time(),
                            endpoint=endpoint,
                            evidence=response[:1000],
                            confidence="high"
                        )
                        observations.append(obs)
                        
                        # Notify human
                        if human_callback:
                            await human_callback(
                                f"Second-Order trace detected at {endpoint}",
                                obs
                            )
                    
                except Exception as e:
                    logger.debug(f"Monitoring poll error: {e}")
            
            await asyncio.sleep(30)  # 30 second interval
        
        duration = asyncio.get_event_loop().time() - start_time
        
        result = MonitoringResult(
            correlation_id=correlation_id,
            observations=observations,
            duration_seconds=duration,
            summary=f"{len(observations)} suspicious observations in {duration:.0f}s"
        )
        
        logger.info(f"Monitoring complete: {result.summary}")
        
        return result
    
    async def _poll_endpoint(self, endpoint: str) -> str:
        """Poll endpoint for monitoring"""
        # Placeholder: real implementation would use HTTP client
        # Return empty for now
        return ""
    
    def _payload_traces_found(self, response: str, payload_param: str) -> bool:
        """Check if payload traces exist in response"""
        # Simplified check
        suspicious_patterns = [
            "error", "exception", "syntax", "sql", "mysql", "postgresql",
            "oracle", "sqlite", "delay", "sleep", "waitfor"
        ]
        
        response_lower = response.lower()
        return any(p in response_lower for p in suspicious_patterns)
    
    def get_active_hint(self, correlation_id: str) -> Optional[SecondOrderHint]:
        """Get active hint by correlation ID"""
        return self._active_hints.get(correlation_id)
    
    def list_active_hints(self) -> List[SecondOrderHint]:
        """List all active Second-Order hints"""
        return list(self._active_hints.values())


# Convenience functions

async def analyze_second_order_candidate(
    finding: Dict[str, Any]
) -> Optional[SecondOrderHint]:
    """
    Analyze finding for Second-Order SQLi potential
    
    Usage:
        hint = await analyze_second_order_candidate(finding)
        if hint:
            print(f"Potential Second-Order: {hint.reasoning}")
            for step in hint.suggested_manual_tests:
                print(f"Step {step.step_number}: {step.description}")
    """
    assistant = SecondOrderAssistant()
    return await assistant.analyze_potential_second_order(finding)
