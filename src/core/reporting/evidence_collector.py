"""
Evidence Collection Engine for SHIGOKU Phase D
Elegant vulnerability evidence gathering with scope boundary enforcement
"""
from __future__ import annotations
import asyncio
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class EvidenceScope(str, Enum):
    """Evidence collection scope levels"""
    PRESENCE_ONLY = "presence_only"      # Confirm vulnerability exists
    VERSION_INFO = "version_info"        # Extract version/tech stack
    SAMPLE_DATA = "sample_data"          # Extract sample record (LIMIT 1)
    FULL_EXTRACTION = "full_extraction"  # Extract multiple records


@dataclass
class Evidence:
    """
    Vulnerability evidence with scope enforcement
    
    CRITICAL: Bug Bounty programs have varying scopes.
    Automatic data extraction can violate program policies.
    This class enforces scope boundaries.
    """
    vulnerability_type: str
    affected_endpoint: str
    payload_used: str
    response_evidence: str  # Truncated response
    timestamp: str
    reproduction_steps: List[str] = field(default_factory=list)
    
    # Scope-controlled fields
    extracted_data: Optional[Any] = None  # HITL approval required
    data_extraction_approved: bool = False
    scope_level: EvidenceScope = EvidenceScope.PRESENCE_ONLY
    
    # Metadata
    scan_session_id: str = ""
    confidence_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for serialization"""
        return {
            "vulnerability_type": self.vulnerability_type,
            "affected_endpoint": self.affected_endpoint,
            "payload_used": self.payload_used[:1000],  # Truncate
            "response_evidence": self.response_evidence[:1000],
            "timestamp": self.timestamp,
            "reproduction_steps": self.reproduction_steps,
            "extracted_data": "[REDACTED - HITL Review Required]" 
                if self.extracted_data and not self.data_extraction_approved 
                else self.extracted_data,
            "data_extraction_approved": self.data_extraction_approved,
            "scope_level": self.scope_level.value,
            "confidence_score": self.confidence_score,
        }


class HITLEngine:
    """Placeholder for HITL approval requests"""
    
    async def request_data_extraction_approval(
        self,
        finding: Dict[str, Any],
        reason: str
    ) -> bool:
        """
        Request human approval for data extraction
        
        Returns:
            True if approved, False otherwise
        """
        # Placeholder: In real implementation, would notify human
        # and wait for response via WebSocket/Slack/Email
        logger.warning(
            f"HITL approval required for data extraction: {finding.get('type')} "
            f"on {finding.get('endpoint')} - {reason}"
        )
        # Default to False (safe)
        return False


class EvidenceCollector:
    """
    Elegant evidence collection with scope boundary enforcement
    
    DESIGN PRINCIPLE:
    - "Existence confirmation" is always safe
    - "Data extraction" requires HITL approval
    - Bug Bounty program policies vary - never assume
    
    Layer 4 Separation:
    - Layer 1: Detection (vulnerability found)
    - Layer 2: Confirmation (reproducible)
    - Layer 3: Evidence (safe collection)
    - Layer 4: Data Extraction (HITL required)
    """
    
    def __init__(self, hitl_engine: Optional[HITLEngine] = None):
        self.hitl = hitl_engine or HITLEngine()
        self._collected_evidence: List[Evidence] = []
    
    async def collect_presence_evidence(
        self,
        vulnerability_type: str,
        endpoint: str,
        payload: str,
        response: str,
        confidence: float
    ) -> Evidence:
        """
        Collect evidence confirming vulnerability presence
        
        This is ALWAYS safe - no data extraction, just confirmation
        """
        evidence = Evidence(
            vulnerability_type=vulnerability_type,
            affected_endpoint=endpoint,
            payload_used=payload,
            response_evidence=response[:2000],  # Truncate
            timestamp=datetime.utcnow().isoformat(),
            reproduction_steps=self._generate_reproduction_steps(
                endpoint, payload
            ),
            scope_level=EvidenceScope.PRESENCE_ONLY,
            confidence_score=confidence,
        )
        
        logger.info(f"Collected presence evidence for {vulnerability_type} on {endpoint}")
        self._collected_evidence.append(evidence)
        
        return evidence
    
    async def collect_with_data_extraction(
        self,
        vulnerability_type: str,
        endpoint: str,
        payload: str,
        response: str,
        confidence: float,
        extraction_payload: Optional[str] = None,
        extraction_reason: str = ""
    ) -> Evidence:
        """
        Collect evidence with potential data extraction
        
        CRITICAL: This requires HITL approval for Bug Bounty compliance
        
        Args:
            extraction_payload: Payload to extract data (e.g., ' UNION SELECT @@version--)
            extraction_reason: Business justification for extraction
        """
        # Start with presence-only evidence
        evidence = await self.collect_presence_evidence(
            vulnerability_type, endpoint, payload, response, confidence
        )
        
        # Request HITL approval for data extraction
        if extraction_payload:
            finding = {
                "type": vulnerability_type,
                "endpoint": endpoint,
                "payload": payload,
            }
            
            approved = await self.hitl.request_data_extraction_approval(
                finding=finding,
                reason=f"Bug Bounty program scope verification required: {extraction_reason}"
            )
            
            if approved:
                # Only execute extraction if approved
                evidence.data_extraction_approved = True
                evidence.scope_level = EvidenceScope.SAMPLE_DATA
                
                # Execute extraction (placeholder)
                # In real implementation, would send extraction_payload
                evidence.extracted_data = "[EXTRACTION_APPROVED - Data would be extracted]"
                
                logger.info(f"Data extraction approved for {endpoint}")
            else:
                logger.warning(f"Data extraction DENIED for {endpoint}")
        
        return evidence
    
    def _generate_reproduction_steps(
        self,
        endpoint: str,
        payload: str
    ) -> List[str]:
        """Generate human-readable reproduction steps"""
        return [
            f"1. Navigate to {endpoint}",
            f"2. Enter payload: {payload[:100]}",
            f"3. Submit request",
            f"4. Observe vulnerability confirmation",
        ]
    
    def get_all_evidence(self) -> List[Evidence]:
        """Get all collected evidence"""
        return self._collected_evidence.copy()
    
    def get_evidence_by_type(self, vuln_type: str) -> List[Evidence]:
        """Filter evidence by vulnerability type"""
        return [e for e in self._collected_evidence if e.vulnerability_type == vuln_type]
    
    def export_to_report_format(self) -> Dict[str, Any]:
        """
        Export evidence to standardized report format
        
        Safe for Bug Bounty submission (no unapproved extraction)
        """
        return {
            "generated_at": datetime.utcnow().isoformat(),
            "evidence_count": len(self._collected_evidence),
            "evidence": [e.to_dict() for e in self._collected_evidence],
            "scope_adherence": "All data extraction approved by HITL",
        }


class EvidenceReportGenerator:
    """
    Generate professional Bug Bounty reports from evidence
    """
    
    def __init__(self, collector: EvidenceCollector):
        self.collector = collector
    
    def generate_report(self, program_name: str) -> Dict[str, Any]:
        """
        Generate structured report for Bug Bounty program
        
        Format compatible with HackerOne/Bugcrowd
        """
        evidence_list = self.collector.get_all_evidence()
        
        # Group by vulnerability type
        by_type: Dict[str, List[Evidence]] = {}
        for e in evidence_list:
            by_type.setdefault(e.vulnerability_type, []).append(e)
        
        # Generate findings
        findings = []
        for vuln_type, evidence_items in by_type.items():
            findings.append({
                "title": f"{vuln_type} Vulnerability Detected",
                "severity": self._infer_severity(vuln_type),
                "description": self._generate_description(evidence_items),
                "evidence": [e.to_dict() for e in evidence_items],
                "reproduction_steps": evidence_items[0].reproduction_steps if evidence_items else [],
            })
        
        return {
            "program": program_name,
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_findings": len(findings),
                "by_type": {k: len(v) for k, v in by_type.items()},
            },
            "findings": findings,
            "compliance_note": (
                "All evidence collected within program scope. "
                "Data extraction approved via HITL process."
            ),
        }
    
    def _infer_severity(self, vuln_type: str) -> str:
        """Infer severity from vulnerability type"""
        severity_map = {
            "sql_injection": "critical",
            "command_injection": "critical",
            "ssrf": "high",
            "xss": "medium",
            "lfi": "high",
            "idor": "medium",
        }
        return severity_map.get(vuln_type.lower(), "medium")
    
    def _generate_description(self, evidence_items: List[Evidence]) -> str:
        """Generate vulnerability description"""
        if not evidence_items:
            return "No evidence available"
        
        first = evidence_items[0]
        return (
            f"{first.vulnerability_type} vulnerability detected on "
            f"{first.affected_endpoint}. "
            f"Confidence: {first.confidence_score:.0%}"
        )


# Convenience functions

async def create_evidence_collector() -> EvidenceCollector:
    """
    Create evidence collector with HITL
    
    Usage:
        collector = await create_evidence_collector()
        
        # Safe: presence-only evidence
        evidence = await collector.collect_presence_evidence(...)
        
        # Requires HITL: data extraction
        evidence = await collector.collect_with_data_extraction(
            ..., extraction_payload="...", extraction_reason="..."
        )
    """
    return EvidenceCollector()
