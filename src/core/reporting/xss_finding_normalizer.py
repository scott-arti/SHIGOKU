"""
XSS Finding Normalizer for Phase X-1
X1-4: 結果正規化とFinding生成

DalFoxおよび他のXSS検出ツールの結果を、
SHIGOKU標準Findingフォーマットに正規化するモジュール。
"""
from __future__ import annotations
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class XSSType(str, Enum):
    """XSS脆弱性タイプ"""
    REFLECTED = "reflected_xss"
    STORED = "stored_xss"
    DOM = "dom_xss"
    BLIND = "blind_xss"
    SELF = "self_xss"


class Severity(str, Enum):
    """脆弱性重大度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


@dataclass
class NormalizedXSSFinding:
    """
    正規化されたXSS Finding
    
    SHIGOKU標準フォーマット - すべてのXSS検出ツールの結果を
    このフォーマットに統一してから報告・保存する。
    """
    # Core identification
    id: str = ""  # UUID v4
    type: XSSType = XSSType.REFLECTED
    
    # Location
    target: str = ""  # FQDN
    endpoint: str = ""  # /path/to/endpoint
    full_url: str = ""  # Complete URL
    method: str = "GET"  # HTTP method
    
    # Injection point
    parameter: str = ""  # Vulnerable parameter name
    payload: str = ""  # XSS payload used
    location: str = ""  # Where XSS executes (url-param, hash, body, etc.)
    
    # Classification
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.0  # 0.0 - 1.0
    cwe_id: str = "CWE-79"  # XSS CWE
    
    # Evidence
    evidence: Dict[str, Any] = field(default_factory=dict)
    screenshots: List[str] = field(default_factory=list)  # Screenshot paths
    http_request: Optional[str] = None
    http_response: Optional[str] = None
    
    # DOM XSS specific
    dom_sink: Optional[str] = None  # document.write, innerHTML, eval, etc.
    source: Optional[str] = None  # location.hash, document.URL, etc.
    browser_engine: str = "unknown"  # headless_chrome, etc.
    
    # Tool metadata
    source_tool: str = ""  # dalfox, smart_xss_hunter, etc.
    tool_version: str = ""
    detection_time_ms: float = 0.0
    
    # Timestamps
    detected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    reported_at: Optional[str] = None
    
    # Bug Bounty metadata
    program: Optional[str] = None  # HackerOne program
    scope_verified: bool = False  # Whether finding is in scope
    duplicate_of: Optional[str] = None  # UUID of duplicate finding
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "id": self.id,
            "type": self.type.value,
            "target": self.target,
            "endpoint": self.endpoint,
            "full_url": self.full_url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "location": self.location,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "cwe_id": self.cwe_id,
            "evidence": self.evidence,
            "screenshots": self.screenshots,
            "http_request": self.http_request,
            "http_response": self.http_response,
            "dom_sink": self.dom_sink,
            "source": self.source,
            "browser_engine": self.browser_engine,
            "source_tool": self.source_tool,
            "tool_version": self.tool_version,
            "detection_time_ms": self.detection_time_ms,
            "detected_at": self.detected_at,
            "reported_at": self.reported_at,
            "program": self.program,
            "scope_verified": self.scope_verified,
            "duplicate_of": self.duplicate_of,
        }
    
    def to_bug_bounty_format(self) -> Dict[str, Any]:
        """
        Bug Bounty報告用フォーマットに変換
        
        HackerOne/Bugcrowdに提出可能な形式。
        """
        severity_scores = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 3.0,
            Severity.INFO: 1.0,
        }
        
        return {
            "title": f"{self.type.value.replace('_', ' ').title()} in {self.parameter} parameter",
            "vulnerability_types": [
                {"id": "xss", "name": "Cross-site Scripting (XSS)"}
            ],
            "severity_rating": severity_scores.get(self.severity, 5.0),
            "severity": self.severity.value,
            "description": self._generate_description(),
            "reproduction_steps": self._generate_reproduction_steps(),
            "impact": self._generate_impact(),
            "references": [
                "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)",
                f"https://cwe.mitre.org/data/definitions/{self.cwe_id.replace('CWE-', '')}.html"
            ],
            "technical_details": {
                "parameter": self.parameter,
                "payload": self.payload,
                "url": self.full_url,
                "dom_sink": self.dom_sink,
            }
        }
    
    def _generate_description(self) -> str:
        """Generate human-readable description"""
        base = f"A {self.type.value.replace('_', ' ')} vulnerability was identified"
        
        if self.type == XSSType.DOM:
            return f"{base} in the {self.parameter} parameter via {self.dom_sink} DOM sink."
        elif self.type == XSSType.STORED:
            return f"{base} in the {self.parameter} parameter. The payload is stored and executes when other users view the data."
        else:
            return f"{base} in the {self.parameter} parameter. The payload reflects immediately in the response."
    
    def _generate_reproduction_steps(self) -> List[str]:
        """Generate reproduction steps"""
        steps = [
            f"1. Navigate to: {self.full_url}",
            f"2. Input the following payload in the '{self.parameter}' parameter:",
            f"   Payload: `{self.payload}`",
            f"3. Observe that the JavaScript executes (alert, console log, etc.)"
        ]
        
        if self.dom_sink:
            steps.append(f"4. The payload executes via {self.dom_sink} DOM sink.")
        
        return steps
    
    def _generate_impact(self) -> str:
        """Generate impact statement"""
        impacts = {
            Severity.CRITICAL: "Session hijacking, account takeover, or arbitrary code execution in victim's browser.",
            Severity.HIGH: "Session hijacking or theft of sensitive data via malicious JavaScript.",
            Severity.MEDIUM: "Phishing attacks or limited data theft via crafted payloads.",
            Severity.LOW: "Minor UI manipulation or limited information disclosure.",
            Severity.INFO: "Proof-of-concept XSS without practical security impact.",
        }
        return impacts.get(self.severity, "Potential security impact via JavaScript execution.")


class XSSFindingNormalizer:
    """
    XSS Finding正規化エンジン
    
    様々なXSS検出ツールの結果をSHIGOKU標準フォーマットに正規化。
    """
    
    # Tool-specific severity mappings
    SEVERITY_MAPPINGS = {
        "dalfox": {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        },
        "smart_xss_hunter": {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
    }
    
    def __init__(self):
        self._normalized_findings: List[NormalizedXSSFinding] = []
    
    def normalize_dalfox_result(
        self, 
        raw_result: Dict[str, Any],
        tool_version: str = "unknown"
    ) -> NormalizedXSSFinding:
        """
        DalFox結果を正規化
        
        Args:
            raw_result: DalFoxのJSON出力
            tool_version: DalFoxバージョン
            
        Returns:
            NormalizedXSSFinding: 正規化されたFinding
        """
        import uuid
        
        # Determine XSS type
        xss_type_str = raw_result.get("type", "reflected").lower()
        if xss_type_str == "dom":
            xss_type = XSSType.DOM
        elif xss_type_str == "stored":
            xss_type = XSSType.STORED
        else:
            xss_type = XSSType.REFLECTED
        
        # Map severity
        raw_severity = raw_result.get("severity", "medium").lower()
        severity = self.SEVERITY_MAPPINGS["dalfox"].get(
            raw_severity, Severity.MEDIUM
        )
        
        # Extract confidence
        confidence = 0.9 if raw_result.get("confirmed") else 0.7
        
        # Build normalized finding
        finding = NormalizedXSSFinding(
            id=str(uuid.uuid4()),
            type=xss_type,
            target=self._extract_target(raw_result.get("url", "")),
            endpoint=self._extract_endpoint(raw_result.get("url", "")),
            full_url=raw_result.get("url", ""),
            method=raw_result.get("method", "GET"),
            parameter=raw_result.get("param", ""),
            payload=raw_result.get("payload", ""),
            location=self._determine_location(raw_result),
            severity=severity,
            confidence=confidence,
            evidence={
                "raw_dalfox_output": raw_result,
                "scan_time": datetime.utcnow().isoformat(),
            },
            dom_sink=raw_result.get("sink"),
            source=raw_result.get("source"),
            browser_engine="headless_chrome",
            source_tool="dalfox",
            tool_version=tool_version,
            detection_time_ms=raw_result.get("scan_time_ms", 0.0),
        )
        
        return finding
    
    def normalize_smart_xss_result(
        self,
        raw_result: Dict[str, Any],
        tool_version: str = "unknown"
    ) -> NormalizedXSSFinding:
        """
        SmartXSSHunter結果を正規化
        """
        import uuid
        
        # SmartXSSHunterは通常Reflected XSSを検出
        xss_type = XSSType.REFLECTED
        
        # Determine severity based on context
        context = raw_result.get("context", {})
        if context.get("in_script_tag"):
            severity = Severity.HIGH
        elif context.get("in_html_tag"):
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        
        return NormalizedXSSFinding(
            id=str(uuid.uuid4()),
            type=xss_type,
            target=raw_result.get("target", ""),
            endpoint=raw_result.get("endpoint", ""),
            full_url=raw_result.get("full_url", ""),
            method=raw_result.get("method", "GET"),
            parameter=raw_result.get("parameter", ""),
            payload=raw_result.get("payload", ""),
            location=raw_result.get("location", "url-param"),
            severity=severity,
            confidence=raw_result.get("confidence", 0.5),
            evidence={
                "context_analysis": context,
                "raw_smart_xss_output": raw_result,
            },
            source_tool="smart_xss_hunter",
            tool_version=tool_version,
        )
    
    def normalize_batch(
        self,
        raw_findings: List[Dict[str, Any]],
        source_tool: str,
        tool_version: str = "unknown"
    ) -> List[NormalizedXSSFinding]:
        """
        複数の結果を一括正規化
        """
        normalized = []
        
        for raw in raw_findings:
            try:
                if source_tool == "dalfox":
                    finding = self.normalize_dalfox_result(raw, tool_version)
                elif source_tool == "smart_xss_hunter":
                    finding = self.normalize_smart_xss_result(raw, tool_version)
                else:
                    # Generic normalization
                    finding = self._generic_normalize(raw, source_tool, tool_version)
                
                normalized.append(finding)
                
            except Exception as e:
                logger.warning(f"Failed to normalize finding from {source_tool}: {e}")
        
        self._normalized_findings.extend(normalized)
        return normalized
    
    def deduplicate_findings(
        self,
        findings: List[NormalizedXSSFinding]
    ) -> List[NormalizedXSSFinding]:
        """
        重複Findingを検出・統合
        
        同じパラメータ・ペイロードのFindingを統合し、
        最も高い重大度と信頼度を保持する。
        """
        unique: Dict[str, NormalizedXSSFinding] = {}
        
        for finding in findings:
            # Create deduplication key
            key = f"{finding.target}:{finding.endpoint}:{finding.parameter}:{finding.payload}"
            
            if key in unique:
                existing = unique[key]
                
                # Keep higher severity
                severity_order = [
                    Severity.INFO, Severity.LOW, Severity.MEDIUM, 
                    Severity.HIGH, Severity.CRITICAL
                ]
                if severity_order.index(finding.severity) > severity_order.index(existing.severity):
                    existing.severity = finding.severity
                
                # Keep higher confidence
                existing.confidence = max(existing.confidence, finding.confidence)
                
                # Merge evidence
                existing.evidence[f"duplicate_{finding.source_tool}"] = finding.to_dict()
                
                # Mark as duplicate
                finding.duplicate_of = existing.id
                
            else:
                unique[key] = finding
        
        return list(unique.values())
    
    def _extract_target(self, url: str) -> str:
        """URLからターゲット（FQDN）を抽出"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc
    
    def _extract_endpoint(self, url: str) -> str:
        """URLからエンドポイント（パス）を抽出"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.path
    
    def _determine_location(self, raw_result: Dict[str, Any]) -> str:
        """インジェクション位置を判定"""
        url = raw_result.get("url", "")
        param = raw_result.get("param", "")
        
        if "#" in url and param in url.split("#")[-1]:
            return "hash"
        elif "?" in url and param in url.split("?")[-1]:
            return "url-param"
        else:
            return "unknown"
    
    def _generic_normalize(
        self,
        raw: Dict[str, Any],
        source_tool: str,
        tool_version: str
    ) -> NormalizedXSSFinding:
        """ジェネリック正規化（不明なツール用）"""
        import uuid
        
        return NormalizedXSSFinding(
            id=str(uuid.uuid4()),
            type=XSSType.REFLECTED,
            target=raw.get("target", ""),
            endpoint=raw.get("endpoint", ""),
            full_url=raw.get("url", ""),
            parameter=raw.get("param", ""),
            payload=raw.get("payload", ""),
            severity=Severity.MEDIUM,
            confidence=0.5,
            evidence={"raw_output": raw},
            source_tool=source_tool,
            tool_version=tool_version,
        )
    
    def generate_report(
        self,
        findings: List[NormalizedXSSFinding]
    ) -> Dict[str, Any]:
        """正規化されたFindingからレポートを生成"""
        total = len(findings)
        
        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        by_tool: Dict[str, int] = {}
        
        for f in findings:
            by_type[f.type.value] = by_type.get(f.type.value, 0) + 1
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
            by_tool[f.source_tool] = by_tool.get(f.source_tool, 0) + 1
        
        return {
            "summary": {
                "total_findings": total,
                "by_type": by_type,
                "by_severity": by_severity,
                "by_tool": by_tool,
            },
            "findings": [f.to_dict() for f in findings],
            "bug_bounty_ready_findings": [
                f.to_bug_bounty_format() for f in findings 
                if f.scope_verified
            ],
        }
