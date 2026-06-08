"""
DOM XSS Detection Pipeline for Phase X-1
X1-3: DOM XSS検出パイプライン

DalFoxを活用したDOM XSS特化検出エンジン。
ブラウザベースの動的検出と静的解析を組み合わせたハイブリッドアプローチ。
"""
from __future__ import annotations
import asyncio
import logging
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from src.core.adapters.external.dalfox_adapter import DalFoxAdapter, ToolInput
from src.core.adapters.external.base_external_adapter import ToolStatus

logger = logging.getLogger(__name__)


@dataclass
class DOMXSSCandidate:
    """DOM XSS検出候補"""
    url: str
    parameter: str
    payload_type: str  # "hash", "search", "pathname"
    confidence: float
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "payload_type": self.payload_type,
            "confidence": self.confidence,
            "context": self.context,
        }


@dataclass
class DOMXSSFinding:
    """DOM XSS検出結果"""
    type: str = "dom_xss"
    target: str = ""
    parameter: str = ""
    payload: str = ""
    url: str = ""
    method: str = "GET"
    severity: str = "high"
    confidence: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    dom_sink: Optional[str] = None  # document.write, innerHTML, etc.
    browser_engine: str = "headless_chrome"
    source_tool: str = "dalfox"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "target": self.target,
            "parameter": self.parameter,
            "payload": self.payload,
            "url": self.url,
            "method": self.method,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "dom_sink": self.dom_sink,
            "browser_engine": self.browser_engine,
            "source_tool": self.source_tool,
            "timestamp": self.timestamp,
        }


class DOMXSSCandidateAnalyzer:
    """
    DOM XSS候補静的解析エンジン
    
    SPA（Single Page Application）のDOM XSS脆弱性を
    URLパターン分析で事前に特定する。
    """
    
    # DOM XSSを引き起こしやすいパラメータパターン
    HIGH_RISK_PARAMS: Set[str] = {
        # Hash-based routing
        "#", "hash", "fragment",
        # Search/Query params that affect DOM
        "redirect", "next", "return", "url", "uri", "path",
        "callback", "cb", "handler",
        # Common SPA params
        "view", "tab", "section", "page",
    }
    
    # DOM XSS sinkパターン
    SINK_PATTERNS: Dict[str, List[str]] = {
        "document.write": ["document.write", "document.writeln"],
        "innerHTML": [".innerHTML", ".outerHTML"],
        "eval": ["eval(", "setTimeout(", "setInterval("],
        "location": ["location.href", "location.replace", "location.assign"],
        "script_src": ["<script", "src="],
    }
    
    def __init__(self):
        self.candidates: List[DOMXSSCandidate] = []
    
    async def analyze_url(self, url: str) -> List[DOMXSSCandidate]:
        """
        URLを解析し、DOM XSS候補を特定
        
        Args:
            url: 解析対象URL
            
        Returns:
            List[DOMXSSCandidate]: 検出された候補リスト
        """
        candidates = []
        parsed = urlparse(url)
        
        # 1. Hash-based routing分析
        if parsed.fragment:
            hash_candidates = self._analyze_hash_fragment(url, parsed)
            candidates.extend(hash_candidates)
        
        # 2. Search query分析
        if parsed.query:
            query_candidates = self._analyze_query_params(url, parsed)
            candidates.extend(query_candidates)
        
        # 3. Pathname分析（SPAルート）
        path_candidates = self._analyze_pathname(url, parsed)
        candidates.extend(path_candidates)
        
        self.candidates.extend(candidates)
        return candidates
    
    def _analyze_hash_fragment(
        self, 
        url: str, 
        parsed: Any
    ) -> List[DOMXSSCandidate]:
        """Hash fragment (#) を分析"""
        candidates = []
        fragment = parsed.fragment
        
        # Check if hash looks like a route or parameter
        if "=" in fragment:
            # Hash-based params: #/route?param=value
            params = parse_qs(fragment.split("?")[-1]) if "?" in fragment else {}
            for param in params:
                if self._is_high_risk_param(param):
                    candidates.append(DOMXSSCandidate(
                        url=url,
                        parameter=param,
                        payload_type="hash",
                        confidence=0.75,
                        context={
                            "hash_fragment": fragment,
                            "pattern": "hash-based-params",
                        }
                    ))
        elif "/" in fragment:
            # SPA route: #/path/to/route
            candidates.append(DOMXSSCandidate(
                url=url,
                parameter="hash_route",
                payload_type="hash",
                confidence=0.6,
                context={
                    "hash_fragment": fragment,
                    "pattern": "spa-route",
                }
            ))
        
        return candidates
    
    def _analyze_query_params(
        self, 
        url: str, 
        parsed: Any
    ) -> List[DOMXSSCandidate]:
        """Query parameters (?x=y) を分析"""
        candidates = []
        params = parse_qs(parsed.query)
        
        for param, values in params.items():
            if self._is_high_risk_param(param):
                candidates.append(DOMXSSCandidate(
                    url=url,
                    parameter=param,
                    payload_type="search",
                    confidence=0.7,
                    context={
                        "query_params": list(params.keys()),
                        "pattern": "high-risk-param",
                    }
                ))
        
        return candidates
    
    def _analyze_pathname(
        self, 
        url: str, 
        parsed: Any
    ) -> List[DOMXSSCandidate]:
        """Pathname (/path) を分析"""
        candidates = []
        path = parsed.path
        
        # Check for parameterized routes
        if "{" in path or ":" in path:
            candidates.append(DOMXSSCandidate(
                url=url,
                parameter="path_param",
                payload_type="pathname",
                confidence=0.5,
                context={
                    "pathname": path,
                    "pattern": "parameterized-route",
                }
            ))
        
        return candidates
    
    def _is_high_risk_param(self, param: str) -> bool:
        """高リスクパラメータかどうか判定"""
        param_lower = param.lower()
        return any(
            risk in param_lower 
            for risk in self.HIGH_RISK_PARAMS
        )


class DOMXSSDetector:
    """
    DOM XSS検出エンジン
    
    DalFoxを活用したブラウザベースDOM XSS検出。
    静的解析で候補を絞り込み、DalFoxで動的検証を実行。
    
    Architecture:
        ┌─────────────────┐
        │  URL Analyzer   │ ← 静的解析で候補特定
        └────────┬────────┘
                 ↓
        ┌─────────────────┐
        │ DalFox Adapter  │ ← ブラウザベース検証
        └────────┬────────┘
                 ↓
        ┌─────────────────┐
        │ Result Parser   │ ← Finding正規化
        └─────────────────┘
    """
    
    def __init__(self, dalfox_adapter: Optional[DalFoxAdapter] = None):
        self.dalfox = dalfox_adapter or DalFoxAdapter()
        self.analyzer = DOMXSSCandidateAnalyzer()
        self._findings: List[DOMXSSFinding] = []

    @classmethod
    def from_static_candidate(cls, candidate: DOMXSSCandidate) -> DOMXSSFinding:
        """静的候補をDOMXSSFindingへ正規化（Stage分離用）。"""
        return DOMXSSFinding(
            type="dom_xss",
            target=candidate.url,
            parameter=candidate.parameter,
            payload="",
            url=candidate.url,
            method="GET",
            severity="medium",
            confidence=candidate.confidence,
            evidence={"stage": "static_analysis", "context": candidate.context},
            source_tool="static_analysis",
        )

    async def run_static_only(self, target_url: str) -> List[DOMXSSFinding]:
        """Stage 1: 静的解析候補のみ返す。"""
        candidates = await self.analyzer.analyze_url(target_url)
        return [self.from_static_candidate(c) for c in candidates]

    async def run_dynamic_only(
        self,
        target_url: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> List[DOMXSSFinding]:
        """Stage 2: DalFox動的結果のみ返す。"""
        opts = options or {}
        static_candidates: Optional[List[DOMXSSFinding]] = opts.get("static_candidates")
        max_candidates = opts.get("max_candidates", 10)

        if static_candidates is None:
            static_candidates = await self.run_static_only(target_url)

        findings: List[DOMXSSFinding] = []
        scan_candidates = static_candidates[:max_candidates]
        for candidate in scan_candidates:
            findings.extend(await self._scan_with_dalfox_candidate(candidate, opts))

        if not scan_candidates:
            findings.extend(await self._scan_url_directly(target_url, opts))

        return findings
    
    async def detect_dom_xss(
        self,
        target_url: str,
        options: Optional[Dict[str, Any]] = None
    ) -> List[DOMXSSFinding]:
        """
        DOM XSS検出メインエントリ
        
        Args:
            target_url: 検出対象URL
            options: 検出オプション
                - use_static_analysis: 静的解析を使用（デフォルトTrue）
                - use_dynamic_scan: 動的スキャンを使用（デフォルトTrue）
                - max_candidates: 最大候補数（デフォルト10）
                - timeout_seconds: タイムアウト（デフォルト120）
        
        Returns:
            List[DOMXSSFinding]: 検出されたDOM XSS脆弱性
        """
        opts = options or {}
        use_static = opts.get("use_static_analysis", True)
        use_dynamic = opts.get("use_dynamic_scan", True)
        findings: List[DOMXSSFinding] = []
        static_candidates: List[DOMXSSFinding] = []

        if use_static:
            logger.info(f"[DOM XSS] Phase 1: Static analysis for {target_url}")
            static_candidates = await self.run_static_only(target_url)
            logger.info(f"[DOM XSS] Found {len(static_candidates)} candidates from static analysis")

        if use_dynamic:
            logger.info(f"[DOM XSS] Phase 2: Dynamic scan with DalFox")
            findings.extend(
                await self.run_dynamic_only(
                    target_url,
                    {**opts, "static_candidates": static_candidates},
                )
            )

        self._findings.extend(findings)
        return findings

    async def _scan_with_dalfox_candidate(
        self,
        candidate: DOMXSSFinding,
        options: Dict[str, Any],
    ) -> List[DOMXSSFinding]:
        """Stage分離後の候補型(DOMXSSFinding)からDalFox実行。"""
        findings: List[DOMXSSFinding] = []
        try:
            tool_input = ToolInput(
                target=candidate.url,
                timeout_seconds=options.get("timeout_seconds", 120),
                options={"param": candidate.parameter, "type": "dom"},
            )
            result = await self.dalfox.run_with_validation(tool_input)
            if result.status == ToolStatus.SUCCESS and result.data:
                for finding_data in result.data:
                    finding = self._normalize_finding(finding_data)
                    finding.confidence = max(finding.confidence, candidate.confidence)
                    findings.append(finding)
        except Exception as e:
            logger.warning(f"[DOM XSS] DalFox scan failed for {candidate.url}: {e}")
        return findings
    
    async def _scan_with_dalfox(
        self,
        candidate: DOMXSSCandidate,
        options: Dict[str, Any]
    ) -> List[DOMXSSFinding]:
        """
        DalFoxで個別候補をスキャン
        """
        findings = []
        
        try:
            # Build ToolInput for DalFox
            tool_input = ToolInput(
                target=candidate.url,
                timeout_seconds=options.get("timeout_seconds", 120),
                options={
                    "param": candidate.parameter,
                    "type": "dom",  # DOM XSS focus
                }
            )
            
            # Execute DalFox
            result = await self.dalfox.run_with_validation(tool_input)
            
            if result.status == ToolStatus.SUCCESS and result.data:
                for finding_data in result.data:
                    finding = self._normalize_finding(finding_data)
                    finding.confidence = max(finding.confidence, candidate.confidence)
                    findings.append(finding)
            
        except Exception as e:
            logger.warning(f"[DOM XSS] DalFox scan failed for {candidate.url}: {e}")
        
        return findings
    
    async def _scan_url_directly(
        self,
        url: str,
        options: Dict[str, Any]
    ) -> List[DOMXSSFinding]:
        """
        URLを直接DalFoxでスキャン（候補が見つからない場合）
        """
        findings = []
        
        try:
            tool_input = ToolInput(
                target=url,
                timeout_seconds=options.get("timeout_seconds", 120),
                options={"type": "dom"}
            )
            
            result = await self.dalfox.run_with_validation(tool_input)
            
            if result.status == ToolStatus.SUCCESS and result.data:
                for finding_data in result.data:
                    finding = self._normalize_finding(finding_data)
                    findings.append(finding)
            
        except Exception as e:
            logger.warning(f"[DOM XSS] Direct DalFox scan failed for {url}: {e}")
        
        return findings
    
    def _normalize_finding(self, raw_data: Dict[str, Any]) -> DOMXSSFinding:
        """
        DalFox結果を標準化されたFindingに変換
        """
        return DOMXSSFinding(
            type="dom_xss",
            target=raw_data.get("url", ""),
            parameter=raw_data.get("param", ""),
            payload=raw_data.get("payload", ""),
            url=raw_data.get("url", ""),
            method=raw_data.get("method", "GET"),
            severity=raw_data.get("severity", "high"),
            confidence=raw_data.get("confidence", 0.7),
            evidence=raw_data.get("evidence", {}),
            dom_sink=raw_data.get("dom_sink"),
            browser_engine="headless_chrome",
            source_tool="dalfox",
        )
    
    def get_findings(self) -> List[DOMXSSFinding]:
        """すべての検出結果を取得"""
        return self._findings.copy()
    
    def generate_report(self) -> Dict[str, Any]:
        """検出結果レポートを生成"""
        total = len(self._findings)
        by_severity: Dict[str, int] = {}
        by_sink: Dict[str, int] = {}
        
        for finding in self._findings:
            # Count by severity
            sev = finding.severity
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
            # Count by sink
            sink = finding.dom_sink or "unknown"
            by_sink[sink] = by_sink.get(sink, 0) + 1
        
        return {
            "total_findings": total,
            "by_severity": by_severity,
            "by_sink": by_sink,
            "findings": [f.to_dict() for f in self._findings],
        }


# Convenience function
async def detect_dom_xss(
    url: str,
    options: Optional[Dict[str, Any]] = None
) -> List[DOMXSSFinding]:
    """
    簡易DOM XSS検出関数
    
    Usage:
        findings = await detect_dom_xss("https://example.com/#/page")
        for finding in findings:
            print(f"DOM XSS: {finding.parameter} = {finding.payload}")
    """
    detector = DOMXSSDetector()
    return await detector.detect_dom_xss(url, options)
