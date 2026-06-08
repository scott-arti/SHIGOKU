"""
Nuclei Integrator - Nuclei統合

テンプレートベーススキャン、結果パース、Finding変換
"""

import json
import logging
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

from src.config import settings

logger = logging.getLogger(__name__)


class NucleiSeverity(Enum):
    """Nuclei深刻度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


@dataclass
class NucleiResult:
    """Nuclei検出結果"""
    template_id: str
    template_name: str = ""
    severity: NucleiSeverity = NucleiSeverity.UNKNOWN
    host: str = ""
    matched_at: str = ""
    extracted_results: List[str] = field(default_factory=list)
    curl_command: str = ""
    description: str = ""
    reference: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


class NucleiIntegrator:
    """
    Nuclei統合
    
    機能:
    - Nuclei実行
    - 結果パース
    - Finding変換
    - テンプレートフィルタ
    """
    
    # 安全なテンプレートタグ（破壊的でないもの）
    SAFE_TAGS = [
        "cve", "exposure", "misconfig", "disclosure",
        "tech", "detect", "info", "panel", "login",
    ]
    
    # 危険なテンプレートタグ（除外）
    DANGEROUS_TAGS = [
        "dos", "rce", "intrusive", "sqli-error",
    ]
    
    def __init__(
        self,
        nuclei_path: str = None,
        templates_path: str = None,
        rate_limit: int = 50
    ):
        self.nuclei_path = nuclei_path or settings.tool_nuclei_path
        self.templates_path = templates_path
        self.rate_limit = rate_limit
        self.results: List[NucleiResult] = []
    
    def scan(
        self,
        targets: List[str],
        tags: List[str] = None,
        severity: List[str] = None,
        templates: List[str] = None,
        exclude_tags: List[str] = None
    ) -> List[NucleiResult]:
        """
        Nucleiスキャン実行
        
        Args:
            targets: ターゲットURL/ホスト
            tags: テンプレートタグフィルタ
            severity: 深刻度フィルタ
            templates: 特定テンプレート
            exclude_tags: 除外タグ
        """
        if exclude_tags is None:
            exclude_tags = self.DANGEROUS_TAGS
        
        # コマンド構築
        cmd = [
            self.nuclei_path,
            "-json",  # JSON出力
            "-silent",
            "-rate-limit", str(self.rate_limit),
        ]
        
        # ターゲット
        for target in targets:
            cmd.extend(["-u", target])
        
        # テンプレートパス
        if self.templates_path:
            cmd.extend(["-t", self.templates_path])
        
        # タグフィルタ
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        
        # 深刻度フィルタ
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
        
        # 除外タグ
        if exclude_tags:
            cmd.extend(["-exclude-tags", ",".join(exclude_tags)])
        
        # 特定テンプレート
        if templates:
            for t in templates:
                cmd.extend(["-t", t])
        
        logger.info("Running Nuclei: %s", " ".join(cmd[:10]) + "...")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1時間タイムアウト
            )
            
            self.results = self._parse_output(result.stdout)
            
            if result.returncode != 0 and result.stderr:
                logger.warning("Nuclei stderr: %s", result.stderr[:500])
            
        except subprocess.TimeoutExpired:
            logger.error("Nuclei scan timed out")
        except FileNotFoundError:
            logger.error("Nuclei not found at %s", self.nuclei_path)
        except Exception as e:
            logger.error("Nuclei scan failed: %s", e)
        
        return self.results
    
    def scan_safe(self, targets: List[str]) -> List[NucleiResult]:
        """
        安全なスキャンのみ実行
        
        破壊的なテンプレートを除外
        """
        return self.scan(
            targets=targets,
            exclude_tags=self.DANGEROUS_TAGS,
            severity=["critical", "high", "medium"],
        )
    
    def _parse_output(self, output: str) -> List[NucleiResult]:
        """Nuclei JSON出力をパース"""
        results = []
        
        for line in output.strip().split("\n"):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                result = NucleiResult(
                    template_id=data.get("template-id", ""),
                    template_name=data.get("info", {}).get("name", ""),
                    severity=self._parse_severity(data.get("info", {}).get("severity", "")),
                    host=data.get("host", ""),
                    matched_at=data.get("matched-at", ""),
                    extracted_results=data.get("extracted-results", []),
                    curl_command=data.get("curl-command", ""),
                    description=data.get("info", {}).get("description", ""),
                    reference=data.get("info", {}).get("reference", []),
                    tags=data.get("info", {}).get("tags", []),
                )
                results.append(result)
                
            except json.JSONDecodeError:
                logger.debug("Failed to parse line: %s", line[:100])
        
        return results
    
    def _parse_severity(self, severity: str) -> NucleiSeverity:
        """深刻度パース"""
        try:
            return NucleiSeverity(severity.lower())
        except ValueError:
            return NucleiSeverity.UNKNOWN
    
    def to_findings(self) -> List[Dict]:
        """
        SHIGOKU Finding形式に変換
        
        Returns:
            Finding互換辞書リスト
        """
        findings = []
        
        for r in self.results:
            finding = {
                "title": f"[Nuclei] {r.template_name}",
                "type": r.template_id,
                "severity": r.severity.value,
                "url": r.matched_at or r.host,
                "description": r.description,
                "evidence": {
                    "curl_command": r.curl_command,
                    "extracted": r.extracted_results,
                },
                "references": r.reference,
                "tags": r.tags,
                "source": "nuclei",
            }
            findings.append(finding)
        
        return findings
    
    def get_by_severity(self, severity: NucleiSeverity) -> List[NucleiResult]:
        """深刻度でフィルタ"""
        return [r for r in self.results if r.severity == severity]
    
    def get_critical_high(self) -> List[NucleiResult]:
        """Critical/Highのみ"""
        return [
            r for r in self.results 
            if r.severity in [NucleiSeverity.CRITICAL, NucleiSeverity.HIGH]
        ]
    
    def get_summary(self) -> Dict:
        """サマリー"""
        by_severity = {}
        for r in self.results:
            by_severity.setdefault(r.severity.value, 0)
            by_severity[r.severity.value] += 1
        
        return {
            "total": len(self.results),
            "by_severity": by_severity,
            "critical": by_severity.get("critical", 0),
            "high": by_severity.get("high", 0),
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"Nuclei Scan: {summary['total']} findings\n"
            f"Critical: {summary['critical']}\n"
            f"High: {summary['high']}\n"
            f"By severity: {summary['by_severity']}"
        )


def create_nuclei_integrator(
    nuclei_path: str = "nuclei",
    templates_path: str = None
) -> NucleiIntegrator:
    """NucleiIntegrator作成ヘルパー"""
    return NucleiIntegrator(nuclei_path, templates_path)
