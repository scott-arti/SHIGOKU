"""
SecretSwarm: 秘密情報・設定ミス検査

Specialists:
- SecretExposure: Git, 環境ファイル, API キー露出検査
- GitDumper: .git ディレクトリダンプ
- CloudMisconfigChecker: S3/GCS バケット設定ミス

Implementation Plan Section 2.2, 2.3 準拠
"""

import logging
from typing import List, Dict, Any, Optional

from src.core.agents.swarm.base import SwarmManager, Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)


class SecretExposure(Specialist):
    """秘密情報露出検査"""
    name = "SecretExposure"
    description = "Detects exposed secrets and API keys using secretfinder"
    timeout_seconds = 300
    is_aggressive = False
    
    PATTERNS = [
        ".env", ".env.bak", ".env.local", ".env.production",
        "*.bak", "*.old", "*~", "*.swp", "*.orig",
        "config.yml", "settings.json", "application.properties",
        "*.js.map",
    ]
    
    async def execute(self, task: Task) -> List[Finding]:
        import asyncio
        findings = []
        target = task.target
        
        logger.info("[%s] Checking for exposed secrets at %s", self.name, target)
        
        try:
            from src.tools.custom.secret_finder import SecretFinderTool
            tool = SecretFinderTool()
            
            # コンテンツの取得
            from src.core.infra.network_client import AsyncNetworkClient
            async with AsyncNetworkClient() as client:
                resp = await client.request("GET", target, use_proxy=True)
                if resp.status == 200:
                    content = resp.text
                    # 高速なインメモリスキャン
                    sf_results = await tool.scan_text(content, url=target)
                    
                    # PII マスク適用
                    from src.core.security.pii_masker import get_pii_masker
                    masker = get_pii_masker()
                    
                    for r in sf_results:
                        matched_text = r.get("matched", "")
                        masked_match = masker.mask(matched_text).masked
                        
                        finding = Finding(
                            vuln_type=VulnType.SECRET_LEAK,
                            severity=Severity.HIGH if r.get("severity") != "CRITICAL" else Severity.CRITICAL,
                            title=f"Secret exposure detected: {r.get('rule')}",
                            description=f"SecretFinder found '{r.get('description')}' at {target}",
                            target_url=target,
                            evidence=f"Match: {masked_match}\nRule: {r.get('rule')}\nConfidence: {r.get('confidence')}",
                            source_agent=self.name,
                            confidence=r.get("confidence", 0.7),
                            recommended_followup="escalate",
                            tags=task.tags + ["secret_exposure_detected", r.get("rule", "unknown")],
                        )
                        findings.append(finding)
        except Exception as e:
            logger.error("[%s] Error in secret finding: %s", self.name, e)
        
        return findings
    
        return findings


class GitDumper(Specialist):
    """.git ディレクトリダンプ"""
    name = "GitDumper"
    description = "Attempts to dump exposed .git directories"
    timeout_seconds = 600
    is_aggressive = False
    
    GIT_PATTERNS = ["/.git/config", "/.git/HEAD", "/.gitignore"]
    
    async def execute(self, task: Task) -> List[Finding]:
        import asyncio
        
        findings = []
        target = task.target
        
        logger.info("[%s] Checking for .git exposure at %s", self.name, target)
        
        try:
            from src.tools.custom.git_dumper import GitDumperTool
            tool = GitDumperTool()
            
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: tool.run(url=target)
            )
            
            # PII マスク適用
            from src.core.security.pii_masker import get_pii_masker
            masker = get_pii_masker()
            masked_result = masker.mask(result).masked

            # Git ダンプ成功判定
            if "extracted" in masked_result.lower() or "repository" in masked_result.lower():
                finding = Finding(
                    vuln_type=VulnType.SECRET_LEAK,
                    severity=Severity.CRITICAL,
                    title="Exposed .git directory extracted",
                    description=f"Git-dumper successfully extracted .git directory from {target}",
                    target_url=target,
                    source_agent=self.name,
                    confidence=0.95,
                    is_aggressive=False,
                    recommended_followup="report",
                    tags=task.tags + ["git_exposed_confirmed"],
                )
                findings.append(finding)
            
        except ImportError:
            logger.error("[%s] GitDumperTool not available", self.name)
        except Exception as e:
            logger.error("[%s] Error: %s", self.name, e)
        
        return findings


class CloudMisconfigChecker(Specialist):
    """S3/GCS バケット設定ミス"""
    name = "CloudMisconfigChecker"
    description = "Checks for cloud storage misconfigurations"
    timeout_seconds = 180
    is_aggressive = False
    
    async def execute(self, task: Task) -> List[Finding]:
        findings = []
        target_url = task.target
        logger.info("[%s] Checking cloud config at %s", self.name, target_url)
        
        if not target_url.startswith(("http://", "https://")):
            # もしドメイン名だけなら https 化を試みる
            target_url = f"https://{target_url}"
            
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, timeout=10) as response:
                    status = response.status
                    text = await response.text()
                    
                    is_s3_open = status == 200 and "<ListBucketResult" in text
                    is_xml_open = status == 200 and "<" in text and "Contents>" in text
                    
                    if is_s3_open or is_xml_open:
                        findings.append(Finding(
                            title="Open Cloud Storage Bucket Detected",
                            severity=Severity.HIGH,
                            vuln_type=VulnType.MISCONFIGURATION,
                            target_url=target_url,
                            description=f"Publicly accessible cloud storage bucket found at {target_url}.",
                            evidence=Evidence(request_url=target_url, request_method="GET", response_body=text[:500])
                        ))
        except ImportError:
            logger.error("[%s] aiohttp not installed.", self.name)
        except Exception as e:
            logger.debug("[%s] Error checking %s: %s", self.name, target_url, e)

        return findings


class SecretSwarm(SwarmManager):
    """秘密情報検査 Swarm Manager"""
    name = "SecretSwarm"
    description = "Detects exposed secrets and misconfigurations"
    default_timeout_seconds = 600
    
    TAG_SPECIALIST_MAP = {
        "js_file": [SecretExposure],
        "git_exposed": [GitDumper],
        "cloud_url": [CloudMisconfigChecker],
        "sourcemap": []  # Will be mapped in __init__
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        from src.core.agents.swarm.secret.sourcemap import SourceMapSpecialist
        self._all_specialists = [
            SecretExposure(self.config),
            GitDumper(self.config),
            CloudMisconfigChecker(self.config),
            SourceMapSpecialist(self.config)
        ]
        self.TAG_SPECIALIST_MAP["sourcemap"] = [SourceMapSpecialist]
        self.TAG_SPECIALIST_MAP["js_file"].append(SourceMapSpecialist)
    
    def get_specialists(self, tags: List[str]) -> List[Specialist]:
        if not tags:
            return self._all_specialists
        selected_classes = set()
        for tag in tags:
            if tag in self.TAG_SPECIALIST_MAP:
                selected_classes.update(self.TAG_SPECIALIST_MAP[tag])
        if not selected_classes:
            return self._all_specialists
        return [s for s in self._all_specialists if type(s) in selected_classes]

