"""
SecretSwarm: 秘密情報・設定ミス検査

Specialists:
- SecretExposure: Git, 環境ファイル, API キー露出検査
- GitDumper: .git ディレクトリダンプ
- CloudMisconfigChecker: S3/GCS バケット設定ミス

Implementation Plan Section 2.2, 2.3 準拠
"""

import logging
import re
from typing import List, Dict, Any, Optional

from src.core.agents.swarm.base import SwarmManager, Specialist, Task
from src.core.agents.swarm.injection.payout_grade import _SECRET_EXPOSURE_PATTERNS
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

# SGK-2026-0483: served-body cap for the confirmable secret-exposure evidence
# (mirrors other specialists' 4000-byte evidence excerpts).
_SECRET_BODY_CAP = 4000

# Credential-bearing assignment line with capture groups (key, sep, value) so
# the VALUE can be redacted while the KEY is kept. The key side mirrors
# payout_grade._SECRET_EXPOSURE_PATTERNS[0], so a value-redacted body still
# fires the payout-grade marker (the match target is the key, never the value).
_CRED_LINE_RE = re.compile(
    r"(?im)^([ \t]*(?:export[ \t]+)?[A-Za-z0-9_.]*"
    r"(?:PASSWORD|PASSWD|SECRET|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|TOKEN|CREDENTIAL)"
    r"[A-Za-z0-9_.]*)[ \t]*([=:])[ \t]*(.*)$"
)

# PEM private-key block: keep the BEGIN/END markers, redact the key material.
_PEM_BLOCK_RE = re.compile(
    r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)"
    r"(.*?)"
    r"(-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)",
    re.DOTALL,
)


def _matched_credential_keys(content: str) -> List[str]:
    """Credential KEY names (never values) served in ``content``.

    Keys are variable names (``DB_PASSWORD``) — not secrets — so they are the
    safe proof token. Returns an ordered, de-duplicated list; includes the
    synthetic key ``PRIVATE KEY`` when a PEM private-key block is present.
    """
    keys: List[str] = []
    seen = set()
    for match in _CRED_LINE_RE.finditer(content):
        key = match.group(1).strip()
        if key and key not in seen:
            seen.add(key)
            keys.append(key)
    if _PEM_BLOCK_RE.search(content) and "PRIVATE KEY" not in seen:
        keys.append("PRIVATE KEY")
    return keys


def _redact_secret_values(content: str) -> str:
    """Redact credential VALUES (and PEM key material) while keeping the KEY
    side, so the served body can be stored as evidence without exposing any
    secret value. The key side still matches the payout-grade pattern."""

    def _redact_line(match: "re.Match[str]") -> str:
        key, sep, value = match.group(1), match.group(2), match.group(3)
        value = value.strip()
        if not value:
            return f"{key}{sep}"
        return f"{key}{sep}<redacted len={len(value)}>"

    redacted = _CRED_LINE_RE.sub(_redact_line, content)
    redacted = _PEM_BLOCK_RE.sub(
        lambda m: f"{m.group(1)}\n<redacted private key material>\n{m.group(3)}",
        redacted,
    )
    return redacted


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
        findings: List[Finding] = []
        target = task.target

        logger.info("[%s] Checking for exposed secrets at %s", self.name, target)

        try:
            resp = await self._get(target)
            status = getattr(resp, "status", 0)
            content = getattr(resp, "text", "") or ""
            if status == 200 and content:
                # SGK-2026-0483: confirmable enumerated secret exposure
                # (credential-bearing file served at a public URL).
                confirmable = self._build_secret_exposure_finding(
                    task, target, status, content, resp
                )
                if confirmable is not None:
                    findings.append(confirmable)

                # Supplementary SecretFinder rule scan (discovery only).
                findings.extend(
                    await self._secretfinder_scan(task, target, content)
                )
        except Exception as e:  # noqa: BLE001 — network/tool boundary, best-effort
            logger.error("[%s] Error in secret finding: %s", self.name, e)

        return findings

    async def _get(self, target: str) -> Any:
        """GET the target via an injected client (``self._client``; E2E/test
        seam, mirrors the smart_* specialists) or a fresh AsyncNetworkClient."""
        injected = getattr(self, "_client", None)
        if injected is not None:
            return await injected.request("GET", target, use_proxy=True)
        from src.core.infra.network_client import AsyncNetworkClient
        async with AsyncNetworkClient() as client:
            return await client.request("GET", target, use_proxy=True)

    def _build_secret_exposure_finding(
        self, task: Task, target: str, status: int, content: str, resp: Any
    ) -> Optional[Finding]:
        """Confirmable secret-exposure Finding (SGK-2026-0483).

        Emitted only when the served body contains a credential-bearing
        assignment (fail-closed: no credential key → None). The served body is
        value-redacted (keys kept) before it ever enters evidence/report, so no
        secret value is persisted; the firing marker matches on the key side.
        """
        matched_keys = _matched_credential_keys(content)
        if not matched_keys:
            return None

        from src.core.security.pii_masker import get_pii_masker
        masker = get_pii_masker()
        # Value-redact credential lines first, then defense-in-depth PII mask.
        redacted = _redact_secret_values(content)
        masked_body = masker.mask(redacted).masked
        served_body = masked_body[:_SECRET_BODY_CAP]

        content_type = ""
        headers = getattr(resp, "headers", None)
        if isinstance(headers, dict):
            content_type = str(
                headers.get("Content-Type") or headers.get("content-type") or ""
            )

        key_list = ", ".join(matched_keys[:8])
        poc_request = f"GET {target} HTTP/1.1\n\n"
        poc_response = (
            f"HTTP/1.1 {status}\n"
            f"Content-Type: {content_type}\n\n"
            f"{served_body}"
        )
        evidence = Evidence(
            request_method="GET",
            request_url=target,
            request_headers={},
            response_status=status,
            response_body=served_body,
        )
        impact = (
            "認証なしの単一 GET で、資格情報を含むファイルが公開配信されている。"
            f"取得元 {target} の応答(200)に認証情報の代入（{key_list} 等）が含まれ、"
            "誰でも取得できる。DB/サービス資格情報の漏洩は不正アクセスに直結する重大な露出。"
        )
        steps = [
            f"GET {target} を認証なしで送信する。",
            "応答ステータス 200 で本文に資格情報の代入"
            "（例: 末尾 PASSWORD=/SECRET=/TOKEN=、または PRIVATE KEY ブロック）"
            "が含まれることを確認する。",
        ]
        return Finding(
            vuln_type=VulnType.SECRET_LEAK,
            severity=Severity.CRITICAL,
            title="Enumerated secret exposure: credentials served at public URL",
            description=(
                f"Credential-bearing file served with HTTP {status} at {target} "
                f"(keys: {key_list})"
            ),
            target_url=target,
            evidence=evidence,
            impact=impact,
            reproduction_steps=steps,
            source_agent=self.name,
            confidence=0.9,
            is_aggressive=False,
            recommended_followup="report",
            tags=task.tags + ["secret_exposure_detected", "secret_exposed"],
            additional_info={
                "secret_exposure_evidence": {
                    "retrieved_url": target,
                    "response_status": status,
                    "served_body": served_body,
                    "matched_keys": matched_keys[:16],
                    "content_type": content_type,
                },
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        )

    async def _secretfinder_scan(
        self, task: Task, target: str, content: str
    ) -> List[Finding]:
        """Supplementary SecretFinder rule scan (discovery; non-confirmable)."""
        findings: List[Finding] = []
        try:
            from src.tools.custom.secret_finder import SecretFinderTool
            from src.core.security.pii_masker import get_pii_masker

            tool = SecretFinderTool()
            sf_results = await tool.scan_text(content, url=target)
            masker = get_pii_masker()

            for r in sf_results:
                masked_match = masker.mask(r.get("matched", "")).masked
                findings.append(
                    Finding(
                        vuln_type=VulnType.SECRET_LEAK,
                        severity=(
                            Severity.CRITICAL
                            if r.get("severity") == "CRITICAL"
                            else Severity.HIGH
                        ),
                        title=f"Secret exposure detected: {r.get('rule')}",
                        description=f"SecretFinder found '{r.get('description')}' at {target}",
                        target_url=target,
                        evidence=(
                            f"Match: {masked_match}\nRule: {r.get('rule')}\n"
                            f"Confidence: {r.get('confidence')}"
                        ),
                        source_agent=self.name,
                        confidence=r.get("confidence", 0.7),
                        recommended_followup="escalate",
                        tags=task.tags
                        + ["secret_exposure_detected", r.get("rule", "unknown")],
                    )
                )
        except Exception as e:  # noqa: BLE001 — tool boundary, discovery is best-effort
            logger.error("[%s] SecretFinder scan error: %s", self.name, e)
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

