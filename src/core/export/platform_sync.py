"""
Platform Sync Client - バグバウンティプラットフォーム連携機能
HackerOne / Bugcrowd の API を叩き、Findingsを自動的にDraftレポートとして送信する。
"""

import os
import logging
from enum import Enum
from typing import Dict, Any, Optional

from src.core.models.finding import Finding
from src.core.infra.network_client import AsyncNetworkClient

logger = logging.getLogger(__name__)


class PlatformType(str, Enum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"


class PlatformSyncClient:
    """
    Bug Bounty プラットフォーム連携用クライアント
    - HackerOne
    - Bugcrowd
    """
    
    def __init__(self, platform: PlatformType, network_client: Optional[AsyncNetworkClient] = None):
        self.platform = platform
        self._network_client = network_client or AsyncNetworkClient()
        self._api_key = self._load_credentials()
        
    def _load_credentials(self) -> str:
        """環境変数からAPIキーをロード"""
        if self.platform == PlatformType.HACKERONE:
            key = os.environ.get("H1_API_KEY", "")
            user = os.environ.get("H1_API_USER", "")
            return f"{user}:{key}" if user and key else ""
        elif self.platform == PlatformType.BUGCROWD:
            return os.environ.get("BUGCROWD_API_KEY", "")
        return ""
        
    def is_configured(self) -> bool:
        """APIキーが設定されているかどうかをチェック"""
        return bool(self._api_key)

    async def sync_finding(self, finding: Finding, program_id: str) -> Optional[str]:
        """
        Finding をプラットフォームに同期する
        
        Args:
            finding: 同期するFinding
            program_id: プラットフォーム固有のプログラムID
            
        Returns:
            生成されたReportのID（成功時）、失敗時はNone
        """
        if not self.is_configured():
            logger.warning(f"PlatformSyncClient not configured for {self.platform.value}")
            return None
            
        if finding.additional_info.get("remediation_status") == "REJECTED":
            logger.info(f"Finding {finding.id} is REJECTED by EthicsGuard. Not syncing.")
            return None
            
        if self.platform == PlatformType.HACKERONE:
            return await self._sync_to_hackerone(finding, program_id)
        elif self.platform == PlatformType.BUGCROWD:
            return await self._sync_to_bugcrowd(finding, program_id)
            
        return None

    async def _sync_to_hackerone(self, finding: Finding, program_id: str) -> Optional[str]:
        """HackerOne用同期処理"""
        url = f"https://api.hackerone.com/v1/programs/{program_id}/reports"
        
        # 認証用に簡易的にBasicをBase64変換
        import base64
        auth_bytes = self._api_key.encode("utf-8")
        b64_auth = base64.b64encode(auth_bytes).decode("utf-8")
        
        headers = {
            "Authorization": f"Basic {b64_auth}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # Severity マッピング
        severity_map = {
            "info": "none",
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical"
        }
        
        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "title": finding.title,
                    "state": "new",
                    "vulnerability_information": self._generate_markdown_report(finding),
                    "severity_rating": severity_map.get(finding.severity.value, "none"),
                }
            }
        }
        
        try:
            resp = await self._network_client.request(
                "POST", url, headers=headers, json=payload, use_cache=False, auto_waf_bypass=False
            )
            
            if resp.is_success:
                data = resp.json()
                report_id = data.get("data", {}).get("id")
                logger.info(f"Successfully synced finding {finding.id} to HackerOne. Report ID: {report_id}")
                return str(report_id)
            else:
                logger.error(f"Failed to sync finding to HackerOne. Status: {resp.status} - {resp.body}")
                return None
        except Exception as e:
            logger.error(f"Network error while syncing to HackerOne: {e}")
            return None

    async def _sync_to_bugcrowd(self, finding: Finding, program_id: str) -> Optional[str]:
        """Bugcrowd用同期処理"""
        url = "https://api.bugcrowd.com/submissions"
        
        headers = {
            "Authorization": f"Token {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.bugcrowd+json; version=2021-10-28"
        }
        
        # VRT(Vulnerability Rating Taxonomy)の完全なマッピングは一旦省略し、概要のみ
        payload = {
            "submission": {
                "bug_url": finding.target_url,
                "title": finding.title,
                "description": self._generate_markdown_report(finding),
                "custom_fields": {
                    "program_id": program_id
                }
            }
        }
        
        try:
            resp = await self._network_client.request(
                "POST", url, headers=headers, json=payload, use_cache=False, auto_waf_bypass=False
            )
            
            if resp.is_success:
                data = resp.json()
                submission_id = data.get("id")
                logger.info(f"Successfully synced finding {finding.id} to Bugcrowd. Submission ID: {submission_id}")
                return str(submission_id)
            else:
                logger.error(f"Failed to sync finding to Bugcrowd. Status: {resp.status} - {resp.body}")
                return None
        except Exception as e:
            logger.error(f"Network error while syncing to Bugcrowd: {e}")
            return None

    def _generate_markdown_report(self, finding: Finding) -> str:
        """FindingからMarkdownのレポートボディを生成"""
        return f'''## Summary
{finding.description}

## Target
{finding.target_url}

## Vulnerability Type
{finding.vuln_type.value} (CWE: {finding.cwe_id})

## Confidence
{finding.confidence * 100:.0f}%

## Generated By
SHIGOKU Autonomous Bug Bounty Hunter
Agent: {finding.source_agent}
Discovered: {finding.discovered_at.strftime('%Y-%m-%d %H:%M:%S')}
'''
