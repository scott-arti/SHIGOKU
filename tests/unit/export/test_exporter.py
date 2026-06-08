import pytest
import os
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime

from src.core.models.finding import Finding, Severity, VulnType
from src.core.export.exporter import FindingExporter
from src.core.export.platform_sync import PlatformType

@pytest.fixture
def sample_findings():
    return [
        Finding(
            title="Test XSS vulnerability",
            description="Found Reflected XSS on search page",
            severity=Severity.HIGH,
            vuln_type=VulnType.XSS,
            target_url="https://example.com/search?q=<script>alert(1)</script>",
            cwe_id="79",
            cvss_score=7.5,
            discovered_at=datetime.utcnow(),
            source_agent="TestAgent"
        ),
        Finding(
            title="Test IDOR",
            description="IDOR on profile page",
            severity=Severity.MEDIUM,
            vuln_type=VulnType.IDOR,
            target_url="https://example.com/api/profile/123",
            discovered_at=datetime.utcnow(),
            source_agent="TestAgent",
            additional_info={"remediation_status": "REJECTED"}
        )
    ]

class TestFindingExporter:
    
    @pytest.mark.asyncio
    @patch("src.core.export.exporter.PlatformSyncClient")
    async def test_sync_to_platform(self, mock_client_class, sample_findings):
        # モックの設定
        mock_instance = mock_client_class.return_value
        mock_instance.is_configured.return_value = True
        
        # 1件目は成功してIDを返す、2件目はNoneを返す（例えばREJECTED等で）
        async def mock_sync(finding, param):
            if finding.additional_info.get("remediation_status") == "REJECTED":
                return None
            return "sync_id_1"
            
        mock_instance.sync_finding = AsyncMock(side_effect=mock_sync)
        
        exporter = FindingExporter("/tmp/exports")
        results = await exporter.sync_to_platform(
            sample_findings,
            PlatformType.HACKERONE,
            "prog_1"
        )
        
        assert len(results) == 1
        assert sample_findings[0].id in results
        assert results[sample_findings[0].id] == "sync_id_1"
        
        # REJECTEDなFindingのIDは結果に含まれていないことを確認
        assert sample_findings[1].id not in results

    @pytest.mark.asyncio
    @patch("src.core.export.exporter.PlatformSyncClient")
    async def test_sync_to_platform_not_configured(self, mock_client_class, sample_findings):
        mock_instance = mock_client_class.return_value
        mock_instance.is_configured.return_value = False
        
        exporter = FindingExporter("/tmp/exports")
        results = await exporter.sync_to_platform(
            sample_findings,
            PlatformType.HACKERONE,
            "prog_1"
        )
        
        # 設定されていない場合は空を返す
        assert results == {}
        mock_instance.sync_finding.assert_not_called()
