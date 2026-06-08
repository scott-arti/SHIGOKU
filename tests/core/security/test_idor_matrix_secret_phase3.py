
import pytest
import asyncio
from unittest.mock import MagicMock, patch
from src.core.workspace.shared_workspace import SharedWorkspace
from src.core.agents.swarm.logic.idor import IdorHunterSpecialist
from src.core.agents.swarm.secret.manager import SecretExposure
from src.core.domain.model.task import Task
from src.core.models.finding import VulnType, Severity

class MockResponse:
    def __init__(self, status, text, headers=None):
        self.status = status
        self.text = text
        self.headers = headers or {}
    
    def __await__(self):
        async def _async_wrapper():
            return self
        return _async_wrapper().__await__()

@pytest.fixture
def workspace(tmp_path):
    ws = SharedWorkspace(workspace_root=str(tmp_path))
    return ws

class TestMatrixTestingPhase3:
    """Matrix Testing (Owner-Aware) のテスト"""

    @pytest.mark.asyncio
    async def test_owner_aware_id_selection(self, workspace):
        # 1. 異なるロールのIDをプールに登録 (idor.py の正規化ロジックに合わせる)
        domain_pattern = "https://example.com/api/items/{id}"
        workspace.register_ids(domain_pattern, ["1001"], owner="user-A")
        workspace.register_ids(domain_pattern, ["2002"], owner="user-B")
        
        agent = IdorHunterSpecialist({"mode": "ctf"})
        agent._workspace_instance = workspace
        
        # 2. 現在のロールを "user-A" に設定
        agent.current_role = "user-A"
        
        with patch("src.core.infra.network_client.AsyncNetworkClient.request") as mock_req:
            mock_req.return_value = MockResponse(200, "OK")
            
            # _run_id_manipulation_check を呼び出し
            # match_value が "1001" (自分のもの) の場合
            matches = [("1001", "numeric", "url")]
            url = "https://example.com/api/items/1001"
            
            mock_client = MagicMock()
            mock_client.request.return_value = MockResponse(200, "OK")
            
            await agent._run_id_manipulation_check(mock_client, url, "GET", {}, None, matches, False)
            
            # 呼ばれたURLの履歴を確認
            all_called_urls = [call[0][1] for call in mock_client.request.call_args_list]
            
            # 自分(user-A)以外のID "2002" が試されているはず
            assert any("2002" in u for u in all_called_urls), f"Expected 2002 in {all_called_urls}"
            
            # 元のURL (1001) は Baseline として「1回だけ」呼ばれているはず
            original_url_calls = [u for u in all_called_urls if u == url]
            assert len(original_url_calls) == 1, f"Original URL should be called exactly once as baseline. Found: {len(original_url_calls)}"

class TestSecretExposurePhase3:
    """SecretExposure アージェントの解析機能テスト"""

    @pytest.mark.asyncio
    async def test_secretfinder_in_memory_scan(self):
        agent = SecretExposure()
        
        # モックの作成
        mock_findings = [
                {"rule": "AWS API Key", "description": "Found AWS Key", "matched": "AKIA...", "severity": "HIGH", "confidence": 0.9}
        ]
        
        with patch("src.core.infra.network_client.AsyncNetworkClient.request") as mock_req, \
             patch("src.tools.custom.secret_finder.SecretFinderTool.scan_text") as mock_sf:
            
            mock_req.return_value = MockResponse(200, "Some content with secrets")
            mock_sf.return_value = mock_findings
            
            # Task ID と Name を指定
            task = Task(id="test-1", name="Secret Scan", target="https://example.com/config.js", tags=["test"])
            results = await agent.execute(task)
            
            assert len(results) == 1
            assert results[0].vuln_type == VulnType.SECRET_LEAK
            # evidence に元データが含まれているか（またはマスクされているか）確認
            # 実際の実装では masker は "AKIA..." を masked に置換するはず
            assert results[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_idor_secret_scan_integration(self, workspace):
        """IdorHunterSpecialist が内部で SecretFinder を呼んでいるか"""
        agent = IdorHunterSpecialist({"mode": "ctf"})
        agent._workspace_instance = workspace
        
        response_text = "Found secret: AIzaSyA..."
        
        with patch("src.tools.custom.secret_finder.SecretFinderTool.scan_text") as mock_sf:
            mock_sf.return_value = [{"rule": "Google API Key", "matched": "AIzaSyA...", "description": "GKey", "severity": "HIGH", "confidence": 0.8}]
            
            # _scan_for_secrets をテスト
            findings = await agent._scan_for_secrets(response_text)
            
            assert len(findings) == 1
            assert findings[0]["rule"] == "Google API Key"
            mock_sf.assert_called_once_with(response_text)
