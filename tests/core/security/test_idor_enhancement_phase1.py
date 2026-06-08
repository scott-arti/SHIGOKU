"""
Tests for IDOR Enhancement Phase 1: ID Pool and Ethical Approval Flow.
"""
import pytest
import re
from unittest.mock import MagicMock, patch
from src.core.workspace.shared_workspace import SharedWorkspace
from src.core.agents.swarm.logic.idor import IdorHunterSpecialist
from src.core.domain.model.task import Task
from src.core.models.finding import Severity

@pytest.fixture
def workspace(tmp_path):
    ws = SharedWorkspace(workspace_root=str(tmp_path))
    return ws

class MockResponse:
    def __init__(self, status, text):
        self.status = status
        self.text = text
    
    def __await__(self):
        async def _async_wrapper():
            return self
        return _async_wrapper().__await__()

class TestIDPoolCore:
    """SharedWorkspaceのIDプール基本機能のテスト"""
    
    def test_register_and_get_ids(self, workspace):
        ids = ["101", "102", "103"]
        workspace.register_ids("/api/users/{id}", ids)
        
        pool_ids = workspace.get_pool_ids("/api/users/{id}")
        assert len(pool_ids) == 3
        assert "101" in pool_ids
        
        # 重複排除の確認
        workspace.register_ids("/api/users/{id}", ["101", "104"])
        assert len(workspace.get_pool_ids("/api/users/{id}")) == 4

    def test_ethical_staging_flow(self, workspace):
        ids = ["vulnerable-id-1"]
        workspace.stage_ids_for_approval("/api/data/{id}", ids, "Found in response")
        
        # まだプールには入っていないはず
        assert len(workspace.get_pool_ids("/api/data/{id}")) == 0
        
        # 承認
        count = workspace.approve_staged_ids("/api/data/{id}")
        assert count == 1
        assert "vulnerable-id-1" in workspace.get_pool_ids("/api/data/{id}")

class TestIdorHunterIntegration:
    """IdorHunterSpecialistとの統合テスト"""
    
    @pytest.mark.asyncio
    async def test_id_collection_in_ctf_mode(self, workspace):
        agent = IdorHunterSpecialist({"mode": "ctf"})
        agent._workspace_instance = workspace
        
        # モックレスポンス: 有効なIDが含まれている
        response_text = '{"status": "success", "data": {"id": 999, "name": "Secret User"}}'
        
        with patch("src.core.infra.network_client.AsyncNetworkClient.request") as mock_req:
            mock_req.return_value = MockResponse(200, response_text)
            
            # 内部メソッドを直接呼んでID収集を確認
            await agent._collect_ids_from_response("https://example.com/api/users/1", response_text)
            
            # CTFモードなので即座にプールに入る
            # Note: idor.py は re.sub で /api/users/1 を /api/users/{id} に置換している
            # ドメインが含まれている可能性を確認
            pool_keys = workspace.id_pool.keys()
            assert any("/api/users/{id}" in k for k in pool_keys)
            
            p_key = [k for k in pool_keys if "/api/users/{id}" in k][0]
            assert "999" in workspace.get_pool_ids(p_key)

    @pytest.mark.asyncio
    async def test_id_staging_in_bugbounty_mode(self, workspace):
        agent = IdorHunterSpecialist({"mode": "bugbounty"})
        agent._workspace_instance = workspace
        
        response_text = '{"id": 888}'
        await agent._collect_ids_from_response("https://example.com/api/items/1", response_text)
        
        # BugBountyモードなのでプールには入らず承認待ちになる
        assert "/api/items/{id}" in [re.sub(r'^https?://[^/]+', '', k) for k in workspace.get_pending_approval_report().keys()]

    @pytest.mark.asyncio
    async def test_use_pool_ids_in_manipulation(self, workspace):
        # 事前にプールにIDを入れておく
        # idor.py は URL 全体を re.sub するため、登録時のキーもそれに合わせる
        url_pattern = "https://example.com/api/users/{id}"
        workspace.register_ids(url_pattern, ["555"])
        
        agent = IdorHunterSpecialist({"mode": "ctf"})
        agent._workspace_instance = workspace
        
        # _run_id_manipulation_check の中でプールからIDが取り出されるか
        with patch.object(agent, "_scan_for_secrets", return_value=[]), \
             patch("src.core.infra.network_client.AsyncNetworkClient.request") as mock_req:
            
            mock_req.return_value = MockResponse(200, "OK")
            
            # URLに数値IDが含まれるケース
            matches = [("1", "numeric", "url")]
            url = "https://example.com/api/users/1"
            
            # 実際のリクエスト実行を伴うテスト
            mock_client = MagicMock()
            mock_client.request.return_value = MockResponse(200, "OK")
            
            await agent._run_id_manipulation_check(mock_client, url, "GET", {}, None, matches, False)
            
            # 呼ばれたURLの中に、プールから取った "555" が含まれているか確認
            # 呼ばれたURLの中に、プールから取った "555" が含まれているか確認
            all_called_urls = []
            for call_args_obj in mock_client.request.call_args_list:
                # call_args_obj[0] is the positional arguments tuple: (method, url, ...)
                all_called_urls.append(call_args_obj[0][1])
                
            assert any("555" in u for u in all_called_urls)
