import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch
from src.core.agents.swarm.logic.idor import IdorHunterSpecialist
from src.core.models.finding import VulnType, Severity

@pytest.fixture
def mock_workspace():
    workspace = MagicMock()
    workspace.get_pool_ids.return_value = ["999"]
    return workspace

@pytest.fixture
def idor_specialist(mock_workspace):
    specialist = IdorHunterSpecialist()
    specialist._workspace_instance = mock_workspace
    specialist.network_client = AsyncMock()
    return specialist

@pytest.mark.asyncio
async def test_test_hpp_url_query(idor_specialist):
    """URL クエリの HPP 検知をテスト"""
    url = "http://example.com/api/user?id=123"
    method = "GET"
    headers = {"Content-Type": "application/json"}
    
    # モックレスポンス: 攻撃パラメータ 999 が含まれる場合に脆弱と判定
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.text = '{"username": "attacker", "id": 999}'
    mock_resp.json.return_value = {"username": "attacker", "id": 999}
    idor_specialist.network_client.request.return_value = mock_resp
    
    findings = await idor_specialist._test_hpp(url, method, headers, None)
    
    assert len(findings) > 0
    assert any("HPP IDOR: Parameter Pollution in URL Query" in f.title for f in findings)
    # request が複数回呼ばれているはず (標準重複, 配列形式など)
    assert idor_specialist.network_client.request.call_count >= 1

@pytest.mark.asyncio
async def test_test_hpp_body(idor_specialist):
    """Body (JSON) の HPP 検知をテスト"""
    url = "http://example.com/api/user"
    method = "POST"
    headers = {"Content-Type": "application/json"}
    body = '{"id": 123, "name": "test"}'
    
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.text = '{"status": "success", "id": 999}'
    idor_specialist.network_client.request.return_value = mock_resp
    
    findings = await idor_specialist._test_hpp(url, method, headers, body)
    
    assert len(findings) > 0
    assert any("HPP IDOR: Parameter Pollution in Body" in f.title for f in findings)

@pytest.mark.asyncio
async def test_test_mass_assignment_dynamic(idor_specialist):
    """動的プロパティ抽出と Mass Assignment 検知をテスト"""
    url = "http://example.com/api/profile/1"
    method = "PUT"
    headers = {"Content-Type": "application/json"}
    body = '{"name": "new_name"}'
    
    # 1. GET ベースライン応答 (admin フィールドが含まれている)
    mock_get_resp = MagicMock()
    mock_get_resp.status = 200
    mock_get_resp.headers = {"Content-Type": "application/json"}
    mock_get_resp.text = '{"id": 1, "name": "new_name", "admin": false, "role": "user"}'
    mock_get_resp.json.return_value = {"id": 1, "name": "new_name", "admin": False, "role": "user"}
    
    # 2. 攻撃後の応答 (admin が true になっている)
    mock_attack_resp = MagicMock()
    mock_attack_resp.status = 200
    mock_attack_resp.text = '{"id": 1, "name": "new_name", "admin": true, "role": "user"}'
    mock_attack_resp.json.return_value = {"id": 1, "name": "new_name", "admin": True, "role": "user"}
    
    # 3. 再取得 (検証) 応答
    mock_final_resp = MagicMock()
    mock_final_resp.status = 200
    mock_final_resp.text = '{"id": 1, "name": "new_name", "admin": true, "role": "user"}'
    mock_final_resp.json.return_value = {"id": 1, "name": "new_name", "admin": True, "role": "user"}
    
    idor_specialist.network_client.request.side_effect = [
        mock_get_resp,    # ベースライン取得
        mock_attack_resp, # 攻撃リクエスト (ループ内)
        mock_final_resp   # 再取得検証
    ]
    
    # safe_mode=False で実行
    findings = await idor_specialist._test_mass_assignment(url, method, headers, body, safe_mode=False)
    
    assert len(findings) > 0
    assert any("Mass Assignment" in f.title for f in findings)
    # admin が候補に入っているはず
    assert any("admin" in f.description for f in findings)
