import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.core.agents.swarm.logic.idor import IdorHunterSpecialist
from src.core.agents.swarm.base import Task
from src.core.session.multi_session_manager import get_multi_session_manager

@pytest.mark.asyncio
async def test_idor_cross_session_integration():
    # 1. MultiSessionManager に代替セッションを登録
    msm = get_multi_session_manager()
    msm.clear()
    msm.add_session("admin", {"Authorization": "Bearer admin-token"})
    
    # 2. IdorHunterSpecialist の準備
    specialist = IdorHunterSpecialist()
    specialist.network_client = AsyncMock()
    
    # モックレスポンスの設定 (side_effect で複数回のリクエストに対応)
    # 1. Unauth Check (Baseline GET)
    # 2. Unauth Check (Test GET)
    # 3. ID Manipulation (Baseline GET)
    # 4. BOLA Check (Alt Session GET)
    # 5. BOLA Check (Baseline GET for comparison)
    # 6. HPP Check etc...
    
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.text = '{"id": "123", "data": "secret", "owner": "user", "user-1": "exists"}'
    mock_resp.headers = {"Content-Type": "application/json"}
    
    # 全てのリクエストに対して同じ正常レスポンスを返すように設定（BOLA検出条件を満たす）
    specialist.network_client.request.return_value = mock_resp
    
    # 3. タスク実行
    task = Task(
        id="test-task-1",
        name="IDOR Test",
        target="https://api.example.com/api/v1/data/123",
        params={
            "method": "GET",
            "headers": {"Authorization": "Bearer user-token"},
            "current_role": "user",
            "original_id": "123" # ResponseComparator 用。これがレスポンスに含まれると加点
        }
    )
    
    findings = await specialist.execute(task)
    
    # 4. 検証
    print(f"\n[Debug] BOLA Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Score: {f.confidence if hasattr(f, 'confidence') else 'N/A'})")
    assert len(findings) > 0

@pytest.mark.asyncio
async def test_idor_mass_assignment_openapi_integration():
    specialist = IdorHunterSpecialist()
    specialist.network_client = AsyncMock()
    # @property workspace のため、内部変数にセット
    specialist._workspace_instance = MagicMock()
    
    # Workspace が OpenAPI Spec を返すように設定
    specialist._workspace_instance.get_openapi_spec.return_value = {
        "paths": {
            "/api/users": {
                "post": {
                    "parameters": [],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/User"}
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "User": {
                    "properties": {
                        "username": {"type": "string"},
                        "is_admin": {"type": "boolean"} # 特権キー候補
                    }
                }
            }
        }
    }
    
    # モックレスポンス: 
    # Specialist は is_admin キーを探し、True を注入しようとする。
    # レスポンスに注入したプロパティが含まれていれば( Echo )、Findings が出る。
    resp = MagicMock()
    resp.status = 200
    resp.text = '{"id": "user-1", "username": "test", "is_admin": true}'
    resp.headers = {"Content-Type": "application/json"}
    specialist.network_client.request.return_value = resp
    
    task = Task(
        id="test-task-2",
        name="Mass Assignment Test",
        target="https://api.example.com/api/users",
        params={
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": '{"username": "test"}',
            "user_approved": True # safe_mode 解除
        }
    )
    
    findings = await specialist.execute(task)
    
    # Findings の確認
    print(f"\n[Debug] Mass Assignment Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title}")
    assert len(findings) > 0
