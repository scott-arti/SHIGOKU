
import pytest
import json
import uuid
from unittest.mock import MagicMock, AsyncMock, patch
from src.core.agents.swarm.logic.idor import IdorHunterSpecialist
from src.core.agents.swarm.logic.body_mutator import BodyMutator
from src.core.domain.model.task import Task
from src.core.models.finding import VulnType

@pytest.mark.asyncio
async def test_body_mutator_hpp():
    # urlencoded HPP
    body = "user_id=100&action=view"
    ct = "urlencoded"
    hpp_body = BodyMutator.duplicate_param(body, ct, "user_id", "200")
    assert "user_id=100" in hpp_body
    assert "user_id=200" in hpp_body
    
    # JSON HPP (Array bypass style)
    json_body = json.dumps({"user_id": 100})
    ct = "json"
    hpp_json = BodyMutator.duplicate_param(json_body, ct, "user_id", 200)
    data = json.loads(hpp_json)
    assert data["user_id"] == [100, 200]

@pytest.mark.asyncio
async def test_idor_hpp_detection():
    # HPP による IDOR 検知のテスト
    specialist = IdorHunterSpecialist()
    task = Task(
        id=str(uuid.uuid4()),
        name="test_hpp",
        target="http://target.com/api/user?id=100",
        params={"method": "GET"}
    )
    
    # Network client モック
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.text = "Success! resource for ID 200"
    mock_resp.headers = {"Content-Type": "text/plain"}
    mock_client.request.return_value = mock_resp
    specialist.network_client = mock_client
    
    # Workspace モック (テスト用 ID 取得用)
    mock_ws = MagicMock()
    mock_ws.get_pool_ids.return_value = ["200"]
    specialist._workspace_instance = mock_ws
    
    findings = await specialist._test_hpp("http://target.com/api/user?id=100", "GET", {}, None)
    
    assert len(findings) > 0
    assert findings[0].vuln_type == VulnType.IDOR
    assert "HPP IDOR" in findings[0].title

@pytest.mark.asyncio
async def test_idor_graphql_detection():
    # GraphQL IDOR 検知のテスト
    specialist = IdorHunterSpecialist()
    
    # GraphQL Crafter と Network Client のモック
    mock_client = AsyncMock()
    
    # 1. Introspection Response
    intro_resp = MagicMock()
    intro_resp.status = 200
    introspection_data = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {
                        "name": "Query",
                        "kind": "OBJECT",
                        "fields": [
                            {
                                "name": "getUser",
                                "args": [
                                    {
                                        "name": "id",
                                        "type": {
                                            "kind": "SCALAR",
                                            "name": "ID",
                                            "ofType": None
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        }
    }
    intro_resp.text = json.dumps(introspection_data)
    schema_json = introspection_data
    
    # 2. Attack Response (Test ID reflected)
    attack_resp = MagicMock()
    attack_resp.status = 200
    # Specialist.py L106 辺りで str(test_id) in resp.text をチェックしている
    attack_resp.text = json.dumps({"data": {"getUser": {"id": "attacking_id_val"}}})
    
    mock_client.request.side_effect = [intro_resp, attack_resp]
    specialist.network_client = mock_client
    
    # Workspace (Test ID)
    mock_ws = MagicMock()
    mock_ws.get_pool_ids.return_value = ["attacking_id_val"]
    specialist._workspace_instance = mock_ws
    
    # テスト対象メソッド呼び出し
    from src.core.attack.graphql_crafter import GraphQLCrafter
    crafter = GraphQLCrafter()
    ops = crafter.extract_id_bearing_operations(schema_json)
    print(f"\nDEBUG: Extracted ops: {ops}")
    
    test_queries = crafter.generate_idor_queries(schema_json, "attacking_id_val")
    print(f"DEBUG: Generated queries count: {len(test_queries)}")

    findings = await specialist._test_graphql_idor("http://target.com/graphql", {}, None)
    
    print(f"DEBUG: Findings count: {len(findings)}")
    for f in findings:
        print(f"DEBUG: Finding title: {f.title}")

    assert len(findings) > 0
    assert findings[0].vuln_type == VulnType.IDOR
    assert "GraphQL IDOR" in findings[0].title
