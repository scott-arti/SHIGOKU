import pytest
import asyncio
import json
import logging
from unittest.mock import AsyncMock, patch
from src.core.agents.swarm.logic.idor import IdorHunterSpecialist
from src.core.agents.swarm.base import Task
from src.core.session.multi_session_manager import get_multi_session_manager
from src.core.agents.swarm.logic.body_mutator import BodyMutator
from src.core.learning.repository import get_learning_repository
from src.core.infra.event_bus import get_event_bus, Event, EventType
from src.core.attack.openapi_tester import OpenAPITester

logger = logging.getLogger(__name__)

@pytest.mark.asyncio
async def test_tier_1_to_3_data_flow():
    """
    Tier 1-3 の各コンポーネント間で、実際にどのようなデータが生成・受け渡し
    されているか（Data Flow）を厳密にテスト・可視化します。
    """
    print("\n" + "="*50)
    print("🚀 [TEST START] Tier 1-3 Data Flow Verification")
    print("="*50)

    # =========================================================================
    # [Tier 1] BodyMutator (Multipart) のデータ検証
    # =========================================================================
    print("\n[✓] Tier 1: Testing BodyMutator (Multipart/form-data)...")
    content_type = 'multipart/form-data; boundary=boundary123'
    body_data = (
        "--boundary123\r\n"
        "Content-Disposition: form-data; name=\"username\"\r\n\r\n"
        "admin\r\n"
        "--boundary123--\r\n"
    )
    parsed = BodyMutator.parse(body_data, content_type)
    print("  -> Parsed multipart data:", parsed)
    
    assert "username" in parsed, "Field name is missing in parsed multipart payload"
    assert parsed["username"]["value"] == "admin", f"Parsed value mismatch: {parsed['username']['value']}"
    
    # データを改変してシリアライズ
    parsed["username"]["value"] = "admin_mutated"
    mutated_body = BodyMutator.serialize(parsed, content_type)
    
    print("  -> Mutated body snippet:")
    print(repr(mutated_body[:50]) + "...")
    assert "admin_mutated" in mutated_body, "Mutation failed during serialization"
    assert "--boundary123" in mutated_body, "Boundary string is missing in serialized multipart payload"
    
    print("  -> [PASS] Tier 1 BodyMutator logic verified.")

    # =========================================================================
    # [Tier 2] LearningRepository & EventBus のデータ検証
    # =========================================================================
    print("\n[✓] Tier 2: Testing LearningRepository & EventBus...")
    
    # 1. LearningRepository
    repo = get_learning_repository()
    # クリアしてからテスト
    repo.delete("vuln_patterns", "test_mass_assign")
    repo.store("vuln_patterns", "test_mass_assign", {"payload": '{"is_admin": true}', "confidence": 0.95})
    
    retrieved = repo.retrieve("vuln_patterns", "test_mass_assign")
    print("  -> Stored and retrieved intelligence:", retrieved)
    assert retrieved is not None, "LearningRepository failed to store/retrieve data"
    assert retrieved["payload"] == '{"is_admin": true}', "Retrieved data content mismatch"
    assert retrieved["confidence"] == 0.95, "Retrieved data value mismatch"
    print("  -> [PASS] Tier 2 LearningRepository verified.")
    
    # 2. EventBus
    bus = get_event_bus()
    await bus.start()
    
    received_events = []
    async def event_listener(evt: Event):
        received_events.append(evt)
        print(f"  -> Event Listener received [Type: {evt.type.value}]: Payload: {evt.payload}")

    bus.subscribe(EventType.VULN_FOUND, event_listener)
    
    # イベント発火
    test_event = Event(
        type=EventType.VULN_FOUND,
        payload={"vuln_type": "IDOR", "target_url": "https://api.test/data/1"}
    )
    await bus.emit(test_event)
    await asyncio.sleep(0.1)  # イベントループの処理待ち
    
    assert len(received_events) == 1, "EventBus did not route the event successfully"
    assert received_events[0].payload["vuln_type"] == "IDOR", "Event payload mismatch"
    assert received_events[0].payload["target_url"] == "https://api.test/data/1", "Event target URL mismatch"
    
    await bus.stop()
    print("  -> [PASS] Tier 2 EventBus verified.")

    # =========================================================================
    # [Tier 3] MultiSessionManager, OpenAPI, IdorHunterSpecialist のデータ検証
    # =========================================================================
    print("\n[✓] Tier 3: Testing MultiSessionManager & OpenAPI extraction...")
    
    # 1. MultiSessionManager
    msm = get_multi_session_manager()
    msm.clear()
    msm.add_session("admin", {"Authorization": "Bearer admin-token-999"})
    msm.add_session("userB", {"Authorization": "Bearer userb-token-111"})
    
    alt_sessions = msm.get_all_alternative_sessions(exclude_role="userA")
    print("  -> Alternative sessions available:", list(alt_sessions.keys()))
    assert "admin" in alt_sessions, "MultiSessionManager missing 'admin' role"
    assert "userB" in alt_sessions, "MultiSessionManager missing 'userB' role"
    assert alt_sessions["admin"]["headers"]["authorization"] == "Bearer admin-token-999", "Auth header value mismatch"
    print("  -> [PASS] Tier 3 MultiSessionManager verified.")

    # 2. OpenAPI 特権キー推測
    openapi_tester = OpenAPITester()
    sample_schema = {
        "components": {
            "schemas": {
                "User": {
                    "properties": {
                        "name": {"type": "string"},
                        "role_id": {"type": "integer"},
                        "is_superuser": {"type": "boolean"},
                        "status": {"type": "string"}
                    }
                }
            }
        }
    }
    openapi_tester.spec = sample_schema
    openapi_tester.endpoints = [] # エラー回避のためのダミー設定
    extracted = openapi_tester.extract_privileged_properties()
    print("  -> Extracted privileged properties from OpenAPI schema:", extracted)
    assert extracted is not None, "OpenAPI extraction failed to return dict"
    assert "role_id" in extracted, "Failed to extract 'role_id' property"
    assert "is_superuser" in extracted, "Failed to extract 'is_superuser' property"
    assert extracted["is_superuser"] is True, "Boolean property should default to True"
    print("  -> [PASS] Tier 3 OpenAPI Privileged Property Extraction verified.")

    # 3. IdorHunterSpecialist の実行による最終結合データフローの検証
    print("\n[✓] Tier 3: Testing IdorHunterSpecialist Data Flow Execution...")
    
    specialist = IdorHunterSpecialist()
    specialist.network_client = AsyncMock()
    from unittest.mock import MagicMock
    # Workspaceモックの設定 (同期メソッドが含まれるためMagicMockを使用)
    specialist._workspace_instance = MagicMock()
    # specのモック
    specialist._workspace_instance.get_openapi_spec.return_value = {
        "openapi": "3.0.0",
        "paths": {
            "/api/v1/update": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/User"
                                }
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
                        "name": {"type": "string"},
                        "role_id": {"type": "integer"},
                        "is_superuser": {"type": "boolean"},
                        "status": {"type": "string"}
                    }
                }
            }
        }
    }

    # BOLA と Mass Assignment リクエストの両方をキャッチするためのモックレスポンス
    mock_resp_baseline = AsyncMock()
    mock_resp_baseline.status = 200
    mock_resp_baseline.text = '{"id": "doc-1", "content": "hello", "owner_id": 1}'
    mock_resp_baseline.headers = {"Content-Type": "application/json"}
    
    mock_resp_vuln = AsyncMock()
    mock_resp_vuln.status = 200
    mock_resp_vuln.text = '{"id": "doc-1", "content": "hello", "owner_id": 1, "is_superuser": true, "role_id": 99}'
    mock_resp_vuln.headers = {"Content-Type": "application/json"}
    
    # ネットワークリクエストのMockの引数をチェックして、想定通りのリクエストが飛んでいるか検証する
    captured_requests = []
    
    async def mock_request_side_effect(method, url, headers=None, data=None, **kwargs):
        captured_requests.append({
            "method": method,
            "url": url,
            "headers": headers,
            "data": data
        })
        if "is_superuser" in str(data):
            return mock_resp_vuln
        return mock_resp_baseline
        
    specialist.network_client.request = AsyncMock(side_effect=mock_request_side_effect)

    # タスク実行
    task = Task(
        id="data-flow-task",
        name="DataFlow Validation Test",
        target="https://api.example.com/api/v1/update",
        params={
            "method": "POST",
            "headers": {"Authorization": "Bearer current-user-token"},
            "body": '{"name": "new_name"}',
            "current_role": "userA",
            "user_approved": True # safe_mode 解除によるPOST許可
        }
    )
    
    findings = await specialist.execute(task)
    
    # 結果の検証
    print(f"\n  -> Found {len(findings)} Findings during Data Flow Test.")
    
    for f in findings:
        print(f"     [Finding] {f.title} (Severity: {f.severity.name})")
        print(f"               Evidence snippet: {repr(f.evidence[:100])}...")
    
    # 実際にエージェントが組み立てたリクエストペーロードを検証
    print(f"\n  -> Captured {len(captured_requests)} Network Requests.")
    
    bola_admin_called = False
    mass_assign_super_called = False
    mass_assign_role_id_called = False
    
    for req in captured_requests:
        # BOLA のテスト: MultiSessionManagerからのヘッダが適用されているか
        if req["headers"] and req["headers"].get("authorization") == "Bearer admin-token-999":
            bola_admin_called = True
            print("     [✓] Verified BOLA Matrix request sent using MultiSessionManager 'admin' header.")
            
        # Mass Assignment のテスト: OpenAPIからの抽出パラメータが注入されているか
        if req["data"] and "is_superuser" in req["data"]:
            mass_assign_super_called = True
            # 値がTrueとして注入されている事も確認
            req_data = json.loads(req["data"])
            assert req_data["is_superuser"] is True, "Injected is_superuser value should be boolean True"
            print("     [✓] Verified Mass Assignment request sent injecting 'is_superuser=True'.")
            
        if req["data"] and "role_id" in req["data"]:
            mass_assign_role_id_called = True
            req_data = json.loads(req["data"])
            assert req_data["role_id"] == 1, "Injected role_id default integer value should be 1"
            print("     [✓] Verified Mass Assignment request sent injecting 'role_id=1'.")
            
    assert bola_admin_called, "BOLA request with alternative session was not made"
    assert mass_assign_super_called, "Mass Assignment request injecting 'is_superuser' was not made"
    assert mass_assign_role_id_called, "Mass Assignment request injecting 'role_id' was not made"

    assert len(findings) > 0, "Expected findings from the vulnerable mock responses"

    print("\n" + "="*50)
    print("🎉 [TEST END] ALL Tier 1-3 Data Flow validations PASSED successfully!")
    print("="*50)
