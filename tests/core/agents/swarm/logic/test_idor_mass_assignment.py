
import pytest
from unittest.mock import AsyncMock, patch
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.logic.idor import IdorHunterSpecialist

class MockResponse:
    def __init__(self, status, text, headers=None):
        self.status = status
        self.text = text
        self.headers = headers or {}

@pytest.mark.asyncio
async def test_mass_assignment_success_write_then_read():
    """Mass Assignment 成功パターン (Write-then-Read)"""
    specialist = IdorHunterSpecialist()
    task = Task(
        id="test_mass_1",
        name="test_mass_1",
        target="http://api.example.com/users",
        params={
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": '{"name": "test"}',
            "safe_mode": False,
            "user_approved": True
        }
    )
    
    mock_unauth = AsyncMock(return_value=None)
    mock_manip = AsyncMock(return_value=[])
    
    with patch.object(IdorHunterSpecialist, "_test_unauthenticated", mock_unauth):
        with patch.object(IdorHunterSpecialist, "_test_id_manipulation", mock_manip):
            mock_client = AsyncMock()
            specialist.set_network_client(mock_client)
            
            get_baseline = MockResponse(200, '{"name": "test", "role": "user"}', {"Content-Type": "application/json"})
            post_resp = MockResponse(201, '{"id": 123, "name": "test", "role": "admin"}')
            read_resp = MockResponse(200, '{"id": 123, "name": "test", "role": "admin"}')
            
            mock_client.request.side_effect = [get_baseline, post_resp, read_resp, get_baseline, post_resp, read_resp]
            
            findings = await specialist.execute(task)
            
            mass_findings = [f for f in findings if "Mass Assignment" in f.title and "Echo Only" not in f.title]
            assert len(mass_findings) > 0

@pytest.mark.asyncio
async def test_mass_assignment_echo_only_potential():
    """Mass Assignment エコーバックのみ (Potential)"""
    specialist = IdorHunterSpecialist()
    task = Task(
        id="test_mass_2",
        name="test_mass_2",
        target="http://api.example.com/users",
        params={
            "method": "POST",
            "body": '{"name": "test"}',
            "safe_mode": False,
            "user_approved": True
        }
    )
    
    mock_unauth = AsyncMock(return_value=None)
    mock_manip = AsyncMock(return_value=[])
    
    with patch.object(IdorHunterSpecialist, "_test_unauthenticated", mock_unauth):
        with patch.object(IdorHunterSpecialist, "_test_id_manipulation", mock_manip):
            mock_client = AsyncMock()
            specialist.set_network_client(mock_client)
            
            get_baseline = MockResponse(200, '{"name": "test"}')
            post_resp = MockResponse(200, '{"id": 123, "role": "admin"}')
            read_resp = MockResponse(200, '{"id": 123, "role": "user"}')
            
            mock_client.request.side_effect = [get_baseline, post_resp, read_resp, get_baseline, post_resp, read_resp]
            
            findings = await specialist.execute(task)
            echo_findings = [f for f in findings if "Potential Mass Assignment (Echo Only)" in f.title]
            assert len(echo_findings) > 0

@pytest.mark.asyncio
async def test_urlencoded_idor_manipulation():
    """URLEncoded Body の IDOR 操作テスト"""
    specialist = IdorHunterSpecialist()
    
    url = "http://api.example.com/profile"
    method = "POST"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    body = "user_id=100&name=victim"
    
    mock_client = AsyncMock()
    specialist.set_network_client(mock_client)
    
    # baseline: 自身のID(100)が反映され、パスワードはない。
    baseline_resp = MockResponse(200, '{"user_id": "100", "role": "user"}', {"Content-Type": "application/json"})
    # test: 他人のID(例:UUIDや101)が反映され、シークレットがある。
    test_resp = MockResponse(200, '{"user_id": "victim", "role": "admin", "api_key": "AIzaSyAxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}', {"Content-Type": "application/json"})
    
    # baseline, and subsequent test requests
    mock_client.request.side_effect = [baseline_resp, test_resp, test_resp, test_resp, test_resp]
    
    from src.core.agents.swarm.logic.response_comparator import ComparisonResult
    from src.core.models.finding import Severity
    mock_compare = AsyncMock(return_value=ComparisonResult(
        is_vulnerable=True,
        confidence=0.9,
        signals=["mock"],
        severity_hint=Severity.HIGH,
        report="Mocked Vulnerable"
    ))
    
    with patch("src.core.agents.swarm.logic.idor.ResponseComparator.compare", mock_compare):
        findings = await specialist._test_id_manipulation(url, method, headers, body, use_proxy=False, safe_mode=False)
    
    # タイトルが一致するか柔軟にチェック
    mani_findings = [f for f in findings if "Manipulation Success" in f.title]
    assert len(mani_findings) > 0
