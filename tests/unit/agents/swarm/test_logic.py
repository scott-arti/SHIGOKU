
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.core.agents.swarm.logic.manager import MassAssignmentSpecialist, RaceConditionSpecialist
from src.core.agents.swarm.base import Task

@pytest.fixture
def mock_task():
    return Task(
        id="test_task",
        name="test",
        target="http://example.com/api/user",
        tags=["payment_flow"],
        params={
            "method": "POST",
            "api_params": {"username": "test", "role": "user"},
            "jwt_token": "test_token"
        }
    )

class TestMassAssignmentSpecialist:
    @pytest.mark.asyncio
    async def test_execute_success(self, mock_task):
        spec = MassAssignmentSpecialist()
        
        # モック
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.description = "Role parameter modified"
        mock_result.injected_field = "role"
        mock_result.payload = '{"role": "admin"}'
        mock_result.response_diff = "diff"
        
        spec._tester.test = AsyncMock(return_value=[mock_result])
        
        findings = await spec.execute(mock_task)
        
        assert len(findings) == 1
        assert findings[0].vuln_type.value == "mass_assignment"
        assert findings[0].additional_info.get("payload") == '{"role": "admin"}'

    @pytest.mark.asyncio
    async def test_execute_no_params(self, mock_task):
        spec = MassAssignmentSpecialist()
        mock_task.params = {} # パラメータなし
        
        findings = await spec.execute(mock_task)
        assert len(findings) == 0

class TestRaceConditionSpecialist:
    @pytest.mark.asyncio
    async def test_execute_critical(self, mock_task):
        spec = RaceConditionSpecialist()
        spec.is_aggressive = True
        
        # クリティカルフローとして認識させる
        mock_task.target = "http://example.com/api/coupon/apply"
        
        # モック: test_race は NetworkResponse のリストを返す
        mock_resp = MagicMock()
        spec._tester.test_race = AsyncMock(return_value=[mock_resp]*5)
        spec._tester.analyze_results = MagicMock(return_value=True)
        
        findings = await spec.execute(mock_task)
        
        assert len(findings) == 1
        assert findings[0].vuln_type.value == "race_condition"
        
    @pytest.mark.asyncio
    async def test_execute_skip_non_critical(self, mock_task):
        spec = RaceConditionSpecialist()
        spec.is_aggressive = False # 非積極的
        
        mock_task.target = "http://example.com/static/image.png"
        mock_task.tags = ["static"]
        
        findings = await spec.execute(mock_task)
        assert len(findings) == 0
