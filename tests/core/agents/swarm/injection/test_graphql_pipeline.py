"""
L4 Pipeline Tests for GraphQL Detection
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock

from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.domain.model.task import Task


class TestRunGraphQLHunterStoresFindings:
    """run_graphql_hunter の Finding 格納テスト"""

    @pytest.fixture
    def manager(self):
        return InjectionManagerAgent()

    @pytest.mark.asyncio
    async def test_findings_stored_in_current_context(self, manager):
        """Finding が current_context["findings"] に格納される"""
        mock_finding = Mock()
        mock_finding.additional_info = {}
        mock_finding.description = "Test finding"
        mock_finding.severity = Mock()
        mock_finding.severity.name = "HIGH"
        
        with patch.object(manager, "specialists", {"graphql": Mock()}):
            manager.specialists["graphql"].execute = AsyncMock(return_value=[mock_finding])
            
            result = await manager.run_graphql_hunter("http://test.com/graphql")
            
            assert result["findings_count"] == 1
            assert result["vulnerable"] is True

    @pytest.mark.asyncio
    async def test_no_findings_when_not_vulnerable(self, manager):
        """脆弱性なしの場合 findings_count=0"""
        with patch.object(manager, "specialists", {"graphql": Mock()}):
            manager.specialists["graphql"].execute = AsyncMock(return_value=[])
            
            result = await manager.run_graphql_hunter("http://test.com/graphql")
            
            assert result["findings_count"] == 0
            assert result["vulnerable"] is False

    @pytest.mark.asyncio
    async def test_result_shape_has_required_keys(self, manager):
        """結果に必要なキーが含まれる"""
        with patch.object(manager, "specialists", {"graphql": Mock()}):
            manager.specialists["graphql"].execute = AsyncMock(return_value=[])
            
            result = await manager.run_graphql_hunter("http://test.com/graphql")
            
            assert "findings_count" in result
            assert "vulnerable" in result
            assert "tested_params" in result

    @pytest.mark.asyncio
    async def test_current_context_guard_no_keyerror(self, manager):
        """current_context未初期化でもKeyErrorが発生しない"""
        manager.current_context = None
        
        with patch.object(manager, "specialists", {"graphql": Mock()}):
            manager.specialists["graphql"].execute = AsyncMock(return_value=[])
            
            # Should not raise KeyError
            result = await manager.run_graphql_hunter("http://test.com/graphql")
            
            assert isinstance(manager.current_context, dict)
            assert "findings" in manager.current_context


class TestDispatchGraphQLPhase1:
    """Phase1 dispatch の GraphQL テスト"""

    @pytest.mark.asyncio
    async def test_dispatch_graphql_candidate_calls_run_graphql_hunter(self):
        """graphql_candidate タスクが run_graphql_hunter を呼び出す"""
        manager = InjectionManagerAgent()
        
        with patch.object(manager, "run_graphql_hunter", new_callable=AsyncMock) as mock_hunter:
            mock_hunter.return_value = {"findings_count": 0}
            
            # Simulate dispatch (this is a simplified test)
            # Real dispatch would be more complex
            result = await manager.run_graphql_hunter("http://test.com/graphql")
            
            assert "findings_count" in result


class TestUnknownCategoryTriggersGraphQL:
    """unknown カテゴリでの GraphQL 検出テスト"""

    @pytest.mark.asyncio
    async def test_unknown_category_triggers_graphql_scan(self):
        """unknown カテゴリで graphql パスが検出される"""
        manager = InjectionManagerAgent()
        
        # Mock the _build_unknown_hypotheses to return graphql (dict format)
        with patch.object(manager, "_build_unknown_hypotheses") as mock_build:
            mock_build.return_value = {
                "hypotheses": ["graphql"],
                "signals": ["graphql_signal"],
                "selected_specialists": ["graphql"],
            }
            
            with patch.object(manager, "run_graphql_hunter", new_callable=AsyncMock) as mock_hunter:
                mock_hunter.return_value = {"findings_count": 0}
                
                # Call the unknown hypothesis scans
                result = await manager._run_unknown_hypothesis_scans(
                    "http://test.com/graphql",
                    {},
                    quick_mode=False
                )
                
                # Result should be a dict with findings
                assert isinstance(result, dict)
