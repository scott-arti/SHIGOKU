import pytest
import asyncio
from unittest.mock import MagicMock, patch
from src.core.agents.swarm.logic.response_comparator import ResponseComparator, ComparisonInput
from src.core.models.finding import Severity

class TestResponseComparator:

    @pytest.mark.asyncio
    async def test_vulnerable_same_structure_different_data(self):
        comparator = ResponseComparator()
        b_body = '{"id": 123, "name": "Alice", "role": "user"}'
        t_body = '{"id": 456, "name": "Bob", "role": "user"}'
        
        data = ComparisonInput(
            baseline_status=200, baseline_body=b_body, baseline_headers={},
            test_status=200, test_body=t_body, test_headers={},
            original_id="123", test_id="456"
        )
        
        with patch("src.core.agents.swarm.logic.response_comparator.ResponseComparator._scan_for_secrets") as mock_sf:
            mock_sf.return_value = []
            result = await comparator.compare(data)
            
            assert result.is_vulnerable is True
            assert result.confidence >= 0.6
            assert "json_structure_match" in str(result.signals)
            assert "different_data" in str(result.signals)
            assert "=== IDOR Diagnostic Report ===" in result.report

    @pytest.mark.asyncio
    async def test_not_vulnerable_error_keywords(self):
        comparator = ResponseComparator()
        b_body = '{"id": 123, "name": "Alice"}'
        t_body = '{"status": "error", "message": "Not Found"}'
        
        data = ComparisonInput(
            baseline_status=200, baseline_body=b_body, baseline_headers={},
            test_status=200, test_body=t_body, test_headers={},
            original_id="123", test_id="456"
        )
        
        with patch("src.core.agents.swarm.logic.response_comparator.ResponseComparator._scan_for_secrets") as mock_sf:
            mock_sf.return_value = []
            result = await comparator.compare(data)
            
            assert result.is_vulnerable is False
            assert "error_body_detected" in str(result.signals)

    @pytest.mark.asyncio
    async def test_critical_with_secrets(self):
        comparator = ResponseComparator()
        b_body = '{"id": 123}'
        t_body = '{"id": 456, "key": "AKIAEXAMPLE"}'
        
        data = ComparisonInput(
            baseline_status=200, baseline_body=b_body, baseline_headers={},
            test_status=200, test_body=t_body, test_headers={},
            original_id="123", test_id="456"
        )
        
        with patch("src.core.agents.swarm.logic.response_comparator.ResponseComparator._scan_for_secrets") as mock_sf:
            mock_sf.return_value = [{"rule": "AWS Key"}]
            result = await comparator.compare(data)
            
            assert result.is_vulnerable is True
            assert result.severity_hint == Severity.CRITICAL
            assert "secret_detected" in str(result.signals)

    @pytest.mark.asyncio
    async def test_json_structure_logic(self):
        comparator = ResponseComparator()
        b = '{"user": {"id": 1, "meta": {"role": "a"}}}'
        t = '{"user": {"id": 2, "meta": {"role": "b"}}}'
        
        ratio, _, _ = comparator._check_json_structure(b, t)
        assert ratio == 1.0
        
        t_missing = '{"user": {"id": 2}}'
        ratio_missing, _, _ = comparator._check_json_structure(b, t_missing)
        assert ratio_missing < 1.0
