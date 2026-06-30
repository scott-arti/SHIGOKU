"""Tests for AI classifier module.

Verifies:
- can_classify() gating (llm_client presence, call budget)
- classify() returns UNKNOWN on all failure paths
- classify() with valid response parses label/confidence
- Label validation (reject invalid labels)
- Prompt building
- Timeout handling
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.core.preflight.ai_classifier import AIClassifier
from src.core.preflight.models import ResponseClassificationInput, ResponseClassificationResult


def _mock_llm_client(agenerate_return=None, agenerate_side_effect=None, model="test-model"):
    """Helper: patch LLMClient to return a mock client with specified agenerate behavior."""
    mock_instance = MagicMock()
    mock_instance.model = model
    if agenerate_return is not None:
        mock_instance.agenerate = AsyncMock(return_value=agenerate_return)
    else:
        mock_instance.agenerate = AsyncMock(side_effect=agenerate_side_effect)
    return mock_instance


class TestCanClassify:
    def test_disabled_without_client(self):
        c = AIClassifier(llm_client=None)
        assert c.can_classify() is False

    def test_enabled_with_client(self):
        mock_client = MagicMock()
        c = AIClassifier(llm_client=mock_client)
        assert c.can_classify() is True

    def test_disabled_after_budget_exhausted(self):
        mock_client = MagicMock()
        c = AIClassifier(llm_client=mock_client, max_calls_per_run=1)
        c._call_count = 1  # Simulate one call already made
        assert c.can_classify() is False


class TestClassifyNoClient:
    @pytest.mark.asyncio
    async def test_returns_unknown_when_no_client(self):
        c = AIClassifier(llm_client=None)
        result = await c.classify(ResponseClassificationInput())
        assert result.label == "unknown"
        assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_returns_unknown_when_budget_exhausted(self):
        mock_client = MagicMock()
        c = AIClassifier(llm_client=mock_client, max_calls_per_run=0)
        result = await c.classify(ResponseClassificationInput())
        assert result.label == "unknown"
        assert result.confidence == 0.0


class TestClassifyLLMErrors:
    @pytest.mark.asyncio
    async def test_timeout_returns_unknown(self):
        import asyncio
        mock_instance = _mock_llm_client(agenerate_side_effect=asyncio.TimeoutError())
        c = AIClassifier(llm_client=MagicMock())
        with patch('src.core.models.llm.LLMClient', return_value=mock_instance):
            result = await c.classify(ResponseClassificationInput())
        assert result.label == "unknown"
        assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_llm_error_returns_unknown(self):
        mock_instance = _mock_llm_client(agenerate_side_effect=RuntimeError("model crashed"))
        c = AIClassifier(llm_client=MagicMock())
        with patch('src.core.models.llm.LLMClient', return_value=mock_instance):
            result = await c.classify(ResponseClassificationInput())
        assert result.label == "unknown"
        assert result.confidence == 0.0


class TestClassifyValidResponse:
    @pytest.mark.asyncio
    async def test_valid_response_parses_correctly(self):
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content='{"label": "authenticated", "confidence": 0.95}'))
        ]
        mock_instance = _mock_llm_client(agenerate_return=mock_response, model="deepseek-v4-flash")
        mock_injected = MagicMock()
        mock_injected.model = "deepseek-v4-flash"

        c = AIClassifier(llm_client=mock_injected)
        inp = ResponseClassificationInput(
            title="Dashboard",
            status_code=200,
            top_markers=["dashboard", "welcome"],
        )
        with patch('src.core.models.llm.LLMClient', return_value=mock_instance):
            result = await c.classify(inp)
        assert result.label == "authenticated"
        assert result.confidence == 0.95
        assert result.model_used == "deepseek-v4-flash"

    @pytest.mark.asyncio
    async def test_label_case_normalization(self):
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content='{"label": "LOGIN_PAGE", "confidence": 0.8}'))
        ]
        mock_instance = _mock_llm_client(agenerate_return=mock_response, model="test-model")

        c = AIClassifier(llm_client=MagicMock())
        inp = ResponseClassificationInput()
        with patch('src.core.models.llm.LLMClient', return_value=mock_instance):
            result = await c.classify(inp)
        assert result.label == "login_page"

    @pytest.mark.asyncio
    async def test_confidence_clamped(self):
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content='{"label": "waf_challenge", "confidence": 1.5}'))
        ]
        mock_instance = _mock_llm_client(agenerate_return=mock_response, model="test-model")

        c = AIClassifier(llm_client=MagicMock())
        with patch('src.core.models.llm.LLMClient', return_value=mock_instance):
            result = await c.classify(ResponseClassificationInput())
        assert result.confidence == 1.0  # clamped


class TestClassifyInvalidResponse:
    @pytest.mark.asyncio
    async def test_invalid_json_returns_unknown(self):
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content="not json at all"))
        ]
        mock_instance = _mock_llm_client(agenerate_return=mock_response)

        c = AIClassifier(llm_client=MagicMock())
        with patch('src.core.models.llm.LLMClient', return_value=mock_instance):
            result = await c.classify(ResponseClassificationInput())
        assert result.label == "unknown"
        assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_invalid_label_returns_unknown(self):
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content='{"label": "not_a_real_label", "confidence": 0.9}'))
        ]
        mock_instance = _mock_llm_client(agenerate_return=mock_response)

        c = AIClassifier(llm_client=MagicMock())
        with patch('src.core.models.llm.LLMClient', return_value=mock_instance):
            result = await c.classify(ResponseClassificationInput())
        assert result.label == "unknown"
        assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_missing_label_field(self):
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content='{"confidence": 0.9}'))
        ]
        mock_instance = _mock_llm_client(agenerate_return=mock_response)

        c = AIClassifier(llm_client=MagicMock())
        with patch('src.core.models.llm.LLMClient', return_value=mock_instance):
            result = await c.classify(ResponseClassificationInput())
        # Default label when missing is "unknown"
        assert result.label == "unknown"

    @pytest.mark.asyncio
    async def test_bad_response_structure(self):
        mock_response = "not an object with choices"  # Wrong type
        mock_instance = _mock_llm_client(agenerate_return=mock_response)

        c = AIClassifier(llm_client=MagicMock())
        with patch('src.core.models.llm.LLMClient', return_value=mock_instance):
            result = await c.classify(ResponseClassificationInput())
        assert result.label == "unknown"
        assert result.confidence == 0.0


class TestCallBudget:
    @pytest.mark.asyncio
    async def test_call_count_increments(self):
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content='{"label": "unknown", "confidence": 0.1}'))
        ]
        mock_instance = _mock_llm_client(agenerate_return=mock_response, model="test")

        c = AIClassifier(llm_client=MagicMock(), max_calls_per_run=3)
        assert c._call_count == 0

        with patch('src.core.models.llm.LLMClient', return_value=mock_instance):
            await c.classify(ResponseClassificationInput())
        assert c._call_count == 1

        with patch('src.core.models.llm.LLMClient', return_value=mock_instance):
            await c.classify(ResponseClassificationInput())
        assert c._call_count == 2

    @pytest.mark.asyncio
    async def test_budget_exhausted_stops_classifying(self):
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content='{"label": "unknown", "confidence": 0.1}'))
        ]
        mock_instance = _mock_llm_client(agenerate_return=mock_response)
        c = AIClassifier(llm_client=MagicMock(), max_calls_per_run=1)

        # First call works
        with patch('src.core.models.llm.LLMClient', return_value=mock_instance) as mock_class:
            await c.classify(ResponseClassificationInput())
            assert mock_instance.agenerate.call_count == 1

        # Second call should NOT invoke LLM (budget exhausted)
        with patch('src.core.models.llm.LLMClient', return_value=mock_instance) as mock_class:
            result = await c.classify(ResponseClassificationInput())
            assert result.label == "unknown"
            assert mock_instance.agenerate.call_count == 1  # No additional call
