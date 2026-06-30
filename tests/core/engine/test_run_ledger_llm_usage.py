"""
TDD tests for LLM usage tracking integration (Step 6).
"""
import pytest

from src.core.models.llm import LLMClient
from src.core.models.run_ledger import (
    LLMUsageRecord, RunLedgerRecorder, RunLedgerEventType,
    UsageStatus, CacheStatus, CostEstimateStatus,
    get_run_ledger_recorder, reset_run_ledger_recorder,
)


# ---------------------------------------------------------------------------
# Mock litellm response with usage
# ---------------------------------------------------------------------------

class MockUsage:
    def __init__(self, prompt_tokens=0, completion_tokens=0, total_tokens=0,
                 cache_read_input_tokens=0):
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.total_tokens = total_tokens
        self.cache_read_input_tokens = cache_read_input_tokens
        self.completion_tokens_details = None
        self.prompt_tokens_details = None


class MockMessage:
    def __init__(self, content="response", tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls


class MockChoice:
    def __init__(self, message=None):
        self.message = message or MockMessage()


_sentinel = object()


class MockResponse:
    def __init__(self, choices=None, usage=_sentinel, model="test-model"):
        self.choices = choices or [MockChoice()]
        self.usage = MockUsage() if usage is _sentinel else usage
        self.model = model

    def dict(self):
        return {"choices": [{"message": {"content": c.message.content}} for c in self.choices]}


# ---------------------------------------------------------------------------
# Usage extraction tests
# ---------------------------------------------------------------------------

class TestLLMUsageExtraction:
    def test_extract_usage_from_response(self) -> None:
        """Extract token counts from a litellm-style response."""
        from src.core.engine.run_ledger_llm_usage import (
            extract_llm_usage, try_record_llm_usage,
        )
        reset_run_ledger_recorder()
        recorder = get_run_ledger_recorder(run_id="test01")

        response = MockResponse(
            usage=MockUsage(prompt_tokens=150, completion_tokens=80),
            model="deepseek/deepseek-chat",
        )
        record = extract_llm_usage(
            response=response,
            model="deepseek/deepseek-chat",
            actor="MasterConductor",
        )
        assert record is not None
        assert record.model == "deepseek/deepseek-chat"
        assert record.actor == "MasterConductor"
        assert record.input_tokens == 150
        assert record.output_tokens == 80
        assert record.usage_status == UsageStatus.MEASURED

    def test_extract_usage_with_cache_read_tokens(self) -> None:
        """Extract usage including cache read tokens."""
        from src.core.engine.run_ledger_llm_usage import extract_llm_usage
        response = MockResponse(
            usage=MockUsage(prompt_tokens=150, completion_tokens=80, cache_read_input_tokens=50),
            model="deepseek/deepseek-chat",
        )
        record = extract_llm_usage(response, "deepseek/deepseek-chat", "MC")
        assert record.input_cache_tokens == 50

    def test_extract_usage_returns_none_for_null_response(self) -> None:
        """None response returns None."""
        from src.core.engine.run_ledger_llm_usage import extract_llm_usage
        record = extract_llm_usage(None, "model", "actor")
        assert record is None

    def test_extract_usage_returns_none_for_no_usage(self) -> None:
        """Response without usage attribute returns None."""
        from src.core.engine.run_ledger_llm_usage import extract_llm_usage
        response = MockResponse(usage=None)
        record = extract_llm_usage(response, "model", "actor")
        assert record is None

    def test_try_record_llm_usage_success(self) -> None:
        """Successful LLM call records usage and llm_called event."""
        from src.core.engine.run_ledger_llm_usage import try_record_llm_usage
        reset_run_ledger_recorder()
        recorder = get_run_ledger_recorder(run_id="test01")

        response = MockResponse(
            usage=MockUsage(prompt_tokens=100, completion_tokens=50),
            model="deepseek/deepseek-chat",
        )
        try_record_llm_usage(
            response=response,
            model="deepseek/deepseek-chat",
            actor="MasterConductor",
        )
        events = recorder.get_events()
        llm_called_events = [e for e in events if e.event_type == RunLedgerEventType.LLM_CALLED]
        assert len(llm_called_events) == 1
        assert llm_called_events[0].result == "success"

        # Usage record added
        usage_records = recorder.get_llm_usage_records()
        assert len(usage_records) == 1
        assert usage_records[0].input_tokens == 100
        assert usage_records[0].output_tokens == 50

    def test_try_record_llm_cache_hit(self) -> None:
        """Cache hit records llm_cache_hit event with UNKNOWN usage."""
        from src.core.engine.run_ledger_llm_usage import try_record_llm_cache_hit
        reset_run_ledger_recorder()
        recorder = get_run_ledger_recorder(run_id="test01")

        try_record_llm_cache_hit(
            model="deepseek/deepseek-chat",
            actor="MasterConductor",
        )
        events = recorder.get_events()
        cache_events = [e for e in events if e.event_type == RunLedgerEventType.LLM_CACHE_HIT]
        assert len(cache_events) == 1
        assert cache_events[0].result == "cache_hit"

        # Usage record with unknown status and cache_hit
        usage_records = recorder.get_llm_usage_records()
        assert len(usage_records) == 1
        assert usage_records[0].usage_status == UsageStatus.UNKNOWN
        assert usage_records[0].cache_status == CacheStatus.HIT
        assert usage_records[0].input_tokens == 0
        assert usage_records[0].output_tokens == 0

    def test_try_record_llm_retry(self) -> None:
        """LLM retry records llm_retry event."""
        from src.core.engine.run_ledger_llm_usage import try_record_llm_retry
        reset_run_ledger_recorder()
        recorder = get_run_ledger_recorder(run_id="test01")

        try_record_llm_retry(
            model="deepseek/deepseek-chat",
            actor="SwarmWorker",
            attempt=2,
            error="RateLimitError",
        )
        events = recorder.get_events()
        retry_events = [e for e in events if e.event_type == RunLedgerEventType.LLM_RETRY]
        assert len(retry_events) == 1
        assert retry_events[0].result == "retry"
        assert "attempt 2" in retry_events[0].input_summary
        assert retry_events[0].error == "RateLimitError"

    def test_try_record_llm_failed(self) -> None:
        """LLM failure records llm_failed event."""
        from src.core.engine.run_ledger_llm_usage import try_record_llm_failed
        reset_run_ledger_recorder()
        recorder = get_run_ledger_recorder(run_id="test01")

        try_record_llm_failed(
            model="deepseek/deepseek-chat",
            actor="MC",
            error="AuthenticationError: Invalid API key",
        )
        events = recorder.get_events()
        failed_events = [e for e in events if e.event_type == RunLedgerEventType.LLM_FAILED]
        assert len(failed_events) == 1
        assert failed_events[0].result == "failed"
        assert "AuthenticationError" in failed_events[0].error

    def test_try_record_provider_fallback(self) -> None:
        """Provider fallback records provider_fallback event."""
        from src.core.engine.run_ledger_llm_usage import try_record_provider_fallback
        reset_run_ledger_recorder()
        recorder = get_run_ledger_recorder(run_id="test01")

        try_record_provider_fallback(
            from_model="deepseek/deepseek-v4-pro",
            to_model="deepseek/deepseek-chat",
            actor="MC",
            reason="AuthenticationError",
        )
        events = recorder.get_events()
        fallback_events = [e for e in events if e.event_type == RunLedgerEventType.PROVIDER_FALLBACK]
        assert len(fallback_events) == 1
        assert fallback_events[0].result == "fallback"
        assert "deepseek-v4-pro" in fallback_events[0].input_summary
        assert "deepseek-chat" in fallback_events[0].input_summary

    def test_try_record_llm_usage_estimated(self) -> None:
        """Estimated usage is NOT mixed into raw totals."""
        from src.core.engine.run_ledger_llm_usage import (
            try_record_llm_usage,
        )
        from src.core.models.run_ledger import LLMUsageSummary
        reset_run_ledger_recorder()
        recorder = get_run_ledger_recorder(run_id="test01")

        # Record an estimated usage manually
        recorder.add_llm_usage(LLMUsageRecord(
            model="deepseek/deepseek-chat",
            actor="MC",
            input_tokens=200,
            output_tokens=100,
            usage_status=UsageStatus.ESTIMATED,
            cost_estimate_status=CostEstimateStatus.ESTIMATED,
        ))
        summary = LLMUsageSummary.from_records(recorder.get_llm_usage_records())
        # Estimated usage NOT in raw totals
        assert summary.totals["input_tokens"] == 0
        assert summary.totals["output_tokens"] == 0
        assert summary.estimated_count == 1
