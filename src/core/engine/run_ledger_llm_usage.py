"""
LLM Usage tracking helpers for Run Ledger integration (Step 6).

Extracts normalized usage from litellm responses and records
events to the RunLedgerRecorder. Designed to be called from
LLMClient boundary (generate / agenerate).
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from src.core.models.run_ledger import (
    LLMUsageRecord,
    RunLedgerEventType,
    UsageStatus,
    CacheStatus,
    CostEstimateStatus,
    get_run_ledger_recorder,
)

logger = logging.getLogger(__name__)


def extract_llm_usage(
    response: Any,
    model: str,
    actor: str,
) -> Optional[LLMUsageRecord]:
    """
    Extract normalized LLMUsageRecord from a litellm response object.

    Returns None if no usage data is available (e.g., response is None,
    no usage attribute, or malformed).

    Args:
        response: litellm ModelResponse or similar object with .usage attribute.
        model: Model name used for the call.
        actor: Actor name (e.g., "MasterConductor", "SwarmWorker").

    Returns:
        LLMUsageRecord or None.
    """
    if response is None:
        return None

    try:
        usage = getattr(response, "usage", None)
        if usage is None:
            return None

        input_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
        output_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
        input_cache_tokens = int(getattr(usage, "cache_read_input_tokens", 0) or 0)

        # Try to get request_id from response
        request_id = getattr(response, "id", None) or getattr(response, "_request_id", None)

        return LLMUsageRecord(
            model=model,
            actor=actor,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            input_cache_tokens=input_cache_tokens,
            request_id=str(request_id) if request_id else None,
            raw_provider=None,
            usage_source="litellm",
            usage_status=UsageStatus.MEASURED,
            cache_status=CacheStatus.HIT if input_cache_tokens > 0 else CacheStatus.MISS,
            cost_estimate_status=CostEstimateStatus.UNAVAILABLE,
        )
    except Exception as exc:
        logger.debug("extract_llm_usage: cannot extract usage from response: %s", exc)
        return None


def try_record_llm_usage(
    response: Any,
    model: str,
    actor: str,
) -> None:
    """
    Extract and record LLM usage from a successful response.

    Records both the LLMUsageRecord and an llm_called event.
    Safe to call — failures are logged but never raised.
    """
    try:
        record = extract_llm_usage(response, model, actor)
        recorder = get_run_ledger_recorder()
        if record is not None:
            recorder.add_llm_usage(record)
        recorder.record(
            event_type=RunLedgerEventType.LLM_CALLED,
            phase="llm",
            actor_type="LLMClient",
            actor_name=actor,
            input_summary=f"LLM call to {model}",
            action="generate",
            result="success" if record is not None else "no_usage_data",
            source_refs={
                "model": model,
                "usage_status": record.usage_status.value if record else "unknown",
            },
        )
    except Exception as exc:
        logger.debug("try_record_llm_usage: recording failed (non-fatal): %s", exc)


def try_record_llm_cache_hit(
    model: str,
    actor: str,
) -> None:
    """
    Record an LLM cache hit event.

    Cache hits produce no real usage — the cached response is used directly.
    We record an llm_cache_hit event and an UNKNOWN usage record to track
    the cache hit (not counted as real token usage).
    """
    try:
        recorder = get_run_ledger_recorder()
        recorder.add_llm_usage(LLMUsageRecord(
            model=model,
            actor=actor,
            input_tokens=0,
            output_tokens=0,
            usage_status=UsageStatus.UNKNOWN,
            cache_status=CacheStatus.HIT,
        ))
        recorder.record(
            event_type=RunLedgerEventType.LLM_CACHE_HIT,
            phase="llm",
            actor_type="LLMClient",
            actor_name=actor,
            input_summary=f"Cache hit for {model}",
            action="cache_hit",
            result="cache_hit",
            source_refs={"model": model},
        )
    except Exception as exc:
        logger.debug("try_record_llm_cache_hit: recording failed (non-fatal): %s", exc)


def try_record_llm_retry(
    model: str,
    actor: str,
    attempt: int,
    error: str,
) -> None:
    """Record an LLM retry attempt."""
    try:
        get_run_ledger_recorder().record(
            event_type=RunLedgerEventType.LLM_RETRY,
            phase="llm",
            actor_type="LLMClient",
            actor_name=actor,
            input_summary=f"Retry attempt {attempt} for {model}",
            action="retry",
            result="retry",
            error=error[:500],
            source_refs={"model": model, "attempt": attempt},
        )
    except Exception as exc:
        logger.debug("try_record_llm_retry: recording failed (non-fatal): %s", exc)


def try_record_llm_failed(
    model: str,
    actor: str,
    error: str,
) -> None:
    """Record an LLM call failure."""
    try:
        get_run_ledger_recorder().record(
            event_type=RunLedgerEventType.LLM_FAILED,
            phase="llm",
            actor_type="LLMClient",
            actor_name=actor,
            input_summary=f"LLM call to {model} failed",
            action="generate",
            result="failed",
            error=error[:500],
            source_refs={"model": model},
        )
    except Exception as exc:
        logger.debug("try_record_llm_failed: recording failed (non-fatal): %s", exc)


def try_record_provider_fallback(
    from_model: str,
    to_model: str,
    actor: str,
    reason: str,
) -> None:
    """Record a provider fallback event."""
    try:
        get_run_ledger_recorder().record(
            event_type=RunLedgerEventType.PROVIDER_FALLBACK,
            phase="llm",
            actor_type="LLMClient",
            actor_name=actor,
            input_summary=f"Provider fallback: {from_model} -> {to_model}",
            action="fallback",
            result="fallback",
            error=reason[:500],
            source_refs={
                "from_model": from_model,
                "to_model": to_model,
            },
        )
    except Exception as exc:
        logger.debug("try_record_provider_fallback: recording failed (non-fatal): %s", exc)
