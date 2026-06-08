from typing import Dict

# Canonical skip reasons for aggregation contracts.
KNOWN_SKIP_REASONS = {
    "low_ssrf_score",
    "ssrf_reachability_gate",
    "dedupe_execution_key",
    "timeout_circuit_breaker_open",
    "react_disabled",
    "react_no_llm_client",
    "react_not_success",
    "react_no_signal",
    "react_low_value_task",
    "react_budget_exceeded",
    "react_circuit_open",
    "react_token_budget_exceeded",
    "react_sampling_policy",
    "react_queue_overflow",
    "react_allow_high_value_signal",
    "react_allow_sampled",
}

# Limited alias mapping. Keep intentionally strict to avoid over-merging semantics.
SKIP_REASON_ALIASES: Dict[str, str] = {
    "timeout_circuit_open": "timeout_circuit_breaker_open",
    "dedupe_key": "dedupe_execution_key",
    "low_ssrf": "low_ssrf_score",
    "skip_disabled": "react_disabled",
    "skip_no_llm_client": "react_no_llm_client",
    "skip_not_success": "react_not_success",
    "skip_no_signal": "react_no_signal",
    "skip_low_value_task": "react_low_value_task",
    "skip_budget_exceeded": "react_budget_exceeded",
    "skip_circuit_open": "react_circuit_open",
    "skip_token_budget_exceeded": "react_token_budget_exceeded",
    "skip_sampling_policy": "react_sampling_policy",
    "skip_queue_overflow": "react_queue_overflow",
    "allow_high_value_signal": "react_allow_high_value_signal",
    "allow_sampled": "react_allow_sampled",
}


def normalize_skip_reason(raw_reason: str) -> str:
    reason = str(raw_reason or "").strip().lower()
    if not reason:
        return "unknown"
    if reason in SKIP_REASON_ALIASES:
        return SKIP_REASON_ALIASES[reason]
    # Normalize common suffix variants without broad fuzzy merge.
    if reason.endswith("_timeout"):
        return "timeout_circuit_breaker_open"
    return reason
