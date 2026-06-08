from src.core.engine.skip_reason_registry import (
    KNOWN_SKIP_REASONS,
    normalize_skip_reason,
)


def test_normalize_skip_reason_alias_mapping():
    assert normalize_skip_reason("timeout_circuit_open") == "timeout_circuit_breaker_open"


def test_normalize_skip_reason_suffix_mapping():
    assert normalize_skip_reason("dns_lookup_timeout") == "timeout_circuit_breaker_open"


def test_normalize_skip_reason_blank_to_unknown():
    assert normalize_skip_reason("") == "unknown"


def test_known_skip_reasons_include_expected_contract_keys():
    assert "low_ssrf_score" in KNOWN_SKIP_REASONS
    assert "ssrf_reachability_gate" in KNOWN_SKIP_REASONS
    assert "dedupe_execution_key" in KNOWN_SKIP_REASONS
    assert "timeout_circuit_breaker_open" in KNOWN_SKIP_REASONS


def test_normalize_skip_reason_react_alias_mapping():
    assert normalize_skip_reason("SKIP_CIRCUIT_OPEN") == "react_circuit_open"
    assert normalize_skip_reason("ALLOW_HIGH_VALUE_SIGNAL") == "react_allow_high_value_signal"
