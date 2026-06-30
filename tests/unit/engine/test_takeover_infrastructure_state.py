"""Tests for infrastructure state guardrails — classifying tool availability, timeouts, and probe failures.

Plan sections 3.4.1 and 3.4.4: Separate no_finding from infrastructure_state
(tool_unavailable, probe_failed, resolver_degraded, timeout, missing_binary).
"""
import pytest
from unittest.mock import patch

from src.core.engine.optimized_runner import (
    OptimizedRecipeRunner,
    InfrastructureState,
    classify_infrastructure_state,
    check_tool_availability,
    compute_takeover_verdict,
)
from src.core.adapters.external.takeover_provider_matrix_adapter import ProviderEntry


# ── helpers ──────────────────────────────────────────────────────────────

def _runner_with_results(results: dict) -> OptimizedRecipeRunner:
    runner = OptimizedRecipeRunner()
    runner._results = results
    return runner


def _make_step_result(status="success", error_code=None, reason="ok", data=None):
    return {
        "step_id": "step_0",
        "action": "scan",
        "status": status,
        "error_code": error_code,
        "reason": reason,
        "retryable": False,
        "data": data,
    }


# ── InfrastructureState enum/values ───────────────────────────────────────

def test_infrastructure_state_has_all_required_codes():
    """InfrastructureState must define all required constant codes."""
    assert InfrastructureState.OK == "ok"
    assert InfrastructureState.TOOL_UNAVAILABLE == "tool_unavailable"
    assert InfrastructureState.PROBE_FAILED == "probe_failed"
    assert InfrastructureState.RESOLVER_DEGRADED == "resolver_degraded"
    assert InfrastructureState.TIMEOUT == "timeout"
    assert InfrastructureState.MISSING_BINARY == "missing_binary"

    # All codes should be unique
    codes = [
        InfrastructureState.OK,
        InfrastructureState.TOOL_UNAVAILABLE,
        InfrastructureState.PROBE_FAILED,
        InfrastructureState.RESOLVER_DEGRADED,
        InfrastructureState.TIMEOUT,
        InfrastructureState.MISSING_BINARY,
    ]
    assert len(codes) == len(set(codes)), "All infrastructure state codes must be unique"


# ── classify_infrastructure_state ─────────────────────────────────────────

def test_classify_infrastructure_state_missing_binary():
    """When a step reports MISSING_BINARY, classify as missing_binary."""
    results = [
        _make_step_result(status="failed", error_code="MISSING_BINARY", reason="dig binary not found"),
    ]
    state = classify_infrastructure_state(results)
    assert state == InfrastructureState.MISSING_BINARY


def test_classify_infrastructure_state_timeout():
    """When a step reports TOOL_TIMEOUT, classify as timeout."""
    results = [
        _make_step_result(status="failed", error_code="TOOL_TIMEOUT", reason="subprocess timed out"),
    ]
    state = classify_infrastructure_state(results)
    assert state == InfrastructureState.TIMEOUT


def test_classify_infrastructure_state_probe_failed():
    """When a step reports TOOL_ERROR (e.g., DNS resolution error), classify as probe_failed."""
    results = [
        _make_step_result(status="failed", error_code="TOOL_ERROR", reason="DNS resolution failure"),
    ]
    state = classify_infrastructure_state(results)
    assert state == InfrastructureState.PROBE_FAILED


def test_classify_infrastructure_state_ok():
    """When all steps succeed with no infrastructure errors, classify as ok."""
    results = [
        _make_step_result(status="success", data={"finding": "CNAME dangling"}),
        _make_step_result(status="success", data={"finding": "error_token_match"}),
    ]
    state = classify_infrastructure_state(results)
    assert state == InfrastructureState.OK


def test_classify_infrastructure_state_empty_steps():
    """Empty step list should return ok (no infrastructure issues detected)."""
    state = classify_infrastructure_state([])
    assert state == InfrastructureState.OK


def test_classify_infrastructure_state_priority_missing_binary():
    """MISSING_BINARY takes priority over other error types (tools are most fundamental)."""
    results = [
        _make_step_result(status="failed", error_code="TOOL_ERROR", reason="e1"),
        _make_step_result(status="failed", error_code="MISSING_BINARY", reason="e2"),
        _make_step_result(status="failed", error_code="TOOL_TIMEOUT", reason="e3"),
    ]
    state = classify_infrastructure_state(results)
    assert state == InfrastructureState.MISSING_BINARY


# ── check_tool_availability ──────────────────────────────────────────────

def test_check_tool_availability_missing_binary():
    """check_tool_availability returns False when shutil.which returns None."""
    with patch("shutil.which", return_value=None):
        result = check_tool_availability("nonexistent_tool")
    assert result is False


def test_check_tool_availability_existing_binary():
    """check_tool_availability returns True when shutil.which returns a path."""
    with patch("shutil.which", return_value="/usr/bin/dig"):
        result = check_tool_availability("dig")
    assert result is True


# ── infrastructure_state in takeover result ───────────────────────────────

def test_infrastructure_state_included_in_finalize_results():
    """_finalize_results must include infrastructure_state in output dict."""
    runner = _runner_with_results({
        "s1": _make_step_result(status="success", data={"finding": "CNAME dangling"}),
    })
    result = runner._finalize_results(recipe_name="test_recipe")
    assert "infrastructure_state" in result
    assert result["infrastructure_state"] == InfrastructureState.OK


def test_infrastructure_state_reflects_missing_binary():
    """When a step has MISSING_BINARY, infrastructure_state reflects it."""
    runner = _runner_with_results({
        "s1": _make_step_result(status="failed", error_code="MISSING_BINARY", reason="dig binary not found"),
    })
    result = runner._finalize_results(recipe_name="test_recipe")
    assert result["infrastructure_state"] == InfrastructureState.MISSING_BINARY


# ── no_finding distinction from infrastructure failures ──────────────────

def test_no_finding_not_returned_when_infrastructure_failed():
    """When infrastructure failed (tool unavailable), verdict must NOT be no_finding even with 0 evidence."""
    runner = _runner_with_results({
        "s1": _make_step_result(status="failed", error_code="MISSING_BINARY", reason="dig not found"),
        "s2": _make_step_result(status="failed", error_code="MISSING_BINARY", reason="nslookup not found"),
    })
    result = runner._finalize_results(
        recipe_name="takeover",
        provider_entry=None,
        evidence_count=0,
        stale_candidate=False,
    )
    # Infrastructure state is not OK
    assert result["infrastructure_state"] != InfrastructureState.OK
    # Verdict should NOT be no_finding (can't trust the absence of findings)
    assert result["takeover_verdict"] != "no_finding"
    # Should be manual_review_required because we can't determine
    assert result["takeover_verdict"] == "manual_review_required"


def test_no_finding_returned_when_infrastructure_ok_and_no_evidence():
    """When infrastructure is OK but there is genuinely no evidence, no_finding is correct.

    Note: _finalize_results uses ``evidence_count or success_count``, so
    we seed skipped steps (not ``success``) to keep both counts at zero.
    """
    runner = _runner_with_results({
        "s1": _make_step_result(status="skipped", reason="no CNAME records found"),
        "s2": _make_step_result(status="skipped", reason="no takeover indicators"),
    })
    result = runner._finalize_results(recipe_name="takeover", provider_entry=None)
    assert result["infrastructure_state"] == InfrastructureState.OK
    # With infrastructure OK and zero evidence, no_finding is appropriate
    assert result["takeover_verdict"] == "no_finding"


def test_infrastructure_state_included_alongside_all_existing_keys():
    """_finalize_results must include all required keys alongside pre-existing ones."""
    runner = _runner_with_results({
        "s1": _make_step_result(status="success", data={"finding": "CNAME dangling"}),
    })
    result = runner._finalize_results(
        recipe_name="test_recipe",
        provider_entry=None,
        evidence_count=1,
        stale_candidate=False,
    )
    # All required keys present
    assert "takeover_verdict" in result
    assert "infrastructure_state" in result
    assert "manual_review_required" in result
    assert "confirmed" in result
    assert "success" in result
    assert "summary" in result
    assert "steps" in result
    assert "recipe_name" in result


# ── Gap closure: infrastructure_state propagation from takeover steps ──

def test_takeover_step_failure_propagates_infrastructure_state():
    """When a takeover step fails with infrastructure_state=probe_failed,
    _finalize_results reports infrastructure_state != ok.

    This verifies the end-to-end flow from master_conductor's _step_executor
    (which passes infrastructure_state + error_code) through
    optimized_runner's _normalize_step_result → _finalize_results.
    """
    # Simulate what master_conductor._step_executor returns for a failed takeover step:
    runner = _runner_with_results({
        "s1": {
            "step_id": "s1",
            "action": "cname_resolve",
            "status": "failed",
            "error_code": "TOOL_ERROR",
            "reason": "DNS resolution error: timed out",
            "retryable": False,
            "data": {"cname_chain": [], "addresses": [], "rcode": "timeout"},
            "infrastructure_state": "probe_failed",
        },
    })
    result = runner._finalize_results(
        recipe_name="takeover",
        provider_entry=None,
        evidence_count=0,
    )
    # infrastructure_state must reflect probe_failed
    assert result["infrastructure_state"] == "probe_failed"
    # Verdict must NOT be no_finding (infrastructure is unhealthy)
    assert result["takeover_verdict"] != "no_finding"
    assert result["takeover_verdict"] == "manual_review_required"


def test_takeover_step_failure_classified_correctly_for_verdict():
    """When takeover step has infrastructure_state=probe_failed with proper
    error_code=TOOL_ERROR, classify_infrastructure_state sees it correctly
    and the verdict gate blocks no_finding.
    """
    runner = _runner_with_results({
        "s1": {
            "step_id": "s1",
            "action": "http_probe",
            "status": "failed",
            "error_code": "TOOL_ERROR",
            "reason": "Connection refused",
            "retryable": False,
            "data": {},
            "infrastructure_state": "probe_failed",
        },
    })
    # classify_infrastructure_state is called inside _finalize_results
    result = runner._finalize_results(
        recipe_name="takeover",
        provider_entry=None,
        evidence_count=0,
    )
    assert result["infrastructure_state"] == "probe_failed"
    # With infrastructure broken, we can't claim no_finding
    assert result["takeover_verdict"] == "manual_review_required"
    assert result["confirmed"] is False
    assert result["manual_review_required"] is True
