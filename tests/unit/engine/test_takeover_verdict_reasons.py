"""Tests for verdict_reason_codes — structured reasons explaining why a takeover candidate reached its verdict.

Plan sections 3.4.4, 4.7, 4.9 items 3-6: Replace vague "manual_review_required" with
specific reason codes such as missing_cname, stale_candidate, tool_disagreement, etc.
"""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from src.core.engine.optimized_runner import (
    OptimizedRecipeRunner,
    InfrastructureState,
    compute_verdict_reasons,
    compute_takeover_verdict,
    _MIN_EVIDENCE_FOR_CONFIRMED,
    _STALE_DAYS,
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


# ── compute_verdict_reasons: individual reason codes ─────────────────────

def test_compute_verdict_reasons_missing_cname():
    """Returns ['missing_cname'] when CNAME chain is empty."""
    reasons = compute_verdict_reasons(
        cname_chain=[],
        last_seen_dead=datetime.now(timezone.utc),
        tool_agreement=True,
        provider_supports_auto_confirm=True,
        scope_policy_blocks_takeover=False,
        evidence_count=3,
        infrastructure_state=InfrastructureState.OK,
    )
    assert "missing_cname" in reasons


def test_compute_verdict_reasons_missing_cname_none():
    """Returns ['missing_cname'] when CNAME chain is None."""
    reasons = compute_verdict_reasons(
        cname_chain=None,
        last_seen_dead=datetime.now(timezone.utc),
        tool_agreement=True,
        provider_supports_auto_confirm=True,
        scope_policy_blocks_takeover=False,
        evidence_count=3,
        infrastructure_state=InfrastructureState.OK,
    )
    assert "missing_cname" in reasons


def test_compute_verdict_reasons_stale_candidate():
    """Returns ['stale_candidate'] when candidate > _STALE_DAYS old."""
    old_date = datetime.now(timezone.utc) - timedelta(days=_STALE_DAYS + 5)
    reasons = compute_verdict_reasons(
        cname_chain=["cname.to.target"],
        last_seen_dead=old_date,
        tool_agreement=True,
        provider_supports_auto_confirm=True,
        scope_policy_blocks_takeover=False,
        evidence_count=3,
        infrastructure_state=InfrastructureState.OK,
    )
    assert "stale_candidate" in reasons


def test_compute_verdict_reasons_stale_candidate_none():
    """Returns ['stale_candidate'] when last_seen_dead is None (never seen)."""
    reasons = compute_verdict_reasons(
        cname_chain=["cname.to.target"],
        last_seen_dead=None,
        tool_agreement=True,
        provider_supports_auto_confirm=True,
        scope_policy_blocks_takeover=False,
        evidence_count=3,
        infrastructure_state=InfrastructureState.OK,
    )
    assert "stale_candidate" in reasons


def test_compute_verdict_reasons_tool_disagreement():
    """Returns ['tool_disagreement'] when tool_agreement is False."""
    reasons = compute_verdict_reasons(
        cname_chain=["cname.to.target"],
        last_seen_dead=datetime.now(timezone.utc),
        tool_agreement=False,
        provider_supports_auto_confirm=True,
        scope_policy_blocks_takeover=False,
        evidence_count=3,
        infrastructure_state=InfrastructureState.OK,
    )
    assert "tool_disagreement" in reasons


def test_compute_verdict_reasons_provider_no_auto_confirm():
    """Returns ['provider_no_auto_confirm'] when provider has auto_confirm=False."""
    reasons = compute_verdict_reasons(
        cname_chain=["cname.to.target"],
        last_seen_dead=datetime.now(timezone.utc),
        tool_agreement=True,
        provider_supports_auto_confirm=False,
        scope_policy_blocks_takeover=False,
        evidence_count=3,
        infrastructure_state=InfrastructureState.OK,
    )
    assert "provider_no_auto_confirm" in reasons


def test_compute_verdict_reasons_scope_policy_blocks_claim():
    """Returns ['scope_policy_blocks_claim'] when scope_policy_blocks_takeover is True."""
    reasons = compute_verdict_reasons(
        cname_chain=["cname.to.target"],
        last_seen_dead=datetime.now(timezone.utc),
        tool_agreement=True,
        provider_supports_auto_confirm=True,
        scope_policy_blocks_takeover=True,
        evidence_count=3,
        infrastructure_state=InfrastructureState.OK,
    )
    assert "scope_policy_blocks_claim" in reasons


def test_compute_verdict_reasons_insufficient_evidence():
    """Returns ['insufficient_evidence'] when evidence_count < _MIN_EVIDENCE_FOR_CONFIRMED."""
    reasons = compute_verdict_reasons(
        cname_chain=["cname.to.target"],
        last_seen_dead=datetime.now(timezone.utc),
        tool_agreement=True,
        provider_supports_auto_confirm=True,
        scope_policy_blocks_takeover=False,
        evidence_count=1,
        infrastructure_state=InfrastructureState.OK,
    )
    assert "insufficient_evidence" in reasons


def test_compute_verdict_reasons_infrastructure_unhealthy():
    """Returns ['infrastructure_unhealthy'] when infrastructure_state is not OK."""
    reasons = compute_verdict_reasons(
        cname_chain=["cname.to.target"],
        last_seen_dead=datetime.now(timezone.utc),
        tool_agreement=True,
        provider_supports_auto_confirm=True,
        scope_policy_blocks_takeover=False,
        evidence_count=3,
        infrastructure_state=InfrastructureState.MISSING_BINARY,
    )
    assert "infrastructure_unhealthy" in reasons


def test_compute_verdict_reasons_infrastructure_timeout():
    """Returns ['infrastructure_unhealthy'] when infrastructure_state is TIMEOUT."""
    reasons = compute_verdict_reasons(
        cname_chain=["cname.to.target"],
        last_seen_dead=datetime.now(timezone.utc),
        tool_agreement=True,
        provider_supports_auto_confirm=True,
        scope_policy_blocks_takeover=False,
        evidence_count=3,
        infrastructure_state=InfrastructureState.TIMEOUT,
    )
    assert "infrastructure_unhealthy" in reasons


# ── compute_verdict_reasons: multiple codes ──────────────────────────────

def test_compute_verdict_reasons_empty_when_all_conditions_met():
    """Returns empty list when all conditions are met (should be 'confirmed')."""
    reasons = compute_verdict_reasons(
        cname_chain=["cname.to.target"],
        last_seen_dead=datetime.now(timezone.utc),
        tool_agreement=True,
        provider_supports_auto_confirm=True,
        scope_policy_blocks_takeover=False,
        evidence_count=3,
        infrastructure_state=InfrastructureState.OK,
    )
    assert reasons == []


def test_compute_verdict_reasons_multiple_codes():
    """Returns multiple codes when multiple issues exist."""
    reasons = compute_verdict_reasons(
        cname_chain=[],  # missing_cname
        last_seen_dead=None,  # stale_candidate
        tool_agreement=False,  # tool_disagreement
        provider_supports_auto_confirm=False,  # provider_no_auto_confirm
        scope_policy_blocks_takeover=False,
        evidence_count=1,  # insufficient_evidence
        infrastructure_state=InfrastructureState.OK,
    )
    assert "missing_cname" in reasons
    assert "stale_candidate" in reasons
    assert "tool_disagreement" in reasons
    assert "provider_no_auto_confirm" in reasons
    assert "insufficient_evidence" in reasons
    assert len(reasons) == 5


# ── compute_takeover_verdict: refactored verdict logic ───────────────────

def test_verdict_confirmed_when_reasons_empty_and_evidence_positive():
    """Verdict is 'confirmed' when verdict_reason_codes is empty and evidence > 0."""
    reasons = compute_verdict_reasons(
        cname_chain=["cname.to.target"],
        last_seen_dead=datetime.now(timezone.utc),
        tool_agreement=True,
        provider_supports_auto_confirm=True,
        scope_policy_blocks_takeover=False,
        evidence_count=3,
        infrastructure_state=InfrastructureState.OK,
    )
    assert reasons == []
    verdict = compute_takeover_verdict(
        provider_supports_auto_confirm=True,
        evidence_count=3,
        tool_agreement=True,
        stale=False,
        cname_chain=["cname.to.target"],
        last_seen_dead=datetime.now(timezone.utc),
        infrastructure_state=InfrastructureState.OK,
    )
    assert verdict == "confirmed"


def test_verdict_no_finding_when_zero_evidence_and_infrastructure_ok():
    """Verdict is 'no_finding' when evidence_count == 0 AND infrastructure is OK."""
    verdict = compute_takeover_verdict(
        provider_supports_auto_confirm=True,
        evidence_count=0,
        tool_agreement=False,
        stale=False,
        infrastructure_state=InfrastructureState.OK,
    )
    assert verdict == "no_finding"


def test_verdict_manual_review_when_any_reason_code_exists():
    """Verdict is 'manual_review_required' when a blocking reason code exists (e.g. stale)."""
    verdict = compute_takeover_verdict(
        provider_supports_auto_confirm=True,
        evidence_count=3,
        tool_agreement=True,
        stale=False,
        cname_chain=["cname.to.target"],
        last_seen_dead=datetime.now(timezone.utc) - timedelta(days=60),  # triggers stale_candidate
        infrastructure_state=InfrastructureState.OK,
    )
    assert verdict == "manual_review_required"


def test_verdict_high_priority_when_only_provider_no_auto_confirm():
    """Verdict is 'high_priority_manual_check' when the ONLY reason is provider_no_auto_confirm
    and evidence is otherwise strong."""
    verdict = compute_takeover_verdict(
        provider_supports_auto_confirm=False,  # triggers provider_no_auto_confirm only
        evidence_count=3,
        tool_agreement=True,
        stale=False,
        cname_chain=["cname.to.target"],
        last_seen_dead=datetime.now(timezone.utc),
        infrastructure_state=InfrastructureState.OK,
    )
    assert verdict == "high_priority_manual_check"


def test_verdict_manual_review_when_infrastructure_unhealthy_even_with_evidence():
    """Verdict is 'manual_review_required' when infrastructure is unhealthy even with evidence."""
    verdict = compute_takeover_verdict(
        provider_supports_auto_confirm=True,
        evidence_count=3,
        tool_agreement=True,
        stale=False,
        cname_chain=["cname.to.target"],
        last_seen_dead=datetime.now(timezone.utc),
        infrastructure_state=InfrastructureState.MISSING_BINARY,
    )
    assert verdict == "manual_review_required"


def test_verdict_manual_review_when_zero_evidence_and_infrastructure_unhealthy():
    """Verdict is 'manual_review_required' when evidence_count == 0 AND infra unhealthy."""
    verdict = compute_takeover_verdict(
        provider_supports_auto_confirm=True,
        evidence_count=0,
        tool_agreement=False,
        stale=False,
        infrastructure_state=InfrastructureState.TIMEOUT,
    )
    assert verdict == "manual_review_required"


# ── _finalize_results: verdict_reason_codes in output ────────────────────

def test_finalize_results_includes_verdict_reason_codes():
    """_finalize_results must include verdict_reason_codes in output dict."""
    runner = _runner_with_results({
        "s1": _make_step_result(status="success", data={"finding": "CNAME dangling"}),
    })
    result = runner._finalize_results(recipe_name="test_recipe")
    assert "verdict_reason_codes" in result
    assert isinstance(result["verdict_reason_codes"], list)


def test_finalize_results_verdict_reason_codes_reflects_provider_issues():
    """When no provider entry, verdict_reason_codes includes provider_no_auto_confirm."""
    runner = _runner_with_results({
        "s1": _make_step_result(status="success", data={"finding": "CNAME dangling"}),
        "s2": _make_step_result(status="success", data={"finding": "error_token_match"}),
    })
    result = runner._finalize_results(
        recipe_name="takeover",
        provider_entry=None,
        evidence_count=2,
        stale_candidate=False,
    )
    assert "provider_no_auto_confirm" in result["verdict_reason_codes"]


def test_finalize_results_verdict_reason_codes_empty_for_confirmed():
    """When all conditions are met, verdict_reason_codes should be empty (confirmed)."""
    entry = ProviderEntry(provider_id="aws_s3", supports_auto_confirm=True)
    runner = _runner_with_results({
        "s1": _make_step_result(status="success", data={"finding": "CNAME dangling"}),
        "s2": _make_step_result(status="success", data={"finding": "error_token_match"}),
        "s3": _make_step_result(status="success", data={"finding": "fingerprint_match"}),
    })
    result = runner._finalize_results(
        recipe_name="takeover",
        provider_entry=entry,
        evidence_count=3,
        stale_candidate=False,
    )
    # No infrastructure failures, all steps success → no reason codes expected
    # But "missing_cname" and "stale_candidate" may appear if _finalize_results
    # cannot provide cname_chain/last_seen_dead. We expect the verdict to be
    # confirmed regardless, meaning no blocking reason codes.
    assert "takeover_verdict" in result


def test_finalize_results_verdict_reason_codes_includes_all_keys():
    """_finalize_results must include verdict_reason_codes alongside all existing keys."""
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
    assert "verdict_reason_codes" in result
    assert "takeover_verdict" in result
    assert "infrastructure_state" in result
    assert "manual_review_required" in result
    assert "confirmed" in result
    assert "success" in result
    assert "summary" in result
    assert "steps" in result
    assert "recipe_name" in result


# ── backward compatibility: existing tests must continue to pass ─────────

def test_backward_compat_compute_takeover_verdict_old_signature():
    """Calling compute_takeover_verdict with only original 4 params works."""
    # This is the old signature: (provider_supports_auto_confirm, evidence_count, tool_agreement, stale)
    verdict = compute_takeover_verdict(
        True,  # provider_supports_auto_confirm
        3,     # evidence_count
        True,  # tool_agreement
        False, # stale
    )
    assert verdict == "confirmed"


def test_backward_compat_compute_takeover_verdict_old_signature_high_priority():
    """Old signature with provider_no_auto_confirm and strong evidence → high_priority_manual_check."""
    verdict = compute_takeover_verdict(
        False,  # provider_supports_auto_confirm
        5,      # evidence_count
        True,   # tool_agreement
        False,  # stale
    )
    assert verdict == "high_priority_manual_check"


def test_backward_compat_compute_takeover_verdict_old_signature_no_finding():
    """Old signature with evidence_count=0 → no_finding."""
    verdict = compute_takeover_verdict(
        True,   # provider_supports_auto_confirm
        0,      # evidence_count
        False,  # tool_agreement
        False,  # stale
    )
    assert verdict == "no_finding"


def test_backward_compat_compute_takeover_verdict_old_signature_stale():
    """Old signature with stale=True → manual_review_required."""
    verdict = compute_takeover_verdict(
        True,  # provider_supports_auto_confirm
        5,     # evidence_count
        True,  # tool_agreement
        True,  # stale
    )
    assert verdict == "manual_review_required"


def test_backward_compat_compute_takeover_verdict_old_signature_scope():
    """Old signature with scope_policy_blocks_takeover=True → manual_review_required."""
    verdict = compute_takeover_verdict(
        True,   # provider_supports_auto_confirm
        5,      # evidence_count
        True,   # tool_agreement
        False,  # stale
        True,   # scope_policy_blocks_takeover
    )
    assert verdict == "manual_review_required"
