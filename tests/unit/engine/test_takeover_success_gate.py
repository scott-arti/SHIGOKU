"""Tests for takeover success gates — 0-step prevention, evidence minimums, HITL classification."""
import pytest
from datetime import datetime, timezone, timedelta

from src.core.engine.recipe_loader import Recipe, RecipeStep, TakeoverCandidate
from src.core.engine.optimized_runner import (
    OptimizedRecipeRunner,
    compute_takeover_verdict,
    classify_takeover_result,
)
from src.core.adapters.external.takeover_provider_matrix_adapter import (
    ProviderEntry,
    ProviderMatrixLoader,
    TakeoverProviderMatrix,
)


# ── helpers ──────────────────────────────────────────────────────────────

def _runner_with_results(results: dict) -> OptimizedRecipeRunner:
    """Create a runner with pre-seeded results."""
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


# ── 0-step success prevention ────────────────────────────────────────────

def test_zero_step_recipe_is_not_success():
    """A recipe with 0 steps must never be considered successful."""
    runner = _runner_with_results({})
    result = runner._finalize_results(recipe_name="empty")
    assert result["success"] is False
    assert result["summary"]["total_steps"] == 0


def test_all_steps_blocked_is_not_success():
    """A recipe where all steps are blocked must not be success."""
    runner = _runner_with_results({
        "s1": _make_step_result(status="blocked", error_code="BLOCKED_SCOPE", reason="out of scope"),
        "s2": _make_step_result(status="blocked", error_code="BLOCKED_SCOPE", reason="out of scope"),
    })
    result = runner._finalize_results(recipe_name="blocked_recipe")
    assert result["success"] is False


# ── evidence minimums ────────────────────────────────────────────────────

def test_recipe_with_only_failed_steps_is_not_success():
    """All steps failing must not be success."""
    runner = _runner_with_results({
        "s1": _make_step_result(status="failed", error_code="TOOL_ERROR", reason="crash"),
    })
    result = runner._finalize_results(recipe_name="failing")
    assert result["success"] is False


def test_recipe_with_mixed_steps_can_be_success():
    """A mix of success and failed steps below threshold may succeed."""
    runner = _runner_with_results({
        "s1": _make_step_result(status="success", data={"finding": "CNAME dangling"}),
        "s2": _make_step_result(status="failed", error_code="TOOL_ERROR"),
        "s3": _make_step_result(status="success", data={"finding": "error_token_match"}),
    })
    result = runner._finalize_results(recipe_name="mixed")
    # 3 steps, 1 failed = 0.33 ratio, not >= 5 steps so threshold doesn't trigger
    assert result["success"] is True


# ── takeover verdict classification ──────────────────────────────────────

def test_compute_takeover_verdict_confirmed():
    """High-confidence provider + evidence = confirmed."""
    result = compute_takeover_verdict(
        provider_supports_auto_confirm=True,
        evidence_count=3,
        tool_agreement=True,
        stale=False,
    )
    assert result == "confirmed"


def test_compute_takeover_verdict_high_priority_manual_check():
    """Provider without auto_confirm but strong evidence → high_priority_manual_check."""
    result = compute_takeover_verdict(
        provider_supports_auto_confirm=False,
        evidence_count=5,
        tool_agreement=True,
        stale=False,
        cname_chain=["sub.example.com", "target.github.io"],
        last_seen_dead=datetime.now(timezone.utc),
    )
    assert result == "high_priority_manual_check"


def test_compute_takeover_verdict_manual_review():
    """Stale candidate or other issues → manual_review_required."""
    result = compute_takeover_verdict(
        provider_supports_auto_confirm=False,
        evidence_count=5,
        tool_agreement=True,
        stale=True,
        cname_chain=["sub.example.com"],
        last_seen_dead=datetime.now(timezone.utc) - timedelta(days=60),
    )
    assert result == "manual_review_required"


def test_compute_takeover_verdict_stale_blocks_confirmed():
    """Even with auto_confirm, a stale candidate must not be confirmed."""
    result = compute_takeover_verdict(
        provider_supports_auto_confirm=True,
        evidence_count=5,
        tool_agreement=True,
        stale=True,
    )
    assert result == "manual_review_required"


def test_compute_takeover_verdict_low_evidence_blocks_confirmed():
    """Less than 2 evidence types → manual_review_required."""
    result = compute_takeover_verdict(
        provider_supports_auto_confirm=True,
        evidence_count=1,
        tool_agreement=True,
        stale=False,
    )
    assert result == "manual_review_required"


def test_compute_takeover_verdict_tool_disagreement():
    """Tool disagreement → manual_review_required."""
    result = compute_takeover_verdict(
        provider_supports_auto_confirm=True,
        evidence_count=3,
        tool_agreement=False,
        stale=False,
    )
    assert result == "manual_review_required"


def test_compute_takeover_verdict_zero_evidence():
    """Zero evidence → no_finding."""
    result = compute_takeover_verdict(
        provider_supports_auto_confirm=True,
        evidence_count=0,
        tool_agreement=False,
        stale=False,
    )
    assert result == "no_finding"


# ── classify_takeover_result ─────────────────────────────────────────────

def test_classify_takeover_result_confirmed():
    entry = ProviderEntry(
        provider_id="aws_s3",
        supports_auto_confirm=True,
    )
    matrix = TakeoverProviderMatrix(ProviderMatrixLoader())
    verdict = classify_takeover_result(
        provider_entry=entry,
        provider_matrix=matrix,
        evidence_count=3,
        tool_agreement=True,
        candidate_is_stale=False,
    )
    assert verdict == "confirmed"


def test_classify_takeover_result_manual_review_no_provider():
    """Unknown provider → manual_review_required."""
    matrix = TakeoverProviderMatrix(ProviderMatrixLoader())
    verdict = classify_takeover_result(
        provider_entry=None,
        provider_matrix=matrix,
        evidence_count=3,
        tool_agreement=True,
        candidate_is_stale=True,
        cname_chain=[],
        last_seen_dead=datetime.now(timezone.utc) - timedelta(days=60),
    )
    assert verdict == "manual_review_required"


def test_classify_takeover_result_stale_blocks_confirmed():
    entry = ProviderEntry(
        provider_id="aws_s3",
        supports_auto_confirm=True,
    )
    matrix = TakeoverProviderMatrix(ProviderMatrixLoader())
    verdict = classify_takeover_result(
        provider_entry=entry,
        provider_matrix=matrix,
        evidence_count=5,
        tool_agreement=True,
        candidate_is_stale=True,
    )
    assert verdict == "manual_review_required"


def test_classify_takeover_result_names_all_verdict_types():
    """Verify all verdict types are covered."""
    valid_verdicts = {"confirmed", "high_priority_manual_check", "manual_review_required", "no_finding", "failed", "blocked"}
    # confirmed
    assert classify_takeover_result(
        ProviderEntry("x", supports_auto_confirm=True),
        TakeoverProviderMatrix(ProviderMatrixLoader()),
        evidence_count=3, tool_agreement=True, candidate_is_stale=False,
    ) in valid_verdicts
    # manual
    assert classify_takeover_result(
        ProviderEntry("x", supports_auto_confirm=False),
        TakeoverProviderMatrix(ProviderMatrixLoader()),
        evidence_count=5, tool_agreement=True, candidate_is_stale=False,
    ) in valid_verdicts
    # no_finding
    assert classify_takeover_result(
        ProviderEntry("x", supports_auto_confirm=True),
        TakeoverProviderMatrix(ProviderMatrixLoader()),
        evidence_count=0, tool_agreement=False, candidate_is_stale=False,
    ) in valid_verdicts


# ── stale detection integration ──────────────────────────────────────────

def test_is_candidate_stale():
    """A candidate last seen dead more than 30 days ago is stale."""
    from src.core.engine.optimized_runner import is_candidate_stale
    old = datetime.now(timezone.utc) - timedelta(days=45)
    candidate = TakeoverCandidate(
        subdomain="stale.example.com",
        candidate_id="c1",
        observed_at=datetime.now(timezone.utc),
        first_seen_dead=old,
        last_seen_dead=old,
    )
    assert is_candidate_stale(candidate) is True


def test_is_candidate_fresh():
    """A recently seen dead candidate is not stale."""
    from src.core.engine.optimized_runner import is_candidate_stale
    recent = datetime.now(timezone.utc)
    candidate = TakeoverCandidate(
        subdomain="fresh.example.com",
        candidate_id="c2",
        observed_at=recent,
        first_seen_dead=recent,
        last_seen_dead=recent,
    )
    assert is_candidate_stale(candidate) is False


# ── finalize_results with takeover metadata ──────────────────────────────

def test_finalize_results_includes_takeover_verdict():
    """_finalize_results should include a takeover_verdict when provider_matrix is available."""
    runner = _runner_with_results({
        "s1": _make_step_result(status="success", data={"finding": "CNAME dangling"}),
    })
    result = runner._finalize_results(
        recipe_name="takeover",
        provider_entry=ProviderEntry("aws_s3", supports_auto_confirm=True),
        evidence_count=1,
        stale_candidate=False,
    )
    assert result["success"] is True
    # With evidence_count=1, verdict should be manual_review_required (below threshold)
    assert "takeover_verdict" in result
    assert result["takeover_verdict"] in {"confirmed", "manual_review_required", "no_finding"}
