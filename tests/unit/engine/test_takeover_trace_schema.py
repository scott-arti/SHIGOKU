"""Tests for TakeoverCandidate trace schema and RecipeCandidate trace propagation.

Covers plan sections 3.1, 3.4.4, 4.4, 4.5, 4.10:
  - TakeoverCandidate trace fields (source_line, producer_step, session_id, artifact_hash)
  - RecipeCandidate supporting_evidence enriched with trace metadata
  - match_recipes_to_context() propagation
  - _finalize_results() trace field inclusion
  - null/None graceful handling
"""
import pytest
from datetime import datetime, timezone
from unittest.mock import patch

from src.core.engine.recipe_loader import (
    TakeoverCandidate,
    RecipeCandidate,
    RecipeLoader,
    Recipe,
    RecipeStep,
    extract_signals,
)


# ── helpers ──────────────────────────────────────────────────────────────

def _make_candidate(**overrides) -> TakeoverCandidate:
    now = datetime.now(timezone.utc)
    defaults = {
        "subdomain": "test.example.com",
        "candidate_id": "takeover_abc123",
        "observed_at": now,
        "first_seen_dead": now,
        "last_seen_dead": now,
        "cname_chain": ["test.example.com", "target.cloudfront.net"],
        "provider_guess": "aws_cloudfront",
        "freshness_score": 1.0,
        "required_signals": {"dns_dead": True, "cname_dangling": True},
        "blocking_signals": set(),
        "raw_evidence": {},
        "manual_claim_review_required": False,
        # trace fields
        "source_line": None,
        "producer_step": None,
        "session_id": None,
        "artifact_hash": None,
    }
    defaults.update(overrides)
    return TakeoverCandidate(**defaults)


def _make_recipe(name="takeover", required_signals=None, blocking_signals=None,
                 success_condition=None, stop_condition=None):
    trigger = {"type": "signal"}
    if required_signals:
        trigger["required_signals"] = required_signals
    if blocking_signals:
        trigger["blocking_signals"] = blocking_signals
    if success_condition:
        trigger["success_condition"] = success_condition
    if stop_condition:
        trigger["stop_condition"] = stop_condition
    return Recipe(
        name=name,
        description="desc",
        agent="swarm",
        trigger=trigger,
        steps=[RecipeStep(id="s0", name="S0", action="scan")],
    )


# ── TakeoverCandidate trace fields ────────────────────────────────────────

class TestTakeoverCandidateTraceFields:
    """Plan section 4.10: TakeoverCandidate must carry trace metadata."""

    def test_default_trace_fields_are_none(self):
        """New trace fields should default to None for backward compat."""
        cand = TakeoverCandidate(
            subdomain="test.example.com",
            candidate_id="c1",
            observed_at=datetime.now(timezone.utc),
            first_seen_dead=datetime.now(timezone.utc),
            last_seen_dead=datetime.now(timezone.utc),
        )
        assert cand.source_line is None
        assert cand.producer_step is None
        assert cand.session_id is None
        assert cand.artifact_hash is None

    def test_trace_fields_accept_values(self):
        """Trace fields should accept and retain assigned values."""
        cand = _make_candidate(
            source_line="dns.json:459",
            producer_step="recon.step3_live_check",
            session_id="sess_20260625_abc",
            artifact_hash="sha256:deadbeef...",
        )
        assert cand.source_line == "dns.json:459"
        assert cand.producer_step == "recon.step3_live_check"
        assert cand.session_id == "sess_20260625_abc"
        assert cand.artifact_hash == "sha256:deadbeef..."

    def test_trace_fields_survive_none_gracefully(self):
        """None values for trace fields should not cause errors anywhere."""
        cand = _make_candidate(
            source_line=None,
            producer_step=None,
            session_id=None,
            artifact_hash=None,
        )
        # simply accessing should not raise
        _ = cand.source_line
        _ = cand.producer_step
        _ = cand.session_id
        _ = cand.artifact_hash
        assert cand.source_line is None


# ── RecipeCandidate success/stop conditions ───────────────────────────────

class TestRecipeCandidateConditions:
    """Plan sections 3.1, 4.4: RecipeCandidate should carry success/stop conditions."""

    def test_recipe_candidate_default_conditions_are_none(self):
        """Default RecipeCandidate should have None for success/stop conditions."""
        r = _make_recipe(name="test")
        rc = RecipeCandidate(recipe=r)
        assert rc.success_condition is None
        assert rc.stop_condition is None

    def test_recipe_candidate_accepts_conditions(self):
        """RecipeCandidate should accept success_condition and stop_condition."""
        r = _make_recipe(name="test")
        rc = RecipeCandidate(
            recipe=r,
            success_condition="provider_identified_and_dangling_evidence_collected",
            stop_condition="provider_unknown_or_signal_stale",
        )
        assert rc.success_condition == "provider_identified_and_dangling_evidence_collected"
        assert rc.stop_condition == "provider_unknown_or_signal_stale"


# ── match_recipes_to_context trace propagation ────────────────────────────

class TestMatchRecipesTracePropagation:
    """Plan sections 4.5, 4.10: trace fields propagate from TakeoverCandidate
    to RecipeCandidate.supporting_evidence via match_recipes_to_context()."""

    def test_trace_fields_in_supporting_evidence(self):
        """match_recipes_to_context should propagate trace fields into supporting_evidence."""
        loader = RecipeLoader()
        loader.recipes["takeover"] = _make_recipe(
            name="takeover",
            required_signals=["dns_dead", "cname_dangling"],
            success_condition="provider_identified",
            stop_condition="provider_unknown",
        )
        cand = _make_candidate(
            subdomain="dangling.test.com",
            producer_step="recon.step3_live_check",
            session_id="sess_abc123",
            source_line="dns.json:42",
            artifact_hash="sha256:abc...",
        )
        context = {"takeover_candidates": [cand]}
        results = loader.match_recipes_to_context(context)
        assert len(results) == 1
        rc = results[0]
        ev = rc.supporting_evidence
        assert ev.get("candidate_id") == cand.candidate_id
        assert ev.get("producer_step") == "recon.step3_live_check"
        assert ev.get("session_id") == "sess_abc123"
        assert ev.get("source_line") == "dns.json:42"
        assert ev.get("artifact_hash") == "sha256:abc..."

    def test_success_stop_conditions_from_recipe_trigger(self):
        """match_recipes_to_context should read success_condition/stop_condition
        from recipe.trigger and set them on RecipeCandidate."""
        loader = RecipeLoader()
        loader.recipes["takeover"] = _make_recipe(
            name="takeover",
            required_signals=["dns_dead", "cname_dangling"],
            success_condition="provider_identified_and_dangling_evidence_collected",
            stop_condition="provider_unknown_or_signal_stale_or_claim_prerequisite_missing",
        )
        cand = _make_candidate(subdomain="dangling.test.com")
        context = {"takeover_candidates": [cand]}
        results = loader.match_recipes_to_context(context)
        assert len(results) == 1
        rc = results[0]
        assert rc.success_condition == "provider_identified_and_dangling_evidence_collected"
        assert rc.stop_condition == "provider_unknown_or_signal_stale_or_claim_prerequisite_missing"

    def test_trace_fields_graceful_when_none(self):
        """When trace fields are None, supporting_evidence should still contain keys with None values."""
        loader = RecipeLoader()
        loader.recipes["takeover"] = _make_recipe(
            name="takeover",
            required_signals=["dns_dead", "cname_dangling"],
        )
        cand = _make_candidate(
            subdomain="dangling.test.com",
            producer_step=None,
            session_id=None,
            source_line=None,
            artifact_hash=None,
        )
        context = {"takeover_candidates": [cand]}
        results = loader.match_recipes_to_context(context)
        assert len(results) == 1
        rc = results[0]
        ev = rc.supporting_evidence
        assert "producer_step" in ev
        assert ev["producer_step"] is None
        assert "session_id" in ev
        assert ev["session_id"] is None

    def test_multiple_candidates_each_get_trace(self):
        """Each candidate should have its own trace fields propagated independently."""
        loader = RecipeLoader()
        loader.recipes["takeover"] = _make_recipe(
            name="takeover",
            required_signals=["dns_dead", "cname_dangling"],
        )
        cand_a = _make_candidate(
            subdomain="a.test.com",
            candidate_id="takeover_a",
            producer_step="recon.step3_live_check",
            session_id="sess_001",
        )
        cand_b = _make_candidate(
            subdomain="b.test.com",
            candidate_id="takeover_b",
            producer_step="recon.step3_live_check",
            session_id="sess_002",
        )
        context = {"takeover_candidates": [cand_a, cand_b]}
        results = loader.match_recipes_to_context(context)
        assert len(results) == 2
        # identify each match by candidate_id
        match_a = next(r for r in results if r.supporting_evidence["candidate_id"] == "takeover_a")
        match_b = next(r for r in results if r.supporting_evidence["candidate_id"] == "takeover_b")
        assert match_a.supporting_evidence["session_id"] == "sess_001"
        assert match_b.supporting_evidence["session_id"] == "sess_002"


# ── _finalize_results trace fields ─────────────────────────────────────────

class TestFinalizeResultsTraceFields:
    """Plan section 4.10: _finalize_results should include trace fields in output."""

    def test_finalize_results_includes_trace_fields(self):
        """When trace fields are provided, they appear in the output dict."""
        from src.core.engine.optimized_runner import OptimizedRecipeRunner

        runner = OptimizedRecipeRunner(max_workers=1)
        result = runner._finalize_results(
            recipe_name="test_recipe",
            source_line="dns.json:42",
            producer_step="recon.step3_live_check",
            session_id="sess_abc",
            artifact_hash="sha256:def...",
        )
        assert result["source_line"] == "dns.json:42"
        assert result["producer_step"] == "recon.step3_live_check"
        assert result["session_id"] == "sess_abc"
        assert result["artifact_hash"] == "sha256:def..."

    def test_finalize_results_trace_defaults_none(self):
        """When trace fields are not provided, they default to None in output."""
        from src.core.engine.optimized_runner import OptimizedRecipeRunner

        runner = OptimizedRecipeRunner(max_workers=1)
        result = runner._finalize_results(recipe_name="test_recipe")
        assert result["source_line"] is None
        assert result["producer_step"] is None
        assert result["session_id"] is None
        assert result["artifact_hash"] is None

    def test_finalize_results_backward_compat(self):
        """Existing callers that don't pass trace fields still get valid output."""
        from src.core.engine.optimized_runner import OptimizedRecipeRunner

        runner = OptimizedRecipeRunner(max_workers=1)
        # legacy call without trace params
        result = runner._finalize_results(
            recipe_name="test",
            provider_entry=None,
            evidence_count=0,
            stale_candidate=False,
        )
        assert result["recipe_name"] == "test"
        assert "success" in result
        assert "summary" in result
        assert "steps" in result
        # trace fields should be present, just None
        assert result["source_line"] is None
        assert result["producer_step"] is None
        assert result["session_id"] is None
        assert result["artifact_hash"] is None


# ── extract_signals does NOT break with trace fields ─────────────────────

class TestExtractSignalsWithTraceFields:
    """Trace fields should not interfere with signal extraction."""

    def test_extract_signals_works_with_trace_fields(self):
        """Signal extraction should work normally when trace fields are populated."""
        cand = _make_candidate(
            subdomain="dangling.test.com",
            producer_step="recon.step3_live_check",
            session_id="sess_123",
            source_line="dns.json:42",
            artifact_hash="sha256:abc...",
        )
        sigs = extract_signals(cand)
        # core signals must still be present
        assert sigs.get("dns_dead") is True
        assert sigs.get("cname_dangling") is True
        assert sigs.get("subdomain") == "dangling.test.com"
        # trace fields should not be dumped as signals
        assert "source_line" not in sigs
        assert "session_id" not in sigs
