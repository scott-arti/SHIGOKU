"""Tests for TakeoverScopePolicy — scope blocking signals for takeover candidates."""
import pytest
from datetime import datetime, timezone

from src.core.policy.takeover_scope_policy import (
    TakeoverScopePolicy,
    evaluate_scope_signals,
)
from src.core.engine.recipe_loader import (
    RecipeLoader,
    Recipe,
    RecipeStep,
    RecipeCandidate,
    TakeoverCandidate,
)


# ── helpers ──────────────────────────────────────────────────────────────

def _recipe(name="r1", trigger_type="signal", required_signals=None,
            blocking_signals=None, steps=None):
    trigger = {"type": trigger_type}
    if required_signals is not None:
        trigger["required_signals"] = required_signals
    if blocking_signals is not None:
        trigger["blocking_signals"] = blocking_signals
    return Recipe(
        name=name,
        description="desc",
        agent="swarm",
        trigger=trigger,
        steps=steps or [RecipeStep(id="s0", name="S0", action="scan")],
    )


def _candidate(subdomain="test.example.com", freshness_score=1.0,
               required_signals=None, blocking_signals=None,
               cname_chain=None, provider_guess=None,
               manual_claim_review_required=False):
    now = datetime.now(timezone.utc)
    return TakeoverCandidate(
        subdomain=subdomain,
        candidate_id=f"cand_{subdomain}",
        observed_at=now,
        first_seen_dead=now,
        last_seen_dead=now,
        cname_chain=cname_chain or [],
        provider_guess=provider_guess,
        freshness_score=freshness_score,
        required_signals=required_signals or {},
        blocking_signals=blocking_signals or set(),
        raw_evidence={},
        manual_claim_review_required=manual_claim_review_required,
    )


# ── TakeoverScopePolicy class ────────────────────────────────────────────

class TestTakeoverScopePolicyClass:
    """Tests for the TakeoverScopePolicy class."""

    def test_class_exists(self):
        """TakeoverScopePolicy class exists with expected methods."""
        policy = TakeoverScopePolicy()
        assert hasattr(policy, "is_takeover_allowed")
        assert hasattr(policy, "claim_action_allowed")
        assert callable(policy.is_takeover_allowed)
        assert callable(policy.claim_action_allowed)

    def test_is_takeover_allowed_returns_bool(self):
        """is_takeover_allowed returns a bool."""
        policy = TakeoverScopePolicy()
        result = policy.is_takeover_allowed("example.com")
        assert isinstance(result, bool)

    def test_is_takeover_allowed_when_in_allowlist(self):
        """is_takeover_allowed returns True when target is in allowed list."""
        policy = TakeoverScopePolicy(allowed_targets={"example.com", "test.com"})
        assert policy.is_takeover_allowed("example.com") is True
        assert policy.is_takeover_allowed("test.com") is True

    def test_is_takeover_allowed_when_not_in_allowlist_default_deny(self):
        """is_takeover_allowed returns False when target is not in allowed list."""
        policy = TakeoverScopePolicy(allowed_targets={"example.com"})
        assert policy.is_takeover_allowed("evil.com") is False

    def test_is_takeover_allowed_permissive_with_empty_allowlist(self):
        """Empty allowlist (default) means all targets are allowed."""
        policy = TakeoverScopePolicy()  # no allowed_targets → permissive
        assert policy.is_takeover_allowed("anything.com") is True
        assert policy.is_takeover_allowed("localhost") is True

    def test_claim_action_allowed_always_false(self):
        """claim_action_allowed returns False by default — claim never automated."""
        policy = TakeoverScopePolicy()
        assert policy.claim_action_allowed("example.com") is False
        assert policy.claim_action_allowed("anything-else.com") is False

    def test_claim_action_allowed_with_override(self):
        """claim_action_allowed can be overridden via constructor for testing."""
        policy = TakeoverScopePolicy(claim_allowed=True)
        assert policy.claim_action_allowed("example.com") is True

        policy2 = TakeoverScopePolicy(claim_allowed=False)
        assert policy2.claim_action_allowed("example.com") is False


# ── evaluate_scope_signals ───────────────────────────────────────────────

class TestEvaluateScopeSignals:
    """Tests for evaluate_scope_signals()."""

    def test_returns_blocking_signal_when_takeover_not_allowed(self):
        """evaluate_scope_signals returns blocking signal when takeover_not_allowed."""
        policy = TakeoverScopePolicy(allowed_targets={"safe.com"})
        result = evaluate_scope_signals("evil.com", policy)
        assert result["scope_policy_blocks_takeover"] is True
        assert result["claim_action_allowed"] is False

    def test_returns_no_blocking_signal_when_takeover_allowed(self):
        """evaluate_scope_signals returns no blocking signal when allowed."""
        policy = TakeoverScopePolicy(allowed_targets={"safe.com"})
        result = evaluate_scope_signals("safe.com", policy)
        assert result["scope_policy_blocks_takeover"] is False
        assert result["claim_action_allowed"] is False

    def test_claim_action_allowed_always_false_in_signals(self):
        """claim_action_allowed is always False in evaluated signals (no automation)."""
        policy = TakeoverScopePolicy()
        result = evaluate_scope_signals("example.com", policy)
        assert result["claim_action_allowed"] is False

    def test_permissive_policy_always_passes(self):
        """Permissive policy (default) never blocks."""
        policy = TakeoverScopePolicy()
        result1 = evaluate_scope_signals("a.com", policy)
        result2 = evaluate_scope_signals("b.com", policy)
        assert result1["scope_policy_blocks_takeover"] is False
        assert result2["scope_policy_blocks_takeover"] is False


# ── Integration: scope blocking in match_recipes_to_context ──────────────

class TestScopePolicyInSelector:
    """Tests for scope_policy integration in match_recipes_to_context."""

    def test_candidate_with_scope_blocked_is_skipped(self):
        """Candidate blocked by scope policy must not produce a RecipeCandidate."""
        from src.core.policy.takeover_scope_policy import TakeoverScopePolicy

        loader = RecipeLoader()
        loader.recipes["takeover"] = _recipe(
            name="takeover",
            trigger_type="signal",
            required_signals=["dns_dead"],
        )
        cand = _candidate(
            subdomain="blocked.example.com",
            freshness_score=1.0,
        )
        context = {
            "takeover_candidates": [cand],
        }
        # Policy that blocks blocked.example.com
        blocking_policy = TakeoverScopePolicy(allowed_targets={"allowed.example.com"})

        results = loader.match_recipes_to_context(
            context, scope_policy=blocking_policy
        )
        takeover_matches = [c for c in results if c.recipe.name == "takeover"]
        assert len(takeover_matches) == 0, (
            "scope-blocked candidate should not produce any RecipeCandidate"
        )

    def test_candidate_with_scope_allowed_is_matched(self):
        """Candidate allowed by scope policy is matched normally."""
        loader = RecipeLoader()
        loader.recipes["takeover"] = _recipe(
            name="takeover",
            trigger_type="signal",
            required_signals=["dns_dead"],
        )
        cand = _candidate(
            subdomain="allowed.example.com",
            freshness_score=1.0,
        )
        context = {
            "takeover_candidates": [cand],
        }
        # Policy that allows this candidate
        permissive_policy = TakeoverScopePolicy(allowed_targets={"allowed.example.com"})

        results = loader.match_recipes_to_context(
            context, scope_policy=permissive_policy
        )
        takeover_matches = [c for c in results if c.recipe.name == "takeover"]
        assert len(takeover_matches) == 1

    def test_scope_policy_default_permissive_does_not_block(self):
        """Default (no scope_policy) should not block any candidates."""
        loader = RecipeLoader()
        loader.recipes["takeover"] = _recipe(
            name="takeover",
            trigger_type="signal",
            required_signals=["dns_dead"],
        )
        cand = _candidate(subdomain="test.example.com", freshness_score=1.0)
        context = {"takeover_candidates": [cand]}

        results = loader.match_recipes_to_context(context)  # no scope_policy
        takeover_matches = [c for c in results if c.recipe.name == "takeover"]
        assert len(takeover_matches) == 1

    def test_scope_policy_is_consulted_before_candidate_evaluation(self):
        """Scope policy blocks candidates before signal matching even runs."""
        loader = RecipeLoader()
        loader.recipes["takeover"] = _recipe(
            name="takeover",
            trigger_type="signal",
            required_signals=["dns_dead"],
        )
        # This candidate has sufficient signals (fresh + dead + cname)
        cand = _candidate(
            subdomain="blocked-via-scope.example.com",
            freshness_score=1.0,
            cname_chain=["unclaimed.s3.amazonaws.com"],
        )
        context = {"takeover_candidates": [cand]}
        blocking_policy = TakeoverScopePolicy(allowed_targets={"other.com"})

        results = loader.match_recipes_to_context(
            context, scope_policy=blocking_policy
        )
        # Even though candidate has all the right signals, scope blocks it
        takeover_matches = [c for c in results if c.recipe.name == "takeover"]
        assert len(takeover_matches) == 0, (
            "scope policy should block before signal evaluation"
        )


# ── Verdict: confirmed blocked when scope blocks takeover ────────────────

class TestScopePolicyBlocksConfirmedVerdict:
    """Tests that scope policy integrates with verdict logic."""

    def test_confirmed_verdict_baseline_no_scope_block(self):
        """compute_takeover_verdict without scope block returns confirmed
        when all other conditions are met."""
        from src.core.engine.optimized_runner import compute_takeover_verdict

        verdict = compute_takeover_verdict(
            provider_supports_auto_confirm=True,
            evidence_count=5,
            tool_agreement=True,
            stale=False,
        )
        assert verdict == "confirmed", "baseline: should be confirmed without scope block"

    def test_confirmed_verdict_blocked_when_scope_policy_blocks(self):
        """compute_takeover_verdict must return manual_review_required
        when scope_policy_blocks_takeover is True."""
        from src.core.engine.optimized_runner import compute_takeover_verdict

        verdict = compute_takeover_verdict(
            provider_supports_auto_confirm=True,
            evidence_count=5,
            tool_agreement=True,
            stale=False,
            scope_policy_blocks_takeover=True,
        )
        assert verdict == "manual_review_required", (
            "scope policy block should prevent confirmed verdict"
        )

    def test_classify_takeover_result_baseline_no_scope_block(self):
        """classify_takeover_result without scope block returns expected verdict."""
        from src.core.engine.optimized_runner import classify_takeover_result
        from src.core.adapters.external.takeover_provider_matrix_adapter import (
            ProviderEntry,
            ProviderMatrixLoader,
            TakeoverProviderMatrix,
        )

        entry = ProviderEntry("aws_s3", supports_auto_confirm=True)
        matrix = TakeoverProviderMatrix(ProviderMatrixLoader())
        verdict = classify_takeover_result(
            provider_entry=entry,
            provider_matrix=matrix,
            evidence_count=5,
            tool_agreement=True,
            candidate_is_stale=False,
        )
        assert verdict == "confirmed"

    def test_classify_takeover_result_with_scope_block(self):
        """classify_takeover_result with scope block → manual_review_required."""
        from src.core.engine.optimized_runner import classify_takeover_result
        from src.core.adapters.external.takeover_provider_matrix_adapter import (
            ProviderEntry,
            ProviderMatrixLoader,
            TakeoverProviderMatrix,
        )

        entry = ProviderEntry("aws_s3", supports_auto_confirm=True)
        matrix = TakeoverProviderMatrix(ProviderMatrixLoader())
        verdict = classify_takeover_result(
            provider_entry=entry,
            provider_matrix=matrix,
            evidence_count=5,
            tool_agreement=True,
            candidate_is_stale=False,
            scope_policy_blocks_takeover=True,
        )
        assert verdict == "manual_review_required", (
            "scope policy block should prevent confirmed verdict in classify_takeover_result"
        )
