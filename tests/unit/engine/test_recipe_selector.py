"""Tests for RecipeCandidate, selector contract, and signal-based matching."""
import pytest
from datetime import datetime, timedelta, timezone
from dataclasses import asdict

from src.core.engine.recipe_loader import (
    RecipeLoader,
    Recipe,
    RecipeStep,
    RecipeCandidate,
    TakeoverCandidate,
    compute_freshness_score,
    extract_signals,
)


# ── helpers ──────────────────────────────────────────────────────────────

def _recipe(name="r1", trigger_type="signal", required_signals=None, blocking_signals=None, steps=None):
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


# ── RecipeCandidate ──────────────────────────────────────────────────────

def test_recipe_candidate_defaults():
    r = _recipe(name="test")
    rc = RecipeCandidate(recipe=r)
    assert rc.recipe == r
    assert rc.score == 0.0
    assert isinstance(rc.reasons, list)
    assert isinstance(rc.required_signals, dict)
    assert isinstance(rc.supporting_evidence, dict)
    assert rc.manual_review_required is False


def test_recipe_candidate_with_signals():
    r = _recipe(name="test")
    rc = RecipeCandidate(
        recipe=r,
        score=0.8,
        reasons=["dns_dead", "cname_dangling"],
        required_signals={"dns_dead": True, "cname_dangling": True},
        supporting_evidence={"cname": "unclaimed.s3.amazonaws.com"},
        manual_review_required=False,
    )
    assert rc.score == 0.8
    assert "dns_dead" in rc.reasons
    assert rc.required_signals["dns_dead"] is True
    assert rc.supporting_evidence["cname"] == "unclaimed.s3.amazonaws.com"


# ── compute_freshness_score ──────────────────────────────────────────────

def test_freshness_score_recent_is_high():
    """A candidate seen dead very recently gets high freshness."""
    now = datetime.now(timezone.utc)
    score = compute_freshness_score(first_seen_dead=now, last_seen_dead=now)
    assert score >= 0.9, f"recent candidate should score >= 0.9, got {score}"


def test_freshness_score_old_is_low():
    """A candidate seen dead weeks ago gets low freshness."""
    old = datetime.now(timezone.utc) - timedelta(days=60)
    score = compute_freshness_score(first_seen_dead=old, last_seen_dead=old)
    assert score < 0.3, f"60-day old candidate should score < 0.3, got {score}"


def test_freshness_score_stale_without_reprobe():
    """A candidate last probed long ago gets penalized regardless of first_seen."""
    recent = datetime.now(timezone.utc) - timedelta(days=1)
    old_probe = datetime.now(timezone.utc) - timedelta(days=30)
    score = compute_freshness_score(
        first_seen_dead=recent,
        last_seen_dead=recent,
        last_dns_probe=old_probe,
    )
    assert score < 0.6, f"stale dns_probe should reduce score, got {score}"


def test_freshness_score_null_dates_are_low():
    """None dates should yield minimal score (no data = low confidence)."""
    score = compute_freshness_score(None, None)
    assert score <= 0.1, f"null dates should yield <= 0.1, got {score}"


# ── extract_signals ──────────────────────────────────────────────────────

def test_extract_signals_returns_empty_for_bare_candidate():
    cand = TakeoverCandidate(
        subdomain="x.example.com",
        candidate_id="c1",
        observed_at=datetime.now(timezone.utc),
        first_seen_dead=datetime.now(timezone.utc),
        last_seen_dead=datetime.now(timezone.utc),
    )
    sigs = extract_signals(cand)
    # derived: freshness from first_seen/last_seen
    assert "freshness_score" in sigs


def test_extract_signals_dns_dead():
    cand = TakeoverCandidate(
        subdomain="dead.example.com",
        candidate_id="c1",
        observed_at=datetime.now(timezone.utc),
        first_seen_dead=datetime.now(timezone.utc),
        last_seen_dead=datetime.now(timezone.utc),
    )
    sigs = extract_signals(cand)
    assert sigs.get("dns_dead") is True


def test_extract_signals_cname_dangling():
    cand = TakeoverCandidate(
        subdomain="dangling.example.com",
        candidate_id="c2",
        observed_at=datetime.now(timezone.utc),
        first_seen_dead=datetime.now(timezone.utc),
        last_seen_dead=datetime.now(timezone.utc),
        cname_chain=["dangling.example.com", "unclaimed.s3.amazonaws.com"],
    )
    sigs = extract_signals(cand)
    assert sigs.get("cname_dangling") is True


def test_extract_signals_provider_guess():
    cand = TakeoverCandidate(
        subdomain="aws.example.com",
        candidate_id="c3",
        observed_at=datetime.now(timezone.utc),
        first_seen_dead=datetime.now(timezone.utc),
        last_seen_dead=datetime.now(timezone.utc),
        provider_guess="aws_s3",
    )
    sigs = extract_signals(cand)
    assert sigs.get("provider_match") is True
    assert sigs.get("provider") == "aws_s3"


def test_extract_signals_manual_review_flag():
    cand = TakeoverCandidate(
        subdomain="flaky.example.com",
        candidate_id="c4",
        observed_at=datetime.now(timezone.utc),
        first_seen_dead=datetime.now(timezone.utc),
        last_seen_dead=datetime.now(timezone.utc),
        manual_claim_review_required=True,
    )
    sigs = extract_signals(cand)
    assert sigs.get("manual_claim_review_required") is True


# ── match_recipes_to_context: signal matching ────────────────────────────

def test_match_no_takeover_candidates_returns_empty():
    """Without takeover candidates, no takeover recipes are matched."""
    loader = RecipeLoader()
    loader.recipes["takeover"] = _recipe(
        name="takeover",
        trigger_type="signal",
        required_signals=["dns_dead", "cname_dangling"],
    )
    context = {}  # no takeover_candidates
    results = loader.match_recipes_to_context(context)
    # takeover recipe should NOT be matched when no candidates exist
    takeover_matches = [c for c in results if c.recipe.name == "takeover"]
    assert len(takeover_matches) == 0


def test_match_with_sufficient_signals():
    """A takeover candidate with all required signals should match."""
    loader = RecipeLoader()
    loader.recipes["takeover"] = _recipe(
        name="takeover",
        trigger_type="signal",
        required_signals=["dns_dead", "cname_dangling"],
    )
    cand = _candidate(
        subdomain="dangling.test.com",
        freshness_score=1.0,
        cname_chain=["dangling.test.com", "unclaimed.s3.amazonaws.com"],
    )
    context = {"takeover_candidates": [cand]}
    results = loader.match_recipes_to_context(context)
    takeover_matches = [c for c in results if c.recipe.name == "takeover"]
    assert len(takeover_matches) == 1
    assert takeover_matches[0].score > 0.0


def test_match_with_insufficient_signals_does_not_match():
    """A candidate missing required signals must not match."""
    loader = RecipeLoader()
    loader.recipes["takeover"] = _recipe(
        name="takeover",
        trigger_type="signal",
        required_signals=["dns_dead", "cname_dangling"],
    )
    cand = _candidate(
        subdomain="just_dead.test.com",
        freshness_score=1.0,
    )
    context = {"takeover_candidates": [cand]}
    results = loader.match_recipes_to_context(context)
    takeover_matches = [c for c in results if c.recipe.name == "takeover"]
    assert len(takeover_matches) == 0


def test_match_blocking_signal_prevents_match():
    """A candidate with a blocking signal must not match."""
    loader = RecipeLoader()
    loader.recipes["takeover"] = _recipe(
        name="takeover",
        trigger_type="signal",
        required_signals=["dns_dead"],
        blocking_signals=["stale_candidate"],
    )
    cand = _candidate(
        subdomain="stale.test.com",
        freshness_score=0.0,
        blocking_signals={"stale_candidate"},
    )
    context = {"takeover_candidates": [cand]}
    results = loader.match_recipes_to_context(context)
    takeover_matches = [c for c in results if c.recipe.name == "takeover"]
    assert len(takeover_matches) == 0


def test_match_score_increases_with_more_signals():
    """More matched required signals should yield higher score."""
    loader = RecipeLoader()
    loader.recipes["takeover"] = _recipe(
        name="takeover",
        trigger_type="signal",
        required_signals=["dns_dead", "cname_dangling", "provider_match"],
    )
    # candidate with all 3 signals
    full = _candidate(
        subdomain="full.test.com",
        freshness_score=1.0,
        cname_chain=["full.test.com", "unclaimed.s3.amazonaws.com"],
        provider_guess="aws_s3",
    )
    context_full = {"takeover_candidates": [full]}
    r_full = loader.match_recipes_to_context(context_full)

    # candidate with only 1 signal (no cname, no provider)
    partial = _candidate(
        subdomain="partial.test.com",
        freshness_score=1.0,
        # no cname_chain, no provider_guess → only dns_dead
    )
    context_partial = {"takeover_candidates": [partial]}
    r_partial = loader.match_recipes_to_context(context_partial)

    full_cands = [c for c in r_full if c.recipe.name == "takeover"]
    partial_cands = [c for c in r_partial if c.recipe.name == "takeover"]
    # full candidate matches, partial does not (missing 2 required signals)
    assert len(full_cands) == 1
    assert len(partial_cands) == 0


def test_non_takeover_recipes_still_match():
    """Recipes without signal trigger are still matched (backward compat)."""
    loader = RecipeLoader()
    loader.recipes["generic"] = _recipe(name="generic", trigger_type="none")
    context = {}
    results = loader.match_recipes_to_context(context)
    assert any(c.recipe.name == "generic" for c in results)


def test_same_recipe_does_not_duplicate_per_candidate():
    """One recipe × N candidates = N matches, but not duplicated per candidate."""
    loader = RecipeLoader()
    loader.recipes["takeover"] = _recipe(
        name="takeover",
        trigger_type="signal",
        required_signals=["dns_dead"],
    )
    cands = [
        _candidate(subdomain="a.example.com"),
        _candidate(subdomain="b.example.com"),
    ]
    context = {"takeover_candidates": cands}
    results = loader.match_recipes_to_context(context)
    takeover_matches = [c for c in results if c.recipe.name == "takeover"]
    assert len(takeover_matches) == 2
    # each match should have a distinct candidate_id
    ids = set()
    for m in takeover_matches:
        cid = m.supporting_evidence.get("candidate_id")
        if cid:
            assert cid not in ids, f"duplicate candidate_id: {cid}"
            ids.add(cid)
