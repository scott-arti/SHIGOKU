"""Tests for RecipeCandidate, selector contract, and signal-based matching."""
import pytest
from datetime import datetime, timedelta, timezone
from dataclasses import asdict
from unittest.mock import MagicMock, patch

from src.core.engine.recipe_loader import (
    RecipeLoader,
    Recipe,
    RecipeStep,
    RecipeCandidate,
    TakeoverCandidate,
    compute_freshness_score,
    extract_signals,
    check_recipe_action_allowlist,
    build_suppression_key,
    is_recipe_suppressed,
    _enrich_score_with_kg_context,
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


def test_match_attack_surface_signal_with_required_signals():
    """AttackSurfaceSignal-like recon signals should match signal recipes."""
    loader = RecipeLoader()
    loader.recipes["auth_recipe"] = _recipe(
        name="auth_recipe",
        trigger_type="signal",
        required_signals=[
            "auth_surface",
            "auth_required",
            "auth_endpoint",
            "cookie_present",
        ],
    )
    context = {
        "attack_surface_signals": [
            {
                "signal_id": "sig-auth-1",
                "entity_type": "auth_surface",
                "url": "https://app.example.com/login",
                "method": "GET",
                "primary_label": "auth",
                "candidate_labels": ["auth_endpoint", "login_surface"],
                "confidence": 0.82,
                "why_suspicious": "login form discovered during recon",
                "source_observations": ["katana"],
                "auth_required": True,
                "auth_context": {"cookie_present": True},
                "params": [{"name": "redirect_uri", "location": "query"}],
            }
        ]
    }

    results = loader.match_recipes_to_context(context)
    auth_matches = [c for c in results if c.recipe.name == "auth_recipe"]
    assert len(auth_matches) == 1
    match = auth_matches[0]
    assert match.score > 0.0
    assert match.required_signals["auth_surface"] is True
    assert match.required_signals["auth_endpoint"] is True
    assert match.supporting_evidence["signal_id"] == "sig-auth-1"
    assert match.supporting_evidence["url"] == "https://app.example.com/login"


# ── SGK-2026-0260: action allowlist filtering ────────────────────────────


def test_allowlist_check_passes_for_valid_actions():
    recipe = _recipe(
        name="ok",
        trigger_type="signal",
        steps=[
            RecipeStep(id="s1", name="S1", action="scan"),
            RecipeStep(id="s2", name="S2", action="report"),
        ],
    )
    result = check_recipe_action_allowlist(recipe)
    assert result["ok"] is True
    assert result["unsupported_actions"] == []


def test_allowlist_check_catches_unsupported_actions():
    recipe = _recipe(
        name="bad",
        trigger_type="signal",
        steps=[
            RecipeStep(id="s1", name="S1", action="scan"),
            RecipeStep(id="s2", name="S2", action="evil_hack"),
        ],
    )
    result = check_recipe_action_allowlist(recipe)
    assert result["ok"] is False
    assert "evil_hack" in result["unsupported_actions"]


def test_allowlist_check_suppresses_unsupported_candidate():
    """Recipe with unsupported action should be present but suppressed."""
    loader = RecipeLoader()
    loader.recipes["bad_recipe"] = _recipe(
        name="bad_recipe",
        trigger_type="signal",
        required_signals=["auth_surface"],
        steps=[
            RecipeStep(id="s1", name="S1", action="scan"),
            RecipeStep(id="s2", name="S2", action="evil_action"),
        ],
    )
    context = {
        "attack_surface_signals": [
            {
                "signal_id": "sig-1",
                "entity_type": "auth_surface",
                "url": "https://test.example.com/login",
                "primary_label": "auth",
                "candidate_labels": ["auth_endpoint"],
                "confidence": 0.82,
                "auth_required": True,
                "auth_context": {},
            }
        ]
    }
    results = loader.match_recipes_to_context(context)
    matches = [c for c in results if c.recipe.name == "bad_recipe"]
    assert len(matches) == 1
    assert matches[0].suppressed is True
    assert "unsupported_action" in (matches[0].suppression_reason or "")
    assert "unsupported_step_action" in matches[0].reasons


# ── SGK-2026-0260: suppression key ───────────────────────────────────────


def test_build_suppression_key_format():
    key = build_suppression_key("auth_recipe", "sig-1")
    assert key == "signal:auth_recipe:sig-1"


def test_build_suppression_key_with_endpoint_prefix():
    key = build_suppression_key("auth_recipe", "https://example.com/login", prefix="endpoint")
    assert key == "endpoint:auth_recipe:https://example.com/login"


def test_is_recipe_suppressed_detects_active_key():
    active = {"signal:auth_recipe:sig-1", "signal:scan_recipe:sig-2"}
    assert is_recipe_suppressed(active, "auth_recipe", "sig-1") is True
    assert is_recipe_suppressed(active, "other_recipe", "sig-1") is False


def test_is_recipe_suppressed_with_endpoint():
    active = {"endpoint:auth_recipe:https://test.example.com"}
    assert is_recipe_suppressed(
        active, "auth_recipe", "sig-1",
        also_check_endpoint="https://test.example.com",
    ) is True


def test_suppression_key_blocks_candidate():
    """Candidates with active suppression should be marked suppressed."""
    loader = RecipeLoader()
    loader.recipes["auth_recipe"] = _recipe(
        name="auth_recipe",
        trigger_type="signal",
        required_signals=["auth_surface", "auth_required"],
        steps=[RecipeStep(id="s1", name="S1", action="scan")],
    )
    context = {
        "attack_surface_signals": [
            {
                "signal_id": "sig-1",
                "entity_type": "auth_surface",
                "url": "https://test.example.com/login",
                "primary_label": "auth",
                "candidate_labels": ["auth_endpoint"],
                "confidence": 0.82,
                "auth_required": True,
                "auth_context": {},
            }
        ]
    }
    active_keys = {"signal:auth_recipe:sig-1"}
    results = loader.match_recipes_to_context(
        context, active_suppression_keys=active_keys,
    )
    matches = [c for c in results if c.recipe.name == "auth_recipe"]
    assert len(matches) == 1
    assert matches[0].suppressed is True
    assert matches[0].suppression_reason == "suppression_key_active"


# ── SGK-2026-0260: KG context enrichment ─────────────────────────────────


def test_kg_context_enrichment_high_freshness_adds_points():
    """KG freshness >= 0.8 should add score and reason."""
    adjusted, additive, suppressive = _enrich_score_with_kg_context(
        0.6,
        {"_recipe_name": "test_recipe"},
        {"kg_freshness_score": 0.9},
    )
    assert adjusted > 0.6, f"score should increase with high freshness, got {adjusted}"
    assert "high_freshness_score" in additive


def test_kg_context_enrichment_stale_freshness_penalizes():
    """KG freshness < 0.3 should reduce score and add suppressive reason."""
    adjusted, additive, suppressive = _enrich_score_with_kg_context(
        0.7,
        {"_recipe_name": "test_recipe"},
        {"kg_freshness_score": 0.1},
    )
    assert adjusted < 0.7, f"score should decrease with stale freshness, got {adjusted}"
    assert "kg_context_stale" in suppressive


def test_kg_context_previous_success_adds_points():
    """Previous recipe success on related endpoint should boost score."""
    adjusted, additive, suppressive = _enrich_score_with_kg_context(
        0.5,
        {"_recipe_name": "auth_recipe"},
        {
            "previous_recipe_runs": ["auth_recipe"],
            "previous_recipe_outcomes": {"auth_recipe": "success"},
        },
    )
    assert "previous_recipe_succeeded" in additive


def test_kg_context_previous_failure_penalizes():
    """Previous recipe failure should suppress score."""
    adjusted, additive, suppressive = _enrich_score_with_kg_context(
        0.8,
        {"_recipe_name": "auth_recipe"},
        {
            "previous_recipe_runs": ["auth_recipe"],
            "previous_recipe_outcomes": {"auth_recipe": "failed"},
        },
    )
    assert "previous_recipe_run_exists" in suppressive
    assert "previous_recipe_failed" in suppressive


def test_kg_context_nearby_finding_confirms():
    """Confirmed nearby finding should boost score."""
    adjusted, additive, suppressive = _enrich_score_with_kg_context(
        0.5,
        {"_recipe_name": "test"},
        {
            "nearby_findings": [
                {"status": "confirmed", "type": "auth_bypass"},
            ]
        },
    )
    assert "nearby_finding_confirms" in additive
    assert adjusted > 0.5


def test_kg_context_nearby_finding_mitigated():
    """Mitigated nearby finding should penalize score."""
    adjusted, additive, suppressive = _enrich_score_with_kg_context(
        0.6,
        {"_recipe_name": "test"},
        {
            "nearby_findings": [
                {"status": "mitigated", "type": "auth_bypass"},
            ]
        },
    )
    assert "nearby_finding_mitigated" in suppressive
    assert adjusted < 0.6


def test_kg_context_nearby_auth_surface():
    """Nearby auth surface endpoint should add reason."""
    adjusted, additive, suppressive = _enrich_score_with_kg_context(
        0.5,
        {"_recipe_name": "test", "entity_type": "api_endpoint"},
        {
            "nearby_endpoints": [
                {"surface_type": "auth_surface", "url": "/login"},
            ]
        },
    )
    assert "nearby_auth_surface" in additive


def test_kg_context_corroborating_surface():
    """Nearby endpoint with same surface type should add reason."""
    adjusted, additive, suppressive = _enrich_score_with_kg_context(
        0.5,
        {"_recipe_name": "test", "entity_type": "auth_surface"},
        {
            "nearby_endpoints": [
                {"surface_type": "auth_surface", "url": "/oauth/callback"},
            ]
        },
    )
    assert "nearby_endpoint_corroborates" in additive


def test_kg_context_integrated_in_match_recipes_to_context():
    """KG context passed to match_recipes_to_context should affect candidate."""
    loader = RecipeLoader()
    loader.recipes["auth_recipe"] = _recipe(
        name="auth_recipe",
        trigger_type="signal",
        required_signals=["auth_surface", "auth_required"],
        steps=[RecipeStep(id="s1", name="S1", action="scan")],
    )
    context = {
        "attack_surface_signals": [
            {
                "signal_id": "sig-1",
                "entity_type": "auth_surface",
                "url": "https://test.example.com/login",
                "primary_label": "auth",
                "candidate_labels": ["auth_endpoint"],
                "confidence": 0.7,
                "auth_required": True,
                "auth_context": {},
            }
        ]
    }
    # Without KG context
    results_no_kg = loader.match_recipes_to_context(context)
    # With KG context providing high freshness boost
    kg_ctx = {
        "kg_freshness_score": 0.95,
        "nearby_findings": [{"status": "confirmed"}],
        "nearby_endpoints": [{"surface_type": "auth_surface"}],
    }
    results_kg = loader.match_recipes_to_context(context, kg_context=kg_ctx)

    match_no_kg = [c for c in results_no_kg if c.recipe.name == "auth_recipe"][0]
    match_kg = [c for c in results_kg if c.recipe.name == "auth_recipe"][0]
    # Score with KG context should differ from without
    assert match_kg.score != match_no_kg.score, (
        f"KG context should change score: no_kg={match_no_kg.score}, kg={match_kg.score}"
    )
    # Reasons should be different
    assert len(match_kg.reasons) > len(match_no_kg.reasons), (
        f"KG context should add reasons: no_kg={match_no_kg.reasons}, kg={match_kg.reasons}"
    )


# ── SGK-2026-0260: decision trace vocabulary ─────────────────────────────

def test_recipe_candidate_suppression_trace_in_evidence():
    """Suppression metadata should be accessible via supporting_evidence."""
    loader = RecipeLoader()
    loader.recipes["bad_recipe"] = _recipe(
        name="bad_recipe",
        trigger_type="signal",
        required_signals=["auth_surface"],
        steps=[RecipeStep(id="s1", name="S1", action="unsupported_step")],
    )
    context = {
        "attack_surface_signals": [
            {
                "signal_id": "sig-1",
                "entity_type": "auth_surface",
                "url": "https://test.example.com/login",
                "primary_label": "auth",
                "candidate_labels": ["auth_endpoint"],
                "confidence": 0.82,
                "auth_required": True,
                "auth_context": {},
            }
        ]
    }
    results = loader.match_recipes_to_context(context)
    matches = [c for c in results if c.recipe.name == "bad_recipe"]
    assert len(matches) == 1
    rc = matches[0]
    assert rc.suppressed is True
    assert "unsupported_action" in (rc.suppression_reason or "")
    # supporting_evidence should have KG trace keys
    assert "_kg_additive_reasons" in rc.supporting_evidence
    assert "_kg_suppressive_reasons" in rc.supporting_evidence
    assert "_kg_adjusted_score" in rc.supporting_evidence


# ── SGK-2026-0260: store_recipe_run parameter integrity ─────────────────


def test_store_recipe_run_passes_suppression_keys():
    """store_recipe_run() must pass suppression_key_signal/_endpoint
    to session.run()."""
    from src.core.infra.knowledge_graph import KnowledgeGraph

    kg = KnowledgeGraph()

    captured_kwargs = {}
    fake_record = MagicMock()
    fake_record.__getitem__ = lambda self, k: "fake-node-id"
    fake_result = MagicMock()
    fake_result.single.return_value = fake_record
    fake_session = MagicMock()
    fake_session.run.return_value = fake_result

    def _capture_run(query, **kwargs):
        captured_kwargs.update(kwargs)
        return fake_result

    fake_session.run.side_effect = _capture_run
    fake_driver = MagicMock()
    fake_driver.session.return_value.__enter__.return_value = fake_session
    kg.driver = fake_driver

    kg.store_recipe_run(
        recipe_name="auth_recipe",
        target="https://app.example.com/login",
        success=True,
        summary={"total_steps": 1},
        verdict="confirmed",
        suppression_key_signal="signal:auth_recipe:sig-1",
        suppression_key_endpoint="endpoint:auth_recipe:https://app.example.com/login",
    )

    assert "suppression_key_signal" in captured_kwargs, (
        f"suppression_key_signal missing from session.run() kwargs: {list(captured_kwargs.keys())}"
    )
    assert captured_kwargs["suppression_key_signal"] == "signal:auth_recipe:sig-1"
    assert "suppression_key_endpoint" in captured_kwargs
    assert captured_kwargs["suppression_key_endpoint"] == "endpoint:auth_recipe:https://app.example.com/login"


# ── SGK-2026-0259: auth recipe matching ───────────────────────────────

def test_auth_recipe_matches_with_bearer_token_and_endpoint_signal():
    """Auth recipe requiring [auth_endpoint, bearer_token] matches when both present."""
    loader = RecipeLoader()
    loader.recipes["auth_bearer"] = _recipe(
        name="auth_bearer",
        trigger_type="signal",
        required_signals=["auth_endpoint", "bearer_token"],
    )
    context = {
        "attack_surface_signals": [
            {
                "signal_id": "sig-bearer-1",
                "entity_type": "auth_surface",
                "url": "https://app.example.com/login",
                "primary_label": "auth_endpoint",
                "candidate_labels": [],
                "confidence": 0.9,
                "auth_context": {"bearer_token": "eyJhbGciOiJIUzI1NiJ9.xxx"},
                "status": "active",
            }
        ]
    }
    results = loader.match_recipes_to_context(context)
    auth_matches = [c for c in results if c.recipe.name == "auth_bearer"]
    assert len(auth_matches) == 1
    assert auth_matches[0].score > 0


def test_auth_recipe_does_not_match_without_required_signals():
    """Auth recipe requiring [auth_endpoint, bearer_token]: signal missing bearer_token → 0 matches."""
    loader = RecipeLoader()
    loader.recipes["auth_bearer"] = _recipe(
        name="auth_bearer",
        trigger_type="signal",
        required_signals=["auth_endpoint", "bearer_token"],
    )
    context = {
        "attack_surface_signals": [
            {
                "signal_id": "sig-no-bearer-1",
                "entity_type": "auth_surface",
                "url": "https://app.example.com/login",
                "primary_label": "auth_endpoint",
                "candidate_labels": [],
                "confidence": 0.9,
                "auth_context": {},  # no bearer_token key
                "status": "active",
            }
        ]
    }
    results = loader.match_recipes_to_context(context)
    auth_matches = [c for c in results if c.recipe.name == "auth_bearer"]
    assert len(auth_matches) == 0


def test_auth_recipe_does_not_match_without_auth_signals():
    """No attack_surface_signals in context → 0 auth recipe matches."""
    loader = RecipeLoader()
    loader.recipes["auth_bearer"] = _recipe(
        name="auth_bearer",
        trigger_type="signal",
        required_signals=["auth_endpoint", "bearer_token"],
    )
    context = {}  # no attack_surface_signals
    results = loader.match_recipes_to_context(context)
    auth_matches = [c for c in results if c.recipe.name == "auth_bearer"]
    assert len(auth_matches) == 0


def test_multiple_auth_recipes_match_same_signal():
    """Loader has 2 auth recipes requiring same signals → both match with distinct names."""
    loader = RecipeLoader()
    loader.recipes["auth_oauth"] = _recipe(
        name="auth_oauth",
        trigger_type="signal",
        required_signals=["auth_endpoint", "oauth"],
    )
    loader.recipes["auth_session"] = _recipe(
        name="auth_session",
        trigger_type="signal",
        required_signals=["auth_endpoint", "oauth"],
    )
    context = {
        "attack_surface_signals": [
            {
                "signal_id": "sig-oauth-1",
                "entity_type": "auth_surface",
                "url": "https://app.example.com/oauth/authorize",
                "primary_label": "auth_endpoint",
                "candidate_labels": ["oauth"],
                "confidence": 0.85,
                "auth_context": {},
                "status": "active",
            }
        ]
    }
    results = loader.match_recipes_to_context(context)
    auth_matches = [c for c in results if c.recipe.name in {"auth_oauth", "auth_session"}]
    assert len(auth_matches) == 2
    names = {c.recipe.name for c in auth_matches}
    assert names == {"auth_oauth", "auth_session"}


def test_oauth_recipe_matches_when_oauth_label_present():
    """Recipe requires [auth_endpoint, oauth], signal primary_label='oauth' → matches."""
    loader = RecipeLoader()
    loader.recipes["oauth_drift"] = _recipe(
        name="oauth_drift",
        trigger_type="signal",
        required_signals=["auth_endpoint", "oauth"],
    )
    context = {
        "attack_surface_signals": [
            {
                "signal_id": "sig-oauth-1",
                "entity_type": "auth_surface",
                "url": "https://app.example.com/oauth/authorize",
                "primary_label": "oauth",
                "candidate_labels": ["auth_endpoint"],
                "confidence": 0.85,
                "auth_context": {},
                "status": "active",
            }
        ]
    }
    results = loader.match_recipes_to_context(context)
    oauth_matches = [c for c in results if c.recipe.name == "oauth_drift"]
    assert len(oauth_matches) == 1
    assert oauth_matches[0].score > 0


def test_jwt_recipe_matches_when_jwt_label_present():
    """Recipe requires [auth_endpoint, jwt], signal primary_label='jwt' → matches."""
    loader = RecipeLoader()
    loader.recipes["jwt_enforce"] = _recipe(
        name="jwt_enforce",
        trigger_type="signal",
        required_signals=["auth_endpoint", "jwt"],
    )
    context = {
        "attack_surface_signals": [
            {
                "signal_id": "sig-jwt-1",
                "entity_type": "auth_surface",
                "url": "https://app.example.com/api",
                "primary_label": "jwt",
                "candidate_labels": ["auth_endpoint"],
                "confidence": 0.85,
                "auth_context": {},
                "status": "active",
            }
        ]
    }
    results = loader.match_recipes_to_context(context)
    jwt_matches = [c for c in results if c.recipe.name == "jwt_enforce"]
    assert len(jwt_matches) == 1


def test_non_auth_recipe_does_not_match_auth_only_signals():
    """Takeover recipe requiring [dns_dead, cname_dangling] does not match auth endpoint signal."""
    loader = RecipeLoader()
    loader.recipes["takeover"] = _recipe(
        name="takeover",
        trigger_type="signal",
        required_signals=["dns_dead", "cname_dangling"],
    )
    context = {
        "attack_surface_signals": [
            {
                "signal_id": "sig-auth-1",
                "entity_type": "auth_surface",
                "url": "https://app.example.com/login",
                "primary_label": "auth_endpoint",
                "candidate_labels": [],
                "confidence": 0.9,
                "auth_context": {},
                "status": "active",
            }
        ]
    }
    results = loader.match_recipes_to_context(context)
    takeover_matches = [c for c in results if c.recipe.name == "takeover"]
    assert len(takeover_matches) == 0


def test_auth_recipe_candidate_has_success_and_stop_conditions():
    """Auth recipe match → RecipeCandidate.success_condition and stop_condition are set."""
    loader = RecipeLoader()
    loader.recipes["auth_full"] = Recipe(
        name="auth_full",
        description="Full auth recipe",
        agent="swarm",
        trigger={
            "type": "signal",
            "required_signals": ["auth_endpoint"],
            "success_condition": "auth_full_success",
            "stop_condition": "auth_full_stop",
        },
        steps=[RecipeStep(id="s1", name="Probe", action="scan")],
    )
    context = {
        "attack_surface_signals": [
            {
                "signal_id": "sig-cond-1",
                "entity_type": "auth_surface",
                "url": "https://app.example.com/login",
                "primary_label": "auth_endpoint",
                "candidate_labels": [],
                "confidence": 0.9,
                "auth_context": {},
                "status": "active",
            }
        ]
    }
    results = loader.match_recipes_to_context(context)
    auth_matches = [c for c in results if c.recipe.name == "auth_full"]
    assert len(auth_matches) == 1
    rc = auth_matches[0]
    assert rc.success_condition == "auth_full_success"
    assert rc.stop_condition == "auth_full_stop"
