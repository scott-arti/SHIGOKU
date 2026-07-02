"""
Unit tests for compiled_guard_evaluator.py.

Covers Phase 1 supported checks:
- exact host allow
- wildcard host allow
- out-of-scope host deny
- URL prefix deny
- post-exploit deny
- denied attack_class deny
- unknown host default deny
- deterministic decision for same input
- loader failure based fail-closed deny
"""

from pathlib import Path

import pytest

from src.core.security.compiled_guard_loader import (
    LoadedGuardPolicy,
    load_active_policy_from_bundle_dir,
)
from src.core.security.compiled_guard_evaluator import (
    GuardDecision,
    GuardInput,
    REASON_ALLOW_EXACT_HOST,
    REASON_ALLOW_WILDCARD_HOST,
    REASON_DENY_ATTACK_CLASS,
    REASON_DENY_DEFAULT,
    REASON_DENY_EXACT_HOST,
    REASON_DENY_FAIL_CLOSED,
    REASON_DENY_POST_EXPLOIT,
    REASON_DENY_URL_PREFIX,
    REASON_DENY_WILDCARD_HOST,
    evaluate_guard,
    evaluate_with_loader_error,
)
from src.core.security.compiled_guard_models import GuardLoadError

FIXTURES_DIR = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "bugbounty_guard"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tiktok_policy() -> LoadedGuardPolicy:
    result = load_active_policy_from_bundle_dir(FIXTURES_DIR / "tiktok")
    assert isinstance(result, LoadedGuardPolicy)
    return result


@pytest.fixture
def fireblocks_policy() -> LoadedGuardPolicy:
    result = load_active_policy_from_bundle_dir(FIXTURES_DIR / "fireblocks")
    assert isinstance(result, LoadedGuardPolicy)
    return result


def _input(bundle_id: str = "", policy_id: str = "", target: str = "", host: str = "",
           phase: str = "", attack_class: str = "") -> GuardInput:
    return GuardInput(
        bundle_id=bundle_id,
        policy_id=policy_id,
        target=target,
        host=host,
        phase=phase,
        attack_class=attack_class,
    )


# ---------------------------------------------------------------------------
# TikTok class tests
# ---------------------------------------------------------------------------

class TestTikTokEvaluator:
    def test_wildcard_allow_in_scope(self, tiktok_policy: LoadedGuardPolicy):
        """*.tiktok.com wildcard allows subdomains."""
        gi = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            target="https://www.tiktok.com/",
            host="www.tiktok.com",
        )
        decision = evaluate_guard(tiktok_policy, gi)
        assert decision.decision == "allow"
        assert decision.reason_code == REASON_ALLOW_WILDCARD_HOST

    def test_exact_wildcard_base_allow(self, tiktok_policy: LoadedGuardPolicy):
        """tiktok.com itself (wildcard base) is allowed by *.tiktok.com."""
        gi = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            target="https://tiktok.com/",
            host="tiktok.com",
        )
        decision = evaluate_guard(tiktok_policy, gi)
        assert decision.decision == "allow"

    def test_out_of_scope_host_deny(self, tiktok_policy: LoadedGuardPolicy):
        """Explicit deny hosts (*tiktokv.us) are blocked."""
        gi = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            target="https://cdn.tiktokv.us/",
            host="cdn.tiktokv.us",
        )
        decision = evaluate_guard(tiktok_policy, gi)
        assert decision.decision == "block"
        assert decision.reason_code in (REASON_DENY_WILDCARD_HOST,)

    def test_url_prefix_deny(self, tiktok_policy: LoadedGuardPolicy):
        """URL prefix deny blocks matching target."""
        gi = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            target="https://developers.tiktok.com/minis/something",
            host="developers.tiktok.com",
        )
        decision = evaluate_guard(tiktok_policy, gi)
        assert decision.decision == "block"
        assert decision.reason_code == REASON_DENY_URL_PREFIX

    def test_post_exploit_deny(self, tiktok_policy: LoadedGuardPolicy):
        """post_exploit phase is denied."""
        gi = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            target="https://www.tiktok.com/",
            host="www.tiktok.com",
            phase="post_exploit",
        )
        decision = evaluate_guard(tiktok_policy, gi)
        assert decision.decision == "block"
        assert decision.reason_code == REASON_DENY_POST_EXPLOIT

    def test_denied_attack_class_social_engineering(self, tiktok_policy: LoadedGuardPolicy):
        """social_engineering attack class is denied."""
        gi = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            target="https://www.tiktok.com/",
            host="www.tiktok.com",
            attack_class="social_engineering",
        )
        decision = evaluate_guard(tiktok_policy, gi)
        assert decision.decision == "block"
        assert decision.reason_code == REASON_DENY_ATTACK_CLASS

    def test_denied_attack_class_dos(self, tiktok_policy: LoadedGuardPolicy):
        """dos attack class is denied."""
        gi = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            target="https://www.tiktok.com/",
            host="www.tiktok.com",
            attack_class="dos",
        )
        decision = evaluate_guard(tiktok_policy, gi)
        assert decision.decision == "block"
        assert decision.reason_code == REASON_DENY_ATTACK_CLASS

    def test_unknown_host_default_deny(self, tiktok_policy: LoadedGuardPolicy):
        """Host not in allow list defaults to deny."""
        gi = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            target="https://random.example.com/",
            host="random.example.com",
        )
        decision = evaluate_guard(tiktok_policy, gi)
        assert decision.decision == "block"
        assert decision.reason_code == REASON_DENY_DEFAULT


# ---------------------------------------------------------------------------
# Fireblocks class tests
# ---------------------------------------------------------------------------

class TestFireblocksEvaluator:
    def test_exact_host_allow(self, fireblocks_policy: LoadedGuardPolicy):
        """Exact host sb-console-api.fireblocks.io is allowed."""
        gi = _input(
            bundle_id=fireblocks_policy.bundle_id,
            policy_id=fireblocks_policy.policy_id,
            target="https://sb-console-api.fireblocks.io/api/v1/status",
            host="sb-console-api.fireblocks.io",
        )
        decision = evaluate_guard(fireblocks_policy, gi)
        assert decision.decision == "allow"
        assert decision.reason_code == REASON_ALLOW_EXACT_HOST

    def test_sbmobile_exact_allow(self, fireblocks_policy: LoadedGuardPolicy):
        gi = _input(
            bundle_id=fireblocks_policy.bundle_id,
            policy_id=fireblocks_policy.policy_id,
            target="https://sb-mobile-api.fireblocks.io/",
            host="sb-mobile-api.fireblocks.io",
        )
        decision = evaluate_guard(fireblocks_policy, gi)
        assert decision.decision == "allow"

    def test_unlisted_subdomain_default_deny(self, fireblocks_policy: LoadedGuardPolicy):
        """Unlisted Fireblocks subdomain is denied."""
        gi = _input(
            bundle_id=fireblocks_policy.bundle_id,
            policy_id=fireblocks_policy.policy_id,
            target="https://internal.fireblocks.io/",
            host="internal.fireblocks.io",
        )
        decision = evaluate_guard(fireblocks_policy, gi)
        assert decision.decision == "block"
        assert decision.reason_code == REASON_DENY_DEFAULT

    def test_post_exploit_deny(self, fireblocks_policy: LoadedGuardPolicy):
        gi = _input(
            bundle_id=fireblocks_policy.bundle_id,
            policy_id=fireblocks_policy.policy_id,
            target="https://sb-console-api.fireblocks.io/",
            host="sb-console-api.fireblocks.io",
            phase="post_exploit",
        )
        decision = evaluate_guard(fireblocks_policy, gi)
        assert decision.decision == "block"
        assert decision.reason_code == REASON_DENY_POST_EXPLOIT

    def test_rate_limit_bypass_attack_class_denied(self, fireblocks_policy: LoadedGuardPolicy):
        gi = _input(
            bundle_id=fireblocks_policy.bundle_id,
            policy_id=fireblocks_policy.policy_id,
            target="https://sb-console-api.fireblocks.io/",
            host="sb-console-api.fireblocks.io",
            attack_class="rate_limit_bypass",
        )
        decision = evaluate_guard(fireblocks_policy, gi)
        assert decision.decision == "block"
        assert decision.reason_code == REASON_DENY_ATTACK_CLASS


# ---------------------------------------------------------------------------
# Determinism and fail-closed
# ---------------------------------------------------------------------------

class TestEvaluatorDeterminismFailClosed:
    def test_deterministic_decision_same_input(self, tiktok_policy: LoadedGuardPolicy):
        """Same input produces same decision (deterministic)."""
        gi = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            target="https://www.tiktok.com/",
            host="www.tiktok.com",
        )
        d1 = evaluate_guard(tiktok_policy, gi)
        d2 = evaluate_guard(tiktok_policy, gi)
        # Decision must be identical (trace_id varies but decision/reason must match)
        assert d1.decision == d2.decision
        assert d1.reason_code == d2.reason_code
        assert d1.matched_rule_ids == d2.matched_rule_ids

    def test_fail_closed_unready_policy(self):
        """Unready policy returns fail-closed block."""
        unready = LoadedGuardPolicy(
            bundle_id="b-1", policy_id="p-1", provider="test",
            program_name="test", program_alias="test",
            compiled_policy_path="/nonexistent", compiled_policy_hash="sha256:abc",
            compile_status="manual_review_required",
        )
        gi = _input(bundle_id="b-1", policy_id="p-1", host="example.com")
        decision = evaluate_guard(unready, gi)
        assert decision.decision == "block"
        assert decision.fail_closed is True
        assert decision.reason_code == REASON_DENY_FAIL_CLOSED

    def test_loader_error_to_fail_closed(self):
        """evaluate_with_loader_error preserves original reason_code."""
        decision = evaluate_with_loader_error("active_bundle_missing", enforcement_layer="mc")
        assert decision.decision == "block"
        assert decision.fail_closed is True
        # Original loader error code is preserved, not crushed to policy_fail_closed
        assert decision.reason_code == "active_bundle_missing"
        assert "compiled_guard_loader#active_bundle_missing" in decision.source_refs

    def test_no_host_default_deny(self, tiktok_policy: LoadedGuardPolicy):
        """Empty host defaults to deny."""
        gi = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
        )
        decision = evaluate_guard(tiktok_policy, gi)
        assert decision.decision == "block"
        assert decision.reason_code == REASON_DENY_DEFAULT

    def test_deterministic_trace_id_same_input(self, tiktok_policy: LoadedGuardPolicy):
        """Same GuardInput with same policy produces identical decision_trace_id."""
        gi1 = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            target="https://www.tiktok.com/",
            host="www.tiktok.com",
        )
        gi2 = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            target="https://www.tiktok.com/",
            host="www.tiktok.com",
        )
        d1 = evaluate_guard(tiktok_policy, gi1)
        d2 = evaluate_guard(tiktok_policy, gi2)
        assert d1.decision_trace_id == d2.decision_trace_id
        assert d1.decision_trace_id.startswith("gd-")

    def test_deterministic_trace_id_different_input(self, tiktok_policy: LoadedGuardPolicy):
        """Different inputs produce different trace IDs."""
        gi_allow = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            target="https://www.tiktok.com/",
            host="www.tiktok.com",
        )
        gi_block = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            host="unknown.example.com",
        )
        d_allow = evaluate_guard(tiktok_policy, gi_allow)
        d_block = evaluate_guard(tiktok_policy, gi_block)
        assert d_allow.decision_trace_id != d_block.decision_trace_id

    def test_trace_id_differs_by_host(self, tiktok_policy: LoadedGuardPolicy):
        """Same policy, different hosts -> different trace IDs (no collision)."""
        gi1 = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            target="https://www.tiktok.com/",
            host="www.tiktok.com",
        )
        gi2 = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            target="https://m.tiktok.com/",
            host="m.tiktok.com",
        )
        d1 = evaluate_guard(tiktok_policy, gi1)
        d2 = evaluate_guard(tiktok_policy, gi2)
        # Both should be allowed, but trace IDs differ by host
        assert d1.decision == d2.decision == "allow"
        assert d1.decision_trace_id != d2.decision_trace_id

    def test_trace_id_differs_by_phase(self, tiktok_policy: LoadedGuardPolicy):
        """Same policy and host, different phase -> different trace IDs."""
        gi_allow = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            target="https://www.tiktok.com/",
            host="www.tiktok.com",
            phase="recon",
        )
        gi_deny = _input(
            bundle_id=tiktok_policy.bundle_id,
            policy_id=tiktok_policy.policy_id,
            target="https://www.tiktok.com/",
            host="www.tiktok.com",
            phase="post_exploit",
        )
        d_allow = evaluate_guard(tiktok_policy, gi_allow)
        d_deny = evaluate_guard(tiktok_policy, gi_deny)
        assert d_allow.decision_trace_id != d_deny.decision_trace_id
