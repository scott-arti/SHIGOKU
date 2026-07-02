"""
Negative fixtures and snapshot verification tests (Step 10: SGK-2026-0335).

Covers:
- Timezone parse failure (invalid timezone in source manifest)
- Wildcard/deny conflict detection (same-specificity allow+deny)
- Secret contamination (credential-like values should not leak to compiled output)
- Active bundle missing (loader fail-closed for missing active_bundle.json)
- Empty scope assets (compile_failed when 0 in-scope assets)
- Same bundle => same policy hash (deterministic compilation)
"""

from pathlib import Path

import pytest

from src.core.security.compiled_guard_compiler import compile_guard_policy
from src.core.security.compiled_guard_loader import (
    GuardLoadError,
    load_active_policy_from_bundle_dir,
)
from src.core.security.hackerone_adapter import HackerOneAdapter
from src.core.security.bugcrowd_adapter import BugcrowdAdapter


FIXTURES_DIR = Path(__file__).resolve().parents[3] / "tests" / "fixtures"
PROGRAM_BUNDLE_DIR = FIXTURES_DIR / "program_bundle"


# ---------------------------------------------------------------------------
# 1. Timezone parse failure
# ---------------------------------------------------------------------------


class TestInvalidTimezone:
    """Adapter should handle invalid default_timezone gracefully."""

    def test_invalid_timezone_does_not_crash(self):
        """H1 adapter with invalid timezone should not crash."""
        bundle_dir = PROGRAM_BUNDLE_DIR / "invalid_timezone"
        adapter = HackerOneAdapter(bundle_dir)
        result = adapter.process()
        assert result is not None
        assert hasattr(result, "extraction_audit")


# ---------------------------------------------------------------------------
# 2. Wildcard/deny conflict
# ---------------------------------------------------------------------------


class TestWildcardDenyConflict:
    """Exact deny wins over wildcard allow (deny precedence), producing ready."""

    def test_compiler_exact_deny_wins_over_wildcard_allow(self):
        """Explicit deny row wins over wildcard allow → scope ready with deny hosts."""
        bundle_dir = PROGRAM_BUNDLE_DIR / "wildcard_deny_conflict"
        adapter = HackerOneAdapter(bundle_dir)
        result = adapter.process()
        assert result is not None

        policy = compile_guard_policy(
            result, {"review_findings": []}, {"overrides": {}},
        )
        # Deny precedence: exact deny wins → ready (not manual_review_required)
        assert policy["compile_status"] == "ready"
        scope = policy.get("scope", {})
        deny_hosts = scope.get("deny_hosts", [])
        allow_hosts = scope.get("allow_hosts", [])
        # example.com should be in deny, *.example.com in allow
        assert "example.com" in deny_hosts
        assert "*.example.com" in allow_hosts


# ---------------------------------------------------------------------------
# 3. Secret contamination
# ---------------------------------------------------------------------------


class TestSecretContamination:
    """Secret-like values in policy text should not appear in compiled output."""

    def test_compiled_policy_excludes_credential_patterns(self):
        """Compiled policy should not contain raw credential values from policy text."""
        bundle_dir = PROGRAM_BUNDLE_DIR / "secret_contamination"
        adapter = HackerOneAdapter(bundle_dir)
        result = adapter.process()
        assert result is not None

        policy = compile_guard_policy(
            result, {"review_findings": []}, {"overrides": {}},
        )

        policy_str = str(policy)
        assert "SuperSecret123!" not in policy_str
        assert "sk-live-" not in policy_str


# ---------------------------------------------------------------------------
# 4. Active bundle missing
# ---------------------------------------------------------------------------


class TestActiveBundleMissing:
    """Loader should fail-closed when active_bundle.json is missing."""

    def test_loader_fails_for_directory_without_active_bundle(self, tmp_path):
        """Directory exists but no active_bundle.json -> GuardLoadError."""
        d = tmp_path / "no_active"
        d.mkdir()
        result = load_active_policy_from_bundle_dir(d)
        assert isinstance(result, GuardLoadError)
        assert result.reason_code == "active_bundle_missing"

    def test_loader_fails_for_nonexistent_directory(self, tmp_path):
        """Nonexistent directory -> GuardLoadError."""
        result = load_active_policy_from_bundle_dir(tmp_path / "nonexistent")
        assert isinstance(result, GuardLoadError)
        assert result.reason_code == "active_bundle_missing"


# ---------------------------------------------------------------------------
# 5. Empty scope assets
# ---------------------------------------------------------------------------


class TestEmptyScopeAssets:
    """Bundle with 0 in-scope assets should fail compilation."""

    def test_empty_assets_produces_compile_failed(self):
        """0 in-scope assets -> compile_failed."""
        from src.core.security.program_adapter_base import NormalizedFacts

        facts = NormalizedFacts()
        facts.program = {"provider": "hackerone", "program_name": "EmptyProgram"}
        facts.assets = []
        facts.rule_candidates = []
        facts.review_candidates = []
        facts.extraction_audit = []

        policy = compile_guard_policy(facts, {"review_findings": []}, {"overrides": {}})
        assert policy["compile_status"] == "compile_failed"


# ---------------------------------------------------------------------------
# 6. Same bundle => same policy hash (snapshot verification)
# ---------------------------------------------------------------------------


class TestSameBundleSameHash:
    """Deterministic compilation: same bundle => same hash values."""

    def test_tiktok_bundle_idempotent_hash(self):
        """TikTok bundle compiled twice -> same compiled_policy_hash."""
        bundle_dir = PROGRAM_BUNDLE_DIR / "tiktok"

        r1 = HackerOneAdapter(bundle_dir).process()
        p1 = compile_guard_policy(r1, {"review_findings": []}, {"overrides": {}})

        r2 = HackerOneAdapter(bundle_dir).process()
        p2 = compile_guard_policy(r2, {"review_findings": []}, {"overrides": {}})

        assert p1.get("compiled_policy_hash")
        assert p1["compiled_policy_hash"] == p2["compiled_policy_hash"]
        assert p1.get("normalized_facts_hash") == p2.get("normalized_facts_hash")

    def test_fireblocks_bundle_idempotent_hash(self):
        """Fireblocks bundle compiled twice -> same compiled_policy_hash."""
        bundle_dir = PROGRAM_BUNDLE_DIR / "fireblocks"

        r1 = BugcrowdAdapter(bundle_dir).process()
        p1 = compile_guard_policy(r1, {"review_findings": []}, {"overrides": {}})

        r2 = BugcrowdAdapter(bundle_dir).process()
        p2 = compile_guard_policy(r2, {"review_findings": []}, {"overrides": {}})

        assert p1.get("compiled_policy_hash")
        assert p1["compiled_policy_hash"] == p2["compiled_policy_hash"]

    def test_different_bundles_produce_different_hashes(self):
        """TikTok != Fireblocks hash (no collision)."""
        r1 = HackerOneAdapter(PROGRAM_BUNDLE_DIR / "tiktok").process()
        p1 = compile_guard_policy(r1, {"review_findings": []}, {"overrides": {}})

        r2 = BugcrowdAdapter(PROGRAM_BUNDLE_DIR / "fireblocks").process()
        p2 = compile_guard_policy(r2, {"review_findings": []}, {"overrides": {}})

        assert p1["compiled_policy_hash"] != p2["compiled_policy_hash"]

    def test_hash_determinism_across_time(self):
        """Hash is stable even with time passing between compilations."""
        import time

        bundle_dir = PROGRAM_BUNDLE_DIR / "tiktok"

        r1 = HackerOneAdapter(bundle_dir).process()
        p1 = compile_guard_policy(r1, {"review_findings": []}, {"overrides": {}})

        time.sleep(0.1)

        r2 = HackerOneAdapter(bundle_dir).process()
        p2 = compile_guard_policy(r2, {"review_findings": []}, {"overrides": {}})

        assert p1["compiled_policy_hash"] == p2["compiled_policy_hash"]
