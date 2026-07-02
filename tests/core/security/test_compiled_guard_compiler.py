"""
Unit and integration tests for compiled_guard_compiler.py.

Covers:
- Compiler from adapter tests (integration-like) for TikTok and Fireblocks
- Compiler unit tests (no adapter dependency): compile status, scope, rules, audit, hashes
- Precedence, fail-closed, idempotency, overrides

TDD order: these tests are written BEFORE the compiler implementation.
"""

from __future__ import annotations

import copy
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from src.core.security.program_adapter_base import (
    NormalizedAsset,
    NormalizedFacts,
    RuleCandidate,
    ReviewCandidate,
)
from src.core.security.hackerone_adapter import HackerOneAdapter
from src.core.security.bugcrowd_adapter import BugcrowdAdapter

# The compiler module will be imported after implementation.
# For TDD, we import the module that will be created:
try:
    from src.core.security.compiled_guard_compiler import (
        compile_guard_policy,
        write_compiled_policy_to_dir,
        write_compiled_policy_artifact,
        activate_bundle,
        _resolve_compile_status,
        _detect_specificity_conflicts,
        _build_scope,
        _build_rules,
        _build_audit,
        _compute_compiled_policy_hash,
        _apply_precedence_deny_over_allow,
    )
except ImportError:
    # Allow test file to exist before the module — tests will fail as expected (TDD red phase).
    pass


# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

PROGRAM_FIXTURES_DIR = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "program_bundle"
COMPILED_FIXTURES_DIR = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "bugbounty_guard"

TIKTOK_BUNDLE = PROGRAM_FIXTURES_DIR / "tiktok"
FIREBLOCKS_BUNDLE = PROGRAM_FIXTURES_DIR / "fireblocks"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict:
    """Load a YAML file."""
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _empty_review_findings() -> dict:
    return {"review_findings": []}


def _empty_overrides() -> dict:
    return {"overrides": {}}


def _make_minimal_facts(
    provider: str = "hackerone",
    program_name: str = "TestProgram",
    assets: list[NormalizedAsset] | None = None,
    rule_candidates: list[RuleCandidate] | None = None,
    review_candidates: list[ReviewCandidate] | None = None,
    bundle_id: str = "test-bundle-id",
) -> NormalizedFacts:
    """Create a minimal NormalizedFacts for unit tests."""
    facts = NormalizedFacts(
        adapter={"name": "test_adapter", "version": 1},
        program={"provider": provider, "program_name": program_name},
    )
    # Set bundle_id via program metadata
    facts.program["bundle_id"] = bundle_id
    if assets is not None:
        facts.assets = list(assets)
    if rule_candidates is not None:
        facts.rule_candidates = list(rule_candidates)
    if review_candidates is not None:
        facts.review_candidates = list(review_candidates)
    return facts


def _make_asset(
    asset_id: str = "asset-1",
    raw_identifier: str = "*.example.com",
    canonical_key: str = "*.example.com",
    asset_kind: str = "host_wildcard",
    submission_allowed: bool = True,
    source_ref: str = "scope_assets.csv#row=1",
    runtime_surface: str = "http",
) -> NormalizedAsset:
    """Create a NormalizedAsset for unit tests."""
    return NormalizedAsset(
        asset_id=asset_id,
        raw_identifier=raw_identifier,
        canonical_key=canonical_key,
        asset_kind=asset_kind,
        runtime_surface=runtime_surface,
        submission_allowed=submission_allowed,
        source_ref=source_ref,
    )


def _make_rule_candidate(
    rule_id: str = "rc-1",
    category: str = "attack_class",
    decision: str = "deny",
    subject: str = "social_engineering",
    origin_type: str = "policy_text",
    specificity: str = "medium",
    source_ref: str = "policy.md",
    constraints: dict | None = None,
) -> RuleCandidate:
    """Create a RuleCandidate for unit tests."""
    return RuleCandidate(
        rule_id=rule_id,
        category=category,
        decision=decision,
        subject=subject,
        origin_type=origin_type,
        specificity=specificity,
        source_ref=source_ref,
        constraints=constraints or {},
    )


# ---------------------------------------------------------------------------
# 1. Compiler from adapter tests (integration-like)
# ---------------------------------------------------------------------------


class TestCompileFromTiktokAdapter:
    """Compile TikTok bundle through adapter -> compiler."""

    @pytest.fixture(scope="class")
    def facts(self):
        """Process the TikTok bundle once."""
        return HackerOneAdapter(TIKTOK_BUNDLE).process()

    def test_compile_tiktok_produces_ready_status(self, facts):
        """Process TikTok bundle through adapter, then compile -> compile_status=ready."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        result = compile_guard_policy(
            facts, _empty_review_findings(), _empty_overrides()
        )
        assert result["compile_status"] == "ready"

    def test_compile_tiktok_scope_matches_fixture(self, facts):
        """Compiler output scope section has the expected structure."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        result = compile_guard_policy(
            facts, _empty_review_findings(), _empty_overrides()
        )
        scope = result["scope"]
        assert isinstance(scope, dict)
        assert "allow_hosts" in scope
        assert "deny_hosts" in scope
        assert "allow_url_prefixes" in scope
        assert "deny_url_prefixes" in scope
        assert "non_http_assets" in scope

    def test_compile_tiktok_has_allow_wildcard(self, facts):
        """scope.allow_hosts contains *.tiktok.com."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        result = compile_guard_policy(
            facts, _empty_review_findings(), _empty_overrides()
        )
        allow_hosts = result["scope"]["allow_hosts"]
        assert "*.tiktok.com" in allow_hosts

    def test_compile_tiktok_has_deny_hosts(self, facts):
        """scope.deny_hosts contains *.tiktokv.us."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        result = compile_guard_policy(
            facts, _empty_review_findings(), _empty_overrides()
        )
        deny_hosts = result["scope"]["deny_hosts"]
        assert "*.tiktokv.us" in deny_hosts

    def test_compile_tiktok_has_url_prefix_deny_with_overrides(self, facts):
        """With overrides, developers.tiktok.com/minis URL appears in deny_url_prefixes."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        overrides = {
            "overrides": {
                "scope": {
                    "allow_hosts": [],
                    "deny_hosts": [],
                    "allow_url_prefixes": [],
                    "deny_url_prefixes": ["https://developers.tiktok.com/minis/"],
                }
            }
        }
        result = compile_guard_policy(facts, _empty_review_findings(), overrides)
        deny_url_prefixes = result["scope"]["deny_url_prefixes"]
        assert "https://developers.tiktok.com/minis/" in deny_url_prefixes

    def test_compile_tiktok_post_exploit_deny(self, facts):
        """Phase post_exploit=deny."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        result = compile_guard_policy(
            facts, _empty_review_findings(), _empty_overrides()
        )
        phases = result["rules"]["phases"]
        assert "post_exploit" in phases
        assert phases["post_exploit"]["decision"] == "deny"

    def test_compile_tiktok_attack_classes_deny(self, facts):
        """social_engineering, dos, privacy_harm all deny."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        result = compile_guard_policy(
            facts, _empty_review_findings(), _empty_overrides()
        )
        attack_classes = result["rules"]["attack_classes"]
        # At minimum, these are in the adapter output
        assert attack_classes.get("social_engineering", {}).get("decision") == "deny"
        assert attack_classes.get("dos", {}).get("decision") == "deny"
        # privacy_harm may or may not be present depending on policy text
        if "privacy_harm" in attack_classes:
            assert attack_classes["privacy_harm"]["decision"] == "deny"

    def test_compile_tiktok_ssrf_allow_with_destinations(self, facts):
        """SSRF rule with allowed destinations from adapter."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        result = compile_guard_policy(
            facts, _empty_review_findings(), _empty_overrides()
        )
        attack_classes = result["rules"]["attack_classes"]
        # SSRF destinations should be mapped to the ssrf attack class
        if "ssrf" in attack_classes:
            ssrf_rule = attack_classes["ssrf"]
            assert ssrf_rule.get("decision") in ("allow", "allow_with_constraints")
            assert "allowed_destinations" in ssrf_rule
            assert len(ssrf_rule["allowed_destinations"]) >= 1


class TestCompileFromFireblocksAdapter:
    """Compile Fireblocks bundle through adapter -> compiler."""

    @pytest.fixture(scope="class")
    def facts(self):
        """Process the Fireblocks bundle once."""
        return BugcrowdAdapter(FIREBLOCKS_BUNDLE).process()

    def test_compile_fireblocks_exact_hosts(self, facts):
        """Fireblocks compile produces 3 exact hosts in allow."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        result = compile_guard_policy(
            facts, _empty_review_findings(), _empty_overrides()
        )
        allow_hosts = result["scope"]["allow_hosts"]
        expected = {
            "sb-console-api.fireblocks.io",
            "sb-mobile-api.fireblocks.io",
            "sandbox-api.fireblocks.io",
        }
        assert set(allow_hosts) == expected

    def test_compile_fireblocks_post_exploit_deny(self, facts):
        """Phase post_exploit=deny."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        result = compile_guard_policy(
            facts, _empty_review_findings(), _empty_overrides()
        )
        phases = result["rules"]["phases"]
        assert "post_exploit" in phases
        assert phases["post_exploit"]["decision"] == "deny"

    def test_compile_fireblocks_auth_email_domains(self, facts):
        """Auth has bugcrowdninja.com."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        result = compile_guard_policy(
            facts, _empty_review_findings(), _empty_overrides()
        )
        auth = result["rules"]["auth"]
        assert "allowed_email_domains" in auth
        assert "bugcrowdninja.com" in auth["allowed_email_domains"]

    def test_compile_fireblocks_rate_limit_deny(self, facts):
        """rate_limit_bypass=deny."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        result = compile_guard_policy(
            facts, _empty_review_findings(), _empty_overrides()
        )
        attack_classes = result["rules"]["attack_classes"]
        assert attack_classes.get("rate_limit_bypass", {}).get("decision") == "deny"


# ---------------------------------------------------------------------------
# 2. Compiler unit tests (no adapter dependency)
# ---------------------------------------------------------------------------


class TestResolveCompileStatus:
    """Tests for _resolve_compile_status."""

    def test_resolve_compile_status_ready(self):
        """No blocking findings + assets exist -> ready."""
        if "_resolve_compile_status" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        facts = _make_minimal_facts(assets=[_make_asset()])
        review_findings = {"review_findings": []}
        status, blocking = _resolve_compile_status(facts, review_findings)
        assert status == "ready"
        assert blocking == []

    def test_resolve_compile_status_manual_review(self):
        """Blocking+pending finding -> manual_review_required."""
        if "_resolve_compile_status" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        facts = _make_minimal_facts(assets=[_make_asset()])
        review_findings = {
            "review_findings": [
                {
                    "finding_id": "T-001",
                    "category": "temporal_scope",
                    "subject": "test subject",
                    "risk_level": "high",
                    "source_refs": ["policy.md"],
                    "machine_guess": {},
                    "status": "pending",
                    "blocking": True,
                }
            ]
        }
        status, blocking = _resolve_compile_status(facts, review_findings)
        assert status == "manual_review_required"
        assert "T-001" in blocking

    def test_resolve_compile_status_failed_no_assets(self):
        """0 in-scope assets -> compile_failed."""
        if "_resolve_compile_status" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        facts = _make_minimal_facts(assets=[])
        review_findings = {"review_findings": []}
        status, blocking = _resolve_compile_status(facts, review_findings)
        assert status == "compile_failed"

    def test_non_blocking_pending_does_not_block(self):
        """Pending but non-blocking finding does not prevent ready."""
        if "_resolve_compile_status" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        facts = _make_minimal_facts(assets=[_make_asset()])
        review_findings = {
            "review_findings": [
                {
                    "finding_id": "T-002",
                    "category": "ambiguity",
                    "subject": "test",
                    "risk_level": "low",
                    "source_refs": ["policy.md"],
                    "machine_guess": {},
                    "status": "pending",
                    "blocking": False,
                }
            ]
        }
        status, blocking = _resolve_compile_status(facts, review_findings)
        assert status == "ready"

    def test_dismissed_blocking_does_not_block(self):
        """Blocking but dismissed/accepted finding does not prevent ready."""
        if "_resolve_compile_status" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        facts = _make_minimal_facts(assets=[_make_asset()])
        review_findings = {
            "review_findings": [
                {
                    "finding_id": "T-003",
                    "category": "temporal_scope",
                    "subject": "test",
                    "risk_level": "high",
                    "source_refs": ["policy.md"],
                    "machine_guess": {},
                    "status": "dismissed",
                    "blocking": True,
                }
            ]
        }
        status, blocking = _resolve_compile_status(facts, review_findings)
        assert status == "ready"

    def test_specificity_conflict_triggers_manual_review(self):
        """Exact host allow+deny at same specificity -> manual_review_required. (Fix Medium 5)"""
        if "_resolve_compile_status" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        assets = [
            _make_asset("a1", "api.example.com", "api.example.com", "host_exact", True, "src#1"),
            _make_asset("a2", "api.example.com", "api.example.com", "host_exact", False, "src#2"),
        ]
        facts = _make_minimal_facts(assets=assets)
        status, conflicts = _resolve_compile_status(facts, _empty_review_findings())
        assert status == "manual_review_required"
        assert any("api.example.com" in c for c in conflicts)

    def test_specificity_conflict_resolved_by_override(self):
        """Override denies the conflicting host -> conflict resolved, status=ready."""
        if "_resolve_compile_status" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        assets = [
            _make_asset("a1", "api.example.com", "api.example.com", "host_exact", True, "src#1"),
            _make_asset("a2", "api.example.com", "api.example.com", "host_exact", False, "src#2"),
        ]
        facts = _make_minimal_facts(assets=assets)
        overrides = {
            "overrides": {
                "scope": {
                    "deny_hosts": ["api.example.com"],
                    "allow_hosts": [],
                    "allow_url_prefixes": [],
                    "deny_url_prefixes": [],
                }
            }
        }
        status, conflicts = _resolve_compile_status(facts, _empty_review_findings(), overrides)
        assert status == "ready", f"Expected ready with override, got {status} with conflicts={conflicts}"


class TestBuildScope:
    """Tests for _build_scope."""

    def test_build_scope_precedence_deny_over_allow(self):
        """Same host in both + deny wins."""
        if "_build_scope" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        assets = [
            _make_asset("a1", "api.example.com", "api.example.com", "host_exact", True, "src#1"),
            _make_asset("a2", "api.example.com", "api.example.com", "host_exact", False, "src#2"),
        ]
        facts = _make_minimal_facts(assets=assets)
        scope = _build_scope(facts, _empty_overrides())
        # Deny wins
        assert "api.example.com" not in scope["allow_hosts"]
        assert "api.example.com" in scope["deny_hosts"]

    def test_build_scope_url_prefix_deny_wins(self):
        """URL prefix deny beats wildcard allow on same domain."""
        if "_build_scope" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        assets = [
            _make_asset("a1", "*.example.com", "*.example.com", "host_wildcard", True, "src#1"),
            _make_asset("a2", "https://dev.example.com/admin/", "https://dev.example.com/admin/", "url_prefix", False, "src#2"),
        ]
        facts = _make_minimal_facts(assets=assets)
        scope = _build_scope(facts, _empty_overrides())
        assert "*.example.com" in scope["allow_hosts"]
        assert "https://dev.example.com/admin/" in scope["deny_url_prefixes"]

    def test_build_scope_exact_deny_wins(self):
        """Exact host deny beats wildcard allow."""
        if "_build_scope" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        assets = [
            _make_asset("a1", "*.example.com", "*.example.com", "host_wildcard", True, "src#1"),
            _make_asset("a2", "admin.example.com", "admin.example.com", "host_exact", False, "src#2"),
        ]
        facts = _make_minimal_facts(assets=assets)
        scope = _build_scope(facts, _empty_overrides())
        # Wildcard allow stays, exact deny added
        assert "*.example.com" in scope["allow_hosts"]
        assert "admin.example.com" in scope["deny_hosts"]

    def test_build_scope_non_http_assets(self):
        """Mobile app assets go to non_http_assets."""
        if "_build_scope" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        assets = [
            _make_asset("m1", "android-app", "android-app", "mobile_app", False, "src#1", "mobile"),
            _make_asset("a1", "*.example.com", "*.example.com", "host_wildcard", True, "src#2"),
        ]
        facts = _make_minimal_facts(assets=assets)
        scope = _build_scope(facts, _empty_overrides())
        assert "android-app" in scope["non_http_assets"]

    def test_build_scope_only_submission_allowed_in_allow(self):
        """Only assets with submission_allowed=True go to allow_hosts."""
        if "_build_scope" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        assets = [
            _make_asset("a1", "host1.example.com", "host1.example.com", "host_exact", True, "src#1"),
            _make_asset("a2", "host2.example.com", "host2.example.com", "host_exact", False, "src#2"),
        ]
        facts = _make_minimal_facts(assets=assets)
        scope = _build_scope(facts, _empty_overrides())
        assert "host1.example.com" in scope["allow_hosts"]
        assert "host2.example.com" in scope["deny_hosts"]
        assert "host2.example.com" not in scope["allow_hosts"]


class TestBuildRules:
    """Tests for _build_rules."""

    def test_build_rules_from_rule_candidates(self):
        """attack_class rule candidates mapped correctly."""
        if "_build_rules" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        candidates = [
            _make_rule_candidate("rc-1", "attack_class", "deny", "social_engineering"),
            _make_rule_candidate("rc-2", "attack_class", "deny", "dos"),
        ]
        facts = _make_minimal_facts(rule_candidates=candidates)
        rules = _build_rules(facts, _empty_overrides())
        attack_classes = rules["attack_classes"]
        assert attack_classes["social_engineering"]["decision"] == "deny"
        assert attack_classes["dos"]["decision"] == "deny"

    def test_build_rules_post_exploit_from_candidate(self):
        """Post-exploit rule candidate -> phases.post_exploit."""
        if "_build_rules" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        candidates = [
            _make_rule_candidate("rc-1", "phase", "deny", "post_exploit"),
        ]
        facts = _make_minimal_facts(rule_candidates=candidates)
        rules = _build_rules(facts, _empty_overrides())
        assert rules["phases"]["post_exploit"]["decision"] == "deny"
        assert rules["phases"]["post_exploit"]["reason_code"] == "post_exploit_prohibited"

    def test_build_rules_auth_from_candidate(self):
        """Auth rule candidate maps to auth section."""
        if "_build_rules" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        candidates = [
            _make_rule_candidate(
                "rc-auth", "auth", "allow", "allowed_email_domain",
                constraints={"allowed_email_domains": ["test.com"]},
            ),
        ]
        facts = _make_minimal_facts(rule_candidates=candidates)
        rules = _build_rules(facts, _empty_overrides())
        assert "allowed_email_domains" in rules["auth"]
        assert "test.com" in rules["auth"]["allowed_email_domains"]

    def test_build_rules_destination_to_ssrf(self):
        """SSRF destination rule candidates map to ssrf attack_class."""
        if "_build_rules" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        candidates = [
            _make_rule_candidate(
                "rc-ssrf-1", "destination", "allow", "https://ssrf-bait.example.com/test",
                constraints={"ssrf_only": True},
                specificity="exact",
            ),
            _make_rule_candidate(
                "rc-ssrf-2", "destination", "deny", "ssrf_other",
                constraints={"ssrf_only": True},
                specificity="broad",
            ),
        ]
        facts = _make_minimal_facts(rule_candidates=candidates)
        rules = _build_rules(facts, _empty_overrides())
        ssrf = rules["attack_classes"].get("ssrf", {})
        assert ssrf.get("decision") in ("allow", "allow_with_constraints")
        assert "allowed_destinations" in ssrf
        assert any("ssrf-bait.example.com" in d for d in ssrf["allowed_destinations"])

    def test_build_rules_default_budget(self):
        """Default budget of 60 requests per minute."""
        if "_build_rules" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        facts = _make_minimal_facts()
        rules = _build_rules(facts, _empty_overrides())
        assert rules["budgets"]["requests_per_minute"] == 60


class TestApplyOverrides:
    """Tests for override application effects on compiled output."""

    def test_apply_overrides_add_deny_host(self):
        """Override adds deny host."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        facts = _make_minimal_facts(assets=[
            _make_asset("a1", "*.example.com", "*.example.com", "host_wildcard", True, "src#1"),
        ])
        overrides = {
            "overrides": {
                "scope": {
                    "deny_hosts": ["api.example.com"],
                    "allow_hosts": [],
                    "allow_url_prefixes": [],
                    "deny_url_prefixes": [],
                }
            }
        }
        result = compile_guard_policy(facts, _empty_review_findings(), overrides)
        assert "api.example.com" in result["scope"]["deny_hosts"]

    def test_apply_overrides_change_attack_class_mode(self):
        """Override changes attack_class to deny."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        facts = _make_minimal_facts(rule_candidates=[
            _make_rule_candidate("rc-1", "attack_class", "allow", "dos"),
        ])
        overrides = {
            "overrides": {
                "attack_classes": {
                    "dos": {"mode": "deny"},
                }
            }
        }
        result = compile_guard_policy(facts, _empty_review_findings(), overrides)
        assert result["rules"]["attack_classes"]["dos"]["decision"] == "deny"

    def test_apply_overrides_budget(self):
        """Override sets request budget."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        facts = _make_minimal_facts()
        overrides = {
            "overrides": {
                "budgets": {"requests_per_minute": 120},
            }
        }
        result = compile_guard_policy(facts, _empty_review_findings(), overrides)
        assert result["rules"]["budgets"]["requests_per_minute"] == 120


class TestHashes:
    """Tests for hash computation."""

    def test_compute_compiled_policy_hash_deterministic(self):
        """Same input -> same hash."""
        if "_compute_compiled_policy_hash" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        policy = {"schema_version": 1, "compile_status": "ready", "scope": {"allow_hosts": ["*.example.com"]}}
        h1 = _compute_compiled_policy_hash(policy)
        h2 = _compute_compiled_policy_hash(policy)
        assert h1 == h2
        assert h1.startswith("sha256:")

    def test_compute_compiled_policy_hash_different_inputs(self):
        """Different inputs -> different hash."""
        if "_compute_compiled_policy_hash" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        p1 = {"schema_version": 1, "scope": {"allow_hosts": ["*.a.com"]}}
        p2 = {"schema_version": 1, "scope": {"allow_hosts": ["*.b.com"]}}
        h1 = _compute_compiled_policy_hash(p1)
        h2 = _compute_compiled_policy_hash(p2)
        assert h1 != h2

    def test_normalized_facts_hash_deterministic(self):
        """Same facts -> same normalized_facts_hash."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        assets = [
            _make_asset("a1", "*.example.com", "*.example.com", "host_wildcard", True, "src#1"),
        ]
        facts1 = _make_minimal_facts(assets=assets)
        facts2 = _make_minimal_facts(assets=assets)
        r1 = compile_guard_policy(facts1, _empty_review_findings(), _empty_overrides())
        r2 = compile_guard_policy(facts2, _empty_review_findings(), _empty_overrides())
        assert r1["normalized_facts_hash"] == r2["normalized_facts_hash"]


class TestAudit:
    """Tests for audit section."""

    def test_audit_rule_origins_populated(self):
        """rule_origins list has entries for all scope rules."""
        if "_build_audit" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        assets = [
            _make_asset("a1", "*.example.com", "*.example.com", "host_wildcard", True, "scope.csv#row=1"),
            _make_asset("a2", "deny.example.com", "deny.example.com", "host_exact", False, "scope.csv#row=2"),
        ]
        facts = _make_minimal_facts(assets=assets)
        audit = _build_audit(facts, _empty_review_findings(), _empty_overrides())
        assert "rule_origins" in audit
        origins = audit["rule_origins"]
        assert len(origins) >= 2  # one allow, one deny

        # Each origin has required fields
        for origin in origins:
            assert "rule_origin_id" in origin
            assert "runtime_rule_id" in origin
            assert "origin_type" in origin
            assert "source_ref" in origin
            assert "subject" in origin
            assert "decision" in origin

    def test_audit_compile_inputs_populated(self):
        """compile_inputs dict has all hash keys."""
        if "_build_audit" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        facts = _make_minimal_facts(assets=[_make_asset()])
        audit = _build_audit(facts, _empty_review_findings(), _empty_overrides())
        assert "compile_inputs" in audit
        compile_inputs = audit["compile_inputs"]
        assert "manifest_hash" in compile_inputs
        assert "policy_hash" in compile_inputs
        assert "scope_hashes" in compile_inputs
        assert "review_findings_hash" in compile_inputs
        assert "overrides_hash" in compile_inputs


class TestIdempotency:
    """Tests for compile idempotency."""

    def test_compile_idempotent(self):
        """Same bundle compiled twice -> identical compiled_policy_hash, even across time."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        assets = [
            _make_asset("a1", "*.example.com", "*.example.com", "host_wildcard", True, "src#1"),
        ]
        facts1 = _make_minimal_facts(assets=assets)
        r1 = compile_guard_policy(facts1, _empty_review_findings(), _empty_overrides())
        # Wait to ensure real time passes (Fix Critical 2)
        time.sleep(1.1)
        facts2 = _make_minimal_facts(assets=assets)
        r2 = compile_guard_policy(facts2, _empty_review_findings(), _empty_overrides())
        assert r1["compiled_policy_hash"] == r2["compiled_policy_hash"], \
            "Hash changed across time — check compiled_at_utc exclusion from hash"
        # compiled_at_utc must differ, but hash must be same
        assert r1["compiled_at_utc"] != r2["compiled_at_utc"], \
            "compiled_at_utc should differ across time, confirming real time delta"

    def test_default_decision_is_deny(self):
        """default_decision field is 'deny'."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        facts = _make_minimal_facts(assets=[_make_asset()])
        result = compile_guard_policy(facts, _empty_review_findings(), _empty_overrides())
        assert result["default_decision"] == "deny"

    def test_non_http_assets_in_scope(self):
        """Mobile app assets go to non_http_assets in compiled output."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        assets = [
            _make_asset("m1", "android-app", "android-app", "mobile_app", False, "src#1", "mobile"),
            _make_asset("a1", "*.example.com", "*.example.com", "host_wildcard", True, "src#2"),
        ]
        facts = _make_minimal_facts(assets=assets)
        result = compile_guard_policy(facts, _empty_review_findings(), _empty_overrides())
        assert "android-app" in result["scope"]["non_http_assets"]

    def test_empty_bundle_compile_failed(self):
        """Adapter that produces 0 assets -> compile_failed."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        facts = _make_minimal_facts(assets=[])
        result = compile_guard_policy(facts, _empty_review_findings(), _empty_overrides())
        assert result["compile_status"] == "compile_failed"


class TestTopLevelStructure:
    """Tests for compiled policy top-level structure."""

    def test_schema_version(self):
        """schema_version is 1."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        facts = _make_minimal_facts(assets=[_make_asset()])
        result = compile_guard_policy(facts, _empty_review_findings(), _empty_overrides())
        assert result["schema_version"] == 1

    def test_provider_and_program_name(self):
        """provider and program_name from facts are preserved."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        facts = _make_minimal_facts(provider="bugcrowd", program_name="TestCo")
        facts.assets = [_make_asset()]
        result = compile_guard_policy(facts, _empty_review_findings(), _empty_overrides())
        assert result["provider"] == "bugcrowd"
        assert result["program_name"] == "TestCo"

    def test_review_gate_structure(self):
        """review_gate section is present with correct structure."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        facts = _make_minimal_facts(assets=[_make_asset()])
        result = compile_guard_policy(facts, _empty_review_findings(), _empty_overrides())
        assert "review_gate" in result
        assert "manual_review_required" in result["review_gate"]
        assert "blocking_findings" in result["review_gate"]

    def test_compatibility_section(self):
        """compatibility section is present."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        facts = _make_minimal_facts(assets=[_make_asset()])
        result = compile_guard_policy(facts, _empty_review_findings(), _empty_overrides())
        assert "compatibility" in result
        assert result["compatibility"]["min_reader_schema_version"] == 1
        assert 1 in result["compatibility"]["backward_compatible_with"]


class TestPrecedence:
    """Tests for _apply_precedence_deny_over_allow."""

    def test_deny_wins_allow(self):
        """When same host appears in allow and deny, deny stays."""
        if "_apply_precedence_deny_over_allow" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        assets = [
            _make_asset("a1", "api.example.com", "api.example.com", "host_exact", True, "src#1"),
            _make_asset("a2", "api.example.com", "api.example.com", "host_exact", False, "src#2"),
        ]
        facts = _make_minimal_facts(assets=assets)
        allow_hosts, deny_hosts, allow_url, deny_url, non_http = _apply_precedence_deny_over_allow(facts)
        assert "api.example.com" not in allow_hosts
        assert "api.example.com" in deny_hosts

    def test_wildcard_allow_exact_deny(self):
        """Wildcard allow + exact deny -> exact deny wins, wildcard stays."""
        if "_apply_precedence_deny_over_allow" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        assets = [
            _make_asset("a1", "*.example.com", "*.example.com", "host_wildcard", True, "src#1"),
            _make_asset("a2", "admin.example.com", "admin.example.com", "host_exact", False, "src#2"),
        ]
        facts = _make_minimal_facts(assets=assets)
        allow_hosts, deny_hosts, allow_url, deny_url, non_http = _apply_precedence_deny_over_allow(facts)
        assert "*.example.com" in allow_hosts
        assert "admin.example.com" in deny_hosts

    def test_url_prefix_deny_wildcard_allow(self):
        """URL prefix deny vs wildcard allow -> both preserved."""
        if "_apply_precedence_deny_over_allow" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        assets = [
            _make_asset("a1", "*.example.com", "*.example.com", "host_wildcard", True, "src#1"),
            _make_asset("a2", "https://dev.example.com/admin/", "https://dev.example.com/admin/", "url_prefix", False, "src#2"),
        ]
        facts = _make_minimal_facts(assets=assets)
        allow_hosts, deny_hosts, allow_url, deny_url, non_http = _apply_precedence_deny_over_allow(facts)
        assert "*.example.com" in allow_hosts
        assert "https://dev.example.com/admin/" in deny_url


# ---------------------------------------------------------------------------
# 3. Integration: compile -> write -> load round-trip (Fix Critical 1)
# ---------------------------------------------------------------------------


class TestCompileWriteLoadIntegration:
    """Tests for compile -> write -> load round-trip integrity."""

    def test_compile_write_load_integration(self, tmp_path: Path):
        """Compile -> write to dir -> load from dir -> verify round-trip."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        if "write_compiled_policy_to_dir" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")

        facts = _make_minimal_facts(
            assets=[_make_asset("a1", "*.example.com", "*.example.com",
                                "host_wildcard", True, "src#1")],
            rule_candidates=[
                _make_rule_candidate("rc-1", "attack_class", "deny", "social_engineering"),
            ],
        )
        policy = compile_guard_policy(facts, _empty_review_findings(), _empty_overrides())
        assert policy["compile_status"] == "ready"

        # Write to temp dir
        output_dir = tmp_path / "bundle"
        output_dir.mkdir()
        file_hash = write_compiled_policy_to_dir(policy, output_dir)

        assert file_hash is not None
        assert file_hash.startswith("sha256:")

        # Verify files were written
        assert (output_dir / "compiled_guard_policy.yaml").exists()
        assert (output_dir / "active_bundle.json").exists()

        # Load back via loader
        from src.core.security.compiled_guard_loader import (
            load_active_policy_from_bundle_dir,
            LoadedGuardPolicy,
        )
        loaded = load_active_policy_from_bundle_dir(output_dir)
        assert isinstance(loaded, LoadedGuardPolicy), \
            f"Expected LoadedGuardPolicy, got {type(loaded).__name__}: {loaded}"
        assert loaded.compile_status == "ready"
        assert loaded.policy_id == policy["policy_id"]
        assert loaded.bundle_id == policy["bundle_id"]

    def test_compile_write_load_hash_fail_closed(self, tmp_path: Path):
        """Tampered policy file triggers integrity error on load."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        if "write_compiled_policy_to_dir" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")

        facts = _make_minimal_facts(
            assets=[_make_asset("a1", "*.example.com", "*.example.com",
                                "host_wildcard", True, "src#1")],
        )
        policy = compile_guard_policy(facts, _empty_review_findings(), _empty_overrides())

        output_dir = tmp_path / "tampered_bundle"
        output_dir.mkdir()
        write_compiled_policy_to_dir(policy, output_dir)

        # Tamper with the compiled policy
        policy_path = output_dir / "compiled_guard_policy.yaml"
        policy_path.write_text(policy_path.read_text() + "# injected\n")

        from src.core.security.compiled_guard_loader import (
            load_active_policy_from_bundle_dir,
            GuardLoadError,
        )
        from src.core.security.compiled_guard_loader import REASON_POLICY_INTEGRITY_ERROR
        loaded = load_active_policy_from_bundle_dir(output_dir)
        assert isinstance(loaded, GuardLoadError)
        assert loaded.reason_code == REASON_POLICY_INTEGRITY_ERROR

    def test_activate_bundle_rejects_non_ready(self, tmp_path: Path):
        """activate_bundle raises ValueError when compile_status is not 'ready'."""
        if "compile_guard_policy" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        if "activate_bundle" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")
        if "write_compiled_policy_artifact" not in globals():
            pytest.skip("Module not yet implemented (TDD red phase)")

        # Empty assets -> compile_failed
        facts = _make_minimal_facts(assets=[])
        policy = compile_guard_policy(facts, _empty_review_findings(), _empty_overrides())
        assert policy["compile_status"] == "compile_failed"

        output_dir = tmp_path / "failed_bundle"
        output_dir.mkdir()
        file_hash = write_compiled_policy_artifact(policy, output_dir)

        with pytest.raises(ValueError, match="Cannot activate bundle"):
            activate_bundle(policy, output_dir, file_hash)
