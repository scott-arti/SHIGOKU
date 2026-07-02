"""
Bugcrowd Program Adapter tests.

Tests for BugcrowdAdapter following TDD — these tests must fail
before the adapter is implemented.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from src.core.security.bugcrowd_adapter import BugcrowdAdapter
from src.core.security.program_adapter_base import NormalizedFacts

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

FIREBLOCKS_BUNDLE = Path(__file__).resolve().parents[2] / "fixtures" / "program_bundle" / "fireblocks"


# ---------------------------------------------------------------------------
# Helper: serialise NormalizedFacts deterministically for comparison
# ---------------------------------------------------------------------------

def _facts_summary(facts: NormalizedFacts) -> str:
    """Return a deterministic JSON summary for comparison."""
    return json.dumps(
        {
            "adapter": facts.adapter,
            "program": facts.program,
            "assets": sorted(
                [
                    {
                        "raw_identifier": a.raw_identifier,
                        "canonical_key": a.canonical_key,
                        "asset_kind": a.asset_kind,
                        "submission_allowed": a.submission_allowed,
                    }
                    for a in facts.assets
                ],
                key=lambda x: x["canonical_key"],
            ),
            "rule_candidates": sorted(
                [
                    {
                        "rule_id": r.rule_id,
                        "category": r.category,
                        "decision": r.decision,
                        "subject": r.subject,
                        "specificity": r.specificity,
                        "origin_type": r.origin_type,
                    }
                    for r in facts.rule_candidates
                ],
                key=lambda x: x["rule_id"],
            ),
            "review_candidates": sorted(
                [
                    {
                        "finding_id": rc.finding_id,
                        "category": rc.category,
                        "subject": rc.subject,
                        "blocking": rc.blocking,
                        "risk_level": rc.risk_level,
                    }
                    for rc in facts.review_candidates
                ],
                key=lambda x: x["finding_id"],
            ),
        },
        sort_keys=True,
    )


# ---------------------------------------------------------------------------
# 1. Happy-path: full Fireblocks bundle
# ---------------------------------------------------------------------------

class TestFireblocksBundleSuccess:
    """Happy-path tests against the Fireblocks Bugcrowd bundle."""

    @pytest.fixture(scope="class")
    def facts(self):
        """Process the Fireblocks bundle once for the test class."""
        adapter = BugcrowdAdapter(FIREBLOCKS_BUNDLE)
        return adapter.process()

    # -- 1.1 Basic identity -------------------------------------------------

    def test_process_fireblocks_bundle_success(self, facts):
        """Adapter processes the Fireblocks bundle and returns NormalizedFacts."""
        assert isinstance(facts, NormalizedFacts)
        assert facts.adapter["name"] == "bugcrowd_program_adapter"
        assert facts.program["provider"] == "bugcrowd"
        assert facts.program["program_name"] == "Fireblocks"

    def test_source_inventory_populated(self, facts):
        """Source inventory records policy.md and scope_assets.txt as loaded."""
        loaded = [e for e in facts.source_inventory if e.loaded]
        kinds = {e.kind for e in loaded}
        assert "policy_text" in kinds
        assert "extracted_scope_block" in kinds

    # -- 1.2 Target host assets ---------------------------------------------

    def test_target_host_assets(self, facts):
        """Three exact host assets extracted with submission_allowed=true."""
        host_assets = [
            a
            for a in facts.assets
            if a.asset_kind == "host_exact" and "fireblocks.io" in a.raw_identifier
        ]
        assert len(host_assets) >= 3

        for a in host_assets:
            assert a.submission_allowed is True

        # Verify the three expected hosts
        hosts = {a.canonical_key for a in host_assets}
        assert "sb-console-api.fireblocks.io" in hosts
        assert "sb-mobile-api.fireblocks.io" in hosts
        assert "sandbox-api.fireblocks.io" in hosts

    def test_no_implicit_deny_for_unlisted_subdomain(self, facts):
        """Adapter does NOT create deny rules for unlisted hosts — compiler's job."""
        for rc in facts.rule_candidates:
            if rc.category == "destination":
                assert "unlisted" not in rc.subject.lower()
                # There shouldn't be a deny rule specifically for unlisted hosts
                assert "other fireblocks" not in rc.subject.lower()

    def test_normalized_hosts_lowercase(self, facts):
        """All host assets have lowercase canonical keys."""
        for a in facts.assets:
            if a.asset_kind in ("host_exact", "host_wildcard"):
                assert a.canonical_key == a.canonical_key.lower()

    # -- 1.3 Post-exploit rule ----------------------------------------------

    def test_post_exploit_rule(self, facts):
        """A phase:post_exploit=deny rule candidate exists."""
        post_exploit_rules = [
            r for r in facts.rule_candidates
            if r.category == "phase" and r.subject == "post_exploit" and r.decision == "deny"
        ]
        assert len(post_exploit_rules) >= 1

    # -- 1.4 Attack class deny rules ----------------------------------------

    def test_dos_attack_class_deny(self, facts):
        """An attack_class:dos=deny rule candidate exists."""
        dos_rules = [
            r for r in facts.rule_candidates
            if r.category == "attack_class" and r.subject == "dos" and r.decision == "deny"
        ]
        assert len(dos_rules) >= 1

    def test_rate_limit_bypass_deny(self, facts):
        """An attack_class:rate_limit_bypass=deny rule candidate exists."""
        rlb_rules = [
            r for r in facts.rule_candidates
            if r.category == "attack_class"
            and r.subject == "rate_limit_bypass"
            and r.decision == "deny"
        ]
        assert len(rlb_rules) >= 1

    def test_third_party_out_of_scope_rule(self, facts):
        """A deny rule for third party providers/services exists."""
        third_party_rules = [
            r for r in facts.rule_candidates
            if "third_party" in r.subject and r.decision == "deny"
        ]
        assert len(third_party_rules) >= 1

    # -- 1.5 Auth rule ------------------------------------------------------

    def test_auth_email_domain_rule(self, facts):
        """Auth rule with bugcrowdninja.com exists."""
        auth_rules = [
            r for r in facts.rule_candidates
            if r.category == "auth"
        ]
        assert len(auth_rules) >= 1
        # At least one must mention bugcrowdninja.com
        bugcrowd_domain_rules = [
            r for r in auth_rules
            if "bugcrowdninja.com" in r.subject
            or "bugcrowdninja.com" in str(r.constraints)
        ]
        assert len(bugcrowd_domain_rules) >= 1

    # -- 1.6 P5 is not a deny rule ------------------------------------------

    def test_p5_not_deny_rule(self, facts):
        """P5 vulnerabilities should NOT produce a deny rule candidate."""
        p5_rules = [
            r for r in facts.rule_candidates
            if "p5" in r.subject.lower() or "p5" in r.rule_id.lower()
        ]
        # P5 should be metadata only, not a deny rule
        deny_p5 = [r for r in p5_rules if r.decision == "deny"]
        assert len(deny_p5) == 0

    # -- 1.7 Focus Areas + Safe Harbor are not rules ------------------------

    def test_focus_areas_not_allow_rules(self, facts):
        """Focus Areas text should NOT generate allow rules."""
        focus_rules = [
            r for r in facts.rule_candidates
            if "focus" in r.subject.lower() or "focus_area" in r.subject.lower()
        ]
        assert len(focus_rules) == 0

    def test_safe_harbor_not_rule(self, facts):
        """Safe Harbor text should NOT generate runtime rules."""
        safe_harbor_rules = [
            r for r in facts.rule_candidates
            if "safe harbor" in r.subject.lower() or "safe_harbor" in r.subject.lower()
        ]
        assert len(safe_harbor_rules) == 0

    # -- 1.8 Review candidates ----------------------------------------------

    def test_review_candidates_generated(self, facts):
        """At least some review candidates exist for N-day, focus area,
        credential ambiguity, etc."""
        assert len(facts.review_candidates) >= 1, (
            "Expected at least one review candidate for N-day, focus, or credential ambiguity"
        )

    def test_review_candidate_n_day_ambiguity(self, facts):
        """A review candidate for N-day/third-party 0-day ambiguity exists."""
        n_day_reviews = [
            rc for rc in facts.review_candidates
            if "n_day" in rc.category
            or "n-day" in rc.subject.lower()
            or "third_party_n_day" in rc.category
            or "third_party_n_day" in rc.subject.lower()
        ]
        assert len(n_day_reviews) >= 1

    # -- 1.9 Deterministic output ------------------------------------------

    def test_deterministic_output(self, facts):
        """Processing the same bundle twice gives identical results."""
        adapter2 = BugcrowdAdapter(FIREBLOCKS_BUNDLE)
        facts2 = adapter2.process()
        assert _facts_summary(facts) == _facts_summary(facts2)


# ---------------------------------------------------------------------------
# 2. Error paths
# ---------------------------------------------------------------------------


class TestErrorPaths:
    """Error-path tests for bundle validation failures."""

    def test_bundle_missing_manifest(self, tmp_path):
        """Bundle without source_manifest.yaml raises ValueError."""
        # Create a bare directory
        empty_dir = tmp_path / "no_manifest"
        empty_dir.mkdir()
        with pytest.raises(ValueError, match="source_manifest.yaml"):
            BugcrowdAdapter(empty_dir).process()

    def test_wrong_provider(self, tmp_path):
        """Manifest with provider=hackerone raises ValueError."""
        bundle_dir = tmp_path / "wrong_provider"
        bundle_dir.mkdir()
        (bundle_dir / "source_manifest.yaml").write_text(
            yaml.dump({
                "schema_version": 1,
                "provider": "hackerone",
                "program_name": "Test",
                "captured_at_utc": "2026-01-01T00:00:00Z",
                "bundle_id": "test-123",
                "policy_path": "policy.md",
                "scope_sources": [{"kind": "extracted_scope_block", "path": "scope_assets.txt"}],
            })
        )
        (bundle_dir / "policy.md").write_text("# Test\n\nNot Bugcrowd\n")
        (bundle_dir / "scope_assets.txt").write_text("example.com\n")
        with pytest.raises(ValueError, match="Provider mismatch"):
            BugcrowdAdapter(bundle_dir).process()

    def test_missing_policy(self, tmp_path):
        """Bundle with source_manifest but no policy.md raises ValueError."""
        bundle_dir = tmp_path / "missing_policy"
        bundle_dir.mkdir()
        (bundle_dir / "source_manifest.yaml").write_text(
            yaml.dump({
                "schema_version": 1,
                "provider": "bugcrowd",
                "program_name": "Test",
                "captured_at_utc": "2026-01-01T00:00:00Z",
                "bundle_id": "test-123",
                "policy_path": "policy.md",
                "scope_sources": [{"kind": "extracted_scope_block", "path": "scope_assets.txt"}],
            })
        )
        # Don't create policy.md — should fail
        # Actually scope_assets.txt must also exist or it'll fail on that first
        (bundle_dir / "scope_assets.txt").write_text("example.com\n")
        with pytest.raises(ValueError, match="Policy file not found"):
            BugcrowdAdapter(bundle_dir).process()

    def test_missing_policy_path_in_manifest(self, tmp_path):
        """Manifest with empty policy_path raises ValueError."""
        bundle_dir = tmp_path / "no_policy_path"
        bundle_dir.mkdir()
        (bundle_dir / "source_manifest.yaml").write_text(
            yaml.dump({
                "schema_version": 1,
                "provider": "bugcrowd",
                "program_name": "Test",
                "captured_at_utc": "2026-01-01T00:00:00Z",
                "bundle_id": "test-123",
                "policy_path": "",
                "scope_sources": [{"kind": "extracted_scope_block", "path": "scope_assets.txt"}],
            })
        )
        (bundle_dir / "scope_assets.txt").write_text("example.com\n")
        with pytest.raises(ValueError, match="missing policy_path"):
            BugcrowdAdapter(bundle_dir).process()
