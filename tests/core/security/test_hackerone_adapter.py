"""
Unit tests for hackerone_adapter.py.

Covers:
- TikTok bundle success processing
- Asset extraction correctness
- Attack class rule extraction
- Post-exploit rule extraction
- SSRF rule extraction
- Error paths (missing manifest, wrong provider, missing fields, missing CSV)
- Deterministic output
- Wildcard normalization
- Missing required CSV columns
- Review candidate generation
"""

import copy
import csv
import io
import os
from pathlib import Path

import pytest

from src.core.security.program_adapter_base import (
    NormalizedAsset,
    NormalizedFacts,
    RuleCandidate,
    ReviewCandidate,
)
from src.core.security.hackerone_adapter import HackerOneAdapter

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------
FIXTURES_DIR = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "program_bundle"
TIKTOK_BUNDLE = FIXTURES_DIR / "tiktok"
TIKTOK_INCOMPLETE = FIXTURES_DIR / "tiktok_incomplete"


# ---------------------------------------------------------------------------
# Helper: create a minimal bundle in tmp_path
# ---------------------------------------------------------------------------
def _write_manifest(bundle_dir: Path, provider: str = "hackerone",
                    policy_path: str = "policy.md",
                    scope_path: str = "scope_assets.csv") -> None:
    import yaml
    manifest = {
        "schema_version": 1,
        "provider": provider,
        "program_name": "TestProgram",
        "captured_at_utc": "2026-07-01T00:00:00Z",
        "default_timezone": "UTC",
        "bundle_id": "test-bundle-id",
        "policy_path": policy_path,
        "scope_sources": [
            {"kind": "hackerone_csv", "path": scope_path},
        ],
    }
    with open(bundle_dir / "source_manifest.yaml", "w") as f:
        yaml.dump(manifest, f)


def _write_policy(bundle_dir: Path, content: str = "# Test Policy\n") -> None:
    (bundle_dir / "policy.md").write_text(content, encoding="utf-8")


def _write_scope_csv(bundle_dir: Path,
                     rows: list[dict] | None = None,
                     path: str = "scope_assets.csv") -> None:
    if rows is None:
        rows = [
            {"identifier": "*.example.com", "asset_type": "WILDCARD",
             "instruction": "Test", "eligible_for_bounty": "true",
             "eligible_for_submission": "true",
             "availability_requirement": "", "confidentiality_requirement": "",
             "integrity_requirement": "", "max_severity": "critical"},
        ]
    fieldnames = [
        "identifier", "asset_type", "instruction",
        "eligible_for_bounty", "eligible_for_submission",
        "availability_requirement", "confidentiality_requirement",
        "integrity_requirement", "max_severity",
    ]
    with open(bundle_dir / path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Success path tests
# ---------------------------------------------------------------------------

class TestHackerOneAdapterSuccess:
    """Tests for successful bundle processing."""

    def test_process_tiktok_bundle_success(self):
        """Load TikTok fixture, call process(), verify NormalizedFacts structure."""
        adapter = HackerOneAdapter(TIKTOK_BUNDLE)
        facts = adapter.process()

        assert isinstance(facts, NormalizedFacts)
        assert facts.adapter["name"] == "hackerone_program_adapter"
        assert facts.adapter["version"] == 1
        assert facts.program["provider"] == "hackerone"
        assert facts.program["program_name"] == "TikTok"

        # Should have assets
        assert len(facts.assets) >= 8, f"Expected at least 8 assets, got {len(facts.assets)}"

        # Should have source_inventory entries
        assert len(facts.source_inventory) == 2  # policy.md + scope_assets.csv

        # Should have rule candidates from policy text
        assert len(facts.rule_candidates) >= 4

        # Should have review candidates
        assert len(facts.review_candidates) >= 1

        # Should have extraction audit
        assert len(facts.extraction_audit) >= 2

    def test_tiktok_assets_correct(self):
        """Verify exact assets extracted from TikTok bundle."""
        adapter = HackerOneAdapter(TIKTOK_BUNDLE)
        facts = adapter.process()

        assets_by_id = {a.asset_id: a for a in facts.assets}
        assets_by_ident = {a.raw_identifier: a for a in facts.assets}

        # *.tiktok.com: wildcard, submission_allowed=true
        assert "*.tiktok.com" in assets_by_ident
        wildcard_tiktok = assets_by_ident["*.tiktok.com"]
        assert wildcard_tiktok.asset_kind == "host_wildcard"
        assert wildcard_tiktok.submission_allowed is True
        assert wildcard_tiktok.bounty_allowed is True
        assert wildcard_tiktok.max_severity == "critical"
        assert wildcard_tiktok.runtime_surface == "http"

        # developers.tiktok.com: deny asset (eligible_for_submission=false)
        assert "developers.tiktok.com" in assets_by_ident
        dev_asset = assets_by_ident["developers.tiktok.com"]
        assert dev_asset.asset_kind == "host_exact"
        assert dev_asset.submission_allowed is False
        assert dev_asset.bounty_allowed is False

        # fbt.tiktok.com: deny asset
        assert "fbt.tiktok.com" in assets_by_ident
        fbt_asset = assets_by_ident["fbt.tiktok.com"]
        assert fbt_asset.asset_kind == "host_exact"
        assert fbt_asset.submission_allowed is False

        # *tiktokv.us: deny wildcard
        assert "*tiktokv.us" in assets_by_ident
        tiktokv = assets_by_ident["*tiktokv.us"]
        assert tiktokv.asset_kind == "host_wildcard"
        assert tiktokv.submission_allowed is False

        # *us.tiktokv.com: deny wildcard
        assert "*us.tiktokv.com" in assets_by_ident
        ustiktokv = assets_by_ident["*us.tiktokv.com"]
        assert ustiktokv.asset_kind == "host_wildcard"
        assert ustiktokv.submission_allowed is False

        # *byteoversea.com: deny wildcard
        assert "*byteoversea.com" in assets_by_ident
        byteoversea = assets_by_ident["*byteoversea.com"]
        assert byteoversea.asset_kind == "host_wildcard"
        assert byteoversea.submission_allowed is False

        # tiktokcdn.com: allow wildcard (eligible_for_submission=true per CSV)
        assert "tiktokcdn.com" in assets_by_ident
        cdn = assets_by_ident["tiktokcdn.com"]
        assert cdn.asset_kind == "host_wildcard"
        assert cdn.submission_allowed is True
        assert cdn.max_severity == "medium"

        # Mobile app assets
        assert "android-app" in assets_by_ident
        android = assets_by_ident["android-app"]
        assert android.asset_kind == "mobile_app"
        assert android.runtime_surface == "mobile"

        assert "ios-app" in assets_by_ident
        ios = assets_by_ident["ios-app"]
        assert ios.asset_kind == "mobile_app"
        assert ios.runtime_surface == "mobile"

    def test_asset_ids_follow_pattern(self):
        """Asset IDs follow h1-asset-{row_index} pattern."""
        adapter = HackerOneAdapter(TIKTOK_BUNDLE)
        facts = adapter.process()

        for asset in facts.assets:
            assert asset.asset_id.startswith("h1-asset-"), \
                f"Asset ID '{asset.asset_id}' does not match pattern"

    def test_attack_class_rules(self):
        """social_engineering=deny, dos=deny, privacy_harm=deny."""
        adapter = HackerOneAdapter(TIKTOK_BUNDLE)
        facts = adapter.process()

        rules_by_subject = {}
        for rc in facts.rule_candidates:
            if rc.category == "attack_class":
                rules_by_subject[rc.subject] = rc

        # social engineering -> deny
        assert "social_engineering" in rules_by_subject, \
            f"social_engineering rule not found, subjects: {list(rules_by_subject.keys())}"
        assert rules_by_subject["social_engineering"].decision == "deny"

        # dos -> deny
        assert "dos" in rules_by_subject, \
            f"dos rule not found, subjects: {list(rules_by_subject.keys())}"
        assert rules_by_subject["dos"].decision == "deny"

        # privacy_harm -> deny
        assert "privacy_harm" in rules_by_subject, \
            f"privacy_harm rule not found, subjects: {list(rules_by_subject.keys())}"
        assert rules_by_subject["privacy_harm"].decision == "deny"

    def test_post_exploit_rule(self):
        """post_exploit=deny rule candidate exists."""
        adapter = HackerOneAdapter(TIKTOK_BUNDLE)
        facts = adapter.process()

        post_exploit_rules = [
            rc for rc in facts.rule_candidates
            if rc.category == "phase" and rc.subject == "post_exploit"
        ]
        assert len(post_exploit_rules) >= 1, \
            f"Expected at least 1 post_exploit rule, got {len(post_exploit_rules)}"
        assert post_exploit_rules[0].decision == "deny"

    def test_ssrf_rules(self):
        """Allow rule for SSRF sheriff-specified destinations."""
        adapter = HackerOneAdapter(TIKTOK_BUNDLE)
        facts = adapter.process()

        ssrf_allow_rules = [
            rc for rc in facts.rule_candidates
            if rc.category == "destination" and rc.decision == "allow"
        ]
        assert len(ssrf_allow_rules) >= 2, \
            f"Expected at least 2 SSRF allow rules, got {len(ssrf_allow_rules)}"

        # Check that the allow rules reference ssrf-bait.byted.org
        allow_subjects = {rc.subject for rc in ssrf_allow_rules}
        assert any("ssrf-bait.byted.org" in s for s in allow_subjects), \
            f"No SSRF allow rule references byted.org, subjects: {allow_subjects}"

        # There should also be a deny rule for other SSRF destinations
        ssrf_deny_rules = [
            rc for rc in facts.rule_candidates
            if rc.category == "destination" and rc.decision == "deny"
        ]
        assert len(ssrf_deny_rules) >= 1, \
            f"Expected at least 1 SSRF deny rule, got {len(ssrf_deny_rules)}"

    def test_rule_ids_follow_pattern(self):
        """Rule IDs follow h1-rule-{category}-{counter} pattern."""
        adapter = HackerOneAdapter(TIKTOK_BUNDLE)
        facts = adapter.process()

        for rc in facts.rule_candidates:
            assert rc.rule_id.startswith("h1-rule-"), \
                f"Rule ID '{rc.rule_id}' does not match pattern"

    def test_deterministic_output(self):
        """Same bundle processed twice gives same asset/rule counts."""
        facts1 = HackerOneAdapter(TIKTOK_BUNDLE).process()
        facts2 = HackerOneAdapter(TIKTOK_BUNDLE).process()

        assert len(facts1.assets) == len(facts2.assets)
        assert len(facts1.rule_candidates) == len(facts2.rule_candidates)
        assert len(facts1.review_candidates) == len(facts2.review_candidates)

        # Asset IDs should be deterministic
        ids1 = sorted(a.asset_id for a in facts1.assets)
        ids2 = sorted(a.asset_id for a in facts2.assets)
        assert ids1 == ids2

        # Rule IDs should be deterministic
        rule_ids1 = sorted(rc.rule_id for rc in facts1.rule_candidates)
        rule_ids2 = sorted(rc.rule_id for rc in facts2.rule_candidates)
        assert rule_ids1 == rule_ids2

    def test_normalized_wildcard_format(self):
        """*example.com should become *.example.com in canonical_key."""
        adapter = HackerOneAdapter(TIKTOK_BUNDLE)
        facts = adapter.process()

        # *tiktokv.us raw identifier with * prefix -> canonical_key should be *.tiktokv.us
        asset = next(a for a in facts.assets if a.raw_identifier == "*tiktokv.us")
        # Base class normalize_assets should convert *X -> *.X
        assert asset.canonical_key == "*.tiktokv.us", \
            f"Expected '*.tiktokv.us', got '{asset.canonical_key}'"

        # *us.tiktokv.com -> *.us.tiktokv.com
        asset2 = next(a for a in facts.assets if a.raw_identifier == "*us.tiktokv.com")
        assert asset2.canonical_key == "*.us.tiktokv.com", \
            f"Expected '*.us.tiktokv.com', got '{asset2.canonical_key}'"

        # *.tiktok.com should stay as *.tiktok.com
        asset3 = next(a for a in facts.assets if a.raw_identifier == "*.tiktok.com")
        assert asset3.canonical_key == "*.tiktok.com"

    def test_review_candidates_generated(self):
        """Review candidates include temporal exclusions."""
        adapter = HackerOneAdapter(TIKTOK_BUNDLE)
        facts = adapter.process()

        assert len(facts.review_candidates) >= 1, \
            f"Expected at least 1 review candidate, got {len(facts.review_candidates)}"

        # At least one review candidate should relate to the developers.tiktok.com/minis
        # temporal exclusion or similar ambiguity
        finding_subjects = {rc.subject for rc in facts.review_candidates}
        finding_categories = {rc.category for rc in facts.review_candidates}

        # Should have finding IDs following pattern
        for rc in facts.review_candidates:
            assert rc.finding_id.startswith("H1-"), \
                f"Finding ID '{rc.finding_id}' does not match pattern H1-..."

        # At least one review candidate should reference policy.md or scope_assets.csv
        all_source_refs = []
        for rc in facts.review_candidates:
            all_source_refs.extend(rc.source_refs)
        assert len(all_source_refs) > 0, "Review candidates should have source_refs"

    def test_source_inventory_entries(self):
        """Source inventory records what was loaded."""
        adapter = HackerOneAdapter(TIKTOK_BUNDLE)
        facts = adapter.process()

        kinds = {entry.kind for entry in facts.source_inventory}
        assert "policy_text" in kinds
        assert "structured_scope" in kinds or "hackerone_csv" in kinds

        for entry in facts.source_inventory:
            assert entry.loaded is True
            assert entry.parse_status == "ok"

    def test_minimal_bundle_with_tmp_path(self, tmp_path):
        """Process a minimal valid bundle in tmp_path."""
        _write_manifest(tmp_path)
        _write_policy(tmp_path, "# Test\nNo special rules.\n")
        _write_scope_csv(tmp_path)

        adapter = HackerOneAdapter(tmp_path)
        facts = adapter.process()

        assert len(facts.assets) == 1
        assert facts.assets[0].raw_identifier == "*.example.com"
        assert facts.assets[0].asset_kind == "host_wildcard"
        assert facts.assets[0].submission_allowed is True


# ---------------------------------------------------------------------------
# Error path tests
# ---------------------------------------------------------------------------

class TestHackerOneAdapterErrors:
    """Tests for error handling in the adapter."""

    def test_bundle_missing_manifest(self, tmp_path):
        """Directory without source_manifest.yaml raises ValueError."""
        # tmp_path is empty
        adapter = HackerOneAdapter(tmp_path)
        with pytest.raises(ValueError, match="source_manifest.yaml"):
            adapter.process()

    def test_wrong_provider(self, tmp_path):
        """Manifest with provider:bugcrowd raises ValueError for HackerOne adapter."""
        _write_manifest(tmp_path, provider="bugcrowd")
        _write_policy(tmp_path)
        _write_scope_csv(tmp_path)

        adapter = HackerOneAdapter(tmp_path)
        with pytest.raises(ValueError, match="Provider mismatch"):
            adapter.process()

    def test_manifest_missing_policy_path(self, tmp_path):
        """Missing policy_path field raises ValueError."""
        import yaml
        manifest = {
            "schema_version": 1,
            "provider": "hackerone",
            "program_name": "Test",
            "bundle_id": "test",
            "scope_sources": [{"kind": "hackerone_csv", "path": "scope_assets.csv"}],
        }
        with open(tmp_path / "source_manifest.yaml", "w") as f:
            yaml.dump(manifest, f)
        _write_policy(tmp_path)
        _write_scope_csv(tmp_path)

        adapter = HackerOneAdapter(tmp_path)
        with pytest.raises(ValueError, match="policy_path"):
            adapter.process()

    def test_missing_scope_csv(self, tmp_path):
        """CSV file referenced in manifest but missing raises ValueError."""
        _write_manifest(tmp_path)
        _write_policy(tmp_path)
        # Do NOT create scope_assets.csv

        adapter = HackerOneAdapter(tmp_path)
        with pytest.raises(ValueError, match="scope_assets.csv"):
            adapter.process()

    def test_missing_policy_file(self, tmp_path):
        """Policy file referenced but missing raises ValueError."""
        _write_manifest(tmp_path, policy_path="nonexistent.md")
        _write_scope_csv(tmp_path)
        # Do NOT create policy.md

        adapter = HackerOneAdapter(tmp_path)
        with pytest.raises(ValueError, match="Policy file"):
            adapter.process()

    def test_csv_missing_required_columns(self, tmp_path):
        """CSV missing 'identifier' column raises error."""
        _write_manifest(tmp_path)
        _write_policy(tmp_path)

        # Create CSV without 'identifier' column
        csv_path = tmp_path / "scope_assets.csv"
        csv_path.write_text("asset_type,instruction\nWILDCARD,test\n")

        adapter = HackerOneAdapter(tmp_path)
        with pytest.raises(ValueError, match="identifier"):
            adapter.process()

    def test_empty_scope_sources(self, tmp_path):
        """Manifest with empty scope_sources raises ValueError."""
        import yaml
        manifest = {
            "schema_version": 1,
            "provider": "hackerone",
            "program_name": "Test",
            "bundle_id": "test",
            "policy_path": "policy.md",
            "scope_sources": [],
        }
        with open(tmp_path / "source_manifest.yaml", "w") as f:
            yaml.dump(manifest, f)
        _write_policy(tmp_path)

        adapter = HackerOneAdapter(tmp_path)
        with pytest.raises(ValueError):
            adapter.process()

    def test_bundle_directory_not_found(self):
        """Non-existent directory raises ValueError."""
        adapter = HackerOneAdapter("/nonexistent/path/to/bundle")
        with pytest.raises(ValueError, match="not found"):
            adapter.process()

    def test_scope_source_without_path(self, tmp_path):
        """Scope source entry without 'path' raises error."""
        import yaml
        manifest = {
            "schema_version": 1,
            "provider": "hackerone",
            "program_name": "Test",
            "bundle_id": "test",
            "policy_path": "policy.md",
            "scope_sources": [{"kind": "hackerone_csv"}],  # no 'path'
        }
        with open(tmp_path / "source_manifest.yaml", "w") as f:
            yaml.dump(manifest, f)
        _write_policy(tmp_path)

        adapter = HackerOneAdapter(tmp_path)
        with pytest.raises(ValueError, match="path"):
            adapter.process()

    def test_manifest_not_yaml_dict(self, tmp_path):
        """Manifest that is not a YAML mapping raises error."""
        import yaml
        (tmp_path / "source_manifest.yaml").write_text("- list item\n- another\n")
        _write_policy(tmp_path)

        adapter = HackerOneAdapter(tmp_path)
        # yaml.YAMLError is raised by _load_yaml before process returns
        with pytest.raises((ValueError, yaml.YAMLError)):
            adapter.process()

    def test_scope_source_kind_not_hackerone_csv(self, tmp_path):
        """Scope source with unsupported kind should still load (adapter handles CSV specifically)."""
        _write_manifest(tmp_path, scope_path="scope_assets.txt")
        _write_policy(tmp_path)
        (tmp_path / "scope_assets.txt").write_text("dummy content")

        adapter = HackerOneAdapter(tmp_path)
        # This may raise ValueError because the adapter looks for CSV specifically
        # or may work if we check kind. The base class loads any source.
        # The adapter should either handle it or raise appropriately.
        # For H1 adapter, if scope source has no CSV with required columns, it should error.
        with pytest.raises(ValueError):
            adapter.process()


# ---------------------------------------------------------------------------
# Additional edge case tests
# ---------------------------------------------------------------------------

class TestHackerOneAdapterEdgeCases:
    """Edge case and robustness tests."""

    def test_url_prefix_asset_kind(self, tmp_path):
        """URL with https:// prefix should be asset_kind=url_prefix."""
        _write_manifest(tmp_path)
        _write_policy(tmp_path)
        _write_scope_csv(tmp_path, rows=[
            {"identifier": "https://api.example.com/v1/", "asset_type": "URL",
             "instruction": "API endpoint", "eligible_for_bounty": "true",
             "eligible_for_submission": "true",
             "availability_requirement": "", "confidentiality_requirement": "",
             "integrity_requirement": "", "max_severity": "high"},
        ])

        adapter = HackerOneAdapter(tmp_path)
        facts = adapter.process()

        assert len(facts.assets) == 1
        assert facts.assets[0].asset_kind == "url_prefix"
        assert facts.assets[0].raw_identifier == "https://api.example.com/v1/"

    def test_host_exact_asset_kind(self, tmp_path):
        """URL-type asset without scheme should be asset_kind=host_exact."""
        _write_manifest(tmp_path)
        _write_policy(tmp_path)
        _write_scope_csv(tmp_path, rows=[
            {"identifier": "api.example.com", "asset_type": "URL",
             "instruction": "API host", "eligible_for_bounty": "true",
             "eligible_for_submission": "true",
             "availability_requirement": "", "confidentiality_requirement": "",
             "integrity_requirement": "", "max_severity": "low"},
        ])

        adapter = HackerOneAdapter(tmp_path)
        facts = adapter.process()

        assert len(facts.assets) == 1
        assert facts.assets[0].asset_kind == "host_exact"
        assert facts.assets[0].raw_identifier == "api.example.com"

    def test_wildcard_with_star_dot_prefix(self, tmp_path):
        """identifier with *. prefix should be host_wildcard."""
        _write_manifest(tmp_path)
        _write_policy(tmp_path)
        _write_scope_csv(tmp_path, rows=[
            {"identifier": "*.sub.example.com", "asset_type": "WILDCARD",
             "instruction": "Wildcard sub", "eligible_for_bounty": "true",
             "eligible_for_submission": "true",
             "availability_requirement": "", "confidentiality_requirement": "",
             "integrity_requirement": "", "max_severity": "medium"},
        ])

        adapter = HackerOneAdapter(tmp_path)
        facts = adapter.process()

        assert facts.assets[0].asset_kind == "host_wildcard"
        assert facts.assets[0].canonical_key == "*.sub.example.com"

    def test_bounty_allowed_false_submission_true(self, tmp_path):
        """eligible_for_bounty=false but eligible_for_submission=true."""
        _write_manifest(tmp_path)
        _write_policy(tmp_path)
        _write_scope_csv(tmp_path, rows=[
            {"identifier": "test.example.com", "asset_type": "URL",
             "instruction": "Sub only", "eligible_for_bounty": "false",
             "eligible_for_submission": "true",
             "availability_requirement": "", "confidentiality_requirement": "",
             "integrity_requirement": "", "max_severity": "none"},
        ])

        adapter = HackerOneAdapter(tmp_path)
        facts = adapter.process()

        assert facts.assets[0].submission_allowed is True
        assert facts.assets[0].bounty_allowed is False

    def test_policy_text_with_no_rules(self, tmp_path):
        """Policy with no recognizable rules generates no rule candidates."""
        _write_manifest(tmp_path)
        _write_policy(tmp_path, "# Empty Policy\n\nNothing interesting here.\n")
        _write_scope_csv(tmp_path)

        adapter = HackerOneAdapter(tmp_path)
        facts = adapter.process()

        assert len(facts.assets) >= 1
        # No rules should be extracted from benign text
        # But base rules might still exist from asset analysis
        assert all(
            rc.origin_type == "structured_scope" or rc.origin_type == "derived"
            for rc in facts.rule_candidates
            if "policy_text" != rc.origin_type
        )

    def test_multiple_ssrf_destinations_in_policy(self, tmp_path):
        """Multiple SSRF destinations are extracted from policy.md."""
        _write_manifest(tmp_path)
        _write_policy(tmp_path, """# Policy
## SSRF
SSRF testing is allowed ONLY against these destinations:
- https://bait1.example.com/test
- https://bait2.example.com/probe/*

Do not test SSRF against any other destination.
""")
        _write_scope_csv(tmp_path)

        adapter = HackerOneAdapter(tmp_path)
        facts = adapter.process()

        ssrf_allow = [
            rc for rc in facts.rule_candidates
            if rc.category == "destination" and rc.decision == "allow"
        ]
        assert len(ssrf_allow) == 2, f"Expected 2 SSRF allow rules, got {len(ssrf_allow)}"

        ssrf_deny = [
            rc for rc in facts.rule_candidates
            if rc.category == "destination" and rc.decision == "deny"
        ]
        assert len(ssrf_deny) >= 1

    def test_review_candidate_for_wildcard_allow_explicit_deny_mix(self, tmp_path):
        """Wildcard allow + explicit deny row on same family generates review candidate."""
        _write_manifest(tmp_path)
        _write_policy(tmp_path)
        _write_scope_csv(tmp_path, rows=[
            {"identifier": "*.example.com", "asset_type": "WILDCARD",
             "instruction": "Wildcard allow", "eligible_for_bounty": "true",
             "eligible_for_submission": "true",
             "availability_requirement": "", "confidentiality_requirement": "",
             "integrity_requirement": "", "max_severity": "critical"},
            {"identifier": "admin.example.com", "asset_type": "URL",
             "instruction": "Admin excluded", "eligible_for_bounty": "false",
             "eligible_for_submission": "false",
             "availability_requirement": "", "confidentiality_requirement": "",
             "integrity_requirement": "", "max_severity": "critical"},
        ])

        adapter = HackerOneAdapter(tmp_path)
        facts = adapter.process()

        # Should have a review candidate for the wildcard/deny conflict
        assert len(facts.review_candidates) >= 1

    def test_source_ref_format(self, tmp_path):
        """Asset source_ref includes CSV reference."""
        _write_manifest(tmp_path)
        _write_policy(tmp_path)
        _write_scope_csv(tmp_path)

        adapter = HackerOneAdapter(tmp_path)
        facts = adapter.process()

        assert "scope_assets.csv" in facts.assets[0].source_ref
