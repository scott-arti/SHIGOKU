"""
Tests for bundle_manager.py — BundleManager lifecycle operations.

Covers:
- import_bundle: directory creation, manifest, review/override stubs
- compile_bundle: adapter + compiler integration
- activate_bundle_manager: activation with ready/not-ready
- list_bundles, show_bundle: inspection operations
- run_preflight: resolver + scope check
- rollback_bundle: version switching
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

# Import the BundleManager — will be created by this TDD step
try:
    from src.core.security.bundle_manager import BundleManager
except ImportError:
    pass

# Fixture paths for existing bundle data
FIXTURES_DIR = Path(__file__).resolve().parents[3] / "tests" / "fixtures"
TIKTOK_BUNDLE = FIXTURES_DIR / "program_bundle" / "tiktok"
FIREBLOCKS_BUNDLE = FIXTURES_DIR / "program_bundle" / "fireblocks"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _skip_if_not_implemented():
    if "BundleManager" not in globals():
        pytest.skip("BundleManager not yet implemented (TDD red phase)")


def _create_bundle_skeleton(tmp_path: Path) -> Path:
    """Create a minimal bundle dir with source_manifest.yaml, policy.md, and scope."""
    bundle_dir = tmp_path / "test_bundle"
    bundle_dir.mkdir()
    manifest = {
        "schema_version": 1,
        "provider": "hackerone",
        "program_name": "TestProgram",
        "captured_at_utc": "2026-07-01T00:00:00Z",
        "default_timezone": "UTC",
        "bundle_id": "bbp-hackerone-testprogram-20260701-abc123",
        "policy_path": "policy.md",
        "scope_sources": [
            {"kind": "hackerone_csv", "path": "scope_assets.csv"},
        ],
    }
    (bundle_dir / "source_manifest.yaml").write_text(
        yaml.dump(manifest), encoding="utf-8"
    )
    (bundle_dir / "policy.md").write_text(
        "# Test Policy\n\nDo not test social engineering, DoS, stop there and report immediately.\n",
        encoding="utf-8",
    )
    (bundle_dir / "scope_assets.csv").write_text(
        "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,"
        "availability_requirement,confidentiality_requirement,integrity_requirement,max_severity\n"
        "*.example.com,WILDCARD,Test,true,true,,,,critical\n"
        "deny.example.com,WILDCARD,Out of scope,false,false,,,,critical\n",
        encoding="utf-8",
    )
    return bundle_dir


def _create_blocking_review_bundle(tmp_path: Path) -> Path:
    """Create a bundle with a blocking pending review finding."""
    bundle_dir = _create_bundle_skeleton(tmp_path)
    (bundle_dir / "review_findings.yaml").write_text(
        yaml.dump({
            "review_findings": [{
                "finding_id": "H1-AMB-001",
                "category": "temporal_scope",
                "subject": "test",
                "risk_level": "high",
                "source_refs": ["policy.md"],
                "machine_guess": {"effect": "deny"},
                "status": "pending",
                "blocking": True,
            }]
        }), encoding="utf-8"
    )
    return bundle_dir


# ---------------------------------------------------------------------------
# 1. Import tests
# ---------------------------------------------------------------------------


class TestImportBundle:
    """Tests for BundleManager.import_bundle()."""

    def test_import_bundle_creates_dir_and_manifest(self, tmp_path: Path):
        """Import from policy.md + scope_assets.csv, verify output directory structure."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")

        policy_file = tmp_path / "mypolicy.md"
        policy_file.write_text("# Test\n\nNo social engineering.\n")
        scope_file = tmp_path / "myscope.csv"
        scope_file.write_text(
            "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,"
            "availability_requirement,confidentiality_requirement,integrity_requirement,max_severity\n"
            "*.example.com,WILDCARD,All apps,true,true,,,,critical\n"
        )

        result = mgr.import_bundle(
            provider="hackerone",
            program_name="TestCo",
            policy_path=str(policy_file),
            scope_path=str(scope_file),
            program_alias="testco",
        )

        assert "bundle_id" in result
        assert result["bundle_id"].startswith("bbp-hackerone-testco-")
        assert result["status"] == "imported"
        assert "bundle_dir" in result

        bundle_dir = Path(result["bundle_dir"])
        assert bundle_dir.is_dir()
        assert (bundle_dir / "source_manifest.yaml").exists()
        assert (bundle_dir / "policy.md").exists()
        # Should auto-detect CSV
        assert (bundle_dir / "scope_assets.csv").exists()
        assert (bundle_dir / "review_findings.yaml").exists()
        assert (bundle_dir / "overrides.yaml").exists()

        # Read manifest and verify its required fields
        manifest = yaml.safe_load((bundle_dir / "source_manifest.yaml").read_text())
        assert manifest["provider"] == "hackerone"
        assert manifest["program_name"] == "TestCo"
        assert manifest["policy_path"] == "policy.md"
        assert manifest["captured_at_utc"] is not None

    def test_import_bundle_generates_bundle_id(self, tmp_path: Path):
        """bundle_id follows format bbp-{provider}-{alias}-{timestamp}-{hash}."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")

        policy_file = tmp_path / "p.md"
        policy_file.write_text("# Hi\n")
        scope_file = tmp_path / "s.csv"
        scope_file.write_text(
            "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,"
            "availability_requirement,confidentiality_requirement,integrity_requirement,max_severity\n"
            "*.x.com,WILDCARD,x,true,true,,,,critical\n"
        )

        result = mgr.import_bundle(
            provider="bugcrowd",
            program_name="MyApp",
            policy_path=str(policy_file),
            scope_path=str(scope_file),
            program_alias="myapp",
        )
        bid = result["bundle_id"]
        assert bid.startswith("bbp-bugcrowd-myapp-")
        # Parts: bbp-provider-alias-timestamp-hash
        parts = bid.split("-")
        assert len(parts) >= 4, f"Expected at least 4 parts in bundle_id, got: {parts}"

    def test_import_bundle_creates_empty_review_and_overrides(self, tmp_path: Path):
        """review_findings.yaml and overrides.yaml are created with correct stubs."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")

        policy_file = tmp_path / "p.md"
        policy_file.write_text("# P\n")
        scope_file = tmp_path / "s.csv"
        scope_file.write_text(
            "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,"
            "availability_requirement,confidentiality_requirement,integrity_requirement,max_severity\n"
            "*.x.com,WILDCARD,x,true,true,,,,critical\n"
        )

        result = mgr.import_bundle(
            provider="hackerone",
            program_name="Test",
            policy_path=str(policy_file),
            scope_path=str(scope_file),
            program_alias="test",
        )
        bundle_dir = Path(result["bundle_dir"])

        review = yaml.safe_load((bundle_dir / "review_findings.yaml").read_text())
        assert review == {"review_findings": []}

        overrides = yaml.safe_load((bundle_dir / "overrides.yaml").read_text())
        assert overrides == {"overrides": {}}

    def test_import_bundle_auto_detect_txt(self, tmp_path: Path):
        """Auto-detects .txt scope files for Bugcrowd-style bundles."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")

        policy_file = tmp_path / "p.md"
        policy_file.write_text("# P\n")
        scope_file = tmp_path / "scope_assets.txt"
        scope_file.write_text("sb-console-api.fireblocks.io\n")

        result = mgr.import_bundle(
            provider="bugcrowd",
            program_name="Fireblocks",
            policy_path=str(policy_file),
            scope_path=str(scope_file),
            program_alias="fireblocks",
        )
        bundle_dir = Path(result["bundle_dir"])
        assert (bundle_dir / "scope_assets.txt").exists()

    def test_import_bundle_rejects_secret_in_policy(self, tmp_path: Path):
        """Policy containing token=ghp_secret... raises ValueError. (Fix 1)"""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")

        policy_path = tmp_path / "secret_policy.md"
        policy_path.write_text("# Program\n\n## Note\nHere is my token: ghp_abc123456789012345")
        scope_path = tmp_path / "scope.csv"
        scope_path.write_text(
            "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,"
            "availability_requirement,confidentiality_requirement,integrity_requirement,max_severity\n"
            "*.example.com,WILDCARD,,true,true,,,,critical\n"
        )

        with pytest.raises(ValueError, match="Secret-like"):
            mgr.import_bundle("hackerone", "Test", str(policy_path), str(scope_path))

    def test_import_bundle_rejects_secret_in_scope_txt(self, tmp_path: Path):
        """Scope file containing token=... raises ValueError. (Fix 1)"""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")

        policy_path = tmp_path / "policy.md"
        policy_path.write_text("# Clean policy")
        scope_path = tmp_path / "scope.txt"
        scope_path.write_text(
            "api.example.com\nstaging.example.com\n# internal token: abc1234567890123456789\n"
        )

        with pytest.raises(ValueError, match="Secret-like"):
            mgr.import_bundle("bugcrowd", "Test", str(policy_path), str(scope_path))

    def test_import_bundle_clean_policy_succeeds(self, tmp_path: Path):
        """Clean policy with no secrets imports successfully. (Fix 1)"""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")

        policy_path = tmp_path / "clean_policy.md"
        policy_path.write_text("# Clean Program\n\n## Targets\n- example.com")
        scope_path = tmp_path / "scope.csv"
        scope_path.write_text(
            "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,"
            "availability_requirement,confidentiality_requirement,integrity_requirement,max_severity\n"
            "*.example.com,WILDCARD,,true,true,,,,critical\n"
        )

        result = mgr.import_bundle("hackerone", "Test", str(policy_path), str(scope_path))
        assert result["status"] == "imported"


# ---------------------------------------------------------------------------
# 2. Compile tests
# ---------------------------------------------------------------------------


class TestCompileBundle:
    """Tests for BundleManager.compile_bundle()."""

    def test_compile_bundle_from_tiktok_fixture(self, tmp_path: Path):
        """Use TikTok fixture bundle, compile -> compile_status=ready."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")

        # Copy tiktok fixture to a temp bundle dir
        bundle_dir = tmp_path / "tiktok_bundle"
        shutil.copytree(str(TIKTOK_BUNDLE), str(bundle_dir))
        # Ensure review_findings and overrides exist (fixture might have them empty)
        if not (bundle_dir / "review_findings.yaml").exists():
            (bundle_dir / "review_findings.yaml").write_text("review_findings: []\n")
        if not (bundle_dir / "overrides.yaml").exists():
            (bundle_dir / "overrides.yaml").write_text("overrides: {}\n")

        result = mgr.compile_bundle(bundle_dir)
        assert result["compile_status"] == "ready"
        assert result["bundle_id"] == "bbp-hackerone-tiktok-2026-07-01T07:38:38Z-ab12cd34"
        assert "policy_path" in result
        # Compiled policy file should exist at the bundle dir
        compiled_path = Path(result["policy_path"])
        assert compiled_path.exists()

    def test_compile_bundle_with_pending_review(self, tmp_path: Path):
        """Bundle with blocking review finding -> compile_status=manual_review_required."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")
        bundle_dir = _create_blocking_review_bundle(tmp_path)

        result = mgr.compile_bundle(bundle_dir)
        assert result["compile_status"] == "manual_review_required"
        assert len(result.get("blocking_findings", [])) >= 1

    def test_compile_bundle_fireblocks(self, tmp_path: Path):
        """Use Fireblocks fixture bundle, compile -> compile_status=ready."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")

        bundle_dir = tmp_path / "fireblocks_bundle"
        shutil.copytree(str(FIREBLOCKS_BUNDLE), str(bundle_dir))
        if not (bundle_dir / "review_findings.yaml").exists():
            (bundle_dir / "review_findings.yaml").write_text("review_findings: []\n")
        if not (bundle_dir / "overrides.yaml").exists():
            (bundle_dir / "overrides.yaml").write_text("overrides: {}\n")

        result = mgr.compile_bundle(bundle_dir)
        assert result["compile_status"] == "ready"
        assert result["bundle_id"] == "bbp-bugcrowd-fireblocks-2026-02-12T13:49:31Z-ef56aa01"


# ---------------------------------------------------------------------------
# 3. Activate tests
# ---------------------------------------------------------------------------


class TestActivateBundle:
    """Tests for BundleManager.activate_bundle_manager()."""

    def test_activate_bundle_manager_ready(self, tmp_path: Path):
        """Compile then activate -> active_bundle.json exists in program dir."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")
        bundle_dir = _create_bundle_skeleton(tmp_path)

        # Compile first
        compile_result = mgr.compile_bundle(bundle_dir)
        assert compile_result["compile_status"] == "ready"

        # Activate
        activate_result = mgr.activate_bundle_manager(bundle_dir)
        assert activate_result["status"] == "activated"
        assert "activated_at_utc" in activate_result

        # active_bundle.json should exist in the program dir
        program_dir = mgr._resolve_program_dir("hackerone", "testprogram")
        active_json = program_dir / "active_bundle.json"
        assert active_json.exists()

    def test_activate_bundle_manager_not_ready_rejected(self, tmp_path: Path):
        """Activate with compile_failed -> ValueError."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")

        # Create a bundle with no in-scope assets -> compile_failed
        bundle_dir = tmp_path / "empty_bundle"
        bundle_dir.mkdir()
        manifest = {
            "schema_version": 1,
            "provider": "hackerone",
            "program_name": "Empty",
            "captured_at_utc": "2026-01-01T00:00:00Z",
            "default_timezone": "UTC",
            "bundle_id": "bbp-hackerone-empty-20260101-000000",
            "policy_path": "policy.md",
            "scope_sources": [
                {"kind": "hackerone_csv", "path": "scope_assets.csv"},
            ],
        }
        (bundle_dir / "source_manifest.yaml").write_text(yaml.dump(manifest))
        (bundle_dir / "policy.md").write_text("# Empty\n")
        # CSV with only deny entries (no submission_allowed=true) -> 0 in-scope assets
        (bundle_dir / "scope_assets.csv").write_text(
            "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,"
            "availability_requirement,confidentiality_requirement,integrity_requirement,max_severity\n"
            "deny.example.com,URL,out of scope,false,false,,,,critical\n"
        )
        if not (bundle_dir / "review_findings.yaml").exists():
            (bundle_dir / "review_findings.yaml").write_text("review_findings: []\n")
        if not (bundle_dir / "overrides.yaml").exists():
            (bundle_dir / "overrides.yaml").write_text("overrides: {}\n")

        # Compile should fail
        compile_result = mgr.compile_bundle(bundle_dir)
        assert compile_result["compile_status"] == "compile_failed"

        # Activate should raise ValueError
        with pytest.raises(ValueError, match="compile_status|not ready|cannot activate"):
            mgr.activate_bundle_manager(bundle_dir)


# ---------------------------------------------------------------------------
# 4. List and Show tests
# ---------------------------------------------------------------------------


class TestListBundles:
    """Tests for BundleManager.list_bundles()."""

    def test_list_bundles_empty(self, tmp_path: Path):
        """Empty workspace returns empty list."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")
        bundles = mgr.list_bundles()
        assert isinstance(bundles, list)

    def test_list_bundles_after_import(self, tmp_path: Path):
        """After importing 2 bundles, list returns both."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")

        # Import 2 bundles
        for i, (provider, name, alias) in enumerate([
            ("hackerone", "AppA", "appa"),
            ("bugcrowd", "AppB", "appb"),
        ]):
            policy_file = tmp_path / f"policy_{i}.md"
            policy_file.write_text(f"# {name}\n")
            scope_file = tmp_path / f"scope_{i}.csv"
            scope_file.write_text(
                "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,"
                "availability_requirement,confidentiality_requirement,integrity_requirement,max_severity\n"
                "*.x.com,WILDCARD,x,true,true,,,,critical\n"
            )
            mgr.import_bundle(
                provider=provider, program_name=name,
                policy_path=str(policy_file), scope_path=str(scope_file),
                program_alias=alias,
            )

        bundles = mgr.list_bundles()
        assert len(bundles) >= 2

    def test_list_bundles_filter_by_provider(self, tmp_path: Path):
        """Filter by provider returns only matching bundles."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")

        # Import hackerone
        pf = tmp_path / "p_h1.md"; pf.write_text("# H1\n")
        sf = tmp_path / "s_h1.csv"
        sf.write_text(
            "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,"
            "availability_requirement,confidentiality_requirement,integrity_requirement,max_severity\n"
            "*.h1.com,WILDCARD,h1,true,true,,,,critical\n"
        )
        mgr.import_bundle("hackerone", "H1App", str(pf), str(sf), "h1app")

        # Import bugcrowd
        pf2 = tmp_path / "p_bc.md"; pf2.write_text("# BC\n")
        sf2 = tmp_path / "s_bc.csv"
        sf2.write_text(
            "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,"
            "availability_requirement,confidentiality_requirement,integrity_requirement,max_severity\n"
            "*.bc.com,WILDCARD,bc,true,true,,,,critical\n"
        )
        mgr.import_bundle("bugcrowd", "BCApp", str(pf2), str(sf2), "bcapp")

        h1_only = mgr.list_bundles(provider="hackerone")
        assert len(h1_only) >= 1
        for b in h1_only:
            assert b["provider"] == "hackerone"


class TestShowBundle:
    """Tests for BundleManager.show_bundle()."""

    def test_show_bundle_returns_details(self, tmp_path: Path):
        """Show returns manifest info and scope counts."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")
        bundle_dir = _create_bundle_skeleton(tmp_path)

        # Compile so we have compiled status
        mgr.compile_bundle(bundle_dir)

        result = mgr.show_bundle(bundle_dir)
        assert result["bundle_id"] == "bbp-hackerone-testprogram-20260701-abc123"
        assert "manifest" in result
        assert "compile_status" in result
        # Should have scope info
        assert "allow_hosts" in result or "scope" in result


# ---------------------------------------------------------------------------
# 5. Preflight tests
# ---------------------------------------------------------------------------

REASON_ACTIVE_BUNDLE_MISSING = "active_bundle_missing"


class TestRunPreflight:
    """Tests for BundleManager.run_preflight()."""

    def test_run_preflight_bugbounty_with_scope_error(self):
        """mode=bugbounty + scope -> ValueError."""
        _skip_if_not_implemented()
        mgr = BundleManager()
        with pytest.raises(ValueError, match="--mode bugbounty requires"):
            mgr.run_preflight(mode="bugbounty", scope_opt="*.example.com")

    def test_run_preflight_bugbounty_with_program(self, tmp_path: Path):
        """mode=bugbounty + program -> resolved policy."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")
        bundle_dir = _create_bundle_skeleton(tmp_path)

        # Compile + activate so preflight can resolve
        mgr.compile_bundle(bundle_dir)
        mgr.activate_bundle_manager(bundle_dir)

        result = mgr.run_preflight(mode="bugbounty", program="testprogram")
        assert result["status"] == "ready"
        assert "policy" in result
        assert "bundle_id" in result

    def test_run_preflight_not_ready_bundle(self, tmp_path: Path):
        """Bundle with manual_review_required -> preflight error."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")
        bundle_dir = _create_blocking_review_bundle(tmp_path)

        # Compile (will be manual_review_required)
        compile_result = mgr.compile_bundle(bundle_dir)
        assert compile_result["compile_status"] == "manual_review_required"

        # This bundle can't activate, so preflight with explicit bundle_dir
        result = mgr.run_preflight(mode="bugbounty", bundle_dir=str(bundle_dir))
        assert result["status"] != "ready", f"Expected non-ready status, got {result}"

    def test_run_preflight_with_target_check(self, tmp_path: Path):
        """Target is checked against compiled policy."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")
        bundle_dir = _create_bundle_skeleton(tmp_path)

        mgr.compile_bundle(bundle_dir)
        mgr.activate_bundle_manager(bundle_dir)

        result = mgr.run_preflight(
            mode="bugbounty",
            program="testprogram",
            target="https://www.example.com/page",
        )
        # Should resolve policy and check target
        assert result["status"] == "ready"

    def test_run_preflight_bundle_id_program_mismatch(self, tmp_path: Path):
        """bundle_id resolves to 'testprogram' but program='wrong' -> error. (Fix 2)"""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")

        # Set up a minimal activated bundle
        program_dir = tmp_path / "workspace" / "programs" / "hackerone" / "testprogram"
        program_dir.mkdir(parents=True)

        policy = {
            "schema_version": 1, "compile_status": "ready",
            "bundle_id": "bbp-hackerone-testprogram-test",
            "policy_id": "bbp:hackerone:testprogram:test",
            "provider": "hackerone", "program_name": "TestProgram",
            "program_alias": "testprogram",
            "compiled_at_utc": "2026-07-01T08:00:00Z",
            "compiled_policy_hash": "sha256:test",
            "normalized_facts_hash": "sha256:test",
            "default_decision": "deny",
            "compatibility": {"min_reader_schema_version": 1,
                              "backward_compatible_with": [1]},
            "scope": {"allow_hosts": ["*.example.com"], "deny_hosts": [],
                      "allow_url_prefixes": [], "deny_url_prefixes": [],
                      "non_http_assets": []},
            "rules": {"phases": {}, "attack_classes": {}, "auth": {},
                      "budgets": {"requests_per_minute": 60}},
            "review_gate": {"manual_review_required": False,
                            "blocking_findings": []},
            "audit": {"source_hashes": {}, "compile_inputs": {},
                      "rule_origins": []},
        }
        yaml_bytes = yaml.dump(policy, sort_keys=True).encode()
        policy_hash = "sha256:" + hashlib.sha256(yaml_bytes).hexdigest()
        (program_dir / "compiled_guard_policy.yaml").write_bytes(yaml_bytes)
        (program_dir / "active_bundle.json").write_text(json.dumps({
            "provider": "hackerone", "program_alias": "testprogram",
            "bundle_id": "bbp-hackerone-testprogram-test",
            "policy_id": "bbp:hackerone:testprogram:test",
            "compiled_policy_path": "compiled_guard_policy.yaml",
            "compiled_policy_hash": policy_hash,
            "activated_at_utc": "2026-07-01T08:00:00Z",
        }))

        result = mgr.run_preflight(
            mode="bugbounty", program="wrongprogram",
            bundle_id="bbp-hackerone-testprogram-test",
        )
        assert result.get("error") is True
        assert result.get("status") == "error"
        assert "mismatch" in result.get("reason_code", "")


# ---------------------------------------------------------------------------
# 6. Rollback tests
# ---------------------------------------------------------------------------


class TestRollbackBundle:
    """Tests for BundleManager.rollback_bundle()."""

    def test_rollback_bundle(self, tmp_path: Path):
        """Activate bundle A, then bundle B, rollback to A -> active_bundle points to A."""
        _skip_if_not_implemented()
        mgr = BundleManager(workspace_root=tmp_path / "workspace")

        # Create and import bundle A using import_bundle (puts it in workspace)
        policy_a = tmp_path / "policy_a.md"
        policy_a.write_text("# App A\n\nDo not test social engineering.\n")
        scope_a = tmp_path / "scope_a.csv"
        scope_a.write_text(
            "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,"
            "availability_requirement,confidentiality_requirement,integrity_requirement,max_severity\n"
            "*.example.com,WILDCARD,test,true,true,,,,critical\n"
        )
        import_a = mgr.import_bundle(
            provider="hackerone", program_name="TestProgram",
            policy_path=str(policy_a), scope_path=str(scope_a),
            program_alias="testprogram",
        )
        bundle_a_dir = Path(import_a["bundle_dir"])
        bundle_a_id = import_a["bundle_id"]

        # Compile and activate A
        mgr.compile_bundle(bundle_a_dir)
        mgr.activate_bundle_manager(bundle_a_dir)

        # Import bundle B with a different captured_at_utc to get distinct bundle_id
        policy_b = tmp_path / "policy_b.md"
        policy_b.write_text("# App B\n\nDo not test social engineering.\n")
        scope_b = tmp_path / "scope_b.csv"
        scope_b.write_text(
            "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,"
            "availability_requirement,confidentiality_requirement,integrity_requirement,max_severity\n"
            "*.example.com,WILDCARD,test,true,true,,,,critical\n"
        )
        import_b = mgr.import_bundle(
            provider="hackerone", program_name="TestProgram",
            policy_path=str(policy_b), scope_path=str(scope_b),
            program_alias="testprogram",
            captured_at_utc="2026-07-02T00:00:01Z",
        )
        bundle_b_dir = Path(import_b["bundle_dir"])
        bundle_b_id = import_b["bundle_id"]
        assert bundle_b_id != bundle_a_id, f"Bundle IDs must differ: {bundle_a_id} vs {bundle_b_id}"

        # Compile and activate B
        mgr.compile_bundle(bundle_b_dir)
        mgr.activate_bundle_manager(bundle_b_dir)

        # Rollback to bundle A
        rollback_result = mgr.rollback_bundle("testprogram", bundle_a_id)
        assert rollback_result["status"] == "activated"
        assert rollback_result["bundle_id"] == bundle_a_id

        # Verify active_bundle.json now points to bundle A
        program_dir = mgr._resolve_program_dir("hackerone", "testprogram")
        active = json.loads((program_dir / "active_bundle.json").read_text())
        assert active["bundle_id"] == bundle_a_id
