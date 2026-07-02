"""
Unit tests for bundle_registry.py — BundleRegistry class.

Covers:
- resolve_storage_path (named, bundle_id, ephemeral)
- verify_active_mapping_integrity (valid, missing json, missing policy, hash mismatch, wrong status)
- scan_for_credentials (clean, api_key found, env var not flagged, password found)
- validate_bundle_import (clean, missing file, secret in overrides)
- prune_ephemeral_bundles (dry_run, real prune)
- list_orphaned_bundles
- get_bundle_retention_info
- atomic_activate (writes, missing field, overwrites)
"""

import json
import os
import shutil
import time
from pathlib import Path

import pytest
import yaml

from src.core.security.bundle_registry import BundleRegistry

FIXTURES_DIR = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "bugbounty_guard"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_bundle_dir(tmp_path: Path, provider: str, program_alias: str) -> Path:
    """Create a program bundle directory inside tmp_path."""
    bundle_dir = tmp_path / "programs" / provider / program_alias
    bundle_dir.mkdir(parents=True, exist_ok=True)
    return bundle_dir


def _write_active_bundle(bundle_dir: Path, **overrides) -> None:
    """Write an active_bundle.json into bundle_dir."""
    data = {
        "provider": "hackerone",
        "program_alias": "tiktok",
        "bundle_id": "bbp-test-001",
        "policy_id": "bbp:hackerone:tiktok:001",
        "compiled_policy_path": "compiled_guard_policy.yaml",
        "compiled_policy_hash": "sha256:dummy",
        "activated_at_utc": "2026-07-01T08:10:00Z",
    }
    data.update(overrides)
    (bundle_dir / "active_bundle.json").write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _write_compiled_policy(policy_path: Path, **overrides) -> str:
    """Write a compiled_guard_policy.yaml and return its sha256 hash."""
    import hashlib

    policy_data = {
        "schema_version": 1,
        "compile_status": "ready",
        "bundle_id": "bbp-test-001",
        "policy_id": "bbp:hackerone:tiktok:001",
        "provider": "hackerone",
        "program_name": "Test",
        "program_alias": "tiktok",
        "compiled_at_utc": "2026-07-01T08:10:00Z",
        "normalized_facts_hash": "sha256:abcd",
        "compiled_policy_hash": "sha256:abcd",
        "default_decision": "deny",
        "compatibility": {
            "min_reader_schema_version": 1,
            "backward_compatible_with": [1],
        },
        "scope": {"allow_hosts": ["example.com"]},
        "rules": {"phases": {}, "attack_classes": {}, "auth": {}, "budgets": {}},
        "review_gate": {"manual_review_required": False, "blocking_findings": []},
        "audit": {"source_hashes": {}, "compile_inputs": {}, "rule_origins": []},
    }
    policy_data.update(overrides)

    yaml_bytes = yaml.dump(policy_data, sort_keys=True, default_flow_style=False).encode(
        "utf-8"
    )
    policy_path.write_bytes(yaml_bytes)
    return f"sha256:{hashlib.sha256(yaml_bytes).hexdigest()}"


def _setup_valid_bundle(tmp_path: Path, provider: str, program_alias: str) -> tuple:
    """Create a valid bundle with matching active_bundle.json and policy.
    Returns (bundle_dir, policy_hash).
    """
    bundle_dir = _make_bundle_dir(tmp_path, provider, program_alias)
    policy_path = bundle_dir / "compiled_guard_policy.yaml"
    policy_hash = _write_compiled_policy(policy_path)
    _write_active_bundle(
        bundle_dir,
        provider=provider,
        program_alias=program_alias,
        compiled_policy_hash=policy_hash,
    )
    return bundle_dir, policy_hash


# ---------------------------------------------------------------------------
# Tests: resolve_storage_path
# ---------------------------------------------------------------------------


class TestResolveStoragePath:
    def test_resolve_storage_path_named(self, tmp_path: Path):
        """Verify path for provider/program_alias."""
        registry = BundleRegistry(workspace_root=str(tmp_path))
        result = registry.resolve_storage_path("hackerone", "tiktok")
        assert result == tmp_path / "programs" / "hackerone" / "tiktok"

    def test_resolve_storage_path_with_bundle_id(self, tmp_path: Path):
        """Path includes bundles/{bundle_id}."""
        registry = BundleRegistry(workspace_root=str(tmp_path))
        result = registry.resolve_storage_path("bugcrowd", "fireblocks", bundle_id="b1")
        assert (
            result
            == tmp_path / "programs" / "bugcrowd" / "fireblocks" / "bundles" / "b1"
        )

    def test_resolve_storage_path_ephemeral(self, tmp_path: Path):
        """Path for _ephemeral/{bundle_id}."""
        registry = BundleRegistry(workspace_root=str(tmp_path))
        result = registry.resolve_storage_path("", "", bundle_id="ephemeral-99")
        assert result == tmp_path / "_ephemeral" / "ephemeral-99"


# ---------------------------------------------------------------------------
# Tests: verify_active_mapping_integrity
# ---------------------------------------------------------------------------


class TestVerifyActiveMappingIntegrity:
    def test_verify_active_mapping_valid_tiktok_fixture(self, tmp_path: Path):
        """Uses real TikTok fixture files in a valid layout -> valid=True."""
        bundle_dir = _make_bundle_dir(tmp_path, "hackerone", "tiktok")

        # Copy fixture files
        tiktok_fixture = FIXTURES_DIR / "tiktok"
        shutil.copy2(tiktok_fixture / "active_bundle.json", bundle_dir)
        shutil.copy2(tiktok_fixture / "compiled_guard_policy.yaml", bundle_dir)

        registry = BundleRegistry(workspace_root=str(tmp_path))
        result = registry.verify_active_mapping_integrity("hackerone", "tiktok")
        assert result["valid"] is True, f"Expected valid=True, got: {result}"
        assert len(result["checks"]) >= 7

    def test_verify_active_mapping_valid_fireblocks_fixture(self, tmp_path: Path):
        """Uses real Fireblocks fixture files in a valid layout -> valid=True."""
        bundle_dir = _make_bundle_dir(tmp_path, "bugcrowd", "fireblocks")

        # Copy fixture files
        fb_fixture = FIXTURES_DIR / "fireblocks"
        shutil.copy2(fb_fixture / "active_bundle.json", bundle_dir)
        shutil.copy2(fb_fixture / "compiled_guard_policy.yaml", bundle_dir)

        registry = BundleRegistry(workspace_root=str(tmp_path))
        result = registry.verify_active_mapping_integrity("bugcrowd", "fireblocks")
        assert result["valid"] is True, f"Expected valid=True, got: {result}"

    def test_verify_active_mapping_missing_active_json(self, tmp_path: Path):
        """No active_bundle.json -> valid=False."""
        bundle_dir = _make_bundle_dir(tmp_path, "hackerone", "tiktok")
        # Directory exists but no active_bundle.json
        registry = BundleRegistry(workspace_root=str(tmp_path))
        result = registry.verify_active_mapping_integrity("hackerone", "tiktok")
        assert result["valid"] is False

    def test_verify_active_mapping_missing_policy_file(self, tmp_path: Path):
        """active_bundle.json points to missing file -> valid=False."""
        bundle_dir = _make_bundle_dir(tmp_path, "hackerone", "tiktok")
        _write_active_bundle(bundle_dir)
        # No compiled_guard_policy.yaml written
        registry = BundleRegistry(workspace_root=str(tmp_path))
        result = registry.verify_active_mapping_integrity("hackerone", "tiktok")
        assert result["valid"] is False

    def test_verify_active_mapping_hash_mismatch(self, tmp_path: Path):
        """Hash doesn't match -> valid=False."""
        bundle_dir = _make_bundle_dir(tmp_path, "hackerone", "tiktok")
        policy_path = bundle_dir / "compiled_guard_policy.yaml"
        _write_compiled_policy(policy_path)
        _write_active_bundle(
            bundle_dir, compiled_policy_hash="sha256:wrong-hash-value"
        )
        registry = BundleRegistry(workspace_root=str(tmp_path))
        result = registry.verify_active_mapping_integrity("hackerone", "tiktok")
        assert result["valid"] is False

    def test_verify_active_mapping_wrong_status(self, tmp_path: Path):
        """Policy compile_status != ready -> valid=False."""
        bundle_dir = _make_bundle_dir(tmp_path, "hackerone", "tiktok")
        policy_path = bundle_dir / "compiled_guard_policy.yaml"
        policy_hash = _write_compiled_policy(policy_path, compile_status="manual_review_required")
        _write_active_bundle(bundle_dir, compiled_policy_hash=policy_hash)
        registry = BundleRegistry(workspace_root=str(tmp_path))
        result = registry.verify_active_mapping_integrity("hackerone", "tiktok")
        assert result["valid"] is False

    def test_verify_active_mapping_bundle_id_mismatch(self, tmp_path: Path):
        """Policy bundle_id doesn't match active_bundle.json -> valid=False."""
        bundle_dir = _make_bundle_dir(tmp_path, "hackerone", "tiktok")
        policy_path = bundle_dir / "compiled_guard_policy.yaml"
        policy_hash = _write_compiled_policy(policy_path, bundle_id="different-bundle-id")
        _write_active_bundle(
            bundle_dir,
            bundle_id="bbp-test-001",
            compiled_policy_hash=policy_hash,
        )
        registry = BundleRegistry(workspace_root=str(tmp_path))
        result = registry.verify_active_mapping_integrity("hackerone", "tiktok")
        assert result["valid"] is False

    def test_verify_active_mapping_policy_id_mismatch(self, tmp_path: Path):
        """Policy policy_id doesn't match active_bundle.json -> valid=False."""
        bundle_dir = _make_bundle_dir(tmp_path, "hackerone", "tiktok")
        policy_path = bundle_dir / "compiled_guard_policy.yaml"
        policy_hash = _write_compiled_policy(policy_path, policy_id="different-policy-id")
        _write_active_bundle(
            bundle_dir,
            policy_id="bbp:hackerone:tiktok:001",
            compiled_policy_hash=policy_hash,
        )
        registry = BundleRegistry(workspace_root=str(tmp_path))
        result = registry.verify_active_mapping_integrity("hackerone", "tiktok")
        assert result["valid"] is False


# ---------------------------------------------------------------------------
# Tests: scan_for_credentials
# ---------------------------------------------------------------------------


class TestScanForCredentials:
    def test_scan_for_credentials_clean(self):
        """No secrets -> empty list."""
        registry = BundleRegistry()
        data = {
            "overrides": {
                "auth": {
                    "allowed_email_domains": ["example.com"],
                    "credential_profile_ref": "sandbox",
                }
            }
        }
        findings = registry.scan_for_credentials(data)
        assert findings == []

    def test_scan_for_credentials_api_key_found(self):
        """dict has api_key with real value -> flagged."""
        registry = BundleRegistry()
        data = {"auth": {"api_key": "sk-live-1234567890abcdef1234567890abcdef"}}
        findings = registry.scan_for_credentials(data)
        assert len(findings) >= 1
        assert any("api_key" in f["path"] for f in findings)

    def test_scan_for_credentials_env_var_not_flagged(self):
        """token_env reference is not flagged."""
        registry = BundleRegistry()
        data = {"auth": {"token_env": "FIREBLOCKS_TEST_TOKEN"}}
        findings = registry.scan_for_credentials(data)
        assert findings == []

    def test_scan_for_credentials_dollar_env_not_flagged(self):
        """$VAR-style env reference is not flagged."""
        registry = BundleRegistry()
        data = {"auth": {"api_key": "$MY_API_KEY"}}
        findings = registry.scan_for_credentials(data)
        assert findings == []

    def test_scan_for_credentials_password_found(self):
        """password= with real value -> flagged."""
        registry = BundleRegistry()
        data = {
            "overrides": {
                "credentials": {"password": "SuperSecretPass123!"}
            }
        }
        findings = registry.scan_for_credentials(data)
        assert len(findings) >= 1

    def test_scan_for_credentials_token_found(self):
        """token value as real credential -> flagged."""
        registry = BundleRegistry()
        data = {"config": {"token": "ghp_12345678901234567890123456789012"}}
        findings = registry.scan_for_credentials(data)
        assert len(findings) >= 1

    def test_scan_for_credentials_secret_found(self):
        """secret key with real value -> flagged."""
        registry = BundleRegistry()
        data = {
            "aws": {
                "secret_access_key": "wJalrXUtTHISISAREA/SECRETKEY/EXAMPLEKEY"
            }
        }
        findings = registry.scan_for_credentials(data)
        assert len(findings) >= 1

    def test_scan_for_credentials_nested_deep(self):
        """Credentials nested 3 levels deep are still detected."""
        registry = BundleRegistry()
        data = {
            "level1": {
                "level2": {
                    "level3": {"api_key": "sk-this_is_a_deeply_nested_secret_value_12345"}
                }
            }
        }
        findings = registry.scan_for_credentials(data)
        assert len(findings) >= 1
        assert "level1.level2.level3.api_key" == findings[0]["path"]

    def test_scan_for_credentials_short_value_not_flagged(self):
        """Short value (< 10 chars) that would match key name is not flagged."""
        registry = BundleRegistry()
        data = {"auth": {"password": "short"}}
        findings = registry.scan_for_credentials(data)
        assert findings == []

    def test_scan_for_credentials_list_values_scanned(self):
        """Values inside lists are scanned too."""
        registry = BundleRegistry()
        data = {
            "tokens": [
                "sk-this-is-a-token-inside-a-list-abc123",
                "$LEGIT_ENV_VAR",
            ]
        }
        findings = registry.scan_for_credentials(data)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Tests: validate_bundle_import
# ---------------------------------------------------------------------------


class TestValidateBundleImport:
    def test_validate_bundle_import_clean(self, tmp_path: Path):
        """Clean bundle with all required files -> valid=True."""
        import_dir = tmp_path / "clean_bundle"
        import_dir.mkdir()

        # Create required files
        (import_dir / "source_manifest.yaml").write_text(
            yaml.dump({"provider": "hackerone", "program": "test"})
        )
        (import_dir / "policy.md").write_text("# Policy\nTest policy document.")
        (import_dir / "review_findings.yaml").write_text(
            yaml.dump({"review_findings": []})
        )
        (import_dir / "overrides.yaml").write_text(
            yaml.dump({"overrides": {}})
        )
        (import_dir / "scope.csv").write_text("domain,submission_allowed\nexample.com,true\n")

        registry = BundleRegistry()
        result = registry.validate_bundle_import(import_dir)
        assert result["valid"] is True, f"Expected valid=True, got: {result}"

    def test_validate_bundle_import_missing_file(self, tmp_path: Path):
        """Missing policy.md -> errors."""
        import_dir = tmp_path / "missing_policy"
        import_dir.mkdir()

        (import_dir / "source_manifest.yaml").write_text("provider: test\n")
        (import_dir / "review_findings.yaml").write_text(
            yaml.dump({"review_findings": []})
        )
        (import_dir / "overrides.yaml").write_text(
            yaml.dump({"overrides": {}})
        )
        (import_dir / "scope.txt").write_text("example.com")

        registry = BundleRegistry()
        result = registry.validate_bundle_import(import_dir)
        assert result["valid"] is False
        assert len(result["errors"]) >= 1

    def test_validate_bundle_import_secret_in_overrides(self, tmp_path: Path):
        """Secret in overrides.yaml -> errors."""
        import_dir = tmp_path / "secret_bundle"
        import_dir.mkdir()

        (import_dir / "source_manifest.yaml").write_text("provider: test\n")
        (import_dir / "policy.md").write_text("# Policy")
        (import_dir / "review_findings.yaml").write_text(
            yaml.dump({"review_findings": []})
        )
        (import_dir / "overrides.yaml").write_text(
            yaml.dump({"overrides": {"auth": {"api_key": "sk-live-secret-value-1234567890abcdef"}}})
        )
        (import_dir / "scope.csv").write_text("example.com")

        registry = BundleRegistry()
        result = registry.validate_bundle_import(import_dir)
        assert result["valid"] is False
        assert len(result["errors"]) >= 1

    def test_validate_bundle_import_secret_in_review_findings(self, tmp_path: Path):
        """Secret in review_findings.yaml -> errors."""
        import_dir = tmp_path / "secret_review_bundle"
        import_dir.mkdir()

        (import_dir / "source_manifest.yaml").write_text("provider: test\n")
        (import_dir / "policy.md").write_text("# Policy")
        (import_dir / "review_findings.yaml").write_text(
            yaml.dump({
                "review_findings": [
                    {
                        "finding_id": "F-001",
                        "note": "Credential leaked: token=ghp_secret12345678901234567890",
                    }
                ]
            })
        )
        (import_dir / "overrides.yaml").write_text(
            yaml.dump({"overrides": {}})
        )
        (import_dir / "scope.csv").write_text("example.com")

        registry = BundleRegistry()
        result = registry.validate_bundle_import(import_dir)
        assert result["valid"] is False
        assert len(result["errors"]) >= 1

    def test_validate_bundle_import_missing_scope_file(self, tmp_path: Path):
        """No scope file -> errors."""
        import_dir = tmp_path / "missing_scope"
        import_dir.mkdir()

        (import_dir / "source_manifest.yaml").write_text("provider: test\n")
        (import_dir / "policy.md").write_text("# Policy")
        (import_dir / "review_findings.yaml").write_text(
            yaml.dump({"review_findings": []})
        )
        (import_dir / "overrides.yaml").write_text(
            yaml.dump({"overrides": {}})
        )
        # No scope file

        registry = BundleRegistry()
        result = registry.validate_bundle_import(import_dir)
        assert result["valid"] is False
        assert len(result["errors"]) >= 1

    def test_validate_bundle_import_rejects_secret_in_policy(self, tmp_path: Path):
        """validate_bundle_import flags secret in policy.md and returns errors."""
        registry = BundleRegistry(str(tmp_path / "bugbounty"))
        bundle_dir = tmp_path / "testbundle"
        bundle_dir.mkdir()

        manifest = {
            "schema_version": 1,
            "provider": "hackerone",
            "program_name": "Test",
            "captured_at_utc": "2026-01-01T00:00:00Z",
            "bundle_id": "bbp-test",
            "policy_path": "policy.md",
            "scope_sources": [{"kind": "hackerone_csv", "path": "scope_assets.csv"}],
        }
        (bundle_dir / "source_manifest.yaml").write_text(yaml.dump(manifest))
        (bundle_dir / "policy.md").write_text(
            "# Program\n\nToken: ghp_abc12345678901234567890123456"
        )
        (bundle_dir / "review_findings.yaml").write_text("review_findings: []")
        (bundle_dir / "overrides.yaml").write_text("overrides: {}")
        (bundle_dir / "scope_assets.csv").write_text(
            "identifier,asset_type,instruction,eligible_for_bounty,"
            "eligible_for_submission\n"
            "*.example.com,WILDCARD,,true,true\n"
        )

        result = registry.validate_bundle_import(bundle_dir)
        assert result["valid"] is False
        assert len(result["errors"]) >= 1
        assert any("policy.md" in e for e in result["errors"])

    def test_validate_bundle_import_rejects_secret_in_scope_csv(self, tmp_path: Path):
        """validate_bundle_import flags secret in scope_assets.csv."""
        registry = BundleRegistry(str(tmp_path / "bugbounty"))
        bundle_dir = tmp_path / "testbundle"
        bundle_dir.mkdir()

        manifest = {
            "schema_version": 1,
            "provider": "hackerone",
            "program_name": "Test",
            "captured_at_utc": "2026-01-01T00:00:00Z",
            "bundle_id": "bbp-test",
            "policy_path": "policy.md",
            "scope_sources": [{"kind": "hackerone_csv", "path": "scope_assets.csv"}],
        }
        (bundle_dir / "source_manifest.yaml").write_text(yaml.dump(manifest))
        (bundle_dir / "policy.md").write_text("# Clean program\n\n## Targets\n- example.com")
        # CSV with embedded secret in instruction column
        (bundle_dir / "scope_assets.csv").write_text(
            "identifier,asset_type,instruction,eligible_for_bounty,"
            "eligible_for_submission\n"
            "*.example.com,WILDCARD,api key: abc123456789012345678901234567890,true,true\n"
        )
        (bundle_dir / "review_findings.yaml").write_text("review_findings: []")
        (bundle_dir / "overrides.yaml").write_text("overrides: {}")

        result = registry.validate_bundle_import(bundle_dir)
        assert result["valid"] is False
        assert len(result["errors"]) >= 1
        assert any("scope_assets.csv" in e for e in result["errors"])

    def test_validate_bundle_import_clean_policy_passes(self, tmp_path: Path):
        """Clean policy with no secrets in any file passes validation."""
        registry = BundleRegistry(str(tmp_path / "bugbounty"))
        bundle_dir = tmp_path / "cleanbundle"
        bundle_dir.mkdir()

        manifest = {
            "schema_version": 1,
            "provider": "hackerone",
            "program_name": "Test",
            "captured_at_utc": "2026-01-01T00:00:00Z",
            "bundle_id": "bbp-test",
            "policy_path": "policy.md",
            "scope_sources": [{"kind": "hackerone_csv", "path": "scope_assets.csv"}],
        }
        (bundle_dir / "source_manifest.yaml").write_text(yaml.dump(manifest))
        (bundle_dir / "policy.md").write_text(
            "# Clean Program\n\n## Targets\n- example.com\n## Notes\nFocus on auth bugs."
        )
        (bundle_dir / "scope_assets.csv").write_text(
            "identifier,asset_type,instruction,eligible_for_bounty,"
            "eligible_for_submission\n"
            "*.example.com,WILDCARD,Focus on auth area,true,true\n"
        )
        (bundle_dir / "review_findings.yaml").write_text("review_findings: []")
        (bundle_dir / "overrides.yaml").write_text("overrides: {}")

        result = registry.validate_bundle_import(bundle_dir)
        assert result["valid"] is True
        assert len(result["errors"]) == 0


# ---------------------------------------------------------------------------
# Tests: prune_ephemeral_bundles
# ---------------------------------------------------------------------------


class TestPruneEphemeralBundles:
    def test_prune_ephemeral_dry_run(self, tmp_path: Path):
        """Dry run doesn't actually delete."""
        ws = tmp_path / "bb"
        ws.mkdir()
        ephemeral_dir = ws / "_ephemeral"
        ephemeral_dir.mkdir()

        # Create an old ephemeral bundle dir
        old_bundle = ephemeral_dir / "old-bundle"
        old_bundle.mkdir()
        (old_bundle / "data.txt").write_text("old")

        # Set mtime to 8 days ago
        old_time = time.time() - 8 * 86400
        os.utime(old_bundle, (old_time, old_time))

        # Create a new ephemeral bundle
        new_bundle = ephemeral_dir / "new-bundle"
        new_bundle.mkdir()
        (new_bundle / "data.txt").write_text("new")

        registry = BundleRegistry(workspace_root=str(ws))
        result = registry.prune_ephemeral_bundles(dry_run=True)
        assert result["dry_run"] is True
        assert result["pruned"] >= 1
        # Old bundle should still exist
        assert old_bundle.exists()

    def test_prune_ephemeral_bundles(self, tmp_path: Path):
        """Prune removes only old ephemeral bundles."""
        ws = tmp_path / "bb"
        ws.mkdir()
        ephemeral_dir = ws / "_ephemeral"
        ephemeral_dir.mkdir()

        # Create old bundles (8 days ago)
        for i in range(3):
            b = ephemeral_dir / f"old-bundle-{i}"
            b.mkdir()
            (b / "data.txt").write_text(f"old-{i}")
            old_time = time.time() - 8 * 86400
            os.utime(b, (old_time, old_time))

        # Create new bundles (1 day ago)
        for i in range(2):
            b = ephemeral_dir / f"new-bundle-{i}"
            b.mkdir()
            (b / "data.txt").write_text(f"new-{i}")
            new_time = time.time() - 1 * 86400
            os.utime(b, (new_time, new_time))

        registry = BundleRegistry(workspace_root=str(ws))
        result = registry.prune_ephemeral_bundles(dry_run=False)
        assert result["dry_run"] is False
        assert result["pruned"] == 3
        assert result["remaining"] == 2

        # Verify old bundles are gone, new bundles remain
        assert not ephemeral_dir.joinpath("old-bundle-0").exists()
        assert not ephemeral_dir.joinpath("old-bundle-1").exists()
        assert not ephemeral_dir.joinpath("old-bundle-2").exists()
        assert ephemeral_dir.joinpath("new-bundle-0").exists()
        assert ephemeral_dir.joinpath("new-bundle-1").exists()

    def test_prune_ephemeral_no_ephemeral_dir(self, tmp_path: Path):
        """No _ephemeral dir exists -> empty result."""
        ws = tmp_path / "bb"
        ws.mkdir()
        registry = BundleRegistry(workspace_root=str(ws))
        result = registry.prune_ephemeral_bundles(dry_run=False)
        assert result["pruned"] == 0
        assert result["remaining"] == 0


# ---------------------------------------------------------------------------
# Tests: list_orphaned_bundles
# ---------------------------------------------------------------------------


class TestListOrphanedBundles:
    def test_list_orphaned_bundles_none(self, tmp_path: Path):
        """Clean workspace -> no orphans."""
        bundle_dir, _ = _setup_valid_bundle(tmp_path, "hackerone", "tiktok")
        registry = BundleRegistry(workspace_root=str(tmp_path))
        orphans = registry.list_orphaned_bundles()
        assert orphans == []

    def test_list_orphaned_bundles_missing_active_json(self, tmp_path: Path):
        """Bundle dir exists but no active_bundle.json -> orphan."""
        bundle_dir = _make_bundle_dir(tmp_path, "hackerone", "noactive")
        bundle_dir.mkdir(parents=True, exist_ok=True)
        # No active_bundle.json
        registry = BundleRegistry(workspace_root=str(tmp_path))
        orphans = registry.list_orphaned_bundles()
        assert len(orphans) >= 1

    def test_list_orphaned_bundles_missing_referenced_policy(self, tmp_path: Path):
        """active_bundle.json exists but referenced policy missing -> orphan."""
        bundle_dir = _make_bundle_dir(tmp_path, "hackerone", "broken")
        _write_active_bundle(bundle_dir)
        # No compiled_guard_policy.yaml
        registry = BundleRegistry(workspace_root=str(tmp_path))
        orphans = registry.list_orphaned_bundles()
        assert len(orphans) >= 1

    def test_list_orphaned_bundles_corrupt_json(self, tmp_path: Path):
        """active_bundle.json is corrupt -> orphan."""
        bundle_dir = _make_bundle_dir(tmp_path, "hackerone", "corrupt")
        (bundle_dir / "active_bundle.json").write_text("not valid json {{{")
        registry = BundleRegistry(workspace_root=str(tmp_path))
        orphans = registry.list_orphaned_bundles()
        assert len(orphans) >= 1


# ---------------------------------------------------------------------------
# Tests: get_bundle_retention_info
# ---------------------------------------------------------------------------


class TestGetBundleRetentionInfo:
    def test_get_bundle_retention_info(self, tmp_path: Path):
        """Returns correct counts."""
        ws = tmp_path / "bb"
        ws.mkdir()

        # Create named bundles area
        programs_dir = ws / "programs" / "hackerone" / "tiktok"
        programs_dir.mkdir(parents=True)

        # Create bundles/ subdir with 3 bundle versions
        for i in range(3):
            (programs_dir / "bundles" / f"bundle-v{i}").mkdir(parents=True)

        # Create active_bundle.json
        _write_active_bundle(programs_dir)

        # Create ephemeral bundles
        ephemeral_dir = ws / "_ephemeral"
        ephemeral_dir.mkdir()
        for i in range(2):
            (ephemeral_dir / f"eph-{i}").mkdir()

        registry = BundleRegistry(workspace_root=str(ws))
        info = registry.get_bundle_retention_info("hackerone", "tiktok")
        assert info["total_bundles"] == 3
        assert info["active_bundle_id"] == "bbp-test-001"
        assert info["superseded_count"] >= 0
        assert info["ephemeral_count"] == 2

    def test_get_bundle_retention_info_empty(self, tmp_path: Path):
        """No bundles -> all zeros."""
        ws = tmp_path / "bb"
        ws.mkdir()
        _make_bundle_dir(tmp_path, "hackerone", "empty")
        registry = BundleRegistry(workspace_root=str(ws))
        info = registry.get_bundle_retention_info("hackerone", "empty")
        assert info["total_bundles"] == 0
        assert info["active_bundle_id"] is None
        assert info["ephemeral_count"] == 0


# ---------------------------------------------------------------------------
# Tests: atomic_activate
# ---------------------------------------------------------------------------


class TestAtomicActivate:
    def test_atomic_activate_writes_active_bundle_json(self, tmp_path: Path):
        """File created with correct content."""
        registry = BundleRegistry(workspace_root=str(tmp_path))
        registry.atomic_activate(
            provider="hackerone",
            program_alias="tiktok",
            bundle_id="bbp-test-002",
            policy_id="bbp:hackerone:tiktok:002",
            compiled_policy_hash="sha256:abc123",
            compiled_policy_path="compiled_guard_policy.yaml",
        )

        # Verify file exists at the resolved storage path
        expected_dir = tmp_path / "programs" / "hackerone" / "tiktok"
        active_path = expected_dir / "active_bundle.json"
        assert active_path.exists()
        content = json.loads(active_path.read_text(encoding="utf-8"))
        assert content["provider"] == "hackerone"
        assert content["program_alias"] == "tiktok"
        assert content["bundle_id"] == "bbp-test-002"
        assert content["policy_id"] == "bbp:hackerone:tiktok:002"
        assert content["compiled_policy_hash"] == "sha256:abc123"
        assert content["compiled_policy_path"] == "compiled_guard_policy.yaml"
        assert "activated_at_utc" in content
        # Verify no .tmp file left behind
        assert not (expected_dir / "active_bundle.json.tmp").exists()

    def test_atomic_activate_missing_field_raises(self, tmp_path: Path):
        """Missing required field -> ValueError."""
        bundle_dir = tmp_path / "activate_missing"
        bundle_dir.mkdir()

        registry = BundleRegistry(workspace_root=str(tmp_path))
        with pytest.raises(ValueError, match="provider"):
            registry.atomic_activate(
                provider="",
                program_alias="tiktok",
                bundle_id="bbp-test-003",
                policy_id="bbp:hackerone:tiktok:003",
                compiled_policy_hash="sha256:abc",
                compiled_policy_path="compiled_guard_policy.yaml",
            )

    def test_atomic_activate_overwrites_existing(self, tmp_path: Path):
        """Overwrites existing active_bundle.json."""
        expected_dir = tmp_path / "programs" / "hackerone" / "tiktok"
        expected_dir.mkdir(parents=True)

        # Write initial active_bundle.json manually at the resolved path
        initial = {
            "provider": "old",
            "program_alias": "old",
            "bundle_id": "old-bundle",
            "policy_id": "old-policy",
            "compiled_policy_path": "compiled_guard_policy.yaml",
            "compiled_policy_hash": "sha256:old",
            "activated_at_utc": "2026-01-01T00:00:00Z",
        }
        (expected_dir / "active_bundle.json").write_text(
            json.dumps(initial, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        registry = BundleRegistry(workspace_root=str(tmp_path))
        registry.atomic_activate(
            provider="hackerone",
            program_alias="tiktok",
            bundle_id="bbp-new-bundle",
            policy_id="bbp:hackerone:tiktok:new",
            compiled_policy_hash="sha256:new",
            compiled_policy_path="compiled_guard_policy.yaml",
        )

        content = json.loads(
            (expected_dir / "active_bundle.json").read_text(encoding="utf-8")
        )
        assert content["provider"] == "hackerone"
        assert content["bundle_id"] == "bbp-new-bundle"
        assert "activated_at_utc" in content

    def test_atomic_activate_creates_parent_dirs(self, tmp_path: Path):
        """Missing parent directories are created."""
        bundle_dir = tmp_path / "deeply" / "nested" / "programs" / "hackerone" / "tiktok"

        registry = BundleRegistry(workspace_root=str(tmp_path / "deeply" / "nested"))
        registry.atomic_activate(
            provider="hackerone",
            program_alias="tiktok",
            bundle_id="bbp-test-dirs",
            policy_id="bbp:hackerone:tiktok:dirs",
            compiled_policy_hash="sha256:dirs",
            compiled_policy_path="compiled_guard_policy.yaml",
        )

        assert (bundle_dir / "active_bundle.json").exists()
