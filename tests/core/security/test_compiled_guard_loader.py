"""
Unit tests for compiled_guard_loader.py.

Covers:
- Active bundle normal load
- active_bundle.json missing -> fail-closed
- compiled_guard_policy.yaml missing -> fail-closed
- Hash mismatch -> fail-closed
- compile_status != ready -> fail-closed
- Schema unsupported -> fail-closed
- Program alias mismatch -> fail-closed
"""

import json
import os
from pathlib import Path

import pytest

from src.core.security.compiled_guard_loader import (
    GuardLoadError,
    LoadedGuardPolicy,
    REASON_ACTIVE_BUNDLE_MISSING,
    REASON_POLICY_INTEGRITY_ERROR,
    REASON_POLICY_NOT_READY,
    REASON_POLICY_SCHEMA_UNSUPPORTED,
    REASON_POLICY_UNAVAILABLE,
    REASON_BUNDLE_PROGRAM_MISMATCH,
    load_active_policy_from_bundle_dir,
)

FIXTURES_DIR = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "bugbounty_guard"


# ---------------------------------------------------------------------------
# Normal load
# ---------------------------------------------------------------------------

class TestLoadActivePolicyNormal:
    def test_load_tiktok_bundle(self):
        """TikTok active bundle loads successfully with valid compiled policy."""
        bundle_dir = FIXTURES_DIR / "tiktok"
        result = load_active_policy_from_bundle_dir(bundle_dir)

        assert isinstance(result, LoadedGuardPolicy)
        assert result.bundle_id == "bbp-hackerone-tiktok-2026-07-01T07:38:38Z-ab12cd34"
        assert result.policy_id == "bbp:hackerone:tiktok:2026-07-01T07:38:38Z"
        assert result.provider == "hackerone"
        assert result.program_name == "TikTok"
        assert result.program_alias == "tiktok"
        assert result.compile_status == "ready"
        assert result.raw_policy.get("scope", {}).get("allow_hosts") == ["*.tiktok.com"]

    def test_load_fireblocks_bundle(self):
        """Fireblocks active bundle loads successfully with valid compiled policy."""
        bundle_dir = FIXTURES_DIR / "fireblocks"
        result = load_active_policy_from_bundle_dir(bundle_dir)

        assert isinstance(result, LoadedGuardPolicy)
        assert result.bundle_id == "bbp-bugcrowd-fireblocks-2026-02-12T13:49:31Z-ef56aa01"
        assert result.policy_id == "bbp:bugcrowd:fireblocks:2026-02-12T13:49:31Z"
        assert result.provider == "bugcrowd"
        assert result.program_name == "Fireblocks"
        assert result.program_alias == "fireblocks"
        assert result.compile_status == "ready"

    def test_load_tiktok_with_program_alias(self):
        """Load with expected_program validation passes."""
        bundle_dir = FIXTURES_DIR / "tiktok"
        result = load_active_policy_from_bundle_dir(bundle_dir, expected_program="tiktok")
        assert isinstance(result, LoadedGuardPolicy)

    def test_load_fireblocks_with_program_alias(self):
        """Load with expected_program validation passes."""
        bundle_dir = FIXTURES_DIR / "fireblocks"
        result = load_active_policy_from_bundle_dir(bundle_dir, expected_program="fireblocks")
        assert isinstance(result, LoadedGuardPolicy)


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------

class TestLoadActivePolicyFailures:
    def test_bundle_dir_missing(self):
        """Non-existent directory returns fail-closed error."""
        result = load_active_policy_from_bundle_dir("/nonexistent/bundle/dir")
        assert isinstance(result, GuardLoadError)
        assert result.reason_code == REASON_ACTIVE_BUNDLE_MISSING

    def test_active_bundle_json_missing(self, tmp_path: Path):
        """Directory without active_bundle.json returns fail-closed."""
        bundle_dir = tmp_path / "no_active_json"
        bundle_dir.mkdir()
        result = load_active_policy_from_bundle_dir(bundle_dir)
        assert isinstance(result, GuardLoadError)
        assert result.reason_code == REASON_ACTIVE_BUNDLE_MISSING

    def test_schema_version_above_supported(self, tmp_path: Path):
        """schema_version=999 > supported_reader_version=1 -> fail-closed."""
        bundle_dir = tmp_path / "schema_999"
        bundle_dir.mkdir()

        import hashlib
        policy_content = (
            "schema_version: 999\n"
            "compile_status: ready\n"
            "bundle_id: bbp-test-123\n"
            "policy_id: bbp:test:1\n"
            "compatibility:\n"
            "  min_reader_schema_version: 1\n"
            "  backward_compatible_with:\n"
            "    - 1\n"
            "scope:\n  allow_hosts: [example.com]\n"
        )
        policy_path = bundle_dir / "compiled_guard_policy.yaml"
        policy_path.write_text(policy_content)
        actual_hash = f"sha256:{hashlib.sha256(policy_path.read_bytes()).hexdigest()}"

        active_json = bundle_dir / "active_bundle.json"
        active_json.write_text(json.dumps({
            "provider": "hackerone",
            "program_alias": "test",
            "bundle_id": "bbp-test-123",
            "policy_id": "bbp:test:1",
            "compiled_policy_path": "compiled_guard_policy.yaml",
            "compiled_policy_hash": actual_hash,
        }))
        result = load_active_policy_from_bundle_dir(bundle_dir)
        assert isinstance(result, GuardLoadError)
        assert result.reason_code == REASON_POLICY_SCHEMA_UNSUPPORTED
        assert "999 exceeds reader supported version" in result.message

    def test_min_reader_above_supported(self, tmp_path: Path):
        """min_reader_schema_version=999 > supported -> fail-closed."""
        bundle_dir = tmp_path / "min_reader_999"
        bundle_dir.mkdir()

        import hashlib
        policy_content = (
            "schema_version: 1\n"
            "compile_status: ready\n"
            "bundle_id: bbp-test-123\n"
            "policy_id: bbp:test:1\n"
            "compatibility:\n"
            "  min_reader_schema_version: 999\n"
            "  backward_compatible_with:\n"
            "    - 1\n"
            "scope:\n  allow_hosts: [example.com]\n"
        )
        policy_path = bundle_dir / "compiled_guard_policy.yaml"
        policy_path.write_text(policy_content)
        actual_hash = f"sha256:{hashlib.sha256(policy_path.read_bytes()).hexdigest()}"

        active_json = bundle_dir / "active_bundle.json"
        active_json.write_text(json.dumps({
            "provider": "hackerone",
            "program_alias": "test",
            "bundle_id": "bbp-test-123",
            "policy_id": "bbp:test:1",
            "compiled_policy_path": "compiled_guard_policy.yaml",
            "compiled_policy_hash": actual_hash,
        }))
        result = load_active_policy_from_bundle_dir(bundle_dir)
        assert isinstance(result, GuardLoadError)
        assert result.reason_code == REASON_POLICY_SCHEMA_UNSUPPORTED

    def test_backward_compatible_missing_reader_version(self, tmp_path: Path):
        """backward_compatible_with does not include reader version -> fail-closed."""
        bundle_dir = tmp_path / "no_backcompat"
        bundle_dir.mkdir()

        import hashlib
        policy_content = (
            "schema_version: 1\n"
            "compile_status: ready\n"
            "bundle_id: bbp-test-123\n"
            "policy_id: bbp:test:1\n"
            "compatibility:\n"
            "  min_reader_schema_version: 1\n"
            "  backward_compatible_with:\n"
            "    - 2\n"
            "scope:\n  allow_hosts: [example.com]\n"
        )
        policy_path = bundle_dir / "compiled_guard_policy.yaml"
        policy_path.write_text(policy_content)
        actual_hash = f"sha256:{hashlib.sha256(policy_path.read_bytes()).hexdigest()}"

        active_json = bundle_dir / "active_bundle.json"
        active_json.write_text(json.dumps({
            "provider": "hackerone",
            "program_alias": "test",
            "bundle_id": "bbp-test-123",
            "policy_id": "bbp:test:1",
            "compiled_policy_path": "compiled_guard_policy.yaml",
            "compiled_policy_hash": actual_hash,
        }))
        result = load_active_policy_from_bundle_dir(bundle_dir)
        assert isinstance(result, GuardLoadError)
        assert result.reason_code == REASON_POLICY_SCHEMA_UNSUPPORTED
        assert "backward_compatible_with" in result.message
    
    def test_compiled_policy_missing(self, tmp_path: Path):
        """active_bundle.json exists but compiled_guard_policy.yaml is missing."""
        bundle_dir = tmp_path / "missing_policy"
        bundle_dir.mkdir()
        active_json = bundle_dir / "active_bundle.json"
        active_json.write_text(json.dumps({
            "provider": "hackerone",
            "program_alias": "test",
            "bundle_id": "bbp-test-123",
            "policy_id": "bbp:test:1",
            "compiled_policy_path": "compiled_guard_policy.yaml",
            "compiled_policy_hash": "sha256:abc",
        }))
        result = load_active_policy_from_bundle_dir(bundle_dir)
        assert isinstance(result, GuardLoadError)
        assert result.reason_code == REASON_POLICY_UNAVAILABLE

    def test_hash_mismatch(self, tmp_path: Path):
        """Hash in active_bundle.json does not match actual policy file hash."""
        bundle_dir = tmp_path / "hash_mismatch"
        bundle_dir.mkdir()

        policy_content = "schema_version: 1\ncompile_status: ready\nbundle_id: bbp-test-123\npolicy_id: bbp:test:1\ncompatibility:\n  min_reader_schema_version: 1\n  backward_compatible_with:\n    - 1\nscope:\n  allow_hosts: [example.com]\n"
        policy_path = bundle_dir / "compiled_guard_policy.yaml"
        policy_path.write_text(policy_content)

        active_json = bundle_dir / "active_bundle.json"
        active_json.write_text(json.dumps({
            "provider": "hackerone",
            "program_alias": "test",
            "bundle_id": "bbp-test-123",
            "policy_id": "bbp:test:1",
            "compiled_policy_path": "compiled_guard_policy.yaml",
            "compiled_policy_hash": "sha256:wrong-hash",
        }))
        result = load_active_policy_from_bundle_dir(bundle_dir)
        assert isinstance(result, GuardLoadError)
        assert result.reason_code == REASON_POLICY_INTEGRITY_ERROR

    def test_compile_status_not_ready(self, tmp_path: Path):
        """Policy with compile_status != ready returns fail-closed."""
        bundle_dir = tmp_path / "not_ready"
        bundle_dir.mkdir()

        import hashlib
        policy_content = "schema_version: 1\ncompile_status: manual_review_required\nbundle_id: bbp-test-123\npolicy_id: bbp:test:1\ncompatibility:\n  min_reader_schema_version: 1\n  backward_compatible_with:\n    - 1\nscope:\n  allow_hosts: [example.com]\n"
        policy_path = bundle_dir / "compiled_guard_policy.yaml"
        policy_path.write_text(policy_content)
        actual_hash = f"sha256:{hashlib.sha256(policy_path.read_bytes()).hexdigest()}"

        active_json = bundle_dir / "active_bundle.json"
        active_json.write_text(json.dumps({
            "provider": "hackerone",
            "program_alias": "test",
            "bundle_id": "bbp-test-123",
            "policy_id": "bbp:test:1",
            "compiled_policy_path": "compiled_guard_policy.yaml",
            "compiled_policy_hash": actual_hash,
        }))
        result = load_active_policy_from_bundle_dir(bundle_dir)
        assert isinstance(result, GuardLoadError)
        assert result.reason_code == REASON_POLICY_NOT_READY

    def test_schema_unsupported(self, tmp_path: Path):
        """Policy with schema_version < min_reader returns fail-closed."""
        bundle_dir = tmp_path / "bad_schema"
        bundle_dir.mkdir()

        import hashlib
        policy_content = (
            "schema_version: 0\n"
            "compile_status: ready\n"
            "bundle_id: bbp-test-123\n"
            "policy_id: bbp:test:1\n"
            "compatibility:\n"
            "  min_reader_schema_version: 1\n"
            "scope:\n  allow_hosts: [example.com]\n"
        )
        policy_path = bundle_dir / "compiled_guard_policy.yaml"
        policy_path.write_text(policy_content)
        actual_hash = f"sha256:{hashlib.sha256(policy_path.read_bytes()).hexdigest()}"

        active_json = bundle_dir / "active_bundle.json"
        active_json.write_text(json.dumps({
            "provider": "hackerone",
            "program_alias": "test",
            "bundle_id": "bbp-test-123",
            "policy_id": "bbp:test:1",
            "compiled_policy_path": "compiled_guard_policy.yaml",
            "compiled_policy_hash": actual_hash,
        }))
        result = load_active_policy_from_bundle_dir(bundle_dir)
        assert isinstance(result, GuardLoadError)
        assert result.reason_code == REASON_POLICY_SCHEMA_UNSUPPORTED

    def test_program_alias_mismatch(self):
        """expected_program does not match active_bundle.json program_alias."""
        bundle_dir = FIXTURES_DIR / "tiktok"
        result = load_active_policy_from_bundle_dir(bundle_dir, expected_program="wrongalias")
        assert isinstance(result, GuardLoadError)
        assert result.reason_code == REASON_BUNDLE_PROGRAM_MISMATCH

    def test_bundle_id_mismatch_between_active_and_policy(self, tmp_path: Path):
        """bundle_id in active_bundle.json differs from bundle_id in compiled policy."""
        bundle_dir = tmp_path / "bundle_id_mismatch"
        bundle_dir.mkdir()

        import hashlib
        policy_content = "schema_version: 1\ncompile_status: ready\nbundle_id: wrong-bundle-id\npolicy_id: bbp:test:1\ncompatibility:\n  min_reader_schema_version: 1\n  backward_compatible_with:\n    - 1\nscope:\n  allow_hosts: [example.com]\n"
        policy_path = bundle_dir / "compiled_guard_policy.yaml"
        policy_path.write_text(policy_content)
        actual_hash = f"sha256:{hashlib.sha256(policy_path.read_bytes()).hexdigest()}"

        active_json = bundle_dir / "active_bundle.json"
        active_json.write_text(json.dumps({
            "provider": "hackerone",
            "program_alias": "test",
            "bundle_id": "bbp-test-123",
            "policy_id": "bbp:test:1",
            "compiled_policy_path": "compiled_guard_policy.yaml",
            "compiled_policy_hash": actual_hash,
        }))
        result = load_active_policy_from_bundle_dir(bundle_dir)
        assert isinstance(result, GuardLoadError)
        assert result.reason_code == REASON_POLICY_INTEGRITY_ERROR
