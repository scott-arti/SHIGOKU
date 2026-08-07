"""
SGK-2026-0423 — confirmed-key lifecycle (Lane A): config + lifecycle tests.

Covers:
- enforce-stage key configuration failures (provider / env var / file path /
  registry path), including TEST_KEY_DENYLIST under enforce
- dev (record_only) fail-closed: configured_signer returns None, no raise
- signer/registry integration: non-ACTIVE key blocks confirmed verdicts
  (create_confirmed_verdict raises; evaluate returns candidate + Hold)
- ACTIVE registered key -> confirmed verdict that verifies through the
  registry-backed public-key provider; canonical proof unchanged (v2)
- EnvKeyProvider parsing (missing / malformed / valid)
- rotation lifecycle end-to-end (sign, rotate, verify old verdict, revoke,
  configured_signer-like flow fails closed)
- effective_stage derivation, explicit cap, stage_flags, enforce detection
"""
from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from src.core.config.settings import VdpModeSettings, is_enforce_stage
from src.core.engine.vdp_evidence_validator import (
    Ed25519EvidenceSigner,
    VdpEvidenceValidator,
)
from src.core.engine.vdp_key_registry import (
    EnvKeyProvider,
    FileKeyProvider,
    KeyConfigError,
    KeyRegistryError,
    KeyState,
    VdpKeyRegistry,
    configured_signer,
    effective_stage,
    load_key_registry,
    resolve_key_provider,
    validate_key_config,
)
from src.core.models.vdp_contract import (
    VDP_CONTRACT_SCHEMA_VERSION,
    AttemptRecord,
    EvidenceRecordV1,
    HypothesisRecord,
    PROOF_SCHEMA_VERSION,
    verify_confirmed_verdict,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _hypothesis(hypothesis_id: str = "hyp-001") -> HypothesisRecord:
    return HypothesisRecord(
        hypothesis_id=hypothesis_id,
        observation_id="obs-001",
        asset="https://example.com/items",
        capability="idor_detector",
        hypothesis_text="object read by another actor",
        trust_boundary="api_endpoint",
        actors=["authA", "authB"],
        success_condition="owner-only field visible to authB",
        falsification_condition="no owner/permission difference",
        required_evidence=["real_http_response", "authz_impact_not_proven"],
        state="attempted",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
    )


def _attempt(attempt_id: str = "att-001") -> AttemptRecord:
    return AttemptRecord(
        attempt_id=attempt_id,
        hypothesis_id="hyp-001",
        actor="authB",
        request_fingerprint="fp-001",
        scope_verdict="allowed",
        state="evidence_saved",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
    )


def _evidence(evidence_id: str = "ev-001", *, markers: dict | None = None) -> EvidenceRecordV1:
    return EvidenceRecordV1(
        evidence_id=evidence_id,
        attempt_id="att-001",
        evidence_type="real_http_response",
        raw_hash="sha256:" + "a" * 64,
        redacted_excerpt="HTTP/1.1 200 OK",
        normalization_rule_version="v1",
        auth_context_version="none",
        captured_at="2026-08-03T00:00:00Z",
        original_size=20,
        truncated=False,
        truncation_reason="",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
        execution_result=dict(markers or {}),
    )


def _enforce_settings(
    *,
    key_provider: str = "env",
    key_env_var: str = "SHIGOKU_VDP_TEST_KEY",
    key_file_path: str = "",
    key_registry_path: str = "",
    stage: str = "m3a",
) -> VdpModeSettings:
    return VdpModeSettings(
        mode="readonly_enforce",
        stage=stage,
        key_provider=key_provider,
        key_env_var=key_env_var,
        key_file_path=key_file_path,
        key_registry_path=key_registry_path,
    )


# ---------------------------------------------------------------------------
# Enforce config failures
# ---------------------------------------------------------------------------

class TestEnforceConfigFailures:
    def test_enforce_forbids_env_or_file_provider(self):
        settings = _enforce_settings(key_provider="env_or_file")
        with pytest.raises(KeyConfigError, match="enforce_forbids_env_or_file_provider"):
            resolve_key_provider(settings)

    def test_enforce_file_provider_requires_path(self):
        settings = _enforce_settings(key_provider="file", key_file_path="")
        with pytest.raises(KeyConfigError, match="enforce_key_file_path_unset"):
            resolve_key_provider(settings)

    def test_enforce_env_provider_requires_env_var(self):
        settings = _enforce_settings(key_provider="env", key_env_var="")
        with pytest.raises(KeyConfigError, match="enforce_key_env_var_unset"):
            resolve_key_provider(settings)

    def test_enforce_requires_key_registry(self):
        settings = _enforce_settings(key_registry_path="")
        with pytest.raises(KeyConfigError, match="enforce_requires_key_registry"):
            load_key_registry(settings)

    def test_enforce_denylisted_test_key_rejected(self, tmp_path, monkeypatch):
        registry = VdpKeyRegistry()
        seed = bytes.fromhex("aa" * 32)
        signer = Ed25519EvidenceSigner(private_key=seed)
        registry.register(signer.key_id, signer.public_key_bytes())
        reg_path = tmp_path / "registry.json"
        registry.save(reg_path)
        monkeypatch.setenv("SHIGOKU_VDP_TEST_KEY", seed.hex())
        settings = _enforce_settings(key_env_var="SHIGOKU_VDP_TEST_KEY",
                                     key_registry_path=str(reg_path))
        with pytest.raises(KeyConfigError, match="test_key_in_production_config"):
            configured_signer(settings)
        with pytest.raises(KeyConfigError, match="test_key_in_production_config"):
            validate_key_config(settings, signing_key=seed)


# ---------------------------------------------------------------------------
# Fail-closed dev / registry-integration
# ---------------------------------------------------------------------------

class TestConfiguredSignerFailClosed:
    def test_dev_record_only_no_key_returns_none(self, monkeypatch):
        monkeypatch.delenv("SHIGOKU_VDP_SIGNING_KEY", raising=False)
        settings = VdpModeSettings(mode="record_only")
        assert configured_signer(settings) is None

    def test_dev_auto_registers_key_when_registry_empty(self, monkeypatch):
        """Dev parity: empty registry -> the signer's key is auto-registered
        as ACTIVE in the in-memory registry."""
        monkeypatch.setenv("SHIGOKU_VDP_SIGNING_KEY", "21" * 32)
        settings = VdpModeSettings(mode="shadow")
        signer = configured_signer(settings)
        assert signer is not None
        expected = Ed25519EvidenceSigner(private_key=bytes.fromhex("21" * 32))
        assert signer.key_id == expected.key_id

    def test_configured_signer_key_not_in_registry_returns_none(self, tmp_path, monkeypatch):
        registry = VdpKeyRegistry()
        registry.register("key-other", bytes.fromhex("11" * 32))
        reg_path = tmp_path / "registry.json"
        registry.save(reg_path)
        monkeypatch.setenv("SHIGOKU_VDP_TEST_KEY_19", "22" * 32)
        settings = _enforce_settings(key_env_var="SHIGOKU_VDP_TEST_KEY_19",
                                     key_registry_path=str(reg_path))
        assert configured_signer(settings) is None


class TestSignerRegistryIntegration:
    def test_signer_with_non_active_registry_key_blocks_confirmed(self):
        registry = VdpKeyRegistry()
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("24" * 32), registry=registry)
        registry.register(signer.key_id, signer.public_key_bytes())
        registry.revoke(signer.key_id)
        with pytest.raises(KeyRegistryError, match="signing_key_not_active"):
            signer.create_confirmed_verdict(
                verdict_id="ver-001",
                hypothesis_id="hyp-001",
                reason_codes=["evidence_contract_satisfied"],
                validator_version="1.0.0",
                evidence_records=[_evidence().to_dict()],
            )

    def test_evaluate_fails_closed_when_signing_key_not_active(self):
        registry = VdpKeyRegistry()
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("25" * 32), registry=registry)
        registry.register(signer.key_id, signer.public_key_bytes())
        registry.revoke(signer.key_id)
        validator = VdpEvidenceValidator(signer=signer)
        verdict = validator.evaluate(
            _hypothesis(),
            [_attempt()],
            [_evidence(markers={"authz_impact_proven": "true"})],
        )
        assert verdict.status == "candidate"
        assert "signing_key_not_active" in verdict.reason_codes
        assert "signer_unavailable_hold" in verdict.reason_codes
        assert verdict.validation_proof == ""

    def test_registry_active_key_confirmed_verdict_verifies(self):
        registry = VdpKeyRegistry()
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("26" * 32), registry=registry)
        registry.register(signer.key_id, signer.public_key_bytes())
        ev = _evidence(markers={"authz_impact_proven": "true"})
        verdict = signer.create_confirmed_verdict(
            verdict_id="ver-021",
            hypothesis_id="hyp-001",
            reason_codes=["evidence_contract_satisfied"],
            validator_version="1.0.0",
            evidence_records=[ev.to_dict()],
        )
        assert verdict.status == "confirmed"
        # canonical proof format is unchanged: ed25519:<key_id>:<b64url>
        assert verdict.proof_schema_version == PROOF_SCHEMA_VERSION == "v2"
        parts = verdict.validation_proof.split(":")
        assert len(parts) == 3
        assert parts[0] == "ed25519"
        assert parts[1] == signer.key_id
        signature = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
        assert len(signature) == 64
        result = verify_confirmed_verdict(
            verdict.to_dict(),
            [ev.to_dict()],
            public_key_provider=signer.public_key_provider(),
        )
        assert result.verified is True, result.detail


# ---------------------------------------------------------------------------
# Key providers
# ---------------------------------------------------------------------------

class TestEnvKeyProvider:
    def test_missing_malformed_and_valid_values(self, monkeypatch):
        monkeypatch.delenv("SHIGOKU_VDP_TEST_KEY", raising=False)
        provider = EnvKeyProvider(env_var="SHIGOKU_VDP_TEST_KEY")
        assert provider.load_signing_key() is None  # missing
        monkeypatch.setenv("SHIGOKU_VDP_TEST_KEY", "zz" * 32)
        assert provider.load_signing_key() is None  # malformed hex
        monkeypatch.setenv("SHIGOKU_VDP_TEST_KEY", "ab" * 31)
        assert provider.load_signing_key() is None  # wrong length
        monkeypatch.setenv("SHIGOKU_VDP_TEST_KEY", "ab" * 32)
        assert provider.load_signing_key() == bytes.fromhex("ab" * 32)


# ---------------------------------------------------------------------------
# Rotation lifecycle end-to-end
# ---------------------------------------------------------------------------

class TestRotationLifecycle:
    def test_rotation_lifecycle_end_to_end(self, tmp_path, monkeypatch):
        registry = VdpKeyRegistry()
        signer_a = Ed25519EvidenceSigner(private_key=bytes.fromhex("27" * 32), registry=registry)
        registry.register(signer_a.key_id, signer_a.public_key_bytes())
        ev = _evidence(markers={"authz_impact_proven": "true"})

        # 1) sign with key A -> confirmed, verifiable
        verdict_a = signer_a.create_confirmed_verdict(
            verdict_id="ver-rot-001",
            hypothesis_id="hyp-001",
            reason_codes=["evidence_contract_satisfied"],
            validator_version="1.0.0",
            evidence_records=[ev.to_dict()],
        )
        assert verdict_a.status == "confirmed"
        result = verify_confirmed_verdict(
            verdict_a.to_dict(), [ev.to_dict()],
            public_key_provider=signer_a.public_key_provider(),
        )
        assert result.verified is True, result.detail

        # 2) rotate A -> VERIFY_ONLY, B ACTIVE
        signer_b = Ed25519EvidenceSigner(private_key=bytes.fromhex("28" * 32))
        registry.rotate(
            signer_a.key_id, signer_b.key_id, signer_b.public_key_bytes(),
            verify_only_days=30,
        )
        assert registry.active_key_id() == signer_b.key_id
        assert registry.get_state(signer_a.key_id) == KeyState.VERIFY_ONLY

        # 3) old verdict still verifies via the registry provider (grace window)
        provider = registry.public_key_provider()
        assert set(provider) == {signer_a.key_id, signer_b.key_id}
        result = verify_confirmed_verdict(
            verdict_a.to_dict(), [ev.to_dict()], public_key_provider=provider,
        )
        assert result.verified is True, result.detail

        # 4) revoke B -> no active key left
        registry.revoke(signer_b.key_id)
        assert registry.active_key_id() is None
        assert registry.resolve_verification_key(signer_b.key_id) is None
        signer_b_bound = Ed25519EvidenceSigner(
            private_key=bytes.fromhex("28" * 32), registry=registry,
        )
        with pytest.raises(KeyRegistryError, match="signing_key_not_active"):
            signer_b_bound.create_confirmed_verdict(
                verdict_id="ver-rot-002",
                hypothesis_id="hyp-001",
                reason_codes=["evidence_contract_satisfied"],
                validator_version="1.0.0",
                evidence_records=[ev.to_dict()],
            )

        # 5) configured_signer-like flow fails closed: key not registered
        reg_path = tmp_path / "registry.json"
        registry.save(reg_path)
        monkeypatch.setenv("SHIGOKU_VDP_TEST_KEY_23", "29" * 32)
        settings = _enforce_settings(key_env_var="SHIGOKU_VDP_TEST_KEY_23",
                                     key_registry_path=str(reg_path))
        assert configured_signer(settings) is None


# ---------------------------------------------------------------------------
# effective_stage
# ---------------------------------------------------------------------------

class TestEffectiveStage:
    def test_mode_only_derivation(self):
        assert effective_stage(VdpModeSettings(mode="record_only")) == "m1"
        assert effective_stage(VdpModeSettings(mode="shadow")) == "m2"
        assert effective_stage(VdpModeSettings(mode="readonly_enforce")) == "m3a"
        assert effective_stage(VdpModeSettings(mode="off")) == "m0"

    def test_explicit_stage_caps_below_mode(self):
        settings = VdpModeSettings(mode="readonly_enforce", stage="m2")
        assert effective_stage(settings) == "m2"

    def test_explicit_stage_above_mode_is_capped_by_mode(self):
        settings = VdpModeSettings(mode="shadow", stage="m4")
        assert effective_stage(settings) == "m2"

    def test_stage_flags_disable_caps_down(self):
        settings = VdpModeSettings(
            mode="readonly_enforce", stage="m3a", stage_flags={"m3a": False},
        )
        assert effective_stage(settings) == "m2"
        assert is_enforce_stage(effective_stage(settings)) is False

    def test_stage_flags_disable_caps_down_from_m2(self):
        settings = VdpModeSettings(
            mode="shadow", stage="m2", stage_flags={"m2": False},
        )
        assert effective_stage(settings) == "m1"
        assert is_enforce_stage(effective_stage(settings)) is False

    def test_stage_flags_cascade_when_previous_stage_also_disabled(self):
        settings = VdpModeSettings(
            mode="readonly_enforce", stage="m3a",
            stage_flags={"m3a": False, "m2": False},
        )
        assert effective_stage(settings) == "m1"

    def test_stage_flags_for_unrelated_stage_no_effect(self):
        settings = VdpModeSettings(
            mode="readonly_enforce", stage="m3a", stage_flags={"m4": False},
        )
        assert effective_stage(settings) == "m3a"

    def test_empty_flags_have_no_effect(self):
        settings = VdpModeSettings(mode="readonly_enforce", stage="m3a")
        assert effective_stage(settings) == "m3a"
        assert is_enforce_stage(effective_stage(settings)) is True

    def test_getattr_safe_for_legacy_settings_object(self):
        legacy = SimpleNamespace(mode="record_only")
        assert effective_stage(legacy) == "m1"

    def test_enforce_detection_via_is_enforce_stage(self):
        assert is_enforce_stage("m3a") is True
        assert is_enforce_stage("m3b") is True
        assert is_enforce_stage("m3c") is True
        assert is_enforce_stage("m4") is True
        assert is_enforce_stage("m2") is False
        assert is_enforce_stage("m0") is False


class TestFileKeyProviderFailClosed:
    """Lane H (SGK-2026-0423): insecure key files fail closed at the config
    path, and error messages never leak key material."""

    def test_configured_signer_rejects_insecure_key_file(self, tmp_path):
        registry = VdpKeyRegistry()
        seed = bytes.fromhex("2a" * 32)
        signer = Ed25519EvidenceSigner(private_key=seed)
        registry.register(signer.key_id, signer.public_key_bytes())
        reg_path = tmp_path / "registry.json"
        registry.save(reg_path)
        key_file = tmp_path / "signing.key"
        key_file.write_text(seed.hex(), encoding="utf-8")
        key_file.chmod(0o644)
        settings = _enforce_settings(
            key_provider="file",
            key_file_path=str(key_file),
            key_registry_path=str(reg_path),
        )
        with pytest.raises(KeyConfigError, match="key_file_permission_too_broad"):
            configured_signer(settings)

    def test_error_message_contains_no_key_material(self, tmp_path, monkeypatch):
        seed_hex = "3b" * 32
        key_file = tmp_path / "signing.key"
        key_file.write_text(seed_hex, encoding="utf-8")
        errors = []

        def _capture(fn):
            try:
                fn()
            except KeyConfigError as exc:
                errors.append(exc)

        key_file.chmod(0o644)
        _capture(lambda: FileKeyProvider(path=key_file).load_signing_key())
        key_file.chmod(0o640)
        _capture(lambda: FileKeyProvider(path=key_file).load_signing_key())
        link = tmp_path / "link.key"
        link.symlink_to(key_file)
        _capture(lambda: FileKeyProvider(path=link).load_signing_key())
        _capture(lambda: FileKeyProvider(path=tmp_path).load_signing_key())
        real_uid = os.lstat(key_file).st_uid
        monkeypatch.setattr(os, "geteuid", lambda: real_uid + 1)
        key_file.chmod(0o600)
        _capture(lambda: FileKeyProvider(path=key_file).load_signing_key())
        assert len(errors) == 5
        codes = [str(exc).split(":")[0] for exc in errors]
        assert codes == [
            "key_file_permission_too_broad",
            "key_file_permission_too_broad",
            "key_file_not_regular_file",
            "key_file_not_regular_file",
            "key_file_owner_mismatch",
        ]
        for exc in errors:
            assert seed_hex not in str(exc)
