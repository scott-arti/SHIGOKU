"""
SGK-2026-0423 — confirmed-key lifecycle (Lane A): registry unit tests.

Covers the ``VdpKeyRegistry`` state machine:
- register / duplicate rejection / at-most-one-ACTIVE invariant
- rotate (ACTIVE -> VERIFY_ONLY grace window + new ACTIVE key)
- revoke (audit entry kept; no active key left behind)
- resolve_verification_key / public_key_provider filtering
- to_dict / from_dict roundtrip, malformed rejection, no private-key hex
- atomic save / load, missing-file rejection, permission gate
- error messages never leak key bytes
"""
from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from src.core.engine.vdp_key_registry import (
    EnvOrFileKeyProvider,
    FileKeyProvider,
    KeyConfigError,
    KeyEntry,
    KeyRegistryError,
    KeyState,
    VdpKeyRegistry,
)


def _pub(seed_byte: int) -> bytes:
    return bytes([seed_byte]) * 32


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TestRegister:
    def test_register_sets_active_key_id(self):
        registry = VdpKeyRegistry()
        registry.register("key-001", _pub(0x11))
        assert registry.active_key_id() == "key-001"
        assert registry.get_state("key-001") == KeyState.ACTIVE

    def test_duplicate_register_rejected(self):
        registry = VdpKeyRegistry()
        registry.register("key-001", _pub(0x11))
        with pytest.raises(KeyRegistryError):
            registry.register("key-001", _pub(0x22))

    def test_second_active_key_rejected(self):
        """Invariant: at most one ACTIVE key — a second ACTIVE registration
        must fail closed."""
        registry = VdpKeyRegistry()
        registry.register("key-001", _pub(0x11))
        with pytest.raises(KeyRegistryError, match="active_key_already_exists"):
            registry.register("key-002", _pub(0x22))


class TestRotate:
    def test_rotate_moves_old_to_verify_only_and_activates_new(self):
        registry = VdpKeyRegistry()
        registry.register("key-a", _pub(0x11))
        registry.rotate("key-a", "key-b", _pub(0x22), verify_only_days=30)
        assert registry.active_key_id() == "key-b"
        assert registry.get_state("key-a") == KeyState.VERIFY_ONLY
        assert registry.get_state("key-b") == KeyState.ACTIVE
        until_raw = registry.entries["key-a"].verify_only_until
        assert until_raw is not None
        until = datetime.fromisoformat(until_raw.replace("Z", "+00:00"))
        delta = until - _now()
        assert timedelta(days=29) < delta < timedelta(days=31)

    def test_rotate_non_active_key_rejected(self):
        registry = VdpKeyRegistry()
        registry.register("key-a", _pub(0x11))
        registry.revoke("key-a")
        with pytest.raises(KeyRegistryError):
            registry.rotate("key-a", "key-b", _pub(0x22))
        with pytest.raises(KeyRegistryError):
            registry.rotate("unknown-key", "key-b", _pub(0x22))

    def test_rotate_to_existing_key_id_rejected(self):
        registry = VdpKeyRegistry()
        registry.register("key-a", _pub(0x11))
        registry.rotate("key-a", "key-b", _pub(0x22))
        with pytest.raises(KeyRegistryError):
            registry.rotate("key-b", "key-a", _pub(0x33))


class TestRevoke:
    def test_revoke_active_key_fail_closed(self):
        """Revoking the active key leaves NO active key (fail-closed)."""
        registry = VdpKeyRegistry()
        registry.register("key-a", _pub(0x11))
        registry.revoke("key-a")
        assert registry.get_state("key-a") == KeyState.REVOKED  # audit entry kept
        assert registry.active_key_id() is None
        assert registry.resolve_verification_key("key-a") is None
        assert "key-a" not in registry.public_key_provider()

    def test_revoke_unknown_key_rejected(self):
        registry = VdpKeyRegistry()
        with pytest.raises(KeyRegistryError):
            registry.revoke("unknown-key")


class TestResolveVerificationKey:
    def test_verify_only_resolvable_within_expiry_not_after(self):
        now = _now()
        future = (now + timedelta(days=7)).isoformat()
        past = (now - timedelta(days=1)).isoformat()
        registry = VdpKeyRegistry(
            entries={
                "in-expiry": KeyEntry(
                    key_id="in-expiry",
                    state=KeyState.VERIFY_ONLY,
                    public_key=_pub(0x44),
                    created_at=now.isoformat(),
                    verify_only_until=future,
                ),
                "expired": KeyEntry(
                    key_id="expired",
                    state=KeyState.VERIFY_ONLY,
                    public_key=_pub(0x55),
                    created_at=now.isoformat(),
                    verify_only_until=past,
                ),
            }
        )
        assert registry.resolve_verification_key("in-expiry") == _pub(0x44)
        assert registry.resolve_verification_key("expired") is None

    def test_unknown_key_id_resolves_none(self):
        registry = VdpKeyRegistry()
        assert registry.resolve_verification_key("missing") is None
        assert registry.get_state("missing") is None


class TestPublicKeyProvider:
    def test_provider_includes_active_and_in_expiry_verify_only(self):
        now = _now()
        future = (now + timedelta(days=7)).isoformat()
        past = (now - timedelta(days=1)).isoformat()
        registry = VdpKeyRegistry(
            entries={
                "active": KeyEntry("active", KeyState.ACTIVE, _pub(0x11), now.isoformat()),
                "verify-ok": KeyEntry(
                    "verify-ok", KeyState.VERIFY_ONLY, _pub(0x22),
                    now.isoformat(), future,
                ),
                "revoked": KeyEntry("revoked", KeyState.REVOKED, _pub(0x33), now.isoformat()),
                "expired": KeyEntry(
                    "expired", KeyState.VERIFY_ONLY, _pub(0x44),
                    now.isoformat(), past,
                ),
            }
        )
        provider = registry.public_key_provider()
        assert set(provider) == {"active", "verify-ok"}
        assert provider["active"] == _pub(0x11)
        assert provider["verify-ok"] == _pub(0x22)


class TestSerialization:
    def test_to_dict_from_dict_roundtrip(self):
        now = _now()
        registry = VdpKeyRegistry(
            entries={
                "active": KeyEntry("active", KeyState.ACTIVE, _pub(0x11), now.isoformat()),
                "verify": KeyEntry(
                    "verify", KeyState.VERIFY_ONLY, _pub(0x22),
                    now.isoformat(), (now + timedelta(days=7)).isoformat(),
                ),
            }
        )
        data = registry.to_dict()
        restored = VdpKeyRegistry.from_dict(data)
        assert restored.to_dict() == data
        assert restored.public_key_provider() == registry.public_key_provider()

    def test_from_dict_malformed_rejected(self):
        bad_inputs = (
            "not-a-dict",
            {"keys": "nope"},
            {"keys": {"k": {"state": "bogus", "public_key": "11" * 32, "created_at": "x"}}},
            {"keys": {"k": {"state": "active", "public_key": "zz", "created_at": "x"}}},
            {"keys": {"k": {"state": "active", "public_key": "11" * 32, "created_at": ""}}},
            {"keys": {"k": {"state": "active", "public_key": "11" * 32, "created_at": "x",
                            "verify_only_until": "not-a-date"}}},
            {"keys": {"a": {"state": "active", "public_key": "11" * 32, "created_at": "x"},
                      "b": {"state": "active", "public_key": "22" * 32, "created_at": "x"}}},
        )
        for bad in bad_inputs:
            with pytest.raises(KeyRegistryError):
                VdpKeyRegistry.from_dict(bad)

    def test_to_dict_json_contains_no_private_key_hex(self):
        from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner

        private_seed = bytes.fromhex("42" * 32)
        signer = Ed25519EvidenceSigner(private_key=private_seed)
        registry = VdpKeyRegistry()
        registry.register(signer.key_id, signer.public_key_bytes())
        blob = json.dumps(registry.to_dict())
        assert private_seed.hex() not in blob
        assert "42" * 64 not in blob


class TestSaveLoad:
    def test_save_load_roundtrip(self, tmp_path):
        registry = VdpKeyRegistry()
        registry.register("key-a", _pub(0x11))
        registry.rotate("key-a", "key-b", _pub(0x22), verify_only_days=14)
        path = tmp_path / "registry.json"
        registry.save(path)
        loaded = VdpKeyRegistry.load(path)
        assert loaded.to_dict() == registry.to_dict()
        assert loaded.active_key_id() == "key-b"
        assert loaded.get_state("key-a") == KeyState.VERIFY_ONLY

    def test_load_missing_file_rejected(self, tmp_path):
        with pytest.raises(KeyRegistryError):
            VdpKeyRegistry.load(tmp_path / "nope.json")


class TestPermissions:
    def test_registry_permission_check(self, tmp_path):
        path = tmp_path / "registry.json"
        path.write_text("{}")
        path.chmod(0o644)
        with pytest.raises(KeyRegistryError, match="registry_permission_too_broad"):
            VdpKeyRegistry.check_registry_permissions(path)
        path.chmod(0o600)
        VdpKeyRegistry.check_registry_permissions(path)  # must not raise
        # missing file is not a permission problem
        VdpKeyRegistry.check_registry_permissions(tmp_path / "missing.json")


class TestErrorMessages:
    def test_error_messages_never_contain_key_bytes(self):
        pub_hex = "11" * 32
        registry = VdpKeyRegistry()
        registry.register("key-a", bytes.fromhex(pub_hex))
        errors = []
        try:
            registry.register("key-a", bytes.fromhex(pub_hex))
        except KeyRegistryError as exc:
            errors.append(exc)
        try:
            registry.register("key-b", bytes.fromhex("22" * 32))
        except KeyRegistryError as exc:
            errors.append(exc)
        registry.revoke("key-a")
        try:
            registry.rotate("key-a", "key-b", bytes.fromhex("33" * 32))
        except KeyRegistryError as exc:
            errors.append(exc)
        assert len(errors) == 3
        for exc in errors:
            assert pub_hex not in str(exc)
            assert "11" not in str(exc)


class TestFileKeyProviderHardening:
    """Lane H (SGK-2026-0423): FileKeyProvider must verify the key file is
    an owner-only regular file BEFORE reading it (fail closed)."""

    VALID_HEX = "ab" * 32

    def test_file_provider_rejects_0644_permissions(self, tmp_path):
        path = tmp_path / "signing.key"
        path.write_text(self.VALID_HEX, encoding="utf-8")
        path.chmod(0o644)
        with pytest.raises(KeyConfigError, match="key_file_permission_too_broad"):
            FileKeyProvider(path=path).load_signing_key()
        path.chmod(0o600)
        assert (
            FileKeyProvider(path=path).load_signing_key()
            == bytes.fromhex(self.VALID_HEX)
        )

    def test_file_provider_rejects_symlink(self, tmp_path):
        target = tmp_path / "real.key"
        target.write_text(self.VALID_HEX, encoding="utf-8")
        target.chmod(0o600)
        link = tmp_path / "link.key"
        link.symlink_to(target)
        with pytest.raises(KeyConfigError, match="key_file_not_regular_file"):
            FileKeyProvider(path=link).load_signing_key()

    def test_file_provider_rejects_directory(self, tmp_path):
        with pytest.raises(KeyConfigError, match="key_file_not_regular_file"):
            FileKeyProvider(path=tmp_path).load_signing_key()

    def test_file_provider_owner_mismatch_rejected(self, tmp_path, monkeypatch):
        # A REAL cross-uid chown requires root (no passwordless sudo here),
        # so the owner check is exercised via a scoped os.geteuid monkeypatch
        # (the monkeypatch fixture restores it afterwards). The permission
        # half of the hardening is exercised for real via chmod in the
        # 0644/0640 tests.
        path = tmp_path / "signing.key"
        path.write_text(self.VALID_HEX, encoding="utf-8")
        path.chmod(0o600)
        real_uid = os.lstat(path).st_uid
        monkeypatch.setattr(os, "geteuid", lambda: real_uid + 1)
        with pytest.raises(KeyConfigError, match="key_file_owner_mismatch"):
            FileKeyProvider(path=path).load_signing_key()

    def test_file_provider_missing_file_returns_none(self, tmp_path):
        # Missing key file stays a soft None (matching legacy behavior).
        assert FileKeyProvider(path=tmp_path / "missing.key").load_signing_key() is None

    def test_file_provider_group_readable_rejected(self, tmp_path):
        path = tmp_path / "signing.key"
        path.write_text(self.VALID_HEX, encoding="utf-8")
        path.chmod(0o640)
        with pytest.raises(KeyConfigError, match="key_file_permission_too_broad"):
            FileKeyProvider(path=path).load_signing_key()

    def test_env_or_file_provider_applies_file_checks(self, tmp_path, monkeypatch):
        # EnvOrFileKeyProvider must delegate through FileKeyProvider so the
        # same fail-closed checks apply to its file branch.
        monkeypatch.delenv("SHIGOKU_VDP_SIGNING_KEY", raising=False)
        path = tmp_path / "signing.key"
        path.write_text(self.VALID_HEX, encoding="utf-8")
        path.chmod(0o644)
        provider = EnvOrFileKeyProvider(file_path=path)
        with pytest.raises(KeyConfigError, match="key_file_permission_too_broad"):
            provider.load_signing_key()

    def test_file_provider_lstat_oserror_fails_closed(self, tmp_path, monkeypatch):
        path = tmp_path / "signing.key"
        path.write_text(self.VALID_HEX, encoding="utf-8")
        path.chmod(0o600)

        def _denied(_target):
            raise PermissionError("simulated lstat denial")

        monkeypatch.setattr(os, "lstat", _denied)
        with pytest.raises(KeyConfigError, match="key_file_unreadable"):
            FileKeyProvider(path=path).load_signing_key()
