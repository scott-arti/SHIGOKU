"""
SGK-2026-0423 — confirmed-key lifecycle (Lane A, engine layer).

Versioned Ed25519 key registry + key configuration resolution for the
confirmed-verdict signing boundary (``src.core.engine.vdp_evidence_validator``).

Security invariants:
- The registry stores PUBLIC keys only. Private key bytes NEVER appear in
  registry JSON, exceptions, logs, sessions, or reports.
- At most one ACTIVE key at any time; rotation moves the old key into a
  VERIFY_ONLY grace window; revocation is fail-closed (no active key).
- Enforce stages (M3a+) never fall back to implicit key sources: the key
  provider and the registry path must be explicit, and the signing key must
  be present and NOT in ``TEST_KEY_DENYLIST``.
- Key files (``FileKeyProvider``) must be owner-only (0600) regular files:
  symlinks, foreign ownership, and any group/other access are rejected with
  ``KeyConfigError`` BEFORE the file is read (fail closed).

This module is Lane A of SGK-2026-0423: it owns the key lifecycle and the
enforce/no-home-fallback decision only. The full rollout gate lives in
``vdp_rollout.py`` (another lane).

Import direction: this module imports ``src.core.config.settings`` at module
level and imports ``Ed25519EvidenceSigner`` lazily inside functions to avoid
import cycles with ``vdp_evidence_validator``.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Mapping, Optional, Protocol

from src.core.config.settings import (
    VDP_STAGES,
    VDP_STAGE_RANKS,
    derive_stage_from_mode,
    is_enforce_stage,
    min_stage,
)

if TYPE_CHECKING:
    from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner


class KeyState(str, Enum):
    """Lifecycle state of a registry key entry."""

    ACTIVE = "active"
    VERIFY_ONLY = "verify_only"
    REVOKED = "revoked"


class KeyRegistryError(Exception):
    """Key registry error. Messages NEVER contain key material."""


class KeyConfigError(KeyRegistryError):
    """Invalid key configuration. Messages NEVER contain key material."""


@dataclass
class KeyEntry:
    """Public-key-only registry entry (NO private key field, ever)."""

    key_id: str
    state: KeyState
    public_key: bytes  # raw 32-byte Ed25519 public key
    created_at: str  # ISO UTC
    verify_only_until: Optional[str] = None  # ISO UTC; None when not in grace


# ---------------------------------------------------------------------------
# ISO UTC helpers
# ---------------------------------------------------------------------------

def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _format_iso(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _now_iso() -> str:
    return _format_iso(datetime.now(timezone.utc))


class VdpKeyRegistry:
    """Versioned public-key registry with an at-most-one-ACTIVE invariant.

    State transitions:
    - ``register``: adds a key (ACTIVE by default; second ACTIVE rejected).
    - ``rotate``: ACTIVE -> VERIFY_ONLY (grace window) + new ACTIVE key.
    - ``revoke``: any state -> REVOKED (audit entry kept); revoking the
      active key leaves NO active key (fail-closed).
    """

    def __init__(self, entries: Optional[Mapping[str, KeyEntry]] = None) -> None:
        self._entries: Dict[str, KeyEntry] = {}
        if entries:
            self._entries.update(entries)
            active = [
                key_id
                for key_id, entry in self._entries.items()
                if entry.state == KeyState.ACTIVE
            ]
            if len(active) > 1:
                raise KeyRegistryError("active_key_already_exists")

    @property
    def entries(self) -> Dict[str, KeyEntry]:
        """Copy of the current entries (key_id -> KeyEntry)."""
        return dict(self._entries)

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def register(
        self,
        key_id: str,
        public_key: bytes,
        *,
        state: KeyState = KeyState.ACTIVE,
    ) -> None:
        if not key_id or not isinstance(key_id, str):
            raise KeyRegistryError("invalid_key_id")
        if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
            raise KeyRegistryError("invalid_public_key")
        if key_id in self._entries:
            raise KeyRegistryError("duplicate_key_id")
        if state == KeyState.ACTIVE and self._active_key_id() is not None:
            raise KeyRegistryError("active_key_already_exists")
        self._entries[key_id] = KeyEntry(
            key_id=key_id,
            state=state,
            public_key=bytes(public_key),
            created_at=_now_iso(),
            verify_only_until=None,
        )

    def rotate(
        self,
        key_id: str,
        new_key_id: str,
        new_public_key: bytes,
        verify_only_days: int = 30,
    ) -> None:
        entry = self._entries.get(key_id)
        if entry is None or entry.state != KeyState.ACTIVE:
            raise KeyRegistryError("key_not_active_for_rotation")
        if not new_key_id or not isinstance(new_key_id, str):
            raise KeyRegistryError("invalid_key_id")
        if new_key_id in self._entries:
            raise KeyRegistryError("new_key_id_already_exists")
        if (
            not isinstance(new_public_key, (bytes, bytearray))
            or len(new_public_key) != 32
        ):
            raise KeyRegistryError("invalid_public_key")
        until = datetime.now(timezone.utc) + timedelta(days=verify_only_days)
        entry.state = KeyState.VERIFY_ONLY
        entry.verify_only_until = _format_iso(until)
        self._entries[new_key_id] = KeyEntry(
            key_id=new_key_id,
            state=KeyState.ACTIVE,
            public_key=bytes(new_public_key),
            created_at=_now_iso(),
            verify_only_until=None,
        )

    def revoke(self, key_id: str) -> None:
        entry = self._entries.get(key_id)
        if entry is None:
            raise KeyRegistryError("key_not_found")
        entry.state = KeyState.REVOKED  # audit entry kept in the registry

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def active_key_id(self) -> Optional[str]:
        return self._active_key_id()

    def get_state(self, key_id: str) -> Optional[KeyState]:
        entry = self._entries.get(key_id)
        return entry.state if entry is not None else None

    def resolve_verification_key(self, key_id: str) -> Optional[bytes]:
        """Resolve the public key for verification, or None (fail-closed).

        ACTIVE -> public key; VERIFY_ONLY -> public key only while the grace
        window is unexpired; REVOKED / unknown / expired -> None.
        """
        entry = self._entries.get(key_id)
        if entry is None:
            return None
        if entry.state == KeyState.ACTIVE:
            return entry.public_key
        if entry.state == KeyState.VERIFY_ONLY:
            until = _parse_iso(entry.verify_only_until)
            if until is not None and datetime.now(timezone.utc) < until:
                return entry.public_key
        return None

    def public_key_provider(self) -> Dict[str, bytes]:
        """Public-key provider dict for ``verify_confirmed_verdict``:
        ACTIVE + in-expiry VERIFY_ONLY keys only."""
        provider: Dict[str, bytes] = {}
        for key_id, entry in self._entries.items():
            if self.resolve_verification_key(key_id) is not None:
                provider[key_id] = entry.public_key
        return provider

    # ------------------------------------------------------------------
    # Serialization (public keys only)
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "keys": {
                key_id: {
                    "key_id": entry.key_id,
                    "state": entry.state.value,
                    "public_key": entry.public_key.hex(),
                    "created_at": entry.created_at,
                    "verify_only_until": entry.verify_only_until,
                }
                for key_id, entry in sorted(self._entries.items())
            },
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VdpKeyRegistry":
        if not isinstance(data, dict) or not isinstance(data.get("keys"), dict):
            raise KeyRegistryError("registry_malformed")
        entries: Dict[str, KeyEntry] = {}
        for key_id, raw in data["keys"].items():
            if not isinstance(raw, dict):
                raise KeyRegistryError("registry_malformed")
            try:
                state = KeyState(str(raw["state"]))
            except (KeyError, ValueError, TypeError):
                raise KeyRegistryError("registry_malformed") from None
            try:
                public_key = bytes.fromhex(str(raw.get("public_key") or ""))
            except (ValueError, TypeError):
                raise KeyRegistryError("registry_malformed") from None
            if len(public_key) != 32:
                raise KeyRegistryError("registry_malformed")
            created_at = raw.get("created_at")
            if not isinstance(created_at, str) or not created_at:
                raise KeyRegistryError("registry_malformed")
            verify_only_until = raw.get("verify_only_until")
            if verify_only_until is not None:
                if not isinstance(verify_only_until, str) or _parse_iso(
                    verify_only_until
                ) is None:
                    raise KeyRegistryError("registry_malformed")
            entries[str(key_id)] = KeyEntry(
                key_id=str(key_id),
                state=state,
                public_key=public_key,
                created_at=created_at,
                verify_only_until=verify_only_until,
            )
        return cls(entries=entries)

    def save(self, path) -> None:
        """Atomic write: temp file in the same directory + os.replace.

        The temp file is chmod 0o600 before replace so the registry always
        satisfies ``check_registry_permissions``.
        """
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self.to_dict(), handle, indent=2, sort_keys=True)
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, target)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    @classmethod
    def load(cls, path) -> "VdpKeyRegistry":
        source = Path(path)
        if not source.exists():
            raise KeyRegistryError("registry_file_missing")
        try:
            raw = source.read_text(encoding="utf-8")
        except OSError as exc:
            raise KeyRegistryError("registry_read_failed") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise KeyRegistryError("registry_malformed_json") from exc
        return cls.from_dict(data)

    @staticmethod
    def check_registry_permissions(path) -> None:
        """Raise KeyRegistryError when the registry file grants group/other
        access (mode & 0o077 != 0). Missing file is fine."""
        source = Path(path)
        if not source.exists():
            return
        mode = source.stat().st_mode & 0o777
        if mode & 0o077:
            raise KeyRegistryError("registry_permission_too_broad")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _active_key_id(self) -> Optional[str]:
        for key_id, entry in self._entries.items():
            if entry.state == KeyState.ACTIVE:
                return key_id
        return None


# ---------------------------------------------------------------------------
# Key providers (private-key sources, dev + explicit)
# ---------------------------------------------------------------------------

class KeyProvider(Protocol):
    """Loads the raw 32-byte Ed25519 seed. ``label`` never contains key
    material (safe for logs)."""

    def load_signing_key(self) -> Optional[bytes]:
        ...

    def label(self) -> str:
        ...


class EnvKeyProvider:
    """Loads the signing seed from an environment variable (64 hex chars)."""

    def __init__(self, env_var: str = "SHIGOKU_VDP_SIGNING_KEY") -> None:
        self._env_var = env_var

    def load_signing_key(self) -> Optional[bytes]:
        value = os.environ.get(self._env_var) if self._env_var else None
        if not value:
            return None
        raw = value.strip()
        if len(raw) != 64:
            return None
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return None

    def label(self) -> str:
        return f"env:{self._env_var}"


class FileKeyProvider:
    """Loads the signing seed from an EXPLICIT file path (64 hex chars).

    Never falls back to Path.home() or any implicit location.

    The key file must be a regular file owned by the current user with no
    group/other access (owner-only 0600): symlinks, foreign ownership, and
    broader modes (e.g. 0644) are rejected with ``KeyConfigError`` BEFORE
    the file is read (fail closed). A missing file stays a soft None.
    """

    def __init__(self, path: Path) -> None:
        self._path = path

    def _check_key_file(self) -> None:
        """Fail closed when the key file is not an owner-only regular file.

        Uses ``os.lstat`` (not ``stat``) so symlinks are rejected. A missing
        file returns normally — the caller treats it as a soft None. Messages
        contain only the reason and the path, never key material.
        """
        try:
            st = os.lstat(self._path)
        except FileNotFoundError:
            return  # missing file -> soft None (caller decides)
        except OSError as exc:
            raise KeyConfigError(f"key_file_unreadable: {self._path}") from exc
        if not stat.S_ISREG(st.st_mode):
            raise KeyConfigError(f"key_file_not_regular_file: {self._path}")
        if st.st_uid != os.geteuid():
            raise KeyConfigError(f"key_file_owner_mismatch: {self._path}")
        if st.st_mode & 0o077:
            raise KeyConfigError(f"key_file_permission_too_broad: {self._path}")

    def load_signing_key(self) -> Optional[bytes]:
        self._check_key_file()
        try:
            raw = self._path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if len(raw) != 64:
            return None
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return None

    def label(self) -> str:
        return f"file:{self._path}"


class EnvOrFileKeyProvider:
    """Dev convenience: env var first, then the explicit file path (never
    the home directory)."""

    def __init__(
        self,
        env_var: str = "SHIGOKU_VDP_SIGNING_KEY",
        file_path: Optional[Path] = None,
    ) -> None:
        self._env_var = env_var
        self._file_path = file_path

    def load_signing_key(self) -> Optional[bytes]:
        key = EnvKeyProvider(env_var=self._env_var).load_signing_key()
        if key is not None:
            return key
        if self._file_path is not None:
            return FileKeyProvider(path=self._file_path).load_signing_key()
        return None

    def label(self) -> str:
        return f"env_or_file:{self._env_var}"


# ---------------------------------------------------------------------------
# Configuration resolution (enforce / no-home-fallback decision)
# ---------------------------------------------------------------------------

# Hex seeds reserved for tests/dev fixtures — NEVER valid in enforce stages.
TEST_KEY_DENYLIST: frozenset[str] = frozenset({("aa" * 32), ("00" * 32)})


def effective_stage(settings) -> str:
    """Effective rollout stage for ``settings`` (getattr-safe).

    - mode-derived stage via ``derive_stage_from_mode``
    - explicit ``stage`` acts as a CAP: effective = min(mode-derived, explicit)
    - ``stage_flags``: when the resulting stage's flag is False, cap down to
      the previous stage in ``VDP_STAGES`` (e.g. m3a flag false -> m2); an
      absent/empty flag dict has no effect.
    """
    mode = getattr(settings, "mode", "off") or "off"
    derived = derive_stage_from_mode(mode)
    explicit = getattr(settings, "stage", "") or ""
    stage = min_stage(derived, explicit or derived)
    flags = getattr(settings, "stage_flags", None) or {}
    if flags:
        rank = VDP_STAGE_RANKS.get(stage, 0)
        while rank > 0 and flags.get(VDP_STAGES[rank], True) is False:
            rank -= 1
        stage = VDP_STAGES[rank]
    return stage


def resolve_key_provider(settings) -> KeyProvider:
    """Resolve the signing-key provider from settings.

    Under enforce stages (M3a+): the provider must be explicitly ``env`` or
    ``file`` with the corresponding env var / file path non-empty;
    ``env_or_file`` is forbidden (no implicit fallback in production).
    Non-enforce: any provider is accepted (dev convenience).
    """
    stage = effective_stage(settings)
    provider_name = getattr(settings, "key_provider", "env") or "env"
    if is_enforce_stage(stage):
        if provider_name == "env_or_file":
            raise KeyConfigError("enforce_forbids_env_or_file_provider")
        if provider_name not in ("env", "file"):
            raise KeyConfigError("enforce_requires_explicit_key_provider")
        env_var = getattr(settings, "key_env_var", "") or ""
        file_path = getattr(settings, "key_file_path", "") or ""
        if provider_name == "env":
            if not env_var:
                raise KeyConfigError("enforce_key_env_var_unset")
            return EnvKeyProvider(env_var=env_var)
        if not file_path:
            raise KeyConfigError("enforce_key_file_path_unset")
        return FileKeyProvider(path=Path(file_path))
    env_var = getattr(settings, "key_env_var", "SHIGOKU_VDP_SIGNING_KEY") or "SHIGOKU_VDP_SIGNING_KEY"
    file_path = getattr(settings, "key_file_path", "") or ""
    if provider_name == "file":
        return FileKeyProvider(path=Path(file_path) if file_path else Path(""))
    if provider_name == "env_or_file":
        return EnvOrFileKeyProvider(
            env_var=env_var, file_path=Path(file_path) if file_path else None
        )
    return EnvKeyProvider(env_var=env_var)


def load_key_registry(settings) -> VdpKeyRegistry:
    """Load the key registry for ``settings``.

    Enforce stages require an explicit ``key_registry_path`` and a readable,
    well-formed registry (permission gate enforced). Non-enforce with an
    empty path yields an empty registry; a missing file in non-enforce is an
    empty registry (dev convenience, fail-closed).
    """
    stage = effective_stage(settings)
    registry_path = getattr(settings, "key_registry_path", "") or ""
    enforce = is_enforce_stage(stage)
    if enforce and not registry_path:
        raise KeyConfigError("enforce_requires_key_registry")
    if not registry_path:
        return VdpKeyRegistry()
    path = Path(registry_path)
    if not enforce and not path.exists():
        return VdpKeyRegistry()
    try:
        VdpKeyRegistry.check_registry_permissions(path)
        return VdpKeyRegistry.load(path)
    except KeyRegistryError as exc:
        raise KeyConfigError(str(exc)) from exc


def validate_key_config(settings, *, signing_key: Optional[bytes] = None) -> None:
    """Validate the resolved signing key against the enforce policy.

    Under enforce stages: the signing key MUST be present and MUST NOT be a
    test/dev seed (``TEST_KEY_DENYLIST``). Non-enforce: no-op.
    """
    stage = effective_stage(settings)
    if not is_enforce_stage(stage):
        return
    if signing_key is None:
        raise KeyConfigError("signing_key_unset_for_enforce")
    hex_key = signing_key.hex() if isinstance(signing_key, (bytes, bytearray)) else ""
    if hex_key in TEST_KEY_DENYLIST:
        raise KeyConfigError("test_key_in_production_config")


def configured_signer(settings) -> Optional["Ed25519EvidenceSigner"]:
    """Build the production signer from settings, or None (fail-closed).

    Steps:
    1. resolve the key provider (KeyConfigError propagates — the caller
       degrades to candidate/Hold instead of confirmed)
    2. load the signing key; when unavailable, enforce stages raise
       ``signing_key_unset_for_enforce``, non-enforce returns None
    3. load the key registry (KeyConfigError propagates)
    4. build the signer with the registry attached; a non-empty registry
       MUST contain the signer's key in ACTIVE state, else None. An empty
       registry (dev) auto-registers the signer's key as ACTIVE in the
       in-memory registry (dev parity with ``default_signer``).
    5. validate the key against the enforce policy (denylist).

    The lazy import of ``Ed25519EvidenceSigner`` avoids an import cycle.
    """
    from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner

    provider = resolve_key_provider(settings)
    key = provider.load_signing_key()
    if key is None:
        # Under enforce this raises; otherwise dev fail-closed (no signer).
        validate_key_config(settings, signing_key=None)
        return None
    registry = load_key_registry(settings)
    if registry.entries:
        signer = Ed25519EvidenceSigner(private_key=key, registry=registry)
        if registry.get_state(signer.key_id) != KeyState.ACTIVE:
            return None
    else:
        signer = Ed25519EvidenceSigner(private_key=key)
        registry.register(signer.key_id, signer.public_key_bytes())
    validate_key_config(settings, signing_key=key)
    return signer
