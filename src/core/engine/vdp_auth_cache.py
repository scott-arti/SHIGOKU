"""
VDP Auth Cache — SGK-2026-0419 Item 10 (HMAC upgrade).

Purpose-built auth cache that prevents stale credential reuse.

The critical design decision: the cache key includes an HMAC-SHA256 tag of the
actual credential value, keyed with a module-level secret key. When a credential
changes (different tag), the cache MUST NOT return a stale result from a previous
credential. The HMAC key provides cryptographic blinding — even if the hash
function is known, an attacker cannot precompute credential tags.

Usage::

    from src.core.engine.vdp_auth_cache import AuthCache, AuthCacheKey

    cache = AuthCache()
    key = AuthCacheKey(
        credential="my-jwt-token",
        actor="unauthenticated",
        auth_context_version="v1",
        scope="https://api.example.com",
    )
    result = cache.get(key)
    if result is None:
        result = perform_expensive_auth_check(...)
        cache.set(key, result)
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

# Module-level HMAC secret key — generated once at module load, never exposed.
_AUTH_CACHE_HMAC_KEY = secrets.token_bytes(32)

# Backward-compatible: keep plain SHA-256 reference for tests that inspect
# credential_hash directly on AuthCacheKey.
_AUTH_CACHE_HASH_FN = hashlib.sha256


def _compute_credential_tag(credential: str) -> str:
    """Compute HMAC-SHA256 tag of a credential using the module-level secret key.

    Returns hex digest string (64 chars).
    """
    credential_bytes = credential.encode("utf-8")
    tag = hmac.new(_AUTH_CACHE_HMAC_KEY, credential_bytes, _AUTH_CACHE_HASH_FN).hexdigest()
    return tag


@dataclass(frozen=True)
class AuthCacheKey:
    """Immutable cache key for auth-sensitive results.

    The ``_credential_tag`` is an HMAC-SHA256 hex digest of the actual credential
    value, keyed with a module-level secret key. This ensures that changing a
    credential inherently changes the key, so stale cache entries are never reused.
    The HMAC key provides cryptographic blinding — even if SHA-256 is known,
    an attacker cannot precompute tags.

    The caller passes ``credential: str`` (raw), NOT a pre-computed hash.
    The tag is computed internally and never exposed to the caller.

    Fields:
        actor: The actor performing the auth (e.g. "unauthenticated",
            "authenticated_user_a").
        auth_context_version: Version of the auth context/session.
        scope: The target scope (e.g. URL or resource identifier).
        _credential_tag: HMAC-SHA256 hex digest of the credential value (64 chars).
            Private — computed internally, never visible to callers.
    """
    actor: str = ""
    auth_context_version: str = ""
    scope: str = ""
    _credential_tag: str = field(default="", repr=False, compare=False)

    def __init__(
        self,
        credential: str = "",
        actor: str = "",
        auth_context_version: str = "",
        scope: str = "",
    ):
        """Initialize AuthCacheKey from raw credential string.

        Args:
            credential: Raw credential string (e.g. JWT token, API key).
                An empty string maps to an empty-credential HMAC tag.
                This is the ONLY way to initialize the key — pre-computed
                hashes are NOT accepted.
            actor: Actor identifier.
            auth_context_version: Auth context version.
            scope: Target scope.

        Raises:
            TypeError: If ``credential`` is not a string.
        """
        if not isinstance(credential, str):
            raise TypeError(
                f"credential must be a string, got {type(credential).__name__}. "
                "Pre-computed hashes are not accepted. Pass the raw credential value."
            )
        tag = _compute_credential_tag(credential)
        object.__setattr__(self, "_credential_tag", tag)
        object.__setattr__(self, "actor", actor)
        object.__setattr__(self, "auth_context_version", auth_context_version)
        object.__setattr__(self, "scope", scope)

    def __hash__(self) -> int:
        return hash((self.actor, self.auth_context_version, self.scope, self._credential_tag))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AuthCacheKey):
            return NotImplemented
        return (
            self.actor == other.actor
            and self.auth_context_version == other.auth_context_version
            and self.scope == other.scope
            and self._credential_tag == other._credential_tag
        )

    @classmethod
    def from_credential(
        cls,
        credential_value: str,
        actor: str = "",
        auth_context_version: str = "",
        scope: str = "",
    ) -> "AuthCacheKey":
        """Create a cache key from a raw credential value.

        The credential is HMAC-SHA256-tagged internally; the raw value is
        not stored in the key.

        Args:
            credential_value: The credential string (e.g. JWT token, API key).
                An empty string maps to an empty-credential HMAC tag.
            actor: Actor identifier.
            auth_context_version: Auth context version.
            scope: Target scope.

        Returns:
            AuthCacheKey with HMAC-SHA256 hex digest of credential_value.
        """
        return cls(
            credential=credential_value,
            actor=actor,
            auth_context_version=auth_context_version,
            scope=scope,
        )


class AuthCache:
    """Thread-safe cache for auth-sensitive lookups.

    Cache keys are ``AuthCacheKey`` which include credential_hash.
    This inherently ensures that credential rotation invalidates
    stale entries — a different credential produces a different key.

    Features:
    - ``get(key)`` / ``set(key, value)``: basic ops.
    - ``invalidate_for_scope(scope)``: remove all entries for a given scope.
    - Thread-safe via internal lock.
    """

    def __init__(self):
        self._store: Dict[AuthCacheKey, Any] = {}
        from threading import Lock
        self._lock = Lock()

    def get(self, key: AuthCacheKey) -> Optional[Any]:
        """Retrieve a cached auth result.

        Args:
            key: AuthCacheKey including credential_hash.

        Returns:
            Cached value if present, None if not cached.
        """
        with self._lock:
            return self._store.get(key)

    def set(self, key: AuthCacheKey, value: Any) -> None:
        """Store an auth result.

        Args:
            key: AuthCacheKey to store under.
            value: Any serializable value (e.g. auth check result dict).
        """
        with self._lock:
            self._store[key] = value

    def invalidate_for_scope(self, scope: str) -> int:
        """Remove all cache entries for a given scope.

        Args:
            scope: The scope string to invalidate.

        Returns:
            Number of entries removed.
        """
        with self._lock:
            to_remove = [k for k in self._store if k.scope == scope]
            for k in to_remove:
                del self._store[k]
            return len(to_remove)

    def invalidate_for_actor(self, actor: str) -> int:
        """Remove all cache entries for a given actor.

        Args:
            actor: The actor identifier to invalidate.

        Returns:
            Number of entries removed.
        """
        with self._lock:
            to_remove = [k for k in self._store if k.actor == actor]
            for k in to_remove:
                del self._store[k]
            return len(to_remove)

    def clear(self) -> None:
        """Clear the entire cache."""
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)
