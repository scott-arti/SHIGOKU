"""
SGK-2026-0419 Item 10: VDP Auth Cache tests.

Tests cover:
- Different credential hash → cache miss (no stale reuse)
- Same credential hash → cache hit
- Cache invalidation by scope
- Empty credential edge cases
"""
from __future__ import annotations

from src.core.engine.vdp_auth_cache import AuthCache, AuthCacheKey


class TestAuthCacheDifferentCredentialHash:
    """The cache MUST NOT return a stale result when credential changes."""

    def test_different_credential_hash_returns_miss(self):
        cache = AuthCache()

        key1 = AuthCacheKey.from_credential(
            credential_value="token-v1-abc123",
            actor="user_a",
            scope="https://api.example.com",
        )
        key2 = AuthCacheKey.from_credential(
            credential_value="token-v2-xyz789",  # different credential
            actor="user_a",
            scope="https://api.example.com",
        )

        # Store result for credential v1
        cache.set(key1, {"authenticated": True, "user": "alice"})

        # Query with credential v2 — must MISS (different hash)
        result = cache.get(key2)
        assert result is None, (
            "Cache returned a stale result from a different credential. "
            "Different credential hashes must produce different cache keys."
        )

    def test_same_credential_hash_returns_hit(self):
        cache = AuthCache()

        key = AuthCacheKey.from_credential(
            credential_value="my-secret-token",
            actor="user_a",
            scope="https://api.example.com",
        )

        # Store result
        cache.set(key, {"authenticated": True})

        # Same key → hit
        result = cache.get(key)
        assert result is not None
        assert result["authenticated"] is True

    def test_different_actor_with_same_credential_different_key(self):
        """Same credential but different actor should be different keys."""
        cache = AuthCache()

        key_user_a = AuthCacheKey.from_credential(
            credential_value="shared-token",
            actor="user_a",
            scope="https://api.example.com",
        )
        key_user_b = AuthCacheKey.from_credential(
            credential_value="shared-token",
            actor="user_b",  # different actor
            scope="https://api.example.com",
        )

        cache.set(key_user_a, {"role": "admin"})

        # user_b with same token → MISS (different key due to actor)
        result = cache.get(key_user_b)
        assert result is None


class TestAuthCacheInvalidateScope:
    """invalidate_for_scope must remove all entries for a scope."""

    def test_invalidate_scope_removes_all_matching_entries(self):
        cache = AuthCache()

        key1 = AuthCacheKey.from_credential(
            credential_value="token1",
            scope="https://api.example.com",
        )
        key2 = AuthCacheKey.from_credential(
            credential_value="token2",
            scope="https://api.example.com",
        )
        key3 = AuthCacheKey.from_credential(
            credential_value="token3",
            scope="https://other.example.com",
        )

        cache.set(key1, "value1")
        cache.set(key2, "value2")
        cache.set(key3, "value3")

        # Invalidate scope "https://api.example.com"
        removed = cache.invalidate_for_scope("https://api.example.com")
        assert removed == 2

        # Entries for invalidated scope are gone
        assert cache.get(key1) is None
        assert cache.get(key2) is None

        # Entry for other scope is preserved
        assert cache.get(key3) == "value3"

    def test_invalidate_nonexistent_scope_returns_zero(self):
        cache = AuthCache()

        key = AuthCacheKey.from_credential(
            credential_value="token",
            scope="https://example.com",
        )
        cache.set(key, "value")

        removed = cache.invalidate_for_scope("https://nonexistent.com")
        assert removed == 0
        assert cache.get(key) == "value"


class TestAuthCacheMisc:
    """Edge cases and utility methods."""

    def test_empty_credential_produces_different_hash(self):
        """Empty credential should produce a different HMAC tag from non-empty."""
        key_empty = AuthCacheKey.from_credential(
            credential_value="",
            scope="https://example.com",
        )
        key_token = AuthCacheKey.from_credential(
            credential_value="some-token",
            scope="https://example.com",
        )

        assert key_empty._credential_tag != key_token._credential_tag

    def test_cache_clear_removes_all_entries(self):
        cache = AuthCache()

        key1 = AuthCacheKey.from_credential("token1", scope="s1")
        key2 = AuthCacheKey.from_credential("token2", scope="s2")

        cache.set(key1, "v1")
        cache.set(key2, "v2")
        assert len(cache) == 2

        cache.clear()
        assert len(cache) == 0
        assert cache.get(key1) is None
        assert cache.get(key2) is None

    def test_auth_cache_key_is_hashable(self):
        """AuthCacheKey must be hashable (frozen=True dataclass)."""
        key = AuthCacheKey(
            credential="some-token",
            actor="user",
            scope="https://example.com",
        )
        # Should not raise
        _ = hash(key)
        d = {key: 42}
        assert d[key] == 42

    def test_same_values_produce_same_key(self):
        """Same credential value should produce the same hash."""
        key_a = AuthCacheKey.from_credential(
            credential_value="secret-123",
            actor="u1",
            scope="s1",
        )
        key_b = AuthCacheKey.from_credential(
            credential_value="secret-123",
            actor="u1",
            scope="s1",
        )
        assert key_a == key_b
        assert hash(key_a) == hash(key_b)
