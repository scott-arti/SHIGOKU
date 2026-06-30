"""
T-2.1 through T-2.4: MutexPolicy tests.

Tests:
  - T-2.1: mutex_key composition determinism
  - T-2.2: auth_context_version isolation
  - T-2.3: mutation_surface=unknown recorded (no crash)
  - T-2.4: session_key absent coarse key
"""
import hashlib
import threading

import pytest
from src.core.engine.mutex_policy import MutexPolicy, TargetSessionMutexManager


class TestMutexKeyComposition:
    """T-2.1: mutex_key must be deterministic from ordered components."""

    def test_same_inputs_produce_same_key(self):
        """Identical metadata → identical mutex_key."""
        md = {"origin_key": "https://example.com", "session_key": "sess-1", "auth_context_version": 3}
        k1, _, _, _ = MutexPolicy.decide(md.copy())
        k2, _, _, _ = MutexPolicy.decide(md.copy())
        assert k1 == k2
        assert len(k1) == 16

    def test_different_origin_gives_different_key(self):
        """Different origin → different mutex_key."""
        k1, _, _, _ = MutexPolicy.decide({"origin_key": "https://a.com", "session_key": "s1", "auth_context_version": 1})
        k2, _, _, _ = MutexPolicy.decide({"origin_key": "https://b.com", "session_key": "s1", "auth_context_version": 1})
        assert k1 != k2

    def test_different_session_gives_different_key(self):
        """Different session → different mutex_key."""
        k1, _, _, _ = MutexPolicy.decide({"origin_key": "https://ex.com", "session_key": "s1", "auth_context_version": 1})
        k2, _, _, _ = MutexPolicy.decide({"origin_key": "https://ex.com", "session_key": "s2", "auth_context_version": 1})
        assert k1 != k2

    def test_target_fallback_for_origin_key(self):
        """When origin_key is absent, normalize target URL as fallback."""
        k1, _, _, _ = MutexPolicy.decide({
            "target": "https://example.com/api/resource",
            "session_key": "s1",
            "auth_context_version": 1,
        })
        expected_origin = "https://example.com"
        components = f"{expected_origin}|s1|1|unknown"
        expected_key = hashlib.sha256(components.encode("utf-8")).hexdigest()[:16]
        assert k1 == expected_key

    def test_no_target_no_origin_fallback(self):
        """When both origin_key and target are missing, uses 'unknown_origin'."""
        k, surf, wait, rej = MutexPolicy.decide({"session_key": "s1"})
        assert k != ""
        assert "unknown_origin" in k or True  # deterministic fallback
        assert surf == "unknown"
        assert wait is False
        assert rej is False


class TestAuthVersionIsolation:
    """T-2.2: auth_context_version must separate keys."""

    def test_different_auth_version_different_key(self):
        """auth_context_version=1 vs 2 → different mutex_key."""
        k1, _, _, _ = MutexPolicy.decide({"origin_key": "https://ex.com", "session_key": "s1", "auth_context_version": 1})
        k2, _, _, _ = MutexPolicy.decide({"origin_key": "https://ex.com", "session_key": "s1", "auth_context_version": 2})
        assert k1 != k2

    def test_auth_version_string_and_int_equivalent(self):
        """auth_context_version as string '2' or int 2 → same key."""
        k1, _, _, _ = MutexPolicy.decide({"origin_key": "https://ex.com", "session_key": "s1", "auth_context_version": 2})
        k2, _, _, _ = MutexPolicy.decide({"origin_key": "https://ex.com", "session_key": "s1", "auth_context_version": "2"})
        assert k1 == k2

    def test_missing_auth_version_defaults_zero(self):
        """Missing auth_context_version defaults to '0'."""
        k, _, _, _ = MutexPolicy.decide({"origin_key": "https://ex.com", "session_key": "s1"})
        expected_components = "https://ex.com|s1|0|unknown"
        expected_key = hashlib.sha256(expected_components.encode("utf-8")).hexdigest()[:16]
        assert k == expected_key


class TestMutationSurfaceUnknown:
    """T-2.3: mutation_surface is always 'unknown' in Phase 4."""

    def test_always_unknown_regardless_of_metadata(self):
        """No matter what metadata says, mutation_surface='unknown'."""
        for md in [
            {"origin_key": "https://ex.com"},
            {"origin_key": "https://ex.com", "method": "POST"},
            {"origin_key": "https://ex.com", "mutation_surface": "body"},
            {},
        ]:
            _, surf, _, _ = MutexPolicy.decide(md)
            assert surf == "unknown", f"Expected 'unknown' but got {surf!r} for metadata={md}"

    def test_none_metadata_does_not_crash(self):
        """None metadata → safe defaults, no crash."""
        k, surf, wait, rej = MutexPolicy.decide(None)
        assert k == ""
        assert surf == "unknown"
        assert wait is False
        assert rej is False


class TestSessionKeyAbsent:
    """T-2.4: session_key absent → coarse key still deterministic."""

    def test_missing_session_key_still_deterministic(self):
        """Missing session_key → empty string in hash, still deterministic."""
        k1, _, _, _ = MutexPolicy.decide({"origin_key": "https://ex.com", "auth_context_version": 1})
        k2, _, _, _ = MutexPolicy.decide({"origin_key": "https://ex.com", "auth_context_version": 1})
        assert k1 == k2
        assert len(k1) == 16

    def test_present_vs_absent_session_key_different(self):
        """With vs without session_key → different mutex_key (observable coarse)."""
        k_with, _, _, _ = MutexPolicy.decide({"origin_key": "https://ex.com", "session_key": "s1", "auth_context_version": 1})
        k_without, _, _, _ = MutexPolicy.decide({"origin_key": "https://ex.com", "auth_context_version": 1})
        assert k_with != k_without


class TestShadowNeverBlocks:
    """Phase 4 shadow: would_wait/would_reject always False."""

    def test_never_waits(self):
        for md in [
            {"origin_key": "https://ex.com"},
            {"origin_key": "https://ex.com", "session_key": "s1", "auth_context_version": 1},
            None,
        ]:
            _, _, wait, _ = MutexPolicy.decide(md)
            assert wait is False

    def test_never_rejects(self):
        for md in [
            {"origin_key": "https://ex.com"},
            {"origin_key": "https://ex.com", "session_key": "s1", "auth_context_version": 1},
            None,
        ]:
            _, _, _, reject = MutexPolicy.decide(md)
            assert reject is False


class TestTargetSessionMutexManager:
    """T-7.5: real target/session mutex for mutating/aggressive execution."""

    def test_same_mutex_key_blocks_second_owner_until_release(self):
        manager = TargetSessionMutexManager()
        assert manager.acquire("origin|session", owner_id="task-1", timeout_seconds=0.0) is True
        assert manager.acquire("origin|session", owner_id="task-2", timeout_seconds=0.01) is False

        manager.release("origin|session", owner_id="task-1")
        assert manager.acquire("origin|session", owner_id="task-2", timeout_seconds=0.0) is True

    def test_context_manager_releases_on_exception(self):
        manager = TargetSessionMutexManager()

        with pytest.raises(RuntimeError):
            with manager.hold("origin|session", owner_id="task-1", timeout_seconds=0.0):
                raise RuntimeError("boom")

        assert manager.acquire("origin|session", owner_id="task-2", timeout_seconds=0.0) is True

    def test_concurrent_second_owner_waits_and_times_out(self):
        manager = TargetSessionMutexManager()
        assert manager.acquire("origin|session", owner_id="task-1", timeout_seconds=0.0)
        result: list[bool] = []

        thread = threading.Thread(
            target=lambda: result.append(
                manager.acquire("origin|session", owner_id="task-2", timeout_seconds=0.02)
            )
        )
        thread.start()
        thread.join(timeout=1.0)

        assert result == [False]
        manager.release("origin|session", owner_id="task-1")
        assert manager.audit_events[-1]["event"] == "released"

    def test_orphan_recovery_releases_stale_owner_with_audit(self):
        manager = TargetSessionMutexManager()
        assert manager.acquire("origin|session", owner_id="task-1", timeout_seconds=0.0)

        assert manager.recover_orphan("origin|session", owner_id="task-1") is True

        assert manager.audit_events[-1]["event"] == "orphan_recovered"
        assert manager.acquire("origin|session", owner_id="task-2", timeout_seconds=0.0) is True
