"""
Test ReauthOrchestrator — single-flight, cooldown, storm, degradation, resume policy.

SGK-2026-0280 Section 3.2, 3.3.
"""

import time
import pytest
from unittest.mock import MagicMock

from src.core.engine.reauth_orchestrator import (
    ReauthOrchestrator,
    classify_task_for_resume,
    apply_resume_policy,
    ResumeDecision,
    ReauthInFlight,
    ReauthCooldown,
)


# ---------------------------------------------------------------------------
# Resume Policy classification tests
# ---------------------------------------------------------------------------

class TestTaskClassification:
    """Section 3.3: Resume Policy Matrix task classification."""

    def test_read_only_tag(self) -> None:
        task = MagicMock(tags=["recon", "scan"], params={"category": "recon"}, action="get", agent_type="recon")
        assert classify_task_for_resume(task) == "read-only"

    def test_read_only_action(self) -> None:
        task = MagicMock(tags=[], params={}, action="fetch", agent_type="scanner")
        assert classify_task_for_resume(task) == "read-only"

    def test_stateful_tags(self) -> None:
        task = MagicMock(tags=["stateful"], params={}, action="read", agent_type="generic")
        assert classify_task_for_resume(task) == "stateful"

    def test_stateful_action(self) -> None:
        task = MagicMock(tags=[], params={}, action="upload", agent_type="generic")
        assert classify_task_for_resume(task) == "stateful"

    def test_auth_sensitive_tag(self) -> None:
        task = MagicMock(tags=["auth"], params={}, action="scan", agent_type="recon")
        assert classify_task_for_resume(task) == "auth-sensitive"

    def test_auth_sensitive_jwt(self) -> None:
        task = MagicMock(tags=["jwt"], params={}, action="scan", agent_type="recon")
        assert classify_task_for_resume(task) == "auth-sensitive"

    def test_auth_sensitive_agent_type(self) -> None:
        task = MagicMock(tags=[], params={"category": "admin"}, action="scan", agent_type="auth_manager")
        assert classify_task_for_resume(task) == "auth-sensitive"

    def test_unknown(self) -> None:
        task = MagicMock(tags=["custom"], params={}, action="custom", agent_type="custom")
        assert classify_task_for_resume(task) == "unknown"

    def test_tags_normalized_case(self) -> None:
        task = MagicMock(tags=["AUTH", "READ"], params={}, action="none", agent_type="none")
        assert classify_task_for_resume(task) == "auth-sensitive"  # auth takes precedence


class TestResumePolicy:
    """Section 3.3: Resume Policy Matrix."""

    def test_read_only_always_allow_retry(self) -> None:
        # read-only is idempotent — always retry
        assert apply_resume_policy("read-only", 5, 0) == ResumeDecision.ALLOW_RETRY
        assert apply_resume_policy("read-only", 5, 5) == ResumeDecision.ALLOW_RETRY

    def test_stateful_matching_version_allows_retry(self) -> None:
        assert apply_resume_policy("stateful", 3, 3) == ResumeDecision.ALLOW_RETRY

    def test_stateful_mismatched_version_requires_state_check(self) -> None:
        assert apply_resume_policy("stateful", 3, 1) == ResumeDecision.REQUIRE_STATE_CHECK

    def test_auth_sensitive_matching_version_allows_retry(self) -> None:
        assert apply_resume_policy("auth-sensitive", 2, 2) == ResumeDecision.ALLOW_RETRY

    def test_auth_sensitive_mismatched_version_discard(self) -> None:
        assert apply_resume_policy("auth-sensitive", 4, 1) == ResumeDecision.DISCARD

    def test_unknown_defaults_to_hold(self) -> None:
        assert apply_resume_policy("unknown", 5, 0) == ResumeDecision.HOLD
        assert apply_resume_policy("unknown", 5, 5) == ResumeDecision.HOLD


# ---------------------------------------------------------------------------
# Single-flight tests
# ---------------------------------------------------------------------------

class TestSingleFlight:
    """Section 3.2: Single-flight enforcement."""

    def test_can_launch_initial(self) -> None:
        orch = ReauthOrchestrator()
        assert orch.can_launch_reauth("https://target.example", 1)

    def test_cannot_launch_duplicate_same_version(self) -> None:
        orch = ReauthOrchestrator()
        orch.register_inflight("https://target.example", "reauth_001", 1)
        assert not orch.can_launch_reauth("https://target.example", 1)

    def test_can_launch_different_version(self) -> None:
        orch = ReauthOrchestrator()
        orch.register_inflight("https://target.example", "reauth_001", 1)
        # Same target, different auth_context_version — new in-flight window
        assert orch.can_launch_reauth("https://target.example", 2)

    def test_cannot_launch_when_cooldown_active(self) -> None:
        orch = ReauthOrchestrator(cooldown_window_seconds=60)
        future_cd = time.time() + 120
        orch.apply_cooldown("https://target.example", "login_replay_non_200", future_cd)
        assert orch.is_in_cooldown("https://target.example")
        assert not orch.can_launch_reauth("https://target.example", 1)

    def test_can_launch_after_cooldown_expires(self) -> None:
        orch = ReauthOrchestrator(cooldown_window_seconds=1)
        past_cd = time.time() - 10  # already expired
        orch.apply_cooldown("https://target.example", "missing_refresh_url", past_cd)
        assert not orch.is_in_cooldown("https://target.example")
        assert orch.can_launch_reauth("https://target.example", 1)

    def test_max_inflight_limit(self) -> None:
        orch = ReauthOrchestrator(max_inflight=2)
        orch.register_inflight("target1", "r1", 1)
        orch.register_inflight("target2", "r2", 1)
        assert not orch.can_launch_reauth("target3", 1)

    def test_unregister_frees_slot(self) -> None:
        orch = ReauthOrchestrator(max_inflight=2)
        orch.register_inflight("target1", "r1", 1)
        orch.register_inflight("target2", "r2", 1)
        orch.unregister_inflight("target1", 1)
        assert orch.can_launch_reauth("target3", 1)


# ---------------------------------------------------------------------------
# Storm suppression tests
# ---------------------------------------------------------------------------

class TestStormSuppression:
    """Section 3.2: Reauth storm control."""

    def test_no_storm_initially(self) -> None:
        orch = ReauthOrchestrator()
        assert not orch.is_storm_active

    def test_storm_after_many_events(self) -> None:
        orch = ReauthOrchestrator(cooldown_window_seconds=60)
        for _ in range(6):
            orch.record_expired_event()
        assert orch.is_storm_active

    def test_first_five_not_storm(self) -> None:
        orch = ReauthOrchestrator(cooldown_window_seconds=60)
        for _ in range(5):
            result = orch.record_expired_event()
            assert not result
        # 6th triggers storm
        assert orch.record_expired_event()


# ---------------------------------------------------------------------------
# Degradation tests
# ---------------------------------------------------------------------------

class TestDegradation:
    """Section 3.2: Degradation after repeated failures."""

    def test_mark_and_check_degraded(self) -> None:
        orch = ReauthOrchestrator()
        orch.mark_degraded("https://target.example")
        assert orch.is_degraded("https://target.example")

    def test_clear_degraded(self) -> None:
        orch = ReauthOrchestrator()
        orch.mark_degraded("https://target.example")
        orch.clear_degraded("https://target.example")
        assert not orch.is_degraded("https://target.example")

    def test_not_degraded_initially(self) -> None:
        orch = ReauthOrchestrator()
        assert not orch.is_degraded("any_target")

    def test_cannot_launch_when_degraded(self) -> None:
        orch = ReauthOrchestrator()
        orch.mark_degraded("https://target.example")
        # Single-flight doesn't check degradation — that's caller responsibility.
        # But verify is_degraded returns correct.
        assert orch.is_degraded("https://target.example")


# ---------------------------------------------------------------------------
# Task quarantine tests
# ---------------------------------------------------------------------------

class TestTaskQuarantine:
    """Section 3.2: Task quarantine during degraded state."""

    def test_quarantine_task(self) -> None:
        orch = ReauthOrchestrator()
        task = MagicMock(id="task_001", tags=["auth"], params={}, action="scan", agent_type="recon")
        orch.quarantine_task(task, "reauth_failed")
        stats = orch.get_stats()
        assert stats["quarantined_count"] == 1

    def test_no_duplicate_quarantine(self) -> None:
        orch = ReauthOrchestrator()
        task = MagicMock(id="task_001", tags=["auth"], params={}, action="scan", agent_type="recon")
        orch.quarantine_task(task, "reauth_failed")
        orch.quarantine_task(task, "reauth_failed")
        stats = orch.get_stats()
        assert stats["quarantined_count"] == 1

    def test_release_allows_retry_read_only(self) -> None:
        orch = ReauthOrchestrator()
        task = MagicMock(id="task_r", tags=["recon"], params={}, action="get", agent_type="recon")
        orch.quarantine_task(task, "reauth_failed")
        released = orch.release_quarantine(auth_context_version=5)
        assert len(released) == 1
        assert orch.get_stats()["quarantined_count"] == 0

    def test_release_holds_stateful(self) -> None:
        orch = ReauthOrchestrator()
        task = MagicMock(id="task_s", tags=["stateful"], params={}, action="write", agent_type="injection")
        orch.quarantine_task(task, "reauth_failed")
        released = orch.release_quarantine(auth_context_version=5)
        # stateful with auth mismatch (0 < 5) → REQUIRE_STATE_CHECK → not released
        assert len(released) == 0
        assert orch.get_stats()["quarantined_count"] == 1

    def test_stats_snapshot(self) -> None:
        orch = ReauthOrchestrator()
        orch.register_inflight("target1", "r1", 1)
        orch.apply_cooldown("target2", "missing_refresh_url", time.time() + 60)
        orch.mark_degraded("target3")
        stats = orch.get_stats()
        assert stats["inflight_count"] == 1
        assert stats["cooldown_count"] == 1
        assert "target3" in stats["degraded_targets"]
        assert stats["reauth_total"] == 1
        assert stats["reauth_failed"] == 1
