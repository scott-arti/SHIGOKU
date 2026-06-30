"""
Phase 7 Control-Plane Tests (SGK-2026-0316).

Tests:
  - State assertion start boundary: mutating task with stale auth → skipped before RUNNING
  - State assertion start boundary: healthy task → passes
  - Origin suppressor: aggressive lane suppress + release
  - Kill switch: serial revert for parallel-safe tasks
  - Degraded origin audit payload
"""
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor
from src.core.engine.lane_policy import LanePolicy


def _make_task(task_id: str, agent_type: str = "scanner", metadata: dict | None = None) -> Task:
    return Task(
        id=task_id,
        name=f"test-{task_id}",
        agent_type=agent_type,
        metadata=metadata or {},
    )


class TestPhase7StateAssertionStartBoundary:
    """Task 1: State assertion evaluated before TaskState.RUNNING."""

    def test_mutating_task_with_stale_auth_assertion_is_skipped_before_running(self):
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc._get_current_snapshot_versions = lambda: (0, 3)
        task = Task(
            id="mut-stale",
            name="mut-stale",
            agent_type="attack_auth",
            metadata={
                "lane": "mutating",
                "auth_context_version": 2,
                "state_assertion": {
                    "precondition": "fresh_auth_context",
                    "postcondition": "no_persistent_side_effect",
                },
            },
        )

        result = mc._evaluate_phase7_state_assertion_before_start(task)

        assert result["skipped"] is True
        assert result["skip_reason"] == "state_assertion_stale_auth_context"
        assert task.metadata["lifecycle_status"] == "rejected"

    def test_mutating_task_with_fresh_auth_passes_assertion(self):
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc._get_current_snapshot_versions = lambda: (0, 3)
        task = Task(
            id="mut-fresh",
            name="mut-fresh",
            agent_type="attack_auth",
            metadata={
                "lane": "mutating",
                "auth_context_version": 3,
                "state_assertion": {
                    "precondition": "fresh_auth_context",
                    "postcondition": "no_persistent_side_effect",
                },
            },
        )

        result = mc._evaluate_phase7_state_assertion_before_start(task)

        assert result is None
        assert task.metadata["state_assertion_audit"]["assertion_result"] == "passed"

    def test_read_only_task_skips_state_assertion(self):
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc._get_current_snapshot_versions = lambda: (0, 3)
        task = Task(
            id="read-1",
            name="read-1",
            agent_type="default",
            metadata={"lane": "read_only"},
        )

        result = mc._evaluate_phase7_state_assertion_before_start(task)

        assert result is None

    def test_mutating_task_with_missing_assertion_is_rejected(self):
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc._get_current_snapshot_versions = lambda: (0, 3)
        task = Task(
            id="mut-no-assert",
            name="mut-no-assert",
            agent_type="attack_auth",
            metadata={"lane": "mutating"},
        )

        result = mc._evaluate_phase7_state_assertion_before_start(task)

        assert result["skipped"] is True
        assert result["skip_reason"] == "state_assertion_precondition_missing"


class TestPhase7OriginSuppressor:
    """Task 2: Aggressive origin suppress controller."""

    def test_suppressor_blocks_other_lanes_until_released(self):
        from src.core.engine.origin_suppressor import OriginSuppressor

        suppressor = OriginSuppressor()
        suppressor.enter("https://example.com", lane="aggressive_exclusive", owner_task_id="aggr-1")

        decision = suppressor.check("https://example.com", lane="read_only", task_id="read-1")

        assert decision.allowed is False
        assert decision.reason_code == "origin_suppressed_by_aggressive"
        assert decision.owner_task_id == "aggr-1"

        suppressor.release("https://example.com", owner_task_id="aggr-1")
        assert suppressor.check("https://example.com", lane="read_only", task_id="read-1").allowed is True

    def test_suppressor_does_not_block_same_origin_aggressive(self):
        from src.core.engine.origin_suppressor import OriginSuppressor

        suppressor = OriginSuppressor()
        suppressor.enter("https://example.com", lane="aggressive_exclusive", owner_task_id="aggr-1")

        decision = suppressor.check("https://example.com", lane="aggressive_exclusive", task_id="aggr-2")

        assert decision.allowed is True

    def test_suppressor_allows_different_origin(self):
        from src.core.engine.origin_suppressor import OriginSuppressor

        suppressor = OriginSuppressor()
        suppressor.enter("https://a.example.com", lane="aggressive_exclusive", owner_task_id="aggr-1")

        decision = suppressor.check("https://b.example.com", lane="read_only", task_id="read-1")

        assert decision.allowed is True

    def test_suppressor_empty_origin_key_allows(self):
        from src.core.engine.origin_suppressor import OriginSuppressor

        suppressor = OriginSuppressor()
        suppressor.enter("https://example.com", lane="aggressive_exclusive", owner_task_id="aggr-1")

        decision = suppressor.check("", lane="read_only", task_id="read-1")

        assert decision.allowed is True

    def test_suppressor_release_wrong_owner_does_not_release(self):
        from src.core.engine.origin_suppressor import OriginSuppressor

        suppressor = OriginSuppressor()
        suppressor.enter("https://example.com", lane="aggressive_exclusive", owner_task_id="aggr-1")

        suppressor.release("https://example.com", owner_task_id="wrong-owner")

        decision = suppressor.check("https://example.com", lane="read_only", task_id="read-1")
        assert decision.allowed is False


class TestPhase7MCIntegration:
    """Integration tests for MC dispatch gate suppress wiring."""

    def test_origin_suppressor_lazy_init(self):
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()

        suppressor = mc._ensure_origin_suppressor()

        assert suppressor is not None
        assert suppressor is mc._ensure_origin_suppressor()

    def test_dispatch_batch_suppresses_read_only_when_origin_has_active_aggressive_owner(self):
        """Phase 7: _dispatch_batch rejects read_only task when origin is suppressed by aggressive owner."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        mc._execute_single_task_full_flow = MagicMock(return_value={"success": True})

        # Lane policy returns read_only + parallel_safe for the scanner task
        lp = MagicMock(spec=LanePolicy)
        lp.classify.return_value = ("read_only", True, False, None, False, "test")
        mc._lane_policy = lp

        # Manually enter aggressive owner before dispatch
        mc._ensure_origin_suppressor().enter(
            "https://target.com", lane="aggressive_exclusive", owner_task_id="aggr-1",
        )

        read_task = Task(id="read-1", name="read-1", agent_type="scanner",
                         metadata={"origin_key": "https://target.com"})

        with patch("src.core.engine.master_conductor.settings") as mock_settings:
            mock_settings.parallelism = SimpleNamespace(enabled=True, kill_switch=False)
            result = mc._dispatch_batch([read_task], force_serial=False)

        assert result["parallel_tasks"] == []
        assert "read-1" in result["rejected_task_ids"]
        assert read_task.metadata["lifecycle_status"] == "rejected"
        assert read_task.metadata["lifecycle_reason"] == "origin_suppressed_by_aggressive"
        assert read_task.metadata["suppressed_by"] == "aggr-1"

    def test_dispatch_batch_clears_suppression_after_aggressive_release(self):
        """After aggressive owner releases origin, read_only tasks pass."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        mc._execute_single_task_full_flow = MagicMock(return_value={"success": True})

        lp = MagicMock(spec=LanePolicy)
        lp.classify.return_value = ("read_only", True, False, None, False, "test")
        mc._lane_policy = lp

        # Enter then release
        suppressor = mc._ensure_origin_suppressor()
        suppressor.enter("https://target.com", lane="aggressive_exclusive", owner_task_id="aggr-1")
        suppressor.release("https://target.com", owner_task_id="aggr-1")

        read_task = Task(id="read-1", name="read-1", agent_type="scanner",
                         metadata={"origin_key": "https://target.com"})

        with patch("src.core.engine.master_conductor.settings") as mock_settings:
            mock_settings.parallelism = SimpleNamespace(enabled=True, kill_switch=False)
            result = mc._dispatch_batch([read_task], force_serial=False)

        assert len(result["parallel_tasks"]) == 1
        assert result["rejected_task_ids"] == []

    def test_dispatch_batch_enters_aggressive_suppress_before_serial_execution(self):
        """When aggressive_exclusive task runs serially, enter() is called before execution."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc._execute_single_task_full_flow = MagicMock(return_value={"success": True})

        lp = MagicMock(spec=LanePolicy)
        lp.classify.return_value = ("aggressive_exclusive", False, False, None, False, "test")
        mc._lane_policy = lp

        aggr_task = Task(id="aggr-1", name="aggr-1", agent_type="aggressive",
                         metadata={"origin_key": "https://target.com"})

        with patch("src.core.engine.master_conductor.settings") as mock_settings:
            mock_settings.parallelism = SimpleNamespace(enabled=True, kill_switch=False)
            result = mc._dispatch_batch([aggr_task], force_serial=False)

        # Assert task was executed serially
        assert "aggr-1" in result["serial_task_ids"]
        mc._execute_single_task_full_flow.assert_called_once_with(aggr_task)
        # After execution, the suppressor should be released
        suppressor = mc._ensure_origin_suppressor()
        decision = suppressor.check("https://target.com", lane="read_only", task_id="read-1")
        assert decision.allowed is True

    def test_dispatch_batch_releases_aggressive_owner_after_serial_exception(self):
        """Even if serial execution of aggressive task raises, release() is called in finally."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc._execute_single_task_full_flow = MagicMock(side_effect=RuntimeError("boom"))

        lp = MagicMock(spec=LanePolicy)
        lp.classify.return_value = ("aggressive_exclusive", False, False, None, False, "test")
        mc._lane_policy = lp

        aggr_task = Task(id="aggr-1", name="aggr-1", agent_type="aggressive",
                         metadata={"origin_key": "https://target.com"})

        with patch("src.core.engine.master_conductor.settings") as mock_settings:
            mock_settings.parallelism = SimpleNamespace(enabled=True, kill_switch=False)
            with pytest.raises(RuntimeError, match="boom"):
                mc._dispatch_batch([aggr_task], force_serial=False)

        # After exception, the suppressor should be released
        suppressor = mc._ensure_origin_suppressor()
        decision = suppressor.check("https://target.com", lane="read_only", task_id="read-1")
        assert decision.allowed is True

    def test_dispatch_batch_suppresses_stateful_read_when_origin_has_active_aggressive_owner(self):
        """T-4.1: stateful_read lane is suppressed when origin has active aggressive owner."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc._execute_single_task_full_flow = MagicMock(return_value={"success": True})

        lp = MagicMock(spec=LanePolicy)
        lp.classify.return_value = ("stateful_read", False, False, None, False, "test")
        mc._lane_policy = lp

        mc._ensure_origin_suppressor().enter(
            "https://target.com", lane="aggressive_exclusive", owner_task_id="aggr-1",
        )

        stateful_task = Task(id="stateful-1", name="stateful-1", agent_type="stateful",
                             metadata={"origin_key": "https://target.com"})

        with patch("src.core.engine.master_conductor.settings") as mock_settings:
            mock_settings.parallelism = SimpleNamespace(enabled=True, kill_switch=False)
            result = mc._dispatch_batch([stateful_task], force_serial=False)

        assert "stateful-1" in result["rejected_task_ids"]
        assert result["serial_task_ids"] == []
        assert stateful_task.metadata["lifecycle_status"] == "rejected"
        assert stateful_task.metadata["lifecycle_reason"] == "origin_suppressed_by_aggressive"
        mc._execute_single_task_full_flow.assert_not_called()

    def test_dispatch_batch_suppresses_mutating_when_origin_has_active_aggressive_owner(self):
        """T-4.1: mutating lane is suppressed when origin has active aggressive owner."""
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc._execute_single_task_full_flow = MagicMock(return_value={"success": True})

        lp = MagicMock(spec=LanePolicy)
        lp.classify.return_value = ("mutating", False, False, None, False, "test")
        mc._lane_policy = lp

        mc._ensure_origin_suppressor().enter(
            "https://target.com", lane="aggressive_exclusive", owner_task_id="aggr-1",
        )

        mut_task = Task(id="mut-1", name="mut-1", agent_type="mutating",
                        metadata={"origin_key": "https://target.com"})

        with patch("src.core.engine.master_conductor.settings") as mock_settings:
            mock_settings.parallelism = SimpleNamespace(enabled=True, kill_switch=False)
            result = mc._dispatch_batch([mut_task], force_serial=False)

        assert "mut-1" in result["rejected_task_ids"]
        assert result["serial_task_ids"] == []
        assert mut_task.metadata["lifecycle_status"] == "rejected"
        assert mut_task.metadata["lifecycle_reason"] == "origin_suppressed_by_aggressive"
        mc._execute_single_task_full_flow.assert_not_called()


class TestPhase7KillSwitch:
    """Task 4: Kill switch serial revert for parallel-safe tasks."""

    def test_phase7_kill_switch_forces_serial_revert_for_parallel_safe_task(self):
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc._lane_policy = MagicMock(spec=LanePolicy)
        mc._lane_policy.classify.return_value = ("read_only", True, False, None, False, "test")
        mc._execute_single_task_full_flow = MagicMock(return_value={"success": True})
        task = Task(id="read-1", name="read-1", agent_type="default", metadata={})

        with patch("src.core.engine.master_conductor.settings") as mock_settings:
            mock_settings.parallelism = SimpleNamespace(enabled=True, kill_switch=True)
            result = mc._dispatch_batch([task], force_serial=mock_settings.parallelism.kill_switch)

        assert result["parallel_tasks"] == []
        assert result["serial_task_ids"] == ["read-1"]
        mc._execute_single_task_full_flow.assert_called_once_with(task)

    def test_phase7_kill_switch_off_allows_parallel_safe_to_parallel(self):
        mc = MasterConductor.__new__(MasterConductor)
        mc._state_lock = threading.RLock()
        mc._lane_policy = MagicMock(spec=LanePolicy)
        mc._lane_policy.classify.return_value = ("read_only", True, False, None, False, "test")
        mc._execute_single_task_full_flow = MagicMock(return_value={"success": True})
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        task = Task(id="read-1", name="read-1", agent_type="scanner", metadata={})

        with patch("src.core.engine.master_conductor.settings") as mock_settings:
            mock_settings.parallelism = SimpleNamespace(enabled=True, kill_switch=False)
            result = mc._dispatch_batch([task], force_serial=False)

        assert result["parallel_tasks"] != []
        assert len(result["parallel_tasks"]) == 1
        assert result["parallel_tasks"][0].id == "read-1"
        assert result["serial_task_ids"] == []


class TestPhase7DegradedOriginAudit:
    """Task 3: Degraded origin suppress result has audit payload."""

    @pytest.mark.asyncio
    async def test_degraded_origin_result_contains_audit_payload(self):
        from src.core.engine.adaptive_rate_limiter import AdaptiveRateLimiter
        from src.core.engine.parallel_orchestrator import ParallelOrchestrator, create_parallel_task

        orch = ParallelOrchestrator()
        limiter = AdaptiveRateLimiter(blocking_degrade_threshold=1)
        limiter.on_response(403, target="https://example.com")
        orch._rate_limiters["default"] = limiter

        result = await orch.execute_parallel([
            create_parallel_task("t1", lambda: {"status": 200}, origin_key="https://example.com")
        ])

        assert result[0].success is False
        assert result[0].error == "origin_degraded:blocking_signal_threshold"
        assert result[0].result["audit"]["degrade_reason"] == "blocking_signal_threshold"
        assert result[0].result["audit"]["event"] == "origin_suppressed"
        assert result[0].result["audit"]["origin_key"] == "https://example.com"
