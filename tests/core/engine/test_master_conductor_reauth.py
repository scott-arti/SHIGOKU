"""
Test MasterConductor Reauth Integration

SGK-2026-0280: integration tests for the full reauth flow:
  - Happy path: 401 -> reauth dispatch -> success -> context update
  - Failure path: REAUTH_FAILED -> cooldown -> degradation -> task quarantine
  - Duplicate 401 collapse (single-flight)
  - Storm suppression
  - Resume policy applied to quarantined tasks
"""

import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from types import SimpleNamespace

from src.core.engine.master_conductor import MasterConductor
from src.core.domain.model.task import Task, TaskState
from src.core.infra.event_bus import Event, EventType
from src.core.agents.swarm.auth.reauth_contracts import generate_reauth_attempt_id


# ---------------------------------------------------------------------------
# Minimal MC factory (following existing _new_mc_with_min_context pattern)
# ---------------------------------------------------------------------------

def _new_mc_reauth() -> MasterConductor:
    """Build a minimal MasterConductor with reauth orchestrator support.

    This uses __new__ + selective field injection to avoid the full DI
    maze in MasterConductor.__init__.
    """
    mc = MasterConductor.__new__(MasterConductor)
    mc.completed_tasks = []
    mc.task_queue = MagicMock()
    mc.task_queue.get_all = MagicMock(return_value=[])
    mc.pending_hitl = []
    mc.context = SimpleNamespace(
        discovered_assets=[],
        bypass_methods=[],
        metrics={"estimated_cost": 0.0, "total_duration": 0},
        target_info={"required_vuln_families": ["api"]},
    )
    mc._derived_task_count = 0
    mc._checkpoint_counter = 0
    mc._react_observation_metrics = {"attempted": 0, "executed": 0, "skipped": 0, "skip_reasons": {}}
    mc._react_observation_inflight = 0

    # State lock
    import threading
    mc._state_lock = threading.RLock()

    # Accumulated context
    from src.core.engine.task_queue import TaskContext
    mc.accumulated_context = TaskContext()

    # Reauth orchestrator (fresh)
    from src.core.engine.reauth_orchestrator import ReauthOrchestrator
    from src.core.agents.swarm.auth.reauth_contracts import AuthContext
    mc.reauth_orchestrator = ReauthOrchestrator(
        cooldown_window_seconds=60.0,
        max_inflight=3,
    )
    mc._auth_ctx = AuthContext()

    # Event bus mock
    mc.event_bus = MagicMock()
    mc.event_bus.emit = AsyncMock()
    mc.event_bus.subscribe = MagicMock()

    # LLM client mock
    mc.llm_client = MagicMock()

    # Project manager mock
    mc.project_manager = MagicMock()
    mc.project_manager.config = {}

    # Run ledger mock
    from src.core.models.run_ledger import RunLedgerRecorder, RunLedgerEventType
    mc.run_ledger_recorder = MagicMock(spec=RunLedgerRecorder)

    # Shared loop mock
    mc._get_loop = MagicMock(return_value=MagicMock())

    # Reauth _handle_session_expired needs SwarmDispatcher
    mc.network_client = MagicMock()
    mc.network_client.request = AsyncMock()

    return mc


# ---------------------------------------------------------------------------
# Happy path: SESSION_EXPIRED -> dispatch -> REAUTH_SUCCESS -> context update
# ---------------------------------------------------------------------------

class TestReauthHappyPath:
    @pytest.mark.asyncio
    async def test_session_expired_dispatches_reauth(self) -> None:
        mc = _new_mc_reauth()
        reauth_id = generate_reauth_attempt_id()

        with patch("src.core.engine.swarm_dispatcher.get_swarm_dispatcher") as mock_disp:
            mock_dispatcher = AsyncMock()
            mock_disp.return_value = mock_dispatcher

            event = Event(
                type=EventType.SESSION_EXPIRED,
                payload={
                    "url": "https://target.example/api/data",
                    "method": "GET",
                    "request_headers": {"Authorization": "Bearer old"},
                    "origin_task_id": "task_001",
                    "reauth_attempt_id": reauth_id,
                    "auth_context_version": 1,
                },
                source="AsyncNetworkClient",
            )

            await mc._handle_session_expired(event)

            # Verify dispatch was called
            assert mock_dispatcher.dispatch.called
            call_args = mock_dispatcher.dispatch.call_args
            assert call_args.kwargs.get("tags") == ["auth", "reauth"]
            assert call_args.kwargs.get("target") == "https://target.example/api/data"

            # Verify auth context updated
            assert mc._auth_ctx.last_auth_error == "401_unauthorized"
            assert mc.accumulated_context.auth_tokens["last_auth_error"] == "401_unauthorized"

    @pytest.mark.asyncio
    async def test_reauth_success_updates_context_and_releases_tasks(self) -> None:
        mc = _new_mc_reauth()

        # Pre-quarantine a task
        task = Task(id="task_q", name="quarantined", tags=["recon"], action="get", agent_type="recon")
        mc.reauth_orchestrator.quarantine_task(task, "reauth_failed")

        # Add a mock _add_tasks
        mc._add_tasks = MagicMock()

        event = Event(
            type=EventType.REAUTH_SUCCESS,
            payload={
                "target": "https://target.example",
                "reauth_attempt_id": generate_reauth_attempt_id(),
                "method": "token_refresh",
                "new_tokens": {"access_token": "new_token_123"},
                "updated_cookies": {"session": "new_session_456"},
                "auth_context_version": 2,
                "success_evidence": {"probe_status": 200},
            },
            source="AutoReauthSpecialist",
        )

        await mc._handle_reauth_success(event)

        # Verify tokens updated
        assert mc.accumulated_context.auth_tokens["access_token"] == "new_token_123"
        assert mc.accumulated_context.auth_tokens["cookie_session"] == "new_session_456"
        assert mc._auth_ctx.last_auth_status == "restored"
        assert mc._auth_ctx.auth_context_version >= 2

        # Verify quarantined task released
        mc._add_tasks.assert_called_once()
        released_tasks = mc._add_tasks.call_args[0][0]
        assert len(released_tasks) == 1
        assert released_tasks[0].id == "task_q"


# ---------------------------------------------------------------------------
# Failure path: REAUTH_FAILED -> cooldown + degradation + quarantine
# ---------------------------------------------------------------------------

class TestReauthFailurePath:
    @pytest.mark.asyncio
    async def test_reauth_failed_applies_cooldown(self) -> None:
        mc = _new_mc_reauth()

        event = Event(
            type=EventType.REAUTH_FAILED,
            payload={
                "target": "https://target.example",
                "reauth_attempt_id": generate_reauth_attempt_id(),
                "reason_code": "token_extraction_failed",
                "reason_detail": "No token in refresh response",
                "attempted_strategies": ["token_refresh"],
                "cooldown_until": time.time() + 60,
            },
            source="AutoReauthSpecialist",
        )

        await mc._handle_reauth_failed(event)

        assert mc.reauth_orchestrator.is_in_cooldown("https://target.example")
        assert mc._auth_ctx.last_auth_status == "failed"
        assert mc._auth_ctx.last_auth_error == "token_extraction_failed"

    @pytest.mark.asyncio
    async def test_consecutive_failures_trigger_degradation(self) -> None:
        mc = _new_mc_reauth()

        # Force the failure counter to 3
        mc.reauth_orchestrator._reauth_count_failed = 3

        event = Event(
            type=EventType.REAUTH_FAILED,
            payload={
                "target": "https://target.example",
                "reauth_attempt_id": generate_reauth_attempt_id(),
                "reason_code": "login_replay_non_200",
                "reason_detail": "Login returned 403",
                "attempted_strategies": ["login_replay"],
                "cooldown_until": time.time() + 60,
            },
            source="AutoReauthSpecialist",
        )

        await mc._handle_reauth_failed(event)

        assert mc.reauth_orchestrator.is_degraded("https://target.example")

    @pytest.mark.asyncio
    async def test_pending_auth_tasks_are_quarantined_on_failure(self) -> None:
        """Regression: REAUTH_FAILED 時に task_queue 内の auth-sensitive タスクが隔離される"""
        mc = _new_mc_reauth()

        # Set up pending tasks in task_queue.get_all()
        auth_task = Task(
            id="pending_auth_task", name="auth_scan",
            target="https://target.example/admin",
            tags=["auth"], agent_type="auth_manager", action="scan",
        )
        read_task = Task(
            id="pending_recon_task", name="recon_scan",
            target="https://target.example/api",
            tags=["recon"], agent_type="recon", action="get",
        )
        stateful_task = Task(
            id="pending_stateful_task", name="stateful_write",
            target="https://target.example/order",
            tags=["stateful"], agent_type="injection", action="write",
        )
        mc.task_queue.get_all = MagicMock(return_value=[auth_task, read_task, stateful_task])

        # Bump auth context version so that version mismatch triggers DISCARD / REQUIRE_STATE_CHECK
        mc._auth_ctx.auth_context_version = 3

        event = Event(
            type=EventType.REAUTH_FAILED,
            payload={
                "target": "https://target.example",
                "reauth_attempt_id": generate_reauth_attempt_id(),
                "reason_code": "token_extraction_failed",
                "reason_detail": "No token found",
                "attempted_strategies": ["token_refresh"],
                "cooldown_until": time.time() + 60,
            },
            source="AutoReauthSpecialist",
        )

        await mc._handle_reauth_failed(event)

        stats = mc.reauth_orchestrator.get_stats()
        # auth-sensitive (auth_task) → DISCARD → quarantined
        # read-only (read_task) → ALLOW_RETRY (read-only is always retry) → NOT quarantined
        # stateful (stateful_task) → REQUIRE_STATE_CHECK (version mismatch) → quarantined
        assert stats["quarantined_count"] == 2, f"Expected 2 quarantined, got {stats['quarantined_count']}"


# ---------------------------------------------------------------------------
# Single-flight (duplicate 401 collapse)
# ---------------------------------------------------------------------------

class TestSingleFlightInMasterConductor:
    @pytest.mark.asyncio
    async def test_second_401_blocked_when_inflight(self) -> None:
        mc = _new_mc_reauth()

        # Register an in-flight reauth
        mc.reauth_orchestrator.register_inflight("https://target.example", "reauth_inflight", 1)

        with patch("src.core.engine.swarm_dispatcher.get_swarm_dispatcher") as mock_disp:
            mock_dispatcher = AsyncMock()
            mock_disp.return_value = mock_dispatcher

            event = Event(
                type=EventType.SESSION_EXPIRED,
                payload={
                    "url": "https://target.example",
                    "method": "GET",
                    "request_headers": {},
                    "origin_task_id": "task_002",
                    "reauth_attempt_id": generate_reauth_attempt_id(),
                    "auth_context_version": 1,
                },
                source="AsyncNetworkClient",
            )

            await mc._handle_session_expired(event)

            # Dispatcher should NOT be called (single-flight blocked)
            assert not mock_dispatcher.dispatch.called


# ---------------------------------------------------------------------------
# Storm suppression
# ---------------------------------------------------------------------------

class TestStormSuppressionInMasterConductor:
    @pytest.mark.asyncio
    async def test_storm_suppresses_reauth(self) -> None:
        mc = _new_mc_reauth()

        # Trigger storm by recording many events
        for _ in range(6):
            mc.reauth_orchestrator.record_expired_event()

        assert mc.reauth_orchestrator.is_storm_active

        with patch("src.core.engine.swarm_dispatcher.get_swarm_dispatcher") as mock_disp:
            mock_dispatcher = AsyncMock()
            mock_disp.return_value = mock_dispatcher

            event = Event(
                type=EventType.SESSION_EXPIRED,
                payload={
                    "url": "https://target.example",
                    "method": "GET",
                    "request_headers": {},
                    "origin_task_id": "task_003",
                    "reauth_attempt_id": generate_reauth_attempt_id(),
                    "auth_context_version": 1,
                },
                source="AsyncNetworkClient",
            )

            await mc._handle_session_expired(event)

            # Dispatcher should NOT be called (storm suppressed)
            assert not mock_dispatcher.dispatch.called


# ---------------------------------------------------------------------------
# Cooldown blocks re-dispatch
# ---------------------------------------------------------------------------

class TestCooldownInMasterConductor:
    @pytest.mark.asyncio
    async def test_cooldown_blocks_reauth_dispatch(self) -> None:
        mc = _new_mc_reauth()

        # Apply a fresh cooldown
        mc.reauth_orchestrator.apply_cooldown(
            "https://target.example", "login_replay_non_200", time.time() + 120
        )

        with patch("src.core.engine.swarm_dispatcher.get_swarm_dispatcher") as mock_disp:
            mock_dispatcher = AsyncMock()
            mock_disp.return_value = mock_dispatcher

            event = Event(
                type=EventType.SESSION_EXPIRED,
                payload={
                    "url": "https://target.example",
                    "method": "GET",
                    "request_headers": {},
                    "origin_task_id": "task_004",
                    "reauth_attempt_id": generate_reauth_attempt_id(),
                    "auth_context_version": 1,
                },
                source="AsyncNetworkClient",
            )

            await mc._handle_session_expired(event)

            assert not mock_dispatcher.dispatch.called


# ---------------------------------------------------------------------------
# Degradation blocks re-dispatch
# ---------------------------------------------------------------------------

class TestDegradationInMasterConductor:
    @pytest.mark.asyncio
    async def test_degraded_target_blocks_reauth(self) -> None:
        mc = _new_mc_reauth()

        mc.reauth_orchestrator.mark_degraded("https://target.example")

        with patch("src.core.engine.swarm_dispatcher.get_swarm_dispatcher") as mock_disp:
            mock_dispatcher = AsyncMock()
            mock_disp.return_value = mock_dispatcher

            event = Event(
                type=EventType.SESSION_EXPIRED,
                payload={
                    "url": "https://target.example",
                    "method": "GET",
                    "request_headers": {},
                    "origin_task_id": "task_005",
                    "reauth_attempt_id": generate_reauth_attempt_id(),
                    "auth_context_version": 1,
                },
                source="AsyncNetworkClient",
            )

            await mc._handle_session_expired(event)

            assert not mock_dispatcher.dispatch.called
