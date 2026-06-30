"""Phase 8 Step 2: Shadow parallel decision tests.

T-2.1 (Dispatcher shadow): 複数 Swarm 候補を shadow schedule しても実実行順は変えず、
parallel candidate / reject reason / state isolation status を記録する。

T-3.1 (Specialist shadow): specialist 候補ごとに parallel_safe, stateful, 
adaptive_skip_sensitive 等を記録し、High/Critical を返す specialist がある場合は実並列化しない。

Key constraint: shadow decisions are recorded ONLY. No execution order change.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.core.engine.swarm_dispatcher import SwarmDispatcher
from src.core.agents.swarm.base import SwarmManager, Specialist
from src.core.agents.swarm.base_manager import BaseManagerAgent
from src.core.models.swarm import SwarmResult
from src.core.models.finding import Finding, Severity, VulnType


# ============================================================================
# Helpers
# ============================================================================

def _shadow_entries(result):
    """Extract shadow_parallel_decision entries from SwarmResult.shadow_decisions."""
    if result is None:
        return []
    return result.shadow_decisions


def _make_result(findings=None, status="success", execution_log=None, swarm_name="test"):
    return SwarmResult(
        findings=findings or [],
        status=status,
        execution_log=execution_log or [],
        swarm_name=swarm_name,
        total_specialists=1,
        successful_specialists=1,
    )


# ============================================================================
# T-2.1: SwarmDispatcher shadow decisions
# ============================================================================


class TestSwarmDispatcherShadow:
    """SwarmDispatcher records shadow decisions per swarm without changing execution order."""

    @pytest.fixture
    def dispatcher(self):
        return SwarmDispatcher()

    def _make_swarm_mock(self, name: str, findings=None, status="success"):
        mock = AsyncMock()
        mock.name = name
        mock.close = AsyncMock()
        mock.dispatch = AsyncMock(return_value=_make_result(
            findings=findings or [],
            status=status,
            execution_log=[{"specialist": f"{name}_spec", "status": "success",
                            "findings_count": len(findings or [])}],
            swarm_name=name,
        ))
        return mock

    # --------------- T-2.1a: shadow entries exist in execution_log ---------------

    @pytest.mark.asyncio
    async def test_shadow_entries_present(self, dispatcher):
        """Each dispatched swarm produces a shadow decision entry in execution_log."""
        swarms = {
            "scanner": self._make_swarm_mock("scanner"),
        }
        with patch.object(dispatcher, "_get_or_create_swarm",
                          side_effect=lambda name: swarms[name]):
            result = await dispatcher.dispatch(
                tags=["ssl"], target="http://example.com/api",
            )

        shadows = _shadow_entries(result)
        assert len(shadows) >= 1, (
            f"No shadow entries in execution_log: {result.execution_log}"
        )
        for s in shadows:
            assert s["source_layer"] == "swarm_dispatcher", (
                f"Wrong source_layer: {s}"
            )

    # --------------- T-2.1b: shadow entries per swarm ---------------

    @pytest.mark.asyncio
    async def test_shadow_one_entry_per_swarm(self, dispatcher):
        """Each swarm dispatched gets exactly one shadow decision entry."""
        swarms = {
            "auth": self._make_swarm_mock("auth"),
            "scanner": self._make_swarm_mock("scanner"),
        }
        with patch.object(dispatcher, "_get_or_create_swarm",
                          side_effect=lambda name: swarms[name]):
            result = await dispatcher.dispatch(
                tags=["auth_endpoint", "ssl"], target="http://example.com/api",
            )

        shadows = _shadow_entries(result)
        source_units = {s["source_unit"] for s in shadows}
        assert source_units == {"auth", "scanner"}, (
            f"Expected shadow for auth+scanner, got: {source_units}"
        )

    # --------------- T-2.1c: execution order unchanged ---------------

    @pytest.mark.asyncio
    async def test_shadow_does_not_change_execution_order(self, dispatcher):
        """Shadow decisions must NOT change swarm execution order."""
        dispatch_order = []

        swarms = {
            "auth": self._make_swarm_mock("auth"),
            "injection": self._make_swarm_mock("injection"),
            "scanner": self._make_swarm_mock("scanner"),
        }

        def _record(name):
            dispatch_order.append(name)
            return swarms[name]

        with patch.object(dispatcher, "_get_or_create_swarm", side_effect=_record):
            await dispatcher.dispatch(
                tags=["auth_endpoint", "has_params", "ssl"],
                target="http://example.com/api",
            )

        # Order must still be auth > injection > scanner (serial)
        assert dispatch_order == ["auth", "injection", "scanner"], (
            f"Execution order changed: {dispatch_order}"
        )

    # --------------- T-2.1d: shadow schema ---------------

    @pytest.mark.asyncio
    async def test_shadow_entry_has_required_fields(self, dispatcher):
        """Each shadow entry has the required schema fields."""
        swarms = {"scanner": self._make_swarm_mock("scanner")}
        with patch.object(dispatcher, "_get_or_create_swarm",
                          side_effect=lambda name: swarms[name]):
            result = await dispatcher.dispatch(
                tags=["ssl"], target="http://example.com/api",
            )

        shadows = _shadow_entries(result)
        for s in shadows:
            required = {"type", "source_layer", "source_unit", "candidate",
                        "parallelism_type", "state_isolation"}
            for field in required:
                assert field in s, f"Missing field '{field}' in shadow entry: {s}"
            assert s["type"] == "shadow_parallel_decision"

    # --------------- T-2.1e: candidate classification ---------------

    @pytest.mark.asyncio
    async def test_shadow_candidate_for_stateless_swarm(self, dispatcher):
        """Stateless (plain SwarmManager) swarms are marked as parallel candidates."""
        swarms = {"scanner": self._make_swarm_mock("scanner")}
        with patch.object(dispatcher, "_get_or_create_swarm",
                          side_effect=lambda name: swarms[name]):
            result = await dispatcher.dispatch(
                tags=["ssl"], target="http://example.com/api",
            )

        shadows = _shadow_entries(result)
        scanner_shadow = [s for s in shadows if s["source_unit"] == "scanner"]
        assert len(scanner_shadow) > 0
        assert scanner_shadow[0]["candidate"] is True
        assert scanner_shadow[0]["parallelism_type"] == "read_only"
        assert scanner_shadow[0]["state_isolation"] is not None

    # --------------- T-2.1f: no secret leak ---------------

    @pytest.mark.asyncio
    async def test_shadow_no_secret_in_entry(self, dispatcher):
        """Shadow entries must not contain secrets, tokens, or credentials."""
        swarms = {"scanner": self._make_swarm_mock("scanner")}
        with patch.object(dispatcher, "_get_or_create_swarm",
                          side_effect=lambda name: swarms[name]):
            result = await dispatcher.dispatch(
                tags=["ssl"], target="http://example.com/api?token=secret123",
            )

        shadows = _shadow_entries(result)
        for s in shadows:
            shadow_str = str(s)
            assert "secret123" not in shadow_str
            assert "token" not in shadow_str.lower()
            assert "api_key" not in shadow_str.lower()
            assert "password" not in shadow_str.lower()

    # --------------- T-2.1g: no match = no shadow ---------------

    @pytest.mark.asyncio
    async def test_no_swarms_no_shadow_entries(self, dispatcher):
        """When no swarms match, no shadow entries are produced."""
        result = await dispatcher.dispatch(
            tags=["nonexistent"], target="http://example.com/api",
        )
        assert result is None


# ============================================================================
# T-3.1: SwarmManager specialist shadow decisions
# ============================================================================


class TestSwarmManagerShadow:
    """SwarmManager records shadow decisions per specialist without changing execution order."""

    def _make_specialist(self, name: str, findings=None, should_fail=False):
        spec = AsyncMock(spec=Specialist)
        spec.name = name
        spec.close = AsyncMock()
        spec.get_execution_time = MagicMock(return_value=0.1)
        if should_fail:
            spec.run_with_timeout = AsyncMock(
                side_effect=RuntimeError(f"{name} failure"))
        else:
            spec.run_with_timeout = AsyncMock(return_value=findings or [])
        return spec

    def _make_manager(self, specialists):
        SwarmManager.__abstractmethods__ = frozenset()
        mgr = SwarmManager(config={"max_concurrent_tasks": 1})
        mgr.name = "test_swarm"
        for s in specialists:
            mgr._specialists.append(s)
        mgr.get_specialists = MagicMock(return_value=specialists)
        return mgr

    def _make_finding(self, title="test", severity=Severity.CRITICAL):
        return Finding(
            vuln_type=VulnType.SQLI,
            target_url="http://example.com",
            title=title,
            severity=severity,
            description="test",
            source_agent="test_spec",
        )

    def _make_task(self, **params):
        task = MagicMock()
        task.tags = params.pop("tags", ["test"])
        task.params = params
        return task

    # --------------- T-3.1a: shadow entries per specialist ---------------

    @pytest.mark.asyncio
    async def test_shadow_entries_exist_per_specialist(self):
        """Each specialist produces a shadow decision entry."""
        s1 = self._make_specialist("spec1", findings=[])
        s2 = self._make_specialist("spec2", findings=[])

        mgr = self._make_manager([s1, s2])
        task = self._make_task()
        result = await mgr.dispatch(task)

        shadows = _shadow_entries(result)
        assert len(shadows) == 2, (
            f"Expected 2 shadow entries, got {len(shadows)}: {shadows}"
        )
        source_units = {s["source_unit"] for s in shadows}
        assert source_units == {"spec1", "spec2"}

    # --------------- T-3.1b: execution order unchanged ---------------

    @pytest.mark.asyncio
    async def test_shadow_does_not_change_specialist_order(self):
        """Shadow decisions must NOT change specialist execution order."""
        exec_order = []

        async def _record(task):
            exec_order.append("spec1")
            return []
        async def _record2(task):
            exec_order.append("spec2")
            return []

        s1 = self._make_specialist("spec1")
        s2 = self._make_specialist("spec2")
        s1.run_with_timeout = AsyncMock(side_effect=_record)
        s2.run_with_timeout = AsyncMock(side_effect=_record2)

        mgr = self._make_manager([s1, s2])
        task = self._make_task()
        await mgr.dispatch(task)

        assert exec_order == ["spec1", "spec2"], (
            f"Execution order changed: {exec_order}"
        )

    # --------------- T-3.1c: adaptive skip still works ---------------

    @pytest.mark.asyncio
    async def test_adaptive_skip_still_active_with_shadow(self):
        """Adaptive skip MUST still work when shadow decisions are recorded."""
        s1 = self._make_specialist("crit_finder",
                                    findings=[self._make_finding(severity=Severity.CRITICAL)])
        s2 = self._make_specialist("skipped_worker")

        mgr = self._make_manager([s1, s2])
        task = self._make_task(adaptive_skip_enabled=True)
        result = await mgr.dispatch(task)

        # s2 must NOT execute
        s2.run_with_timeout.assert_not_called()
        # execution_log must have "skipped" for s2
        skipped = [e for e in result.execution_log
                   if e.get("status") == "skipped"]
        assert len(skipped) == 1

    # --------------- T-3.1d: shadow entry schema ---------------

    @pytest.mark.asyncio
    async def test_shadow_entry_schema(self):
        """Each shadow entry has required fields with correct source_layer."""
        s1 = self._make_specialist("spec1", findings=[])
        mgr = self._make_manager([s1])
        task = self._make_task()
        result = await mgr.dispatch(task)

        shadows = _shadow_entries(result)
        assert len(shadows) >= 1
        s = shadows[0]
        assert s["type"] == "shadow_parallel_decision"
        assert s["source_layer"] == "swarm_manager"
        assert s["source_unit"] == "spec1"
        assert "candidate" in s
        assert "parallelism_type" in s

    # --------------- T-3.1e: all specialists adaptive_skip_sensitive in Phase 8 ---------------

    @pytest.mark.asyncio
    async def test_shadow_classifies_as_adaptive_skip_sensitive(self):
        """In Phase 8 shadow, all SwarmManager specialists are rejected as
        adaptive_skip_sensitive (per plan C3/LB-3)."""
        s1 = self._make_specialist("sqli_tester", findings=[])
        mgr = self._make_manager([s1])
        task = self._make_task()
        result = await mgr.dispatch(task)

        shadows = _shadow_entries(result)
        assert len(shadows) == 1
        s = shadows[0]
        # In Phase 8, all specialists are rejected for inner parallelism
        assert s["candidate"] is False, (
            f"Expected candidate=False for adaptive_skip_sensitive, got {s}"
        )
        assert "adaptive_skip" in s.get("rejection_reason", "").lower(), (
            f"Expected adaptive_skip in rejection_reason, got: {s}"
        )

    # --------------- T-3.1f: no secret leak from specialist ---------------

    @pytest.mark.asyncio
    async def test_shadow_no_secret_from_specialist(self):
        """Shadow entries from specialists must not contain secrets."""
        s1 = self._make_specialist("spec1", findings=[])
        mgr = self._make_manager([s1])
        # Task target may contain token
        task = self._make_task()
        task.target = "http://example.com/api?token=super_secret"
        result = await mgr.dispatch(task)

        shadows = _shadow_entries(result)
        for s in shadows:
            shadow_str = str(s)
            assert "super_secret" not in shadow_str
            assert "token" not in shadow_str.lower()

    # --------------- T-3.1g: shadow entries in dedicated field ---------------

    @pytest.mark.asyncio
    async def test_shadow_entries_in_dedicated_field(self):
        """Shadow decisions are in shadow_decisions, not mixed with execution_log."""
        s1 = self._make_specialist("spec1", findings=[])
        mgr = self._make_manager([s1])
        task = self._make_task()
        result = await mgr.dispatch(task)

        # execution_log must NOT contain shadow entries
        for entry in result.execution_log:
            assert entry.get("type") != "shadow_parallel_decision", (
                f"Shadow entry leaked into execution_log: {entry}"
            )
        # All execution_log entries should have "specialist" field
        for entry in result.execution_log:
            assert "specialist" in entry, (
                f"Non-specialist entry in execution_log: {entry}"
            )
        # shadow_decisions must contain the shadow entry
        assert len(result.shadow_decisions) == 1
        assert result.shadow_decisions[0]["type"] == "shadow_parallel_decision"
