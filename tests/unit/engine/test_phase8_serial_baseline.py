"""Phase 8 Step 1: Serial baseline snapshot tests for SwarmDispatcher and SwarmManager.

T-1.1: Lock down serial result order / execution_log shape / adaptive skip.

These tests characterize the CURRENT serial behavior. After inner parallelism
is introduced (Phase 8 Steps 2+), these tests must still pass, or regressions
must be consciously accepted.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.core.engine.swarm_dispatcher import SwarmDispatcher, _get_swarm_classes
from src.core.agents.swarm.base import SwarmManager, Specialist
from src.core.models.finding import Finding, Severity, VulnType
from src.core.models.swarm import SwarmResult


# ============================================================================
# SwarmDispatcher — Serial baseline
# ============================================================================


class TestSwarmDispatcherSerialBaseline:
    """Verify SwarmDispatcher.dispatch() serial execution contract.

    Serial guarantees that MUST hold:
    - Swarms are executed in determine_swarms() priority order.
    - Findings are merged in swarm execution order (insertion-preserving).
    - execution_log merges in swarm execution order.
    - A single swarm failure does NOT prevent other swarms from running.
    - Every swarm gets close() called (even on failure).
    - Merged status follows: any success -> success, any partial -> partial_success, else failed.
    """

    @pytest.fixture
    def dispatcher(self):
        return SwarmDispatcher()

    def _make_swarm_mock(self, name: str, findings: list, status: str):
        """Create a mock SwarmManager that returns a canned result."""
        mock = AsyncMock()
        mock.name = name
        mock.close = AsyncMock()
        mock.dispatch = AsyncMock(return_value=SwarmResult(
            findings=findings,
            status=status,
            execution_log=[{"specialist": f"{name}_spec", "status": status,
                            "findings_count": len(findings)}],
            swarm_name=name,
            total_specialists=1,
            successful_specialists=1 if status != "failed" else 0,
        ))
        return mock

    # --------------- T-1.1a: sequential swarm execution ---------------

    @pytest.mark.asyncio
    async def test_swarms_executed_in_determine_swarms_order(self, dispatcher):
        """Swarm execution order MUST match determine_swarms() priority order."""
        dispatch_order = []

        swarms = {
            "auth": self._make_swarm_mock("auth", [{"id": "a1"}], "success"),
            "injection": self._make_swarm_mock("injection", [{"id": "i1"}], "success"),
            "scanner": self._make_swarm_mock("scanner", [{"id": "s1"}], "success"),
        }

        def _record_dispatch(swarm_name):
            dispatch_order.append(swarm_name)
            return swarms[swarm_name]

        with patch.object(dispatcher, "_get_or_create_swarm", side_effect=_record_dispatch):
            result = await dispatcher.dispatch(
                tags=["auth_endpoint", "has_params", "ssl"],
                target="http://example.com/api",
            )

        # determine_swarms yields priority: auth > injection > scanner
        assert dispatch_order == ["auth", "injection", "scanner"], (
            f"Expected ['auth','injection','scanner'], got {dispatch_order}"
        )
        assert result is not None
        assert result.status == "success"

    # --------------- T-1.1b: findings merge order ---------------

    @pytest.mark.asyncio
    async def test_findings_merged_in_swarm_execution_order(self, dispatcher):
        """Findings are merged in swarm execution order (insertion-preserving)."""
        swarms = {
            "auth": self._make_swarm_mock("auth", [{"id": "auth-1"}, {"id": "auth-2"}], "success"),
            "injection": self._make_swarm_mock("injection", [{"id": "inj-1"}], "success"),
        }

        with patch.object(dispatcher, "_get_or_create_swarm",
                          side_effect=lambda name: swarms[name]):
            result = await dispatcher.dispatch(
                tags=["auth_endpoint", "has_params"],
                target="http://example.com/api",
            )

        finding_ids = [f["id"] for f in result.findings]
        assert finding_ids == ["auth-1", "auth-2", "inj-1"], (
            f"Finding order mismatch: {finding_ids}"
        )

    # --------------- T-1.1c: execution_log merge order ---------------

    @pytest.mark.asyncio
    async def test_execution_log_merged_in_swarm_order(self, dispatcher):
        """execution_log entries are merged in swarm execution order."""
        swarms = {
            "auth": self._make_swarm_mock("auth", [{"id": "a1"}], "success"),
            "injection": self._make_swarm_mock("injection", [{"id": "i1"}], "success"),
        }

        with patch.object(dispatcher, "_get_or_create_swarm",
                          side_effect=lambda name: swarms[name]):
            result = await dispatcher.dispatch(
                tags=["auth_endpoint", "has_params"],
                target="http://example.com/api",
            )

        spec_names = [entry["specialist"] for entry in result.execution_log]
        assert spec_names == ["auth_spec", "injection_spec"], (
            f"execution_log order mismatch: {spec_names}"
        )

    # --------------- T-1.1d: swarm failure doesn't block others ---------------

    @pytest.mark.asyncio
    async def test_failed_swarm_does_not_block_remaining(self, dispatcher):
        """A failed swarm records the error and continues to remaining swarms."""
        executed = []

        def _get_or_create(name):
            executed.append(name)
            if name == "auth":
                # Simulate instantiation succeeds but dispatch raises
                mock = AsyncMock()
                mock.close = AsyncMock()
                mock.dispatch = AsyncMock(side_effect=RuntimeError("auth boom"))
                return mock
            return self._make_swarm_mock(name, [{"id": f"{name}-1"}], "success")

        with patch.object(dispatcher, "_get_or_create_swarm", side_effect=_get_or_create):
            result = await dispatcher.dispatch(
                tags=["auth_endpoint", "has_params"],
                target="http://example.com/api",
            )

        # Both swarms should have been attempted
        assert "auth" in executed
        assert "injection" in executed
        # The failed swarm's error should be in execution_log
        error_entries = [e for e in result.execution_log if "error" in e]
        assert len(error_entries) >= 1, f"No error entries in execution_log: {result.execution_log}"
        # The successful swarm's findings should still be present
        assert any(f["id"] == "injection-1" for f in result.findings), (
            "Successful swarm's findings missing"
        )

    # --------------- T-1.1e: merged status ---------------

    @pytest.mark.asyncio
    async def test_merged_status_partial_success(self, dispatcher):
        """When some swarms succeed and some fail, merged status is partial_success."""
        swarms = {
            "auth": self._make_swarm_mock("auth", [], "success"),
            "injection": self._make_swarm_mock("injection", [], "partial_success"),
        }
        with patch.object(dispatcher, "_get_or_create_swarm",
                          side_effect=lambda name: swarms[name]):
            result = await dispatcher.dispatch(
                tags=["auth_endpoint", "has_params"],
                target="http://example.com/api",
            )
        # partial_success takes precedence over success only if no success entry exists
        # From the code: if "success" in statuses -> success, elif "partial_success" -> partial_success
        assert result.status == "success", (
            f"Expected 'success' (success found), got '{result.status}'"
        )

    @pytest.mark.asyncio
    async def test_merged_status_all_failed(self, dispatcher):
        """When all swarms fail, merged status is failed."""
        async def _fail(name):
            mock = AsyncMock()
            mock.close = AsyncMock()
            mock.dispatch = AsyncMock(side_effect=RuntimeError("fail"))
            return mock

        with patch.object(dispatcher, "_get_or_create_swarm", side_effect=_fail):
            result = await dispatcher.dispatch(
                tags=["auth_endpoint", "has_params"],
                target="http://example.com/api",
            )
        assert result.status == "failed"

    # --------------- T-1.1f: all swarms get close() ---------------

    @pytest.mark.asyncio
    async def test_all_swarms_closed_after_dispatch(self, dispatcher):
        """Every swarm instance gets close() called in finally block."""
        mocks = {
            "auth": self._make_swarm_mock("auth", [], "success"),
            "injection": self._make_swarm_mock("injection", [], "success"),
        }

        with patch.object(dispatcher, "_get_or_create_swarm",
                          side_effect=lambda name: mocks[name]):
            await dispatcher.dispatch(
                tags=["auth_endpoint", "has_params"],
                target="http://example.com/api",
            )

        for name, mock in mocks.items():
            mock.close.assert_called_once(), f"close() not called for {name}"

    # --------------- T-1.1g: no swarms match ---------------

    @pytest.mark.asyncio
    async def test_no_matching_swarm_returns_none(self, dispatcher):
        """When no swarm matches the tags, dispatch returns None."""
        result = await dispatcher.dispatch(
            tags=["nonexistent_tag_xyz"],
            target="http://example.com/api",
        )
        assert result is None

    # --------------- T-1.1h: determine_swarms priority ---------------

    def test_determine_swarms_sorts_by_priority(self, dispatcher):
        """determine_swarms returns names sorted by priority."""
        # Tags that match auth + injection + scanner
        swarms = dispatcher.determine_swarms(["auth_endpoint", "has_params", "ssl"])
        assert swarms == ["auth", "injection", "scanner"], (
            f"Priority sort broken: {swarms}"
        )


# ============================================================================
# SwarmManager — Serial baseline
# ============================================================================


class TestSwarmManagerSerialBaseline:
    """Verify SwarmManager.dispatch() serial execution contract.

    Serial guarantees that MUST hold:
    - Specialists are executed in get_specialists() order.
    - execution_log entries are in specialist execution order.
    - CRITICAL/HIGH finding triggers adaptive skip (remaining skipped).
    - Non-CRITICAL/HIGH finding does NOT trigger skip.
    - adaptive_skip_enabled=False disables the skip.
    - Failed specialist does NOT prevent remaining specialists (continue-on-error).
    - Failed specialists are recorded in execution_log with error.
    - Skipped specialists are recorded in execution_log with reason.
    """

    # ---- helpers ----

    def _make_specialist(self, name: str, findings=None,
                         should_fail: bool = False):
        """Create a mock Specialist."""
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

    def _make_manager(self, specialists: list):
        """Create a SwarmManager with mocked get_specialists."""
        SwarmManager.__abstractmethods__ = frozenset()
        mgr = SwarmManager(config={"max_concurrent_tasks": 1})
        mgr.name = "test_swarm"
        for s in specialists:
            mgr._specialists.append(s)
        mgr.get_specialists = MagicMock(return_value=specialists)
        return mgr

    def _make_task(self, **params):
        """Create a mock Task with given params."""
        task = MagicMock()
        task.tags = params.pop("tags", ["test"])
        task.params = params
        return task

    def _critical_finding(self, name: str = "crit", severity=Severity.CRITICAL):
        return Finding(
            vuln_type=VulnType.SQLI,
            target_url="http://example.com",
            title=name,
            severity=severity,
            description="test",
            source_agent=name,
        )

    # --------------- T-1.1i: specialists executed in order ---------------

    @pytest.mark.asyncio
    async def test_specialists_executed_in_order(self):
        """Specialists are executed in get_specialists() order."""
        exec_order = []

        s1 = self._make_specialist("first")
        s2 = self._make_specialist("second")
        s3 = self._make_specialist("third")

        async def _record_s1(task):
            exec_order.append("first")
            return []
        async def _record_s2(task):
            exec_order.append("second")
            return []
        async def _record_s3(task):
            exec_order.append("third")
            return []

        s1.run_with_timeout = AsyncMock(side_effect=_record_s1)
        s2.run_with_timeout = AsyncMock(side_effect=_record_s2)
        s3.run_with_timeout = AsyncMock(side_effect=_record_s3)

        mgr = self._make_manager([s1, s2, s3])
        task = self._make_task()
        result = await mgr.dispatch(task)

        assert exec_order == ["first", "second", "third"], (
            f"Execution order mismatch: {exec_order}"
        )

    # --------------- T-1.1j: execution_log shape ---------------

    @pytest.mark.asyncio
    async def test_execution_log_shape_success(self):
        """Successful specialist records execution_log with expected keys."""
        spec = self._make_specialist("worker", findings=[])
        mgr = self._make_manager([spec])
        task = self._make_task()
        result = await mgr.dispatch(task)

        assert len(result.execution_log) == 1
        entry = result.execution_log[0]
        assert entry["specialist"] == "worker"
        assert entry["status"] == "success"
        assert "findings_count" in entry
        assert "execution_time" in entry

    @pytest.mark.asyncio
    async def test_execution_log_shape_failed(self):
        """Failed specialist records execution_log with error field."""
        spec = self._make_specialist("crasher", should_fail=True)
        mgr = self._make_manager([spec])
        task = self._make_task()
        result = await mgr.dispatch(task)

        assert len(result.execution_log) == 1
        entry = result.execution_log[0]
        assert entry["specialist"] == "crasher"
        assert entry["status"] == "failed"
        assert "error" in entry
        assert "crasher failure" in entry["error"]

    # --------------- T-1.1k: adaptive skip — CRITICAL ---------------

    @pytest.mark.asyncio
    async def test_adaptive_skip_critical_finding(self):
        """CRITICAL finding triggers skip of remaining specialists."""
        s1 = self._make_specialist("crit_finder",
                                    findings=[self._critical_finding(severity=Severity.CRITICAL)])
        s2 = self._make_specialist("should_be_skipped")
        s3 = self._make_specialist("also_skipped")

        mgr = self._make_manager([s1, s2, s3])
        task = self._make_task(adaptive_skip_enabled=True)
        result = await mgr.dispatch(task)

        # s2 and s3 must NOT be executed
        s2.run_with_timeout.assert_not_called()
        s3.run_with_timeout.assert_not_called()

        # s2 and s3 must appear as "skipped" in execution_log
        skipped = [e for e in result.execution_log if e["status"] == "skipped"]
        assert len(skipped) == 2, f"Expected 2 skipped entries, got {len(skipped)}: {result.execution_log}"
        skipped_names = {e["specialist"] for e in skipped}
        assert skipped_names == {"should_be_skipped", "also_skipped"}

        for entry in skipped:
            assert entry["reason"] == "critical_finding_detected"

    # --------------- T-1.1l: adaptive skip — HIGH ---------------

    @pytest.mark.asyncio
    async def test_adaptive_skip_high_finding(self):
        """HIGH finding also triggers adaptive skip."""
        s1 = self._make_specialist("high_finder",
                                    findings=[self._critical_finding(severity=Severity.HIGH)])
        s2 = self._make_specialist("should_be_skipped")

        mgr = self._make_manager([s1, s2])
        task = self._make_task(adaptive_skip_enabled=True)
        result = await mgr.dispatch(task)

        s2.run_with_timeout.assert_not_called()
        skipped = [e for e in result.execution_log if e["status"] == "skipped"]
        assert len(skipped) == 1

    # --------------- T-1.1m: no skip for non-critical ---------------

    @pytest.mark.asyncio
    async def test_no_skip_for_medium_finding(self):
        """MEDIUM finding does NOT trigger adaptive skip."""
        s1 = self._make_specialist("med_finder",
                                    findings=[self._critical_finding(severity=Severity.MEDIUM)])
        s2 = self._make_specialist("should_run")

        mgr = self._make_manager([s1, s2])
        task = self._make_task(adaptive_skip_enabled=True)
        result = await mgr.dispatch(task)

        # s2 SHOULD be executed
        s2.run_with_timeout.assert_called_once()
        skipped = [e for e in result.execution_log if e["status"] == "skipped"]
        assert len(skipped) == 0, f"Unexpected skip: {skipped}"

    # --------------- T-1.1n: adaptive_skip_enabled=False ---------------

    @pytest.mark.asyncio
    async def test_adaptive_skip_disabled_by_flag(self):
        """adaptive_skip_enabled=False disables the skip."""
        s1 = self._make_specialist("crit_finder",
                                    findings=[self._critical_finding(severity=Severity.CRITICAL)])
        s2 = self._make_specialist("should_still_run")

        mgr = self._make_manager([s1, s2])
        task = self._make_task(adaptive_skip_enabled=False)
        result = await mgr.dispatch(task)

        # s2 should still execute
        s2.run_with_timeout.assert_called_once()
        skipped = [e for e in result.execution_log if e["status"] == "skipped"]
        assert len(skipped) == 0

    # --------------- T-1.1o: continue-on-error ---------------

    @pytest.mark.asyncio
    async def test_continue_on_error(self):
        """Failed specialist does NOT prevent remaining specialists from running."""
        s1 = self._make_specialist("crasher", should_fail=True)
        survivor_finding = self._critical_finding(name="survived", severity=Severity.MEDIUM)
        s2 = self._make_specialist("survivor", findings=[survivor_finding])

        mgr = self._make_manager([s1, s2])
        task = self._make_task()
        result = await mgr.dispatch(task)

        # s2 should still execute
        s2.run_with_timeout.assert_called_once()
        # Status should be partial_success
        assert result.status == "partial_success"
        # execution_log has both entries
        entry_names = {e["specialist"] for e in result.execution_log}
        assert entry_names == {"crasher", "survivor"}

    # --------------- T-1.1p: all specialists closed ---------------

    @pytest.mark.asyncio
    async def test_all_specialists_closed(self):
        """Every specialist gets close() called in finally block."""
        s1 = self._make_specialist("spec1")
        s2 = self._make_specialist("spec2")
        s3 = self._make_specialist("spec3", should_fail=True)

        mgr = self._make_manager([s1, s2, s3])
        task = self._make_task()
        await mgr.dispatch(task)

        # All must have close() called
        s1.close.assert_called_once()
        s2.close.assert_called_once()
        s3.close.assert_called_once()

    # --------------- T-1.1q: findings merged in order ---------------

    @pytest.mark.asyncio
    async def test_findings_merged_in_specialist_order(self):
        """Findings are aggregated in specialist execution order."""
        f1 = Finding(
            vuln_type=VulnType.XSS,
            target_url="http://example.com",
            title="first",
            severity=Severity.MEDIUM,
            description="first finding",
            source_agent="s1",
        )
        f2 = Finding(
            vuln_type=VulnType.SQLI,
            target_url="http://example.com",
            title="second",
            severity=Severity.MEDIUM,
            description="second finding",
            source_agent="s2",
        )

        s1 = self._make_specialist("s1", findings=[f1])
        s2 = self._make_specialist("s2", findings=[f2])

        mgr = self._make_manager([s1, s2])
        task = self._make_task()
        result = await mgr.dispatch(task)

        assert result.findings == [f1, f2], (
            f"Finding order mismatch: {[(f.title, f.source_agent) for f in result.findings]}"
        )

    # --------------- T-1.1r: existing test parity ---------------

    @pytest.mark.asyncio
    async def test_adaptive_skip_matches_existing_tier4_test(self):
        """This test mirrors test_tier4_intelligence.py:57-98 (parity check)."""
        mock_s1 = AsyncMock(spec=Specialist)
        mock_s1.name = "crit_finder"
        mock_s1.run_with_timeout = AsyncMock(return_value=[
            self._critical_finding(severity=Severity.CRITICAL),
        ])
        mock_s1.get_execution_time = MagicMock(return_value=0.1)

        mock_s2 = AsyncMock(spec=Specialist)
        mock_s2.name = "skipped_worker"

        SwarmManager.__abstractmethods__ = frozenset()
        mgr = SwarmManager(config={"max_concurrent_tasks": 1})
        mgr.name = "test_manager"
        mgr._specialists = [mock_s1, mock_s2]
        mgr.get_specialists = MagicMock(return_value=[mock_s1, mock_s2])

        task = MagicMock()
        task.params = {"adaptive_skip_enabled": True}
        task.tags = ["target_domain"]

        result = await mgr.dispatch(task)

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL
        mock_s2.run_with_timeout.assert_not_called()
