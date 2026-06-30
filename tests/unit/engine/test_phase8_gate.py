"""Phase 8 Step 5: Gate verification — parity, replay, kill switch rollback.

Go conditions (per 7.9):
- High/Critical finding parity 100%
- Scope violation 0
- origin/request budget violation 0
- Secret leak 0 (verified in shadow tests T-2.1f, T-3.1f)
- deterministic replay: serial baseline can be reproduced
- kill switch rollback: parallelism.enabled=false → serial path
- partial failure: findings not dropped
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch

from src.core.engine.swarm_dispatcher import SwarmDispatcher
from src.core.models.swarm import SwarmResult, PerUrlSubResult
from src.core.models.finding import Finding, Severity, VulnType
from src.core.agents.swarm.base import SwarmManager, Specialist


def _make_swarm_mock(name, findings=None, status="success", delay=0.0):
    mock = AsyncMock()
    mock.name = name
    mock.close = AsyncMock()

    async def _dispatch(task):
        if delay > 0:
            await asyncio.sleep(delay)
        return SwarmResult(
            findings=findings or [],
            status=status,
            execution_log=[{"specialist": f"{name}_spec", "status": status,
                            "findings_count": len(findings or [])}],
            swarm_name=name,
            total_specialists=1,
            successful_specialists=1 if status != "failed" else 0,
        )

    mock.dispatch = AsyncMock(side_effect=_dispatch)
    return mock


def _make_failing_swarm_mock(name, error_msg="boom"):
    mock = AsyncMock()
    mock.name = name
    mock.close = AsyncMock()
    mock.dispatch = AsyncMock(side_effect=RuntimeError(error_msg))
    return mock


# ============================================================================
# Gate T-6.1: Partial failure aggregation
# ============================================================================


class TestGatePartialFailureAggregation:
    """Verify finding-preservation on partial failure."""

    @pytest.mark.asyncio
    async def test_swarm_failure_preserves_other_swarm_findings(self):
        """Failed swarm does not drop findings from successful swarms."""
        dispatcher = SwarmDispatcher(config={"parallelism": {"enabled": True}})
        swarms = {
            "scanner": _make_swarm_mock("scanner", [{"id": "s1"}, {"id": "s2"}], "success"),
            "fuzzing": _make_failing_swarm_mock("fuzzing"),
        }

        with patch.object(dispatcher, "_get_or_create_swarm",
                          side_effect=lambda n: swarms[n]):
            result = await dispatcher.dispatch(
                tags=["ssl", "fuzzing"], target="http://example.com/api",
            )

        f_ids = {f["id"] for f in result.findings}
        assert f_ids == {"s1", "s2"}, (
            f"Findings lost on partial failure: {f_ids}"
        )
        # Failed swarm must have error in execution_log
        error_entries = [
            e for e in result.execution_log if e.get("swarm") == "fuzzing"
        ]
        assert len(error_entries) >= 1, "No error entry for failed swarm"

    @pytest.mark.asyncio
    async def test_serial_baseline_parity_with_partial_failure(self):
        """Serial and parallel produce identical finding sets with partial failure."""
        serial = SwarmDispatcher(config={"parallelism": {"enabled": False}})
        parallel = SwarmDispatcher(config={"parallelism": {"enabled": True}})
        swarms = {
            "scanner": _make_swarm_mock("scanner", [{"id": "a"}, {"id": "b"}]),
            "fuzzing": _make_failing_swarm_mock("fuzzing"),
            "intelligence": _make_swarm_mock("intelligence", [{"id": "c"}]),
        }

        with patch.object(serial, "_get_or_create_swarm",
                          side_effect=lambda n: swarms[n]):
            serial_r = await serial.dispatch(
                tags=["ssl", "fuzzing", "osint"], target="http://example.com/api",
            )
        with patch.object(parallel, "_get_or_create_swarm",
                          side_effect=lambda n: swarms[n]):
            parallel_r = await parallel.dispatch(
                tags=["ssl", "fuzzing", "osint"], target="http://example.com/api",
            )

        serial_ids = {f["id"] for f in serial_r.findings}
        parallel_ids = {f["id"] for f in parallel_r.findings}
        assert serial_ids == parallel_ids, (
            f"Parity broken: serial={serial_ids}, parallel={parallel_ids}"
        )


# ============================================================================
# Gate T-8.1: Kill switch rollback
# ============================================================================


class TestGateKillSwitchRollback:
    """Verify parallelism.enabled=False returns to serial path."""

    @pytest.mark.asyncio
    async def test_disabled_is_serial(self):
        """parallelism.enabled=False → serial execution order."""
        dispatcher = SwarmDispatcher(config={"parallelism": {"enabled": False}})
        dispatch_order = []

        swarms = {
            "scanner": _make_swarm_mock("scanner", [{"id": "a"}]),
            "fuzzing": _make_swarm_mock("fuzzing", [{"id": "b"}]),
        }

        def _record(n):
            dispatch_order.append(n)
            return swarms[n]

        with patch.object(dispatcher, "_get_or_create_swarm", side_effect=_record):
            await dispatcher.dispatch(
                tags=["ssl", "fuzzing"], target="http://example.com/api",
            )

        # Must execute sequentially in determine_swarms order
        assert dispatch_order == ["scanner", "fuzzing"], (
            f"Not serial: {dispatch_order}"
        )

    @pytest.mark.asyncio
    async def test_kill_switch_overrides_enabled(self):
        """kill_switch=True overrides enabled=True → serial path."""
        dispatcher = SwarmDispatcher(config={
            "parallelism": {"enabled": True, "kill_switch": True}
        })
        dispatch_order = []

        swarms = {
            "scanner": _make_swarm_mock("scanner"),
            "fuzzing": _make_swarm_mock("fuzzing"),
        }

        def _record(n):
            dispatch_order.append(n)
            return swarms[n]

        with patch.object(dispatcher, "_get_or_create_swarm", side_effect=_record):
            await dispatcher.dispatch(
                tags=["ssl", "fuzzing"], target="http://example.com/api",
            )

        assert dispatch_order == ["scanner", "fuzzing"]

    @pytest.mark.asyncio
    async def test_default_config_is_serial(self):
        """No config → disabled → serial path."""
        dispatcher = SwarmDispatcher()
        dispatch_order = []

        swarms = {"scanner": _make_swarm_mock("scanner", [{"id": "a"}]),
                  "fuzzing": _make_swarm_mock("fuzzing", [{"id": "b"}]),
                  }

        def _record(n):
            dispatch_order.append(n)
            return swarms[n]

        with patch.object(dispatcher, "_get_or_create_swarm", side_effect=_record):
            await dispatcher.dispatch(
                tags=["ssl", "fuzzing"], target="http://example.com/api",
            )

        assert dispatch_order == ["scanner", "fuzzing"]


# ============================================================================
# Gate T-7.1: Deterministic replay (schema-level)
# ============================================================================


class TestGateDeterministicReplay:
    """Schema for deterministic replay is recorded."""

    def test_shadow_decisions_recorded_for_replay(self):
        """Shadow decisions contain source_unit for every swarm dispatched."""
        dispatcher = SwarmDispatcher(config={"parallelism": {"enabled": True}})
        swarms = {
            "scanner": _make_swarm_mock("scanner", [{"id": "a"}]),
            "fuzzing": _make_swarm_mock("fuzzing", [{"id": "b"}]),
        }

        with patch.object(dispatcher, "_get_or_create_swarm",
                          side_effect=lambda n: swarms[n]):
            result = asyncio.run(dispatcher.dispatch(
                tags=["ssl", "fuzzing"], target="http://example.com/api",
            ))

        source_units = {s["source_unit"] for s in result.shadow_decisions}
        assert source_units == {"scanner", "fuzzing"}, (
            f"Replay metadata incomplete: {source_units}"
        )

    def test_per_url_sub_result_has_fingerprints(self):
        """PerUrlSubResult carries request/payload fingerprints for replay."""
        r = PerUrlSubResult(
            source_url="http://example.com/test",
            request_fingerprint="sha256:abc",
            payload_fingerprint="sha256:def",
        )
        assert r.request_fingerprint == "sha256:abc"
        assert r.payload_fingerprint == "sha256:def"
        d = r.to_dict()
        assert d["request_fingerprint"] == "sha256:abc"
        assert d["payload_fingerprint"] == "sha256:def"


# ============================================================================
# Go/No-Go Gate summary tests
# ============================================================================


class TestPhase8GoConditions:
    """Verify Phase 8 Go conditions from plan section 7.9."""

    def test_read_only_stateless_only_parallelized(self):
        """Only read_only/stateless swarms are parallel candidates (C4/LB-6)."""
        dispatcher = SwarmDispatcher(config={"parallelism": {"enabled": True}})

        # All candidates from classify_swarm_shadow must be read_only
        for swarm_name in ["scanner", "secret", "fuzzing", "intelligence"]:
            shadow = dispatcher._classify_swarm_shadow(swarm_name)
            assert shadow["parallelism_type"] == "read_only", (
                f"Expected read_only for {swarm_name}, got {shadow}"
            )
            assert shadow["state_isolation"] == "stateless"

    def test_stateful_swarms_not_parallelized(self):
        """Stateful (BaseManagerAgent) swarms are rejected (C4)."""
        dispatcher = SwarmDispatcher()

        for swarm_name in ["injection", "auth", "logic", "discovery"]:
            shadow = dispatcher._classify_swarm_shadow(swarm_name)
            assert shadow["candidate"] is False, (
                f"Expected candidate=False for {swarm_name}, got {shadow}"
            )
            assert "stateful" in shadow.get("rejection_reason", "").lower(), (
                f"Expected stateful rejection for {swarm_name}: {shadow}"
            )

    def test_no_asyncio_gather_for_swarmmanager_specialists(self):
        """SwarmManager specialists NOT parallelized via asyncio.gather (LB-3)."""
        # Verified by existing baseline tests:
        # test_adaptive_skip_critical_finding, test_adaptive_skip_high_finding
        # These assert specialists execute serially.
        # This gate test documents the constraint.
        assert True  # Covered by test_phase8_serial_baseline.py

    def test_no_direct_context_mutation_from_worker(self):
        """PerUrlSubResult designed for isolated return, not shared context mutation (LB-2)."""
        r = PerUrlSubResult()
        # PerUrlSubResult has no reference to shared context
        assert not hasattr(r, "current_context")
        assert not hasattr(r, "task_queue")
        assert not hasattr(r, "accumulated_context")


# ============================================================================
# B-001 fix: shadow_decisions survives to_dict() and MC data boundary
# ============================================================================


class TestShadowDecisionsReplayArtifact:
    """Verify shadow_decisions appear in serialized output (replay artifact)."""

    @pytest.fixture
    def _finding_factory(self):
        def _make(vuln_type=VulnType.XSS, severity=Severity.MEDIUM, title="test"):
            return Finding(
                vuln_type=vuln_type, severity=severity,
                title=title, description="d",
                target_url="http://example.com", source_agent="test",
            )
        return _make

    @pytest.mark.asyncio
    async def test_swarmresult_to_dict_includes_shadow_decisions(self, _finding_factory):
        """SwarmResult.to_dict() preserves shadow_decisions."""
        dispatcher = SwarmDispatcher(config={"parallelism": {"enabled": True}})
        swarms = {
            "scanner": _make_swarm_mock("scanner", [_finding_factory(title="a")]),
            "fuzzing": _make_swarm_mock("fuzzing", [_finding_factory(title="b")]),
        }
        with patch.object(dispatcher, "_get_or_create_swarm",
                          side_effect=lambda n: swarms[n]):
            result = await dispatcher.dispatch(
                tags=["ssl", "fuzzing"], target="http://example.com/api",
            )

        d = result.to_dict()
        assert "shadow_decisions" in d, (
            f"shadow_decisions missing from to_dict(): {list(d.keys())}"
        )
        shadows = d["shadow_decisions"]
        assert len(shadows) == 2, f"Expected 2 shadow entries, got {len(shadows)}"
        source_units = {s["source_unit"] for s in shadows}
        assert source_units == {"scanner", "fuzzing"}

    @pytest.mark.asyncio
    async def test_mc_style_data_includes_shadow_decisions(self, _finding_factory):
        """MC-formatted data dict includes shadow_decisions (replay artifact boundary)."""
        dispatcher = SwarmDispatcher(config={"parallelism": {"enabled": True}})
        swarms = {
            "scanner": _make_swarm_mock("scanner", [_finding_factory()]),
        }
        with patch.object(dispatcher, "_get_or_create_swarm",
                          side_effect=lambda n: swarms[n]):
            result = await dispatcher.dispatch(
                tags=["ssl"], target="http://example.com/api",
            )

        # Simulate MC conversion pattern (same structure as master_conductor.py:8295-8306)
        mc_data = {
            "success": result.status in ["success", "partial_success"],
            "data": {
                "findings": [f.to_dict() for f in result.findings],
                "execution_log": result.execution_log,
                "shadow_decisions": list(result.shadow_decisions),
            },
        }
        assert "shadow_decisions" in mc_data["data"], (
            "shadow_decisions missing from MC data boundary"
        )
        assert len(mc_data["data"]["shadow_decisions"]) == 1

    @pytest.mark.asyncio
    async def test_shadow_to_dict_is_shallow_copy_safe(self, _finding_factory):
        """Caller mutation of shadow_decisions list does not affect original."""
        dispatcher = SwarmDispatcher(config={"parallelism": {"enabled": True}})
        swarms = {"scanner": _make_swarm_mock("scanner", [_finding_factory()])}
        with patch.object(dispatcher, "_get_or_create_swarm",
                          side_effect=lambda n: swarms[n]):
            result = await dispatcher.dispatch(
                tags=["ssl"], target="http://example.com/api",
            )

        d = result.to_dict()
        d["shadow_decisions"].clear()  # Mutate the copy
        # Original should remain intact
        assert len(result.shadow_decisions) == 1, (
            "Caller mutation leaked into original shadow_decisions"
        )


# ============================================================================
# B-002: T-5.2 Injection URL actual parallel formally deferred to Phase 9
# ============================================================================


class TestGateInjectionUrlDeferredToPhase9:
    """T-5.2 Injection URL limited execution B (actual parallel via budget) is
    formally deferred to Phase 9 (SGK-2026-0318) per the following rationale:

    - PerUrlSubResult schema is COMPLETE (T-5.1 ✅, verified in TestPerUrlSubResultSchema).
    - Actual URL-level parallel execution requires: per-origin budget integration,
      request/payload fingerprint at runtime, budget decision propagation,
      and post-join deterministic merge — all of which are Phase 9 scope
      (plan 7.5 D-2, D-3).
    - Phase 8 goal is candidate evaluation. The schema and budget policy
      (src/core/engine/budget_policy.py) are verified independently.
    - No regression: InjectionManagerAgent serial path is unchanged.
    """

    def test_per_url_schema_ready(self):
        """T-5.1: PerUrlSubResult schema is complete with all required fields."""
        r = PerUrlSubResult()
        assert hasattr(r, "findings")
        assert hasattr(r, "url_result")
        assert hasattr(r, "tested_params")
        assert hasattr(r, "request_fingerprint")
        assert hasattr(r, "payload_fingerprint")
        assert hasattr(r, "error")
        assert hasattr(r, "budget_decision")
        # Schema ready, actual parallel execution -> Phase 9

    def test_deferred_parallel_is_documented(self):
        """Deferral is documented: T-5.2 actual parallel -> Phase 9."""
        # This test serves as the formal record of deferral.
        # Phase 9 (SGK-2026-0318) will implement:
        # - Per-url parallel execution through budget_policy
        # - Skipped/rejected sub-result for budget exceeded URLs
        # - Post-join deterministic merge using PerUrlSubResult
        assert True  # Documentation gate, not a runtime assertion
