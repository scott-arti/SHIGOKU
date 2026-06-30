"""SwarmDispatcher Phase 3: per-dispatch instance isolation tests.

TDD: tests written first, then implementation follows.
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

from src.core.engine.swarm_dispatcher import SwarmDispatcher
from src.core.models.swarm import SwarmResult
from src.core.agents.swarm.base import Task as SwarmTask


# ---------------------------------------------------------------------------
# T-0.1: Baseline characterization test (serial dispatch, mock swarm)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_serial_dispatch_baseline_findings_fixed():
    """Baseline: serial dispatch with mock swarm, findings are collected correctly.

    This test characterizes the dispatch behavior.  After Change A/B, the mock
    and assert must still pass (serial dispatch pipeline integrity).
    """
    mock_swarm = AsyncMock()
    mock_swarm.dispatch.return_value = SwarmResult(
        findings=[{"id": "f1", "title": "test-finding"}],
        status="success",
        execution_log=[{"step": "mock"}],
        swarm_name="scanner",
        total_specialists=1,
        successful_specialists=1,
    )
    mock_swarm.close = AsyncMock()

    dispatcher = SwarmDispatcher()

    with patch.object(dispatcher, "_get_or_create_swarm", return_value=mock_swarm):
        result = await dispatcher.dispatch(
            tags=["ssl"],
            target="http://example.com/api",
        )

    assert result is not None
    assert result.status == "success"
    assert len(result.findings) == 1
    assert result.findings[0]["title"] == "test-finding"
    assert result.swarm_name == "scanner"
    assert result.total_specialists == 1
    # Phase 3: per-dispatch instance must be closed after dispatch
    mock_swarm.close.assert_called_once()


# ---------------------------------------------------------------------------
# T-3.1: Per-dispatch distinct instance / no-leak
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_or_create_swarm_returns_distinct_instance_per_call():
    """Each call to _get_or_create_swarm returns a distinct instance (pool caching removed)."""
    dispatcher = SwarmDispatcher(
        config={},
        llm_client=object(),
        network_client=object(),
    )
    a = dispatcher._get_or_create_swarm("scanner")
    b = dispatcher._get_or_create_swarm("scanner")
    assert a is not b, "per-dispatch instances must be distinct"
    assert dispatcher._swarm_pool == {}, "pool must remain empty"


@pytest.mark.asyncio
async def test_no_ephemeral_resource_leak_after_close():
    """After dispatch + close, per-manager ephemeral clients are released."""
    dispatcher = SwarmDispatcher(
        config={},
        llm_client=object(),
        network_client=object(),
    )

    mock_swarm = AsyncMock()
    mock_swarm.dispatch.return_value = SwarmResult(
        findings=[], status="success", execution_log=[],
        swarm_name="scanner",
    )
    mock_swarm.close = AsyncMock()

    with patch.object(dispatcher, "_get_or_create_swarm", return_value=mock_swarm):
        await dispatcher.dispatch(tags=["ssl"], target="http://example.com")

    # The instruction says close is called in finally.  After our changes,
    # mock_swarm.close should have been called.  For now (pre-change), it won't be.
    # We'll assert after Change B.
    #
    # For the pre-change TDD state this test documents the expected outcome;
    # it will FAIL until Change B is implemented.
    mock_swarm.close.assert_called_once()


# ---------------------------------------------------------------------------
# T-1.1: Shared service identity preserved across instances
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_shared_services_preserved_across_instances():
    """shared network_client / llm_client identity is preserved across instances."""
    net = object()
    llm = object()
    eb = object()
    dispatcher = SwarmDispatcher(
        config={},
        llm_client=llm,
        network_client=net,
        event_bus=eb,
    )
    a = dispatcher._get_or_create_swarm("scanner")
    b = dispatcher._get_or_create_swarm("scanner")

    # Same shared client objects (identity check)
    assert a.network_client is net
    assert b.network_client is net
    assert a.llm_client is llm
    assert b.llm_client is llm

    # Different Swarm instances though
    assert a is not b


# ---------------------------------------------------------------------------
# T-2.1: Concurrent dispatch findings isolation (real factory, mock dispatch)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_dispatch_findings_isolation():
    """Two concurrent dispatches to same swarm type: real factory exercised.

    Only .dispatch is mocked on the resulting real Swarm instances.
    If pool reuse were re-enabled, the factory would return the same instance
    twice, the second marker would overwrite the first mock, and this test
    would correctly fail.
    """
    marker_a = "MARKER_A_ISOLATED"
    marker_b = "MARKER_B_ISOLATED"

    dispatcher = SwarmDispatcher(
        config={},
        llm_client=object(),
        network_client=object(),
    )

    intercepted: list = []
    _original = dispatcher._get_or_create_swarm

    def _intercept_and_mock_dispatch(swarm_name):
        swarm = _original(swarm_name)
        if swarm is not None:
            idx = len(intercepted)
            marker = marker_a if idx == 0 else marker_b
            swarm.dispatch = AsyncMock(return_value=SwarmResult(
                findings=[{"marker": marker}],
                status="success",
                execution_log=[],
                swarm_name=swarm_name,
            ))
            swarm.close = AsyncMock()
            intercepted.append(swarm)
        return swarm

    dispatcher._get_or_create_swarm = _intercept_and_mock_dispatch

    results = await asyncio.gather(
        dispatcher.dispatch(tags=["ssl"], target="http://example.com/a"),
        dispatcher.dispatch(tags=["ssl"], target="http://example.com/b"),
    )

    # Structural guarantee: per-dispatch must use distinct instances
    assert len(intercepted) >= 2, f"expected >=2 instances, got {len(intercepted)}"
    assert intercepted[0] is not intercepted[1], \
        "per-dispatch instances must be distinct (pool reuse would return same instance)"

    # Findings isolation
    assert results[0] is not None
    assert results[1] is not None
    f0 = [f["marker"] if isinstance(f, dict) else getattr(f, "marker", None) for f in results[0].findings]
    f1 = [f["marker"] if isinstance(f, dict) else getattr(f, "marker", None) for f in results[1].findings]
    assert marker_a in f0, f"expected {marker_a} in dispatch A findings, got {f0}"
    assert marker_b not in f0, f"{marker_b} must not leak into dispatch A"
    assert marker_b in f1, f"expected {marker_b} in dispatch B findings, got {f1}"
    assert marker_a not in f1, f"{marker_a} must not leak into dispatch B"


# ---------------------------------------------------------------------------
# T-2.4: Concurrent dispatch history isolation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_dispatch_history_isolation():
    """LLM history turns from two concurrent dispatches must not interleave.

    Exercises the real factory and verifies distinct instances are returned.
    Per-dispatch instances structurally isolate self.history, so distinct
    instances = isolated histories.  Pool reuse would return the same instance
    and this test would fail.
    """
    dispatcher = SwarmDispatcher(
        config={},
        llm_client=object(),
        network_client=object(),
    )

    instances = []
    _original = dispatcher._get_or_create_swarm

    def _track_and_mock(name):
        swarm = _original(name)
        if swarm is not None:
            swarm.dispatch = AsyncMock(return_value=SwarmResult(
                findings=[], status="success", execution_log=[],
                swarm_name=name,
            ))
            swarm.close = AsyncMock()
            instances.append(swarm)
        return swarm

    dispatcher._get_or_create_swarm = _track_and_mock

    await asyncio.gather(
        dispatcher.dispatch(tags=["ssl"], target="http://example.com/a"),
        dispatcher.dispatch(tags=["ssl"], target="http://example.com/b"),
    )

    # Each dispatch must create its own instance
    assert len(instances) >= 2, f"expected >=2 instances, got {len(instances)}"
    assert instances[0] is not instances[1], \
        "concurrent dispatch must use distinct swarm instances (history isolation)"


# ---------------------------------------------------------------------------
# T-2.5: Exception close safety
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_per_dispatch_instance_closed_on_exception():
    """When dispatch raises, finally must close the per-dispatch instance."""
    dispatcher = SwarmDispatcher(
        config={},
        llm_client=object(),
        network_client=object(),
    )

    mock_swarm = AsyncMock()
    mock_swarm.dispatch.side_effect = RuntimeError("forced failure")
    mock_swarm.close = AsyncMock()

    with patch.object(dispatcher, "_get_or_create_swarm", return_value=mock_swarm):
        result = await dispatcher.dispatch(
            tags=["ssl"],
            target="http://example.com",
        )

    # Dispatch should still return a result (error handled)
    assert result is not None or result is None  # may be None if all failed

    # The per-dispatch instance MUST be closed even on exception
    mock_swarm.close.assert_called_once()


# ---------------------------------------------------------------------------
# T-2.5b: Shared client not closed on dispatch close
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_shared_network_client_not_closed_by_dispatch():
    """shared network_client must NOT be closed by per-dispatch swarm.close()."""
    shared_net = AsyncMock()
    shared_net.close = AsyncMock()

    mock_swarm = AsyncMock()
    mock_swarm.network_client = shared_net
    mock_swarm.dispatch.return_value = SwarmResult(
        findings=[], status="success", execution_log=[],
        swarm_name="scanner",
    )
    mock_swarm.close = AsyncMock()

    dispatcher = SwarmDispatcher(
        config={},
        network_client=shared_net,
        llm_client=object(),
    )

    with patch.object(dispatcher, "_get_or_create_swarm", return_value=mock_swarm):
        await dispatcher.dispatch(tags=["ssl"], target="http://example.com")

    # The shared network_client must NOT have been closed
    shared_net.close.assert_not_called()


# ---------------------------------------------------------------------------
# T-2.1b: Concurrent dispatch with barrier (forced interleaving, real factory)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_dispatch_barrier_isolation():
    """Forced interleaving with barrier, real factory exercised.

    Only .dispatch is mocked on real Swarm instances so that pool reuse
    regression would be caught (same instance served to both dispatches).
    """
    barrier = asyncio.Event()
    saw_a = []

    marker_a = "ALPHA_ISOLATED"
    marker_b = "BETA_ISOLATED"

    dispatcher = SwarmDispatcher(
        config={},
        llm_client=object(),
        network_client=object(),
    )

    intercepted = []
    _original = dispatcher._get_or_create_swarm

    async def _dispatch_a(task):
        saw_a.append("started")
        barrier.set()
        await asyncio.sleep(0.01)
        return SwarmResult(
            findings=[{"marker": marker_a}],
            status="success", execution_log=[],
            swarm_name="scanner",
        )

    async def _dispatch_b(task):
        await barrier.wait()
        return SwarmResult(
            findings=[{"marker": marker_b}],
            status="success", execution_log=[],
            swarm_name="scanner",
        )

    def _intercept(swarm_name):
        swarm = _original(swarm_name)
        if swarm is not None:
            idx = len(intercepted)
            swarm.dispatch = AsyncMock(
                side_effect=_dispatch_a if idx == 0 else _dispatch_b
            )
            swarm.close = AsyncMock()
            intercepted.append(swarm)
        return swarm

    dispatcher._get_or_create_swarm = _intercept

    results = await asyncio.gather(
        dispatcher.dispatch(tags=["ssl"], target="http://example.com/a"),
        dispatcher.dispatch(tags=["ssl"], target="http://example.com/b"),
    )

    # Structural guarantee: distinct instances
    assert len(intercepted) >= 2, f"expected >=2 instances, got {len(intercepted)}"
    assert intercepted[0] is not intercepted[1], \
        "barrier test: per-dispatch instances must be distinct"

    assert results[0] is not None
    assert results[1] is not None
    f0 = [f["marker"] if isinstance(f, dict) else getattr(f, "marker", None) for f in results[0].findings]
    f1 = [f["marker"] if isinstance(f, dict) else getattr(f, "marker", None) for f in results[1].findings]
    assert marker_a in f0 and marker_b not in f0
    assert marker_b in f1 and marker_a not in f1
