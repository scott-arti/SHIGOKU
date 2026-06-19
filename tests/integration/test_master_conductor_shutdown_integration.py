"""
Integration test for MasterConductor shutdown sequence.

Uses setup_module/teardown_module for sys.modules mocks (non-event_bus).
get_event_bus is patched directly on master_conductor_facade to avoid
import-time binding issues with sys.modules.
"""

import sys
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

_MODULE_MOCKS = {
    "neo4j": MagicMock(),
    "bs4": MagicMock(),
    "aiofiles": MagicMock(),
    "src.core.engine.recipe_loader": MagicMock(),
    "src.core.engine.strategy_optimizer": MagicMock(),
    "src.core.engine.task_queue": MagicMock(),
    "src.core.engine.context_propagator": MagicMock(),
    "src.core.engine.context_designer": MagicMock(),
    "src.core.engine.critical_path_analyzer": MagicMock(),
    "src.core.wordlist.wordlist_manager": MagicMock(),
    "src.core.notifications.notifier": MagicMock(),
    "src.tools.custom.notify": MagicMock(),
    "src.core.engine.flag_watcher": MagicMock(),
    "src.core.models.task_execution_log": MagicMock(),
    "src.core.models.decision_trace": MagicMock(),
    "src.core.engine.phase_gate": MagicMock(),
    "src.core.infra.async_writer": MagicMock(),
    "src.core.learning.findings_repository": MagicMock(),
}

_ORIG_MODULES: dict = {}


def _install_mocks():
    global _ORIG_MODULES
    _ORIG_MODULES = {}
    for name, mock in _MODULE_MOCKS.items():
        _ORIG_MODULES[name] = sys.modules.get(name)
        sys.modules[name] = mock


def _restore_modules():
    for name in _MODULE_MOCKS:
        if name in _ORIG_MODULES and _ORIG_MODULES[name] is not None:
            sys.modules[name] = _ORIG_MODULES[name]
        elif name in sys.modules:
            del sys.modules[name]


def setup_module():
    _install_mocks()
    # Lazy import: must happen AFTER sys.modules mocks are installed
    global MasterConductor
    from src.core.engine.master_conductor import MasterConductor as _MC
    MasterConductor = _MC


def teardown_module():
    _restore_modules()


MasterConductor = None  # placeholder, assigned in setup_module


def _make_mock_event_bus():
    """Return a mock event_bus with awaitable stop."""
    bus = MagicMock()
    bus.start = MagicMock()   # consumed by patched run_coroutine_threadsafe in __init__
    bus.stop = AsyncMock()    # consumed by await in _async_shutdown
    bus.subscribe = MagicMock()
    return bus


@pytest.fixture
def mock_mc():
    """MasterConductor instance with minimal mocked dependencies."""
    mock_bus = _make_mock_event_bus()

    with patch("src.core.engine.master_conductor_facade.KnowledgeGraph"), \
         patch("src.core.engine.master_conductor_facade.get_findings_repository"), \
         patch("src.core.engine.master_conductor_facade.AsyncDatabaseWriter"), \
         patch("src.core.engine.master_conductor_facade.get_event_bus",
               return_value=mock_bus), \
         patch("asyncio.create_task"), \
         patch("asyncio.run_coroutine_threadsafe"):

        mc = MasterConductor()
        mc.save_session = MagicMock()
        mc.async_save_session = AsyncMock()
        mc.writer.stop = AsyncMock()
        if hasattr(mc, "network_client") and mc.network_client:
            mc.network_client.close = AsyncMock()

        return mc


@pytest.mark.asyncio
async def test_shutdown_completes_without_error(mock_mc):
    """shutdown completes without raising."""
    await mock_mc._async_shutdown()
    assert mock_mc._shutdown_requested is True


@pytest.mark.asyncio
async def test_shutdown_resilient_to_dispatcher_error(mock_mc):
    """shutdown survives SwarmDispatcher.close() error."""

    mock_module = sys.modules["src.core.engine.swarm_dispatcher"] = MagicMock()
    mock_dispatcher = AsyncMock()
    mock_dispatcher.close.side_effect = RuntimeError("Dispatcher close error")
    mock_module.get_swarm_dispatcher.return_value = mock_dispatcher

    await mock_mc._async_shutdown()
    assert mock_mc._shutdown_requested is True
