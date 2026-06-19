"""
Character tests for MasterConductor import-origin and re-export integrity.

These tests serve as a safety net during the SGK-2026-0287 deep extraction.
They verify that the public import surface remains intact regardless of
internal reorganization (shim/facade/coordinator).

IMPORTANT: Do NOT delete or weaken these tests during extraction.
They are the go/no-go gate for import compatibility.
"""

import inspect
import pytest


# ---------------------------------------------------------------------------
# 1. Import-origin smoke -- verify symbols come from the expected modules
# ---------------------------------------------------------------------------

_EXPECTED_REEXPORTS = [
    # Core class
    "MasterConductor",
    # Domain model re-exports (consumed by commands/report.py and others)
    "Task",
    "TaskState",
    # Context
    "ExecutionContext",
    # Event infrastructure re-exports
    "Event",
    "EventType",
    # Finding re-export
    "Finding",
    # Intel re-export
    "SiteNode",
]


def _import_symbol(name: str):
    """Import a single symbol from master_conductor and return (obj, module_name)."""
    mod = __import__("src.core.engine.master_conductor", fromlist=[name])
    obj = getattr(mod, name)
    return obj, obj.__module__ if hasattr(obj, "__module__") else None


@pytest.mark.parametrize("symbol_name", _EXPECTED_REEXPORTS)
def test_symbol_importable(symbol_name: str) -> None:
    """Every expected re-export symbol must be importable."""
    obj, mod = _import_symbol(symbol_name)
    assert obj is not None, f"{symbol_name} not found in master_conductor"
    assert mod is not None, f"{symbol_name} has no __module__"


@pytest.mark.parametrize("symbol_name", _EXPECTED_REEXPORTS)
def test_symbol_module_origin(symbol_name: str) -> None:
    """Each symbol's __module__ must point to its canonical definition module."""
    obj, mod = _import_symbol(symbol_name)
    # master_conductor.py re-exports these from their canonical modules
    if symbol_name in ("Task", "TaskState"):
        assert mod == "src.core.domain.model.task", (
            f"{symbol_name}.__module__={mod}, expected src.core.domain.model.task"
        )
    elif symbol_name in ("Event", "EventType"):
        assert mod == "src.core.infra.event_bus", (
            f"{symbol_name}.__module__={mod}, expected src.core.infra.event_bus"
        )
    elif symbol_name == "Finding":
        assert mod == "src.core.models.finding", (
            f"{symbol_name}.__module__={mod}, expected src.core.models.finding"
        )
    elif symbol_name == "SiteNode":
        assert mod == "src.core.intel.cartographer", (
            f"{symbol_name}.__module__={mod}, expected src.core.intel.cartographer"
        )
    elif symbol_name == "MasterConductor":
        # MasterConductor is defined in master_conductor.py (or facade after extraction)
        assert mod in (
            "src.core.engine.master_conductor",
            "src.core.engine.master_conductor_facade",
        ), f"{symbol_name}.__module__={mod}"
    elif symbol_name == "ExecutionContext":
        assert mod in (
            "src.core.engine.master_conductor",
            "src.core.engine.master_conductor_facade",
        ), f"{symbol_name}.__module__={mod}"


def test_masterconductor_source_file() -> None:
    """MasterConductor class source file must be one of the canonical locations."""
    from src.core.engine.master_conductor import MasterConductor

    src = inspect.getfile(MasterConductor)
    assert src.endswith("master_conductor.py") or src.endswith(
        "master_conductor_facade.py"
    ), f"MasterConductor source: {src}"


# ---------------------------------------------------------------------------
# 2. Import path canonical smoke (the one that must NEVER break)
# ---------------------------------------------------------------------------

def test_canonical_import_path_works() -> None:
    """The canonical import path must remain functional through all phases."""
    from src.core.engine.master_conductor import (  # noqa: F401
        MasterConductor,
        Task,
        TaskState,
        ExecutionContext,
        Event,
        EventType,
        Finding,
        SiteNode,
    )

    assert MasterConductor.__name__ == "MasterConductor"
    assert Task.__name__ == "Task"
    assert TaskState.__name__ == "TaskState"
    assert ExecutionContext.__name__ == "ExecutionContext"


# ---------------------------------------------------------------------------
# 3. No same-name package collision
# ---------------------------------------------------------------------------

def test_no_master_conductor_package() -> None:
    """There must NOT be a src/core/engine/master_conductor/ package (import collision)."""
    import importlib.util

    spec = importlib.util.find_spec("src.core.engine.master_conductor")
    assert spec is not None, "master_conductor module not found"
    # spec.origin should point to a .py file, not a package __init__.py
    assert spec.origin is not None
    assert spec.origin.endswith(".py"), f"master_conductor origin: {spec.origin}"
    # The origin should be the single file module, not inside a package directory
    assert "/master_conductor/" not in spec.origin, (
        f"master_conductor appears to be a package: {spec.origin}"
    )
