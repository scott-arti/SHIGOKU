from types import SimpleNamespace

import pytest

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor
from src.core.security.ethics_guard import get_ethics_guard


@pytest.mark.asyncio
async def test_dispatch_scope_parser_fast_path_sets_scope_and_context():
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "CTF"
    mc.context = SimpleNamespace(target_info={"mode": "ctf"})

    task = Task(
        id="task_001",
        name="Scope Verification",
        agent_type="scope_parser",
        action="verify_scope",
        params={"target": "localhost:3000"},
    )

    guard = get_ethics_guard()
    previous_scope = guard.scope
    try:
        result = await mc._dispatch(task)
    finally:
        guard.scope = previous_scope

    assert result.get("success") is True
    assert result.get("agent") == "scope_parser"
    assert result.get("data", {}).get("target") == "http://localhost:3000"
    assert result.get("context", {}).get("target_info", {}).get("host") == "localhost"
    assert "localhost" in result.get("data", {}).get("in_scope_domains", [])
