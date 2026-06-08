from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor


@pytest.mark.asyncio
async def test_recon_master_dispatch_uses_to_thread_for_isolated_pipeline():
    mc = MasterConductor.__new__(MasterConductor)
    mc.context = SimpleNamespace(target_info={"target": "http://127.0.0.1:8888/", "mode": "bugbounty"})
    mc.project_manager = None
    mc.workspace = None
    mc.phase_gate = MagicMock()
    mc._create_attack_tasks_from_recon = MagicMock(return_value=[])
    mc._add_tasks = MagicMock()
    mc.accumulated_context = MagicMock()
    mc.llm_client = MagicMock()
    mc.network_client = MagicMock()
    mc._recon_executed = False

    fake_state = SimpleNamespace(
        live_subs=[],
        tech_stack=[],
        results={},
        current_step=8,
        screenshots_count=0,
    )

    task = Task(
        id="task_002",
        name="Deep Reconnaissance (Parallel)",
        agent_type="recon_master",
        params={"target": "http://127.0.0.1:8888/", "start_step": 1, "end_step": 8},
    )

    with patch("src.recon.pipeline.ReconPipeline") as mock_pipeline_cls:
        mock_pipeline_cls.return_value = MagicMock()
        with patch("src.core.engine.master_conductor.asyncio.to_thread", new=AsyncMock(return_value=fake_state)) as mock_to_thread:
            result = await mc._dispatch(task)

    assert result.get("success") is True
    assert result.get("agent") == "recon_master"
    assert mock_to_thread.await_count == 1
