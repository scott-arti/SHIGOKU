from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.agents.swarm.base import Task
from src.core.engine.master_conductor import MasterConductor
from src.core.engine.parallel_orchestrator import TaskResult


@pytest.fixture
def mock_mc():
    with (
        patch("src.core.engine.master_conductor_facade.get_findings_repository"),
        patch("src.core.engine.master_conductor_facade.AsyncDatabaseWriter"),
        patch("src.core.engine.master_conductor_facade.AgentFactory"),
        patch("src.core.engine.master_conductor_facade.SmartScheduler"),
        patch("src.core.engine.master_conductor_facade.KnowledgeGraph"),
        patch("src.core.engine.master_conductor_facade.get_event_bus") as mock_get_event_bus,
        patch("src.core.engine.master_conductor_facade.get_phase_gate"),
        patch("src.core.engine.master_conductor_facade.get_notifier"),
    ):
        mock_get_event_bus.return_value.start = AsyncMock()
        mc = MasterConductor()
        mc.risk_predictor = MagicMock()
        mc.self_reflection = MagicMock()
        mc.error_analyzer = MagicMock()
        mc.priority_booster = MagicMock()
        mc.orchestrator = MagicMock()
        mc.task_queue = MagicMock()
        mc.optimizer = MagicMock()
        mc.optimizer.should_review.return_value = False
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 4
        mc.writer = MagicMock()
        mc._run_async_safe = MagicMock()
        mc._run_safe = MagicMock()
        return mc


def _prepare_queue(mock_mc: MasterConductor, tasks: list[Task]) -> None:
    queue = list(tasks)

    def _peek():
        return queue[0] if queue else None

    def _empty():
        return len(queue) == 0

    def _select():
        if queue:
            return queue.pop(0)
        return None

    mock_mc.task_queue.peek.side_effect = _peek
    mock_mc.task_queue.empty.side_effect = _empty
    mock_mc.task_queue.is_empty.side_effect = _empty
    mock_mc._select_next_task_from_queue = MagicMock(side_effect=_select)


def _prepare_parallel_executor(mock_mc: MasterConductor) -> None:
    def _execute_parallel(chunk, timeout=None):  # noqa: ANN001
        return [
            TaskResult(task_id=pt.id, success=True, result={"success": True}, category=pt.category)
            for pt in chunk
        ]

    mock_mc.orchestrator.execute_parallel.side_effect = _execute_parallel
    mock_mc._run_async_safe.side_effect = lambda result, timeout_override=None: result


def test_injection_full_parallel_dispatch_enables_multi_task_batch(mock_mc):
    tasks = [
        Task(id="inj-1", name="inj-1", agent_type="InjectionSwarm"),
        Task(id="inj-2", name="inj-2", agent_type="InjectionSwarm"),
    ]
    _prepare_queue(mock_mc, tasks)
    _prepare_parallel_executor(mock_mc)

    with patch("src.core.engine.master_conductor_facade.settings") as mock_settings:
        mock_settings.max_session_tasks = 10
        mock_settings.injection_full_parallel_dispatch = True
        mock_settings.injection_batch_parallelism = 2
        mock_settings.injection_manager_timeout = 900
        mock_settings.parallel_batch_timeout = 600
        mock_settings.reflection_interval = 1000
        mock_settings.checkpoint_interval = 9999

        mock_mc.execute_with_replan(max_tasks=10)

    assert mock_mc.orchestrator.execute_parallel.call_count == 1
    first_chunk = mock_mc.orchestrator.execute_parallel.call_args_list[0].args[0]
    assert len(first_chunk) == 2


def test_injection_default_dispatch_keeps_sequential_batch(mock_mc):
    tasks = [
        Task(id="inj-1", name="inj-1", agent_type="InjectionSwarm"),
        Task(id="inj-2", name="inj-2", agent_type="InjectionSwarm"),
    ]
    _prepare_queue(mock_mc, tasks)
    _prepare_parallel_executor(mock_mc)

    with patch("src.core.engine.master_conductor_facade.settings") as mock_settings:
        mock_settings.max_session_tasks = 10
        mock_settings.injection_full_parallel_dispatch = False
        mock_settings.injection_batch_parallelism = 2
        mock_settings.injection_manager_timeout = 900
        mock_settings.parallel_batch_timeout = 600
        mock_settings.reflection_interval = 1000
        mock_settings.checkpoint_interval = 9999

        mock_mc.execute_with_replan(max_tasks=10)

    first_chunk = mock_mc.orchestrator.execute_parallel.call_args_list[0].args[0]
    assert len(first_chunk) == 1
