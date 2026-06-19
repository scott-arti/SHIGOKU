
import pytest
from unittest.mock import MagicMock, patch
from src.core.engine.master_conductor import MasterConductor, Task
from src.core.engine.context_designer import ContextDesigner
from src.core.engine.task_queue import TaskContext

@pytest.fixture
def mock_settings():
    with patch("src.core.engine.master_conductor_facade.settings") as mock:
        mock.use_llm_planning = False
        mock.notify_on_task_start = False
        mock.notify_on_task_complete = False
        mock.checkpoint_interval = 100
        mock.max_derived_tasks_per_session = 100
        yield mock

@pytest.fixture
def mc(mock_settings):
    # Mock dependencies to avoid complex setup
    # Patch where they are defined, not where they are imported (since they are imported inside functions or not at module level)
    with patch("src.core.infra.event_bus.get_event_bus"), \
         patch("src.core.notifications.notifier.get_notifier"), \
         patch("src.core.engine.phase_gate.get_phase_gate"), \
         patch("src.core.engine.critical_path_analyzer.CriticalPathAnalyzer"), \
         patch("src.core.wordlist.wordlist_manager.get_wordlist_manager"), \
         patch("src.core.engine.error_replanner.ErrorReplanner"), \
         patch("src.core.models.task_execution_log.get_execution_log"), \
         patch("src.core.models.decision_trace.get_decision_tracer"):
        
        conductor = MasterConductor()
        # Mock ContextDesigner to verify calls
        conductor.context_designer = MagicMock(spec=ContextDesigner)
        # Mock _dispatch to avoid actual execution
        conductor._dispatch = MagicMock(return_value={"success": True})
        return conductor

def test_context_designer_integration(mc):
    # Setup task and context
    task = Task(id="test_task", name="Test", agent_type="custom", action="run")
    mc.task_queue.add(task)
    
    # Mock accumulcated context
    mc.accumulated_context = TaskContext()
    mc.accumulated_context.auth_tokens = {"Bearer": "token"}
    
    # Mock enrich_task return
    enriched_task = Task(id="test_task", name="Test", agent_type="custom", action="run", params={"enriched": True})
    mc.context_designer.enrich_task.return_value = enriched_task
    
    # Execute (limit to 1 task)
    mc.execute_with_replan(max_tasks=1)
    
    # Verify enrich_task was called
    mc.context_designer.enrich_task.assert_called_once()
    args, _ = mc.context_designer.enrich_task.call_args
    assert args[0].id == "test_task" # Task
    assert args[2] == mc.accumulated_context # Accumulated Context
