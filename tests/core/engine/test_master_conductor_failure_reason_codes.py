from types import SimpleNamespace

from src.core.domain.model.task import Task, TaskState
from src.core.engine.master_conductor import MasterConductor


def _new_mc_with_min_context() -> MasterConductor:
    mc = MasterConductor.__new__(MasterConductor)
    mc.completed_tasks = []
    mc.task_queue = []
    mc.pending_hitl = []
    mc.context = SimpleNamespace(
        discovered_assets=[],
        bypass_methods=[],
        metrics={"estimated_cost": 0.0, "total_duration": 0},
        target_info={"required_vuln_families": ["api"]},
    )
    return mc


def test_record_failure_context_sets_normalized_reason_code_and_meta() -> None:
    mc = _new_mc_with_min_context()
    task = Task(
        id="task_failure_reason_code_01",
        name="dependency failure",
        agent_type="test_agent",
        action="scan",
        params={},
    )
    task.error = "ModuleNotFoundError: No module named 'pydantic_core'"

    mc._record_failure_context(
        task,
        "dispatch_exception",
        "ModuleNotFoundError: No module named 'pydantic_core'",
    )

    assert task.failure_phase == "dispatch_exception"
    assert task.failure_reason_code == "DEPENDENCY_ERROR"
    assert isinstance(task.params.get("_failure"), dict)
    assert task.params["_failure"]["reason_code"] == "DEPENDENCY_ERROR"


def test_generate_summary_counts_failed_reason_codes() -> None:
    mc = _new_mc_with_min_context()
    task = Task(
        id="task_failure_reason_code_02",
        name="phase2 timeout",
        agent_type="InjectionSwarm",
        action="scan",
        params={"category": "api_candidate"},
    )
    task.state = TaskState.FAILED
    task.error = "Phase 2 timed out after 60s"
    task.failure_phase = "dispatch_result"
    task.failure_reason = "phase2_timeout"
    mc.completed_tasks = [task]

    summary = mc._generate_summary()

    assert summary["failed"] == 1
    assert summary["failed_reason_codes"].get("TIMEOUT_PHASE2") == 1
