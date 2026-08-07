"""SGK-2026-0413: execution admission and dependency ordering tests."""
from types import SimpleNamespace

from src.core.domain.model.task import Task, TaskState
from src.core.engine.master_conductor import MasterConductor
from src.core.engine.task_queue import DynamicTaskQueue


def _build_conductor() -> MasterConductor:
    """Build only the state needed by queue-admission helpers."""
    conductor = MasterConductor.__new__(MasterConductor)
    conductor.task_queue = DynamicTaskQueue()
    conductor.completed_tasks = []
    conductor.task_prioritizer = None
    conductor._sync_task_queue_snapshot_versions = lambda: None
    conductor._is_task_quarantined = lambda task: False
    return conductor


def test_static_plan_makes_scope_a_real_recon_dependency():
    """The initial recon task cannot run in the same batch as scope verification."""
    conductor = _build_conductor()
    conductor.context = SimpleNamespace(target_info={})
    conductor.llm_client = None
    conductor.recipe_loader = None

    tasks = conductor.plan("security test", "http://target.invalid")
    recon = next(task for task in tasks if task.id == "task_002")

    assert recon.phase == "recon"
    assert recon.depends_on_task_ids == ["task_001"]


def test_dependency_blocks_recon_until_scope_succeeds():
    """A queued dependent task is deferred, then selected only after success."""
    conductor = _build_conductor()
    scope = Task(id="scope", name="scope")
    recon = Task(
        id="recon",
        name="recon",
        depends_on_task_ids=["scope"],
    )
    conductor.task_queue.add_batch([scope, recon])

    assert conductor._select_next_task_from_queue() is scope
    assert conductor._select_next_task_from_queue(reserved_task_ids={"scope"}) is None

    scope.state = TaskState.SUCCESS
    conductor.completed_tasks.append(scope)

    assert conductor._select_next_task_from_queue() is recon


def test_missing_dependency_is_skipped_with_a_reason_code():
    """An impossible dependency is terminalized instead of ending normally pending."""
    conductor = _build_conductor()
    blocked = Task(
        id="blocked",
        name="blocked",
        depends_on_task_ids=["not-in-this-run"],
    )
    conductor.task_queue.add(blocked)

    assert conductor._select_next_task_from_queue() is None
    assert blocked.state == TaskState.SKIPPED
    assert blocked.failure_reason == "dependency_missing"
    assert blocked in conductor.completed_tasks


def test_dependency_cycle_is_terminalized_without_claiming_completion():
    """A cycle has no runnable root, so every member receives a terminal reason."""
    conductor = _build_conductor()
    first = Task(id="first", name="first", depends_on_task_ids=["second"])
    second = Task(id="second", name="second", depends_on_task_ids=["first"])
    conductor.task_queue.add_batch([first, second])

    assert conductor._terminalize_dependency_deadlock() == 2
    assert {first.failure_reason, second.failure_reason} == {"dependency_cycle"}
    assert {first.state, second.state} == {TaskState.SKIPPED}


def test_coverage_guards_wait_for_attack_phase_unlock():
    """Coverage checks do not consume the first batch before recon has evidence."""
    conductor = MasterConductor.__new__(MasterConductor)
    conductor.phase_gate = SimpleNamespace(is_unlocked=lambda _phase: False)

    assert conductor._can_enqueue_global_coverage_guards() is False

    conductor.phase_gate = SimpleNamespace(is_unlocked=lambda _phase: True)
    assert conductor._can_enqueue_global_coverage_guards() is True


def test_summary_marks_unresolved_selected_task_as_incomplete():
    """A selected task left pending must suppress the normal-completion claim."""
    conductor = _build_conductor()
    pending = Task(id="pending", name="pending")
    conductor.completed_tasks = [pending]
    conductor.context = SimpleNamespace(
        discovered_assets=[],
        bypass_methods=[],
        metrics={"estimated_cost": 0.0, "total_duration": 0.0},
        target_info={"required_vuln_families": []},
    )

    summary = conductor._generate_summary()

    assert summary["completion_status"] == "incomplete"
    assert summary["outcome_status"] == "incomplete"
    assert summary["unresolved_task_ids"] == ["pending"]


def test_outcome_status_distinguishes_terminal_failure_from_success():
    assert MasterConductor._outcome_status({
        "completion_status": "completed",
        "failed": 0,
    }) == "succeeded"
    assert MasterConductor._outcome_status({
        "completion_status": "completed",
        "failed": 1,
    }) == "completed_with_failures"
    assert MasterConductor._outcome_status({
        "completion_status": "incomplete",
        "failed": 0,
    }) == "incomplete"
