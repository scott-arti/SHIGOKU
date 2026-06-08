from src.core.domain.model.task import Task
from src.core.engine.master_conductor_hitl_snapshot import snapshot_task_for_hitl


def test_snapshot_task_for_hitl_returns_expected_shape() -> None:
    task = Task(
        id="task_snapshot_01",
        name="Snapshot Task",
        action="scan",
        agent_type="InjectionSwarm",
        phase="attack",
        params={"alpha": 1, "nested": {"beta": 2}},
        priority=64,
        parent_id="parent-task",
        replan_depth=3,
        tags=["one", "two"],
        target="https://snapshot.example",
    )

    snapshot = snapshot_task_for_hitl(task)

    assert snapshot == {
        "id": "task_snapshot_01",
        "name": "Snapshot Task",
        "agent_type": "InjectionSwarm",
        "action": "scan",
        "phase": "attack",
        "params": {"alpha": 1, "nested": {"beta": 2}},
        "priority": 64,
        "parent_id": "parent-task",
        "replan_depth": 3,
        "tags": ["one", "two"],
        "target": "https://snapshot.example",
    }


def test_snapshot_task_for_hitl_deep_copies_params() -> None:
    task = Task(
        id="task_snapshot_02",
        name="Snapshot Task",
        action="scan",
        agent_type="InjectionSwarm",
        params={"nested": {"beta": 2}},
    )

    snapshot = snapshot_task_for_hitl(task)
    task.params["nested"]["beta"] = 99

    assert snapshot["params"]["nested"]["beta"] == 2
