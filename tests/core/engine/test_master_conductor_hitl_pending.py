import threading

from src.config import settings
from src.core.domain.model.task import Task, TaskState
from src.core.engine.intervention_policy import InterventionPolicy
from src.core.engine.master_conductor_hitl_ticket import build_pending_hitl_ticket
from src.core.engine.master_conductor import MasterConductor
from src.core.engine.task_queue import DynamicTaskQueue


def _new_conductor(callback=None) -> MasterConductor:
    mc = MasterConductor.__new__(MasterConductor)
    mc.human_approval_callback = callback
    mc.intervention_policy = InterventionPolicy(settings.get_intervention_scenarios())
    mc._state_lock = threading.RLock()
    mc.pending_hitl = []
    mc.task_queue = DynamicTaskQueue()
    return mc


def test_intervention_precheck_without_callback_creates_pending_hitl_ticket(monkeypatch) -> None:
    monkeypatch.setattr(settings, "intervention_gate_mode", "enforce_hitl", raising=False)
    monkeypatch.setattr(settings, "intervention_human_preferred_fail_closed", False, raising=False)

    mc = _new_conductor(callback=None)
    task = Task(
        id="task_hitl_pending_01",
        name="Custom manual checkpoint",
        action="scan",
        agent_type="InjectionSwarm",
        params={"requires_human_input": True},
    )

    blocked = mc._run_intervention_precheck(task)

    assert blocked is not None
    assert blocked.get("pending_hitl") is True
    assert blocked.get("skipped") is True
    assert task.state == TaskState.SKIPPED
    assert len(mc.pending_hitl) == 1
    ticket = mc.pending_hitl[0]
    assert ticket.get("status") == "pending"
    assert ticket.get("scenario_id") == "explicit_requires_human_input"
    assert blocked.get("hitl_ticket_id") == ticket.get("ticket_id")


def test_approved_pending_hitl_ticket_can_be_enqueued_and_marked_done(monkeypatch) -> None:
    monkeypatch.setattr(settings, "intervention_gate_mode", "enforce_hitl", raising=False)
    monkeypatch.setattr(settings, "intervention_human_preferred_fail_closed", False, raising=False)

    mc = _new_conductor(callback=None)
    task = Task(
        id="task_hitl_pending_02",
        name="Custom manual checkpoint",
        action="scan",
        agent_type="InjectionSwarm",
        params={"requires_human_input": True},
    )
    blocked = mc._run_intervention_precheck(task)
    ticket_id = str(blocked.get("hitl_ticket_id", "") or "")
    assert ticket_id

    assert mc.set_pending_hitl_status(ticket_id, "approved") is True
    queued = mc.enqueue_approved_hitl_tasks()
    assert queued == 1

    queued_task = mc.task_queue.pop()
    assert queued_task is not None
    assert queued_task.params.get("_intervention", {}).get("resumed_from_pending_hitl") is True
    assert queued_task.params.get("_intervention", {}).get("hitl_ticket_id") == ticket_id

    mc._mark_pending_hitl_done(queued_task, success=True)
    tickets = mc.list_pending_hitl_tickets()
    assert tickets[0].get("status") == "done"
    assert tickets[0].get("outcome") == "success"


def test_pending_hitl_ticket_keeps_task_snapshot_shape(monkeypatch) -> None:
    monkeypatch.setattr(settings, "intervention_gate_mode", "enforce_hitl", raising=False)
    monkeypatch.setattr(settings, "intervention_human_preferred_fail_closed", False, raising=False)

    mc = _new_conductor(callback=None)
    task = Task(
        id="task_hitl_pending_03",
        name="Custom manual checkpoint",
        action="scan",
        agent_type="InjectionSwarm",
        phase="attack",
        params={"requires_human_input": True, "nested": {"value": 1}},
        priority=77,
        parent_id="parent-1",
        replan_depth=2,
        tags=["tag-a", "tag-b"],
        target="https://example.test",
    )

    blocked = mc._run_intervention_precheck(task)

    assert blocked is not None
    assert len(mc.pending_hitl) == 1
    snapshot = mc.pending_hitl[0]["task"]
    assert snapshot["id"] == "task_hitl_pending_03"
    assert snapshot["name"] == "Custom manual checkpoint"
    assert snapshot["agent_type"] == "InjectionSwarm"
    assert snapshot["action"] == "scan"
    assert snapshot["phase"] == "attack"
    assert snapshot["priority"] == 77
    assert snapshot["parent_id"] == "parent-1"
    assert snapshot["replan_depth"] == 2
    assert snapshot["tags"] == ["tag-a", "tag-b"]
    assert snapshot["target"] == "https://example.test"
    assert snapshot["params"]["requires_human_input"] is True
    assert snapshot["params"]["nested"] == {"value": 1}
    assert snapshot["params"]["_intervention"]["gate_mode"] == "enforce_hitl"
    assert snapshot["params"]["_intervention"]["decision"]["scenario_id"] == "explicit_requires_human_input"

    task.params["nested"]["value"] = 99
    assert mc.pending_hitl[0]["task"]["params"]["nested"]["value"] == 1


def test_build_pending_hitl_ticket_preserves_schema_and_snapshot() -> None:
    task = Task(
        id="task_hitl_pending_04",
        name="Custom manual checkpoint",
        action="scan",
        agent_type="InjectionSwarm",
        phase="attack",
        params={"requires_human_input": True, "nested": {"value": 1}},
        priority=77,
        parent_id="parent-1",
        replan_depth=2,
        tags=["tag-a", "tag-b"],
        target="https://example.test",
    )
    decision = {
        "scenario_id": "explicit_requires_human_input",
        "route": "shigoku_hitl",
        "reasons": ["requires_human_input"],
        "matched_signals": ["explicit"],
        "friction_score": 90,
        "friction_axes": {"state": 3},
        "route_decision_basis": "policy",
    }
    snapshot = {
        "id": "task_hitl_pending_04",
        "name": "Custom manual checkpoint",
        "agent_type": "InjectionSwarm",
        "action": "scan",
        "phase": "attack",
        "params": {"requires_human_input": True, "nested": {"value": 1}},
        "priority": 77,
        "parent_id": "parent-1",
        "replan_depth": 2,
        "tags": ["tag-a", "tag-b"],
        "target": "https://example.test",
    }

    ticket = build_pending_hitl_ticket(
        task=task,
        decision=decision,
        gate_mode="enforce_hitl",
        snapshot=snapshot,
        ticket_id="hitl_scn00_12345678",
        created_at=1234567890,
    )

    assert ticket == {
        "ticket_id": "hitl_scn00_12345678",
        "status": "pending",
        "created_at": 1234567890,
        "updated_at": 1234567890,
        "resolved_at": None,
        "task_id": "task_hitl_pending_04",
        "task_name": "Custom manual checkpoint",
        "task_agent": "InjectionSwarm",
        "scenario_id": "explicit_requires_human_input",
        "route": "shigoku_hitl",
        "gate_mode": "enforce_hitl",
        "reasons": ["requires_human_input"],
        "matched_signals": ["explicit"],
        "friction_score": 90,
        "friction_axes": {"state": 3},
        "route_decision_basis": "policy",
        "task": {
            "id": "task_hitl_pending_04",
            "name": "Custom manual checkpoint",
            "agent_type": "InjectionSwarm",
            "action": "scan",
            "phase": "attack",
            "params": {"requires_human_input": True, "nested": {"value": 1}},
            "priority": 77,
            "parent_id": "parent-1",
            "replan_depth": 2,
            "tags": ["tag-a", "tag-b"],
            "target": "https://example.test",
        },
        "queued_task_id": None,
        "outcome": None,
    }
