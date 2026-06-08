from types import SimpleNamespace

from src.config import settings
from src.core.domain.model.task import Task
from src.core.engine.intervention_policy import InterventionPolicy
from src.core.engine.master_conductor import MasterConductor
from src.core.engine.task_queue import DynamicTaskQueue


def _new_mc(monkeypatch, gate_mode: str) -> MasterConductor:
    mc = MasterConductor.__new__(MasterConductor)
    mc.context = SimpleNamespace(target_info={"aggressive_targets": []})
    mc.task_queue = DynamicTaskQueue(max_memory_size=32)
    mc._injected_task_ids = set()
    mc._derived_task_count = 0
    mc.mode = "bugbounty"
    mc.strategy_selector = None
    mc.intervention_policy = InterventionPolicy(settings.get_intervention_scenarios())

    monkeypatch.setattr(mc, "_calculate_dynamic_priority_boost", lambda task, max_boost=3.0: (1.0, []))
    monkeypatch.setattr(settings, "intervention_gate_mode", gate_mode, raising=False)
    return mc


def _mk_auth_task(priority: int = 95) -> Task:
    return Task(
        id="t_auth",
        name="Authentication Analysis",
        agent_type="AuthSwarm",
        action="analyze",
        params={"category": "auth"},
        priority=priority,
    )


def test_add_tasks_boosts_hitl_route_priority_when_gate_enforced(monkeypatch):
    mc = _new_mc(monkeypatch, "enforce_hitl")
    task = _mk_auth_task(priority=95)

    added = mc._add_tasks([task], source="test")

    queued = mc.task_queue.get_by_id(task.id)
    assert added == 1
    assert queued is not None
    assert queued.priority >= 1000


def test_add_tasks_does_not_boost_in_observe_mode(monkeypatch):
    mc = _new_mc(monkeypatch, "observe")
    task = _mk_auth_task(priority=95)

    added = mc._add_tasks([task], source="test")

    queued = mc.task_queue.get_by_id(task.id)
    assert added == 1
    assert queued is not None
    assert queued.priority == 95
