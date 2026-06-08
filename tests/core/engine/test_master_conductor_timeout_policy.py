from types import SimpleNamespace

import pytest

from src.config import settings
from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor


def _new_mc_minimal() -> MasterConductor:
    mc = MasterConductor.__new__(MasterConductor)
    mc.rag = None
    mc.context = SimpleNamespace(bypass_methods=[])
    return mc


def test_default_task_retries_timeout_once(monkeypatch):
    mc = _new_mc_minimal()
    task = Task(id="task_default", name="Default Task", agent_type="default")

    monkeypatch.setattr(settings, "timeout_retry_max", 1, raising=False)
    monkeypatch.setattr(settings, "recon_master_timeout_retry_max", 0, raising=False)

    calls = {"count": 0}

    def _always_timeout(*args, **kwargs):
        calls["count"] += 1
        raise TimeoutError("forced timeout")

    mc._run_async_safe = _always_timeout
    mc._dispatch = lambda _task: None

    with pytest.raises(TimeoutError):
        mc._dispatch_with_timeout_retry(task)

    assert calls["count"] == 2


def test_recon_master_does_not_retry_timeout_by_default(monkeypatch):
    mc = _new_mc_minimal()
    task = Task(id="task_recon", name="Recon Task", agent_type="recon_master")

    monkeypatch.setattr(settings, "timeout_retry_max", 1, raising=False)
    monkeypatch.setattr(settings, "recon_master_timeout_retry_max", 0, raising=False)

    calls = {"count": 0}

    def _always_timeout(*args, **kwargs):
        calls["count"] += 1
        raise TimeoutError("forced timeout")

    mc._run_async_safe = _always_timeout
    mc._dispatch = lambda _task: None

    with pytest.raises(TimeoutError):
        mc._dispatch_with_timeout_retry(task)

    assert calls["count"] == 1


def test_recon_master_timeout_replan_disabled_by_default(monkeypatch):
    mc = _new_mc_minimal()
    task = Task(id="task_recon", name="Recon Task", agent_type="recon_master")

    monkeypatch.setattr(settings, "recon_master_timeout_replan_enabled", False, raising=False)

    alternatives = mc.replan(task, "network timeout while running recon")
    assert alternatives == []


def test_recon_master_timeout_replan_can_be_enabled(monkeypatch):
    mc = _new_mc_minimal()
    task = Task(id="task_recon", name="Recon Task", agent_type="recon_master", priority=100)

    monkeypatch.setattr(settings, "recon_master_timeout_replan_enabled", True, raising=False)

    alternatives = mc.replan(task, "network timeout while running recon")
    assert len(alternatives) >= 1
    assert alternatives[0].agent_type == "recon_master"
    assert alternatives[0].params.get("delay_seconds") == 5
