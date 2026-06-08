from types import SimpleNamespace

from src.core.engine.master_conductor import MasterConductor
from src.core.engine.task_queue import DynamicTaskQueue


def _new_mc_with_context(recon_start_step=None, recon_end_step=None):
    mc = MasterConductor.__new__(MasterConductor)
    target_info = {"aggressive_targets": []}
    if recon_start_step is not None:
        target_info["recon_start_step"] = recon_start_step
    if recon_end_step is not None:
        target_info["recon_end_step"] = recon_end_step
    mc.context = SimpleNamespace(target_info=target_info)
    mc.task_queue = DynamicTaskQueue(max_memory_size=32)
    mc.recipe_loader = None
    mc.llm_client = None
    return mc


def _extract_recon_task(tasks):
    return next(task for task in tasks if getattr(task, "agent_type", "") == "recon_master")


def test_plan_uses_context_recon_step_override():
    mc = _new_mc_with_context(recon_start_step=6, recon_end_step=8)

    tasks = mc.plan("Reconnaissance", "http://127.0.0.1:8888/")
    recon_task = _extract_recon_task(tasks)

    assert recon_task.params.get("start_step") == 6
    assert recon_task.params.get("end_step") == 8


def test_plan_falls_back_when_recon_step_override_invalid_range():
    mc = _new_mc_with_context(recon_start_step=8, recon_end_step=3)

    tasks = mc.plan("Reconnaissance", "http://127.0.0.1:8888/")
    recon_task = _extract_recon_task(tasks)

    assert recon_task.params.get("start_step") == 1
    assert recon_task.params.get("end_step") == 8

