from __future__ import annotations

import copy
from typing import Any

from src.core.domain.model.task import Task


def snapshot_task_for_hitl(task: Task) -> dict[str, Any]:
    params = task.params if isinstance(task.params, dict) else {}
    return {
        "id": str(task.id),
        "name": str(task.name),
        "agent_type": str(task.agent_type),
        "action": str(task.action),
        "phase": str(getattr(task, "phase", "attack") or "attack"),
        "params": copy.deepcopy(params),
        "priority": int(getattr(task, "priority", 50) or 50),
        "parent_id": getattr(task, "parent_id", None),
        "replan_depth": int(getattr(task, "replan_depth", 0) or 0),
        "tags": list(getattr(task, "tags", []) or []),
        "target": str(getattr(task, "target", "") or ""),
    }
