from __future__ import annotations

import copy
import json
from typing import Callable
from pathlib import Path

from src.core.domain.model.task import Task
from src.core.utils.json_utils import safe_json_loads


def resolve_running_task_resume_policy(
    running_count: int,
    prompt_for_resume: Callable[[str], str] = input,
) -> bool:
    should_rerun = True
    if running_count <= 0:
        return should_rerun

    try:
        choice = prompt_for_resume("   Resume these tasks? (Y/n): ").strip().lower()
        if choice == "n":
            should_rerun = False
    except Exception:
        pass

    return should_rerun


def load_session_payload_from_path(filepath: str):
    path = Path(filepath)
    if not path.exists():
        return None
    return safe_json_loads(path.read_text(), context=f"load_session:{filepath}")


def build_start_session_payload(
    target: str,
    mode: str,
    context_target_info,
) -> dict:
    project_name = target.replace("https://", "").replace("http://", "").replace("/", "_")[:50]
    return {
        "project_name": project_name,
        "mode": mode,
        "target_url": target,
        "metadata": {
            "context": context_target_info,
        },
    }


def await_session_save_future(future, timeout: int = 15) -> None:
    if future:
        future.result(timeout=timeout)


def build_async_session_payload(
    task_queue,
    completed_tasks,
    context,
    pending_hitl,
    coverage_gate,
    scenario_coverage,
    timestamp: float,
    default_start_time: float,
):
    payload = {
        "task_queue": [
            {
                "id": task.id,
                "name": task.name,
                "agent_type": task.agent_type,
                "action": task.action,
                "phase": task.phase,
                "params": task.params,
                "state": task.state.value if hasattr(task.state, "value") else str(task.state),
                "priority": task.priority,
                "parent_id": task.parent_id,
                "replan_depth": task.replan_depth,
            }
            for task in task_queue
        ],
        "completed_tasks": [
            {
                "id": task.id,
                "name": task.name,
                "agent_type": task.agent_type,
                "action": task.action,
                "phase": task.phase,
                "params": task.params,
                "state": task.state.value if hasattr(task.state, "value") else str(task.state),
                "error": task.error,
                "result": task.result,
                "priority": getattr(task, "priority", 50),
                "failure_phase": getattr(task, "failure_phase", None),
                "failure_reason": getattr(task, "failure_reason", None),
                "failure_reason_code": getattr(task, "failure_reason_code", None),
                "timeout_retry_count": int(getattr(task, "timeout_retry_count", 0) or 0),
            }
            for task in completed_tasks
        ],
        "context": {
            "total_attempts": context._total_attempts,
            "successful_attempts": context._successful_attempts,
            "bypass_methods": context.bypass_methods,
            "discovered_assets": context.discovered_assets,
            "target_info": context.target_info,
            "coverage_gate": coverage_gate,
            "scenario_coverage": scenario_coverage,
            "pending_hitl": copy.deepcopy(pending_hitl),
        },
        "start_time": context.target_info.get("start_time", default_start_time),
        "timestamp": timestamp,
        "coverage_gate": coverage_gate,
        "scenario_coverage": scenario_coverage,
        "pending_hitl": copy.deepcopy(pending_hitl),
    }

    adjacency_list = {}
    all_tasks = list(task_queue) + list(completed_tasks)
    for task in all_tasks:
        if task.parent_id:
            adjacency_list.setdefault(task.parent_id, []).append(task.id)
    payload["adjacency_list"] = adjacency_list
    return payload


def build_checkpoint_session_state(
    task_queue,
    completed_tasks,
    context,
    pending_hitl,
):
    completed_targets = [task.id for task in completed_tasks]
    metadata = {
        "context": context.target_info,
        "success_rate": context.success_rate,
        "total_attempts": context.total_attempts,
        "successful_attempts": context.successful_attempts,
        "discovered_assets": context.discovered_assets,
        "bypass_methods": context.bypass_methods,
        "attack_chain": context.current_attack_chain,
        "pending_hitl": copy.deepcopy(pending_hitl),
    }
    return (
        serialize_legacy_session_task_queue(task_queue),
        completed_targets,
        metadata,
    )


def serialize_legacy_session_task_queue(task_queue) -> list[str]:
    return [
        safe_json_dumps(
            {
                "id": task.id,
                "name": task.name,
                "agent_type": task.agent_type,
                "action": task.action,
                "params": task.params,
                "priority": task.priority,
                "parent_id": task.parent_id,
            }
        )
        for task in task_queue
    ]


def restore_legacy_resume_session_state(session) -> dict:
    metadata = session.metadata or {}
    pending_hitl = metadata.get("pending_hitl", [])
    task_queue, failed_task_deserializations = deserialize_legacy_session_task_queue(
        session.pending_targets or []
    )
    return {
        "context_target_info": metadata.get("context", {}),
        "total_attempts": metadata.get("total_attempts", 0),
        "successful_attempts": metadata.get("successful_attempts", 0),
        "discovered_assets": metadata.get("discovered_assets", []),
        "bypass_methods": metadata.get("bypass_methods", []),
        "attack_chain": metadata.get("attack_chain", []),
        "pending_hitl": copy.deepcopy(pending_hitl) if isinstance(pending_hitl, list) else [],
        "task_queue": task_queue,
        "failed_task_deserializations": failed_task_deserializations,
    }


def deserialize_legacy_session_task_queue(serialized: list[str]) -> tuple[list[Task], list[str]]:
    tasks: list[Task] = []
    failed_ids: list[str] = []
    for s in serialized:
        try:
            d = json.loads(s)
            task = Task(
                id=d["id"],
                name=d["name"],
                agent_type=d["agent_type"],
                action=d["action"],
                params=d.get("params", {}),
                priority=d.get("priority", 0),
                parent_id=d.get("parent_id"),
            )
            tasks.append(task)
        except (json.JSONDecodeError, KeyError):
            failed_ids.append(s[:50] if len(s) > 50 else s)
    return tasks, failed_ids


def safe_json_dumps(payload) -> str:
    return json.dumps(payload, ensure_ascii=False)
