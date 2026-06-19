"""
MasterConductor intervention coordinator (SGK-2026-0298).

Handles intervention gate approval actions. Takes facade reference as parameter.
Does NOT hold MasterConductor instance. Final state mutation stays in facade.
"""

from __future__ import annotations

import logging
from contextlib import nullcontext
from typing import Any, Optional

from src.core.domain.model.task import Task, TaskState

_log = logging.getLogger(__name__)


def apply_intervention_defer_v1_coordinator(
    facade: Any, task: Task, precheck: Any, gate_mode: str,
) -> dict:
    """Apply defer_manual_v1 intervention action. Extracted from facade."""
    task.params.setdefault("_intervention", {})
    task.params["_intervention"]["approval"] = {
        "required": True, "approved": False,
        "mode": gate_mode, "status": "deferred_manual_v1",
    }
    task.state = TaskState.SKIPPED
    task.error = precheck.error_message or ""
    facade._record_failure_context(task, "precheck", "intervention_gate_deferred_manual_v1")
    return {
        "success": True, "skipped": True, "pending_hitl": False,
        "manual_deferred": True, "message": task.error,
        "intervention": precheck.intervention_meta,
    }


def apply_intervention_require_approval_coordinator(
    facade: Any, task: Task, decision: dict, gate_mode: str,
    precheck: Any, exec_record: Any, has_callback: bool,
) -> Optional[dict]:
    """Handle require_approval intervention: callback / pending / denied. Extracted from facade."""
    route = str(decision.get("route", "shigoku_only") or "shigoku_only").strip().lower()
    approved: Optional[bool] = None
    if has_callback:
        hitl_info = facade._build_intervention_hitl_info(task, decision, gate_mode)
        approved = facade.request_human_approval(hitl_info)
    else:
        _log.info(
            "Intervention gate marked task %s as pending HITL (route=%s, scenario=%s)",
            task.id, route, decision.get("scenario_id", "default_route"),
        )

    task.params.setdefault("_intervention", {})
    task.params["_intervention"]["approval"] = {
        "required": True,
        "approved": bool(approved) if approved is not None else False,
        "mode": gate_mode,
    }

    if approved is True:
        task.params["_intervention"]["approval"]["status"] = "approved"
        return None

    if approved is None:
        ticket_id = facade._register_pending_hitl_ticket(task, decision, gate_mode)
        pending_message = (
            f"Pending HITL approval (ticket={ticket_id}, mode={gate_mode}, route={route}, "
            f"scenario={decision.get('scenario_id', 'default_route')})"
        )
        task.params["_intervention"]["approval"]["status"] = "pending"
        task.params["_intervention"]["approval"]["ticket_id"] = ticket_id
        lock_obj = getattr(facade, "_state_lock", None)
        lock_ctx = lock_obj if lock_obj is not None else nullcontext()
        with lock_ctx:
            task.state = TaskState.SKIPPED
            task.error = pending_message
            facade._record_failure_context(task, "precheck", "intervention_gate_pending_hitl")
            if exec_record is not None:
                exec_record.mark_completed(
                    success=True, summary=pending_message,
                    metadata={"intervention": {
                        "decision": decision, "gate_mode": gate_mode,
                        "approved": False, "pending_hitl": True, "ticket_id": ticket_id,
                    }},
                )
                if getattr(facade, "execution_log", None) is not None:
                    facade.execution_log.add_record(exec_record)
        return {
            "success": True, "skipped": True, "pending_hitl": True,
            "hitl_ticket_id": ticket_id, "message": pending_message,
            "intervention": {
                "decision": decision, "gate_mode": gate_mode,
                "approved": False, "pending_hitl": True, "ticket_id": ticket_id,
            },
        }

    # approved is False: denied
    task.params["_intervention"]["approval"]["status"] = "rejected"
    denial_error = (
        f"Blocked by intervention gate (mode={gate_mode}, route={route}, "
        f"scenario={decision.get('scenario_id', 'default_route')})"
    )
    lock_obj = getattr(facade, "_state_lock", None)
    lock_ctx = lock_obj if lock_obj is not None else nullcontext()
    with lock_ctx:
        task.state = TaskState.SKIPPED
        task.error = denial_error
        facade._record_failure_context(task, "precheck", "intervention_gate_denied")
        if exec_record is not None:
            exec_record.mark_completed(
                success=False, error=denial_error,
                metadata={"intervention": {
                    "decision": decision, "gate_mode": gate_mode, "approved": False,
                }},
            )
            if getattr(facade, "execution_log", None) is not None:
                facade.execution_log.add_record(exec_record)
    return {
        "success": False, "skipped": True, "error": denial_error,
        "intervention": {"decision": decision, "gate_mode": gate_mode, "approved": False},
    }
