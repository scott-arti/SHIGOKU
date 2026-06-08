from __future__ import annotations

import copy
from typing import Any


def build_pending_hitl_ticket(
    task,
    decision: dict[str, Any],
    gate_mode: str,
    snapshot: dict[str, Any],
    ticket_id: str,
    created_at: int,
) -> dict[str, Any]:
    reasons = decision.get("reasons", [])
    if not isinstance(reasons, list):
        reasons = [str(reasons)]

    matched_signals = decision.get("matched_signals", [])
    if not isinstance(matched_signals, list):
        matched_signals = []

    friction_axes = decision.get("friction_axes", {})
    if not isinstance(friction_axes, dict):
        friction_axes = {}

    return {
        "ticket_id": ticket_id,
        "status": "pending",
        "created_at": created_at,
        "updated_at": created_at,
        "resolved_at": None,
        "task_id": str(getattr(task, "id", "") or ""),
        "task_name": str(getattr(task, "name", "") or ""),
        "task_agent": str(getattr(task, "agent_type", "") or ""),
        "scenario_id": str(decision.get("scenario_id", "default_route") or "default_route").strip().lower(),
        "route": str(decision.get("route", "shigoku_only") or "shigoku_only").strip().lower(),
        "gate_mode": str(gate_mode or "observe"),
        "reasons": reasons,
        "matched_signals": matched_signals,
        "friction_score": int(decision.get("friction_score", 0) or 0),
        "friction_axes": dict(friction_axes),
        "route_decision_basis": str(decision.get("route_decision_basis", "") or "").strip(),
        "task": copy.deepcopy(snapshot),
        "queued_task_id": None,
        "outcome": None,
    }
