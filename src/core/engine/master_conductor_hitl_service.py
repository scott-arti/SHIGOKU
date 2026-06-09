"""HITL (Human-in-the-Loop) Service

pending HITL ticket 管理と承認済み task enqueue を担当。
pending_hitl list の所有は facade に残し、本 service は状態遷移のみを担当する。
"""

from __future__ import annotations

import copy
import time
import uuid as uuid_module
from typing import Any, Optional

from src.core.domain.model.task import Task
from src.core.engine.master_conductor_hitl_snapshot import snapshot_task_for_hitl
from src.core.engine.master_conductor_hitl_ticket import build_pending_hitl_ticket


class HitlService:

    def __init__(
        self,
        *,
        pending_hitl: list[dict[str, Any]],
        task_queue,
        extract_scn_number,
    ):
        self._pending_hitl = pending_hitl
        self._task_queue = task_queue
        self._extract_scn_number = extract_scn_number

    @staticmethod
    def requires_intervention_approval(decision: dict[str, Any], gate_mode: str) -> bool:
        route = str(decision.get("route", "shigoku_only") or "shigoku_only").strip().lower()
        if gate_mode == "observe":
            return False
        if gate_mode == "enforce_hitl":
            return route in {"shigoku_hitl", "human_preferred"}
        if gate_mode == "enforce_human_preferred":
            return route == "human_preferred"
        return False

    @staticmethod
    def build_intervention_hitl_info(task: Task, decision: dict[str, Any], gate_mode: str) -> dict[str, Any]:
        route = str(decision.get("route", "shigoku_only") or "shigoku_only")
        scenario_id = str(decision.get("scenario_id", "default_route") or "default_route")
        reasons = decision.get("reasons", [])
        if not isinstance(reasons, list):
            reasons = [str(reasons)]
        matched = decision.get("matched_signals", [])
        if not isinstance(matched, list):
            matched = [str(matched)]
        friction_score = int(decision.get("friction_score", 0) or 0)
        friction_axes = decision.get("friction_axes", {})
        if not isinstance(friction_axes, dict):
            friction_axes = {}
        decision_basis = str(decision.get("route_decision_basis", "") or "").strip()
        return {
            "reason": "Intervention policy checkpoint",
            "severity": "warning" if route == "shigoku_hitl" else "critical",
            "summary": (
                f"Intervention route={route} (scenario={scenario_id}, gate_mode={gate_mode}) "
                f"for task '{task.name}'"
            ),
            "data": {
                "route": route,
                "scenario_id": scenario_id,
                "confidence": decision.get("confidence", 0.0),
                "reasons": reasons,
                "matched_signals": matched,
                "friction_score": friction_score,
                "friction_axes": friction_axes,
                "route_decision_basis": decision_basis,
                "task_id": task.id,
                "task_name": task.name,
                "task_action": task.action,
                "task_agent": task.agent_type,
            },
        }

    @staticmethod
    def build_task_from_hitl_snapshot(ticket: dict[str, Any]) -> Optional[Task]:
        if not isinstance(ticket, dict):
            return None
        snapshot = ticket.get("task")
        if not isinstance(snapshot, dict):
            return None

        base_id = str(snapshot.get("id", "task_hitl") or "task_hitl").strip()
        new_id = f"{base_id}_hitl_{uuid_module.uuid4().hex[:8]}"
        params = snapshot.get("params", {})
        params = copy.deepcopy(params) if isinstance(params, dict) else {}
        intervention = params.get("_intervention", {})
        if not isinstance(intervention, dict):
            intervention = {}
        intervention["hitl_ticket_id"] = str(ticket.get("ticket_id", "") or "")
        intervention["resumed_from_pending_hitl"] = True
        params["_intervention"] = intervention
        return Task(
            id=new_id,
            name=str(snapshot.get("name", "HITL Resumed Task") or "HITL Resumed Task"),
            agent_type=str(snapshot.get("agent_type", "universal") or "universal"),
            action=str(snapshot.get("action", "run") or "run"),
            phase=str(snapshot.get("phase", "attack") or "attack"),
            params=params,
            priority=int(snapshot.get("priority", 50) or 50),
            parent_id=snapshot.get("parent_id"),
            replan_depth=int(snapshot.get("replan_depth", 0) or 0),
            tags=list(snapshot.get("tags", []) or []),
            target=str(snapshot.get("target", "") or ""),
        )

    def register_pending_hitl_ticket(self, task: Task, decision: dict[str, Any], gate_mode: str) -> str:
        tickets = self._pending_hitl
        scenario_id = str(decision.get("scenario_id", "default_route") or "default_route").strip().lower()
        route = str(decision.get("route", "shigoku_only") or "shigoku_only").strip().lower()
        task_id_str = str(getattr(task, "id", "") or "")

        for ticket in tickets:
            if not isinstance(ticket, dict):
                continue
            if str(ticket.get("task_id", "") or "") != task_id_str:
                continue
            if str(ticket.get("scenario_id", "") or "").strip().lower() != scenario_id:
                continue
            status = str(ticket.get("status", "pending") or "pending").strip().lower()
            if status in {"pending", "approved", "queued"}:
                return str(ticket.get("ticket_id", "") or "")

        number = self._extract_scn_number(scenario_id)
        ticket_prefix = f"scn{number:02d}" if number > 0 else "scn00"
        ticket_id = f"hitl_{ticket_prefix}_{uuid_module.uuid4().hex[:8]}"
        created_at = int(time.time())
        ticket = build_pending_hitl_ticket(
            task=task,
            decision=decision,
            gate_mode=gate_mode,
            snapshot=snapshot_task_for_hitl(task),
            ticket_id=ticket_id,
            created_at=created_at,
        )
        tickets.append(ticket)
        return ticket_id

    def list_pending_hitl_tickets(self, statuses: Optional[set[str]] = None) -> list[dict[str, Any]]:
        tickets = self._pending_hitl
        wanted = {s.strip().lower() for s in statuses} if statuses else None
        rows: list[dict[str, Any]] = []
        for ticket in tickets:
            if not isinstance(ticket, dict):
                continue
            status = str(ticket.get("status", "pending") or "pending").strip().lower()
            if wanted and status not in wanted:
                continue
            rows.append(copy.deepcopy(ticket))
        rows.sort(key=lambda row: int(row.get("created_at", 0) or 0))
        return rows

    def set_pending_hitl_status(self, ticket_id: str, status: str) -> bool:
        target_id = str(ticket_id or "").strip()
        desired = str(status or "").strip().lower()
        if not target_id or desired not in {"approved", "rejected", "pending"}:
            return False

        now = int(time.time())
        tickets = self._pending_hitl
        for ticket in tickets:
            if not isinstance(ticket, dict):
                continue
            if str(ticket.get("ticket_id", "") or "") != target_id:
                continue
            ticket["status"] = desired
            ticket["updated_at"] = now
            if desired == "approved":
                ticket["resolved_at"] = None
            else:
                ticket["resolved_at"] = now if desired == "rejected" else None
            return True
        return False

    def enqueue_approved_hitl_tasks(self, max_tasks: Optional[int] = None) -> int:
        limit = None if max_tasks is None else max(0, int(max_tasks))
        queued = 0
        now = int(time.time())
        tickets = self._pending_hitl

        for ticket in tickets:
            if not isinstance(ticket, dict):
                continue
            status = str(ticket.get("status", "pending") or "pending").strip().lower()
            if status != "approved":
                continue
            task = self.build_task_from_hitl_snapshot(ticket)
            if task is None:
                ticket["status"] = "rejected"
                ticket["updated_at"] = now
                ticket["resolved_at"] = now
                ticket["outcome"] = "invalid_task_snapshot"
                continue
            self._task_queue.add(task)
            ticket["status"] = "queued"
            ticket["queued_task_id"] = task.id
            ticket["updated_at"] = now
            queued += 1
            if limit is not None and queued >= limit:
                break

        return queued

    def mark_pending_hitl_done(self, task: Task, success: bool) -> None:
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        intervention = params.get("_intervention", {})
        if not isinstance(intervention, dict):
            return
        ticket_id = str(intervention.get("hitl_ticket_id", "") or "").strip()
        if not ticket_id:
            return

        tickets = self._pending_hitl
        now = int(time.time())
        for ticket in tickets:
            if not isinstance(ticket, dict):
                continue
            if str(ticket.get("ticket_id", "") or "") != ticket_id:
                continue
            ticket["status"] = "done"
            ticket["resolved_at"] = now
            ticket["updated_at"] = now
            ticket["outcome"] = "success" if success else "failed"
            ticket["queued_task_id"] = str(getattr(task, "id", "") or ticket.get("queued_task_id"))
            break
