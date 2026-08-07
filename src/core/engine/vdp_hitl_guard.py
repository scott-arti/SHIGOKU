"""
VDP HITL ticket verification — SGK-2026-0421 Step 6 (design constraint G).

A HITL ticket ID existing is NOT approval. Before a confirmation_required
capability may pass, the ticket must:
1. exist in the pending HITL store,
2. have status ``approved``, and
3. be bound to the same action / hypothesis / actor / risk_class.

The existing MasterConductor ``pending_hitl`` store is reused: 0421 tickets
are created via ``build_vdp_hitl_ticket`` (status pending) and approved
through the existing ``set_pending_hitl_status`` path. Legacy tickets
without a ``vdp_binding`` can never satisfy the binding check (fail-closed).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class HitlVerification:
    """Result of a HITL ticket verification."""

    verified: bool
    reason_code: str  # "" | hitl_ticket_not_found | hitl_ticket_not_approved | hitl_ticket_not_bound
    detail: str = ""


def build_vdp_hitl_ticket(
    ticket_id: str,
    *,
    action: str,
    hypothesis_id: str,
    actor: str,
    risk_class: str,
    evidence_gap: str = "",
) -> Dict[str, Any]:
    """Create a VDP HITL ticket entry (status pending).

    The binding fields live under ``vdp_binding``; approval happens through
    the existing pending_hitl status transition (``set_pending_hitl_status``).
    """
    return {
        "ticket_id": ticket_id,
        "status": "pending",
        "created_at": int(time.time()),
        "updated_at": int(time.time()),
        "resolved_at": None,
        "task_id": "",
        "scenario_id": "vdp_follow_up",
        "gate_mode": "vdp",
        "vdp_binding": {
            "action": str(action or ""),
            "hypothesis_id": str(hypothesis_id or ""),
            "actor": str(actor or ""),
            "risk_class": str(risk_class or ""),
            "evidence_gap": str(evidence_gap or ""),
        },
    }


def verify_hitl_ticket(
    ticket_id: str,
    *,
    tickets: Optional[List[Any]],
    action: str = "",
    hypothesis_id: str = "",
    actor: str = "",
    risk_class: str = "",
) -> HitlVerification:
    """Verify a HITL ticket against the pending store and binding context.

    Args:
        ticket_id: The claimed ticket ID (presence alone is not approval).
        tickets: The pending_hitl store entries (list of dicts).
        action: Expected action class (e.g. follow_up_probe).
        hypothesis_id: Expected hypothesis ID.
        actor: Expected actor (authA/authB/...).
        risk_class: Expected risk class.

    Returns:
        HitlVerification with verified flag and reason code.
    """
    tid = str(ticket_id or "").strip()
    if not tid:
        return HitlVerification(False, "hitl_ticket_not_found", "no ticket id")

    store = tickets if isinstance(tickets, list) else []
    ticket = next(
        (t for t in store if isinstance(t, dict) and str(t.get("ticket_id", "") or "") == tid),
        None,
    )
    if ticket is None:
        return HitlVerification(
            False,
            "hitl_ticket_not_found",
            f"ticket {tid} does not exist in the pending HITL store",
        )

    status = str(ticket.get("status", "") or "").strip().lower()
    if status != "approved":
        return HitlVerification(
            False,
            "hitl_ticket_not_approved",
            f"ticket {tid} status is {status!r}, not 'approved'",
        )

    binding = ticket.get("vdp_binding")
    if not isinstance(binding, dict):
        return HitlVerification(
            False,
            "hitl_ticket_not_bound",
            f"ticket {tid} has no vdp_binding (legacy ticket cannot be verified)",
        )

    expected = {
        "action": str(action or ""),
        "hypothesis_id": str(hypothesis_id or ""),
        "actor": str(actor or ""),
        "risk_class": str(risk_class or ""),
    }
    for key, want in expected.items():
        got = str(binding.get(key, "") or "")
        if want and got != want:
            return HitlVerification(
                False,
                "hitl_ticket_not_bound",
                f"ticket {tid} binding {key}={got!r} != expected {want!r}",
            )

    return HitlVerification(True, "", f"ticket {tid} verified")
