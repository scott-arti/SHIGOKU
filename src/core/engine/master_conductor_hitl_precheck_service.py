"""
HITL / intervention precheck 判定サービス。

MasterConductor facade から受け取った callable を使って
precheck decision / mutation plan / notification payload を返す。
task state や execution_log の最終 mutation は facade 側が担当する。

HitlService は ticket add/update/enqueue/done を担当する。
本 service は precheck decision / mutation plan のみを担当する。

依存方向: master_conductor.py -> master_conductor_hitl_precheck_service.py -> なし
service は MasterConductor instance を保持せず、必要な依存は
snapshot、明示引数、または callable として渡す。

サービス構造:
- scenario check: SCN07-12 / manual defer V1 の判定
- approval gate: 承認要不要 / gate mode 判定
- payload builder: notification / HITL info を構築

代表テストファイル:
- tests/core/engine/test_master_conductor_intervention_gate.py
- tests/core/engine/test_master_conductor_hitl_pending.py
- tests/core/engine/test_master_conductor_hitl_priority.py

禁止依存:
- master_conductor.py への import 禁止
- task_queue / execution_log / pending_hitl への直接書き込み禁止
- close/shutdown 対象 resource の保持禁止
"""

from __future__ import annotations

from typing import Any, Optional


# ── Scenario Classification ────────────────────────────────────────────


def is_scn07_to_12(
    decision: dict[str, Any],
    extract_scn_number: Any,
) -> bool:
    """SCN07〜SCN12 の範囲内かを判定する。"""
    scenario_id = str(decision.get("scenario_id", "") or "").strip().lower().replace("-", "_")
    if not scenario_id.startswith("scn_"):
        return False
    number = extract_scn_number(scenario_id)
    return 7 <= number <= 12


def is_manual_defer_target_v1(
    decision: dict[str, Any],
    extract_scn_number: Any,
) -> bool:
    """Ver.1 manual defer policy: SCN11は自律chain probing用に実行可能に残す。"""
    scenario_id = str(decision.get("scenario_id", "") or "").strip().lower().replace("-", "_")
    if not scenario_id.startswith("scn_"):
        return False
    number = extract_scn_number(scenario_id)
    return number in {7, 8, 9, 10, 12}


def normalize_intervention_gate_mode(
    settings: Any,
) -> str:
    """intervention gate mode を正規化する。"""
    mode = str(getattr(settings, "intervention_gate_mode", "observe") or "observe").strip().lower()
    if mode not in {"observe", "enforce_human_preferred", "enforce_hitl"}:
        return "observe"
    return mode


# ── Approval Gate ──────────────────────────────────────────────────────


def requires_intervention_approval(
    decision: dict[str, Any],
    gate_mode: str,
) -> bool:
    """承認が必要かどうかを判定する。"""
    route = str(decision.get("route", "shigoku_only") or "shigoku_only").strip().lower()
    confidence = float(decision.get("confidence", 0.0) or 0.0)
    enforce_hitl = gate_mode == "enforce_hitl"
    enforce_human = gate_mode == "enforce_human_preferred"
    is_hitl = route in {
        "shigoku_hitl",
        "shigoku_hitl_priority",
        "intervention_hitl_direct",
    }
    is_autonomous = route == "shigoku_only"
    low_confidence = confidence < 0.3

    if enforce_hitl:
        return True
    if enforce_human and (is_hitl or low_confidence):
        return True
    if is_hitl:
        return True
    if is_autonomous and low_confidence:
        return False
    if gate_mode == "observe":
        return False
    return False


# ── Notification Payload ───────────────────────────────────────────────


def build_scn07_12_notification_lines(
    task_id: str,
    task_name: str,
    decision: dict[str, Any],
    gate_mode: str,
    *,
    target_summary: str,
) -> list[str]:
    """SCN07-12 intervention 通知のメッセージ行を構築する。"""
    scenario_id = str(decision.get("scenario_id", "") or "").strip().lower().replace("-", "_")
    number = _extract_scn_number_static(scenario_id)

    scenario_titles = {
        7: "Token Trust Boundary",
        8: "Out-of-Band External Channel",
        9: "Multi-step State Machine",
        10: "Semantic Business Logic",
        11: "Multi-Vector Chain",
        12: "Advanced SSRF Internal Topology",
    }
    suspected = scenario_titles.get(number, "Manual Review Scenario")
    route = str(decision.get("route", "shigoku_only") or "shigoku_only")
    confidence = str(decision.get("confidence", 0.0))

    reasons = decision.get("reasons", [])
    if not isinstance(reasons, list):
        reasons = [str(reasons)]
    matched = decision.get("matched_signals", [])
    if not isinstance(matched, list):
        matched = [str(matched)]
    reason_text = " | ".join(str(x) for x in reasons[:4]) if reasons else "-"
    matched_text = " | ".join(str(x) for x in matched[:6]) if matched else "-"

    return [
        f"🔔 SCN{number:02d} Manual Validation Candidate",
        f"- Scenario: {suspected} ({scenario_id})",
        f"- Target(s): {target_summary}",
        f"- Task: {task_name}",
        f"- Route/Gate: {route} / {str(gate_mode or 'observe')}",
        f"- Confidence: {confidence}",
        f"- Suspected Signals: {matched_text}",
        f"- Why Flagged: {reason_text}",
        "- Required Action: Manually validate this scenario and record outcome (verified / not reproducible / needs more evidence).",
    ]


# ── HITL Info Builder ──────────────────────────────────────────────────


def build_intervention_hitl_info(
    task_id: str,
    task_name: str,
    task_action: str,
    decision: dict[str, Any],
    gate_mode: str,
) -> dict[str, Any]:
    """HITL callback 用の info dict を構築する。"""
    return {
        "task_id": task_id,
        "task_name": task_name,
        "task_action": task_action,
        "risk_level": "warning",
        "scenario_id": str(decision.get("scenario_id", "default_route") or "default_route"),
        "route": str(decision.get("route", "shigoku_only") or "shigoku_only"),
        "gate_mode": gate_mode,
        "confidence": float(decision.get("confidence", 0.0) or 0.0),
        "reasons": list(decision.get("reasons", []) or []),
    }


# ── Static Helpers ─────────────────────────────────────────────────────


def _extract_scn_number_static(scenario_id: str) -> int:
    """scenario_id から scn 番号を抽出する（static 版）。"""
    try:
        if scenario_id.startswith("scn_"):
            return int(scenario_id.split("_")[1])
        return 0
    except (ValueError, IndexError):
        return 0


# ── Precheck Decision Tree (pure: mutation plan のみ、状態変更は facade) ──


class PrecheckDecision:
    """intervention precheck の判定結果（mutation plan）。"""
    __slots__ = (
        "action",
        "skipped",
        "pending_hitl",
        "manual_deferred",
        "approved",
        "error_message",
        "ticket_id",
        "exec_record_metadata",
        "intervention_meta",
    )

    def __init__(
        self,
        action: str,
        *,
        skipped: bool = False,
        pending_hitl: bool = False,
        manual_deferred: bool = False,
        approved: Optional[bool] = None,
        error_message: Optional[str] = None,
        ticket_id: Optional[str] = None,
        exec_record_metadata: Optional[dict[str, Any]] = None,
        intervention_meta: Optional[dict[str, Any]] = None,
    ):
        self.action = action
        self.skipped = skipped
        self.pending_hitl = pending_hitl
        self.manual_deferred = manual_deferred
        self.approved = approved
        self.error_message = error_message
        self.ticket_id = ticket_id
        self.exec_record_metadata = exec_record_metadata or {}
        self.intervention_meta = intervention_meta or {}


def evaluate_precheck_decision(
    task_id: str,
    decision: dict[str, Any],
    gate_mode: str,
    *,
    is_hitl_resume: bool,
    extract_scn_number: Any,
    is_manual_defer_v1_enabled: bool,
    has_callback: bool,
) -> PrecheckDecision:
    """precheck decision tree を評価し、PrecheckDecision を返す。

    task state や execution_log への書き込みは行わない。
    返された PrecheckDecision を元に facade が最終 mutation を適用する。
    """
    route = str(decision.get("route", "shigoku_only") or "shigoku_only").strip().lower()
    scenario_id = str(decision.get("scenario_id", "default_route") or "default_route")

    # 1. HITL resume
    if is_hitl_resume:
        return PrecheckDecision(
            action="resume",
            approved=True,
            intervention_meta={
                "decision": decision,
                "gate_mode": gate_mode,
                "approved": True,
                "pending_hitl": False,
                "resumed_from_pending_hitl": True,
            },
        )

    # 2. Manual defer V1
    if is_manual_defer_v1_enabled and is_manual_defer_target_v1(decision, extract_scn_number):
        return PrecheckDecision(
            action="defer_manual_v1",
            skipped=True,
            manual_deferred=True,
            error_message=(
                f"Deferred for manual validation in Ver.1 (scenario={scenario_id}, "
                f"route={route}, gate_mode={gate_mode})"
            ),
            intervention_meta={
                "decision": decision,
                "gate_mode": gate_mode,
                "approved": False,
                "pending_hitl": False,
                "manual_deferred": True,
            },
        )

    # 3. No approval needed
    if not requires_intervention_approval(decision, gate_mode):
        return PrecheckDecision(
            action="allow",
            intervention_meta={
                "decision": decision,
                "gate_mode": gate_mode,
                "approved": True,
                "pending_hitl": False,
            },
        )

    # 4. Approval required
    return PrecheckDecision(
        action="require_approval",
        skipped=True,
        pending_hitl=True,
        approved=False,
        ticket_id=None,  # facade が割り当てる
        intervention_meta={
            "decision": decision,
            "gate_mode": gate_mode,
            "approved": False,
            "pending_hitl": True,
            "route": route,
            "scenario_id": scenario_id,
        },
    )
