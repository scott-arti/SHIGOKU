from __future__ import annotations

import copy
import json
from typing import Any, Callable
from pathlib import Path

from src.core.domain.model.task import Task, _redact_secrets
from src.core.utils.json_utils import safe_json_loads
from src.reporting.attack_review_builder import build_all_review_fields
from src.core.models.vdp_contract import redact_secrets_deep, VDP_CONTRACT_SCHEMA_VERSION


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


def _sanitize_metadata_for_session_payload(task: Task) -> dict:
    """Redact secrets and inject schema_version, matching Task.to_dict() contract.

    Returns a safe deep copy suitable for disk persistence in session payloads.
    """
    md = task.metadata if hasattr(task, "metadata") and task.metadata else {}
    if not md:
        return {}
    safe = _redact_secrets(md)
    # Auto-inject schema_version when metadata is present but version is missing
    if "schema_version" not in safe:
        safe["schema_version"] = 1
    return safe


def build_async_session_payload(
    task_queue,
    completed_tasks,
    context,
    pending_hitl,
    coverage_gate,
    scenario_coverage,
    timestamp: float,
    default_start_time: float,
    decision_traces=None,
    task_execution_records=None,
    run_ledger_payload=None,
    session_id: str | None = None,
    run_id: str | None = None,
    target_system_profile: dict | None = None,
    attack_review_trail: dict | None = None,
    scenario_candidates: list | None = None,
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
                "metadata": _sanitize_metadata_for_session_payload(task),
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
                "metadata": _sanitize_metadata_for_session_payload(task),
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

    # --- S1: Run Ledger fields (optional, backward-compatible) ---
    if decision_traces is not None:
        payload["decision_traces"] = copy.deepcopy(decision_traces)
    if task_execution_records is not None:
        payload["task_execution_records"] = copy.deepcopy(task_execution_records)
    if run_ledger_payload is not None:
        # Merge run ledger fields into payload root
        payload["run_ledger_schema_version"] = run_ledger_payload.get(
            "run_ledger_schema_version", 1
        )
        payload["run_ledger"] = copy.deepcopy(run_ledger_payload.get("run_ledger", []))
        payload["llm_usage_summary"] = copy.deepcopy(
            run_ledger_payload.get("llm_usage_summary", {})
        )
        payload["spool_path"] = run_ledger_payload.get("spool_path")
        payload["spool_sha256"] = run_ledger_payload.get("spool_sha256")
        payload["spool_event_count"] = run_ledger_payload.get("spool_event_count", 0)

    adjacency_list = {}
    all_tasks = list(task_queue) + list(completed_tasks)
    for task in all_tasks:
        if task.parent_id:
            adjacency_list.setdefault(task.parent_id, []).append(task.id)
    payload["adjacency_list"] = adjacency_list

    # --- S2 (SGK-2026-0293): Auto-build additive review fields ---
    auto_review = build_all_review_fields(payload, session_id=session_id, run_id=run_id)

    payload["session_id"] = session_id
    payload["run_id"] = run_id
    payload["target_system_profile"] = (
        target_system_profile
        if target_system_profile is not None
        else auto_review["target_system_profile"]
    )
    payload["attack_review_trail"] = (
        attack_review_trail
        if attack_review_trail is not None
        else auto_review["attack_review_trail"]
    )
    payload["scenario_candidates"] = (
        scenario_candidates
        if scenario_candidates is not None
        else auto_review["scenario_candidates"]
    )

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
        safe_json_dumps(task.to_dict())
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
            task = Task.from_dict(d)
            tasks.append(task)
        except (json.JSONDecodeError, KeyError):
            failed_ids.append(s[:50] if len(s) > 50 else s)
    return tasks, failed_ids


def inject_vdp_section_to_session_payload(payload: dict, vdp_state: dict) -> dict:
    """Add a ``vdp_contract`` section to a session payload (backward-compatible).

    Redacts ALL secrets in the ENTIRE payload using ``redact_secrets_deep()``
    before returning. The VDP section records are also individually redacted.
    Does **not** mutate the input payload — returns a new shallow copy.

    Args:
        payload: Existing session payload dict (e.g. from build_async_session_payload).
        vdp_state: Dict with optional VDP contract fields:
            - vdp_contract_version (int)
            - hypotheses (list of HypothesisRecord.to_dict() dicts)
            - attempts (list of AttemptRecord.to_dict() dicts)
            - evidence_records (list of EvidenceRecordV1.to_dict() dicts)
            - verdicts (list of EvidenceVerdictV1.to_dict() dicts)
            - next_actions (list of NextActionRecord.to_dict() dicts)
            - budget_snapshot (dict from VdpExecutionBudget.snapshot())
            - run_health (RunHealthRecord.to_dict() dict)

    Returns:
        New payload dict with ``vdp_contract`` section added.
        Entire payload (including task metadata, context, etc.) is deep-redacted
        to strip secrets (Authorization, Cookie, X-API-Key etc.) from all paths.
        Missing vdp_state keys are omitted (empty dicts not added).
    """
    result = dict(payload)

    vdp_section: dict[str, Any] = {}
    vdp_active = vdp_state.get("vdp_active", False)

    version = vdp_state.get("vdp_contract_version", VDP_CONTRACT_SCHEMA_VERSION)
    vdp_section["vdp_contract_version"] = version
    vdp_section["vdp_active"] = vdp_active

    # Always include all five record lists (even if empty) when VDP is active
    for key in ("hypotheses", "attempts", "evidence_records", "verdicts", "next_actions"):
        items = vdp_state.get(key, [])
        vdp_section[key] = redact_secrets_deep(list(items) if items else [])

    budget = vdp_state.get("budget_snapshot", {})
    vdp_section["budget_snapshot"] = redact_secrets_deep(dict(budget)) if budget else {}

    run_health = vdp_state.get("run_health", {})
    vdp_section["run_health"] = redact_secrets_deep(dict(run_health)) if run_health else {}

    # SGK-2026-0423 Lane C: shadow/enforce diff trace (append-only, no
    # secrets) — included only when present.
    shadow_diff = vdp_state.get("shadow_diff")
    if shadow_diff is not None:
        vdp_section["shadow_diff"] = redact_secrets_deep(list(shadow_diff))

    # SGK-2026-0426 W3 (additive): fail-closed run outcome surfaced in the
    # session. Absent = normal run. When follow-up injection failed with
    # zero attempts, ``run_outcome=follow_up_stage_failed`` and
    # ``verdicts_finalized=false`` are persisted so the reporting layer can
    # degrade the report and the consistency checker can refuse a
    # "normal completion" pass.
    if vdp_state.get("run_outcome"):
        vdp_section["run_outcome"] = str(vdp_state["run_outcome"])
    if vdp_state.get("verdicts_finalized") is not None:
        vdp_section["verdicts_finalized"] = bool(vdp_state["verdicts_finalized"])

    result["vdp_contract"] = vdp_section

    # Redact the ENTIRE payload (not just VDP section)
    return redact_secrets_deep(result)


def build_session_with_vdp(
    task_queue,
    completed_tasks,
    context,
    vdp_state: dict | None = None,
    **kwargs,
) -> dict:
    """Build a session payload with VDP contract section injected.

    Wraps ``build_async_session_payload()`` + ``inject_vdp_section_to_session_payload()``.

    Args:
        task_queue: Task queue list.
        completed_tasks: Completed tasks list.
        context: Conductor context.
        vdp_state: Optional VDP state dict with keys: hypotheses, attempts,
            evidence_records, verdicts, next_actions, budget_snapshot, run_health.
        **kwargs: Passed through to ``build_async_session_payload()``.

    Returns:
        Session payload dict with ``vdp_contract`` section if vdp_state provided.
    """
    payload = build_async_session_payload(
        task_queue=task_queue,
        completed_tasks=completed_tasks,
        context=context,
        **kwargs,
    )
    if vdp_state:
        payload = inject_vdp_section_to_session_payload(payload, vdp_state)
    return payload


def safe_json_dumps(payload) -> str:
    return json.dumps(payload, ensure_ascii=False)
