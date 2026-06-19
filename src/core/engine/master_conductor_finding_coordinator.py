"""
MasterConductor finding/reaction coordinator (SGK-2026-0297).

Handles finding processing and ReAct observation orchestration.
Takes facade reference as parameter. Does NOT hold MasterConductor instance.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from src.core.domain.model.task import Task
from src.core.models.finding import Finding

_log = logging.getLogger(__name__)


def handle_finding_coordinator(facade: Any, finding: Finding) -> None:
    """Process a finding: persist, notify, follow-up, aggressive, chain inference.

    Extracted from facade.handle_finding.
    """
    if not isinstance(finding, Finding):
        return

    target_url = finding.target_url

    facade.save_finding(finding)
    facade._emit_finding_vuln_event(finding, target_url)

    if facade.project_manager:
        try:
            facade._run_async_safe_forget(facade.project_manager.save_finding(finding))
        except Exception as e:
            _log.error("Failed to enqueue finding persistence: %s", e)

    if finding.recommended_followup == "escalate":
        facade._boost_related_tasks(target_url, priority_delta=20)
    elif finding.recommended_followup == "report":
        from src.core.notifications.notifier import get_notifier
        get_notifier().notify(
            f"Critical Finding: {finding.title}\nTarget: {finding.target_url}\nSeverity: {finding.severity.value}",
            bulk=False,
        )
        report_task = Task(
            id=f"report_{uuid.uuid4().hex[:8]}",
            name=f"Generate Report for Finding: {finding.title[:50]}",
            agent_type="report", action="generate",
            params={
                "finding_id": finding.id, "target": target_url,
                "tags": finding.tags, "findings": [finding.to_dict()],
            },
            priority=150,
        )
        facade._add_tasks([report_task], source="finding_feedback")

    if finding.is_aggressive:
        facade._mark_target_as_aggressive(target_url)

    try:
        tags = {str(t).lower() for t in (finding.tags or [])}
        is_chain_finding = "attack_chain" in tags or bool(
            (finding.additional_info or {}).get("is_attack_chain", False)
        )
        if not is_chain_finding:
            facade._infer_and_emit_attack_chains(finding)
    except Exception as e:
        _log.debug("Attack chain inference skipped: %s", e)

    facade._trigger_post_exploit(finding)


def observe_and_rethink_coordinator(facade: Any, task: Task, result: dict) -> list[Task]:
    """ReAct observation → rethink: analyze success, generate follow-up tasks.

    Extracted from facade._observe_and_rethink.
    """
    import time as _time

    allowed, reason = facade._should_observe(task, result)
    facade._record_react_decision(reason, allowed)
    if not allowed:
        return []

    queue_token = f"{task.id}:{_time.time_ns()}"
    facade._react_field("observation_pending_queue", []).append(queue_token)
    facade._set_react_field("observation_inflight", facade._react_field("observation_inflight", 0) + 1)
    facade._set_react_field("observation_executed_total", facade._react_field("observation_executed_total", 0) + 1)

    target = ""
    if isinstance(getattr(task, "params", None), dict):
        target = str(task.params.get("target", "") or "")
    if target:
        _by_target = facade._react_field("observation_executed_by_target", {})
        _by_target[target] = _by_target.get(target, 0) + 1
        facade._set_react_field("observation_executed_by_target", _by_target)

    additional_tasks: list[Task] = []
    try:
        suggestions = facade._generate_react_suggestions(task, result)
        additional_tasks = facade._build_react_followup_tasks(task, suggestions)

        if additional_tasks:
            _log.info("[ReAct] Observation generated %d additional tasks", len(additional_tasks))
            if getattr(facade, "_debug_logger", None):
                facade._debug_logger.log_decision(
                    agent="MasterConductor",
                    decision=f"ReAct generated {len(additional_tasks)} tasks",
                    reasoning=f"Analyzed success of task '{task.name}'",
                    next_steps=[t.name for t in additional_tasks],
                )
        facade._set_react_field("observation_cb_failures", 0)
    except Exception as e:
        facade._set_react_field("observation_retry_used", facade._react_field("observation_retry_used", 0) + 1)
        facade._set_react_field("observation_cb_failures", facade._react_field("observation_cb_failures", 0) + 1)
        cb_threshold = int(facade._react_setting("react_observation_circuit_breaker_threshold", 5))
        if facade._react_field("observation_cb_failures", 0) >= cb_threshold:
            cooldown = int(facade._react_setting("react_observation_circuit_breaker_cooldown_seconds", 120))
            facade._set_react_field("observation_cb_open_until", _time.time() + max(1, cooldown))
            _log.warning("[ReAct] circuit breaker opened cooldown=%ss failures=%s",
                         cooldown, facade._react_field("observation_cb_failures", 0))
        _log.warning("[ReAct] Observation failed: %s", e)
    finally:
        _inflight = facade._react_field("observation_inflight", 0)
        if _inflight > 0:
            facade._set_react_field("observation_inflight", _inflight - 1)
        _pq = facade._react_field("observation_pending_queue", [])
        if queue_token in _pq:
            _pq.remove(queue_token)
        facade._sync_react_observation_metrics_snapshot()

    return additional_tasks
