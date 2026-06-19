"""
MasterConductor task enrichment service (SGK-2026-0292).

Pure helper for pre-enqueue task enrichment. No MasterConductor instance.
"""

from __future__ import annotations

import logging
from typing import Any


def enrich_task_for_enqueue(
    facade: Any,
    task: Any,
    source: str,
    aggressive_targets: list,
    *,
    strategy_selector: Any = None,
    priority_booster: Any = None,
    context: Any = None,
    mode: str = "BUG_BOUNTY",
    normalize_gate: Any = None,
    get_decision: Any = None,
    requires_approval: Any = None,
    calc_boost: Any = None,
    logger: Any = None,
) -> None:
    """Apply priority boost, strategy, intervention, and aggressive inheritance.

    Mutates task in-place. Extracted from facade._enrich_task_before_enqueue.
    The facade reference is used only for readonly access to helpers.
    """
    _log = logger or logging.getLogger(__name__)
    max_boost = 3.0

    # Priority boost
    boost_factor, boost_reasons = calc_boost(task, max_boost=max_boost)
    if boost_factor > 1.0:
        base_priority = int(getattr(task, "priority", 0) or 0)
        task.priority = max(base_priority, int(round(base_priority * boost_factor)))
        _log.info(
            "Dynamic priority boost: task_id=%s task_name=%s source=%s factor=%s boosted=%s",
            task.id, task.name, source, boost_factor, task.priority,
        )

    # Strategy selection
    if strategy_selector is not None:
        try:
            decision = strategy_selector.select(
                task=task, target_info=context.target_info, mode=mode,
            )
            if decision.priority_delta:
                task.priority = max(0, int(task.priority) + int(decision.priority_delta))
            for k, v in (decision.param_overrides or {}).items():
                task.params.setdefault(k, v)
            existing_tags = set(getattr(task, "tags", []) or [])
            for tag in (decision.tag_hints or []):
                if tag not in existing_tags:
                    task.tags.append(tag)
            task.params["_strategy"] = {
                "id": decision.strategy_id, "confidence": decision.confidence,
                "rationale": decision.rationale,
            }
            if not decision.is_default:
                _log.info(
                    "Strategy selected: task_id=%s strategy=%s confidence=%s source=%s",
                    task.id, decision.strategy_id, decision.confidence, source,
                )
        except Exception as e:
            _log.debug("StrategySelector failed for task %s: %s", task.id, e)

    # Intervention priority boost
    try:
        gate_mode = normalize_gate()
        if gate_mode in {"enforce_hitl", "enforce_human_preferred"}:
            intervention_decision = get_decision(task)
            if requires_approval(intervention_decision, gate_mode):
                route = str(intervention_decision.get("route", "") or "")
                current_priority = int(getattr(task, "priority", 0) or 0)
                priority_floor = 1200 if route == "human_preferred" else 1000
                if current_priority < priority_floor:
                    task.priority = priority_floor
    except Exception as e:
        _log.debug("Intervention priority boost skipped for task %s: %s", task.id, e)

    # PriorityBooster registration
    if priority_booster is not None:
        priority_booster.register_task(
            task.id, base_priority=max(0.01, min(task.priority / 100.0, 1.0))
        )

    # Aggressive inheritance
    target = task.params.get("target", "")
    if target and target in aggressive_targets:
        task.params["is_aggressive"] = True
