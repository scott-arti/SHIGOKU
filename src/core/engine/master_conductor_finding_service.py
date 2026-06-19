"""
MasterConductor finding/observation service (SGK-2026-0291).

Pure helper functions extracted from facade. No MasterConductor instance.
"""

from __future__ import annotations

from typing import Any

from src.core.domain.model.task import Task


def build_react_followup_tasks(
    task: Task,
    suggestions: dict,
    max_additions: int = 5,
) -> list[Task]:
    """Build follow-up Task objects from ReAct LLM suggestions.

    Pure function. Extracted from facade._build_react_followup_tasks.
    """
    additional_tasks: list[Task] = []
    for i, s in enumerate(suggestions.get("additional_attacks", [])[:max_additions]):
        new_task = Task(
            id=f"{task.id}_react_{i}",
            name=s.get("name", f"ReAct: Follow-up {i}"),
            agent_type=s.get("agent_type", "universal"),
            action=s.get("action", "scan"),
            params={
                "target": task.params.get("target"),
                "hint": s.get("rationale", ""),
                **s.get("params", {}),
            },
            priority=task.priority - 5,
        )
        additional_tasks.append(new_task)
    return additional_tasks


def generate_react_suggestions(
    task, result, rag, llm_client, context_target_info,
    react_field_get, react_field_set, react_setting_get,
):
    """RAG fallback + cache check + LLM call for ReAct observation.

    Pure function. Extracted from facade._generate_react_suggestions.
    No MasterConductor instance.
    """
    import hashlib, json, time, logging
    _logger = logging.getLogger(__name__)
    data = result.get("data", {})
    technologies = data.get("technologies", [])
    rag_suggestions = []
    if rag and technologies and not result.get("findings"):
        try:
            tech_str = ", ".join(technologies[:3])
            rag_results = rag.query(f"attack patterns for {tech_str}", n_results=2)
            rag_suggestions = [r.content[:200] for r in rag_results]
        except Exception:
            pass

    data_hash = hashlib.md5(json.dumps(data, sort_keys=True).encode()).hexdigest()
    rag_hash = hashlib.md5(json.dumps(rag_suggestions, sort_keys=True).encode()).hexdigest()
    cache_key = f"{task.name}_{data_hash}_{rag_hash}"

    cache = react_field_get("cache", {})
    if cache_key in cache:
        return cache[cache_key]

    from src.core.conductor.conductor_prompts import get_react_observation_prompt
    prompt = get_react_observation_prompt(
        task_name=task.name, task_result=data,
        tech_stack=context_target_info.get("tech_stack", []),
        rag_hints=rag_suggestions,
    )
    retry_max = int(react_setting_get("react_observation_retry_max", 1))
    latency_threshold = float(react_setting_get("react_observation_circuit_breaker_latency_seconds", 8.0))
    response = None
    last_exc = None
    for _attempt in range(max(1, retry_max + 1)):
        started = time.time()
        try:
            response = llm_client.generate(
                messages=[
                    {"role": "system", "content": "You are a security analyst. Suggest additional attack vectors based on the result. Output JSON only."},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"}, temperature=0.3, max_tokens=500,
            )
            elapsed = time.time() - started
            if elapsed > latency_threshold:
                react_field_set("observation_cb_failures", react_field_get("observation_cb_failures", 0) + 1)
            break
        except Exception as exc:
            last_exc = exc
            react_field_set("observation_retry_used", react_field_get("observation_retry_used", 0) + 1)
            react_field_set("observation_cb_failures", react_field_get("observation_cb_failures", 0) + 1)
            if _attempt >= retry_max:
                raise
    if response is None and last_exc is not None:
        raise last_exc

    content_suggestions = json.loads(response.choices[0].message.content)
    cache[cache_key] = content_suggestions
    react_field_set("cache", cache)
    return content_suggestions



def emit_finding_vuln_payload(
    finding: Any,
    target_url: str,
    context_target_info: dict,
    event_bus: Any,
    notifier: Any,
) -> dict:
    """Build and emit VULN_FOUND event payload for a finding.

    Pure function. Extracted from facade._emit_finding_vuln_event.
    Returns the payload dict for testability.
    """
    from src.core.infra.event_bus import Event, EventType
    from src.core.observability.phase1_contracts import ensure_observability_fields

    correlation = context_target_info.get("correlation", {})
    vuln_payload = ensure_observability_fields(
        {
            "title": finding.title,
            "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            "target": target_url,
            "vuln_type": finding.vuln_type.value if hasattr(finding.vuln_type, "value") else str(finding.vuln_type),
            "source_agent": finding.source_agent,
            "schema_severity": str((finding.additional_info or {}).get("schema_severity", "none")),
        },
        correlation=correlation,
        endpoint=target_url,
        error_type="vuln_found",
        timeout_ms=0,
        retry_count=0,
        test_case_id=str(getattr(finding, "id", "") or "finding"),
    )
    event_bus.emit_sync(
        Event(type=EventType.VULN_FOUND, payload=vuln_payload, source="master_conductor")
    )
    notifier.notify_event(
        event_type="vuln_found",
        target=target_url,
        details={
            "title": finding.title,
            "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            "type": finding.vuln_type.value if hasattr(finding.vuln_type, "value") else str(finding.vuln_type),
        },
    )
    return vuln_payload
