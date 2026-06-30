"""
Common finding extraction helper shared across formatters.

Extracts findings from session data using the canonical extraction order
defined in main.py:2975-3048, ensuring consistent behaviour in all reporting
paths.
"""
from __future__ import annotations

from typing import Any, Dict, List


def extract_all_findings(session_data: dict) -> List[Dict[str, Any]]:
    """Extract all findings from a session using the canonical extraction logic.

    Follows main.py:2975-3048 extraction order:

    1. completed_tasks[*].result.findings
    2. completed_tasks[*].result.data.findings
    3. completed_tasks[*].result.data.finding (single)
    4. completed_tasks[*].result.finding (single)
    5. completed_tasks[*].result.vulnerability (single)
    6. Fallback: session.findings
    7. Fallback: session.partial_findings

    Each finding dict receives an injected ``_source_task_id`` field set to
    the parent task's ``id`` for traceability.

    Args:
        session_data: Raw session dictionary.

    Returns:
        List of finding dicts with ``_source_task_id`` injected.
    """
    all_findings: List[Dict[str, Any]] = []

    completed_tasks: list = session_data.get("completed_tasks", [])
    if not isinstance(completed_tasks, list):
        completed_tasks = []

    for task in completed_tasks:
        if not isinstance(task, dict):
            continue
        task_result = task.get("result", {})
        if not isinstance(task_result, dict):
            task_result = {}
        task_data = task_result.get("data", {})
        if not isinstance(task_data, dict):
            task_data = {}

        task_id = task.get("id", "")

        # Level 1: result.findings
        task_findings: list = task_result.get("findings", [])
        if not isinstance(task_findings, list):
            task_findings = []

        # Level 2: result.data.findings
        if not task_findings and isinstance(task_data, dict):
            data_findings = task_data.get("findings", [])
            if isinstance(data_findings, list):
                task_findings = data_findings

        # Level 3: result.data.finding (single)
        if not task_findings and isinstance(task_data, dict):
            single = task_data.get("finding")
            if single and isinstance(single, dict):
                task_findings = [single]

        # Level 4: result.finding (single)
        if not task_findings and isinstance(task_result, dict):
            single = task_result.get("finding")
            if single and isinstance(single, dict):
                task_findings = [single]

        # Level 5: result.vulnerability (single)
        if not task_findings and isinstance(task_result, dict) and "vulnerability" in task_result:
            vuln = task_result.get("vulnerability")
            if isinstance(vuln, dict):
                task_findings = [vuln]

        # Inject _source_task_id for traceability
        for f in task_findings:
            if isinstance(f, dict):
                f_copy = dict(f)
                f_copy["_source_task_id"] = task_id
                all_findings.append(f_copy)

    if not all_findings:
        # Level 6: Fallback – session.findings
        session_findings = session_data.get("findings", [])
        if isinstance(session_findings, list) and session_findings:
            all_findings = list(session_findings)

    if not all_findings:
        # Level 7: Fallback – session.partial_findings
        partial_findings = session_data.get("partial_findings", [])
        if isinstance(partial_findings, list):
            all_findings = [f for f in partial_findings if f]

    return all_findings
