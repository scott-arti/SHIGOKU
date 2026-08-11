"""
Common finding extraction helper shared across formatters.

Extracts findings from session data using the canonical extraction order
defined in main.py:2975-3048, ensuring consistent behaviour in all reporting
paths.

SGK-2026-0422: adds the canonical VDP extractor entry point. For sessions
carrying a ``vdp_contract`` section, callers MUST use
``extract_vdp_canonical()`` (read-only, proof-verified, source_kind-aware)
instead of raw finding labels. For legacy sessions without a VDP contract
section, the existing ``extract_all_findings()`` path is preserved.
"""
from __future__ import annotations

from typing import Any, Dict, List

from src.reporting.vdp_canonical import (
    VdpCanonicalSummary,
    build_vdp_canonical_index,
    extract_vdp_canonical,
)

__all__ = [
    "extract_all_findings",
    "extract_vdp_canonical",
    "build_vdp_canonical_index",
    "VdpCanonicalSummary",
]


def _funnel_entries_by_id(session_data: dict) -> Dict[str, Dict[str, Any]]:
    """Index the session's ``finding_funnel_v1`` entries by finding_id.

    SGK-2026-0440 Lane B (additive): empty when the funnel section is
    absent. The funnel is measurement-only (finding_id hashes + vocab
    strings, no secrets).
    """
    funnel = session_data.get("finding_funnel_v1")
    if not isinstance(funnel, dict):
        return {}
    entries = funnel.get("entries")
    if not isinstance(entries, list):
        return {}
    return {
        str(entry.get("finding_id", "") or "").strip(): entry
        for entry in entries
        if isinstance(entry, dict) and str(entry.get("finding_id", "") or "").strip()
    }


def _finding_id_for_dict(finding: Dict[str, Any]) -> str:
    """Resolve a raw finding dict's funnel id.

    Matches the funnel recorder's ``finding_id`` (the ``Finding.id`` md5,
    serialized as the top-level ``id`` key in sessions): additional_info
    ``finding_id`` first, then top-level ``id``, then the title-hash
    fallback used by ``build_finding_memo_map``.
    """
    info = finding.get("additional_info")
    if isinstance(info, dict):
        finding_id = str(info.get("finding_id", "") or "").strip()
        if finding_id:
            return finding_id
    finding_id = str(finding.get("id", "") or "").strip()
    if finding_id:
        return finding_id
    return f"C{hash(finding.get('title', '')) & 0xFFFF:X}"


def _attach_funnel_first_failure_to_dicts(
    findings: List[Dict[str, Any]],
    funnel_entries: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Additively attach first_failure_stage/reason from funnel entries.

    Returns new copies for matched findings; unmatched findings are
    returned unchanged. No-op when there are no funnel entries.
    """
    if not funnel_entries:
        return findings
    result: List[Dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            result.append(finding)
            continue
        entry = funnel_entries.get(_finding_id_for_dict(finding))
        if entry is None:
            result.append(finding)
            continue
        stage = entry.get("first_failure_stage")
        reason = entry.get("first_failure_reason")
        if stage is None and reason is None:
            result.append(finding)
            continue
        finding_copy = dict(finding)
        finding_copy["first_failure_stage"] = stage
        finding_copy["first_failure_reason"] = reason
        result.append(finding_copy)
    return result


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

    # SGK-2026-0440 Lane B (additive): expose per-finding first-failure
    # stage/reason from the funnel section when present. Absent -> output
    # unchanged (legacy byte-identical).
    return _attach_funnel_first_failure_to_dicts(
        all_findings,
        _funnel_entries_by_id(session_data),
    )
