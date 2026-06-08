from __future__ import annotations

from pathlib import Path
from typing import Any

from src.core.utils.json_utils import safe_json_loads


def _normalize_finding_entry(finding: Any) -> dict[str, Any] | None:
    if isinstance(finding, dict):
        return finding
    if hasattr(finding, "to_dict") and callable(getattr(finding, "to_dict")):
        try:
            converted = finding.to_dict()
            if isinstance(converted, dict):
                return converted
        except Exception:
            return None
    return None


def _extract_findings_from_result_payload(payload: Any) -> list[dict[str, Any]]:
    extracted: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    queue: list[Any] = [payload]
    visited_dict_ids: set[int] = set()

    def _add_finding(finding_obj: Any) -> None:
        finding_dict = _normalize_finding_entry(finding_obj)
        if not finding_dict:
            return

        key = str(finding_dict.get("id") or "").strip()
        if not key:
            vuln_type = str(finding_dict.get("vuln_type") or finding_dict.get("type") or "").strip()
            title = str(finding_dict.get("title") or "").strip()
            target = str(
                finding_dict.get("target_url")
                or finding_dict.get("target")
                or finding_dict.get("url")
                or ""
            ).strip()
            key = f"{vuln_type}|{title}|{target}"

        if key in seen_keys:
            return

        seen_keys.add(key)
        extracted.append(finding_dict)

    while queue:
        current = queue.pop(0)
        if not isinstance(current, dict):
            continue

        current_id = id(current)
        if current_id in visited_dict_ids:
            continue
        visited_dict_ids.add(current_id)

        raw_findings = current.get("findings")
        if isinstance(raw_findings, list):
            for entry in raw_findings:
                _add_finding(entry)

        if "finding" in current:
            _add_finding(current.get("finding"))

        nested_data = current.get("data")
        if isinstance(nested_data, dict):
            queue.append(nested_data)

        nested_result = current.get("result")
        if isinstance(nested_result, dict):
            queue.append(nested_result)

    return extracted


def _project_finding_fields(
    finding: dict[str, Any],
    finding_fields: list[str] | None,
) -> dict[str, Any]:
    if not finding_fields:
        return finding

    projected: dict[str, Any] = {}
    for field in finding_fields:
        token = str(field or "").strip()
        if not token:
            continue
        if token in finding:
            projected[token] = finding[token]
    return projected


def inspect_session_findings(
    session_path: str | Path,
    detection_class: str | None = None,
    *,
    max_findings: int | None = None,
    finding_fields: list[str] | None = None,
) -> dict[str, Any]:

    path = Path(session_path)
    raw_text = path.read_text(encoding="utf-8")
    session_data = safe_json_loads(raw_text, context=f"session_finding_inspector:{path.name}")

    completed_tasks = session_data.get("completed_tasks", [])
    normalized_detection_class = str(detection_class or "").strip().lower()

    findings: list[dict[str, Any]] = []
    for task in completed_tasks:
        if not isinstance(task, dict):
            continue

        task_id = str(task.get("id") or "").strip()
        task_result = task.get("result", {})
        extracted = _extract_findings_from_result_payload(task_result)
        for finding in extracted:
            additional_info = finding.get("additional_info", {})
            if not isinstance(additional_info, dict):
                additional_info = {}

            finding_detection_class = str(additional_info.get("detection_class") or "").strip().lower()
            if normalized_detection_class and finding_detection_class != normalized_detection_class:
                continue

            normalized_entry = (
                {
                    "task_id": task_id,
                    "title": finding.get("title"),
                    "target_url": finding.get("target_url") or finding.get("target") or finding.get("url"),
                    "vuln_type": finding.get("vuln_type") or finding.get("type"),
                    "detection_class": additional_info.get("detection_class"),
                    "schema_severity": additional_info.get("schema_severity") or finding.get("schema_severity"),
                    "heuristic_candidate": additional_info.get("heuristic_candidate"),
                    "verification_required": additional_info.get("verification_required"),
                }
            )
            findings.append(_project_finding_fields(normalized_entry, finding_fields))

    if max_findings is not None:
        limit = max(0, int(max_findings))
        findings = findings[:limit]

    return {
        "session": str(path),
        "completed_tasks_count": len(completed_tasks) if isinstance(completed_tasks, list) else 0,
        "filters": {
            "detection_class": normalized_detection_class or None,
            "max_findings": max_findings,
            "finding_fields": finding_fields or None,
        },
        "findings_count": len(findings),
        "findings": findings,
    }
