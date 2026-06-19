from __future__ import annotations

from pathlib import Path
from typing import Any

from src.core.utils.json_utils import safe_json_loads
from src.reporting.initial_release_gate_policy import (
    _normalize_detection_class,
    _normalize_tokens,
    _safe_int,
    _SCENARIO_TO_DETECTION_CLASS,
)
from src.reporting.session_finding_inspector import inspect_session_findings


def _load_session_scenario_coverage(session_path: Path | None) -> dict[str, Any]:
    if session_path is None:
        return {}
    try:
        raw_text = session_path.read_text(encoding="utf-8")
    except Exception:
        return {}

    session_data = safe_json_loads(
        raw_text,
        default={},
        context=f"initial_release_gate:{session_path.name}",
    )
    if not isinstance(session_data, dict):
        return {}

    coverage = session_data.get("scenario_coverage")
    if not isinstance(coverage, dict):
        context = session_data.get("context", {})
        if isinstance(context, dict):
            coverage = context.get("scenario_coverage")
    return coverage if isinstance(coverage, dict) else {}


def _build_detection_class_summary(findings_class_summary: dict[str, Any]) -> dict[str, Any]:
    confirmed_raw = findings_class_summary.get("confirmed_by_vuln_class", {})
    candidate_raw = findings_class_summary.get("candidate_by_vuln_class", {})
    if not isinstance(confirmed_raw, dict):
        confirmed_raw = {}
    if not isinstance(candidate_raw, dict):
        candidate_raw = {}

    confirmed_by_detection_class: dict[str, int] = {}
    candidate_by_detection_class: dict[str, int] = {}

    for raw_class, raw_count in confirmed_raw.items():
        detection_class = _normalize_detection_class(raw_class)
        if not detection_class:
            continue
        confirmed_by_detection_class[detection_class] = (
            int(confirmed_by_detection_class.get(detection_class, 0) or 0)
            + int(_safe_int(raw_count) or 0)
        )

    for raw_class, raw_count in candidate_raw.items():
        detection_class = _normalize_detection_class(raw_class)
        if not detection_class:
            continue
        candidate_by_detection_class[detection_class] = (
            int(candidate_by_detection_class.get(detection_class, 0) or 0)
            + int(_safe_int(raw_count) or 0)
        )

    classes = sorted(set(confirmed_by_detection_class.keys()) | set(candidate_by_detection_class.keys()))
    total_by_detection_class: dict[str, int] = {}
    rows: list[dict[str, Any]] = []
    for detection_class in classes:
        confirmed = int(confirmed_by_detection_class.get(detection_class, 0) or 0)
        candidate = int(candidate_by_detection_class.get(detection_class, 0) or 0)
        total = confirmed + candidate
        total_by_detection_class[detection_class] = total
        rows.append(
            {
                "detection_class": detection_class,
                "confirmed": confirmed,
                "candidate": candidate,
                "total": total,
            }
        )

    return {
        "confirmed_by_detection_class": dict(sorted(confirmed_by_detection_class.items())),
        "candidate_by_detection_class": dict(sorted(candidate_by_detection_class.items())),
        "total_by_detection_class": dict(sorted(total_by_detection_class.items())),
        "rows": rows,
    }


def _merge_detection_class_summary_with_scenario_backfill(
    findings_class_summary: dict[str, Any],
    scenario_backfill: dict[str, int],
) -> dict[str, Any]:
    summary = _build_detection_class_summary(findings_class_summary)
    confirmed_raw = summary.get("confirmed_by_detection_class", {})
    candidate_raw = summary.get("candidate_by_detection_class", {})
    if not isinstance(confirmed_raw, dict):
        confirmed_raw = {}
    if not isinstance(candidate_raw, dict):
        candidate_raw = {}

    merged_confirmed = {
        str(key): int(_safe_int(value) or 0)
        for key, value in confirmed_raw.items()
        if str(key or "").strip()
    }
    for detection_class, raw_count in scenario_backfill.items():
        count = int(_safe_int(raw_count) or 0)
        if count <= 0:
            continue
        merged_confirmed[detection_class] = max(int(merged_confirmed.get(detection_class, 0) or 0), count)

    merged_candidate = {
        str(key): int(_safe_int(value) or 0)
        for key, value in candidate_raw.items()
        if str(key or "").strip()
    }

    classes = sorted(set(merged_confirmed.keys()) | set(merged_candidate.keys()))
    total_by_detection_class: dict[str, int] = {}
    rows: list[dict[str, Any]] = []
    for detection_class in classes:
        confirmed = int(merged_confirmed.get(detection_class, 0) or 0)
        candidate = int(merged_candidate.get(detection_class, 0) or 0)
        total = confirmed + candidate
        total_by_detection_class[detection_class] = total
        rows.append(
            {
                "detection_class": detection_class,
                "confirmed": confirmed,
                "candidate": candidate,
                "total": total,
            }
        )

    summary.update(
        {
            "confirmed_by_detection_class": dict(sorted(merged_confirmed.items())),
            "candidate_by_detection_class": dict(sorted(merged_candidate.items())),
            "total_by_detection_class": dict(sorted(total_by_detection_class.items())),
            "rows": rows,
            "scenario_backfill_by_detection_class": dict(sorted(scenario_backfill.items())),
        }
    )
    return summary


def _build_session_findings_summary(session_path: Path | None) -> dict[str, Any]:
    if session_path is None:
        return {
            "source": "session_raw_unique",
            "available": False,
            "confirmed_count": None,
            "candidate_count": None,
            "raw_findings_count": 0,
            "unique_findings_count": 0,
        }
    try:
        inspected = inspect_session_findings(session_path)
    except Exception:
        return {
            "source": "session_raw_unique",
            "available": False,
            "confirmed_count": None,
            "candidate_count": None,
            "raw_findings_count": 0,
            "unique_findings_count": 0,
        }

    findings = inspected.get("findings", [])
    if not isinstance(findings, list) or not findings:
        return {
            "source": "session_raw_unique",
            "available": False,
            "confirmed_count": None,
            "candidate_count": None,
            "raw_findings_count": 0,
            "unique_findings_count": 0,
        }

    # Gate decision should be stable and report-heuristic-independent.
    # We dedupe by core vulnerability signature and only use session-native flags.
    deduped_by_signature: dict[tuple[str, str, str], bool] = {}
    for entry in findings:
        if not isinstance(entry, dict):
            continue
        target_url = str(entry.get("target_url", "") or "").strip().lower()
        vuln_type = str(entry.get("vuln_type", "") or "").strip().lower()
        title = str(entry.get("title", "") or "").strip().lower()
        if not target_url and not vuln_type and not title:
            continue

        signature = (target_url, vuln_type, title)
        is_candidate = bool(entry.get("heuristic_candidate")) or bool(entry.get("verification_required"))
        existing = deduped_by_signature.get(signature)
        if existing is None or (existing and not is_candidate):
            deduped_by_signature[signature] = is_candidate

    if not deduped_by_signature:
        return {
            "source": "session_raw_unique",
            "available": False,
            "confirmed_count": None,
            "candidate_count": None,
            "raw_findings_count": len(findings),
            "unique_findings_count": 0,
        }

    candidate_count = sum(1 for is_candidate in deduped_by_signature.values() if is_candidate)
    confirmed_count = len(deduped_by_signature) - candidate_count
    return {
        "source": "session_raw_unique",
        "available": True,
        "confirmed_count": int(confirmed_count),
        "candidate_count": int(candidate_count),
        "raw_findings_count": len(findings),
        "unique_findings_count": len(deduped_by_signature),
    }


def _build_session_detection_class_summary(session_path: Path | None) -> dict[str, Any]:
    if session_path is None:
        return {
            "source": "session_detection_class_summary",
            "available": False,
            "confirmed_by_detection_class": {},
            "candidate_by_detection_class": {},
            "total_by_detection_class": {},
            "rows": [],
            "unique_findings_count": 0,
        }
    try:
        inspected = inspect_session_findings(session_path)
    except Exception:
        return {
            "source": "session_detection_class_summary",
            "available": False,
            "confirmed_by_detection_class": {},
            "candidate_by_detection_class": {},
            "total_by_detection_class": {},
            "rows": [],
            "unique_findings_count": 0,
        }

    findings = inspected.get("findings", [])
    if not isinstance(findings, list) or not findings:
        return {
            "source": "session_detection_class_summary",
            "available": False,
            "confirmed_by_detection_class": {},
            "candidate_by_detection_class": {},
            "total_by_detection_class": {},
            "rows": [],
            "unique_findings_count": 0,
        }

    deduped: dict[tuple[str, str, str, str], bool] = {}
    for entry in findings:
        if not isinstance(entry, dict):
            continue
        detection_class = _normalize_detection_class(entry.get("detection_class"))
        if not detection_class:
            continue
        target_url = str(entry.get("target_url", "") or "").strip().lower()
        vuln_type = str(entry.get("vuln_type", "") or "").strip().lower()
        title = str(entry.get("title", "") or "").strip().lower()
        signature = (detection_class, target_url, vuln_type, title)
        is_candidate = bool(entry.get("heuristic_candidate")) or bool(entry.get("verification_required"))
        existing = deduped.get(signature)
        if existing is None or (existing and not is_candidate):
            deduped[signature] = is_candidate

    if not deduped:
        return {
            "source": "session_detection_class_summary",
            "available": False,
            "confirmed_by_detection_class": {},
            "candidate_by_detection_class": {},
            "total_by_detection_class": {},
            "rows": [],
            "unique_findings_count": 0,
        }

    confirmed_by_detection_class: dict[str, int] = {}
    candidate_by_detection_class: dict[str, int] = {}
    for signature, is_candidate in deduped.items():
        detection_class = signature[0]
        if is_candidate:
            candidate_by_detection_class[detection_class] = int(
                candidate_by_detection_class.get(detection_class, 0) or 0
            ) + 1
        else:
            confirmed_by_detection_class[detection_class] = int(
                confirmed_by_detection_class.get(detection_class, 0) or 0
            ) + 1

    total_by_detection_class: dict[str, int] = {}
    rows: list[dict[str, Any]] = []
    classes = sorted(set(confirmed_by_detection_class.keys()) | set(candidate_by_detection_class.keys()))
    for detection_class in classes:
        confirmed = int(confirmed_by_detection_class.get(detection_class, 0) or 0)
        candidate = int(candidate_by_detection_class.get(detection_class, 0) or 0)
        total = confirmed + candidate
        total_by_detection_class[detection_class] = total
        rows.append(
            {
                "detection_class": detection_class,
                "confirmed": confirmed,
                "candidate": candidate,
                "total": total,
            }
        )

    return {
        "source": "session_detection_class_summary",
        "available": True,
        "confirmed_by_detection_class": dict(sorted(confirmed_by_detection_class.items())),
        "candidate_by_detection_class": dict(sorted(candidate_by_detection_class.items())),
        "total_by_detection_class": dict(sorted(total_by_detection_class.items())),
        "rows": rows,
        "unique_findings_count": len(deduped),
    }


def _build_session_schema_severity_summary(session_path: Path | None) -> dict[str, Any]:
    if session_path is None:
        return {
            "source": "session_schema_severity_summary",
            "available": False,
            "counts": {},
            "unique_findings_count": 0,
        }
    try:
        inspected = inspect_session_findings(session_path)
    except Exception:
        return {
            "source": "session_schema_severity_summary",
            "available": False,
            "counts": {},
            "unique_findings_count": 0,
        }

    findings = inspected.get("findings", [])
    if not isinstance(findings, list) or not findings:
        return {
            "source": "session_schema_severity_summary",
            "available": False,
            "counts": {},
            "unique_findings_count": 0,
        }

    ranking = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    deduped: dict[tuple[str, str, str], str] = {}
    for entry in findings:
        if not isinstance(entry, dict):
            continue
        target_url = str(entry.get("target_url", "") or "").strip().lower()
        vuln_type = str(entry.get("vuln_type", "") or "").strip().lower()
        title = str(entry.get("title", "") or "").strip().lower()
        if not target_url and not vuln_type and not title:
            continue
        signature = (target_url, vuln_type, title)
        sev = str(entry.get("schema_severity", "") or "").strip().lower()
        if sev not in ranking:
            sev = "none"
        existing = deduped.get(signature)
        if existing is None or ranking.get(sev, 0) > ranking.get(existing, 0):
            deduped[signature] = sev

    counts: dict[str, int] = {}
    for sev in deduped.values():
        counts[sev] = int(counts.get(sev, 0) or 0) + 1

    return {
        "source": "session_schema_severity_summary",
        "available": bool(deduped),
        "counts": dict(sorted(counts.items())),
        "unique_findings_count": len(deduped),
    }


def _build_scenario_detection_backfill(session_scenario_coverage: dict[str, Any]) -> dict[str, int]:
    if not isinstance(session_scenario_coverage, dict):
        return {}

    backfill: dict[str, int] = {}

    covered_scenarios = _normalize_tokens(session_scenario_coverage.get("covered_scenarios", []))
    for scenario_id in covered_scenarios:
        detection_class = _SCENARIO_TO_DETECTION_CLASS.get(scenario_id)
        if detection_class:
            backfill[detection_class] = max(int(backfill.get(detection_class, 0) or 0), 1)

    coverage_items = session_scenario_coverage.get("coverage_items", [])
    if isinstance(coverage_items, list):
        for item in coverage_items:
            if not isinstance(item, dict):
                continue
            if not bool(item.get("covered", False)):
                continue
            scenario_id = str(item.get("scenario_id", "") or "").strip().lower()
            detection_class = _SCENARIO_TO_DETECTION_CLASS.get(scenario_id)
            if detection_class:
                backfill[detection_class] = max(int(backfill.get(detection_class, 0) or 0), 1)

    return dict(sorted(backfill.items()))
