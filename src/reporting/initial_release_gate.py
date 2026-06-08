from __future__ import annotations

from datetime import datetime
import json
import hashlib
from pathlib import Path
import re
from typing import Any

from src.core.utils.json_utils import safe_json_loads
from src.reporting.report_session_consistency import verify_report_session_consistency
from src.reporting.session_finding_inspector import inspect_session_findings

_SCN08 = "scn_08_oob_external_channel_flow"
_SCN10 = "scn_10_semantic_business_logic"
_SCN12 = "scn_12_advanced_ssrf_internal_topology"

DEFAULT_ALLOWED_MISSING_SCENARIOS = [
    _SCN08,
    _SCN10,
    _SCN12,
]
DEFAULT_REQUIRED_CONFIRMED_CLASSES: list[str] = []

_FAMILY_GATE_LINE_RE = re.compile(
    r"^Gate:\s*(PASS|FAIL)\s*,\s*Coverage:\s*(\d+)\s*/\s*(\d+)\s*\([^)]*\)\s*,\s*Missing:\s*(.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_FINDINGS_SUMMARY_LINE_RE = re.compile(
    r"^Confirmed:\s*(\d+)\s*/\s*Candidate:\s*(\d+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_CONFIRMED_POC_MISSING_LINE_RE = re.compile(
    r"^Confirmed PoC Missing:\s*(\d+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_CANDIDATE_REASON_MISSING_LINE_RE = re.compile(
    r"^Candidate Reason-Code Missing:\s*(\d+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_FINDING_CLASS_ROW_RE = re.compile(
    r"^\|\s*([a-z0-9_.:-]+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*$",
    re.IGNORECASE,
)
_BASELINE_LOCK_FILENAME = "quality_baseline_lock.json"

_DEFERRED_SCENARIO_PLAYBOOK: dict[str, dict[str, str]] = {
    _SCN08: {
        "title": "Out-of-Band External Channel",
        "route": "human_preferred",
        "why_deferred": "Depends on mailbox/SMS/OOB callback validation that is high-friction for full automation.",
        "trigger": "Initial release gate passed with SCN08 still missing.",
        "operator_input": "Provide reachable OOB channels (mailbox/SMS/callback sink) and verification boundaries.",
        "success_criteria": "Reproducible OOB evidence trail or documented negative verification with trace logs.",
    },
    _SCN10: {
        "title": "Semantic Business Logic",
        "route": "human_preferred",
        "why_deferred": "Requires intent/business-policy interpretation across multi-step workflows.",
        "trigger": "Initial release gate passed with SCN10 still missing.",
        "operator_input": "Select high-impact workflow and define unacceptable business outcome.",
        "success_criteria": "Documented reproducible workflow-abuse path with clear business impact.",
    },
    _SCN12: {
        "title": "Advanced SSRF Internal Topology",
        "route": "human_preferred",
        "why_deferred": "Depends on internal topology hypotheses and high-friction callback validation.",
        "trigger": "Initial release gate passed with SCN12 still missing.",
        "operator_input": "Provide internal target hypotheses/callback strategy and safe test boundaries.",
        "success_criteria": "Verified internal reachability pattern or disproved hypothesis with evidence.",
    },
}

_DETECTION_CLASS_ALIASES: dict[str, set[str]] = {
    "access_control": {
        "access_control",
        "broken_access_control",
        "broken_object_level_authorization",
        "unauthenticated_api_access",
        "authorization_bypass",
    },
    "idor_bola": {
        "idor_bola",
        "idor",
        "bola",
        "object_level_auth",
    },
    "mass_assignment": {
        "mass_assignment",
        "bopla",
        "broken_object_property_level_authorization",
    },
    "endpoint_bfla": {
        "endpoint_bfla",
        "bfla",
        "endpoint_enumeration_bfla",
        "api",
        "admin_api",
    },
    "injection_xss": {
        "injection_xss",
        "xss",
    },
    "injection_sqli_nosqli": {
        "injection_sqli_nosqli",
        "sqli",
        "sql_injection",
        "nosql_injection",
    },
    "injection_ssrf": {
        "injection_ssrf",
        "ssrf",
    },
    "injection_other": {
        "injection_other",
        "ssti",
        "lfi",
        "rce",
        "os_command_injection",
        "deserialization",
        "prototype_pollution",
        "crlf_injection",
        "open_redirect",
        "host_header_injection",
    },
    "rate_limit_bruteforce": {
        "rate_limit_bruteforce",
        "rate_limit",
        "bruteforce",
        "weak_password",
    },
}

_SCENARIO_TO_DETECTION_CLASS: dict[str, str] = {
    "scn_01_idor_bola_object_access": "idor_bola",
    "scn_02_mass_assignment_object_update": "mass_assignment",
    "scn_04_endpoint_enumeration_bfla": "endpoint_bfla",
    "scn_07_token_trust_boundary": "access_control",
}


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except Exception:
        return None


def _metric_delta(current: Any, baseline: Any) -> int | None:
    current_num = _safe_int(current)
    baseline_num = _safe_int(baseline)
    if current_num is None or baseline_num is None:
        return None
    return current_num - baseline_num


def _build_baseline_id(report_path: Path | None, session_path: Path | None) -> str | None:
    if report_path is None or session_path is None:
        return None
    token = f"{str(report_path.resolve())}::{str(session_path.resolve())}"
    digest = hashlib.sha1(token.encode("utf-8")).hexdigest()[:12]
    return f"baseline_{digest}"


def _build_baseline_diff(
    *,
    current_scenario_coverage: dict[str, Any],
    current_family_gate: dict[str, Any],
    current_findings_summary: dict[str, Any],
    current_findings_class_summary: dict[str, Any],
    baseline_scenario_coverage: dict[str, Any],
    baseline_family_gate: dict[str, Any],
    baseline_findings_summary: dict[str, Any],
    baseline_findings_class_summary: dict[str, Any],
) -> dict[str, Any]:
    current_missing_scenarios = _normalize_tokens(current_scenario_coverage.get("missing_scenarios", []))
    baseline_missing_scenarios = _normalize_tokens(baseline_scenario_coverage.get("missing_scenarios", []))
    current_missing_families = _normalize_tokens(current_family_gate.get("missing_families", []))
    baseline_missing_families = _normalize_tokens(baseline_family_gate.get("missing_families", []))

    return {
        "scenario_coverage": {
            "current_covered_count": current_scenario_coverage.get("covered_count"),
            "baseline_covered_count": baseline_scenario_coverage.get("covered_count"),
            "covered_delta": _metric_delta(
                current_scenario_coverage.get("covered_count"),
                baseline_scenario_coverage.get("covered_count"),
            ),
            "current_required_count": current_scenario_coverage.get("required_count"),
            "baseline_required_count": baseline_scenario_coverage.get("required_count"),
            "current_missing_scenarios": current_missing_scenarios,
            "baseline_missing_scenarios": baseline_missing_scenarios,
            "missing_added": sorted(set(current_missing_scenarios) - set(baseline_missing_scenarios)),
            "missing_resolved": sorted(set(baseline_missing_scenarios) - set(current_missing_scenarios)),
        },
        "findings": {
            "current_confirmed": current_findings_summary.get("confirmed_count"),
            "baseline_confirmed": baseline_findings_summary.get("confirmed_count"),
            "confirmed_delta": _metric_delta(
                current_findings_summary.get("confirmed_count"),
                baseline_findings_summary.get("confirmed_count"),
            ),
            "current_candidate": current_findings_summary.get("candidate_count"),
            "baseline_candidate": baseline_findings_summary.get("candidate_count"),
            "candidate_delta": _metric_delta(
                current_findings_summary.get("candidate_count"),
                baseline_findings_summary.get("candidate_count"),
            ),
        },
        "finding_classes": _build_finding_class_diff(
            current_summary=current_findings_class_summary,
            baseline_summary=baseline_findings_class_summary,
        ),
        "family_gate": {
            "current_status": current_family_gate.get("status"),
            "baseline_status": baseline_family_gate.get("status"),
            "status_changed": (
                str(current_family_gate.get("status", "") or "").strip().lower()
                != str(baseline_family_gate.get("status", "") or "").strip().lower()
            )
            if current_family_gate.get("status") is not None and baseline_family_gate.get("status") is not None
            else None,
            "current_missing_families": current_missing_families,
            "baseline_missing_families": baseline_missing_families,
        },
    }


def _build_finding_class_diff(
    *,
    current_summary: dict[str, Any],
    baseline_summary: dict[str, Any],
) -> dict[str, Any]:
    current_confirmed = current_summary.get("confirmed_by_vuln_class", {})
    baseline_confirmed = baseline_summary.get("confirmed_by_vuln_class", {})
    current_candidate = current_summary.get("candidate_by_vuln_class", {})
    baseline_candidate = baseline_summary.get("candidate_by_vuln_class", {})
    if not isinstance(current_confirmed, dict):
        current_confirmed = {}
    if not isinstance(baseline_confirmed, dict):
        baseline_confirmed = {}
    if not isinstance(current_candidate, dict):
        current_candidate = {}
    if not isinstance(baseline_candidate, dict):
        baseline_candidate = {}

    classes = sorted(
        set(str(k).strip().lower() for k in current_confirmed.keys())
        | set(str(k).strip().lower() for k in baseline_confirmed.keys())
        | set(str(k).strip().lower() for k in current_candidate.keys())
        | set(str(k).strip().lower() for k in baseline_candidate.keys())
    )
    class_rows: list[dict[str, Any]] = []
    for vuln_class in classes:
        current_conf = int(_safe_int(current_confirmed.get(vuln_class)) or 0)
        baseline_conf = int(_safe_int(baseline_confirmed.get(vuln_class)) or 0)
        current_cand = int(_safe_int(current_candidate.get(vuln_class)) or 0)
        baseline_cand = int(_safe_int(baseline_candidate.get(vuln_class)) or 0)
        class_rows.append(
            {
                "vuln_class": vuln_class,
                "current_confirmed": current_conf,
                "baseline_confirmed": baseline_conf,
                "confirmed_delta": current_conf - baseline_conf,
                "current_candidate": current_cand,
                "baseline_candidate": baseline_cand,
                "candidate_delta": current_cand - baseline_cand,
            }
        )

    return {
        "classes": class_rows,
        "current_confirmed_class_count": len([c for c in classes if int(_safe_int(current_confirmed.get(c)) or 0) > 0]),
        "baseline_confirmed_class_count": len([c for c in classes if int(_safe_int(baseline_confirmed.get(c)) or 0) > 0]),
    }


def _normalize_tokens(raw: Any) -> list[str]:
    if isinstance(raw, str):
        value = raw.strip().lower()
        if not value or value == "-":
            return []
        return [value]
    if not isinstance(raw, list):
        return []
    normalized: list[str] = []
    for item in raw:
        token = str(item or "").strip().lower()
        if not token or token == "-":
            continue
        if token not in normalized:
            normalized.append(token)
    return sorted(normalized)


def _normalize_detection_class(value: Any) -> str:
    token = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    if not token:
        return ""
    for canonical, aliases in _DETECTION_CLASS_ALIASES.items():
        if token in aliases:
            return canonical
    return token


def _normalize_required_detection_classes(raw: Any) -> list[str]:
    normalized: list[str] = []
    if isinstance(raw, str):
        tokens = [str(token or "").strip() for token in raw.split(",")]
    elif isinstance(raw, list):
        tokens = [str(token or "").strip() for token in raw]
    else:
        tokens = []
    for token in tokens:
        if not token:
            continue
        canonical = _normalize_detection_class(token)
        if canonical and canonical not in normalized:
            normalized.append(canonical)
    return normalized


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


def _parse_family_gate(report_text: str) -> dict[str, Any]:
    match = _FAMILY_GATE_LINE_RE.search(report_text or "")
    if not match:
        return {
            "status": None,
            "covered_count": None,
            "required_count": None,
            "missing_families": [],
        }

    status = str(match.group(1) or "").strip().lower()
    covered_count = int(match.group(2))
    required_count = int(match.group(3))
    missing_raw = str(match.group(4) or "").strip()
    missing_families = [] if missing_raw == "-" else _normalize_tokens([x.strip() for x in missing_raw.split(",")])
    return {
        "status": status,
        "covered_count": covered_count,
        "required_count": required_count,
        "missing_families": missing_families,
    }


def _parse_findings_summary(report_text: str) -> dict[str, Any]:
    match = _FINDINGS_SUMMARY_LINE_RE.search(report_text or "")
    if not match:
        return {
            "confirmed_count": None,
            "candidate_count": None,
        }
    return {
        "confirmed_count": int(match.group(1)),
        "candidate_count": int(match.group(2)),
    }


def _parse_findings_quality_summary(report_text: str) -> dict[str, Any]:
    confirmed_poc_missing_match = _CONFIRMED_POC_MISSING_LINE_RE.search(report_text or "")
    candidate_reason_missing_match = _CANDIDATE_REASON_MISSING_LINE_RE.search(report_text or "")
    return {
        "confirmed_poc_missing": (
            int(confirmed_poc_missing_match.group(1))
            if confirmed_poc_missing_match
            else None
        ),
        "reason_code_missing": (
            int(candidate_reason_missing_match.group(1))
            if candidate_reason_missing_match
            else None
        ),
    }


def _parse_findings_class_summary(report_text: str) -> dict[str, Any]:
    lines = (report_text or "").splitlines()
    in_section = False
    rows: list[dict[str, Any]] = []
    confirmed_by_vuln_class: dict[str, int] = {}
    candidate_by_vuln_class: dict[str, int] = {}
    total_by_vuln_class: dict[str, int] = {}

    for raw_line in lines:
        line = str(raw_line or "")
        stripped = line.strip()
        if stripped == "### Findings by Vulnerability Class":
            in_section = True
            continue
        if not in_section:
            continue
        if stripped.startswith("### ") and stripped != "### Findings by Vulnerability Class":
            break
        if stripped.startswith("## "):
            break
        match = _FINDING_CLASS_ROW_RE.match(stripped)
        if not match:
            continue
        vuln_class = str(match.group(1) or "").strip().lower()
        if vuln_class in {"vulnerability class", "---------------------"}:
            continue
        confirmed = int(match.group(2))
        candidate = int(match.group(3))
        total = int(match.group(4))
        confirmed_by_vuln_class[vuln_class] = confirmed
        candidate_by_vuln_class[vuln_class] = candidate
        total_by_vuln_class[vuln_class] = total
        rows.append(
            {
                "vuln_class": vuln_class,
                "confirmed": confirmed,
                "candidate": candidate,
                "total": total,
            }
        )

    return {
        "section_found": bool(in_section),
        "confirmed_by_vuln_class": dict(sorted(confirmed_by_vuln_class.items())),
        "candidate_by_vuln_class": dict(sorted(candidate_by_vuln_class.items())),
        "total_by_vuln_class": dict(sorted(total_by_vuln_class.items())),
        "rows": rows,
    }


def _load_baseline_lock(report_file: Path) -> tuple[Path | None, Path | None]:
    lock_path = report_file.parent / _BASELINE_LOCK_FILENAME
    if not lock_path.exists():
        return None, None
    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
    except Exception:
        return None, None
    if not isinstance(payload, dict):
        return None, None

    report_path_raw = str(payload.get("baseline_report_path", "") or "").strip()
    if not report_path_raw:
        return None, None
    try:
        baseline_report = Path(report_path_raw).expanduser().resolve()
    except Exception:
        return None, None
    if not baseline_report.exists():
        return None, None

    baseline_session: Path | None = None
    session_path_raw = str(payload.get("baseline_session_path", "") or "").strip()
    if session_path_raw:
        try:
            session_path = Path(session_path_raw).expanduser().resolve()
            if session_path.exists():
                baseline_session = session_path
        except Exception:
            baseline_session = None

    return baseline_report, baseline_session


def _write_baseline_lock(
    report_file: Path,
    session_file: Path | None,
    *,
    overwrite: bool = False,
) -> None:
    lock_path = report_file.parent / _BASELINE_LOCK_FILENAME
    if lock_path.exists() and not overwrite:
        return
    payload = {
        "version": 1,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "baseline_report_path": str(report_file.resolve()),
        "baseline_session_path": str(session_file.resolve()) if session_file is not None else "",
    }
    try:
        lock_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        return


def set_locked_baseline(
    report_path: Path | str,
    *,
    session_path: Path | str | None = None,
    sessions_dir: Path | str | None = None,
) -> dict[str, Any]:
    report_file = Path(report_path).expanduser().resolve()
    consistency = verify_report_session_consistency(
        report_file,
        session_path=Path(session_path) if session_path else None,
        sessions_dir=Path(sessions_dir) if sessions_dir else None,
    )
    status = str(consistency.get("status", "") or "").strip().lower()
    if status != "consistent":
        return {
            "status": "blocked",
            "updated": False,
            "reason_codes": [
                str(code or "").strip().lower()
                for code in consistency.get("reason_codes", [])
                if str(code or "").strip()
            ],
            "consistency": consistency,
            "lock_path": str((report_file.parent / _BASELINE_LOCK_FILENAME).resolve()),
            "suggested_next_step": "Resolve report/session consistency first, then set baseline lock.",
        }

    report_meta = consistency.get("report", {}) if isinstance(consistency.get("report", {}), dict) else {}
    session_meta = consistency.get("session", {}) if isinstance(consistency.get("session", {}), dict) else {}
    baseline_report_raw = str(report_meta.get("path", "") or "").strip()
    baseline_session_raw = str(session_meta.get("path", "") or "").strip()
    baseline_report = Path(baseline_report_raw).expanduser().resolve() if baseline_report_raw else report_file
    baseline_session = Path(baseline_session_raw).expanduser().resolve() if baseline_session_raw else None

    _write_baseline_lock(
        baseline_report,
        baseline_session,
        overwrite=True,
    )
    baseline_id = _build_baseline_id(baseline_report, baseline_session)
    return {
        "status": "updated",
        "updated": True,
        "reason_codes": [],
        "lock_path": str((baseline_report.parent / _BASELINE_LOCK_FILENAME).resolve()),
        "baseline_id": baseline_id,
        "baseline_report_path": str(baseline_report.resolve()),
        "baseline_session_path": str(baseline_session.resolve()) if baseline_session is not None else None,
        "consistency": consistency,
        "suggested_next_step": "Baseline lock updated. Use this report/session pair as strict-gate baseline.",
    }


def _build_policy_notes(allowed_missing: list[str]) -> list[str]:
    notes: list[str] = []
    allowed_set = {str(item or "").strip().lower() for item in allowed_missing}
    if _SCN08 in allowed_set and _SCN10 in allowed_set and _SCN12 in allowed_set:
        notes.append(
            "Initial-release exception (Ver.1): SCN08/SCN10/SCN12 can remain missing when routed to HITL/manual validation."
        )
    elif _SCN10 in allowed_set and _SCN12 in allowed_set:
        notes.append(
            "Initial-release exception: SCN10/SCN12 can remain missing and are handled in a later phase (HITL/manual)."
        )
    elif _SCN08 in allowed_set:
        notes.append(
            "Initial-release exception: SCN08 can remain missing and is handled in a later phase (HITL/manual)."
        )
    elif _SCN10 in allowed_set:
        notes.append(
            "Initial-release exception: SCN10 can remain missing and is handled in a later phase (HITL/manual)."
        )
    elif _SCN12 in allowed_set:
        notes.append(
            "Initial-release exception: SCN12 can remain missing and is handled in a later phase (HITL/manual)."
        )
    return notes


def _build_recommended_actions(
    *,
    status: str,
    reason_codes: list[str],
    report_path: Path,
    allowed_missing: list[str],
    confirmed_min: int,
    candidate_max: int,
    confirmed_poc_missing_max: int,
    reason_code_missing_max: int,
    required_confirmed_classes: list[str],
    required_class_confirmed_min: int,
    unexpected_missing: list[str],
    missing_required_detection_classes: list[str],
    deferred_scenarios: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    normalized_codes = {str(code or "").strip().lower() for code in reason_codes if str(code or "").strip()}
    actions: list[dict[str, Any]] = []

    def _add(
        action_id: str,
        *,
        priority: str,
        owner: str,
        summary: str,
        command_hint: str,
        applies_when: list[str],
    ) -> None:
        if any(existing.get("id") == action_id for existing in actions):
            return
        actions.append(
            {
                "id": action_id,
                "priority": priority,
                "owner": owner,
                "summary": summary,
                "command_hint": command_hint,
                "applies_when_reason_codes": applies_when,
            }
        )

    if status == "pass":
        required_classes_arg = ",".join(required_confirmed_classes)
        required_flags = ""
        if required_classes_arg:
            required_flags = (
                f" --required-confirmed-classes {required_classes_arg}"
                f" --required-class-confirmed-min {int(required_class_confirmed_min)}"
            )
        _add(
            "proceed_release_candidate",
            priority="info",
            owner="operator",
            summary="Initial-release gate passed. Keep allowed deferred exceptions and proceed.",
            command_hint=(
                f"python3 /app/scripts/check_initial_release_gate.py --report \"{report_path}\" "
                f"--allowed-missing {','.join(allowed_missing)} "
                f"--confirmed-min {int(confirmed_min)} --candidate-max {int(candidate_max)} "
                f"--confirmed-poc-missing-max {int(confirmed_poc_missing_max)} "
                f"--reason-code-missing-max {int(reason_code_missing_max)}"
                f"{required_flags}"
            ),
            applies_when=[],
        )
        if deferred_scenarios:
            scenario_ids = ",".join(
                sorted(
                    {
                        str(item.get("scenario_id", "") or "").strip().lower()
                        for item in deferred_scenarios
                        if isinstance(item, dict) and str(item.get("scenario_id", "") or "").strip()
                    }
                )
            )
            _add(
                "run_deferred_scenario_track",
                priority="medium",
                owner="operator",
                summary=(
                    "Start deferred high-friction track after initial release gate pass "
                    f"(scenarios: {scenario_ids or '-'})"
                ),
                command_hint=f"python3 /app/scripts/check_initial_release_gate.py --report \"{report_path}\"",
                applies_when=[],
            )
        return actions

    if "consistency_blocked" in normalized_codes or "consistency_inconsistent" in normalized_codes:
        _add(
            "resolve_report_session_consistency",
            priority="high",
            owner="operator",
            summary="Resolve report/session mismatch before any rerun decision.",
            command_hint=f"python3 /app/scripts/verify_report_session_consistency.py --report \"{report_path}\"",
            applies_when=["consistency_blocked", "consistency_inconsistent"],
        )

    if "family_gate_not_passed" in normalized_codes or "family_gate_not_found" in normalized_codes:
        _add(
            "improve_family_gate_coverage",
            priority="high",
            owner="shigoku",
            summary="Re-run scan with coverage-backfill tasks enabled to satisfy vulnerability-family gate.",
            command_hint="python3 -m src.main --target <TARGET> --skip-initial-recon",
            applies_when=["family_gate_not_passed", "family_gate_not_found"],
        )

    if "confirmed_below_minimum" in normalized_codes:
        _add(
            "increase_confirmed_density",
            priority="high",
            owner="shigoku",
            summary="Increase confirmed findings by strengthening auth/id/params seed surfaces first.",
            command_hint=(
                "python3 -m src.main --focus-tests --focus-group density "
                "&& python3 -m src.main --target <TARGET> --skip-initial-recon"
            ),
            applies_when=["confirmed_below_minimum"],
        )

    if "required_detection_class_below_minimum" in normalized_codes:
        class_hint = ",".join(missing_required_detection_classes) if missing_required_detection_classes else "<CLASS_LIST>"
        _add(
            "expand_detection_class_coverage",
            priority="high",
            owner="shigoku",
            summary=(
                "Required detection classes are below minimum confirmed threshold. "
                "Expand probes for missing classes and re-run gate."
            ),
            command_hint=(
                "python3 -m src.main --focus-tests --focus-group density "
                "&& python3 -m src.main --target <TARGET> --skip-initial-recon "
                f"# prioritize classes: {class_hint}"
            ),
            applies_when=["required_detection_class_below_minimum"],
        )

    if "candidate_above_maximum" in normalized_codes:
        _add(
            "drain_candidate_queue",
            priority="medium",
            owner="operator",
            summary="Reduce candidate findings by manual verification or stricter promotion thresholds.",
            command_hint=(
                "python3 -m src.main --hitl-list --target <TARGET> "
                "&& python3 -m src.main --hitl-approve <TICKET_ID> --hitl-run --target <TARGET>"
            ),
            applies_when=["candidate_above_maximum"],
        )

    if "confirmed_poc_missing_above_maximum" in normalized_codes or "confirmed_poc_missing_not_found" in normalized_codes:
        _add(
            "enforce_confirmed_poc_artifacts",
            priority="high",
            owner="shigoku",
            summary="Ensure confirmed findings always include PoC request/response evidence artifacts.",
            command_hint=(
                "python3 -m src.main --focus-tests --focus-group report "
                "&& python3 -m src.main --report --format haddix --target <PROJECT_OR_TARGET>"
            ),
            applies_when=["confirmed_poc_missing_above_maximum", "confirmed_poc_missing_not_found"],
        )

    if "reason_code_missing_above_maximum" in normalized_codes or "reason_code_missing_not_found" in normalized_codes:
        _add(
            "enforce_candidate_reason_codes",
            priority="high",
            owner="shigoku",
            summary="Ensure every candidate/failed finding includes standardized reason codes.",
            command_hint=(
                "python3 -m src.main --focus-tests --focus-group report "
                "&& python3 -m src.main --report --format haddix --target <PROJECT_OR_TARGET>"
            ),
            applies_when=["reason_code_missing_above_maximum", "reason_code_missing_not_found"],
        )

    if "unexpected_missing_scenarios" in normalized_codes:
        missing_hint = ",".join(unexpected_missing) if unexpected_missing else "<SCN_ID_LIST>"
        _add(
            "close_unexpected_scenario_gaps",
            priority="high",
            owner="shigoku",
            summary="Unexpected missing scenarios exist. Cover them before initial release.",
            command_hint=(
                "python3 -m src.main --target <TARGET> --skip-initial-recon "
                f"# prioritize missing scenarios: {missing_hint}"
            ),
            applies_when=["unexpected_missing_scenarios"],
        )

    if "findings_summary_not_found" in normalized_codes:
        _add(
            "regenerate_haddix_report",
            priority="medium",
            owner="operator",
            summary="Report format is missing findings summary line; regenerate Haddix report from source session.",
            command_hint="python3 -m src.main --report --format haddix --target <PROJECT_OR_TARGET>",
            applies_when=["findings_summary_not_found"],
        )

    if not actions:
        _add(
            "inspect_reason_codes",
            priority="medium",
            owner="operator",
            summary="Inspect reason_codes and apply targeted remediation.",
            command_hint=f"python3 /app/scripts/check_initial_release_gate.py --report \"{report_path}\"",
            applies_when=sorted(normalized_codes),
        )

    return actions


def _build_deferred_scenarios(
    *,
    allowed_missing: list[str],
    actual_missing: list[str],
) -> list[dict[str, Any]]:
    allowed_set = {str(token or "").strip().lower() for token in allowed_missing if str(token or "").strip()}
    deferred_ids = sorted(
        {
            str(token or "").strip().lower()
            for token in actual_missing
            if str(token or "").strip() and str(token or "").strip().lower() in allowed_set
        }
    )
    deferred: list[dict[str, Any]] = []
    for sid in deferred_ids:
        playbook = _DEFERRED_SCENARIO_PLAYBOOK.get(sid, {})
        deferred.append(
            {
                "scenario_id": sid,
                "title": str(playbook.get("title", sid) or sid),
                "route": str(playbook.get("route", "human_preferred") or "human_preferred"),
                "why_deferred": str(
                    playbook.get(
                        "why_deferred",
                        "Deferred to post-release high-friction track due to low automation efficiency.",
                    )
                ),
                "trigger": str(playbook.get("trigger", "Initial release gate passed while scenario remained missing.")),
                "operator_input": str(playbook.get("operator_input", "Provide domain context and approval constraints.")),
                "success_criteria": str(playbook.get("success_criteria", "Produce reproducible evidence and risk narrative.")),
            }
        )
    return deferred


def evaluate_initial_release_gate(
    report_path: Path | str,
    *,
    session_path: Path | str | None = None,
    sessions_dir: Path | str | None = None,
    baseline_report_path: Path | str | None = None,
    baseline_session_path: Path | str | None = None,
    allowed_missing_scenarios: list[str] | None = None,
    confirmed_min: int = 3,
    candidate_max: int = 2,
    confirmed_poc_missing_max: int = 0,
    reason_code_missing_max: int = 0,
    required_confirmed_classes: list[str] | None = None,
    required_class_confirmed_min: int = 1,
    schema_severity_critical_max: int = 0,
    schema_severity_high_max: int = 0,
    schema_severity_enforcement_mode: str = "warn",
    schema_severity_soft_fail_missing_ratio: float = 0.2,
    schema_severity_soft_fail_missing_count: int = 3,
) -> dict[str, Any]:
    report_file = Path(report_path).expanduser().resolve()
    baseline_report_file = Path(baseline_report_path).expanduser().resolve() if baseline_report_path else None
    baseline_session_file = Path(baseline_session_path).expanduser().resolve() if baseline_session_path else None
    comparison_mode = "against_explicit_baseline" if baseline_report_file is not None else "self_baseline"
    if baseline_report_file is None:
        locked_report, locked_session = _load_baseline_lock(report_file)
        if locked_report is not None:
            baseline_report_file = locked_report
            baseline_session_file = locked_session
            comparison_mode = "against_locked_baseline"
    allowed_missing = _normalize_tokens(
        allowed_missing_scenarios if isinstance(allowed_missing_scenarios, list) else DEFAULT_ALLOWED_MISSING_SCENARIOS
    )
    required_detection_classes = _normalize_required_detection_classes(
        required_confirmed_classes if isinstance(required_confirmed_classes, list) else DEFAULT_REQUIRED_CONFIRMED_CLASSES
    )
    required_class_confirmed_min = max(0, int(required_class_confirmed_min))

    consistency = verify_report_session_consistency(
        report_file,
        session_path=Path(session_path) if session_path else None,
        sessions_dir=Path(sessions_dir) if sessions_dir else None,
    )
    consistency_status = str(consistency.get("status", "") or "").strip().lower()
    consistency_reason_codes = [
        str(code or "").strip().lower()
        for code in consistency.get("reason_codes", [])
        if str(code or "").strip()
    ]
    if consistency_status != "consistent":
        reason_codes = [f"consistency_{consistency_status or 'unknown'}"]
        reason_codes.extend(consistency_reason_codes)
        policy_notes = _build_policy_notes(allowed_missing)
        return {
            "status": "blocked",
            "gate_passed": False,
            "reason_codes": sorted(set(reason_codes)),
            "policy": {
                "allowed_missing_scenarios": allowed_missing,
                "confirmed_min": int(confirmed_min),
                "candidate_max": int(candidate_max),
                "confirmed_poc_missing_max": int(confirmed_poc_missing_max),
                "reason_code_missing_max": int(reason_code_missing_max),
                "required_confirmed_classes": required_detection_classes,
                "required_class_confirmed_min": int(required_class_confirmed_min),
                "schema_severity_critical_max": int(schema_severity_critical_max),
                "schema_severity_high_max": int(schema_severity_high_max),
                "schema_severity_enforcement_mode": str(schema_severity_enforcement_mode or "warn"),
                "schema_severity_soft_fail_missing_ratio": float(schema_severity_soft_fail_missing_ratio),
                "schema_severity_soft_fail_missing_count": int(schema_severity_soft_fail_missing_count),
                "notes": policy_notes,
            },
            "consistency": consistency,
            "report_metrics": {},
            "evaluation_context": {
                "comparison_mode": comparison_mode,
                "baseline_id": _build_baseline_id(baseline_report_file, baseline_session_file),
                "baseline_report_path": str(baseline_report_file.resolve()) if baseline_report_file is not None else str(report_file),
                "baseline_session_path": str(baseline_session_file.resolve()) if baseline_session_file is not None else None,
            },
            "deferred_scenarios": [],
            "recommended_actions": _build_recommended_actions(
                status="blocked",
                reason_codes=reason_codes,
                report_path=report_file,
                allowed_missing=allowed_missing,
                confirmed_min=confirmed_min,
                candidate_max=candidate_max,
                confirmed_poc_missing_max=confirmed_poc_missing_max,
                reason_code_missing_max=reason_code_missing_max,
                required_confirmed_classes=required_detection_classes,
                required_class_confirmed_min=required_class_confirmed_min,
                unexpected_missing=[],
                missing_required_detection_classes=[],
                deferred_scenarios=[],
            ),
            "suggested_next_step": "Resolve report/session consistency first, then evaluate initial-release gate.",
        }

    report_text = report_file.read_text(encoding="utf-8")
    family_gate = _parse_family_gate(report_text)
    findings_summary = _parse_findings_summary(report_text)
    findings_quality = _parse_findings_quality_summary(report_text)
    findings_class_summary = _parse_findings_class_summary(report_text)
    session_meta = consistency.get("session", {})
    session_file_for_backfill: Path | None = None
    if isinstance(session_meta, dict):
        session_path_raw = session_meta.get("path")
        if session_path_raw:
            try:
                session_file_for_backfill = Path(str(session_path_raw)).expanduser().resolve()
            except Exception:
                session_file_for_backfill = None
    session_scenario_coverage = _load_session_scenario_coverage(session_file_for_backfill)
    session_findings_summary = _build_session_findings_summary(session_file_for_backfill)
    session_detection_class_summary = _build_session_detection_class_summary(session_file_for_backfill)
    session_schema_severity_summary = _build_session_schema_severity_summary(session_file_for_backfill)
    scenario_detection_backfill = _build_scenario_detection_backfill(session_scenario_coverage)
    detection_class_summary_raw = _build_detection_class_summary(findings_class_summary)
    detection_class_summary = _merge_detection_class_summary_with_scenario_backfill(
        findings_class_summary,
        scenario_detection_backfill,
    )

    findings_summary_for_decision = findings_summary
    findings_summary_source = "report"
    if bool(session_findings_summary.get("available")):
        findings_summary_for_decision = {
            "confirmed_count": session_findings_summary.get("confirmed_count"),
            "candidate_count": session_findings_summary.get("candidate_count"),
        }
        findings_summary_source = str(session_findings_summary.get("source") or "session_raw_unique")

    scenario_coverage_raw = consistency.get("report", {}).get("scenario_coverage", {})
    scenario_coverage = scenario_coverage_raw if isinstance(scenario_coverage_raw, dict) else {}
    actual_missing = _normalize_tokens(scenario_coverage.get("missing_scenarios", []))
    allowed_set = set(allowed_missing)
    unexpected_missing = sorted([sid for sid in actual_missing if sid not in allowed_set])
    deferred_scenarios = _build_deferred_scenarios(
        allowed_missing=allowed_missing,
        actual_missing=actual_missing,
    )

    reason_codes: list[str] = []
    missing_required_detection_classes: list[str] = []

    baseline_consistency = consistency
    baseline_report_text = report_text
    baseline_family_gate = family_gate
    baseline_findings_summary = findings_summary
    baseline_findings_class_summary = findings_class_summary
    baseline_scenario_coverage = scenario_coverage
    baseline_report_resolved = report_file
    baseline_session_resolved: Path | None = None
    if isinstance(consistency.get("session"), dict):
        session_path_raw = consistency.get("session", {}).get("path")
        if session_path_raw:
            try:
                baseline_session_resolved = Path(str(session_path_raw)).expanduser().resolve()
            except Exception:
                baseline_session_resolved = None
    if baseline_report_file is None:
        baseline_report_file = report_file
        baseline_session_file = baseline_session_resolved
        comparison_mode = "baseline_initialized"
        _write_baseline_lock(report_file, baseline_session_resolved)

    if baseline_report_file is not None:
        baseline_consistency = verify_report_session_consistency(
            baseline_report_file,
            session_path=baseline_session_file,
            sessions_dir=Path(sessions_dir) if sessions_dir else None,
        )
        baseline_status = str(baseline_consistency.get("status", "") or "").strip().lower()
        if baseline_status != "consistent":
            reason_codes.append(f"baseline_consistency_{baseline_status or 'unknown'}")
            for code in baseline_consistency.get("reason_codes", []):
                token = str(code or "").strip().lower()
                if token:
                    reason_codes.append(f"baseline_{token}")
        else:
            baseline_report_meta = baseline_consistency.get("report", {})
            if isinstance(baseline_report_meta, dict):
                baseline_report_path_raw = baseline_report_meta.get("path")
                if baseline_report_path_raw:
                    baseline_report_resolved = Path(str(baseline_report_path_raw)).expanduser().resolve()
                baseline_scenario_cov_raw = baseline_report_meta.get("scenario_coverage", {})
                if isinstance(baseline_scenario_cov_raw, dict):
                    baseline_scenario_coverage = baseline_scenario_cov_raw

            baseline_session_meta = baseline_consistency.get("session", {})
            if isinstance(baseline_session_meta, dict):
                baseline_session_path_raw = baseline_session_meta.get("path")
                if baseline_session_path_raw:
                    baseline_session_resolved = Path(str(baseline_session_path_raw)).expanduser().resolve()

            try:
                baseline_report_text = baseline_report_resolved.read_text(encoding="utf-8")
                baseline_family_gate = _parse_family_gate(baseline_report_text)
                baseline_findings_summary = _parse_findings_summary(baseline_report_text)
                baseline_findings_class_summary = _parse_findings_class_summary(baseline_report_text)
            except Exception:
                reason_codes.append("baseline_report_parse_failed")

    family_gate_status = str(family_gate.get("status", "") or "").strip().lower()
    if family_gate_status not in {"pass", "fail"}:
        reason_codes.append("family_gate_not_found")
    elif family_gate_status != "pass":
        reason_codes.append("family_gate_not_passed")

    confirmed_count_raw = findings_summary_for_decision.get("confirmed_count")
    candidate_count_raw = findings_summary_for_decision.get("candidate_count")
    confirmed_poc_missing_raw = findings_quality.get("confirmed_poc_missing")
    reason_code_missing_raw = findings_quality.get("reason_code_missing")
    if confirmed_count_raw is None or candidate_count_raw is None:
        reason_codes.append("findings_summary_not_found")
        confirmed_count = None
        candidate_count = None
    else:
        confirmed_count = int(confirmed_count_raw)
        candidate_count = int(candidate_count_raw)
        if confirmed_count < int(confirmed_min):
            reason_codes.append("confirmed_below_minimum")
        if candidate_count > int(candidate_max):
            reason_codes.append("candidate_above_maximum")

    if confirmed_poc_missing_raw is None:
        reason_codes.append("confirmed_poc_missing_not_found")
        confirmed_poc_missing = None
    else:
        confirmed_poc_missing = int(confirmed_poc_missing_raw)
        if confirmed_poc_missing > int(confirmed_poc_missing_max):
            reason_codes.append("confirmed_poc_missing_above_maximum")

    if reason_code_missing_raw is None:
        reason_codes.append("reason_code_missing_not_found")
        reason_code_missing = None
    else:
        reason_code_missing = int(reason_code_missing_raw)
        if reason_code_missing > int(reason_code_missing_max):
            reason_codes.append("reason_code_missing_above_maximum")

    schema_counts = session_schema_severity_summary.get("counts", {})
    if not isinstance(schema_counts, dict):
        schema_counts = {}
    schema_critical_count = int(_safe_int(schema_counts.get("critical")) or 0)
    schema_high_count = int(_safe_int(schema_counts.get("high")) or 0)
    if schema_critical_count > int(schema_severity_critical_max):
        reason_codes.append("schema_severity_critical_above_maximum")
    if schema_high_count > int(schema_severity_high_max):
        reason_codes.append("schema_severity_high_above_maximum")
    mode_token = str(schema_severity_enforcement_mode or "warn").strip().lower()
    if mode_token not in {"warn", "soft-fail", "hard-fail"}:
        mode_token = "warn"
    missing_schema_count = int(_safe_int(schema_counts.get("none")) or 0)
    schema_unique_findings = int(_safe_int(session_schema_severity_summary.get("unique_findings_count")) or 0)
    missing_schema_ratio = (
        float(missing_schema_count) / float(schema_unique_findings)
        if schema_unique_findings > 0
        else 0.0
    )
    if mode_token == "soft-fail":
        if (
            missing_schema_count > int(schema_severity_soft_fail_missing_count)
            or missing_schema_ratio > float(schema_severity_soft_fail_missing_ratio)
        ):
            reason_codes.append("schema_severity_missing_soft_fail")
    elif mode_token == "hard-fail":
        if missing_schema_count > 0:
            reason_codes.append("schema_severity_missing_hard_fail")

    if required_detection_classes:
        required_detection_class_source = "raw_detection_class_summary"
        raw_confirmed_by_detection_class = detection_class_summary_raw.get("confirmed_by_detection_class", {})
        session_confirmed_by_detection_class = session_detection_class_summary.get("confirmed_by_detection_class", {})
        if not isinstance(raw_confirmed_by_detection_class, dict):
            raw_confirmed_by_detection_class = {}
        if not isinstance(session_confirmed_by_detection_class, dict):
            session_confirmed_by_detection_class = {}
        if bool(session_detection_class_summary.get("available")):
            required_detection_class_source = "hybrid_session_raw_detection_class_summary_max"

        def _hybrid_confirmed_count_for_class(detection_class: str) -> int:
            raw_value = int(_safe_int(raw_confirmed_by_detection_class.get(detection_class)) or 0)
            session_value = int(_safe_int(session_confirmed_by_detection_class.get(detection_class)) or 0)
            return max(raw_value, session_value)

        for detection_class in required_detection_classes:
            confirmed_for_class = _hybrid_confirmed_count_for_class(detection_class)
            if confirmed_for_class < int(required_class_confirmed_min):
                missing_required_detection_classes.append(detection_class)
        if missing_required_detection_classes:
            reason_codes.append("required_detection_class_below_minimum")

    if unexpected_missing:
        reason_codes.append("unexpected_missing_scenarios")

    gate_passed = not reason_codes
    status = "pass" if gate_passed else "fail"
    policy_notes = _build_policy_notes(allowed_missing)
    recommended_actions = _build_recommended_actions(
        status=status,
        reason_codes=reason_codes,
        report_path=report_file,
        allowed_missing=allowed_missing,
        confirmed_min=confirmed_min,
        candidate_max=candidate_max,
        confirmed_poc_missing_max=confirmed_poc_missing_max,
        reason_code_missing_max=reason_code_missing_max,
        required_confirmed_classes=required_detection_classes,
        required_class_confirmed_min=required_class_confirmed_min,
        unexpected_missing=unexpected_missing,
        missing_required_detection_classes=missing_required_detection_classes,
        deferred_scenarios=deferred_scenarios,
    )
    required_detection_class_eval: dict[str, Any] = {
        "required_confirmed_classes": required_detection_classes,
        "required_class_confirmed_min": int(required_class_confirmed_min),
        "missing_classes": missing_required_detection_classes,
        "decision_source": (
            required_detection_class_source if required_detection_classes else "disabled"
        ),
        "status": (
            "disabled"
            if not required_detection_classes
            else ("pass" if not missing_required_detection_classes else "fail")
        ),
    }
    if required_detection_classes:
        confirmed_by_detection_class_for_eval = detection_class_summary_raw.get("confirmed_by_detection_class", {})
        if not isinstance(confirmed_by_detection_class_for_eval, dict):
            confirmed_by_detection_class_for_eval = {}
        session_confirmed_by_detection_class_for_eval = session_detection_class_summary.get(
            "confirmed_by_detection_class", {}
        )
        if not isinstance(session_confirmed_by_detection_class_for_eval, dict):
            session_confirmed_by_detection_class_for_eval = {}

        def _hybrid_confirmed_count_for_eval(detection_class: str) -> int:
            raw_value = int(_safe_int(confirmed_by_detection_class_for_eval.get(detection_class)) or 0)
            session_value = int(_safe_int(session_confirmed_by_detection_class_for_eval.get(detection_class)) or 0)
            return max(raw_value, session_value)

        confirmed_by_detection_class_with_backfill = detection_class_summary.get("confirmed_by_detection_class", {})
        if not isinstance(confirmed_by_detection_class_with_backfill, dict):
            confirmed_by_detection_class_with_backfill = {}
        required_detection_class_eval["class_confirmed_counts"] = {
            detection_class: _hybrid_confirmed_count_for_eval(detection_class)
            for detection_class in required_detection_classes
        }
        required_detection_class_eval["class_confirmed_counts_with_backfill"] = {
            detection_class: int(_safe_int(confirmed_by_detection_class_with_backfill.get(detection_class)) or 0)
            for detection_class in required_detection_classes
        }

    return {
        "status": status,
        "gate_passed": gate_passed,
        "reason_codes": sorted(set(reason_codes)),
        "policy": {
            "allowed_missing_scenarios": allowed_missing,
            "confirmed_min": int(confirmed_min),
            "candidate_max": int(candidate_max),
            "confirmed_poc_missing_max": int(confirmed_poc_missing_max),
            "reason_code_missing_max": int(reason_code_missing_max),
            "required_confirmed_classes": required_detection_classes,
            "required_class_confirmed_min": int(required_class_confirmed_min),
                "schema_severity_critical_max": int(schema_severity_critical_max),
                "schema_severity_high_max": int(schema_severity_high_max),
                "schema_severity_enforcement_mode": mode_token,
                "schema_severity_soft_fail_missing_ratio": float(schema_severity_soft_fail_missing_ratio),
                "schema_severity_soft_fail_missing_count": int(schema_severity_soft_fail_missing_count),
                "notes": policy_notes,
            },
        "evaluation_context": {
            "comparison_mode": comparison_mode,
            "baseline_id": _build_baseline_id(baseline_report_resolved, baseline_session_resolved),
            "baseline_report_path": str(baseline_report_resolved.resolve()),
            "baseline_session_path": str(baseline_session_resolved.resolve()) if baseline_session_resolved is not None else None,
        },
        "consistency": consistency,
        "report_metrics": {
            "actual_missing_scenarios": actual_missing,
            "unexpected_missing_scenarios": unexpected_missing,
            "family_gate": family_gate,
            "findings_summary": {
                "confirmed_count": confirmed_count,
                "candidate_count": candidate_count,
                "confirmed_poc_missing": confirmed_poc_missing,
                "reason_code_missing": reason_code_missing,
                "source": findings_summary_source,
            },
            "report_findings_summary": findings_summary,
            "session_findings_summary": session_findings_summary,
            "session_detection_class_summary": session_detection_class_summary,
            "session_schema_severity_summary": session_schema_severity_summary,
            "schema_severity_enforcement": {
                "mode": mode_token,
                "missing_schema_count": missing_schema_count,
                "missing_schema_ratio": missing_schema_ratio,
                "unique_findings_count": schema_unique_findings,
                "soft_fail_missing_ratio_threshold": float(schema_severity_soft_fail_missing_ratio),
                "soft_fail_missing_count_threshold": int(schema_severity_soft_fail_missing_count),
            },
            "findings_class_summary": findings_class_summary,
            "detection_class_summary_raw": detection_class_summary_raw,
            "detection_class_summary": detection_class_summary,
            "required_detection_class_evaluation": required_detection_class_eval,
            "baseline_diff": _build_baseline_diff(
                current_scenario_coverage=scenario_coverage,
                current_family_gate=family_gate,
                current_findings_summary=findings_summary,
                current_findings_class_summary=findings_class_summary,
                baseline_scenario_coverage=baseline_scenario_coverage,
                baseline_family_gate=baseline_family_gate,
                baseline_findings_summary=baseline_findings_summary,
                baseline_findings_class_summary=baseline_findings_class_summary,
            ),
        },
        "deferred_scenarios": deferred_scenarios,
        "recommended_actions": recommended_actions,
        "suggested_next_step": (
            "Initial-release gate passed. Continue with release workflow."
            if gate_passed
            else "Address reason_codes (or update policy) and re-run gate check."
        ),
    }
