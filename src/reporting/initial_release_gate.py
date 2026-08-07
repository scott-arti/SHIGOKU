from __future__ import annotations

from datetime import datetime
import json
import hashlib
from pathlib import Path
import re
from typing import Any

from src.core.utils.json_utils import safe_json_loads
from src.reporting.expected_detection_matrix import extract_session_security_level
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
    display_metadata = {
        # These counts classify only the session's native candidate flags.  They
        # do not run the submission evidence-quality validator, so they must
        # never be presented as submission confirmation.
        "classification_scope": "pre_evidence_quality_session_metadata",
        "confirmed_count_label": (
            "Raw findings without candidate flags (not submission-confirmed)"
        ),
        "candidate_count_label": "Raw findings marked candidate before evidence-quality review",
        "authoritative_confirmation_source": "report_findings_summary",
    }
    if session_path is None:
        return {
            "source": "session_raw_unique",
            **display_metadata,
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
            **display_metadata,
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
            **display_metadata,
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
            **display_metadata,
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
        **display_metadata,
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


def _session_security_level(session_path: Path | None) -> str:
    if session_path is None:
        return ""
    try:
        payload = json.loads(session_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    return extract_session_security_level(payload) or ""


def _load_baseline_lock(
    report_file: Path,
    *,
    current_session: Path | None = None,
) -> tuple[Path | None, Path | None]:
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

    current_level = _session_security_level(current_session)
    baseline_level = _session_security_level(baseline_session)
    if current_level and baseline_level and current_level != baseline_level:
        return None, None
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


def _make_condition_log(
    condition_id: str,
    policy_value: Any,
    actual_value: Any,
    comparison_operator: str,
    individual_result: str,
    *,
    exception_applied: bool = False,
    exception_scope: str = "",
    final_result: str | None = None,
) -> dict[str, Any]:
    """Build a structured condition log entry for gate evaluation."""
    return {
        "condition_id": condition_id,
        "policy_value": policy_value,
        "actual_value": actual_value,
        "comparison_operator": comparison_operator,
        "individual_result": individual_result,
        "exception_applied": exception_applied,
        "exception_scope": exception_scope,
        "final_result": final_result if final_result is not None else individual_result,
    }


def _evaluate_gate_overall(gates: dict[str, dict[str, Any]]) -> tuple[str, bool, list[str]]:
    """Compute overall gate status: FAIL-CLOSED — only PASS if ALL required gates pass."""
    reason_codes: list[str] = []
    all_passed = True
    any_blocked = False
    for gate_name, gate_result in gates.items():
        gate_rc = gate_result.get("reason_codes", [])
        reason_codes.extend(gate_rc)
        gate_status = str(gate_result.get("status", "")).strip().lower()
        if gate_status == "blocked":
            any_blocked = True
        if gate_result.get("passed") is False:
            if gate_status != "not_applicable":
                all_passed = False
    if any_blocked:
        return ("blocked", False, sorted(set(reason_codes)))
    if all_passed:
        return ("pass", True, [])
    return ("fail", False, sorted(set(reason_codes)))


def _evaluate_regression_gate(
    baseline_diff: dict[str, Any],
    *,
    regression_confirmed_delta_min: int = 0,
    regression_allow_dedup_reduction: bool = True,
) -> dict[str, Any]:
    """Independent Regression Gate: detects confirmed count drops vs baseline."""
    findings = baseline_diff.get("findings", {})
    confirmed_delta = findings.get("confirmed_delta")
    reason_codes: list[str] = []
    condition_logs: list[dict[str, Any]] = []
    failed = False

    if confirmed_delta is not None:
        delta_value = int(_safe_int(confirmed_delta) or 0)
        condition = _make_condition_log(
            condition_id="regression_confirmed_delta",
            policy_value=regression_confirmed_delta_min,
            actual_value=delta_value,
            comparison_operator="gte",
            individual_result="pass" if delta_value >= regression_confirmed_delta_min else "fail",
        )
        condition_logs.append(condition)
        if delta_value < regression_confirmed_delta_min:
            reason_codes.append("regression_confirmed_drop")
            failed = True

    class_diffs = baseline_diff.get("finding_classes", {}).get("classes", [])
    dropped_classes: list[dict[str, Any]] = []
    for cls in class_diffs:
        cls_delta = cls.get("confirmed_delta", 0)
        if isinstance(cls_delta, (int, float)) and cls_delta < 0:
            dropped_classes.append(
                {
                    "vuln_class": cls.get("vuln_class", ""),
                    "confirmed_delta": cls_delta,
                    "current_confirmed": cls.get("current_confirmed", 0),
                    "baseline_confirmed": cls.get("baseline_confirmed", 0),
                }
            )
    if dropped_classes and not regression_allow_dedup_reduction:
        reason_codes.append("regression_class_drop")
        failed = True

    status = "not_applicable" if confirmed_delta is None else ("fail" if failed else "pass")
    return {
        "status": status,
        "passed": status == "pass",
        "reason_codes": sorted(set(reason_codes)),
        "policy_values": {
            "regression_confirmed_delta_min": regression_confirmed_delta_min,
            "regression_allow_dedup_reduction": regression_allow_dedup_reduction,
        },
        "actual_values": {
            "confirmed_delta": confirmed_delta,
            "dropped_classes": dropped_classes,
        },
        "baseline_diff": baseline_diff,
        "condition_logs": condition_logs,
    }


def evaluate_gate_separated(
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
    regression_confirmed_delta_min: int = 0,
    regression_allow_dedup_reduction: bool = True,
    schema_severity_critical_max: int = 0,
    schema_severity_high_max: int = 0,
    schema_severity_enforcement_mode: str = "warn",
    schema_severity_soft_fail_missing_ratio: float = 0.2,
    schema_severity_soft_fail_missing_count: int = 3,
) -> dict[str, Any]:
    """Evaluate the initial-release gate with 5 independent sub-gates.

    Returns a structured result where each sub-gate has its own status,
    reason codes, policy values, and actual values. The overall gate
    is FAIL-CLOSED: overall PASS only when ALL required gates pass.
    """
    # ── 1. Resolve paths and policy parameters ──
    report_file = Path(report_path).expanduser().resolve()
    baseline_report_file = Path(baseline_report_path).expanduser().resolve() if baseline_report_path else None
    baseline_session_file = Path(baseline_session_path).expanduser().resolve() if baseline_session_path else None
    comparison_mode = "against_explicit_baseline" if baseline_report_file is not None else "self_baseline"
    if baseline_report_file is None:
        locked_report, locked_session = _load_baseline_lock(
            report_file,
            current_session=Path(session_path) if session_path else None,
        )
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
    mode_token = str(schema_severity_enforcement_mode or "warn").strip().lower()
    if mode_token not in {"warn", "soft-fail", "hard-fail"}:
        mode_token = "warn"

    # ── 2. Consistency check ──
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
    policy_notes = _build_policy_notes(allowed_missing)

    if consistency_status != "consistent":
        blocked_reason_codes = sorted(set([f"consistency_{consistency_status or 'unknown'}", *consistency_reason_codes]))
        blocked_result = {
            "status": "blocked",
            "gate_passed": False,
            "reason_codes": blocked_reason_codes,
            "gates": {
                "submission": {
                    "status": "fail",
                    "passed": False,
                    "reason_codes": consistency_reason_codes,
                    "policy_values": {"consistency_required": True},
                    "actual_values": {"consistency_status": consistency_status},
                    "condition_logs": [
                        _make_condition_log(
                            condition_id="consistency_check",
                            policy_value="consistent",
                            actual_value=consistency_status,
                            comparison_operator="eq",
                            individual_result="fail",
                        )
                    ],
                },
                "scenario_coverage": {"status": "not_evaluated", "passed": True, "reason_codes": [], "policy_values": {}, "actual_values": {}, "condition_logs": []},
                "evidence_quality": {"status": "not_evaluated", "passed": True, "reason_codes": [], "policy_values": {}, "actual_values": {}, "condition_logs": []},
                "finding_policy": {"status": "not_evaluated", "passed": True, "reason_codes": [], "policy_values": {}, "actual_values": {}, "condition_logs": []},
                "regression": {"status": "not_evaluated", "passed": True, "reason_codes": [], "policy_values": {}, "actual_values": {}, "baseline_diff": {}, "condition_logs": []},
            },
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
                reason_codes=blocked_reason_codes,
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
        return blocked_result

    # ── 3. Parse report and session data ──
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

    # Finding Policy Gate must use the report's parsed findings summary, NOT the session
    # raw findings. The session may contain pre-evidence-quality-gate counts that differ
    # from what the report actually renders (e.g., session has 10 confirmed, but evidence
    # quality gate demoted 9 to candidate → report shows 1 confirmed / 10 candidate).
    # Accept criteria: §9「Confirmed 1 < 3 でFAILになる」「Candidate 10 > 2 でFAILになる」
    findings_summary_for_decision = findings_summary
    findings_summary_source = "report"
    # Session findings are available for Evidence Quality Gate comparison (schema severity,
    # detection class backfill) but MUST NOT override the report's confirmed/candidate
    # counts in the Finding Policy Gate.
    session_findings_available = bool(session_findings_summary.get("available"))

    scenario_coverage_raw = consistency.get("report", {}).get("scenario_coverage", {})
    scenario_coverage = scenario_coverage_raw if isinstance(scenario_coverage_raw, dict) else {}
    actual_missing = _normalize_tokens(scenario_coverage.get("missing_scenarios", []))
    allowed_set = set(allowed_missing)
    unexpected_missing = sorted([sid for sid in actual_missing if sid not in allowed_set])
    deferred_scenarios = _build_deferred_scenarios(
        allowed_missing=allowed_missing,
        actual_missing=actual_missing,
    )

    # ── 4. Baseline loading ──
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
    baseline_reason_codes: list[str] = []

    if baseline_report_file is not None:
        baseline_consistency = verify_report_session_consistency(
            baseline_report_file,
            session_path=baseline_session_file,
            sessions_dir=Path(sessions_dir) if sessions_dir else None,
        )
        baseline_status = str(baseline_consistency.get("status", "") or "").strip().lower()
        if baseline_status != "consistent":
            baseline_reason_codes.append(f"baseline_consistency_{baseline_status or 'unknown'}")
            for code in baseline_consistency.get("reason_codes", []):
                token = str(code or "").strip().lower()
                if token:
                    baseline_reason_codes.append(f"baseline_{token}")
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
                baseline_reason_codes.append("baseline_report_parse_failed")

    baseline_diff = _build_baseline_diff(
        current_scenario_coverage=scenario_coverage,
        current_family_gate=family_gate,
        current_findings_summary=findings_summary,
        current_findings_class_summary=findings_class_summary,
        baseline_scenario_coverage=baseline_scenario_coverage,
        baseline_family_gate=baseline_family_gate,
        baseline_findings_summary=baseline_findings_summary,
        baseline_findings_class_summary=baseline_findings_class_summary,
    )

    # ── 5. Evaluate 5 independent sub-gates ──

    # --- Gate 1: Scenario Coverage (SCOPED allowed_missing) ---
    scenario_condition_logs: list[dict[str, Any]] = []
    scenario_reason_codes: list[str] = []
    scenario_passed = True

    scenario_condition = _make_condition_log(
        condition_id="unexpected_missing_scenarios",
        policy_value=sorted(allowed_set),
        actual_value=unexpected_missing,
        comparison_operator="eq",
        individual_result="pass" if not unexpected_missing else "fail",
        exception_applied=len(unexpected_missing) == 0 and len(actual_missing) > 0,
        exception_scope="allowed_missing_scenarios",
    )
    scenario_condition_logs.append(scenario_condition)
    if unexpected_missing:
        scenario_reason_codes.append("unexpected_missing_scenarios")
        scenario_passed = False

    scenario_coverage_gate = {
        "status": "pass" if scenario_passed else "fail",
        "passed": scenario_passed,
        "reason_codes": sorted(set(scenario_reason_codes)),
        "allowed_missing": allowed_missing,
        "unexpected_missing": unexpected_missing,
        "policy_values": {"allowed_missing_scenarios": allowed_missing},
        "actual_values": {
            "actual_missing_scenarios": actual_missing,
            "unexpected_missing_scenarios": unexpected_missing,
        },
        "condition_logs": scenario_condition_logs,
    }

    # --- Gate 2: Evidence Quality ---
    evidence_condition_logs: list[dict[str, Any]] = []
    evidence_reason_codes: list[str] = []
    evidence_passed = True

    # Family gate check
    family_gate_status = str(family_gate.get("status", "") or "").strip().lower()
    family_gate_found = family_gate_status in {"pass", "fail"}
    family_condition = _make_condition_log(
        condition_id="family_gate",
        policy_value="pass",
        actual_value=family_gate_status,
        comparison_operator="eq",
        individual_result="pass" if family_gate_status == "pass" else "fail",
    )
    evidence_condition_logs.append(family_condition)
    if not family_gate_found:
        evidence_reason_codes.append("family_gate_not_found")
        evidence_passed = False
    elif family_gate_status != "pass":
        evidence_reason_codes.append("family_gate_not_passed")
        evidence_passed = False

    # Confirmed PoC missing check
    confirmed_poc_missing_raw = findings_quality.get("confirmed_poc_missing")
    confirmed_poc_missing: int | None = None
    if confirmed_poc_missing_raw is None:
        evidence_reason_codes.append("confirmed_poc_missing_not_found")
        evidence_passed = False
        poc_condition = _make_condition_log(
            condition_id="confirmed_poc_missing_found",
            policy_value=True,
            actual_value=False,
            comparison_operator="eq",
            individual_result="fail",
        )
        evidence_condition_logs.append(poc_condition)
    else:
        confirmed_poc_missing = int(confirmed_poc_missing_raw)
        poc_condition = _make_condition_log(
            condition_id="confirmed_poc_missing",
            policy_value=confirmed_poc_missing_max,
            actual_value=confirmed_poc_missing,
            comparison_operator="lte",
            individual_result="pass" if confirmed_poc_missing <= int(confirmed_poc_missing_max) else "fail",
        )
        evidence_condition_logs.append(poc_condition)
        if confirmed_poc_missing > int(confirmed_poc_missing_max):
            evidence_reason_codes.append("confirmed_poc_missing_above_maximum")
            evidence_passed = False

    # Reason code missing check
    reason_code_missing_raw = findings_quality.get("reason_code_missing")
    reason_code_missing_val: int | None = None
    if reason_code_missing_raw is None:
        evidence_reason_codes.append("reason_code_missing_not_found")
        evidence_passed = False
        rc_condition = _make_condition_log(
            condition_id="reason_code_missing_found",
            policy_value=True,
            actual_value=False,
            comparison_operator="eq",
            individual_result="fail",
        )
        evidence_condition_logs.append(rc_condition)
    else:
        reason_code_missing_val = int(reason_code_missing_raw)
        rc_condition = _make_condition_log(
            condition_id="reason_code_missing",
            policy_value=reason_code_missing_max,
            actual_value=reason_code_missing_val,
            comparison_operator="lte",
            individual_result="pass" if reason_code_missing_val <= int(reason_code_missing_max) else "fail",
        )
        evidence_condition_logs.append(rc_condition)
        if reason_code_missing_val > int(reason_code_missing_max):
            evidence_reason_codes.append("reason_code_missing_above_maximum")
            evidence_passed = False

    # Schema severity checks
    schema_counts = session_schema_severity_summary.get("counts", {})
    if not isinstance(schema_counts, dict):
        schema_counts = {}
    schema_critical_count = int(_safe_int(schema_counts.get("critical")) or 0)
    schema_high_count = int(_safe_int(schema_counts.get("high")) or 0)
    missing_schema_count = int(_safe_int(schema_counts.get("none")) or 0)
    schema_unique_findings = int(_safe_int(session_schema_severity_summary.get("unique_findings_count")) or 0)
    missing_schema_ratio = (
        float(missing_schema_count) / float(schema_unique_findings)
        if schema_unique_findings > 0
        else 0.0
    )

    crit_condition = _make_condition_log(
        condition_id="schema_severity_critical",
        policy_value=schema_severity_critical_max,
        actual_value=schema_critical_count,
        comparison_operator="lte",
        individual_result="pass" if schema_critical_count <= int(schema_severity_critical_max) else "fail",
    )
    evidence_condition_logs.append(crit_condition)
    if schema_critical_count > int(schema_severity_critical_max):
        evidence_reason_codes.append("schema_severity_critical_above_maximum")
        evidence_passed = False

    high_condition = _make_condition_log(
        condition_id="schema_severity_high",
        policy_value=schema_severity_high_max,
        actual_value=schema_high_count,
        comparison_operator="lte",
        individual_result="pass" if schema_high_count <= int(schema_severity_high_max) else "fail",
    )
    evidence_condition_logs.append(high_condition)
    if schema_high_count > int(schema_severity_high_max):
        evidence_reason_codes.append("schema_severity_high_above_maximum")
        evidence_passed = False

    if mode_token == "soft-fail":
        schema_soft_condition = _make_condition_log(
            condition_id="schema_severity_missing",
            policy_value={
                "max_count": int(schema_severity_soft_fail_missing_count),
                "max_ratio": float(schema_severity_soft_fail_missing_ratio),
            },
            actual_value={
                "missing_count": missing_schema_count,
                "missing_ratio": missing_schema_ratio,
            },
            comparison_operator="threshold",
            individual_result=(
                "fail"
                if missing_schema_count > int(schema_severity_soft_fail_missing_count)
                or missing_schema_ratio > float(schema_severity_soft_fail_missing_ratio)
                else "pass"
            ),
        )
        evidence_condition_logs.append(schema_soft_condition)
        if (
            missing_schema_count > int(schema_severity_soft_fail_missing_count)
            or missing_schema_ratio > float(schema_severity_soft_fail_missing_ratio)
        ):
            evidence_reason_codes.append("schema_severity_missing_soft_fail")
            evidence_passed = False
    elif mode_token == "hard-fail":
        schema_hard_condition = _make_condition_log(
            condition_id="schema_severity_missing",
            policy_value=0,
            actual_value=missing_schema_count,
            comparison_operator="lte",
            individual_result="pass" if missing_schema_count <= 0 else "fail",
        )
        evidence_condition_logs.append(schema_hard_condition)
        if missing_schema_count > 0:
            evidence_reason_codes.append("schema_severity_missing_hard_fail")
            evidence_passed = False

    evidence_quality_gate = {
        "status": "pass" if evidence_passed else "fail",
        "passed": evidence_passed,
        "reason_codes": sorted(set(evidence_reason_codes)),
        "policy_values": {
            "confirmed_poc_missing_max": int(confirmed_poc_missing_max),
            "reason_code_missing_max": int(reason_code_missing_max),
            "schema_severity_critical_max": int(schema_severity_critical_max),
            "schema_severity_high_max": int(schema_severity_high_max),
            "schema_severity_enforcement_mode": mode_token,
            "schema_severity_soft_fail_missing_ratio": float(schema_severity_soft_fail_missing_ratio),
            "schema_severity_soft_fail_missing_count": int(schema_severity_soft_fail_missing_count),
        },
        "actual_values": {
            "family_gate_status": family_gate_status,
            "confirmed_poc_missing": confirmed_poc_missing,
            "reason_code_missing": reason_code_missing_val,
            "schema_critical_count": schema_critical_count,
            "schema_high_count": schema_high_count,
            "missing_schema_count": missing_schema_count,
            "missing_schema_ratio": missing_schema_ratio,
        },
        "condition_logs": evidence_condition_logs,
    }

    # --- Gate 3: Finding Policy ---
    finding_condition_logs: list[dict[str, Any]] = []
    finding_reason_codes: list[str] = []
    finding_passed = True

    confirmed_count_raw = findings_summary_for_decision.get("confirmed_count")
    candidate_count_raw = findings_summary_for_decision.get("candidate_count")
    confirmed_count: int | None = None
    candidate_count: int | None = None

    if confirmed_count_raw is None or candidate_count_raw is None:
        finding_reason_codes.append("findings_summary_not_found")
        finding_passed = False
        finding_condition_logs.append(_make_condition_log(
            condition_id="findings_summary_available",
            policy_value=True,
            actual_value=False,
            comparison_operator="eq",
            individual_result="fail",
        ))
    else:
        confirmed_count = int(confirmed_count_raw)
        candidate_count = int(candidate_count_raw)
        finding_condition_logs.append(_make_condition_log(
            condition_id="findings_summary_available",
            policy_value=True,
            actual_value=True,
            comparison_operator="eq",
            individual_result="pass",
        ))

        conf_condition = _make_condition_log(
            condition_id="confirmed_below_minimum",
            policy_value=confirmed_min,
            actual_value=confirmed_count,
            comparison_operator="gte",
            individual_result="pass" if confirmed_count >= int(confirmed_min) else "fail",
        )
        finding_condition_logs.append(conf_condition)
        if confirmed_count < int(confirmed_min):
            finding_reason_codes.append("confirmed_below_minimum")
            finding_passed = False

        cand_condition = _make_condition_log(
            condition_id="candidate_above_maximum",
            policy_value=candidate_max,
            actual_value=candidate_count,
            comparison_operator="lte",
            individual_result="pass" if candidate_count <= int(candidate_max) else "fail",
        )
        finding_condition_logs.append(cand_condition)
        if candidate_count > int(candidate_max):
            finding_reason_codes.append("candidate_above_maximum")
            finding_passed = False

    # Required detection classes
    missing_required_detection_classes: list[str] = []
    required_detection_class_source = "disabled"
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

        def _hybrid_count(detection_class: str) -> int:
            raw_value = int(_safe_int(raw_confirmed_by_detection_class.get(detection_class)) or 0)
            session_value = int(_safe_int(session_confirmed_by_detection_class.get(detection_class)) or 0)
            return max(raw_value, session_value)

        for detection_class in required_detection_classes:
            confirmed_for_class = _hybrid_count(detection_class)
            finding_condition_logs.append(_make_condition_log(
                condition_id=f"required_class_{detection_class}",
                policy_value=required_class_confirmed_min,
                actual_value=confirmed_for_class,
                comparison_operator="gte",
                individual_result="pass" if confirmed_for_class >= int(required_class_confirmed_min) else "fail",
            ))
            if confirmed_for_class < int(required_class_confirmed_min):
                missing_required_detection_classes.append(detection_class)

    if missing_required_detection_classes:
        finding_reason_codes.append("required_detection_class_below_minimum")
        finding_passed = False

    finding_policy_gate = {
        "status": "pass" if finding_passed else "fail",
        "passed": finding_passed,
        "reason_codes": sorted(set(finding_reason_codes)),
        "policy_values": {
            "confirmed_min": int(confirmed_min),
            "candidate_max": int(candidate_max),
            "required_confirmed_classes": required_detection_classes,
            "required_class_confirmed_min": int(required_class_confirmed_min),
        },
        "actual_values": {
            "confirmed_count": confirmed_count,
            "candidate_count": candidate_count,
            "missing_required_detection_classes": missing_required_detection_classes,
        },
        "condition_logs": finding_condition_logs,
    }

    # --- Gate 4: Regression (NOT affected by allowed_missing) ---
    regression_gate = _evaluate_regression_gate(
        baseline_diff,
        regression_confirmed_delta_min=regression_confirmed_delta_min,
        regression_allow_dedup_reduction=regression_allow_dedup_reduction,
    )

    # --- Gate 5: Submission ---
    submission_gate = {
        "status": "pass",
        "passed": True,
        "reason_codes": [],
        "policy_values": {"consistency_required": True},
        "actual_values": {"consistency_status": "consistent"},
        "condition_logs": [
            _make_condition_log(
                condition_id="consistency_check",
                policy_value="consistent",
                actual_value="consistent",
                comparison_operator="eq",
                individual_result="pass",
            )
        ],
    }

    # ── 6. Compute overall status (FAIL-CLOSED) ──
    gates = {
        "scenario_coverage": scenario_coverage_gate,
        "evidence_quality": evidence_quality_gate,
        "finding_policy": finding_policy_gate,
        "regression": regression_gate,
        "submission": submission_gate,
    }
    overall_status, overall_gate_passed, overall_reason_codes = _evaluate_gate_overall(gates)
    if baseline_reason_codes:
        overall_reason_codes = sorted(set(overall_reason_codes + baseline_reason_codes))

    # ── 7. Build required detection class eval (for report_metrics compat) ──
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
        cbc_for_eval = detection_class_summary_raw.get("confirmed_by_detection_class", {})
        if not isinstance(cbc_for_eval, dict):
            cbc_for_eval = {}
        scbc_for_eval = session_detection_class_summary.get("confirmed_by_detection_class", {})
        if not isinstance(scbc_for_eval, dict):
            scbc_for_eval = {}

        def _hybrid_eval_count(detection_class: str) -> int:
            return max(
                int(_safe_int(cbc_for_eval.get(detection_class)) or 0),
                int(_safe_int(scbc_for_eval.get(detection_class)) or 0),
            )

        cbc_backfill = detection_class_summary.get("confirmed_by_detection_class", {})
        if not isinstance(cbc_backfill, dict):
            cbc_backfill = {}
        required_detection_class_eval["class_confirmed_counts"] = {
            dc: _hybrid_eval_count(dc) for dc in required_detection_classes
        }
        required_detection_class_eval["class_confirmed_counts_with_backfill"] = {
            dc: int(_safe_int(cbc_backfill.get(dc)) or 0) for dc in required_detection_classes
        }

    # ── 8. Build recommended actions ──
    recommended_actions = _build_recommended_actions(
        status=overall_status,
        reason_codes=overall_reason_codes,
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

    # ── 9. Assemble result ──
    return {
        "status": overall_status,
        "gate_passed": overall_gate_passed,
        "reason_codes": overall_reason_codes,
        "gates": gates,
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
        "consistency": consistency,
        "report_metrics": {
            "actual_missing_scenarios": actual_missing,
            "unexpected_missing_scenarios": unexpected_missing,
            "family_gate": family_gate,
            "findings_summary": {
                "confirmed_count": confirmed_count,
                "candidate_count": candidate_count,
                "confirmed_poc_missing": confirmed_poc_missing,
                "reason_code_missing": reason_code_missing_val,
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
            "baseline_diff": baseline_diff,
        },
        "evaluation_context": {
            "comparison_mode": comparison_mode,
            "baseline_id": _build_baseline_id(baseline_report_resolved, baseline_session_resolved),
            "baseline_report_path": str(baseline_report_resolved.resolve()),
            "baseline_session_path": str(baseline_session_resolved.resolve()) if baseline_session_resolved is not None else None,
        },
        "deferred_scenarios": deferred_scenarios,
        "recommended_actions": recommended_actions,
        "suggested_next_step": (
            "Initial-release gate passed. Continue with release workflow."
            if overall_gate_passed
            else "Address reason_codes (or update policy) and re-run gate check."
        ),
    }


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
    """Backward-compatible wrapper for the initial-release quality gate.

    Delegates to evaluate_gate_separated() and returns the result without
    the ``gates`` key for backwards compatibility with existing callers.
    """
    result = evaluate_gate_separated(
        report_path=report_path,
        session_path=session_path,
        sessions_dir=sessions_dir,
        baseline_report_path=baseline_report_path,
        baseline_session_path=baseline_session_path,
        allowed_missing_scenarios=allowed_missing_scenarios,
        confirmed_min=confirmed_min,
        candidate_max=candidate_max,
        confirmed_poc_missing_max=confirmed_poc_missing_max,
        reason_code_missing_max=reason_code_missing_max,
        required_confirmed_classes=required_confirmed_classes,
        required_class_confirmed_min=required_class_confirmed_min,
        regression_confirmed_delta_min=0,
        regression_allow_dedup_reduction=True,
        schema_severity_critical_max=schema_severity_critical_max,
        schema_severity_high_max=schema_severity_high_max,
        schema_severity_enforcement_mode=schema_severity_enforcement_mode,
        schema_severity_soft_fail_missing_ratio=schema_severity_soft_fail_missing_ratio,
        schema_severity_soft_fail_missing_count=schema_severity_soft_fail_missing_count,
    )
    # Remove the 'gates' key for backward compatibility with the old schema
    result.pop("gates", None)
    return result
