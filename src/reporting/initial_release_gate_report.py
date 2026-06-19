from __future__ import annotations

import re
from typing import Any

from src.reporting.initial_release_gate_policy import _normalize_tokens

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
