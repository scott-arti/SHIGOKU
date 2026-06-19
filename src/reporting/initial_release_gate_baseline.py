from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Any

from src.reporting.initial_release_gate_policy import (
    _normalize_tokens,
    _safe_int,
)
from src.reporting.report_session_consistency import verify_report_session_consistency

_BASELINE_LOCK_FILENAME = "quality_baseline_lock.json"


def _build_baseline_id(report_path: Path | None, session_path: Path | None) -> str | None:
    if report_path is None or session_path is None:
        return None
    token = f"{str(report_path.resolve())}::{str(session_path.resolve())}"
    digest = hashlib.sha1(token.encode("utf-8")).hexdigest()[:12]
    return f"baseline_{digest}"


def _metric_delta(current: Any, baseline: Any) -> int | None:
    current_num = _safe_int(current)
    baseline_num = _safe_int(baseline)
    if current_num is None or baseline_num is None:
        return None
    return current_num - baseline_num


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
