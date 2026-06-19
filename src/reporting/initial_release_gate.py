from __future__ import annotations

from pathlib import Path
from typing import Any

from src.reporting.initial_release_gate_actions import _build_deferred_scenarios, _build_recommended_actions
from src.reporting.initial_release_gate_baseline import (
    _build_baseline_diff,
    _build_baseline_id,
    _load_baseline_lock,
    _write_baseline_lock,
    set_locked_baseline,
)
from src.reporting.initial_release_gate_policy import (
    DEFAULT_ALLOWED_MISSING_SCENARIOS,
    DEFAULT_REQUIRED_CONFIRMED_CLASSES,
    _build_policy_notes,
    _normalize_required_detection_classes,
    _normalize_tokens,
    _safe_int,
)
from src.reporting.initial_release_gate_report import (
    _parse_family_gate,
    _parse_findings_class_summary,
    _parse_findings_quality_summary,
    _parse_findings_summary,
)
from src.reporting.initial_release_gate_session import (
    _build_detection_class_summary,
    _build_scenario_detection_backfill,
    _build_session_detection_class_summary,
    _build_session_findings_summary,
    _build_session_schema_severity_summary,
    _load_session_scenario_coverage,
    _merge_detection_class_summary_with_scenario_backfill,
)
from src.reporting.report_session_consistency import verify_report_session_consistency

__all__ = [
    "DEFAULT_ALLOWED_MISSING_SCENARIOS",
    "DEFAULT_REQUIRED_CONFIRMED_CLASSES",
    "evaluate_initial_release_gate",
    "set_locked_baseline",
]


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
