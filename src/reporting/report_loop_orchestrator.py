from __future__ import annotations

from pathlib import Path
from typing import Any

from src.reporting.initial_release_gate import DEFAULT_ALLOWED_MISSING_SCENARIOS, evaluate_initial_release_gate
from src.reporting.report_session_consistency import verify_report_session_consistency
from src.reporting.session_finding_inspector import inspect_session_findings


def _normalize_status(value: Any) -> str:
    return str(value or "").strip().lower()


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        token = str(item or "").strip()
        if not token or token in seen:
            continue
        seen.add(token)
        ordered.append(token)
    return ordered


def _build_consistency_next_commands(
    report_path: Path,
    reason_codes: list[str],
) -> list[str]:
    report_arg = str(report_path.resolve())
    base_consistency = f"python3 scripts/shigoku_ops_cli.py --json report consistency --report {report_arg}"
    base_loop = f"python3 scripts/shigoku_ops_cli.py --json report loop --report {report_arg}"
    cmds = [base_consistency]
    reasons = {str(code or "").strip().lower() for code in reason_codes if str(code or "").strip()}

    if "report_not_found" in reasons:
        cmds.append("ls -l <absolute-path-to-haddix_report_*.md>")
    if "report_parse_failed" in reasons:
        cmds.append("python3 scripts/check_initial_release_gate.py --report <absolute-path-to-haddix_report_*.md>")
    if "sessions_dir_not_found" in reasons or "sessions_dir_not_resolved" in reasons:
        cmds.append(
            f"python3 scripts/shigoku_ops_cli.py --json session resolve-from-report --report {report_arg} --sessions-dir <abs-sessions-dir>"
        )
    if "session_not_found" in reasons or "source_session_not_found" in reasons or "explicit_session_not_found" in reasons:
        cmds.append(
            f"python3 scripts/shigoku_ops_cli.py --json session resolve-from-report --report {report_arg} --session <abs-session_*.json>"
        )
    if "session_parse_failed" in reasons:
        cmds.append("python3 -m json.tool <abs-session_*.json> >/dev/null")
    if "scenario_coverage_count_mismatch" in reasons or "scenario_missing_set_mismatch" in reasons:
        cmds.append(base_loop)

    return _dedupe_keep_order(cmds)


def _build_gate_next_commands(
    report_path: Path,
    reason_codes: list[str],
    gate: dict[str, Any],
) -> list[str]:
    report_arg = str(report_path.resolve())
    cmds = [
        f"python3 scripts/shigoku_ops_cli.py --json report gate --report {report_arg}",
        f"python3 scripts/shigoku_ops_cli.py --json report loop --report {report_arg} --include-findings --finding-preset triage --max-findings 20",
    ]
    reasons = {str(code or "").strip().lower() for code in reason_codes if str(code or "").strip()}

    if "reason_code_missing_above_maximum" in reasons or "reason_code_missing_not_found" in reasons:
        cmds.append(
            f"python3 scripts/shigoku_ops_cli.py --json report gate --report {report_arg} --reason-code-missing-max 0"
        )
    if "required_detection_class_below_minimum" in reasons:
        cmds.append(
            f"python3 scripts/shigoku_ops_cli.py --json report gate --report {report_arg} --required-class-confirmed-min 1"
        )
    if "unexpected_missing_scenarios" in reasons:
        allowed_missing_arg = ",".join(DEFAULT_ALLOWED_MISSING_SCENARIOS)
        cmds.append(
            f"python3 scripts/shigoku_ops_cli.py --json report gate --report {report_arg} --allowed-missing {allowed_missing_arg}"
        )
    if "consistency_blocked" in reasons or "consistency_inconsistent" in reasons:
        cmds.append(
            f"python3 scripts/shigoku_ops_cli.py --json report consistency --report {report_arg}"
        )

    recommended_actions = gate.get("recommended_actions", [])
    if isinstance(recommended_actions, list):
        for action in recommended_actions:
            if not isinstance(action, dict):
                continue
            command = str(action.get("command", "") or "").strip()
            if command:
                cmds.append(command)

    return _dedupe_keep_order(cmds)


def run_report_loop(
    report_path: str | Path,
    *,
    session_path: str | Path | None = None,
    sessions_dir: str | Path | None = None,
    include_findings: bool = False,
    max_findings: int | None = None,
    finding_fields: list[str] | None = None,
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
    report_file = Path(report_path)
    explicit_session = Path(session_path) if session_path else None
    explicit_sessions_dir = Path(sessions_dir) if sessions_dir else None

    stages: list[dict[str, Any]] = []
    consistency = verify_report_session_consistency(
        report_file,
        session_path=explicit_session,
        sessions_dir=explicit_sessions_dir,
    )
    consistency_status = _normalize_status(consistency.get("status"))
    stages.append(
        {
            "name": "consistency",
            "status": consistency_status or "blocked",
            "result": consistency,
        }
    )

    if consistency_status == "blocked":
        reason_codes = consistency.get("reason_codes", [])
        return {
            "status": "blocked",
            "stages": stages,
            "reason_codes": reason_codes,
            "suggested_next_step": consistency.get("suggested_next_step"),
            "next_commands": _build_consistency_next_commands(report_file, reason_codes),
        }

    resolved_session_path = None
    session_meta = consistency.get("session")
    if isinstance(session_meta, dict):
        resolved_session_path = session_meta.get("path")

    gate = evaluate_initial_release_gate(
        report_file,
        session_path=Path(str(resolved_session_path)) if resolved_session_path else explicit_session,
        sessions_dir=explicit_sessions_dir,
        allowed_missing_scenarios=allowed_missing_scenarios or [],
        confirmed_min=max(0, int(confirmed_min)),
        candidate_max=max(0, int(candidate_max)),
        confirmed_poc_missing_max=max(0, int(confirmed_poc_missing_max)),
        reason_code_missing_max=max(0, int(reason_code_missing_max)),
        required_confirmed_classes=required_confirmed_classes or [],
        required_class_confirmed_min=max(0, int(required_class_confirmed_min)),
        schema_severity_critical_max=max(0, int(schema_severity_critical_max)),
        schema_severity_high_max=max(0, int(schema_severity_high_max)),
        schema_severity_enforcement_mode=str(schema_severity_enforcement_mode or "warn"),
        schema_severity_soft_fail_missing_ratio=max(0.0, float(schema_severity_soft_fail_missing_ratio)),
        schema_severity_soft_fail_missing_count=max(0, int(schema_severity_soft_fail_missing_count)),
    )
    gate_status = _normalize_status(gate.get("status"))
    stages.append(
        {
            "name": "gate",
            "status": gate_status or "blocked",
            "result": gate,
        }
    )

    if include_findings and resolved_session_path:
        findings_summary = inspect_session_findings(
            Path(str(resolved_session_path)),
            max_findings=max_findings,
            finding_fields=finding_fields,
        )
        stages.append(
            {
                "name": "findings",
                "status": "ok",
                "result": findings_summary,
            }
        )

    if consistency_status == "inconsistent":
        final_status = "failed"
    elif gate_status == "fail":
        final_status = "failed"
    elif gate_status == "blocked":
        final_status = "blocked"
    elif gate_status == "pass":
        final_status = "ok"
    else:
        final_status = "blocked"

    reason_codes = gate.get("reason_codes", [])
    result = {
        "status": final_status,
        "stages": stages,
        "reason_codes": reason_codes,
        "suggested_next_step": gate.get("suggested_next_step"),
    }
    if final_status in {"failed", "blocked"}:
        result["next_commands"] = _build_gate_next_commands(report_file, reason_codes, gate)
    return result
