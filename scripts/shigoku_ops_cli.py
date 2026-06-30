#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.initial_release_gate import (  # noqa: E402
    DEFAULT_ALLOWED_MISSING_SCENARIOS,
    DEFAULT_REQUIRED_CONFIRMED_CLASSES,
    evaluate_initial_release_gate,
    set_locked_baseline,
)
from src.reporting.report_session_consistency import verify_report_session_consistency  # noqa: E402
from src.reporting.report_loop_orchestrator import run_report_loop  # noqa: E402
from src.reporting.session_finding_inspector import inspect_session_findings  # noqa: E402
from src.reporting.runtime_control_release_gate import evaluate_gate_evidence_bundle  # noqa: E402
from src.reporting.run_narrative_formatter import RunNarrativeFormatter  # noqa: E402
from src.reporting.target_profile_formatter import TargetProfileFormatter  # noqa: E402
from src.reporting.attack_path_formatter import AttackPathFormatter  # noqa: E402
from src.core.observability.phase1_contracts import (  # noqa: E402
    REQUIRED_OBSERVABILITY_FIELDS,
    evaluate_minimum_sample_size,
    generate_correlation_ids,
    validate_event_required_fields,
)
from src.core.observability.phase2_classification import (  # noqa: E402
    classify_failure_pattern,
    classify_schema_mismatch_severity,
)
from src.core.observability.flaky_quarantine import (  # noqa: E402
    FlakyQuarantinePolicy,
    FlakyQuarantineTracker,
)


VALIDATION_SUITES: dict[str, list[str]] = {
    "report": [
        "tests/unit/reporting/test_report_session_consistency.py",
        "tests/unit/reporting/test_run_narrative_formatter.py",
        "tests/unit/reporting/test_target_profile_formatter.py",
        "tests/unit/reporting/test_attack_path_formatter.py",
        "tests/unit/main/test_main_report_haddix.py",
    ],
    "session": [
        "tests/unit/reporting/test_session_finding_inspector.py",
    ],
    "ops_cli": [
        "tests/unit/scripts/test_shigoku_ops_cli.py",
    ],
    "runtime_control": [
        "tests/unit/reporting/test_runtime_control_release_gate.py",
        "tests/unit/scripts/test_shigoku_ops_cli.py",
    ],
    "report_loop": [
        "tests/unit/reporting/test_report_session_consistency.py",
        "tests/unit/reporting/test_initial_release_gate.py",
        "tests/unit/reporting/test_session_finding_inspector.py",
        "tests/unit/scripts/test_shigoku_ops_cli.py",
    ],
    "phase1_smoke": [
        "tests/core/engine/test_master_conductor_recipe_contracts.py",
        "tests/core/agents/swarm/test_discovery_graphql_contract.py",
        "tests/unit/scripts/test_shigoku_ops_cli.py",
    ],
    "phase_e2_minimal": [
        "tests/core/adapters/external/test_external_tool_executor.py::test_execute_returns_error_result_on_unhandled_exception",
        "tests/core/adapters/external/test_ai_integration.py::TestScannerSwarmIntegration::test_swarm_registers_all_external_tools",
        "tests/core/adapters/external/test_ai_integration.py::TestExternalToolExecutorIntegration::test_executor_config_out_of_range_env",
        "tests/unit/agents/swarm/test_scanner.py::TestScannerSwarm::test_port_scan_specialist",
        "tests/unit/agents/swarm/test_fuzzing.py::TestDirBruteSpecialist::test_ffuf_execution",
        "tests/unit/agents/swarm/test_fuzzing.py::TestDirBruteSpecialist::test_native_fallback",
        "tests/unit/commands/test_monitoring_dashboard.py::test_alerts_use_avg_waiting_time_ms_key",
    ],
}

FINDING_FIELD_PRESETS: dict[str, list[str] | None] = {
    "minimal": ["title", "target_url"],
    "triage": [
        "title",
        "target_url",
        "vuln_type",
        "detection_class",
        "verification_required",
        "heuristic_candidate",
    ],
    "full": None,
}


def _parse_csv_tokens(raw: str) -> list[str]:
    tokens = [str(token or "").strip() for token in str(raw or "").split(",")]
    return [token for token in tokens if token]


def _status_exit_code(status: Any, ok: str, fail: str) -> int:
    token = str(status or "").strip().lower()
    if token == ok:
        return 0
    if token == fail:
        return 3
    return 2


def _resolve_finding_fields(
    finding_fields_raw: str | None,
    finding_preset: str | None,
) -> list[str] | None:
    explicit_fields = _parse_csv_tokens(finding_fields_raw or "")
    if explicit_fields:
        return explicit_fields
    preset_key = str(finding_preset or "").strip().lower()
    if not preset_key:
        return None
    return FINDING_FIELD_PRESETS.get(preset_key)


def _wrap_agent_payload(payload: dict[str, Any], *, command: str) -> dict[str, Any]:
    return {
        "schema_version": "shigoku.ops.v1",
        "command": command,
        "payload": payload,
    }


def _emit_payload(payload: dict[str, Any], output_json: bool) -> None:
    if output_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    for key, value in payload.items():
        if isinstance(value, (dict, list)):
            print(f"{key}: {json.dumps(value, ensure_ascii=False)}")
        else:
            print(f"{key}: {value}")


def _emit_command_payload(args: argparse.Namespace, payload: dict[str, Any]) -> None:
    output_json = bool(getattr(args, "json", False))
    if output_json and bool(getattr(args, "json_envelope", False)):
        domain = str(getattr(args, "domain", "") or "").strip()
        action = str(getattr(args, "action", "") or "").strip()
        command = f"{domain}.{action}" if domain and action else action or domain or "unknown"
        _emit_payload(_wrap_agent_payload(payload, command=command), output_json=True)
        return
    _emit_payload(payload, output_json=output_json)


def _run_report_consistency(args: argparse.Namespace) -> int:
    verdict = verify_report_session_consistency(
        Path(args.report),
        session_path=Path(args.session) if args.session else None,
        sessions_dir=Path(args.sessions_dir) if args.sessions_dir else None,
    )
    _emit_command_payload(args, verdict)
    return _status_exit_code(verdict.get("status"), ok="consistent", fail="inconsistent")


def _run_report_gate(args: argparse.Namespace) -> int:
    if args.set_locked_baseline:
        result = set_locked_baseline(
            Path(args.report),
            session_path=Path(args.session) if args.session else None,
            sessions_dir=Path(args.sessions_dir) if args.sessions_dir else None,
        )
        _emit_command_payload(args, result)
        return 0 if bool(result.get("updated", False)) else 2

    allowed_missing = _parse_csv_tokens(args.allowed_missing)
    required_confirmed_classes = _parse_csv_tokens(args.required_confirmed_classes)
    verdict = evaluate_initial_release_gate(
        Path(args.report),
        session_path=Path(args.session) if args.session else None,
        sessions_dir=Path(args.sessions_dir) if args.sessions_dir else None,
        baseline_report_path=Path(args.baseline_report) if args.baseline_report else None,
        baseline_session_path=Path(args.baseline_session) if args.baseline_session else None,
        allowed_missing_scenarios=allowed_missing,
        confirmed_min=max(0, int(args.confirmed_min)),
        candidate_max=max(0, int(args.candidate_max)),
        confirmed_poc_missing_max=max(0, int(args.confirmed_poc_missing_max)),
        reason_code_missing_max=max(0, int(args.reason_code_missing_max)),
        required_confirmed_classes=required_confirmed_classes,
        required_class_confirmed_min=max(0, int(args.required_class_confirmed_min)),
        schema_severity_critical_max=max(0, int(args.schema_severity_critical_max)),
        schema_severity_high_max=max(0, int(args.schema_severity_high_max)),
        schema_severity_enforcement_mode=str(args.schema_severity_enforcement_mode or "warn"),
        schema_severity_soft_fail_missing_ratio=max(0.0, float(args.schema_severity_soft_fail_missing_ratio)),
        schema_severity_soft_fail_missing_count=max(0, int(args.schema_severity_soft_fail_missing_count)),
    )
    _emit_command_payload(args, verdict)
    return _status_exit_code(verdict.get("status"), ok="pass", fail="fail")


def _run_report_loop(args: argparse.Namespace) -> int:
    finding_fields = _resolve_finding_fields(
        args.finding_fields,
        getattr(args, "finding_preset", None),
    )
    allowed_missing = _parse_csv_tokens(args.allowed_missing)
    required_confirmed_classes = _parse_csv_tokens(args.required_confirmed_classes)
    payload = run_report_loop(
        Path(args.report),
        session_path=Path(args.session) if args.session else None,
        sessions_dir=Path(args.sessions_dir) if args.sessions_dir else None,
        include_findings=bool(args.include_findings),
        max_findings=args.max_findings,
        finding_fields=finding_fields,
        allowed_missing_scenarios=allowed_missing,
        confirmed_min=max(0, int(args.confirmed_min)),
        candidate_max=max(0, int(args.candidate_max)),
        confirmed_poc_missing_max=max(0, int(args.confirmed_poc_missing_max)),
        reason_code_missing_max=max(0, int(args.reason_code_missing_max)),
        required_confirmed_classes=required_confirmed_classes,
        required_class_confirmed_min=max(0, int(args.required_class_confirmed_min)),
        schema_severity_critical_max=max(0, int(args.schema_severity_critical_max)),
        schema_severity_high_max=max(0, int(args.schema_severity_high_max)),
        schema_severity_enforcement_mode=str(args.schema_severity_enforcement_mode or "warn"),
        schema_severity_soft_fail_missing_ratio=max(0.0, float(args.schema_severity_soft_fail_missing_ratio)),
        schema_severity_soft_fail_missing_count=max(0, int(args.schema_severity_soft_fail_missing_count)),
    )
    _emit_command_payload(args, payload)

    status = str(payload.get("status", "") or "").strip().lower()
    if status == "ok":
        return 0
    if status == "failed":
        return 3
    return 2


def _resolve_session_from_args(
    args: argparse.Namespace,
) -> tuple[dict | None, str | None, list[str]]:
    """Resolve session data from --session or --report arguments.

    Returns:
        (session_data, consistency_status, reason_codes)

        - session_data: parsed session JSON dict, or None
        - consistency_status: None if --session used directly; otherwise
          the verdict status ("consistent", "inconsistent", "blocked", ...)
        - reason_codes: list of reason codes (empty for direct --session)
    """
    import json as _json

    if args.session:
        session_path = Path(args.session).expanduser().resolve()
        if not session_path.exists():
            return (None, None, [])
        try:
            return (
                _json.loads(session_path.read_text(encoding="utf-8")),
                None,
                [],
            )
        except Exception:
            return (None, None, [])

    if args.report:
        consistency = verify_report_session_consistency(
            Path(args.report),
            session_path=Path(args.session) if args.session else None,
            sessions_dir=Path(args.sessions_dir) if args.sessions_dir else None,
        )
        status = consistency.get("status")
        reason_codes = list(consistency.get("reason_codes", []))

        session_info = consistency.get("session", {})
        if isinstance(session_info, dict):
            resolved_path = session_info.get("path")
            if resolved_path:
                try:
                    return (
                        _json.loads(Path(resolved_path).read_text(encoding="utf-8")),
                        status,
                        reason_codes,
                    )
                except Exception:
                    return (None, status, reason_codes + ["session_parse_failed"])
        # No session path resolved
        return (None, status, reason_codes)

    return (None, None, [])


def _run_report_narrative(args: argparse.Namespace) -> int:
    session_data, consistency_status, reason_codes = _resolve_session_from_args(args)

    if session_data is None:
        payload: dict[str, Any] = {
            "status": "blocked",
            "reason_codes": reason_codes
            if reason_codes
            else ["session_not_resolved"],
            "hint": "Provide --session or a valid --report path.",
        }
        _emit_command_payload(args, payload)
        return 2

    # Block if consistency status is explicitly set and not "consistent"
    if consistency_status is not None and consistency_status != "consistent":
        payload = {
            "status": "blocked",
            "reason_codes": reason_codes,
            "hint": (
                "Report-session consistency check failed. "
                "Use --session directly if you want to force generation, "
                "or rerun the scan to produce a consistent report."
            ),
        }
        _emit_command_payload(args, payload)
        return 2

    formatter = RunNarrativeFormatter()
    markdown = formatter.format(session_data)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(markdown, encoding="utf-8")
        payload = {"status": "ok", "output": str(output_path)}
    else:
        output_json = bool(getattr(args, "json", False))
        if output_json:
            payload = {"status": "ok", "output": "stdout", "markdown": markdown}
        else:
            print(markdown)
            payload = {"status": "ok", "output": "stdout"}
    _emit_command_payload(args, payload)
    return 0


def _run_report_target_profile(args: argparse.Namespace) -> int:
    session_data, consistency_status, reason_codes = _resolve_session_from_args(args)

    if session_data is None:
        payload: dict[str, Any] = {
            "status": "blocked",
            "reason_codes": reason_codes
            if reason_codes
            else ["session_not_resolved"],
            "hint": "Provide --session or a valid --report path.",
        }
        _emit_command_payload(args, payload)
        return 2

    # Block if consistency status is explicitly set and not "consistent"
    if consistency_status is not None and consistency_status != "consistent":
        payload = {
            "status": "blocked",
            "reason_codes": reason_codes,
            "hint": (
                "Report-session consistency check failed. "
                "Use --session directly if you want to force generation, "
                "or rerun the scan to produce a consistent report."
            ),
        }
        _emit_command_payload(args, payload)
        return 2

    formatter = TargetProfileFormatter()
    markdown = formatter.format(session_data)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(markdown, encoding="utf-8")
        payload = {"status": "ok", "output": str(output_path)}
    else:
        output_json = bool(getattr(args, "json", False))
        if output_json:
            payload = {"status": "ok", "output": "stdout", "markdown": markdown}
        else:
            print(markdown)
            payload = {"status": "ok", "output": "stdout"}
    _emit_command_payload(args, payload)
    return 0


def _run_report_attack_paths(args: argparse.Namespace) -> int:
    """Generate attack_paths.md Markdown + optional attack_paths.json from session data."""
    session_data, consistency_status, reason_codes = _resolve_session_from_args(args)

    if session_data is None:
        payload: dict[str, Any] = {
            "status": "blocked",
            "reason_codes": reason_codes
            if reason_codes
            else ["session_not_resolved"],
            "hint": "Provide --session or a valid --report path.",
        }
        _emit_command_payload(args, payload)
        return 2

    # Block if consistency status is explicitly set and not "consistent"
    if consistency_status is not None and consistency_status != "consistent":
        payload = {
            "status": "blocked",
            "reason_codes": reason_codes,
            "hint": (
                "Report-session consistency check failed. "
                "Use --session directly if you want to force generation, "
                "or rerun the scan to produce a consistent report."
            ),
        }
        _emit_command_payload(args, payload)
        return 2

    # Load reporting config from shigoku.yaml if available
    config = _load_attack_paths_config()

    formatter = AttackPathFormatter(config=config)
    markdown = formatter.format(session_data)

    output_path = None
    payload: dict[str, Any]
    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(markdown, encoding="utf-8")
        payload = {"status": "ok", "output": str(output_path)}
    elif args.output_dir:
        output_dir = Path(args.output_dir).expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        # Derive filename from session id or fallback timestamp
        session_id = str(session_data.get("session_id", "unknown"))
        safe_id = re.sub(r"[^a-zA-Z0-9._-]", "_", session_id)
        output_path = output_dir / f"attack_paths_{safe_id}.md"
        output_path.write_text(markdown, encoding="utf-8")
        payload = {"status": "ok", "output": str(output_path)}
    else:
        output_json = bool(getattr(args, "json", False))
        if output_json:
            payload = {"status": "ok", "output": "stdout", "markdown": markdown}
        else:
            print(markdown)
            payload = {"status": "ok", "output": "stdout"}

    if output_path is not None and args.json_output:
        json_path = output_path.with_suffix(".json")
        formatter.export_json(session_data, json_path)
        payload["json_output"] = str(json_path)

    _emit_command_payload(args, payload)
    return 0


def _load_attack_paths_config() -> dict | None:
    """Load reporting.attack_paths config from config/shigoku.yaml."""
    try:
        import yaml as _yaml  # noqa: F811
    except ImportError:
        return None
    config_path = PROJECT_ROOT / "config" / "shigoku.yaml"
    if not config_path.exists():
        return None
    try:
        with open(config_path, encoding="utf-8") as fh:
            cfg = _yaml.safe_load(fh)
    except Exception:
        return None
    if not isinstance(cfg, dict):
        return None
    reporting = cfg.get("reporting")
    if not isinstance(reporting, dict):
        return None
    return reporting.get("attack_paths")


def _run_session_findings(args: argparse.Namespace) -> int:
    finding_fields = _resolve_finding_fields(
        args.finding_fields,
        getattr(args, "finding_preset", None),
    )
    summary = inspect_session_findings(
        Path(args.session),
        detection_class=args.detection_class,
        max_findings=args.max_findings,
        finding_fields=finding_fields,
    )
    _emit_command_payload(args, summary)
    return 0


def _run_session_resolve_from_report(args: argparse.Namespace) -> int:
    verdict = verify_report_session_consistency(
        Path(args.report),
        session_path=Path(args.session) if args.session else None,
        sessions_dir=Path(args.sessions_dir) if args.sessions_dir else None,
    )

    session_info = verdict.get("session", {}) if isinstance(verdict.get("session"), dict) else {}
    resolved_path = str(session_info.get("path", "") or "").strip()
    payload = {
        "status": verdict.get("status"),
        "rerun_required": bool(verdict.get("rerun_required", False)),
        "reason_codes": verdict.get("reason_codes", []),
        "report_path": str((Path(args.report).expanduser().resolve())),
        "session_path": resolved_path or None,
        "session_selection": session_info.get("selection"),
        "suggested_next_step": verdict.get("suggested_next_step"),
    }
    _emit_command_payload(args, payload)

    if not resolved_path:
        return 2
    return 0


def _resolve_python_bin(preferred: str | None) -> str:
    if preferred:
        return preferred

    venv_python = PROJECT_ROOT / ".venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)
    return "python3"


def _run_validate_pytest(args: argparse.Namespace) -> int:
    selected_tests: list[str] = []
    for suite_name in args.suite or []:
        selected_tests.extend(VALIDATION_SUITES.get(str(suite_name), []))
    selected_tests.extend(args.test or [])

    if not selected_tests:
        error_payload = {
            "status": "blocked",
            "reason": "no_tests_selected",
            "hint": "Pass --suite and/or --test.",
            "available_suites": sorted(VALIDATION_SUITES.keys()),
        }
        _emit_command_payload(args, error_payload)
        return 2

    python_bin = _resolve_python_bin(args.python)
    cmd: list[str] = [python_bin, "-m", "pytest"]
    if args.quiet:
        cmd.append("-q")
    if args.fail_fast:
        cmd.append("-x")
    cmd.extend(selected_tests)

    if args.dry_run:
        payload = {
            "status": "dry_run",
            "cwd": str(PROJECT_ROOT),
            "command": cmd,
            "command_shell": shlex.join(cmd),
            "selected_tests": selected_tests,
        }
        _emit_command_payload(args, payload)
        return 0

    result = subprocess.run(
        cmd,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    payload = {
        "status": "ok" if result.returncode == 0 else "failed",
        "cwd": str(PROJECT_ROOT),
        "command": cmd,
        "command_shell": shlex.join(cmd),
        "selected_tests": selected_tests,
        "returncode": int(result.returncode),
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    _emit_command_payload(args, payload)
    return int(result.returncode)


def _run_phase1_correlation_ids(args: argparse.Namespace) -> int:
    payload = {
        "status": "ok",
        "correlation": generate_correlation_ids(build_id=args.build_id),
    }
    _emit_command_payload(args, payload)
    return 0


def _run_phase1_check_event(args: argparse.Namespace) -> int:
    event = json.loads(args.event_json)
    verdict = validate_event_required_fields(event)
    payload = {
        "status": verdict["status"],
        "required_fields": list(REQUIRED_OBSERVABILITY_FIELDS),
        **verdict,
    }
    _emit_command_payload(args, payload)
    return 0 if verdict["status"] == "ok" else 3


def _run_phase1_sample_guard(args: argparse.Namespace) -> int:
    verdict = evaluate_minimum_sample_size(args.sample_size, args.minimum_sample_size)
    _emit_command_payload(args, verdict)
    return 0 if verdict["status"] == "ok" else 3


def _run_phase1_runbook(args: argparse.Namespace) -> int:
    request_id = str(args.request_id or "").strip()
    endpoint = str(args.endpoint or "").strip()
    payload = {
        "status": "ok",
        "runbook": {
            "step_1": f"アラート確認: type={args.alert_type}, severity={args.severity}",
            "step_2": f"request_id でログ抽出: rg -n '{request_id}' logs/ -S",
            "step_3": f"主要項目照合: endpoint='{endpoint}', timeout_ms/error_type/retry_count を確認",
            "step_4": "最小再現入力で再現: fixture + payload + seed + clock を使用",
            "step_5": "回避策/恒久対策を記録し、再発防止テストIDをチケットへ添付",
        },
    }
    _emit_command_payload(args, payload)
    return 0


def _run_phase2_classify_failure(args: argparse.Namespace) -> int:
    category = classify_failure_pattern(reason_code=args.reason_code, error_message=args.error_message)
    _emit_command_payload(
        args,
        {
            "status": "ok",
            "reason_code": args.reason_code,
            "error_message": args.error_message,
            "failure_category": category,
        },
    )
    return 0


def _run_phase2_schema_severity(args: argparse.Namespace) -> int:
    verdict = classify_schema_mismatch_severity(
        added=args.added,
        removed=args.removed,
        type_changed=args.type_changed,
        nullability_changed=args.nullability_changed,
        missing_required_fields=args.missing_required_fields,
    )
    _emit_command_payload(args, {"status": "ok", **verdict})
    return 0


def _run_phase2_flaky_evaluate(args: argparse.Namespace) -> int:
    tracker = FlakyQuarantineTracker(
        policy=FlakyQuarantinePolicy(
            window_size=args.window_size,
            min_failures=args.min_failures,
        )
    )
    for token in [x.strip().lower() for x in str(args.outcomes_csv or "").split(",") if x.strip()]:
        tracker.record(success=token in {"ok", "success", "pass", "passed", "1", "true"})
    verdict = tracker.evaluate()
    _emit_command_payload(args, verdict)
    return 0 if verdict["status"] == "ok" else 3


def _run_runtime_control_gate(args: argparse.Namespace) -> int:
    evidence_path = Path(args.evidence_file).expanduser().resolve()
    if not evidence_path.exists():
        payload = {
            "status": "blocked",
            "decision": "hold",
            "reason_codes": ["runtime_control_evidence_missing"],
            "evidence_file": str(evidence_path),
        }
        _emit_command_payload(args, payload)
        return 2

    try:
        payload_obj = json.loads(evidence_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        payload = {
            "status": "blocked",
            "decision": "hold",
            "reason_codes": ["runtime_control_evidence_invalid_json"],
            "evidence_file": str(evidence_path),
        }
        _emit_command_payload(args, payload)
        return 2

    records = payload_obj if isinstance(payload_obj, list) else payload_obj.get("gate_evidence_records", [])
    if not isinstance(records, list):
        payload = {
            "status": "blocked",
            "decision": "hold",
            "reason_codes": ["runtime_control_evidence_invalid_schema"],
            "evidence_file": str(evidence_path),
        }
        _emit_command_payload(args, payload)
        return 2

    reason_codes: list[str] = []
    if args.integrity_manifest:
        manifest_path = Path(args.integrity_manifest).expanduser().resolve()
        if not manifest_path.exists():
            reason_codes.append("runtime_control_integrity_manifest_missing")
        else:
            try:
                manifest_obj = json.loads(manifest_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                reason_codes.append("runtime_control_integrity_manifest_invalid_json")
            else:
                expected_sha = str(manifest_obj.get("gate_evidence_sha256", "") or "").strip().lower()
                if not expected_sha:
                    reason_codes.append("runtime_control_integrity_manifest_missing_sha256")
                actual_sha = hashlib.sha256(evidence_path.read_bytes()).hexdigest().lower()
                if expected_sha and expected_sha != actual_sha:
                    reason_codes.append("runtime_control_evidence_hash_mismatch")

    review_id_pattern = re.compile(r"^[^/\s]+/[^#\s]+#\d+:\d+$")
    if args.approval_evidence_file:
        approval_path = Path(args.approval_evidence_file).expanduser().resolve()
        if not approval_path.exists():
            reason_codes.append("approval_source_unavailable")
        else:
            try:
                approval_obj = json.loads(approval_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                reason_codes.append("approval_source_unavailable")
            else:
                approvals = approval_obj.get("approved_review_ids", [])
                if not isinstance(approvals, list):
                    reason_codes.append("approval_source_unavailable")
                else:
                    approved = {str(item).strip() for item in approvals if str(item).strip()}
                    required_count = int(approval_obj.get("required_approving_review_count", 0) or 0)
                    approved_count = int(approval_obj.get("approved_unique_count", len(approved)) or 0)
                    actual_require_code_owner_reviews = bool(approval_obj.get("require_code_owner_reviews", False))
                    expected_require_code_owner_reviews = bool(args.require_code_owner_reviews)
                    if required_count > 0 and approved_count < required_count:
                        reason_codes.append("approval_source_insufficient_approvals")
                    if expected_require_code_owner_reviews and not actual_require_code_owner_reviews:
                        reason_codes.append("approval_source_branch_protection_mismatch")
                    for record in records:
                        gate_name = str(record.get("gate_name", "") or "").strip().lower()
                        if gate_name in {"compatibility", "distributed_control", "fault_injection"}:
                            review_id = str(record.get("review_id", "") or "").strip()
                            if not review_id_pattern.fullmatch(review_id):
                                reason_codes.append("approval_source_invalid_review_id_format")
                                continue
                            if review_id not in approved:
                                reason_codes.append("approval_source_mismatch")

    critical_gate_names = _parse_csv_tokens(args.critical_gates)
    verdict = evaluate_gate_evidence_bundle(records, critical_gate_names=critical_gate_names)
    all_errors = list(verdict.errors) + reason_codes
    unique_errors = sorted(set(all_errors))
    is_valid = verdict.valid and not reason_codes
    output = {
        "status": "pass" if is_valid else "fail",
        "decision": "proceed" if is_valid else "hold",
        "critical_gate_names": critical_gate_names,
        "evidence_file": str(evidence_path),
        "record_count": len(records),
        "errors": unique_errors,
    }
    _emit_command_payload(args, output)
    return 0 if is_valid else 3


def _run_ops_secret_audit(args: argparse.Namespace) -> int:
    from scripts.audit_secrets import scan as _audit_scan

    config_dirs = list(args.config_dir) if args.config_dir else None
    findings = _audit_scan(
        config_dirs=config_dirs,
        max_age_days=args.max_age_days,
        project_root=args.project_root,
    )
    output = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "max_age_days": args.max_age_days,
        "total_findings": len(findings),
        "overdue_count": sum(1 for f in findings if f.get("overdue")),
        "expiry_unknown_count": sum(1 for f in findings if f.get("expiry_unknown")),
        "findings": findings,
    }
    _emit_command_payload(args, output)
    if args.exit_nonzero_on_findings and findings:
        return 1
    return 0


def _run_ops_learn_categories(args: argparse.Namespace) -> int:
    from collections import Counter
    from pathlib import Path as _Path

    log_file = _Path(args.log_file)
    if not log_file.exists():
        _emit_command_payload(args, {"error": f"log file not found: {log_file}", "entries": 0})
        return 2

    entries: list[dict] = []
    with log_file.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    url_counter: Counter = Counter(e.get("url", "") for e in entries if e.get("url"))
    top_n = args.top_n
    top_urls = [{"url": url, "count": cnt} for url, cnt in url_counter.most_common(top_n)]

    alert_counter: Counter = Counter(
        e.get("alert") for e in entries if e.get("alert")
    )

    output = {
        "log_file": str(log_file),
        "total_entries": len(entries),
        "unique_urls": len(url_counter),
        "alert_summary": dict(alert_counter),
        f"top_{top_n}_urls": top_urls,
    }
    _emit_command_payload(args, output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shigoku-ops",
        description=(
            "CLI-first utility for SHIGOKU report/session/validation workflows. "
            "Designed for agent-friendly command composition."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output.",
    )
    parser.add_argument(
        "--json-envelope",
        action="store_true",
        help="Wrap JSON output in stable envelope {schema_version, command, payload}.",
    )

    top = parser.add_subparsers(dest="domain", required=True)

    report_parser = top.add_parser("report", help="Report-related operations")
    report_sub = report_parser.add_subparsers(dest="action", required=True)

    report_consistency = report_sub.add_parser(
        "consistency",
        help="Verify consistency between a haddix report and source session.",
    )
    report_consistency.add_argument("--report", required=True, help="Path to haddix_report_*.md")
    report_consistency.add_argument("--session", help="Optional explicit session_*.json path")
    report_consistency.add_argument("--sessions-dir", help="Optional sessions directory path")
    report_consistency.set_defaults(handler=_run_report_consistency)

    report_gate = report_sub.add_parser(
        "gate",
        help="Evaluate initial-release gate for a haddix report.",
    )
    report_gate.add_argument("--report", required=True, help="Path to haddix_report_*.md")
    report_gate.add_argument("--session", help="Optional explicit session_*.json path")
    report_gate.add_argument("--sessions-dir", help="Optional sessions directory path")
    report_gate.add_argument("--baseline-report", help="Optional baseline report path")
    report_gate.add_argument("--baseline-session", help="Optional baseline session path")
    report_gate.add_argument(
        "--allowed-missing",
        default=",".join(DEFAULT_ALLOWED_MISSING_SCENARIOS),
        help="Comma-separated scenario IDs allowed to be missing.",
    )
    report_gate.add_argument("--confirmed-min", type=int, default=3)
    report_gate.add_argument("--candidate-max", type=int, default=2)
    report_gate.add_argument("--confirmed-poc-missing-max", type=int, default=0)
    report_gate.add_argument("--reason-code-missing-max", type=int, default=0)
    report_gate.add_argument(
        "--required-confirmed-classes",
        default=",".join(DEFAULT_REQUIRED_CONFIRMED_CLASSES),
        help="Comma-separated required detection classes.",
    )
    report_gate.add_argument("--required-class-confirmed-min", type=int, default=1)
    report_gate.add_argument("--schema-severity-critical-max", type=int, default=0)
    report_gate.add_argument("--schema-severity-high-max", type=int, default=0)
    report_gate.add_argument(
        "--schema-severity-enforcement-mode",
        choices=["warn", "soft-fail", "hard-fail"],
        default="warn",
    )
    report_gate.add_argument(
        "--schema-severity-soft-fail-missing-ratio",
        type=float,
        default=0.2,
    )
    report_gate.add_argument(
        "--schema-severity-soft-fail-missing-count",
        type=int,
        default=3,
    )
    report_gate.add_argument(
        "--set-locked-baseline",
        action="store_true",
        help="Update quality_baseline_lock.json for this report/session pair.",
    )
    report_gate.set_defaults(handler=_run_report_gate)

    report_loop = report_sub.add_parser(
        "loop",
        help="Run consistency -> gate -> findings(optional) for agent loops.",
    )
    report_loop.add_argument("--report", required=True, help="Path to haddix_report_*.md")
    report_loop.add_argument("--session", help="Optional explicit session_*.json path")
    report_loop.add_argument("--sessions-dir", help="Optional sessions directory path")
    report_loop.add_argument("--include-findings", action="store_true", help="Include findings stage.")
    report_loop.add_argument("--max-findings", type=int, help="Optional findings cap.")
    report_loop.add_argument("--finding-fields", help="Comma-separated finding fields projection.")
    report_loop.add_argument(
        "--finding-preset",
        choices=sorted(FINDING_FIELD_PRESETS.keys()),
        help=(
            "Finding field preset. Ignored when --finding-fields is provided. "
            "minimal=title,target_url; triage adds decision fields; full keeps all."
        ),
    )
    report_loop.add_argument(
        "--allowed-missing",
        default=",".join(DEFAULT_ALLOWED_MISSING_SCENARIOS),
        help="Comma-separated scenario IDs allowed to be missing.",
    )
    report_loop.add_argument("--confirmed-min", type=int, default=3)
    report_loop.add_argument("--candidate-max", type=int, default=2)
    report_loop.add_argument("--confirmed-poc-missing-max", type=int, default=0)
    report_loop.add_argument("--reason-code-missing-max", type=int, default=0)
    report_loop.add_argument(
        "--required-confirmed-classes",
        default=",".join(DEFAULT_REQUIRED_CONFIRMED_CLASSES),
        help="Comma-separated required detection classes.",
    )
    report_loop.add_argument("--required-class-confirmed-min", type=int, default=1)
    report_loop.add_argument("--schema-severity-critical-max", type=int, default=0)
    report_loop.add_argument("--schema-severity-high-max", type=int, default=0)
    report_loop.add_argument(
        "--schema-severity-enforcement-mode",
        choices=["warn", "soft-fail", "hard-fail"],
        default="warn",
    )
    report_loop.add_argument(
        "--schema-severity-soft-fail-missing-ratio",
        type=float,
        default=0.2,
    )
    report_loop.add_argument(
        "--schema-severity-soft-fail-missing-count",
        type=int,
        default=3,
    )
    report_loop.set_defaults(handler=_run_report_loop)

    report_narrative = report_sub.add_parser(
        "narrative",
        help="Generate a run_narrative.md Markdown report from a session.",
    )
    report_narrative.add_argument("--session", help="Path to session_*.json")
    report_narrative.add_argument("--report", help="Path to haddix_report_*.md (resolves source session)")
    report_narrative.add_argument("--sessions-dir", help="Optional sessions directory for --report resolution")
    report_narrative.add_argument("--output", help="Optional output file path (default: stdout)")
    report_narrative.set_defaults(handler=_run_report_narrative)

    report_target_profile = report_sub.add_parser(
        "target-profile",
        help="Generate a target_profile.md Markdown report from a session.",
    )
    report_target_profile.add_argument("--session", help="Path to session_*.json")
    report_target_profile.add_argument("--report", help="Path to haddix_report_*.md (resolves source session)")
    report_target_profile.add_argument("--sessions-dir", help="Optional sessions directory for --report resolution")
    report_target_profile.add_argument("--output", help="Optional output file path (default: stdout)")
    report_target_profile.set_defaults(handler=_run_report_target_profile)

    report_attack_paths = report_sub.add_parser(
        "attack-paths",
        help="Generate an attack_paths.md Markdown + Mermaid report from a session.",
    )
    report_attack_paths.add_argument("--session", help="Path to session_*.json")
    report_attack_paths.add_argument("--report", help="Path to haddix_report_*.md (resolves source session)")
    report_attack_paths.add_argument("--sessions-dir", help="Optional sessions directory for --report resolution")
    report_attack_paths.add_argument("--output", help="Optional output file path (default: stdout)")
    report_attack_paths.add_argument("--output-dir", help="Optional output directory (filename derived from session ID)")
    report_attack_paths.add_argument("--json-output", action="store_true", help="Also export attack_paths.json for Neo4j ingest")
    report_attack_paths.set_defaults(handler=_run_report_attack_paths)

    session_parser = top.add_parser("session", help="Session-related operations")
    session_sub = session_parser.add_subparsers(dest="action", required=True)

    session_findings = session_sub.add_parser(
        "findings",
        help="Inspect canonical findings from a session JSON.",
    )
    session_findings.add_argument("--session", required=True, help="Path to session_*.json")
    session_findings.add_argument("--detection-class", help="Optional detection class filter")
    session_findings.add_argument("--max-findings", type=int, help="Optional findings cap.")
    session_findings.add_argument("--finding-fields", help="Comma-separated finding fields projection.")
    session_findings.add_argument(
        "--finding-preset",
        choices=sorted(FINDING_FIELD_PRESETS.keys()),
        help=(
            "Finding field preset. Ignored when --finding-fields is provided. "
            "minimal=title,target_url; triage adds decision fields; full keeps all."
        ),
    )
    session_findings.set_defaults(handler=_run_session_findings)

    session_resolve = session_sub.add_parser(
        "resolve-from-report",
        help="Resolve source session path from a haddix report.",
    )
    session_resolve.add_argument("--report", required=True, help="Path to haddix_report_*.md")
    session_resolve.add_argument("--session", help="Optional explicit session_*.json path")
    session_resolve.add_argument("--sessions-dir", help="Optional sessions directory path")
    session_resolve.set_defaults(handler=_run_session_resolve_from_report)

    validate_parser = top.add_parser("validate", help="Validation helpers")
    validate_sub = validate_parser.add_subparsers(dest="action", required=True)

    validate_pytest = validate_sub.add_parser(
        "pytest",
        help="Run targeted pytest checks with stable JSON output.",
    )
    validate_pytest.add_argument(
        "--suite",
        action="append",
        choices=sorted(VALIDATION_SUITES.keys()),
        help="Named validation suite (repeatable).",
    )
    validate_pytest.add_argument(
        "--test",
        action="append",
        metavar="PATH_OR_NODEID",
        help="Additional pytest path/nodeid (repeatable).",
    )
    validate_pytest.add_argument("--python", help="Python executable for pytest run.")
    validate_pytest.add_argument("--fail-fast", action="store_true", help="Use pytest -x.")
    validate_pytest.add_argument("--quiet", action="store_true", help="Use pytest -q.")
    validate_pytest.add_argument("--dry-run", action="store_true", help="Print command without executing.")
    validate_pytest.set_defaults(handler=_run_validate_pytest)

    phase1_parser = top.add_parser("phase1", help="Phase 1 observability helpers")
    phase1_sub = phase1_parser.add_subparsers(dest="action", required=True)

    phase1_correlation = phase1_sub.add_parser("correlation-ids", help="Generate correlation IDs.")
    phase1_correlation.add_argument("--build-id", help="Optional explicit build_id.")
    phase1_correlation.set_defaults(handler=_run_phase1_correlation_ids)

    phase1_check_event = phase1_sub.add_parser(
        "check-event",
        help="Validate Phase1 required observability fields from JSON event.",
    )
    phase1_check_event.add_argument("--event-json", required=True, help="JSON string for one event.")
    phase1_check_event.set_defaults(handler=_run_phase1_check_event)

    phase1_sample_guard = phase1_sub.add_parser(
        "sample-guard",
        help="Evaluate minimum_sample_size gate.",
    )
    phase1_sample_guard.add_argument("--sample-size", type=int, required=True)
    phase1_sample_guard.add_argument("--minimum-sample-size", type=int, required=True)
    phase1_sample_guard.set_defaults(handler=_run_phase1_sample_guard)

    phase1_runbook = phase1_sub.add_parser(
        "runbook",
        help="Emit CLI-style Phase1 runbook steps.",
    )
    phase1_runbook.add_argument("--alert-type", default="timeout_rate")
    phase1_runbook.add_argument("--severity", default="high")
    phase1_runbook.add_argument("--request-id", required=True)
    phase1_runbook.add_argument("--endpoint", required=True)
    phase1_runbook.set_defaults(handler=_run_phase1_runbook)

    phase2_parser = top.add_parser("phase2", help="Phase 2 quality helpers")
    phase2_sub = phase2_parser.add_subparsers(dest="action", required=True)

    phase2_classify = phase2_sub.add_parser("classify-failure", help="Classify failure category.")
    phase2_classify.add_argument("--reason-code", default="")
    phase2_classify.add_argument("--error-message", default="")
    phase2_classify.set_defaults(handler=_run_phase2_classify_failure)

    phase2_schema = phase2_sub.add_parser("schema-severity", help="Classify schema mismatch severity.")
    phase2_schema.add_argument("--added", type=int, default=0)
    phase2_schema.add_argument("--removed", type=int, default=0)
    phase2_schema.add_argument("--type-changed", type=int, default=0)
    phase2_schema.add_argument("--nullability-changed", type=int, default=0)
    phase2_schema.add_argument("--missing-required-fields", type=int, default=0)
    phase2_schema.set_defaults(handler=_run_phase2_schema_severity)

    phase2_flaky = phase2_sub.add_parser("flaky-evaluate", help="Evaluate flaky quarantine decision.")
    phase2_flaky.add_argument("--outcomes-csv", required=True, help="Comma list: success/fail tokens.")
    phase2_flaky.add_argument("--window-size", type=int, default=20)
    phase2_flaky.add_argument("--min-failures", type=int, default=2)
    phase2_flaky.set_defaults(handler=_run_phase2_flaky_evaluate)

    runtime_control_parser = top.add_parser("runtime-control", help="Runtime control gate helpers")
    runtime_control_sub = runtime_control_parser.add_subparsers(dest="action", required=True)

    runtime_control_gate = runtime_control_sub.add_parser(
        "gate",
        help="Evaluate runtime control release gate evidence bundle.",
    )
    runtime_control_gate.add_argument(
        "--evidence-file",
        required=True,
        help="Path to gate evidence JSON (list or {gate_evidence_records:[...]}).",
    )
    runtime_control_gate.add_argument(
        "--critical-gates",
        default="compatibility,distributed_control,fault_injection",
        help="Comma-separated gate names that cannot be waived.",
    )
    runtime_control_gate.add_argument(
        "--integrity-manifest",
        help="Optional JSON manifest containing gate_evidence_sha256 for tamper detection.",
    )
    runtime_control_gate.add_argument(
        "--approval-evidence-file",
        help="Optional JSON source-of-truth approval evidence with approved_review_ids array.",
    )
    runtime_control_gate.add_argument(
        "--require-code-owner-reviews",
        action="store_true",
        default=False,
        help="Require branch protection evidence to enable code owner reviews.",
    )
    runtime_control_gate.set_defaults(handler=_run_runtime_control_gate)

    ops_parser = top.add_parser("ops", help="Operational hardening helpers")
    ops_sub = ops_parser.add_subparsers(dest="action", required=True)

    ops_secret_audit = ops_sub.add_parser(
        "secret-audit",
        help="Audit credential rotation age in config/ and .env files.",
    )
    ops_secret_audit.add_argument(
        "--max-age-days",
        type=int,
        default=90,
        help="Maximum allowed credential age in days (default: 90).",
    )
    ops_secret_audit.add_argument(
        "--config-dir",
        action="append",
        dest="config_dir",
        default=None,
        help="Config directory to scan (repeatable, default: config/).",
    )
    ops_secret_audit.add_argument(
        "--project-root",
        dest="project_root",
        default=None,
        help="Project root directory (default: cwd).",
    )
    ops_secret_audit.add_argument(
        "--exit-nonzero-on-findings",
        action="store_true",
        default=False,
        help="Exit with code 1 if any findings are detected.",
    )
    ops_secret_audit.set_defaults(handler=_run_ops_secret_audit, domain="ops", action="secret-audit")

    ops_learn = ops_sub.add_parser(
        "learn-categories",
        help="Summarize other_category_log.jsonl to surface top error-URL patterns.",
    )
    ops_learn.add_argument(
        "--log-file",
        required=True,
        help="Path to other_category_log.jsonl (e.g. workspace/projects/<id>/other_category_log.jsonl).",
    )
    ops_learn.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="Number of top URLs to surface (default: 10).",
    )
    ops_learn.set_defaults(handler=_run_ops_learn_categories, domain="ops", action="learn-categories")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 2
    return int(handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
