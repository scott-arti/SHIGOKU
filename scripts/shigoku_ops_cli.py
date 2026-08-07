#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
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
from src.reporting.expected_detection_matrix import (  # noqa: E402
    compare_expected_detections,
    compare_session_finding_sets,
)
from src.reporting.endpoint_extractor import (  # noqa: E402
    build_attack_target_bundle_from_findings,
    build_attack_target_bundle_from_session,
    extract_attack_targets_from_session,
    write_attack_target_artifacts,
)
from src.cli.intent_parser import (  # noqa: E402
    build_execution_preview,
    load_ops_intent_settings,
    parse_operator_intent,
)
from src.core.learning.findings_repository import FindingsRepository  # noqa: E402
from src.core.models.ops_artifacts import extract_host_from_url  # noqa: E402
from src.reporting.runtime_control_release_gate import evaluate_gate_evidence_bundle  # noqa: E402
from src.reporting.runtime_control_release_gate import evaluate_phase9_evidence_bundle  # noqa: E402
from src.reporting.vdp_diagnostic import (  # noqa: E402
    COVERAGE_NOTE,
    analyze_observed_lineages,
)
from src.reporting.run_narrative_formatter import RunNarrativeFormatter  # noqa: E402
from src.reporting.target_profile_formatter import TargetProfileFormatter  # noqa: E402
from src.reporting.attack_path_formatter import AttackPathFormatter  # noqa: E402
from src.reporting.attack_review_formatter import format_attack_review  # noqa: E402
from src.core.knowledge.attack_path_ingestor import (  # noqa: E402
    build_attack_path_cypher,
    ingest_attack_path_payload,
)
from src.reporting.decision_tree_formatter import (  # noqa: E402
    DecisionTreeFormatter,
    DEFAULT_MAX_NODES,
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_CHILDREN_PER_NODE,
)
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
        "tests/unit/reporting/test_decision_tree_formatter.py",
        "tests/unit/main/test_main_report_haddix.py",
    ],
    "session": [
        "tests/unit/reporting/test_session_finding_inspector.py",
    ],
    "ops_cli": [
        "tests/unit/scripts/test_shigoku_ops_cli.py",
        "tests/unit/scripts/test_shigoku_ops_attack_paths_cli.py",
        "tests/unit/scripts/test_shigoku_ops_attack_review_cli.py",
        "tests/unit/scripts/test_shigoku_ops_export_targets_cli.py",
        "tests/unit/scripts/test_shigoku_ops_findings_cli.py",
        "tests/unit/scripts/test_shigoku_ops_expected_detection_cli.py",
        "tests/unit/scripts/test_shigoku_ops_intent_cli.py",
        "tests/unit/cli/test_intent_parser.py",
        # SGK-2026-0422: vdp gate CLI
        "tests/unit/scripts/test_shigoku_ops_vdp_gate.py",
        # SGK-2026-0425 M2: vdp diagnose CLI (plan §17.2)
        "tests/unit/scripts/test_shigoku_ops_vdp_diagnose.py",
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


def _write_json_atomic(path: Path, data: dict[str, Any]) -> Path:
    """Atomically write a JSON artifact: temp file in the SAME directory,
    then os.replace — a partial artifact is never left under the official
    filename. PermissionError/OSError propagate (never swallowed)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as fh:
            tmp_path = Path(fh.name)
            json.dump(data, fh, sort_keys=True, ensure_ascii=False, indent=2)
        os.replace(str(tmp_path), str(path))
        tmp_path = None
    finally:
        # Best-effort cleanup of the temp file on failure; never mask the
        # original exception.
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
    return path


def _load_vdp_key_provider(path: Any) -> dict | None:
    """Public-key-only provider {key_id: bytes} from a VDP key registry JSON.

    SGK-2026-0423 close-out: the registry serialization is public data
    (``{"schema_version": 1, "keys": {key_id: {"public_key": <hex>}}}``);
    parsed directly so the CLI never imports engine modules (0422
    structural boundary). Missing/malformed → None (fail-closed: proofs
    stay unverifiable).
    """
    if not path:
        return None
    try:
        import json as _json

        registry_path = Path(str(path))
        if not registry_path.exists():
            return None
        data = _json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    keys = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(keys, dict) or not keys:
        return None
    provider: dict = {}
    for key_id, entry in keys.items():
        if not isinstance(entry, dict):
            continue
        raw = str(entry.get("public_key", "") or "")
        try:
            provider[str(key_id)] = bytes.fromhex(raw)
        except ValueError:
            continue
    return provider or None


def _run_vdp_gate(args: argparse.Namespace) -> int:
    """Handle 'vdp gate' — separated VDP quality gate (training|real)."""
    from src.core.utils.json_utils import safe_json_loads
    from src.reporting.vdp_gates import evaluate_vdp_gate

    session_path = Path(args.session).expanduser().resolve() if args.session else None
    if session_path is None or not session_path.exists():
        payload = {
            "status": "blocked",
            "reason_codes": ["session_required_for_vdp_gate"],
            "profile": args.profile,
        }
        _emit_command_payload(args, payload)
        return 2

    session_data = safe_json_loads(
        session_path.read_text(encoding="utf-8"),
        context=f"vdp_gate:{session_path.name}",
    )

    consistency_status = "consistent"
    consistency_reason_codes: list[str] = []
    vdp_key_provider = _load_vdp_key_provider(getattr(args, "vdp_key_registry", None))
    if args.report:
        # Audit I-07: a separated report group must be manifest-verified
        # before its content is consumed by the gate.
        rejected = _reject_unverified_separated_group(args.report, args)
        if rejected is not None:
            return rejected
        consistency = verify_report_session_consistency(
            Path(args.report),
            session_path=session_path,
            sessions_dir=Path(args.sessions_dir) if args.sessions_dir else None,
            public_key_provider=vdp_key_provider,
        )
        consistency_status = str(consistency.get("status", "") or "").strip().lower()
        consistency_reason_codes = [
            str(c) for c in consistency.get("reason_codes", [])
        ]
        # real profile: continue only when consistency is consistent.
        if args.profile == "real" and consistency_status != "consistent":
            payload = {
                "status": "blocked",
                "reason_codes": [f"consistency_{consistency_status}"] + consistency_reason_codes,
                "profile": args.profile,
                "consistency": consistency,
            }
            _emit_command_payload(args, payload)
            return 2

    gate = evaluate_vdp_gate(
        args.profile,
        session_data,
        labels_path=Path(args.labels) if getattr(args, "labels", None) else None,
        consistency_status=consistency_status,
        consistency_reason_codes=consistency_reason_codes,
        public_key_provider=vdp_key_provider,
    )
    payload = gate.to_dict()
    if args.report:
        payload["consistency"] = {
            "status": consistency_status,
            "reason_codes": consistency_reason_codes,
        }
    _emit_command_payload(args, payload)

    status = str(payload.get("status", "") or "").strip().lower()
    decision = str(payload.get("decision", "") or "").strip().lower()
    # exit: 0=pass/go, 2=blocked/hold/input-missing, 3=fail/no_go
    if status == "pass" and decision in {"", "go"}:
        return 0
    if decision == "no_go" or status == "fail":
        return 3
    return 2


def _run_vdp_diagnose(args: argparse.Namespace) -> int:
    """Handle 'vdp diagnose' — read-only, artifact-only first-failure
    diagnosis of a session's ``vdp_diagnostics_v1`` telemetry
    (SGK-2026-0425 M2).

    - when ``--report`` is given, the official consistency checker ALWAYS
      runs first (regardless of session explicitness) and any verdict other
      than ``consistent`` blocks the artifact (exit 2);
    - the JSON artifact is deep-redacted, hash/count-only and written
      atomically; an existing artifact with a DIFFERENT
      ``diagnostics_section_hash`` is refused, the same hash is an idempotent
      success;
    - no ``--labels`` / ground-truth argument exists; recall / S01-miss
      estimates are NEVER output (plan §5.2 / §11 test 24).
    """
    from src.core.engine.master_conductor_session_service import (
        load_session_payload_from_path,
    )
    from src.core.models.vdp_contract import redact_secrets_deep
    from src.reporting.vdp_canonical import extract_vdp_canonical

    session_path = Path(args.session).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()
    report_path = (
        Path(args.report).expanduser().resolve()
        if getattr(args, "report", None)
        else None
    )

    try:
        session_data = load_session_payload_from_path(str(session_path))
    except OSError:
        session_data = None
    if not isinstance(session_data, dict):
        print(
            f"vdp diagnose: session missing or unreadable: {session_path}",
            file=sys.stderr,
        )
        if bool(getattr(args, "json", False)):
            _emit_command_payload(
                args,
                {
                    "status": "blocked",
                    "reason_codes": ["session_missing_or_unreadable"],
                    "session_path": str(session_path),
                },
            )
        return 2

    vdp_key_provider = _load_vdp_key_provider(getattr(args, "vdp_key_registry", None))
    if report_path is not None:
        # Consumer-side manifest enforcement for separated report groups
        # (audit I-07), then the official consistency checker.
        rejected = _reject_unverified_separated_group(report_path, args)
        if rejected is not None:
            return rejected
        consistency = verify_report_session_consistency(
            report_path,
            session_path=session_path,
            public_key_provider=vdp_key_provider,
        )
        if str(consistency.get("status", "") or "").strip().lower() != "consistent":
            print(
                json.dumps(consistency, ensure_ascii=False, indent=2),
                file=sys.stderr,
            )
            if bool(getattr(args, "json", False)):
                _emit_command_payload(
                    args,
                    {
                        "status": "blocked",
                        "reason_codes": ["consistency_not_consistent"]
                        + [str(c) for c in consistency.get("reason_codes", [])],
                        "report_path": str(report_path),
                    },
                )
            return 2

    diag_section = session_data.get("vdp_diagnostics_v1")
    if "vdp_diagnostics_v1" in session_data and not isinstance(diag_section, dict):
        print(
            "vdp diagnose: vdp_diagnostics_v1 section invalid (not a dict)",
            file=sys.stderr,
        )
        if bool(getattr(args, "json", False)):
            _emit_command_payload(
                args,
                {
                    "status": "blocked",
                    "reason_codes": ["diagnostic_section_invalid"],
                    "session_path": str(session_path),
                },
            )
        return 2
    events = diag_section.get("events") if isinstance(diag_section, dict) else []
    if not isinstance(events, list):
        events = []

    try:
        analysis = analyze_observed_lineages(
            events,
            canonical_summary=extract_vdp_canonical(session_data).to_dict(),
        )
    except Exception as exc:
        print(f"vdp diagnose: runtime error: {exc}", file=sys.stderr)
        return 3

    events_hash = "sha256:" + hashlib.sha256(
        json.dumps(events, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()

    artifact = redact_secrets_deep(
        {
            "schema_version": 1,
            "command": "vdp diagnose",
            "session_path": str(session_path),
            "report_path": str(report_path) if report_path is not None else None,
            "analysis": analysis,
            "diagnostics_section_hash": events_hash,
            "coverage_note": COVERAGE_NOTE,
        }
    )

    # Overwrite protection: an existing artifact must carry the SAME
    # diagnostics_section_hash (idempotent success, no rewrite); a different
    # hash is refused and nothing is written.
    if output_path.exists():
        try:
            existing = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            existing = None
        if (
            not isinstance(existing, dict)
            or existing.get("diagnostics_section_hash") != events_hash
        ):
            print(
                f"vdp diagnose: refusing to overwrite {output_path}: existing "
                "artifact has a different diagnostics_section_hash",
                file=sys.stderr,
            )
            if bool(getattr(args, "json", False)):
                _emit_command_payload(
                    args,
                    {
                        "status": "blocked",
                        "reason_codes": ["output_hash_conflict"],
                        "output": str(output_path),
                    },
                )
            return 2
    else:
        try:
            _write_json_atomic(output_path, artifact)
        except OSError as exc:
            print(
                f"vdp diagnose: runtime error: cannot write artifact: {exc}",
                file=sys.stderr,
            )
            return 3

    # stdout carries the human summary; the compact JSON payload is emitted
    # only with the global --json flag. stderr stays empty on success.
    first_failures = sum(
        1
        for lineage in (analysis.get("lineages") or [])
        if isinstance(lineage, dict) and lineage.get("first_failure") is not None
    )
    stage_counts: dict[str, int] = {}
    for ev in events:
        if isinstance(ev, dict) and isinstance(ev.get("stage_id"), str):
            key = str(ev["stage_id"])
            stage_counts[key] = stage_counts.get(key, 0) + 1
    print(
        f"diagnostic: events={len(events)} first_failures={first_failures} "
        f"stage_counts={json.dumps(stage_counts, sort_keys=True, ensure_ascii=False)} "
        f"coverage_note={COVERAGE_NOTE}"
    )
    if bool(getattr(args, "json", False)):
        _emit_command_payload(
            args,
            {
                "status": "ok",
                "command": "vdp diagnose",
                "session_path": str(session_path),
                "report_path": str(report_path) if report_path is not None else None,
                "output": str(output_path),
                "events": len(events),
                "first_failures": first_failures,
                "coverage_note": COVERAGE_NOTE,
            },
        )
    return 0


def _reject_unverified_separated_group(report_path: Any, args: argparse.Namespace) -> int | None:
    """Consumer-side manifest enforcement (SGK-2026-0422 audit I-07).

    When ``report_path`` is a member of a separated report group, the group
    completion manifest MUST exist and all recorded files MUST match their
    sha256. Returns an exit code when the artifact is rejected (None when
    the report is a plain single-file report or the group verifies).
    """
    try:
        from src.reporting.vdp_report_projection import verify_separated_group
    except Exception:
        return None
    check = verify_separated_group(report_path)
    if check["ok"]:
        return None
    payload = {
        "status": "fail",
        "reason_codes": [str(check.get("reason", "separated_manifest_invalid"))],
        "manifest": check.get("manifest"),
    }
    _emit_command_payload(args, payload)
    return 3


def _run_report_consistency(args: argparse.Namespace) -> int:
    rejected = _reject_unverified_separated_group(args.report, args)
    if rejected is not None:
        return rejected
    verdict = verify_report_session_consistency(
        Path(args.report),
        session_path=Path(args.session) if args.session else None,
        sessions_dir=Path(args.sessions_dir) if args.sessions_dir else None,
        public_key_provider=_load_vdp_key_provider(
            getattr(args, "vdp_key_registry", None)
        ),
    )
    _emit_command_payload(args, verdict)
    return _status_exit_code(verdict.get("status"), ok="consistent", fail="inconsistent")


def _run_report_gate(args: argparse.Namespace) -> int:
    rejected = _reject_unverified_separated_group(args.report, args)
    if rejected is not None:
        return rejected
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
    rejected = _reject_unverified_separated_group(args.report, args)
    if rejected is not None:
        return rejected
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

    # CRITICAL: When both --session and --report are provided, the
    # consistency check MUST run.  The explicit --session overrides
    # source-session resolution but the report/session pair is still
    # verified for consistency.
    if args.session and args.report:
        consistency = verify_report_session_consistency(
            Path(args.report),
            session_path=Path(args.session),
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
            session_path=None,
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


def _run_report_attack_review(args: argparse.Namespace) -> int:
    """Generate attack_review.md from session data (SGK-2026-0324 Step 5)."""
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

    markdown = format_attack_review(session_data)

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
    graph_payload: dict[str, Any] | None = None

    def _ensure_graph_payload() -> dict[str, Any]:
        nonlocal graph_payload
        if graph_payload is None:
            graph_payload = formatter.build_json_payload(session_data)
        return graph_payload

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
        json_path.write_text(
            json.dumps(_ensure_graph_payload(), indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        payload["json_output"] = str(json_path)

    if output_path is not None and getattr(args, "cypher_output", False):
        cypher_path = output_path.with_suffix(".cypher")
        cypher_path.write_text(
            build_attack_path_cypher(_ensure_graph_payload()),
            encoding="utf-8",
        )
        payload["cypher_output"] = str(cypher_path)

    if getattr(args, "neo4j_ingest", False):
        try:
            payload["neo4j_ingest"] = ingest_attack_path_payload(
                _ensure_graph_payload()
            )
        except Exception as exc:
            payload["status"] = "blocked"
            payload["reason_codes"] = ["neo4j_ingest_failed"]
            payload["hint"] = (
                "Cypher/JSON artifacts may still have been generated, "
                "but Neo4j ingest did not complete."
            )
            payload["error"] = str(exc)
            _emit_command_payload(args, payload)
            return 2

    _emit_command_payload(args, payload)
    return 0


def _run_report_decision_tree(args: argparse.Namespace) -> int:
    """Handle 'report decision-tree' subcommand — SGK-2026-0334 (P1b)."""
    session_data, consistency_status, reason_codes = _resolve_session_from_args(args)

    if session_data is None:
        payload: dict[str, Any] = {
            "status": "blocked",
            "reason_codes": reason_codes if reason_codes else ["session_not_resolved"],
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

    formatter = DecisionTreeFormatter(
        max_nodes=max(1, int(getattr(args, "max_nodes", DEFAULT_MAX_NODES))),
        max_edges=max(1, int(getattr(args, "max_edges", DEFAULT_MAX_EDGES))),
        max_depth=max(1, int(getattr(args, "max_depth", DEFAULT_MAX_DEPTH))),
        max_children_per_node=max(1, int(getattr(args, "max_children_per_node", DEFAULT_MAX_CHILDREN_PER_NODE))),
    )

    phase = str(getattr(args, "phase", "") or "").strip()
    actor = str(getattr(args, "actor", "") or "").strip()
    only_failures = bool(getattr(args, "only_failures", False))
    output_json = bool(getattr(args, "json", False))

    markdown = formatter.format(
        session_data, phase=phase, actor=actor, only_failures=only_failures,
    )

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(markdown, encoding="utf-8")
        payload = {"status": "ok", "output": str(output_path)}
    elif output_json:
        payload = formatter.format_json(
            session_data, phase=phase, actor=actor, only_failures=only_failures,
        )
    else:
        print(markdown)
        payload = {"status": "ok", "output": "stdout"}

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


def _run_report_findings(args: argparse.Namespace) -> int:
    session_data, consistency_status, reason_codes = _resolve_session_from_args(args)
    if session_data is None:
        payload: dict[str, Any] = {
            "status": "blocked",
            "reason_codes": reason_codes if reason_codes else ["session_not_resolved"],
            "hint": "Provide --report that resolves to a consistent session.",
        }
        _emit_command_payload(args, payload)
        return 2
    if consistency_status is not None and consistency_status != "consistent":
        payload = {
            "status": "blocked",
            "reason_codes": ["report_consistency_inconsistent", *reason_codes],
            "hint": "Report-session consistency check failed.",
        }
        _emit_command_payload(args, payload)
        return 2

    verdict = verify_report_session_consistency(
        Path(args.report),
        session_path=Path(args.session) if args.session else None,
        sessions_dir=Path(args.sessions_dir) if args.sessions_dir else None,
    )
    session_info = verdict.get("session", {}) if isinstance(verdict.get("session"), dict) else {}
    resolved_path = str(session_info.get("path", "") or "").strip()
    if not resolved_path:
        payload = {
            "status": "blocked",
            "reason_codes": ["session_not_resolved"],
        }
        _emit_command_payload(args, payload)
        return 2

    finding_fields = _resolve_finding_fields(
        args.finding_fields,
        getattr(args, "finding_preset", None),
    )
    summary = inspect_session_findings(
        Path(resolved_path),
        detection_class=args.detection_class,
        max_findings=args.max_findings,
        finding_fields=finding_fields,
    )
    _emit_command_payload(args, summary)
    return 0


def _run_report_expected_detections(args: argparse.Namespace) -> int:
    session_data, source_meta = _load_consistent_report_session(
        args.report,
        session_path=args.session,
        sessions_dir=args.sessions_dir,
    )
    if session_data is None:
        payload: dict[str, Any] = {
            "status": "blocked",
            "reason_codes": source_meta.get("reason_codes", []) or ["session_not_resolved"],
            "hint": "Provide --report that resolves to a consistent session.",
            "source": source_meta,
        }
        _emit_command_payload(args, payload)
        return 2

    summary = compare_expected_detections(
        session_data,
        require_security_level=True,
        profile=str(getattr(args, "profile", "generic") or "generic"),
    )
    if not bool(getattr(args, "include_matrix", False)):
        summary.pop("matrix", None)
    summary.setdefault("status", "ok")
    summary["source"] = source_meta
    _emit_command_payload(args, summary)
    return 2 if summary.get("reason_codes") else 0


def _load_consistent_report_session(
    report_path: str,
    *,
    session_path: str | None = None,
    sessions_dir: str | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    verdict = verify_report_session_consistency(
        Path(report_path),
        session_path=Path(session_path) if session_path else None,
        sessions_dir=Path(sessions_dir) if sessions_dir else None,
    )
    status = str(verdict.get("status", "") or "").strip().lower()
    if status != "consistent":
        return None, {
            "status": "blocked",
            "reason_codes": ["report_consistency_inconsistent", *list(verdict.get("reason_codes", []))],
            "consistency_status": verdict.get("status"),
        }

    session_info = verdict.get("session", {}) if isinstance(verdict.get("session"), dict) else {}
    resolved_path = str(session_info.get("path", "") or "").strip()
    if not resolved_path:
        return None, {
            "status": "blocked",
            "reason_codes": ["session_not_resolved"],
            "consistency_status": verdict.get("status"),
        }

    try:
        payload = json.loads(Path(resolved_path).read_text(encoding="utf-8"))
    except Exception:
        return None, {
            "status": "blocked",
            "reason_codes": ["session_parse_failed"],
            "consistency_status": verdict.get("status"),
            "session": resolved_path,
        }

    return payload, {
        "status": "ok",
        "reason_codes": [],
        "report": str(Path(report_path).expanduser().resolve()),
        "session": resolved_path,
        "session_selection": session_info.get("selection"),
    }


def _run_report_compare_findings(args: argparse.Namespace) -> int:
    baseline_session_data, baseline_meta = _load_consistent_report_session(
        args.baseline_report,
        session_path=args.baseline_session,
        sessions_dir=args.baseline_sessions_dir or args.sessions_dir,
    )
    current_session_data, current_meta = _load_consistent_report_session(
        args.report,
        session_path=args.session,
        sessions_dir=args.sessions_dir,
    )

    if baseline_session_data is None or current_session_data is None:
        payload = {
            "status": "blocked",
            "baseline": baseline_meta,
            "current": current_meta,
            "reason_codes": list(
                dict.fromkeys(
                    list(baseline_meta.get("reason_codes", []))
                    + list(current_meta.get("reason_codes", []))
                )
            )
            or ["session_not_resolved"],
        }
        _emit_command_payload(args, payload)
        return 2

    diff = compare_session_finding_sets(baseline_session_data, current_session_data)
    diff["status"] = "ok"
    diff["baseline"] = baseline_meta
    diff["current"] = current_meta
    _emit_command_payload(args, diff)
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


def _default_export_dir_for_session(session_path: Path) -> Path:
    session_file = session_path.expanduser().resolve()
    return session_file.parent.parent / "exports" / session_file.stem


def _default_export_dir_for_findings_db(db_path: Path) -> Path:
    resolved_db = db_path.expanduser().resolve()
    return resolved_db.parent / "exports" / resolved_db.stem


def _serialize_findings(findings: list[Any]) -> list[dict[str, Any]]:
    serialized: list[dict[str, Any]] = []
    for finding in findings:
        payload = finding.to_dict() if hasattr(finding, "to_dict") else finding
        if isinstance(payload, dict):
            serialized.append(payload)
    return serialized


def _normalize_host_list(values: list[str] | None) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for raw in values or []:
        host = extract_host_from_url(str(raw or "").strip())
        if not host or host in seen:
            continue
        seen.add(host)
        hosts.append(host)
    return hosts


def _load_findings_repository(args: argparse.Namespace) -> FindingsRepository:
    db_path = getattr(args, "db_path", None)
    return FindingsRepository(db_path=str(db_path) if db_path else None)


def _build_findings_filters(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "severity": getattr(args, "severity", None),
        "vuln_type": getattr(args, "vuln_type", None),
        "target": getattr(args, "target", None),
        "source_agent": getattr(args, "source_agent", None),
        "verified_only": bool(getattr(args, "verified_only", False)),
    }


def _search_findings_for_args(args: argparse.Namespace, *, limit: int) -> list[Any]:
    repo = _load_findings_repository(args)
    filters = _build_findings_filters(args)
    return repo.search(
        severity=filters["severity"],
        vuln_type=filters["vuln_type"],
        target=filters["target"],
        source_agent=filters["source_agent"],
        verified_only=filters["verified_only"],
        limit=max(0, int(limit)),
    )


def _resolve_findings_allowed_hosts(args: argparse.Namespace, findings: list[Any]) -> tuple[list[str], list[str], list[str]]:
    explicit_hosts = _normalize_host_list(getattr(args, "allowed_host", None))
    if explicit_hosts:
        return explicit_hosts, [], []

    target_host = extract_host_from_url(str(getattr(args, "target", None) or "").strip())
    if target_host:
        return [target_host], [], []

    discovered_hosts = sorted(
        {
            extract_host_from_url(str(getattr(finding, "target_url", "") or ""))
            for finding in findings
            if extract_host_from_url(str(getattr(finding, "target_url", "") or ""))
        }
    )
    if len(discovered_hosts) > 1:
        return [], ["cross_session_scope_required"], discovered_hosts
    return discovered_hosts, [], discovered_hosts


def _run_session_export_targets(args: argparse.Namespace) -> int:
    session_path = Path(args.session).expanduser().resolve()
    output_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else _default_export_dir_for_session(session_path)
    )
    try:
        bundle = build_attack_target_bundle_from_session(
            session_path,
            ttl_days=max(0, int(args.ttl_days)),
            max_records=max(0, int(args.max_records)),
        )
        artifacts = write_attack_target_artifacts(
            bundle,
            output_dir,
            overwrite=bool(args.overwrite),
        )
    except ValueError as exc:
        payload = {
            "status": "blocked",
            "reason_codes": ["empty_export"] if "empty export" in str(exc) else ["invalid_export"],
            "error": str(exc),
            "session": str(session_path),
        }
        _emit_command_payload(args, payload)
        return 3
    except FileExistsError as exc:
        payload = {
            "status": "blocked",
            "reason_codes": ["export_overwrite_blocked"],
            "error": str(exc),
            "session": str(session_path),
            "output_dir": str(output_dir),
        }
        _emit_command_payload(args, payload)
        return 2

    payload = {
        "status": "ok",
        "session": str(session_path),
        "output_dir": str(output_dir),
        "target_count": len(bundle.targets),
        "manifest": bundle.manifest.to_dict(),
        "artifacts": artifacts,
        "reason_codes": list(bundle.manifest.reason_codes),
    }
    _emit_command_payload(args, payload)
    return 0


def _run_findings_list(args: argparse.Namespace) -> int:
    repo = _load_findings_repository(args)
    findings = repo.list_all(
        limit=max(0, int(getattr(args, "limit", 100) or 100)),
        offset=max(0, int(getattr(args, "offset", 0) or 0)),
        order_by=str(getattr(args, "order_by", "created_at") or "created_at"),
        desc=not bool(getattr(args, "asc", False)),
    )
    payload = {
        "status": "ok",
        "db_path": str(repo.db_path),
        "finding_count": len(findings),
        "findings": _serialize_findings(findings),
    }
    _emit_command_payload(args, payload)
    return 0


def _run_findings_search(args: argparse.Namespace) -> int:
    repo = _load_findings_repository(args)
    findings = _search_findings_for_args(
        args,
        limit=max(0, int(getattr(args, "limit", 100) or 100)),
    )
    payload = {
        "status": "ok",
        "db_path": str(repo.db_path),
        "filters": _build_findings_filters(args),
        "finding_count": len(findings),
        "findings": _serialize_findings(findings),
    }
    _emit_command_payload(args, payload)
    return 0


def _run_findings_stats(args: argparse.Namespace) -> int:
    repo = _load_findings_repository(args)
    payload = {
        "status": "ok",
        "db_path": str(repo.db_path),
        "stats": repo.get_statistics(),
    }
    _emit_command_payload(args, payload)
    return 0


def _run_findings_export_targets(args: argparse.Namespace) -> int:
    repo = _load_findings_repository(args)
    export_limit = max(1, int(getattr(args, "max_records", 500) or 500))
    findings = _search_findings_for_args(args, limit=export_limit)
    if not findings:
        payload = {
            "status": "blocked",
            "db_path": str(repo.db_path),
            "reason_codes": ["empty_export"],
            "filters": _build_findings_filters(args),
        }
        _emit_command_payload(args, payload)
        return 2

    allowed_hosts, scope_reason_codes, discovered_hosts = _resolve_findings_allowed_hosts(args, findings)
    if scope_reason_codes:
        payload = {
            "status": "blocked",
            "db_path": str(repo.db_path),
            "reason_codes": scope_reason_codes,
            "filters": _build_findings_filters(args),
            "discovered_hosts": discovered_hosts,
            "hint": "Pass --allowed-host or --target to constrain cross-session export scope.",
        }
        _emit_command_payload(args, payload)
        return 2

    output_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else _default_export_dir_for_findings_db(repo.db_path)
    )
    try:
        bundle = build_attack_target_bundle_from_findings(
            findings,
            db_path=repo.db_path,
            ttl_days=max(0, int(getattr(args, "ttl_days", 7) or 7)),
            max_records=export_limit,
            allowed_hosts=allowed_hosts,
            filters={
                **_build_findings_filters(args),
                "allowed_hosts": allowed_hosts,
            },
        )
        violations = bundle.validate_allowed_hosts()
        if violations:
            payload = {
                "status": "blocked",
                "db_path": str(repo.db_path),
                "reason_codes": ["allowed_hosts_mismatch"],
                "filters": _build_findings_filters(args),
                "allowed_hosts": allowed_hosts,
                "violations": violations[:5],
            }
            _emit_command_payload(args, payload)
            return 2
        artifacts = write_attack_target_artifacts(
            bundle,
            output_dir,
            overwrite=bool(args.overwrite),
        )
    except ValueError as exc:
        payload = {
            "status": "blocked",
            "db_path": str(repo.db_path),
            "reason_codes": ["empty_export"] if "empty export" in str(exc) else ["invalid_export"],
            "error": str(exc),
        }
        _emit_command_payload(args, payload)
        return 3
    except FileExistsError as exc:
        payload = {
            "status": "blocked",
            "db_path": str(repo.db_path),
            "reason_codes": ["export_overwrite_blocked"],
            "error": str(exc),
            "output_dir": str(output_dir),
        }
        _emit_command_payload(args, payload)
        return 2

    payload = {
        "status": "ok",
        "db_path": str(repo.db_path),
        "output_dir": str(output_dir),
        "filters": _build_findings_filters(args),
        "finding_count": len(findings),
        "target_count": len(bundle.targets),
        "manifest": bundle.manifest.to_dict(),
        "artifacts": artifacts,
        "reason_codes": list(bundle.manifest.reason_codes),
    }
    _emit_command_payload(args, payload)
    return 0


def _run_report_export_targets(args: argparse.Namespace) -> int:
    verdict = verify_report_session_consistency(
        Path(args.report),
        session_path=Path(args.session) if args.session else None,
        sessions_dir=Path(args.sessions_dir) if args.sessions_dir else None,
    )
    session_info = verdict.get("session", {}) if isinstance(verdict.get("session"), dict) else {}
    resolved_path = str(session_info.get("path", "") or "").strip()
    if str(verdict.get("status", "") or "").strip().lower() != "consistent" or not resolved_path:
        payload = {
            "status": "blocked",
            "reason_codes": ["report_consistency_inconsistent", *list(verdict.get("reason_codes", []) or [])],
            "report_path": str(Path(args.report).expanduser().resolve()),
            "session_path": resolved_path or None,
            "suggested_next_step": verdict.get("suggested_next_step"),
        }
        _emit_command_payload(args, payload)
        return 3

    session_path = Path(resolved_path).expanduser().resolve()
    output_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else _default_export_dir_for_session(session_path)
    )
    try:
        bundle = build_attack_target_bundle_from_session(
            session_path,
            report_path=Path(args.report).expanduser().resolve(),
            ttl_days=max(0, int(args.ttl_days)),
            max_records=max(0, int(args.max_records)),
        )
        artifacts = write_attack_target_artifacts(
            bundle,
            output_dir,
            overwrite=bool(args.overwrite),
        )
    except ValueError as exc:
        payload = {
            "status": "blocked",
            "reason_codes": ["empty_export"] if "empty export" in str(exc) else ["invalid_export"],
            "error": str(exc),
            "report_path": str(Path(args.report).expanduser().resolve()),
            "session_path": str(session_path),
        }
        _emit_command_payload(args, payload)
        return 3
    except FileExistsError as exc:
        payload = {
            "status": "blocked",
            "reason_codes": ["export_overwrite_blocked"],
            "error": str(exc),
            "report_path": str(Path(args.report).expanduser().resolve()),
            "session_path": str(session_path),
            "output_dir": str(output_dir),
        }
        _emit_command_payload(args, payload)
        return 2

    payload = {
        "status": "ok",
        "report_path": str(Path(args.report).expanduser().resolve()),
        "session_path": str(session_path),
        "output_dir": str(output_dir),
        "target_count": len(bundle.targets),
        "manifest": bundle.manifest.to_dict(),
        "artifacts": artifacts,
        "reason_codes": list(bundle.manifest.reason_codes),
    }
    _emit_command_payload(args, payload)
    return 0


def _build_endpoint_payload(
    targets: list[Any],
    *,
    source_path: str,
    filters: dict[str, Any],
) -> dict[str, Any]:
    return {
        "status": "ok",
        "source_path": source_path,
        "filters": filters,
        "endpoint_count": len(targets),
        "endpoints": [target.to_dict() for target in targets],
    }


def _filter_targets(
    targets: list[Any],
    *,
    host: str | None = None,
    category: str | None = None,
    method: str | None = None,
    limit: int | None = None,
) -> list[Any]:
    filtered = list(targets)
    if host:
        normalized_host = str(host).strip().lower()
        filtered = [target for target in filtered if str(getattr(target, "host", "") or "").strip().lower() == normalized_host]
    if category:
        normalized_category = str(category).strip().lower()
        filtered = [target for target in filtered if str(getattr(target, "category", "") or "").strip().lower() == normalized_category]
    if method:
        normalized_method = str(method).strip().upper()
        filtered = [target for target in filtered if str(getattr(target, "method", "") or "").strip().upper() == normalized_method]
    if limit is not None:
        filtered = filtered[: max(0, int(limit))]
    return filtered


def _run_session_endpoints(args: argparse.Namespace) -> int:
    session_path = Path(args.session).expanduser().resolve()
    targets = extract_attack_targets_from_session(session_path)
    filtered = _filter_targets(
        targets,
        host=getattr(args, "host", None),
        category=getattr(args, "category", None),
        method=getattr(args, "method", None),
        limit=getattr(args, "limit", None),
    )
    payload = _build_endpoint_payload(
        filtered,
        source_path=str(session_path),
        filters={
            "host": getattr(args, "host", None),
            "category": getattr(args, "category", None),
            "method": getattr(args, "method", None),
            "limit": getattr(args, "limit", None),
        },
    )
    _emit_command_payload(args, payload)
    return 0


def _run_report_endpoints(args: argparse.Namespace) -> int:
    verdict = verify_report_session_consistency(
        Path(args.report),
        session_path=Path(args.session) if args.session else None,
        sessions_dir=Path(args.sessions_dir) if args.sessions_dir else None,
    )
    session_info = verdict.get("session", {}) if isinstance(verdict.get("session"), dict) else {}
    resolved_path = str(session_info.get("path", "") or "").strip()
    if str(verdict.get("status", "") or "").strip().lower() != "consistent" or not resolved_path:
        payload = {
            "status": "blocked",
            "reason_codes": ["report_consistency_inconsistent", *list(verdict.get("reason_codes", []) or [])],
            "report_path": str(Path(args.report).expanduser().resolve()),
            "session_path": resolved_path or None,
        }
        _emit_command_payload(args, payload)
        return 2

    session_path = Path(resolved_path).expanduser().resolve()
    targets = extract_attack_targets_from_session(session_path)
    filtered = _filter_targets(
        targets,
        host=getattr(args, "host", None),
        category=getattr(args, "category", None),
        method=getattr(args, "method", None),
        limit=getattr(args, "limit", None),
    )
    payload = _build_endpoint_payload(
        filtered,
        source_path=str(session_path),
        filters={
            "host": getattr(args, "host", None),
            "category": getattr(args, "category", None),
            "method": getattr(args, "method", None),
            "limit": getattr(args, "limit", None),
            "report_path": str(Path(args.report).expanduser().resolve()),
        },
    )
    _emit_command_payload(args, payload)
    return 0


def _resolve_python_bin(preferred: str | None) -> str:
    if preferred:
        return preferred

    venv_python = PROJECT_ROOT / ".venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)
    return "python3"


def _run_ops_intent(args: argparse.Namespace) -> int:
    settings = load_ops_intent_settings()
    translated = parse_operator_intent(
        str(args.intent or ""),
        target=getattr(args, "target", None),
        report_path=getattr(args, "report", None),
        session_path=getattr(args, "session", None),
        attack_targets_file=getattr(args, "attack_targets", None),
        wordlist_path=getattr(args, "wordlist", None),
        mode=getattr(args, "mode", None),
        settings=settings,
    )
    preview = build_execution_preview(
        translated,
        settings=settings,
        python_bin=_resolve_python_bin(getattr(args, "python", None)),
        output_dir=getattr(args, "output_dir", None),
        max_records=max(1, int(getattr(args, "max_records", 500) or 500)),
        ttl_days=max(0, int(getattr(args, "ttl_days", 7) or 7)),
        main_dry_run=bool(getattr(args, "main_dry_run", False)),
    )
    payload: dict[str, Any] = {
        "settings": settings.to_dict(),
        "translated": translated.to_dict(),
        **preview.to_dict(),
    }
    payload["status"] = "preview" if preview.status == "ok" and not getattr(args, "execute", False) else preview.status
    if preview.status != "ok":
        _emit_command_payload(args, payload)
        return 2

    if not getattr(args, "execute", False):
        _emit_command_payload(args, payload)
        return 0

    if settings.kill_switch:
        payload.update({"status": "blocked", "reason_codes": [*payload.get("reason_codes", []), "ops_intent_kill_switch"]})
        _emit_command_payload(args, payload)
        return 2
    if not settings.feature_flag:
        payload.update({"status": "blocked", "reason_codes": [*payload.get("reason_codes", []), "ops_intent_disabled"]})
        _emit_command_payload(args, payload)
        return 2

    requires_confirmation = any(bool(step.requires_confirmation) for step in preview.steps)
    if requires_confirmation and not getattr(args, "approve", False):
        if not sys.stdin.isatty():
            payload.update({"status": "blocked", "reason_codes": [*payload.get("reason_codes", []), "approval_required_non_tty"]})
            _emit_command_payload(args, payload)
            return 2
        confirm = input("Preview looks correct. Execute it? [y/N]: ").strip().lower()
        if confirm not in {"y", "yes"}:
            payload.update({"status": "blocked", "reason_codes": [*payload.get("reason_codes", []), "approval_denied"]})
            _emit_command_payload(args, payload)
            return 2

    executed_steps: list[dict[str, Any]] = []
    for step in preview.steps:
        child_env = os.environ.copy()
        if any(item.intent_command == "main.attack-targets" for item in preview.steps):
            child_env["SHIGOKU_ATTACK_TARGETS_APPROVED"] = "1"
        if bool(getattr(args, "main_dry_run", False)) and step.intent_command.startswith("main."):
            child_env["SHIGOKU_SKIP_ENTRY_GATE"] = "1"
        try:
            result = subprocess.run(
                step.command,
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                env=child_env,
                timeout=max(1, int(settings.command_timeout_sec)),
                check=False,
            )
        except subprocess.TimeoutExpired:
            payload.update(
                {
                    "status": "blocked",
                    "reason_codes": [*payload.get("reason_codes", []), "command_timeout"],
                    "executed_steps": executed_steps,
                }
            )
            _emit_command_payload(args, payload)
            return 3
        step_payload = {
            "intent_command": step.intent_command,
            "command": step.command,
            "returncode": int(result.returncode),
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        if result.stdout.strip().startswith("{"):
            try:
                step_payload["json"] = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        executed_steps.append(step_payload)
        if result.returncode != 0:
            payload.update(
                {
                    "status": "failed",
                    "reason_codes": [*payload.get("reason_codes", []), "step_failed"],
                    "executed_steps": executed_steps,
                }
            )
            _emit_command_payload(args, payload)
            return int(result.returncode)

    payload.update({"status": "ok", "executed_steps": executed_steps})
    _emit_command_payload(args, payload)
    return 0


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

    phase = getattr(args, "phase", "generic")
    if phase == "phase9":
        verdict = evaluate_phase9_evidence_bundle(records)
        # Phase 9 uses its own allowed/required gate names
    else:
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
    report_consistency.add_argument(
        "--vdp-key-registry",
        help="Optional VDP key registry JSON (public keys only) for proof verification.",
    )
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

    report_export_targets = report_sub.add_parser(
        "export-targets",
        help="Export a single-session structured target bundle from a report after consistency checks.",
    )
    report_export_targets.add_argument("--report", required=True, help="Path to haddix_report_*.md")
    report_export_targets.add_argument("--session", help="Optional explicit session_*.json path")
    report_export_targets.add_argument("--sessions-dir", help="Optional sessions directory path")
    report_export_targets.add_argument("--output-dir", help="Optional artifact output directory")
    report_export_targets.add_argument("--ttl-days", type=int, default=7, help="Manifest TTL days")
    report_export_targets.add_argument("--max-records", type=int, default=500, help="Maximum exported targets")
    report_export_targets.add_argument("--overwrite", action="store_true", help="Overwrite existing artifacts")
    report_export_targets.set_defaults(handler=_run_report_export_targets)

    report_findings = report_sub.add_parser(
        "findings",
        help="Inspect canonical findings from a report after resolving a consistent source session.",
    )
    report_findings.add_argument("--report", required=True, help="Path to haddix_report_*.md")
    report_findings.add_argument("--session", help="Optional explicit session_*.json path")
    report_findings.add_argument("--sessions-dir", help="Optional sessions directory path")
    report_findings.add_argument("--detection-class", help="Optional detection class filter")
    report_findings.add_argument("--max-findings", type=int, help="Optional findings cap.")
    report_findings.add_argument("--finding-fields", help="Comma-separated finding fields projection.")
    report_findings.add_argument(
        "--finding-preset",
        choices=sorted(FINDING_FIELD_PRESETS.keys()),
        help=(
            "Finding field preset. Ignored when --finding-fields is provided. "
            "minimal=title,target_url; triage adds decision fields; full keeps all."
        ),
    )
    report_findings.set_defaults(handler=_run_report_findings)

    report_expected_detections = report_sub.add_parser(
        "expected-detections",
        help="Evaluate a consistent report/session against its Security-level expectation profile.",
    )
    report_expected_detections.add_argument("--report", required=True, help="Path to haddix_report_*.md")
    report_expected_detections.add_argument("--session", help="Optional explicit session_*.json path")
    report_expected_detections.add_argument("--sessions-dir", help="Optional sessions directory path")
    report_expected_detections.add_argument(
        "--profile", choices=("generic", "dvwa-low-regression"), default="generic",
        help="generic assesses evidence discipline; dvwa-low-regression uses the DVWA Low fixture matrix.",
    )
    report_expected_detections.add_argument(
        "--include-matrix",
        action="store_true",
        help="Include the full expected detection matrix in the output.",
    )
    report_expected_detections.set_defaults(handler=_run_report_expected_detections)

    report_compare_findings = report_sub.add_parser(
        "compare-findings",
        help="Compare canonical finding keys between two consistent report/session pairs.",
    )
    report_compare_findings.add_argument("--baseline-report", required=True, help="Baseline haddix_report_*.md")
    report_compare_findings.add_argument("--baseline-session", help="Optional explicit baseline session_*.json")
    report_compare_findings.add_argument("--baseline-sessions-dir", help="Optional baseline sessions directory")
    report_compare_findings.add_argument("--report", required=True, help="Current haddix_report_*.md")
    report_compare_findings.add_argument("--session", help="Optional explicit current session_*.json")
    report_compare_findings.add_argument("--sessions-dir", help="Optional current sessions directory")
    report_compare_findings.set_defaults(handler=_run_report_compare_findings)

    report_endpoints = report_sub.add_parser(
        "endpoints",
        help="List extracted single-session endpoints from a report after consistency checks.",
    )
    report_endpoints.add_argument("--report", required=True, help="Path to haddix_report_*.md")
    report_endpoints.add_argument("--session", help="Optional explicit session_*.json path")
    report_endpoints.add_argument("--sessions-dir", help="Optional sessions directory path")
    report_endpoints.add_argument("--host", help="Optional host filter")
    report_endpoints.add_argument("--category", help="Optional endpoint category filter")
    report_endpoints.add_argument("--method", help="Optional HTTP method filter")
    report_endpoints.add_argument("--limit", type=int, help="Optional endpoint cap")
    report_endpoints.set_defaults(handler=_run_report_endpoints)

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
    report_attack_paths.add_argument("--cypher-output", action="store_true", help="Also export attack_paths.cypher for Neo4j ingest review")
    report_attack_paths.add_argument("--neo4j-ingest", action="store_true", help="Write the generated attack path graph into Neo4j")
    report_attack_paths.set_defaults(handler=_run_report_attack_paths)

    report_decision_tree = report_sub.add_parser(
        "decision-tree",
        help="Generate a decision_tree.md Mermaid + Markdown report from a session (SGK-2026-0334).",
    )
    report_decision_tree.add_argument("--session", help="Path to session_*.json")
    report_decision_tree.add_argument("--report", help="Path to haddix_report_*.md (resolves source session)")
    report_decision_tree.add_argument("--sessions-dir", help="Optional sessions directory for --report resolution")
    report_decision_tree.add_argument("--output", help="Optional output file path (default: stdout)")
    report_decision_tree.add_argument("--phase", help="Filter by phase (e.g. attack, recon)")
    report_decision_tree.add_argument("--actor", help="Filter by actor type or name")
    report_decision_tree.add_argument("--only-failures", action="store_true", help="Show only failed/error nodes")
    report_decision_tree.add_argument("--max-nodes", type=int, default=DEFAULT_MAX_NODES, help=f"Max nodes (default: {DEFAULT_MAX_NODES})")
    report_decision_tree.add_argument("--max-edges", type=int, default=DEFAULT_MAX_EDGES, help=f"Max edges (default: {DEFAULT_MAX_EDGES})")
    report_decision_tree.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH, help=f"Max depth (default: {DEFAULT_MAX_DEPTH})")
    report_decision_tree.add_argument("--max-children-per-node", type=int, default=DEFAULT_MAX_CHILDREN_PER_NODE, help=f"Max children per node (default: {DEFAULT_MAX_CHILDREN_PER_NODE})")
    report_decision_tree.set_defaults(handler=_run_report_decision_tree)

    report_attack_review = report_sub.add_parser(
        "attack-review",
        help="Generate an attack_review.md Markdown report from a session (SGK-2026-0324).",
    )
    report_attack_review.add_argument("--session", help="Path to session_*.json")
    report_attack_review.add_argument("--report", help="Path to haddix_report_*.md (resolves source session)")
    report_attack_review.add_argument("--sessions-dir", help="Optional sessions directory for --report resolution")
    report_attack_review.add_argument("--output", help="Optional output file path (default: stdout)")
    report_attack_review.set_defaults(handler=_run_report_attack_review)

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

    session_export_targets = session_sub.add_parser(
        "export-targets",
        help="Export a single-session structured target bundle and endpoint lists from a session.",
    )
    session_export_targets.add_argument("--session", required=True, help="Path to session_*.json")
    session_export_targets.add_argument("--output-dir", help="Optional artifact output directory")
    session_export_targets.add_argument("--ttl-days", type=int, default=7, help="Manifest TTL days")
    session_export_targets.add_argument("--max-records", type=int, default=500, help="Maximum exported targets")
    session_export_targets.add_argument("--overwrite", action="store_true", help="Overwrite existing artifacts")
    session_export_targets.set_defaults(handler=_run_session_export_targets)

    session_endpoints = session_sub.add_parser(
        "endpoints",
        help="List extracted single-session endpoints from a session.",
    )
    session_endpoints.add_argument("--session", required=True, help="Path to session_*.json")
    session_endpoints.add_argument("--host", help="Optional host filter")
    session_endpoints.add_argument("--category", help="Optional endpoint category filter")
    session_endpoints.add_argument("--method", help="Optional HTTP method filter")
    session_endpoints.add_argument("--limit", type=int, help="Optional endpoint cap")
    session_endpoints.set_defaults(handler=_run_session_endpoints)

    findings_parser = top.add_parser("findings", help="Cross-session findings repository operations")
    findings_sub = findings_parser.add_subparsers(dest="action", required=True)

    findings_list = findings_sub.add_parser(
        "list",
        help="List stored findings from FindingsRepository.",
    )
    findings_list.add_argument("--db-path", help="Optional FindingsRepository SQLite path")
    findings_list.add_argument("--limit", type=int, default=100, help="Maximum findings to return")
    findings_list.add_argument("--offset", type=int, default=0, help="Offset for paginated reads")
    findings_list.add_argument(
        "--order-by",
        default="created_at",
        choices=["created_at", "updated_at", "severity", "vuln_type", "target_url"],
        help="Ordering column",
    )
    findings_list.add_argument("--asc", action="store_true", help="Sort ascending instead of descending")
    findings_list.set_defaults(handler=_run_findings_list)

    findings_search = findings_sub.add_parser(
        "search",
        help="Search FindingsRepository records with server-side filters.",
    )
    findings_search.add_argument("--db-path", help="Optional FindingsRepository SQLite path")
    findings_search.add_argument("--severity", help="Optional severity filter")
    findings_search.add_argument("--vuln-type", help="Optional vulnerability type filter")
    findings_search.add_argument("--target", help="Optional target URL/host substring filter")
    findings_search.add_argument("--source-agent", help="Optional source agent filter")
    findings_search.add_argument("--verified-only", action="store_true", help="Return only verified findings")
    findings_search.add_argument("--limit", type=int, default=100, help="Maximum findings to return")
    findings_search.set_defaults(handler=_run_findings_search)

    findings_stats = findings_sub.add_parser(
        "stats",
        help="Return aggregate counts from FindingsRepository.",
    )
    findings_stats.add_argument("--db-path", help="Optional FindingsRepository SQLite path")
    findings_stats.set_defaults(handler=_run_findings_stats)

    findings_export_targets = findings_sub.add_parser(
        "export-targets",
        help="Export a cross-session structured target bundle from FindingsRepository.",
    )
    findings_export_targets.add_argument("--db-path", help="Optional FindingsRepository SQLite path")
    findings_export_targets.add_argument("--severity", help="Optional severity filter")
    findings_export_targets.add_argument("--vuln-type", help="Optional vulnerability type filter")
    findings_export_targets.add_argument("--target", help="Optional target URL/host substring filter")
    findings_export_targets.add_argument("--source-agent", help="Optional source agent filter")
    findings_export_targets.add_argument("--verified-only", action="store_true", help="Return only verified findings")
    findings_export_targets.add_argument("--allowed-host", action="append", help="Explicit allowed host (repeatable)")
    findings_export_targets.add_argument("--output-dir", help="Optional artifact output directory")
    findings_export_targets.add_argument("--ttl-days", type=int, default=7, help="Manifest TTL days")
    findings_export_targets.add_argument("--max-records", type=int, default=500, help="Maximum exported targets")
    findings_export_targets.add_argument("--overwrite", action="store_true", help="Overwrite existing artifacts")
    findings_export_targets.set_defaults(handler=_run_findings_export_targets)

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
    runtime_control_gate.add_argument(
        "--phase",
        default="generic",
        choices=["generic", "phase9"],
        help="Gate evaluation phase. 'phase9' routes to Phase 9 specific evaluator with extended metrics.",
    )
    runtime_control_gate.set_defaults(handler=_run_runtime_control_gate)

    # SGK-2026-0422: separated VDP quality gates (training | real).
    vdp_parser = top.add_parser("vdp", help="VDP quality gate operations")
    vdp_sub = vdp_parser.add_subparsers(dest="action", required=True)

    vdp_gate = vdp_sub.add_parser(
        "gate",
        help=(
            "Evaluate the separated VDP quality gate. "
            "--profile training requires --labels; --profile real accepts "
            "an optional --report and only continues when consistency is "
            "consistent."
        ),
    )
    vdp_gate.add_argument(
        "--profile",
        required=True,
        choices=["training", "real"],
        help="Gate profile: training capability gate or real VDP run-quality gate.",
    )
    vdp_gate.add_argument("--session", help="Path to session_*.json (required)")
    vdp_gate.add_argument("--report", help="Optional haddix_report_*.md path (real profile)")
    vdp_gate.add_argument("--sessions-dir", help="Optional sessions directory for --report")
    vdp_gate.add_argument(
        "--vdp-key-registry",
        help=(
            "Optional VDP key registry JSON (public keys only) so confirmed "
            "proofs are verified (SGK-2026-0423 close-out)."
        ),
    )
    vdp_gate.add_argument(
        "--labels",
        help="Label manifest (fixture-manifest JSON) — REQUIRED for the training profile.",
    )
    vdp_gate.set_defaults(handler=_run_vdp_gate)

    # SGK-2026-0425 M2: read-only artifact-only first-failure diagnosis.
    # NO --labels / ground-truth argument (plan §11 test 24).
    vdp_diagnose = vdp_sub.add_parser(
        "diagnose",
        help=(
            "Read-only artifact-only first-failure diagnosis of a session's "
            "vdp_diagnostics_v1 telemetry. When --report is given the "
            "official consistency checker always runs first and any verdict "
            "other than consistent blocks the artifact."
        ),
    )
    vdp_diagnose.add_argument("--session", required=True, help="Path to session_*.json")
    vdp_diagnose.add_argument(
        "--report",
        help="Optional haddix_report_*.md path — consistency checker runs first.",
    )
    vdp_diagnose.add_argument(
        "--output",
        required=True,
        help="Path for the JSON diagnostic artifact (atomic write, overwrite-protected).",
    )
    vdp_diagnose.add_argument(
        "--vdp-key-registry",
        help="Optional VDP key registry JSON (public keys only) for proof verification.",
    )
    vdp_diagnose.set_defaults(handler=_run_vdp_diagnose)

    ops_parser = top.add_parser("ops", help="Operational hardening helpers")
    ops_sub = ops_parser.add_subparsers(dest="action", required=True)

    ops_intent = ops_sub.add_parser(
        "intent",
        help="Translate natural-language operator intent into an allowlisted preview and optional execution flow.",
    )
    ops_intent.add_argument("--intent", required=True, help="Natural-language operator request")
    ops_intent.add_argument("--target", help="Optional target URL for main.* commands")
    ops_intent.add_argument("--report", help="Optional report path used as source context")
    ops_intent.add_argument("--session", help="Optional session path used as source context")
    ops_intent.add_argument("--sessions-dir", help="Optional sessions directory for --report resolution")
    ops_intent.add_argument("--attack-targets", help="Optional structured target file path")
    ops_intent.add_argument("--wordlist", help="Optional wordlist path for attack intents")
    ops_intent.add_argument("--mode", default="bugbounty", help="Execution mode for main.* commands")
    ops_intent.add_argument("--output-dir", help="Optional preview/export directory")
    ops_intent.add_argument("--python", help="Python executable for main.* commands")
    ops_intent.add_argument("--ttl-days", type=int, default=7, help="Manifest TTL days when export is needed")
    ops_intent.add_argument("--max-records", type=int, default=500, help="Maximum export records when export is needed")
    ops_intent.add_argument("--main-dry-run", action="store_true", help="Append --dry-run to main.* execution steps")
    ops_intent.add_argument("--execute", action="store_true", help="Execute the translated flow after preview")
    ops_intent.add_argument("--approve", action="store_true", help="Skip the interactive confirmation prompt")
    ops_intent.set_defaults(handler=_run_ops_intent, domain="ops", action="intent")

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

    recon_parser = top.add_parser("recon", help="Recon pipeline state and diff operations")
    recon_sub = recon_parser.add_subparsers(dest="action", required=True)

    recon_status = recon_sub.add_parser(
        "status",
        help="Show recon checkpoint/resume status for a target.",
    )
    recon_status.add_argument(
        "--state",
        required=True,
        help="Path to recon_state.json",
    )
    recon_status.add_argument(
        "--target",
        help="Target to verify fingerprint match",
        default="",
    )
    recon_status.set_defaults(handler=_run_recon_status, domain="recon", action="status")

    recon_diff = recon_sub.add_parser(
        "diff",
        help="Show diff between two recon_state.json snapshots.",
    )
    recon_diff.add_argument(
        "--prev",
        required=True,
        help="Path to previous recon_state.json (diff base)",
    )
    recon_diff.add_argument(
        "--current",
        help="Path to current recon_state.json (default: same as --prev)",
    )
    recon_diff.add_argument(
        "--target",
        help="Target to verify fingerprint match on prev state",
        default="",
    )
    recon_diff.set_defaults(handler=_run_recon_diff, domain="recon", action="diff")

    return parser


def _run_recon_status(args: argparse.Namespace) -> int:
    """Handle 'recon status' subcommand."""
    from src.recon.pipeline import ReconState, _compute_target_fingerprint as compute_fp

    state_path = Path(args.state)
    target = str(args.target or "").strip()

    payload: dict[str, Any] = {
        "state_path": str(state_path),
        "state_exists": state_path.exists(),
    }

    if not state_path.exists():
        payload["can_resume"] = False
        payload["reason_code"] = "no_state_file"
        payload["reason_message"] = "State file not found."
    else:
        try:
            state = ReconState.load(state_path)
            payload["schema_version"] = state.schema_version
            payload["saved_at"] = state.saved_at
            payload["run_id"] = state.run_id
            payload["current_step"] = state.current_step
            payload["last_completed_step"] = state.last_completed_step
            payload["completed_steps"] = state.completed_steps
            payload["target"] = state.target
            payload["target_fingerprint"] = state.target_fingerprint
            payload["reason_codes"] = list(state.reason_codes)
            payload["all_subs_count"] = len(state.all_subs)
            payload["live_subs_count"] = len(state.live_subs)
            payload["dead_subs_count"] = len(state.dead_subs)
            payload["screenshots_count"] = state.screenshots_count
            payload["tech_stack"] = state.tech_stack
            payload["resume_source"] = state.resume_source
            payload["diff_base_run_id"] = state.diff_base_run_id
            payload["checkpoint_healthy"] = (
                state.schema_version >= 1
                and state.saved_at
                and state.run_id
                and state.current_step > 0
            )

            if target:
                expected_fp = compute_fp(target)
                payload["target_match"] = state.target_fingerprint == expected_fp

            # Resume assessment
            verdict = ReconState.validate_for_resume(state_path, target or state.target)
            payload["can_resume"] = verdict["can_resume"]
            payload["reason_code"] = verdict["reason_code"]
            payload["reason_message"] = verdict["reason_message"]
            payload["next_step"] = verdict["next_step"]
        except Exception as e:
            payload["can_resume"] = False
            payload["reason_code"] = "corrupt_state"
            payload["reason_message"] = f"Cannot parse state file: {e}"

    _emit_command_payload(args, payload)
    return 0 if payload.get("can_resume", False) else 3


def _run_recon_diff(args: argparse.Namespace) -> int:
    """Handle 'recon diff' subcommand."""
    from src.recon.pipeline import ReconState, compute_recon_diff

    prev_path = Path(args.prev)
    curr_path = Path(args.current) if args.current else prev_path
    target = str(args.target or "").strip()

    payload: dict[str, Any] = {
        "prev_path": str(prev_path),
        "current_path": str(curr_path),
    }

    if not prev_path.exists():
        payload["error"] = f"Previous state file not found: {prev_path}"
        _emit_command_payload(args, payload)
        return 3

    if not curr_path.exists():
        payload["error"] = f"Current state file not found: {curr_path}"
        _emit_command_payload(args, payload)
        return 3

    try:
        prev_state = ReconState.load(prev_path)
        curr_state = ReconState.load(curr_path)

        if target and prev_state.target_fingerprint:
            from src.recon.pipeline import _compute_target_fingerprint as compute_fp
            expected_fp = compute_fp(target)
            if prev_state.target_fingerprint != expected_fp:
                payload["warning"] = (
                    f"Previous state target fingerprint mismatch: "
                    f"prev={prev_state.target_fingerprint[:8]}..., "
                    f"expected={expected_fp[:8]}..."
                )

        diff = compute_recon_diff(prev_state, curr_state)
        payload.update(diff)
    except Exception as e:
        payload["error"] = f"Diff computation failed: {e}"

    _emit_command_payload(args, payload)
    return 0


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
