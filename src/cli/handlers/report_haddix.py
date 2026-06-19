"""report/haddix functions extracted from src.main.

Extracted from src/main.py lines 289-1385.
All functions have leading underscores removed from their names.
Internal calls updated to use the new public names.
"""

import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Any
import logging

from src.commands import print_banner, print_step, print_result
from src.config import settings

from src.cli.handlers.report_haddix_evidence import (
    coerce_finding_dict,
    first_non_empty_string,
    clip_http_text,
    synthesize_request_raw_from_evidence,
    synthesize_response_raw_from_evidence,
    build_replay_command_for_finding,
    build_detector_signals,
    materialize_haddix_evidence_artifacts,
)
from src.cli.handlers.report_haddix_coverage import (
    enable_debug_mode,
    extract_scn_number,
    normalize_scenario_id_for_report,
    resolve_scn_catalog_for_report,
    build_scenario_coverage_for_report,
    build_heuristic_findings_from_execution_notes,
    finding_signature_for_merge,
    merge_heuristic_candidates_into_findings,
)

logger = logging.getLogger(__name__)


def run_haddix_report_generation(session_file: str, args: argparse.Namespace) -> None:
    try:
        from src.reporting.haddix_formatter import generate_haddix_report
        from src.reporting.initial_release_gate import (
            DEFAULT_ALLOWED_MISSING_SCENARIOS,
            evaluate_initial_release_gate,
        )
        from src.core.utils.json_utils import safe_json_loads

        # セッションデータを読み込み
        raw_text = Path(session_file).read_text(encoding="utf-8")
        session_data = safe_json_loads(raw_text, context="haddix_gen")

        # Findingsを抽出 (completed_tasksの中からvuln情報があるものを探す)
        all_tasks = session_data.get("completed_tasks", [])
        haddix_findings = []
        execution_notes = []

        for task in all_tasks:
            task_result = task.get("result", {}) if isinstance(task, dict) else {}
            task_data = task_result.get("data", {}) if isinstance(task_result, dict) else {}

            task_findings = task_result.get("findings", []) if isinstance(task_result, dict) else []
            if not task_findings and isinstance(task_data, dict):
                task_findings = task_data.get("findings", [])

            if not task_findings and isinstance(task_data, dict):
                single_finding = task_data.get("finding")
                if single_finding:
                    task_findings = [single_finding]

            if not task_findings and isinstance(task_result, dict):
                single_finding = task_result.get("finding")
                if single_finding:
                    task_findings = [single_finding]

            if not task_findings and isinstance(task_result, dict) and "vulnerability" in task_result:
                task_findings = [task_result.get("vulnerability")]

            task_exec_log = task_data.get("execution_log", []) if isinstance(task_data, dict) else []
            if isinstance(task_exec_log, list):
                for log_entry in task_exec_log:
                    if not isinstance(log_entry, dict):
                        continue
                    url_results = log_entry.get("url_results", [])
                    if not isinstance(url_results, list):
                        continue
                    for item in url_results:
                        if not isinstance(item, dict):
                            continue
                        tested_params = item.get("tested_params", [])
                        blind_correlation = item.get("blind_correlation", {})
                        status = str(item.get("status", ""))
                        status_lower = status.lower()
                        retry_count = int(item.get("retry_count", 0) or 0)
                        duration_seconds = item.get("duration_seconds")
                        has_blind_evidence = bool(blind_correlation) and (
                            bool(blind_correlation.get("correlated"))
                            or bool((blind_correlation.get("time_based") or {}).get("confirmed"))
                            or bool((blind_correlation.get("oob") or {}).get("confirmed"))
                        )
                        should_keep_for_kpi = status_lower in {"completed", "cache_hit", "timeout", "error"}
                        if not tested_params and not has_blind_evidence and not should_keep_for_kpi and retry_count <= 0 and duration_seconds is None:
                            continue
                        execution_notes.append({
                            "url": item.get("url", ""),
                            "vuln_type": item.get("vuln_type", ""),
                            "status": status,
                            "duration_seconds": duration_seconds,
                            "retry_count": retry_count,
                            "tested_params": tested_params,
                            "probe_sent": item.get("probe_sent"),
                            "probe_skipped_reason": item.get("probe_skipped_reason", ""),
                            "poc_request": item.get("poc_request", ""),
                            "poc_response": item.get("poc_response", ""),
                            "blind_correlation": blind_correlation,
                        })

            for f in task_findings:
                if f:
                    haddix_findings.append(f)

        if not haddix_findings:
            # session_data直下にfindingsがある場合も考慮 (システム構成に依存)
            haddix_findings = session_data.get("findings", [])

        if not haddix_findings:
            # 途中経過のみ保存されたFindingもレポート対象に含める
            partial_findings = session_data.get("partial_findings", [])
            if isinstance(partial_findings, list):
                haddix_findings = [f for f in partial_findings if f]

        scenario_coverage = build_scenario_coverage_for_report(session_data)
        vulnerability_family_coverage: dict[str, Any] = {}
        raw_coverage_gate = session_data.get("coverage_gate")
        if not isinstance(raw_coverage_gate, dict):
            session_context = session_data.get("context", {})
            if isinstance(session_context, dict):
                raw_coverage_gate = session_context.get("coverage_gate") or session_context.get("vulnerability_family_coverage")
        if isinstance(raw_coverage_gate, dict):
            vulnerability_family_coverage = raw_coverage_gate
        report_target = session_data.get("goal_target", args.target)

        heuristic_budget = int(getattr(settings, "report_heuristic_max_candidates", 6) or 6)
        if haddix_findings:
            heuristic_budget = min(
                heuristic_budget,
                int(getattr(settings, "report_heuristic_append_when_confirmed", 3) or 3),
            )
        heuristic_promote_privilege_probe_min = max(
            1,
            int(getattr(settings, "report_heuristic_promote_privilege_probe_min", 2) or 2),
        )
        heuristic_promote_completed_probe_min = max(
            1,
            int(getattr(settings, "report_heuristic_promote_completed_probe_min", 2) or 2),
        )

        heuristic_candidates = build_heuristic_findings_from_execution_notes(
            execution_notes,
            target=report_target,
            scenario_coverage=scenario_coverage,
            max_candidates=max(0, heuristic_budget),
            promote_privilege_probe_min=heuristic_promote_privilege_probe_min,
            promote_completed_probe_min=heuristic_promote_completed_probe_min,
        )
        if heuristic_candidates:
            if haddix_findings:
                before_len = len(haddix_findings)
                merged = merge_heuristic_candidates_into_findings(
                    confirmed_findings=haddix_findings,
                    heuristic_candidates=heuristic_candidates,
                    max_append=max(0, heuristic_budget),
                )
                appended = max(0, len(merged) - before_len)
                if appended > 0:
                    haddix_findings = merged
                    print_step(
                        "\U0001f9ea",
                        f"Appended {appended} heuristic candidate finding(s) from execution telemetry",
                    )
            else:
                haddix_findings = heuristic_candidates
                print_step(
                    "\U0001f9ea",
                    f"Promoted {len(heuristic_candidates)} heuristic candidate finding(s) from execution telemetry",
                )

        # report-only 経路でも重複排除を適用（特に file_upload の大量重複を統合）
        try:
            from src.core.deduplication.finding_deduplicator import deduplicate_findings
            from src.core.models.finding import Finding, VulnType, Severity

            finding_objects = []
            for raw in haddix_findings:
                if isinstance(raw, Finding):
                    finding_objects.append(raw)
                    continue
                if not isinstance(raw, dict):
                    continue

                vuln_raw = str(raw.get("vuln_type", raw.get("type", "other"))).lower()
                sev_raw = str(raw.get("severity", "low")).lower()

                try:
                    vuln_type = VulnType(vuln_raw)
                except Exception:
                    vuln_type = VulnType.OTHER

                try:
                    severity = Severity(sev_raw)
                except Exception:
                    severity = Severity.LOW

                confidence_raw = raw.get("confidence", 0.0)
                try:
                    confidence = float(confidence_raw)
                except Exception:
                    confidence = 0.0

                finding_objects.append(Finding(
                    vuln_type=vuln_type,
                    severity=severity,
                    title=raw.get("title", "Unknown Vulnerability"),
                    description=raw.get("description", raw.get("summary", "")),
                    target_url=raw.get("target_url", raw.get("target", raw.get("url", report_target))),
                    target_program=raw.get("target_program", session_data.get("program_name", "")),
                    evidence=raw.get("evidence", {}),
                    reproduction_steps=raw.get("reproduction_steps", raw.get("steps_to_reproduce", [])),
                    impact=raw.get("impact", ""),
                    source_agent=raw.get("source_agent", raw.get("discovered_by", "")),
                    confidence=confidence,
                    additional_info=raw.get("additional_info", {}),
                    cwe_id=raw.get("cwe_id"),
                    cvss_score=raw.get("cvss_score"),
                ))

            if len(finding_objects) > 1:
                deduped = deduplicate_findings(finding_objects)
                if len(deduped) < len(finding_objects):
                    logger.info("Report dedup applied: %d -> %d", len(finding_objects), len(deduped))
                haddix_findings = [f.to_dict() for f in deduped]
        except Exception as _dedup_error:
            logger.warning("Report dedup skipped: %s", _dedup_error)

        # 出力パスの決定
        output_dir = Path(session_file).parent.parent / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = output_dir / f"haddix_report_{timestamp}.md"
        gate_output_path = output_dir / f"haddix_gate_{timestamp}.json"
        deferred_output_path = output_dir / f"haddix_deferred_{timestamp}.json"
        evidence_output_dir = output_dir / f"haddix_evidence_{timestamp}"

        haddix_findings, evidence_artifact_paths = materialize_haddix_evidence_artifacts(
            findings=haddix_findings,
            evidence_dir=evidence_output_dir,
            captured_at=datetime.now().isoformat(timespec="seconds"),
        )
        if evidence_artifact_paths:
            print_step(
                "\U0001f9fe",
                f"Saved finding evidence artifacts: {len(evidence_artifact_paths)} -> {evidence_output_dir.resolve()}",
            )

        generate_haddix_report(
            findings=haddix_findings,
            target=report_target,
            output_path=output_path,
            program_name=session_data.get("program_name", ""),
            execution_notes=execution_notes,
            scenario_coverage=scenario_coverage,
            vulnerability_family_coverage=vulnerability_family_coverage,
            initial_release_gate={},
            source_session=str(Path(session_file).resolve()),
        )

        raw_allowed_missing = getattr(
            settings,
            "report_initial_release_allowed_missing_scenarios",
            ",".join(DEFAULT_ALLOWED_MISSING_SCENARIOS),
        )
        if isinstance(raw_allowed_missing, list):
            allowed_missing_scenarios = [
                str(token or "").strip()
                for token in raw_allowed_missing
                if str(token or "").strip()
            ]
        else:
            allowed_missing_scenarios = [
                str(token or "").strip()
                for token in str(raw_allowed_missing or "").split(",")
                if str(token or "").strip()
            ]
        if not allowed_missing_scenarios:
            allowed_missing_scenarios = list(DEFAULT_ALLOWED_MISSING_SCENARIOS)

        raw_required_classes = getattr(
            settings,
            "report_initial_release_required_confirmed_classes",
            "",
        )
        if isinstance(raw_required_classes, list):
            required_confirmed_classes = [
                str(token or "").strip()
                for token in raw_required_classes
                if str(token or "").strip()
            ]
        else:
            required_confirmed_classes = [
                str(token or "").strip()
                for token in str(raw_required_classes or "").split(",")
                if str(token or "").strip()
            ]

        baseline_report_path_raw = str(
            getattr(settings, "report_initial_release_baseline_report_path", "") or ""
        ).strip()
        baseline_session_path_raw = str(
            getattr(settings, "report_initial_release_baseline_session_path", "") or ""
        ).strip()
        baseline_report_path = (
            Path(baseline_report_path_raw).expanduser().resolve()
            if baseline_report_path_raw
            else None
        )
        baseline_session_path = (
            Path(baseline_session_path_raw).expanduser().resolve()
            if baseline_session_path_raw
            else None
        )

        gate_result = evaluate_initial_release_gate(
            output_path,
            session_path=Path(session_file),
            baseline_report_path=baseline_report_path,
            baseline_session_path=baseline_session_path,
            allowed_missing_scenarios=allowed_missing_scenarios,
            confirmed_min=max(
                0,
                int(getattr(settings, "report_initial_release_confirmed_min", 3) or 3),
            ),
            candidate_max=max(
                0,
                int(getattr(settings, "report_initial_release_candidate_max", 2) or 2),
            ),
            confirmed_poc_missing_max=max(
                0,
                int(getattr(settings, "report_initial_release_confirmed_poc_missing_max", 0) or 0),
            ),
            reason_code_missing_max=max(
                0,
                int(getattr(settings, "report_initial_release_reason_code_missing_max", 0) or 0),
            ),
            required_confirmed_classes=required_confirmed_classes,
            required_class_confirmed_min=max(
                0,
                int(
                    getattr(
                        settings,
                        "report_initial_release_required_class_confirmed_min",
                        1,
                    )
                    or 1
                ),
            ),
        )

        generate_haddix_report(
            findings=haddix_findings,
            target=report_target,
            output_path=output_path,
            program_name=session_data.get("program_name", ""),
            execution_notes=execution_notes,
            scenario_coverage=scenario_coverage,
            vulnerability_family_coverage=vulnerability_family_coverage,
            initial_release_gate=gate_result,
            source_session=str(Path(session_file).resolve()),
        )
        gate_output_path.write_text(
            json.dumps(gate_result, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        deferred_scenarios = gate_result.get("deferred_scenarios", [])
        if isinstance(deferred_scenarios, list) and deferred_scenarios:
            deferred_payload = {
                "report_path": str(output_path.resolve()),
                "gate_path": str(gate_output_path.resolve()),
                "generated_at": datetime.now().isoformat(timespec="seconds"),
                "deferred_scenarios": deferred_scenarios,
            }
            deferred_output_path.write_text(
                json.dumps(deferred_payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

        abs_path = output_path.resolve()
        print_result(True, f"jHADDIX Style Report generated: [bold cyan]{abs_path}[/bold cyan]")
        print_step("\U0001f6a6", f"Initial-release gate verdict saved: {gate_output_path.resolve()}")
        if isinstance(deferred_scenarios, list) and deferred_scenarios:
            print_step("\U0001f5c2\ufe0f", f"Deferred scenario backlog saved: {deferred_output_path.resolve()}")

        gate_status = str(gate_result.get("status", "") or "").strip().upper() or "UNKNOWN"
        reason_codes = gate_result.get("reason_codes", [])
        reason_codes_text = ", ".join(str(code) for code in reason_codes) if reason_codes else "-"
        print_step("\U0001f6a6", f"Initial-release gate: {gate_status} (reason_codes={reason_codes_text})")

        recommended_actions = gate_result.get("recommended_actions", [])
        if isinstance(recommended_actions, list) and recommended_actions:
            for action in recommended_actions[:5]:
                if not isinstance(action, dict):
                    continue
                action_id = str(action.get("id", "") or "action")
                priority = str(action.get("priority", "") or "medium").lower()
                summary = str(action.get("summary", "") or "").strip()
                command_hint = str(action.get("command_hint", "") or "").strip()
                print_step(
                    "\U0001f9ed",
                    f"[{priority}] {action_id}: {summary}" if summary else f"[{priority}] {action_id}",
                )
                if command_hint:
                    print(f"   \u2514\u2500 {command_hint}")

        if not Path("/.dockerenv").exists():
            print(f"\U0001f4a1 You can view the markdown report at: {abs_path}")

    except Exception as e:
        print_result(False, f"Failed to generate jHADDIX report: {e}")
        import traceback
        logger.error(traceback.format_exc())
