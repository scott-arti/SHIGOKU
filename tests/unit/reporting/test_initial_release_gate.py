from __future__ import annotations

import json
from pathlib import Path

from src.reporting.initial_release_gate import (
    evaluate_gate_separated,
    evaluate_initial_release_gate,
    set_locked_baseline,
)


def _write_session(
    path: Path,
    *,
    covered: int,
    required: int,
    missing: list[str],
    family_gate_passed: bool = True,
    coverage_items: list[dict[str, object]] | None = None,
    completed_tasks: list[dict[str, object]] | None = None,
    security_level: str = "",
) -> None:
    payload = {
        "completed_tasks": completed_tasks or ([{"params": {"cookies": f"security={security_level}"}}] if security_level else []),
        "task_queue": [],
        "scenario_coverage": {
            "covered_count": covered,
            "required_count": required,
            "missing_scenarios": missing,
            "coverage_items": coverage_items or [],
        },
        "context": {
            "coverage_gate": {
                "missing_families": [] if family_gate_passed else ["xss"],
            }
        },
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _write_report(
    path: Path,
    *,
    source_session: str,
    coverage_line: str,
    family_gate_line: str,
    findings_line: str,
    confirmed_poc_missing_line: str = "Confirmed PoC Missing: 0",
    candidate_reason_missing_line: str = "Candidate Reason-Code Missing: 0",
    findings_class_rows: list[tuple[str, int, int, int]] | None = None,
) -> None:
    lines = [
        "# 🔒 Vulnerability Report",
        "",
        "**Target:** http://127.0.0.1:8888/",
        "**Generated:** 2026-04-21 04:46:14",
    ]
    if source_session:
        lines.append(f"**Source Session:** {source_session}")
    lines.extend(
        [
            "**Tool:** SHIGOKU - Sovereign VAPT Engine",
            "",
            "## 🧪 Scenario Coverage (SCN01-12)",
            "",
            coverage_line,
            "",
            "## 🧱 Vulnerability Family Coverage Gate",
            "",
            family_gate_line,
            "",
            "## 🐛 Findings",
            "",
            findings_line,
            confirmed_poc_missing_line,
            candidate_reason_missing_line,
            "",
        ]
    )
    if findings_class_rows:
        lines.extend(
            [
                "### Findings by Vulnerability Class",
                "",
                "| Vulnerability Class | Confirmed | Candidate | Total |",
                "|---------------------|-----------|-----------|-------|",
            ]
        )
        for vuln_class, confirmed_count, candidate_count, total_count in findings_class_rows:
            lines.append(
                f"| {vuln_class} | {confirmed_count} | {candidate_count} | {total_count} |"
            )
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def test_initial_release_gate_passes_with_allowed_missing_only(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    missing = [
        "scn_10_semantic_business_logic",
        "scn_12_advanced_ssrf_internal_topology",
    ]
    _write_session(session_file, covered=10, required=12, missing=missing)

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 3 / Candidate: 0",
    )

    verdict = evaluate_initial_release_gate(report_file)
    assert verdict["status"] == "pass"
    assert verdict["gate_passed"] is True
    assert verdict["reason_codes"] == []
    assert verdict["policy"]["notes"]
    assert any("SCN08/SCN10/SCN12" in note for note in verdict["policy"]["notes"])
    actions = verdict.get("recommended_actions", [])
    assert isinstance(actions, list)
    assert any(action.get("id") == "proceed_release_candidate" for action in actions)
    assert any(action.get("id") == "run_deferred_scenario_track" for action in actions)
    deferred = verdict.get("deferred_scenarios", [])
    deferred_ids = {str(item.get("scenario_id", "")) for item in deferred if isinstance(item, dict)}
    assert deferred_ids == {
        "scn_10_semantic_business_logic",
        "scn_12_advanced_ssrf_internal_topology",
    }


def test_initial_release_gate_default_policy_allows_scn08_10_12_for_ver1x(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    missing = [
        "scn_08_oob_external_channel_flow",
        "scn_10_semantic_business_logic",
        "scn_12_advanced_ssrf_internal_topology",
    ]
    _write_session(session_file, covered=9, required=12, missing=missing)

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line=(
            "Coverage: 9/12 (75.0%), Missing: scn_08_oob_external_channel_flow, "
            "scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology"
        ),
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 3 / Candidate: 0",
    )

    verdict = evaluate_initial_release_gate(report_file)
    assert verdict["status"] == "pass"
    assert "unexpected_missing_scenarios" not in verdict["reason_codes"]
    assert any("SCN08/SCN10/SCN12" in note for note in verdict["policy"]["notes"])

    deferred = verdict.get("deferred_scenarios", [])
    deferred_ids = {str(item.get("scenario_id", "")) for item in deferred if isinstance(item, dict)}
    assert deferred_ids == {
        "scn_08_oob_external_channel_flow",
        "scn_10_semantic_business_logic",
        "scn_12_advanced_ssrf_internal_topology",
    }


def test_initial_release_gate_pass_action_uses_effective_policy_values(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    missing = [
        "scn_08_oob_external_channel_flow",
        "scn_10_semantic_business_logic",
    ]
    _write_session(session_file, covered=10, required=12, missing=missing)

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_08_oob_external_channel_flow, scn_10_semantic_business_logic",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 5 / Candidate: 1",
        findings_class_rows=[
            ("broken_access_control", 2, 0, 2),
            ("mass_assignment", 3, 0, 3),
        ],
    )

    verdict = evaluate_initial_release_gate(
        report_file,
        allowed_missing_scenarios=[
            "scn_08_oob_external_channel_flow",
            "scn_10_semantic_business_logic",
            "scn_12_advanced_ssrf_internal_topology",
        ],
        confirmed_min=5,
        candidate_max=1,
        confirmed_poc_missing_max=0,
        reason_code_missing_max=0,
        required_confirmed_classes=["access_control", "mass_assignment"],
        required_class_confirmed_min=1,
    )

    assert verdict["status"] == "pass"
    actions = verdict.get("recommended_actions", [])
    proceed_action = next(
        (action for action in actions if isinstance(action, dict) and action.get("id") == "proceed_release_candidate"),
        None,
    )
    assert isinstance(proceed_action, dict)
    command_hint = str(proceed_action.get("command_hint", ""))
    assert "--allowed-missing scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology" in command_hint
    assert "--confirmed-min 5" in command_hint
    assert "--candidate-max 1" in command_hint
    assert "--confirmed-poc-missing-max 0" in command_hint
    assert "--reason-code-missing-max 0" in command_hint
    assert "--required-confirmed-classes access_control,mass_assignment" in command_hint
    assert "--required-class-confirmed-min 1" in command_hint


def test_initial_release_gate_fails_for_unexpected_missing_scenarios(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    missing = [
        "scn_03_injection_input_tampering",
        "scn_10_semantic_business_logic",
    ]
    _write_session(session_file, covered=10, required=12, missing=missing)

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_03_injection_input_tampering, scn_10_semantic_business_logic",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 3 / Candidate: 0",
    )

    verdict = evaluate_initial_release_gate(report_file)
    assert verdict["status"] == "fail"
    assert "unexpected_missing_scenarios" in verdict["reason_codes"]
    assert verdict["report_metrics"]["unexpected_missing_scenarios"] == ["scn_03_injection_input_tampering"]


def test_initial_release_gate_fails_when_family_gate_not_passed(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    missing = [
        "scn_10_semantic_business_logic",
        "scn_12_advanced_ssrf_internal_topology",
    ]
    _write_session(session_file, covered=10, required=12, missing=missing, family_gate_passed=False)

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: FAIL, Coverage: 6/7 (85.7%), Missing: xss",
        findings_line="Confirmed: 3 / Candidate: 0",
    )

    verdict = evaluate_initial_release_gate(report_file)
    assert verdict["status"] == "fail"
    assert "family_gate_not_passed" in verdict["reason_codes"]


def test_initial_release_gate_fails_when_finding_thresholds_not_met(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    missing = [
        "scn_10_semantic_business_logic",
        "scn_12_advanced_ssrf_internal_topology",
    ]
    _write_session(session_file, covered=10, required=12, missing=missing)

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 1 / Candidate: 1",
    )

    verdict = evaluate_initial_release_gate(report_file)
    assert verdict["status"] == "fail"
    assert "confirmed_below_minimum" in verdict["reason_codes"]
    assert "candidate_above_maximum" not in verdict["reason_codes"]
    actions = verdict.get("recommended_actions", [])
    action_ids = {str(action.get("id", "")) for action in actions if isinstance(action, dict)}
    assert "increase_confirmed_density" in action_ids
    assert "drain_candidate_queue" not in action_ids


def test_initial_release_gate_exposes_findings_class_summary_and_baseline_diff(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    baseline_session = sessions_dir / "session_20260421_044611.json"
    baseline_missing = [
        "scn_10_semantic_business_logic",
        "scn_12_advanced_ssrf_internal_topology",
    ]
    _write_session(baseline_session, covered=10, required=12, missing=baseline_missing)

    baseline_report = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        baseline_report,
        source_session=str(baseline_session.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 3 / Candidate: 0",
        findings_class_rows=[
            ("broken_access_control", 1, 0, 1),
            ("mass_assignment", 2, 0, 2),
        ],
    )

    current_session = sessions_dir / "session_20260421_044700.json"
    _write_session(current_session, covered=10, required=12, missing=baseline_missing)
    current_report = reports_dir / "haddix_report_20260421_044701.md"
    _write_report(
        current_report,
        source_session=str(current_session.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 3 / Candidate: 0",
        findings_class_rows=[
            ("broken_access_control", 2, 0, 2),
            ("mass_assignment", 1, 0, 1),
        ],
    )

    verdict = evaluate_initial_release_gate(
        current_report,
        baseline_report_path=baseline_report,
        baseline_session_path=baseline_session,
    )
    assert verdict["status"] == "pass"
    class_summary = verdict["report_metrics"]["findings_class_summary"]
    assert class_summary["confirmed_by_vuln_class"]["broken_access_control"] == 2
    class_diff = verdict["report_metrics"]["baseline_diff"]["finding_classes"]["classes"]
    broken_access_row = next(
        row for row in class_diff if row["vuln_class"] == "broken_access_control"
    )
    assert broken_access_row["confirmed_delta"] == 1


def test_initial_release_gate_fails_when_required_detection_class_is_missing(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    missing = [
        "scn_10_semantic_business_logic",
        "scn_12_advanced_ssrf_internal_topology",
    ]
    _write_session(session_file, covered=10, required=12, missing=missing)

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 3 / Candidate: 0",
        findings_class_rows=[
            ("broken_access_control", 1, 0, 1),
            ("mass_assignment", 2, 0, 2),
        ],
    )

    verdict = evaluate_initial_release_gate(
        report_file,
        required_confirmed_classes=["access_control", "mass_assignment", "endpoint_bfla"],
        required_class_confirmed_min=1,
    )
    assert verdict["status"] == "fail"
    assert "required_detection_class_below_minimum" in verdict["reason_codes"]
    required_eval = verdict["report_metrics"]["required_detection_class_evaluation"]
    assert required_eval["status"] == "fail"
    assert required_eval["missing_classes"] == ["endpoint_bfla"]
    assert required_eval["class_confirmed_counts"]["endpoint_bfla"] == 0
    action_ids = {
        str(action.get("id", ""))
        for action in verdict.get("recommended_actions", [])
        if isinstance(action, dict)
    }
    assert "expand_detection_class_coverage" in action_ids


def test_initial_release_gate_passes_when_required_detection_classes_met(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    missing = [
        "scn_10_semantic_business_logic",
        "scn_12_advanced_ssrf_internal_topology",
    ]
    _write_session(session_file, covered=10, required=12, missing=missing)

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 4 / Candidate: 0",
        findings_class_rows=[
            ("broken_access_control", 1, 0, 1),
            ("mass_assignment", 2, 0, 2),
            ("endpoint_bfla", 1, 0, 1),
        ],
    )

    verdict = evaluate_initial_release_gate(
        report_file,
        required_confirmed_classes=["access_control", "mass_assignment", "endpoint_bfla"],
        required_class_confirmed_min=1,
    )
    assert verdict["status"] == "pass"
    assert verdict["reason_codes"] == []
    required_eval = verdict["report_metrics"]["required_detection_class_evaluation"]
    assert required_eval["status"] == "pass"
    assert required_eval["missing_classes"] == []
    assert required_eval["class_confirmed_counts"]["access_control"] == 1
    assert required_eval["class_confirmed_counts"]["mass_assignment"] == 2
    assert required_eval["class_confirmed_counts"]["endpoint_bfla"] == 1


def test_initial_release_gate_does_not_use_scenario_backfill_for_required_detection_class_gate(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    missing = []
    _write_session(
        session_file,
        covered=12,
        required=12,
        missing=missing,
        coverage_items=[
            {
                "scenario_id": "scn_01_idor_bola_object_access",
                "covered": True,
                "count": 6,
            },
            {
                "scenario_id": "scn_04_endpoint_enumeration_bfla",
                "covered": True,
                "count": 1,
            },
        ],
    )

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 12/12 (100.0%), Missing: -",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 3 / Candidate: 0",
        findings_class_rows=[
            ("broken_access_control", 1, 0, 1),
            ("mass_assignment", 2, 0, 2),
        ],
    )

    verdict = evaluate_initial_release_gate(
        report_file,
        required_confirmed_classes=["access_control", "idor_bola", "mass_assignment", "endpoint_bfla"],
        required_class_confirmed_min=1,
    )
    assert verdict["status"] == "fail"
    assert "required_detection_class_below_minimum" in verdict["reason_codes"]
    required_eval = verdict["report_metrics"]["required_detection_class_evaluation"]
    assert required_eval["status"] == "fail"
    assert required_eval["missing_classes"] == ["idor_bola", "endpoint_bfla"]
    assert required_eval["class_confirmed_counts"]["access_control"] == 1
    assert required_eval["class_confirmed_counts"]["idor_bola"] == 0
    assert required_eval["class_confirmed_counts"]["mass_assignment"] == 2
    assert required_eval["class_confirmed_counts"]["endpoint_bfla"] == 0
    assert required_eval["class_confirmed_counts_with_backfill"]["idor_bola"] == 1
    assert required_eval["class_confirmed_counts_with_backfill"]["endpoint_bfla"] == 1
    scenario_backfill = verdict["report_metrics"]["detection_class_summary"]["scenario_backfill_by_detection_class"]
    assert scenario_backfill["idor_bola"] == 1
    assert scenario_backfill["endpoint_bfla"] == 1


def test_initial_release_gate_uses_session_raw_findings_summary_for_threshold_decision(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    _write_session(
        session_file,
        covered=10,
        required=12,
        missing=[
            "scn_10_semantic_business_logic",
            "scn_12_advanced_ssrf_internal_topology",
        ],
        completed_tasks=[
            {
                "id": "task_1",
                "result": {
                    "findings": [
                        {
                            "title": "Potential Unauthenticated API Access",
                            "target_url": "http://127.0.0.1:8888/chatbot/genai/state?account_id=2",
                            "vuln_type": "broken_access_control",
                            "additional_info": {
                                "detection_class": "endpoint_bfla",
                            },
                        }
                    ]
                },
            },
            {
                "id": "task_2",
                "result": {
                    "findings": [
                        {
                            "title": "Potential Unauthenticated API Access",
                            "target_url": "http://127.0.0.1:8888/chatbot/genai/state?user_id=2",
                            "vuln_type": "broken_access_control",
                            "additional_info": {
                                "detection_class": "endpoint_bfla",
                            },
                        }
                    ]
                },
            },
        ],
    )

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 3 / Candidate: 0",
    )

    verdict = evaluate_initial_release_gate(report_file)
    # With the P3 fix: Finding Policy Gate uses the report's findings summary
    # (Confirmed: 3 / Candidate: 0). The report has 3 >= 3 confirmed, so this
    # passes. Session data (2 confirmed) is preserved in session_findings_summary
    # for evidence quality comparison but does not override the finding policy.
    assert verdict["status"] == "pass"
    assert "confirmed_below_minimum" not in verdict["reason_codes"]
    findings_summary = verdict["report_metrics"]["findings_summary"]
    assert findings_summary["source"] == "report"
    assert findings_summary["confirmed_count"] == 3
    assert findings_summary["candidate_count"] == 0
    assert verdict["report_metrics"]["report_findings_summary"]["confirmed_count"] == 3
    # Session raw data (2 confirmed) is still available but does not override
    assert verdict["report_metrics"]["session_findings_summary"]["confirmed_count"] == 2


def test_initial_release_gate_uses_session_detection_class_for_required_class_decision(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    _write_session(
        session_file,
        covered=10,
        required=12,
        missing=[
            "scn_10_semantic_business_logic",
            "scn_12_advanced_ssrf_internal_topology",
        ],
        completed_tasks=[
            {
                "id": "task_1",
                "result": {
                    "findings": [
                        {
                            "title": "Potential Unauthenticated API Access",
                            "target_url": "http://127.0.0.1:8888/chatbot/genai/state?account_id=2",
                            "vuln_type": "broken_access_control",
                            "additional_info": {
                                "detection_class": "endpoint_bfla",
                            },
                        }
                    ]
                },
            }
        ],
    )

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 3 / Candidate: 0",
        findings_class_rows=[
            ("broken_access_control", 1, 0, 1),
        ],
    )

    verdict = evaluate_initial_release_gate(
        report_file,
        required_confirmed_classes=["endpoint_bfla"],
        required_class_confirmed_min=1,
    )
    required_eval = verdict["report_metrics"]["required_detection_class_evaluation"]
    assert required_eval["decision_source"] == "hybrid_session_raw_detection_class_summary_max"
    assert required_eval["status"] == "pass"
    assert required_eval["class_confirmed_counts"]["endpoint_bfla"] == 1


def test_initial_release_gate_uses_hybrid_detection_class_counts_for_required_class_decision(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    _write_session(
        session_file,
        covered=10,
        required=12,
        missing=[
            "scn_10_semantic_business_logic",
            "scn_12_advanced_ssrf_internal_topology",
        ],
        completed_tasks=[
            {
                "id": "task_1",
                "result": {
                    "findings": [
                        {
                            "title": "Potential Unauthenticated API Access",
                            "target_url": "http://127.0.0.1:8888/chatbot/genai/state?account_id=2",
                            "vuln_type": "broken_access_control",
                            "additional_info": {
                                "detection_class": "endpoint_bfla",
                            },
                        }
                    ]
                },
            }
        ],
    )

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 4 / Candidate: 0",
        findings_class_rows=[
            ("broken_access_control", 1, 0, 1),
            ("idor", 1, 0, 1),
            ("mass_assignment", 2, 0, 2),
        ],
    )

    verdict = evaluate_initial_release_gate(
        report_file,
        required_confirmed_classes=["access_control", "idor_bola", "mass_assignment", "endpoint_bfla"],
        required_class_confirmed_min=1,
    )
    required_eval = verdict["report_metrics"]["required_detection_class_evaluation"]
    assert required_eval["decision_source"] == "hybrid_session_raw_detection_class_summary_max"
    assert required_eval["status"] == "pass"
    assert required_eval["class_confirmed_counts"] == {
        "access_control": 1,
        "idor_bola": 1,
        "mass_assignment": 2,
        "endpoint_bfla": 1,
    }


def test_initial_release_gate_blocks_when_consistency_check_is_blocked(tmp_path: Path) -> None:
    reports_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_file = reports_dir / "haddix_report_20260421_044614.md"

    _write_report(
        report_file,
        source_session="/workspace/projects/__missing_project__/sessions/session_20990101_000000.json",
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 3 / Candidate: 0",
    )

    verdict = evaluate_initial_release_gate(report_file)
    assert verdict["status"] == "blocked"
    assert "consistency_blocked" in verdict["reason_codes"]
    assert "source_session_not_found" in verdict["reason_codes"]
    assert verdict.get("deferred_scenarios", []) == []
    actions = verdict.get("recommended_actions", [])
    assert any(
        isinstance(action, dict) and action.get("id") == "resolve_report_session_consistency"
        for action in actions
    )


def test_initial_release_gate_includes_explicit_baseline_context_and_diff(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    baseline_session = sessions_dir / "session_20260420_234516.json"
    baseline_missing = [
        "scn_10_semantic_business_logic",
        "scn_12_advanced_ssrf_internal_topology",
    ]
    _write_session(baseline_session, covered=10, required=12, missing=baseline_missing)

    baseline_report = reports_dir / "haddix_report_20260420_234519.md"
    _write_report(
        baseline_report,
        source_session=str(baseline_session.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 3 / Candidate: 0",
    )

    current_session = sessions_dir / "session_20260421_044611.json"
    current_missing = [
        "scn_10_semantic_business_logic",
        "scn_12_advanced_ssrf_internal_topology",
    ]
    _write_session(current_session, covered=10, required=12, missing=current_missing)

    current_report = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        current_report,
        source_session=str(current_session.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 4 / Candidate: 0",
    )

    verdict = evaluate_initial_release_gate(
        current_report,
        baseline_report_path=baseline_report,
        baseline_session_path=baseline_session,
    )

    assert verdict["status"] == "pass"
    assert verdict["gate_passed"] is True
    evaluation_context = verdict.get("evaluation_context", {})
    assert evaluation_context.get("comparison_mode") == "against_explicit_baseline"
    assert evaluation_context.get("baseline_report_path") == str(baseline_report.resolve())
    assert evaluation_context.get("baseline_session_path") == str(baseline_session.resolve())
    assert str(evaluation_context.get("baseline_id", "")).startswith("baseline_")

    baseline_diff = verdict.get("report_metrics", {}).get("baseline_diff", {})
    findings_diff = baseline_diff.get("findings", {})
    assert findings_diff.get("confirmed_delta") == 1
    assert findings_diff.get("candidate_delta") == 0


def test_initial_release_gate_fails_when_reason_code_quality_metrics_missing(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    missing = [
        "scn_10_semantic_business_logic",
        "scn_12_advanced_ssrf_internal_topology",
    ]
    _write_session(session_file, covered=10, required=12, missing=missing)

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 3 / Candidate: 0",
        confirmed_poc_missing_line="",
        candidate_reason_missing_line="",
    )

    verdict = evaluate_initial_release_gate(report_file)
    assert verdict["status"] == "fail"
    assert "confirmed_poc_missing_not_found" in verdict["reason_codes"]
    assert "reason_code_missing_not_found" in verdict["reason_codes"]


def test_initial_release_gate_fails_when_reason_code_quality_metrics_exceed_policy(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    missing = [
        "scn_10_semantic_business_logic",
        "scn_12_advanced_ssrf_internal_topology",
    ]
    _write_session(session_file, covered=10, required=12, missing=missing)

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 3 / Candidate: 0",
        confirmed_poc_missing_line="Confirmed PoC Missing: 1",
        candidate_reason_missing_line="Candidate Reason-Code Missing: 1",
    )

    verdict = evaluate_initial_release_gate(report_file)
    assert verdict["status"] == "fail"
    assert "confirmed_poc_missing_above_maximum" in verdict["reason_codes"]
    assert "reason_code_missing_above_maximum" in verdict["reason_codes"]


def test_initial_release_gate_uses_locked_baseline_when_explicit_baseline_not_provided(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    base_session = sessions_dir / "session_20260421_044611.json"
    missing = [
        "scn_10_semantic_business_logic",
        "scn_12_advanced_ssrf_internal_topology",
    ]
    _write_session(base_session, covered=10, required=12, missing=missing)
    base_report = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        base_report,
        source_session=str(base_session.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 3 / Candidate: 0",
    )

    first_verdict = evaluate_initial_release_gate(base_report)
    first_context = first_verdict.get("evaluation_context", {})
    assert first_context.get("comparison_mode") == "baseline_initialized"
    baseline_lock = reports_dir / "quality_baseline_lock.json"
    assert baseline_lock.exists()

    new_session = sessions_dir / "session_20260421_055511.json"
    _write_session(new_session, covered=10, required=12, missing=missing)
    new_report = reports_dir / "haddix_report_20260421_055514.md"
    _write_report(
        new_report,
        source_session=str(new_session.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 3 / Candidate: 0",
    )

    second_verdict = evaluate_initial_release_gate(new_report)
    second_context = second_verdict.get("evaluation_context", {})
    assert second_context.get("comparison_mode") == "against_locked_baseline"
    assert second_context.get("baseline_report_path") == str(base_report.resolve())
    assert second_context.get("baseline_session_path") == str(base_session.resolve())


def test_set_locked_baseline_overwrites_existing_lock(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_a = sessions_dir / "session_20260421_044611.json"
    report_a = reports_dir / "haddix_report_20260421_044614.md"
    _write_session(session_a, covered=10, required=12, missing=["scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"])
    _write_report(
        report_a,
        source_session=str(session_a.resolve()),
        coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 3 / Candidate: 0",
    )

    first = set_locked_baseline(report_a)
    assert first["status"] == "updated"
    assert first["updated"] is True

    session_b = sessions_dir / "session_20260421_055511.json"
    report_b = reports_dir / "haddix_report_20260421_055514.md"
    _write_session(session_b, covered=12, required=12, missing=[])
    _write_report(
        report_b,
        source_session=str(session_b.resolve()),
        coverage_line="Coverage: 12/12 (100.0%), Missing: -",
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 4 / Candidate: 0",
    )

    second = set_locked_baseline(report_b)
    assert second["status"] == "updated"
    assert second["updated"] is True
    assert second["baseline_report_path"] == str(report_b.resolve())
    assert second["baseline_session_path"] == str(session_b.resolve())

    lock_file = reports_dir / "quality_baseline_lock.json"
    lock_payload = json.loads(lock_file.read_text(encoding="utf-8"))
    assert lock_payload["baseline_report_path"] == str(report_b.resolve())
    assert lock_payload["baseline_session_path"] == str(session_b.resolve())


def test_initial_release_gate_schema_severity_warn_mode_does_not_fail(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    completed_tasks = [
        {
            "id": "task_schema_warn",
            "result": {
                "findings": [
                    {
                        "title": "Schema candidate",
                        "target_url": "http://127.0.0.1:8888/api/users",
                        "vuln_type": "broken_access_control",
                        "additional_info": {
                            "detection_class": "access_control",
                        },
                    }
                ]
            },
        }
    ]
    _write_session(
        session_file,
        covered=9,
        required=12,
        missing=["scn_08_oob_external_channel_flow", "scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"],
        completed_tasks=completed_tasks,
    )

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line=(
            "Coverage: 9/12 (75.0%), Missing: scn_08_oob_external_channel_flow, "
            "scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology"
        ),
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 1 / Candidate: 0",
    )

    verdict = evaluate_initial_release_gate(
        report_file,
        confirmed_min=1,
        schema_severity_enforcement_mode="warn",
        schema_severity_soft_fail_missing_count=0,
        schema_severity_soft_fail_missing_ratio=0.0,
    )
    assert verdict["status"] == "pass"
    assert "schema_severity_missing_soft_fail" not in verdict["reason_codes"]
    assert "schema_severity_missing_hard_fail" not in verdict["reason_codes"]


def test_initial_release_gate_schema_severity_soft_fail_blocks_on_missing(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    completed_tasks = [
        {
            "id": "task_schema_soft",
            "result": {
                "findings": [
                    {
                        "title": "Schema candidate soft fail",
                        "target_url": "http://127.0.0.1:8888/api/orders",
                        "vuln_type": "broken_access_control",
                        "additional_info": {"detection_class": "access_control"},
                    }
                ]
            },
        }
    ]
    _write_session(
        session_file,
        covered=9,
        required=12,
        missing=["scn_08_oob_external_channel_flow", "scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"],
        completed_tasks=completed_tasks,
    )

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line=(
            "Coverage: 9/12 (75.0%), Missing: scn_08_oob_external_channel_flow, "
            "scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology"
        ),
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 1 / Candidate: 0",
    )

    verdict = evaluate_initial_release_gate(
        report_file,
        confirmed_min=1,
        schema_severity_enforcement_mode="soft-fail",
        schema_severity_soft_fail_missing_count=0,
        schema_severity_soft_fail_missing_ratio=0.0,
    )
    assert verdict["status"] == "fail"
    assert "schema_severity_missing_soft_fail" in verdict["reason_codes"]


def test_initial_release_gate_schema_severity_hard_fail_blocks_on_missing(tmp_path: Path) -> None:
    project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
    sessions_dir = project_dir / "sessions"
    reports_dir = project_dir / "reports"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260421_044611.json"
    completed_tasks = [
        {
            "id": "task_schema_hard",
            "result": {
                "findings": [
                    {
                        "title": "Schema candidate hard fail",
                        "target_url": "http://127.0.0.1:8888/api/invoices",
                        "vuln_type": "broken_access_control",
                        "additional_info": {"detection_class": "access_control"},
                    }
                ]
            },
        }
    ]
    _write_session(
        session_file,
        covered=9,
        required=12,
        missing=["scn_08_oob_external_channel_flow", "scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"],
        completed_tasks=completed_tasks,
    )

    report_file = reports_dir / "haddix_report_20260421_044614.md"
    _write_report(
        report_file,
        source_session=str(session_file.resolve()),
        coverage_line=(
            "Coverage: 9/12 (75.0%), Missing: scn_08_oob_external_channel_flow, "
            "scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology"
        ),
        family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
        findings_line="Confirmed: 1 / Candidate: 0",
    )

    verdict = evaluate_initial_release_gate(
        report_file,
        confirmed_min=1,
        schema_severity_enforcement_mode="hard-fail",
    )
    assert verdict["status"] == "fail"
    assert "schema_severity_missing_hard_fail" in verdict["reason_codes"]


# ─────────────────────────────────────────────
# Phase 3: Gate Separation Tests
# ─────────────────────────────────────────────


class TestGateSeparation:
    """P3-1: Initial Release Gate Fail-Closed with independent sub-gates."""

    def test_confirmed_below_minimum_fails_even_with_allowed_missing(self, tmp_path: Path) -> None:
        """Confirmed=1, Candidate=0 with allowed_missing for SCN08/10/12 → FAIL because confirmed<3."""
        project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
        sessions_dir = project_dir / "sessions"
        reports_dir = project_dir / "reports"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        session_file = sessions_dir / "session_20260714_000000.json"
        missing = [
            "scn_08_oob_external_channel_flow",
            "scn_10_semantic_business_logic",
            "scn_12_advanced_ssrf_internal_topology",
        ]
        _write_session(session_file, covered=9, required=12, missing=missing)
        report_file = reports_dir / "haddix_report_20260714_000000.md"
        _write_report(
            report_file,
            source_session=str(session_file.resolve()),
            coverage_line=(
                "Coverage: 9/12 (75.0%), Missing: scn_08_oob_external_channel_flow, "
                "scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology"
            ),
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 1 / Candidate: 0",
        )

        verdict = evaluate_gate_separated(
            report_file,
            allowed_missing_scenarios=missing,
            confirmed_min=3,
            candidate_max=2,
        )
        # Overall gate must FAIL because confirmed=1 < 3
        assert verdict["status"] == "fail"
        assert verdict["gate_passed"] is False
        assert "confirmed_below_minimum" in verdict["reason_codes"]
        # Scenario coverage gate should PASS (all missing are allowed)
        scenario_gate = verdict["gates"]["scenario_coverage"]
        assert scenario_gate["status"] == "pass"
        assert scenario_gate["passed"] is True
        # Finding policy gate should FAIL
        finding_gate = verdict["gates"]["finding_policy"]
        assert finding_gate["status"] == "fail"
        assert "confirmed_below_minimum" in finding_gate["reason_codes"]

    def test_candidate_above_maximum_fails_even_with_allowed_missing(self, tmp_path: Path) -> None:
        """Confirmed=3, Candidate=10 with allowed_missing for SCN08/10/12 → FAIL because candidate>2."""
        project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
        sessions_dir = project_dir / "sessions"
        reports_dir = project_dir / "reports"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        session_file = sessions_dir / "session_20260714_000000.json"
        missing = [
            "scn_08_oob_external_channel_flow",
            "scn_10_semantic_business_logic",
            "scn_12_advanced_ssrf_internal_topology",
        ]
        _write_session(session_file, covered=9, required=12, missing=missing)
        report_file = reports_dir / "haddix_report_20260714_000000.md"
        _write_report(
            report_file,
            source_session=str(session_file.resolve()),
            coverage_line=(
                "Coverage: 9/12 (75.0%), Missing: scn_08_oob_external_channel_flow, "
                "scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology"
            ),
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 3 / Candidate: 10",
        )

        verdict = evaluate_gate_separated(
            report_file,
            allowed_missing_scenarios=missing,
            confirmed_min=3,
            candidate_max=2,
        )
        # Overall gate must FAIL because candidate=10 > 2
        assert verdict["status"] == "fail"
        assert "candidate_above_maximum" in verdict["reason_codes"]
        # Scenario coverage gate should PASS (all missing are allowed)
        assert verdict["gates"]["scenario_coverage"]["status"] == "pass"
        # Finding policy gate should FAIL
        finding_gate = verdict["gates"]["finding_policy"]
        assert finding_gate["status"] == "fail"
        assert "candidate_above_maximum" in finding_gate["reason_codes"]

    def test_allowed_missing_only_affects_scenario_coverage(self, tmp_path: Path) -> None:
        """allowed_missing must only affect scenario coverage gate, not confirmed/candidate counts."""
        project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
        sessions_dir = project_dir / "sessions"
        reports_dir = project_dir / "reports"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        session_file = sessions_dir / "session_20260714_000000.json"
        missing = ["scn_10_semantic_business_logic"]
        _write_session(session_file, covered=11, required=12, missing=missing)
        report_file = reports_dir / "haddix_report_20260714_000000.md"
        _write_report(
            report_file,
            source_session=str(session_file.resolve()),
            coverage_line="Coverage: 11/12 (91.7%), Missing: scn_10_semantic_business_logic",
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 0 / Candidate: 0",
        )

        verdict = evaluate_gate_separated(
            report_file,
            allowed_missing_scenarios=missing,
            confirmed_min=3,
            candidate_max=2,
        )
        # Scenario coverage should PASS (SCN10 is allowed missing)
        assert verdict["gates"]["scenario_coverage"]["status"] == "pass"
        # But finding policy should FAIL due to confirmed=0 < 3 (allowed_missing does NOT help)
        assert verdict["status"] == "fail"
        assert "confirmed_below_minimum" in verdict["reason_codes"]
        assert verdict["gates"]["finding_policy"]["status"] == "fail"

    def test_gate_separated_returns_structured_gates(self, tmp_path: Path) -> None:
        """Call evaluate_gate_separated, verify gates dict has all 5 sub-gates."""
        project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
        sessions_dir = project_dir / "sessions"
        reports_dir = project_dir / "reports"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        session_file = sessions_dir / "session_20260714_000000.json"
        _write_session(session_file, covered=10, required=12, missing=["scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"])
        report_file = reports_dir / "haddix_report_20260714_000000.md"
        _write_report(
            report_file,
            source_session=str(session_file.resolve()),
            coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 3 / Candidate: 0",
        )

        verdict = evaluate_gate_separated(report_file)
        assert "gates" in verdict
        gates = verdict["gates"]
        expected_gates = {"scenario_coverage", "evidence_quality", "finding_policy", "regression", "submission"}
        assert set(gates.keys()) == expected_gates
        for gate_name in expected_gates:
            gate = gates[gate_name]
            assert "status" in gate, f"{gate_name} missing status"
            assert "passed" in gate, f"{gate_name} missing passed"
            assert "reason_codes" in gate, f"{gate_name} missing reason_codes"

    def test_overall_gate_passes_only_when_all_sub_gates_pass(self, tmp_path: Path) -> None:
        """All sub-gates pass → overall pass."""
        project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
        sessions_dir = project_dir / "sessions"
        reports_dir = project_dir / "reports"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        session_file = sessions_dir / "session_20260714_000000.json"
        _write_session(session_file, covered=10, required=12, missing=["scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"])
        report_file = reports_dir / "haddix_report_20260714_000000.md"
        _write_report(
            report_file,
            source_session=str(session_file.resolve()),
            coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 3 / Candidate: 0",
        )

        verdict = evaluate_gate_separated(report_file)
        assert verdict["status"] == "pass"
        assert verdict["gate_passed"] is True
        assert verdict["reason_codes"] == []

    def test_overall_gate_fails_when_any_sub_gate_fails(self, tmp_path: Path) -> None:
        """One sub-gate fails → overall fail."""
        project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
        sessions_dir = project_dir / "sessions"
        reports_dir = project_dir / "reports"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        session_file = sessions_dir / "session_20260714_000000.json"
        missing_scenarios = ["scn_03_injection_input_tampering"]
        _write_session(session_file, covered=11, required=12, missing=missing_scenarios)
        report_file = reports_dir / "haddix_report_20260714_000000.md"
        _write_report(
            report_file,
            source_session=str(session_file.resolve()),
            coverage_line="Coverage: 11/12 (91.7%), Missing: scn_03_injection_input_tampering",
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 3 / Candidate: 0",
        )

        verdict = evaluate_gate_separated(report_file)
        assert verdict["status"] == "fail"
        assert verdict["gate_passed"] is False
        assert "unexpected_missing_scenarios" in verdict["reason_codes"]
        # Verify which gate failed
        assert verdict["gates"]["scenario_coverage"]["status"] == "fail"
        assert verdict["gates"]["finding_policy"]["status"] == "pass"

    def test_each_sub_gate_has_policy_and_actual_values(self, tmp_path: Path) -> None:
        """Each sub-gate dict contains policy_values and actual_values."""
        project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
        sessions_dir = project_dir / "sessions"
        reports_dir = project_dir / "reports"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        session_file = sessions_dir / "session_20260714_000000.json"
        _write_session(session_file, covered=10, required=12, missing=["scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"])
        report_file = reports_dir / "haddix_report_20260714_000000.md"
        _write_report(
            report_file,
            source_session=str(session_file.resolve()),
            coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 3 / Candidate: 0",
        )

        verdict = evaluate_gate_separated(report_file)
        for gate_name in {"scenario_coverage", "evidence_quality", "finding_policy", "regression", "submission"}:
            gate = verdict["gates"][gate_name]
            assert "policy_values" in gate, f"{gate_name} missing policy_values"
            assert "actual_values" in gate, f"{gate_name} missing actual_values"
            assert isinstance(gate["policy_values"], dict), f"{gate_name} policy_values not dict"
            assert isinstance(gate["actual_values"], dict), f"{gate_name} actual_values not dict"

    def test_structured_log_contains_condition_details(self, tmp_path: Path) -> None:
        """Each gate evaluation has condition_id, policy_value, actual_value in condition_logs."""
        project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
        sessions_dir = project_dir / "sessions"
        reports_dir = project_dir / "reports"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        session_file = sessions_dir / "session_20260714_000000.json"
        _write_session(session_file, covered=9, required=12, missing=["scn_03_injection_input_tampering"])
        report_file = reports_dir / "haddix_report_20260714_000000.md"
        _write_report(
            report_file,
            source_session=str(session_file.resolve()),
            coverage_line="Coverage: 9/12 (75.0%), Missing: scn_03_injection_input_tampering",
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 1 / Candidate: 10",
        )

        verdict = evaluate_gate_separated(
            report_file,
            confirmed_min=3,
            candidate_max=2,
        )
        # Each evaluated gate should have condition_logs
        for gate_name in {"scenario_coverage", "evidence_quality", "finding_policy", "submission"}:
            gate = verdict["gates"][gate_name]
            condition_logs = gate.get("condition_logs", [])
            assert isinstance(condition_logs, list), f"{gate_name} condition_logs not list"
            if condition_logs:
                for condition in condition_logs:
                    assert "condition_id" in condition
                    assert "policy_value" in condition
                    assert "actual_value" in condition
                    assert "comparison_operator" in condition
                    assert "individual_result" in condition
                    assert condition["individual_result"] in {"pass", "fail"}

        # Specifically verify finding_policy has structured logs for confirmed/candidate
        fp_logs = verdict["gates"]["finding_policy"]["condition_logs"]
        log_ids = {c["condition_id"] for c in fp_logs}
        assert "confirmed_below_minimum" in log_ids
        assert "candidate_above_maximum" in log_ids


class TestRegressionGate:
    """P3-2: Regression Gate Separation — independent from allowed_missing."""

    def test_regression_gate_fails_on_confirmed_delta_drop(self, tmp_path: Path) -> None:
        """confirmed_delta=-9 → regression gate FAIL."""
        project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
        sessions_dir = project_dir / "sessions"
        reports_dir = project_dir / "reports"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        # Baseline: confirmed=10
        baseline_session = sessions_dir / "session_baseline.json"
        _write_session(baseline_session, covered=10, required=12, missing=["scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"])
        baseline_report = reports_dir / "haddix_report_baseline.md"
        _write_report(
            baseline_report,
            source_session=str(baseline_session.resolve()),
            coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 10 / Candidate: 0",
        )

        # Current: confirmed=1 (delta = -9)
        current_session = sessions_dir / "session_current.json"
        _write_session(current_session, covered=10, required=12, missing=["scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"])
        current_report = reports_dir / "haddix_report_current.md"
        _write_report(
            current_report,
            source_session=str(current_session.resolve()),
            coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 1 / Candidate: 0",
        )

        verdict = evaluate_gate_separated(
            current_report,
            baseline_report_path=baseline_report,
            baseline_session_path=baseline_session,
            confirmed_min=1,  # Low bar so finding_policy passes
            regression_confirmed_delta_min=0,
        )
        assert verdict["status"] == "fail"
        assert verdict["gates"]["regression"]["status"] == "fail"
        assert "regression_confirmed_drop" in verdict["gates"]["regression"]["reason_codes"]
        assert verdict["gates"]["finding_policy"]["status"] == "pass"

    def test_regression_gate_passes_when_confirmed_delta_zero(self, tmp_path: Path) -> None:
        """confirmed_delta=0 → regression gate PASS."""
        project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
        sessions_dir = project_dir / "sessions"
        reports_dir = project_dir / "reports"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        baseline_session = sessions_dir / "session_baseline.json"
        _write_session(baseline_session, covered=10, required=12, missing=["scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"])
        baseline_report = reports_dir / "haddix_report_baseline.md"
        _write_report(
            baseline_report,
            source_session=str(baseline_session.resolve()),
            coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 3 / Candidate: 0",
        )

        current_session = sessions_dir / "session_current.json"
        _write_session(current_session, covered=10, required=12, missing=["scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"])
        current_report = reports_dir / "haddix_report_current.md"
        _write_report(
            current_report,
            source_session=str(current_session.resolve()),
            coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 3 / Candidate: 0",
        )

        verdict = evaluate_gate_separated(
            current_report,
            baseline_report_path=baseline_report,
            baseline_session_path=baseline_session,
            regression_confirmed_delta_min=0,
        )
        assert verdict["gates"]["regression"]["status"] == "pass"

    def test_regression_gate_passes_when_no_baseline(self, tmp_path: Path) -> None:
        """No baseline available → regression gate NOT_APPLICABLE."""
        project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
        sessions_dir = project_dir / "sessions"
        reports_dir = project_dir / "reports"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        session_file = sessions_dir / "session_20260714_000000.json"
        _write_session(session_file, covered=10, required=12, missing=["scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"])
        report_file = reports_dir / "haddix_report_20260714_000000.md"
        _write_report(
            report_file,
            source_session=str(session_file.resolve()),
            coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 3 / Candidate: 0",
        )

        verdict = evaluate_gate_separated(report_file)
        # Self-baseline: confirmed_delta=0 (self vs self), so regression gate passes
        assert verdict["gates"]["regression"]["status"] == "pass"
        # Regression gate passing should NOT block overall gate
        assert verdict["status"] == "pass"

    def test_regression_gate_not_affected_by_allowed_missing(self, tmp_path: Path) -> None:
        """allowed_missing set → regression should still FAIL on confirmed_delta=-9."""
        project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
        sessions_dir = project_dir / "sessions"
        reports_dir = project_dir / "reports"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        baseline_session = sessions_dir / "session_baseline.json"
        _write_session(baseline_session, covered=9, required=12, missing=["scn_08_oob_external_channel_flow", "scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"])
        baseline_report = reports_dir / "haddix_report_baseline.md"
        _write_report(
            baseline_report,
            source_session=str(baseline_session.resolve()),
            coverage_line=(
                "Coverage: 9/12 (75.0%), Missing: scn_08_oob_external_channel_flow, "
                "scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology"
            ),
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 10 / Candidate: 0",
        )

        current_session = sessions_dir / "session_current.json"
        _write_session(current_session, covered=9, required=12, missing=["scn_08_oob_external_channel_flow", "scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"])
        current_report = reports_dir / "haddix_report_current.md"
        _write_report(
            current_report,
            source_session=str(current_session.resolve()),
            coverage_line=(
                "Coverage: 9/12 (75.0%), Missing: scn_08_oob_external_channel_flow, "
                "scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology"
            ),
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 1 / Candidate: 0",
        )

        verdict = evaluate_gate_separated(
            current_report,
            baseline_report_path=baseline_report,
            baseline_session_path=baseline_session,
            allowed_missing_scenarios=[
                "scn_08_oob_external_channel_flow",
                "scn_10_semantic_business_logic",
                "scn_12_advanced_ssrf_internal_topology",
            ],
            confirmed_min=1,
            regression_confirmed_delta_min=0,
        )
        # Scenario coverage should PASS (all missing are allowed)
        assert verdict["gates"]["scenario_coverage"]["status"] == "pass"
        # Regression gate should still FAIL — not affected by allowed_missing
        assert verdict["gates"]["regression"]["status"] == "fail"
        assert "regression_confirmed_drop" in verdict["gates"]["regression"]["reason_codes"]

    def test_regression_gate_tracks_class_level_drops(self, tmp_path: Path) -> None:
        """Class-level confirmed drops are tracked in the gate result."""
        project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
        sessions_dir = project_dir / "sessions"
        reports_dir = project_dir / "reports"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        baseline_session = sessions_dir / "session_baseline.json"
        _write_session(baseline_session, covered=10, required=12, missing=["scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"])
        baseline_report = reports_dir / "haddix_report_baseline.md"
        _write_report(
            baseline_report,
            source_session=str(baseline_session.resolve()),
            coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 3 / Candidate: 0",
            findings_class_rows=[
                ("broken_access_control", 2, 0, 2),
                ("mass_assignment", 1, 0, 1),
            ],
        )

        current_session = sessions_dir / "session_current.json"
        _write_session(current_session, covered=10, required=12, missing=["scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"])
        current_report = reports_dir / "haddix_report_current.md"
        _write_report(
            current_report,
            source_session=str(current_session.resolve()),
            coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 3 / Candidate: 0",
            findings_class_rows=[
                ("broken_access_control", 0, 0, 0),  # Dropped from 2→0
                ("mass_assignment", 3, 0, 3),  # Increased
            ],
        )

        verdict = evaluate_gate_separated(
            current_report,
            baseline_report_path=baseline_report,
            baseline_session_path=baseline_session,
            regression_confirmed_delta_min=0,
            regression_allow_dedup_reduction=True,  # Allow dedup reduction
        )
        # Regression gate should be not_applicable (confirmed_delta 3-3=0, but... wait, report shows confirmed:3 but class rows broken_access_control: 2→0)
        # Actually the report says "Confirmed: 3" both times, but class rows show a drop in broken_access_control
        # The confirmed_delta is 0, so regression passes. But dropped_classes should still be tracked.
        reg_gate = verdict["gates"]["regression"]
        assert "dropped_classes" in reg_gate["actual_values"]
        dropped_classes = reg_gate["actual_values"]["dropped_classes"]
        # There should be at least one dropped class (broken_access_control: 2→0)
        assert len(dropped_classes) > 0
        dropped_names = {d["vuln_class"] for d in dropped_classes}
        assert "broken_access_control" in dropped_names


class TestBackwardCompatibility:
    """Verify evaluate_initial_release_gate() still works and matches separated gate."""

    def test_existing_evaluate_initial_release_gate_still_works(self, tmp_path: Path) -> None:
        """The original function still returns expected fields."""
        project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
        sessions_dir = project_dir / "sessions"
        reports_dir = project_dir / "reports"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        session_file = sessions_dir / "session_20260421_044611.json"
        missing = [
            "scn_10_semantic_business_logic",
            "scn_12_advanced_ssrf_internal_topology",
        ]
        _write_session(session_file, covered=10, required=12, missing=missing)
        report_file = reports_dir / "haddix_report_20260421_044614.md"
        _write_report(
            report_file,
            source_session=str(session_file.resolve()),
            coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 3 / Candidate: 0",
        )

        verdict = evaluate_initial_release_gate(report_file)
        # All expected top-level fields
        assert "status" in verdict
        assert "gate_passed" in verdict
        assert "reason_codes" in verdict
        assert "policy" in verdict
        assert "consistency" in verdict
        assert "report_metrics" in verdict
        assert "evaluation_context" in verdict
        assert "deferred_scenarios" in verdict
        assert "recommended_actions" in verdict
        assert "suggested_next_step" in verdict
        # The 'gates' key should NOT be present in backward-compat mode
        assert "gates" not in verdict

    def test_separated_gate_same_result_as_unified_for_basic_cases(self, tmp_path: Path) -> None:
        """For simple passing cases, both functions agree on status and gate_passed."""
        project_dir = tmp_path / "workspace" / "projects" / "127.0.0.1:8888"
        sessions_dir = project_dir / "sessions"
        reports_dir = project_dir / "reports"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        session_file = sessions_dir / "session_20260714_000000.json"
        missing = [
            "scn_10_semantic_business_logic",
            "scn_12_advanced_ssrf_internal_topology",
        ]
        _write_session(session_file, covered=10, required=12, missing=missing)
        report_file = reports_dir / "haddix_report_20260714_000000.md"
        _write_report(
            report_file,
            source_session=str(session_file.resolve()),
            coverage_line="Coverage: 10/12 (83.3%), Missing: scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology",
            family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -",
            findings_line="Confirmed: 3 / Candidate: 0",
        )

        unified = evaluate_initial_release_gate(report_file)
        separated = evaluate_gate_separated(report_file)
        # Both should agree on status and gate_passed
        assert unified["status"] == separated["status"]
        assert unified["gate_passed"] == separated["gate_passed"]
        assert unified["reason_codes"] == separated["reason_codes"]


def test_locked_baseline_is_not_reused_across_security_levels(tmp_path: Path) -> None:
    reports_dir = tmp_path / "reports"
    sessions_dir = tmp_path / "sessions"
    reports_dir.mkdir()
    sessions_dir.mkdir()
    missing = ["scn_08_oob_external_channel_flow", "scn_10_semantic_business_logic", "scn_12_advanced_ssrf_internal_topology"]
    low_session = sessions_dir / "session_low.json"
    high_session = sessions_dir / "session_high.json"
    _write_session(low_session, covered=9, required=12, missing=missing, security_level="low")
    _write_session(high_session, covered=9, required=12, missing=missing, security_level="high")
    low_report = reports_dir / "haddix_report_low.md"
    high_report = reports_dir / "haddix_report_high.md"
    for report, session, confirmed in ((low_report, low_session, 10), (high_report, high_session, 4)):
        _write_report(report, source_session=str(session), coverage_line="Coverage: 9/12 (75.0%), Missing: scn_08_oob_external_channel_flow, scn_10_semantic_business_logic, scn_12_advanced_ssrf_internal_topology", family_gate_line="Gate: PASS, Coverage: 7/7 (100.0%), Missing: -", findings_line=f"Confirmed: {confirmed} / Candidate: 3")
    (reports_dir / "quality_baseline_lock.json").write_text(json.dumps({"baseline_report_path": str(low_report), "baseline_session_path": str(low_session)}), encoding="utf-8")

    result = evaluate_initial_release_gate(high_report, session_path=high_session)

    assert result["evaluation_context"]["comparison_mode"] == "baseline_initialized"
    assert "regression_confirmed_drop" not in result["reason_codes"]
