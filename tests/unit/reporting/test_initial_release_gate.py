from __future__ import annotations

import json
from pathlib import Path

from src.reporting.initial_release_gate import evaluate_initial_release_gate, set_locked_baseline


def _write_session(
    path: Path,
    *,
    covered: int,
    required: int,
    missing: list[str],
    family_gate_passed: bool = True,
    coverage_items: list[dict[str, object]] | None = None,
    completed_tasks: list[dict[str, object]] | None = None,
) -> None:
    payload = {
        "completed_tasks": completed_tasks or [],
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
    assert verdict["status"] == "fail"
    assert "confirmed_below_minimum" in verdict["reason_codes"]
    findings_summary = verdict["report_metrics"]["findings_summary"]
    assert findings_summary["source"] == "session_raw_unique"
    assert findings_summary["confirmed_count"] == 2
    assert findings_summary["candidate_count"] == 0
    assert verdict["report_metrics"]["report_findings_summary"]["confirmed_count"] == 3


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
