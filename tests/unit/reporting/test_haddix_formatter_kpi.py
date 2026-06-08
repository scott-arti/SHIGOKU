from src.reporting.haddix_formatter import HaddixFormatter


def test_injection_execution_notes_kpi_includes_avg_retry():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.set_execution_notes(
        [
            {
                "url": "http://example.com/a",
                "vuln_type": "sqli",
                "status": "completed",
                "duration_seconds": 1.2,
                "retry_count": 1,
                "tested_params": ["id"],
                "blind_correlation": {},
            },
            {
                "url": "http://example.com/b",
                "vuln_type": "xss",
                "status": "timeout",
                "duration_seconds": 60.0,
                "retry_count": 3,
                "tested_params": [],
                "blind_correlation": {},
            },
        ]
    )

    md = formatter.format_markdown()

    assert "KPI: total=2, completed=1, timeout=1, error=0, timeout_rate=50.0%, avg_retry=2.00" in md


def test_authz_differential_includes_signals_in_summary_and_steps():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.add_finding_from_dict(
        {
            "title": "IDOR differential",
            "severity": "high",
            "vuln_type": "idor",
            "target_url": "http://example.com/api/user/1",
            "summary": "Potential IDOR",
            "additional_info": {
                "authz_differential": {
                    "scenario": "cross_session_access",
                    "confidence": 0.91,
                    "signals": [
                        "id_reflected",
                        {"name": "secret_keyword"},
                        "id_reflected",
                    ],
                    "baseline_status": 200,
                    "test_status": 200,
                    "original_id": "1",
                    "test_id": "2",
                }
            },
        }
    )

    md = formatter.format_markdown()

    assert "AuthZ differential: cross_session_access (score=0.91, id=1->2, status=200->200, signals=id_reflected, secret_keyword)" in md
    assert "ベースラインID `1` と検証ID `2` でアクセス差を確認する。" in md
    assert "レスポンス差分シグナル（id_reflected, secret_keyword）が再現されることを確認する。" in md


def test_execution_notes_deduplicates_same_url_type_status_with_stronger_values():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.set_execution_notes(
        [
            {
                "url": "http://example.com/chatbot/genai/state",
                "vuln_type": "unknown",
                "status": "completed",
                "duration_seconds": 25.0,
                "retry_count": 0,
                "tested_params": [],
                "blind_correlation": {},
            },
            {
                "url": "http://example.com/chatbot/genai/state",
                "vuln_type": "unknown",
                "status": "completed",
                "duration_seconds": 0.0,
                "retry_count": 1,
                "tested_params": ["state"],
                "blind_correlation": {},
            },
        ]
    )

    md = formatter.format_markdown()

    assert md.count("`http://example.com/chatbot/genai/state`") == 1
    assert "| `http://example.com/chatbot/genai/state` | unknown | completed | 25.0 | 1 | state | - | - | - |" in md
    assert "KPI: total=1, completed=1, timeout=0, error=0, timeout_rate=0.0%, avg_retry=1.00" in md


def test_execution_notes_render_probe_sent_and_skip_reason_columns():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.set_execution_notes(
        [
            {
                "url": "http://example.com/api/user",
                "vuln_type": "api",
                "status": "completed",
                "duration_seconds": 0.2,
                "retry_count": 0,
                "tested_params": ["role", "is_admin"],
                "probe_sent": True,
                "probe_skipped_reason": "",
                "blind_correlation": {},
            },
            {
                "url": "http://example.com/account/settings",
                "vuln_type": "api",
                "status": "completed",
                "duration_seconds": 0.1,
                "retry_count": 0,
                "tested_params": [],
                "probe_sent": False,
                "probe_skipped_reason": "write_method_not_discovered_from_options_or_fallback_probes",
                "blind_correlation": {},
            },
        ]
    )

    md = formatter.format_markdown()

    assert "| URL | Type | Status | Duration(s) | Retry | Tested Params | Probe Sent | Probe Skip Reason | Blind Evidence |" in md
    assert "| `http://example.com/api/user` | api | completed | 0.2 | 0 | role, is_admin | yes | - | - |" in md
    assert "| `http://example.com/account/settings` | api | completed | 0.1 | 0 | - | no | write_method_not_discovered_from_options_or_fallback_probes | - |" in md


def test_scenario_coverage_section_is_rendered():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.set_scenario_coverage(
        {
            "required_count": 12,
            "covered_count": 2,
            "coverage_rate": 2 / 12,
            "missing_scenarios": ["scn_02_mass_assignment_object_update"],
            "coverage_items": [
                {
                    "scenario_id": "scn_01_idor_bola_object_access",
                    "number": 1,
                    "title": "IDOR/BOLA Object Access",
                    "route": "shigoku_only",
                    "covered": True,
                    "count": 2,
                },
                {
                    "scenario_id": "scn_02_mass_assignment_object_update",
                    "number": 2,
                    "title": "Mass Assignment Object Update",
                    "route": "shigoku_only",
                    "covered": False,
                    "count": 0,
                },
            ],
        }
    )

    md = formatter.format_markdown()

    assert "## 🧪 Scenario Coverage (SCN01-12)" in md
    assert "Coverage: 2/12 (16.7%), Missing: scn_02_mass_assignment_object_update" in md
    assert "| SCN01 | IDOR/BOLA Object Access | shigoku_only | YES | 2 |" in md
    assert "| SCN02 | Mass Assignment Object Update | shigoku_only | NO | 0 |" in md


def test_suspicious_high_friction_scenarios_are_rendered_when_missing():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.set_scenario_coverage(
        {
            "required_count": 12,
            "covered_count": 6,
            "coverage_rate": 0.5,
            "missing_scenarios": [
                "scn_08_oob_external_channel_flow",
                "scn_10_semantic_business_logic",
                "scn_11_multi_vector_chain",
                "scn_12_advanced_ssrf_internal_topology",
            ],
            "coverage_items": [],
        }
    )

    md = formatter.format_markdown()

    assert "### ⚠️ Suspicious High-Friction Scenarios" in md
    assert "| scn_08_oob_external_channel_flow |" in md
    assert "| scn_12_advanced_ssrf_internal_topology |" in md


def test_vulnerability_family_coverage_gate_section_includes_missing_reason():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.set_vulnerability_family_coverage(
        {
            "required_families": ["access_control", "csrf", "api"],
            "reached_families": ["access_control", "api"],
            "missing_families": ["csrf"],
            "gate_passed": False,
            "coverage_rate": 2 / 3,
            "coverage_items": [
                {
                    "family": "access_control",
                    "reached": True,
                    "category_evidence": ["admin"],
                    "finding_evidence": [],
                },
                {
                    "family": "csrf",
                    "reached": False,
                    "category_evidence": [],
                    "finding_evidence": [],
                },
                {
                    "family": "api",
                    "reached": True,
                    "category_evidence": ["api_data"],
                    "finding_evidence": ["api_exposure"],
                },
            ],
        }
    )

    md = formatter.format_markdown()

    assert "## 🧱 Vulnerability Family Coverage Gate" in md
    assert "Gate: FAIL, Coverage: 2/3 (66.7%), Missing: csrf" in md
    assert "| csrf | NO | - | - | no_completed_csrf_candidate_task |" in md


def test_findings_are_split_into_confirmed_and_candidate_sections():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.add_finding_from_dict(
        {
            "title": "Confirmed IDOR",
            "severity": "high",
            "vuln_type": "idor",
            "target_url": "http://example.com/api/user/2",
            "summary": "Differential access confirmed",
            "poc_request": "GET /api/user/2 HTTP/1.1",
            "poc_response": "HTTP/1.1 200 OK",
            "tags": ["idor"],
            "additional_info": {
                "tested_params": ["id"],
                "detection_mode": "phase1",
            },
        }
    )
    formatter.add_finding_from_dict(
        {
            "title": "Candidate Privilege Surface",
            "severity": "medium",
            "vuln_type": "api",
            "target_url": "http://example.com/api/state",
            "summary": "Heuristic candidate generated from execution telemetry; manual verification required.",
            "tags": ["api_candidate", "manual_verify"],
            "additional_info": {
                "heuristic_candidate": True,
                "verification_required": True,
                "detection_mode": "heuristic_fallback",
            },
        }
    )

    md = formatter.format_markdown()

    assert "Confirmed: 1 / Candidate: 1" in md
    assert "Confirmed PoC Missing: 0" in md
    assert "Candidate Reason-Code Missing: 0" in md
    assert "### ✅ Confirmed Findings" in md
    assert "## 📮 Submission Readiness" in md
    assert "Submission-ready findings: 1" in md
    assert "Hold-back candidates: 1" in md
    assert "### Appendix A. Non-Submission Candidates (Manual Verification Required)" in md


def test_heuristic_promoted_finding_renders_promotion_rationale_in_body():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.add_finding_from_dict(
        {
            "title": "Potential privilege parameter tampering surface",
            "severity": "medium",
            "vuln_type": "mass_assignment",
            "target_url": "http://example.com/account/settings",
            "summary": "Auto-verified heuristic signal from repeated successful privilege-parameter probes.",
            "additional_info": {
                "heuristic_candidate": False,
                "verification_required": False,
                "detection_mode": "heuristic_promoted",
                "repeat_signal": {
                    "total": 3,
                    "completed_with_probe": 3,
                    "privilege_probe": 3,
                    "privilege_probe_min": 2,
                    "completed_with_probe_min": 2,
                },
            },
        }
    )

    md = formatter.format_markdown()

    assert "Confirmed: 0 / Candidate: 1" in md
    assert "Confirmed PoC Missing: 0" in md
    assert "Candidate Reason-Code Missing: 0" in md
    assert "### Appendix A. Non-Submission Candidates (Manual Verification Required)" in md
    assert "- 自動昇格理由: repeat_signal(privilege_probe=3/2, completed_with_probe=3/2, total=3)" in md


def test_finding_without_full_poc_is_demoted_to_candidate():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.add_finding_from_dict(
        {
            "title": "Potential Unauthenticated API Access",
            "severity": "medium",
            "vuln_type": "broken_access_control",
            "target_url": "http://example.com/api/state",
            "summary": "Auth differential suggests unauthenticated access.",
            "poc_request": "GET /api/state HTTP/1.1",
            "additional_info": {
                "detection_mode": "phase1",
            },
        }
    )

    md = formatter.format_markdown()

    assert "Confirmed: 0 / Candidate: 1" in md


def test_confirmed_finding_renders_response_body_and_baseline_attack_comparison():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.add_finding_from_dict(
        {
            "title": "Confirmed IDOR with differential evidence",
            "severity": "high",
            "vuln_type": "idor",
            "target_url": "http://example.com/api/users/2",
            "summary": "Authenticated request for another user returned a successful response.",
            "poc_request": "GET /api/users/2 HTTP/1.1\nAuthorization: Bearer demo",
            "poc_response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"user_id\":2,\"email\":\"victim@example.com\"}",
            "additional_info": {
                "detection_mode": "phase1",
                "tested_params": ["user_id"],
                "authz_differential": {
                    "scenario": "cross_session_access",
                    "confidence": 0.93,
                    "baseline_status": 403,
                    "test_status": 200,
                    "original_id": "1",
                    "test_id": "2",
                    "auth_body_length": 24,
                    "test_body_length": 38,
                    "body_length_delta": 14,
                    "body_length_delta_ratio": 0.58,
                    "signals": ["status_improved", "email_exposed"],
                },
            },
        }
    )

    md = formatter.format_markdown()

    assert "##### Baseline vs Attack Comparison" in md
    assert "| Baseline Status | 403 |" in md
    assert "| Attack Status | 200 |" in md
    assert "| Resource ID Transition | 1 -> 2 |" in md
    assert "| Response Length Delta | 14 (ratio=0.58) |" in md
    assert "##### Response Evidence" in md
    assert "{\"user_id\":2,\"email\":\"victim@example.com\"}" in md


def test_broken_access_control_finding_renders_target_specific_impact():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.add_finding_from_dict(
        {
            "title": "Potential Unauthenticated API Access",
            "severity": "medium",
            "vuln_type": "broken_access_control",
            "target_url": "http://example.com/api/balance?account_id=2",
            "summary": "API-like endpoint responded successfully without auth headers.",
            "poc_request": "GET /api/balance?account_id=2 HTTP/1.1",
            "poc_response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"account_id\":2,\"balance\":1000,\"email\":\"victim@example.com\"}",
            "additional_info": {
                "detection_mode": "phase1",
                "authz_differential": {
                    "scenario": "unauthenticated_api_access",
                    "confidence": 0.89,
                    "baseline_status": 401,
                    "test_status": 200,
                    "signals": ["balance_exposed", "email_exposed"],
                },
            },
        }
    )

    md = formatter.format_markdown()

    assert "- 対象固有の影響:" in md
    assert "api/balance" in md
    assert "balance" in md
    assert "email" in md
    assert "### ✅ Confirmed Findings" in md


def test_candidate_reason_code_keeps_explicit_standard_code():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.add_finding_from_dict(
        {
            "title": "Auth Boundary Candidate",
            "severity": "medium",
            "vuln_type": "broken_access_control",
            "target_url": "http://example.com/api/admin",
            "summary": "Auth differential produced candidate signal.",
            "additional_info": {
                "heuristic_candidate": True,
                "verification_required": True,
                "reason_code": "insufficient_privilege",
            },
        }
    )

    md = formatter.format_markdown()

    assert "Confirmed: 0 / Candidate: 1" in md
    assert "Candidate Reason-Code Coverage: 1/1 (missing=0)" in md
    assert "- 未成立 Reason Code: insufficient_privilege" in md


def test_findings_class_summary_section_is_rendered():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.add_finding_from_dict(
        {
            "title": "Confirmed API auth bypass",
            "severity": "high",
            "vuln_type": "broken_access_control",
            "target_url": "http://example.com/api/admin",
            "summary": "Auth differential confirmed.",
            "poc_request": "GET /api/admin HTTP/1.1",
            "poc_response": "HTTP/1.1 200 OK",
            "additional_info": {"tested_params": []},
        }
    )
    formatter.add_finding_from_dict(
        {
            "title": "Candidate SQLi surface",
            "severity": "medium",
            "vuln_type": "broken_access_control",
            "target_url": "http://example.com/api/search",
            "summary": "Signal exists but validation incomplete.",
            "additional_info": {
                "heuristic_candidate": True,
                "verification_required": True,
                "reason_code": "insufficient_validation",
            },
        }
    )

    md = formatter.format_markdown()

    assert "### Findings by Vulnerability Class" in md
    assert "| Vulnerability Class | Confirmed | Candidate | Total |" in md
    assert "| broken_access_control | 1 | 1 | 2 |" in md


def test_detection_class_summary_section_includes_scenario_backfill():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.set_scenario_coverage(
        {
            "required_count": 12,
            "covered_count": 3,
            "coverage_rate": 0.25,
            "missing_scenarios": [],
            "coverage_items": [
                {
                    "scenario_id": "scn_01_idor_bola_object_access",
                    "number": 1,
                    "title": "IDOR/BOLA Object Access",
                    "route": "shigoku_only",
                    "covered": True,
                    "count": 2,
                },
                {
                    "scenario_id": "scn_02_mass_assignment_object_update",
                    "number": 2,
                    "title": "Mass Assignment Object Update",
                    "route": "shigoku_only",
                    "covered": True,
                    "count": 1,
                },
                {
                    "scenario_id": "scn_04_endpoint_enumeration_bfla",
                    "number": 4,
                    "title": "Endpoint Enumeration BFLA",
                    "route": "shigoku_only",
                    "covered": True,
                    "count": 1,
                },
            ],
        }
    )
    formatter.add_finding_from_dict(
        {
            "title": "Confirmed API auth bypass",
            "severity": "high",
            "vuln_type": "broken_access_control",
            "target_url": "http://example.com/api/admin",
            "summary": "Auth differential confirmed.",
            "poc_request": "GET /api/admin HTTP/1.1",
            "poc_response": "HTTP/1.1 200 OK",
            "additional_info": {"tested_params": []},
        }
    )
    formatter.add_finding_from_dict(
        {
            "title": "Confirmed role tampering",
            "severity": "medium",
            "vuln_type": "mass_assignment",
            "target_url": "http://example.com/account/settings",
            "summary": "Privilege parameter accepted.",
            "poc_request": "GET /account/settings?role=admin HTTP/1.1",
            "poc_response": "HTTP/1.1 200 OK",
            "additional_info": {"tested_params": ["role"]},
        }
    )

    md = formatter.format_markdown()

    assert "### Findings by Detection Class" in md
    assert "| Detection Class | Confirmed | Candidate | Total | Scenario Backfill |" in md
    assert "| access_control | 1 | 0 | 1 | 0 |" in md
    assert "| mass_assignment | 1 | 0 | 1 | 1 |" in md
    assert "| idor_bola | 1 | 0 | 1 | 1 |" in md
    assert "| endpoint_bfla | 1 | 0 | 1 | 1 |" in md


def test_detection_class_summary_prefers_explicit_detection_class_metadata():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.add_finding_from_dict(
        {
            "title": "Confirmed admin endpoint exposure",
            "severity": "high",
            "vuln_type": "broken_access_control",
            "target_url": "http://example.com/api/admin/export",
            "summary": "Admin endpoint reachable from lower privilege context.",
            "poc_request": "GET /api/admin/export HTTP/1.1",
            "poc_response": "HTTP/1.1 200 OK",
            "additional_info": {
                "detection_class": "endpoint_bfla",
                "tested_params": [],
            },
        }
    )

    md = formatter.format_markdown()

    assert "| endpoint_bfla | 1 | 0 | 1 | 0 |" in md
    assert "| access_control | 1 | 0 | 1 | 0 |" not in md


def test_confirmed_finding_renders_detection_class_metadata():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.add_finding_from_dict(
        {
            "title": "Confirmed object-level access issue",
            "severity": "high",
            "vuln_type": "broken_access_control",
            "target_url": "http://example.com/api/orders/42",
            "summary": "Cross-account object access confirmed.",
            "poc_request": "GET /api/orders/42 HTTP/1.1",
            "poc_response": "HTTP/1.1 200 OK",
            "additional_info": {
                "detection_class": "idor_bola",
                "tested_params": ["order_id"],
            },
        }
    )

    md = formatter.format_markdown()

    assert "- Detection Class: idor_bola" in md


def test_confirmed_finding_includes_standardized_evidence_template():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.add_finding_from_dict(
        {
            "title": "Confirmed IDOR with evidence",
            "severity": "high",
            "vuln_type": "idor",
            "target_url": "http://example.com/api/users/2",
            "summary": "Cross-account access confirmed.",
            "poc_request": "GET /api/users/2 HTTP/1.1",
            "poc_response": "HTTP/1.1 200 OK",
            "payloads_used": ["2"],
            "additional_info": {
                "tested_params": ["id"],
                "detection_mode": "phase1",
            },
        }
    )

    md = formatter.format_markdown()

    assert "##### Evidence Template (Standardized)" in md
    assert "| Evidence ID | EV-001-IDOR |" in md
    assert "| Endpoint | `http://example.com/api/users/2` |" in md
    assert "| PoC Request Captured | yes |" in md
    assert "| PoC Response Captured | yes |" in md


def test_initial_release_gate_section_renders_policy_and_actions():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.set_initial_release_gate(
        {
            "status": "fail",
            "reason_codes": ["confirmed_below_minimum"],
            "policy": {
                "allowed_missing_scenarios": [
                    "scn_10_semantic_business_logic",
                    "scn_12_advanced_ssrf_internal_topology",
                ],
                "confirmed_min": 2,
                "candidate_max": 0,
                "notes": [
                    "Initial-release exception: SCN10/SCN12 can remain missing and are handled in a later phase (HITL/manual)."
                ],
            },
            "recommended_actions": [
                {
                    "id": "increase_confirmed_density",
                    "priority": "high",
                    "owner": "shigoku",
                    "summary": "Increase confirmed findings by strengthening auth/id/params seed surfaces first.",
                    "command_hint": "python3 -m src.main --focus-tests --focus-group density",
                }
            ],
            "deferred_scenarios": [
                {
                    "scenario_id": "scn_10_semantic_business_logic",
                    "route": "human_preferred",
                    "trigger": "Initial release gate passed with SCN10 still missing.",
                    "operator_input": "Select high-impact workflow and define unacceptable business outcome.",
                    "success_criteria": "Documented reproducible workflow-abuse path with clear business impact.",
                }
            ],
        }
    )

    md = formatter.format_markdown()

    assert "## 🚦 Initial Release Gate" in md
    assert "Status: **FAIL**" in md
    assert "SCN10/SCN12" in md
    assert "### Auto Actions (Reason Code Driven)" in md
    assert "| increase_confirmed_density | high | shigoku |" in md
    assert "### Deferred Scenario Backlog (Post-Release Track)" in md
    assert "| scn_10_semantic_business_logic | human_preferred |" in md


def test_initial_release_gate_section_renders_baseline_context():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")
    formatter.set_initial_release_gate(
        {
            "status": "pass",
            "reason_codes": [],
            "policy": {
                "allowed_missing_scenarios": [
                    "scn_10_semantic_business_logic",
                    "scn_12_advanced_ssrf_internal_topology",
                ],
                "confirmed_min": 2,
                "candidate_max": 0,
                "notes": [],
            },
            "evaluation_context": {
                "comparison_mode": "against_explicit_baseline",
                "baseline_id": "baseline_abc12345",
                "baseline_report_path": "/tmp/reports/haddix_report_20260420_234519.md",
                "baseline_session_path": "/tmp/sessions/session_20260420_234516.json",
            },
            "report_metrics": {
                "baseline_diff": {
                    "findings": {
                        "confirmed_delta": 1,
                        "candidate_delta": 0,
                    }
                }
            },
        }
    )

    md = formatter.format_markdown()

    assert "Baseline: id=baseline_abc12345, mode=against_explicit_baseline" in md
    assert "- baseline_report_path: `/tmp/reports/haddix_report_20260420_234519.md`" in md
    assert "- baseline_session_path: `/tmp/sessions/session_20260420_234516.json`" in md
    assert "Baseline Diff: confirmed_delta=1, candidate_delta=0" in md


def test_generated_header_uses_jst_suffix():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")

    md = formatter.format_markdown()

    generated_line = next((line for line in md.splitlines() if line.startswith("**Generated:** ")), "")
    assert generated_line.endswith(" JST")
