from __future__ import annotations

from src.reporting.expected_detection_matrix import (
    DEFAULT_DVWA_LOW_EXPECTED_DETECTIONS,
    compare_expected_detections,
    evaluate_generic_capability,
    extract_session_security_level,
    compare_finding_sets,
    normalize_finding_key,
)


def test_expected_matrix_marks_real_world_required_and_dvwa_specific_optional() -> None:
    entries = {entry.detection_id: entry for entry in DEFAULT_DVWA_LOW_EXPECTED_DETECTIONS}

    assert entries["sqli_normal"].real_world_relevance == "high"
    assert entries["sqli_normal"].expected_level == "required_confirmed"
    assert entries["authbypass_idor"].real_world_relevance == "high"

    assert entries["captcha_validation"].expected_level == "conditional_or_out_of_scope"
    assert "DVWA" in entries["captcha_validation"].out_of_scope_condition
    assert entries["csp_policy"].expected_level == "supporting_evidence_or_out_of_scope"


def test_expected_detection_comparison_uses_real_world_weak_id_impact_not_exact_dvwa_id() -> None:
    session_data = {
        "completed_tasks": [
            {
                "id": "weak-id",
                "result": {
                    "findings": [
                        {
                            "vuln_type": "broken_access_control",
                            "title": "Broken Access Control Risk via Predictable Session Identifier",
                            "target_url": "http://localhost:4280/vulnerabilities/weak_id/",
                        }
                    ]
                },
            }
        ]
    }

    result = compare_expected_detections(session_data)
    matched = {item["detection_id"] for item in result["matched"]}
    missing = {item["detection_id"] for item in result["missing_required"]}

    assert "weak_session_impact" in matched
    assert "weak_session_impact" not in missing


def test_high_security_session_uses_generic_capability_not_dvwa_low_expectations() -> None:
    session_data = {
        "completed_tasks": [{"params": {"cookies": "security=high"}}],
        "coverage_gate": {"coverage_items": [{"reached": True}]},
        "scenario_coverage": {"covered_count": 1, "required_count": 1},
    }

    result = compare_expected_detections(session_data, require_security_level=True)

    assert result["status"] == "ok"
    assert result["assessment_type"] == "generic_capability"
    assert result["security_level"] == "high"
    assert result["dimensions"]["observed_security_signals"] == {"confirmed_count": 0, "candidate_count": 0}


def test_generic_capability_requires_coverage_but_not_a_vulnerability() -> None:
    result = evaluate_generic_capability({"completed_tasks": []})

    assert result["status"] == "needs_review"
    assert result["reason_codes"] == ["capability_coverage_incomplete"]


def test_extract_security_level_rejects_conflicting_session_contexts() -> None:
    session_data = {
        "completed_tasks": [
            {"params": {"cookies": "security=low"}},
            {"params": {"cookies": "security=high"}},
        ],
    }

    assert extract_session_security_level(session_data) is None


def test_expected_detection_comparison_reports_missing_authbypass_and_open_redirect() -> None:
    session_data = {
        "completed_tasks": [
            {
                "id": "current",
                "result": {
                    "findings": [
                        {
                            "vuln_type": "sqli",
                            "title": "SQL Injection in parameter 'id'",
                            "target_url": "http://localhost:4280/vulnerabilities/sqli/",
                            "poc_request": (
                                "GET /vulnerabilities/sqli/?id=1'&Submit=Submit HTTP/1.1\n"
                                "Host: localhost:4280\n\n"
                            ),
                            "poc_response": "HTTP/1.1 200 OK\n\nYou have an error in your SQL syntax",
                            "payloads_used": ["1'"],
                            "additional_info": {
                                "sql_error_observed": True,
                            },
                        },
                        {
                            "vuln_type": "crlf_injection",
                            "title": "CRLF Injection via parameter 'redirect'",
                            "target_url": "http://localhost:4280/vulnerabilities/open_redirect/source/low.php?redirect=info.php?id=2",
                        },
                    ]
                },
            }
        ]
    }

    result = compare_expected_detections(session_data)
    missing = {item["detection_id"] for item in result["missing_required"]}
    conditional_missing = {item["detection_id"] for item in result["missing_conditional"]}

    assert "authbypass_idor" in missing
    assert "open_redirect_control" in conditional_missing
    assert "crlf_header_injection" not in conditional_missing


def test_required_confirmed_detection_is_missing_when_only_candidate_evidence_exists() -> None:
    session_data = {
        "completed_tasks": [
            {
                "id": "authbypass",
                "result": {
                    "findings": [
                        {
                            "vuln_type": "broken_access_control",
                            "title": "Privilege Escalation via PHPSESSID Cookie",
                            "target_url": "http://localhost:4280/vulnerabilities/authbypass/get_user_data.php?id=2",
                            "poc_request": (
                                "GET /vulnerabilities/authbypass/get_user_data.php?id=2 HTTP/1.1\n"
                                "Host: localhost:4280\n\n"
                            ),
                            "poc_response": "HTTP/1.1 200 OK\n\n{\"id\":2,\"role\":\"admin\"}",
                            "payloads_used": ["id=2"],
                            "additional_info": {
                                "authz_differential": {
                                    "scenario": "cookie_privilege_escalation",
                                    "requires_second_account": True,
                                    "precondition_status": "second_account_not_available",
                                    "reason": "second_account_not_available",
                                }
                            },
                        }
                    ]
                },
            }
        ]
    }

    result = compare_expected_detections(session_data)
    missing = {item["detection_id"]: item for item in result["missing_required"]}

    assert "authbypass_idor" in missing
    assert missing["authbypass_idor"]["match_count"] == 1
    assert missing["authbypass_idor"]["confirmed_match_count"] == 0
    assert missing["authbypass_idor"]["candidate_match_count"] == 1
    assert missing["authbypass_idor"]["match_status"] == "candidate"
    assert "untested_no_second_account" in missing["authbypass_idor"]["reason_codes"]


def test_candidate_to_confirm_detection_accepts_candidate_match_without_required_miss() -> None:
    session_data = {
        "completed_tasks": [
            {
                "id": "csrf",
                "result": {
                    "findings": [
                        {
                            "vuln_type": "misconfiguration",
                            "title": "CSRF Protection Missing (Tokenless Stateful Form)",
                            "target_url": "http://localhost:4280/vulnerabilities/csrf/",
                            "poc_request": (
                                "POST /vulnerabilities/csrf/ HTTP/1.1\n"
                                "Host: localhost:4280\n\n"
                                "password_new=hacked&password_conf=hacked&Change=Change"
                            ),
                            "poc_response": "HTTP/1.1 200 OK\n\nPassword Changed.",
                            "payloads_used": ["password_new=hacked"],
                            "additional_info": {
                                "detection_mode": "phase1",
                                "csrf_state_change": {},
                            },
                        }
                    ]
                },
            }
        ]
    }

    result = compare_expected_detections(session_data)
    matched = {item["detection_id"]: item for item in result["matched"]}
    missing = {item["detection_id"] for item in result["missing_required"]}

    assert "csrf_state_change" in matched
    assert "csrf_state_change" not in missing
    assert matched["csrf_state_change"]["match_status"] == "candidate"
    assert "state_change_not_verified" in matched["csrf_state_change"]["reason_codes"]


def test_finding_set_comparison_uses_vuln_title_and_normalized_target_url() -> None:
    baseline = [
        {
            "vuln_type": "open_redirect",
            "title": "Open Redirect in parameter 'redirect'",
            "target_url": "http://127.0.0.1:4280/vulnerabilities/open_redirect/source/low.php?redirect=info.php&id=1",
        }
    ]
    current = [
        {
            "vuln_type": "crlf_injection",
            "title": "CRLF Injection via parameter 'redirect'",
            "target_url": "http://localhost:4280/vulnerabilities/open_redirect/source/low.php?id=1&redirect=info.php",
        }
    ]

    baseline_key = normalize_finding_key(baseline[0])
    current_key = normalize_finding_key(current[0])

    assert baseline_key.target == current_key.target
    assert baseline_key.vuln_type != current_key.vuln_type

    diff = compare_finding_sets(baseline, current)

    assert diff["missing_in_current"][0]["vuln_type"] == "open_redirect"
    assert diff["new_in_current"][0]["vuln_type"] == "crlf_injection"
