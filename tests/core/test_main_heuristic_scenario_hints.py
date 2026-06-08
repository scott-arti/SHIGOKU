from src.main import (
    _build_heuristic_findings_from_execution_notes,
    _merge_heuristic_candidates_into_findings,
)


def test_heuristic_candidates_do_not_attach_scn12_to_privilege_parameter_surface() -> None:
    execution_notes = [
        {
            "url": "http://example.com/api/user/profile",
            "vuln_type": "api",
            "status": "completed",
            "duration_seconds": 0.2,
            "tested_params": ["role", "is_admin"],
            "blind_correlation": {},
        }
    ]
    scenario_coverage = {
        "missing_scenarios": [
            "scn_11_multi_vector_chain",
            "scn_12_advanced_ssrf_internal_topology",
        ]
    }

    candidates = _build_heuristic_findings_from_execution_notes(
        execution_notes,
        target="http://example.com/",
        scenario_coverage=scenario_coverage,
    )

    assert candidates
    hints = candidates[0].get("additional_info", {}).get("scenario_hints", [])
    assert "scn_11_multi_vector_chain" in hints
    assert "scn_12_advanced_ssrf_internal_topology" not in hints


def test_heuristic_candidates_attach_scn12_for_ssrf_like_parameters() -> None:
    execution_notes = [
        {
            "url": "http://example.com/api/fetch",
            "vuln_type": "api",
            "status": "completed",
            "duration_seconds": 0.1,
            "tested_params": ["callback", "target"],
            "blind_correlation": {},
        }
    ]
    scenario_coverage = {
        "missing_scenarios": [
            "scn_12_advanced_ssrf_internal_topology",
        ]
    }

    candidates = _build_heuristic_findings_from_execution_notes(
        execution_notes,
        target="http://example.com/",
        scenario_coverage=scenario_coverage,
    )

    assert candidates
    hints = candidates[0].get("additional_info", {}).get("scenario_hints", [])
    assert "scn_12_advanced_ssrf_internal_topology" in hints


def test_heuristic_candidates_map_privilege_surface_to_mass_assignment_type() -> None:
    execution_notes = [
        {
            "url": "http://127.0.0.1:8888/account/settings",
            "vuln_type": "api",
            "status": "completed",
            "duration_seconds": 0.03,
            "tested_params": ["role", "is_admin"],
            "blind_correlation": {},
        }
    ]

    candidates = _build_heuristic_findings_from_execution_notes(
        execution_notes,
        target="http://127.0.0.1:8888/",
        scenario_coverage={},
    )

    assert candidates
    assert candidates[0].get("vuln_type") == "mass_assignment"
    assert candidates[0].get("additional_info", {}).get("detection_class") == "mass_assignment"


def test_heuristic_api_surface_sets_endpoint_bfla_detection_class() -> None:
    execution_notes = [
        {
            "url": "http://127.0.0.1:8888/api/admin/users",
            "vuln_type": "api",
            "status": "completed",
            "duration_seconds": 0.03,
            "tested_params": ["page"],
            "blind_correlation": {},
        }
    ]

    candidates = _build_heuristic_findings_from_execution_notes(
        execution_notes,
        target="http://127.0.0.1:8888/",
        scenario_coverage={},
    )

    assert candidates
    assert candidates[0].get("vuln_type") == "api"
    assert candidates[0].get("additional_info", {}).get("detection_class") == "endpoint_bfla"


def test_heuristic_privilege_surface_auto_promotes_when_repeated_successful_probes() -> None:
    execution_notes = [
        {
            "url": "http://127.0.0.1:8888/account/settings",
            "vuln_type": "api",
            "status": "completed",
            "duration_seconds": 0.03,
            "tested_params": ["role", "is_admin"],
            "probe_sent": True,
            "blind_correlation": {},
        },
        {
            "url": "http://127.0.0.1:8888/account/settings",
            "vuln_type": "api",
            "status": "completed",
            "duration_seconds": 0.04,
            "tested_params": ["role", "is_admin"],
            "probe_sent": True,
            "blind_correlation": {},
        },
    ]

    candidates = _build_heuristic_findings_from_execution_notes(
        execution_notes,
        target="http://127.0.0.1:8888/",
        scenario_coverage={},
    )

    assert candidates
    info = candidates[0].get("additional_info", {})
    assert candidates[0].get("vuln_type") == "mass_assignment"
    assert info.get("heuristic_candidate") is False
    assert info.get("verification_required") is False
    assert info.get("detection_mode") == "heuristic_promoted"
    assert "manual verification required" not in str(candidates[0].get("summary", "")).lower()
    assert "not yet confirmed" not in str(candidates[0].get("impact", "")).lower()


def test_heuristic_privilege_surface_promoted_candidate_carries_poc_from_execution_notes() -> None:
    execution_notes = [
        {
            "url": "http://127.0.0.1:8888/account/settings",
            "vuln_type": "api",
            "status": "completed",
            "duration_seconds": 0.03,
            "tested_params": ["role", "is_admin"],
            "probe_sent": True,
            "poc_request": "PATCH /account/settings HTTP/1.1\nContent-Type: application/json\n\n{\"role\":\"admin\"}",
            "poc_response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"role\":\"admin\"}",
            "blind_correlation": {},
        },
        {
            "url": "http://127.0.0.1:8888/account/settings",
            "vuln_type": "api",
            "status": "completed",
            "duration_seconds": 0.04,
            "tested_params": ["role", "is_admin"],
            "probe_sent": True,
            "poc_request": "PATCH /account/settings HTTP/1.1\nContent-Type: application/json\n\n{\"role\":\"auditor\"}",
            "poc_response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"role\":\"auditor\"}",
            "blind_correlation": {},
        },
    ]

    candidates = _build_heuristic_findings_from_execution_notes(
        execution_notes,
        target="http://127.0.0.1:8888/",
        scenario_coverage={},
    )

    assert candidates
    top = candidates[0]
    info = top.get("additional_info", {})
    assert info.get("detection_mode") == "heuristic_promoted"
    assert bool(str(top.get("poc_request", "")).strip())
    assert bool(str(top.get("poc_response", "")).strip())
    assert bool(str(info.get("poc_request", "")).strip())
    assert bool(str(info.get("poc_response", "")).strip())


def test_heuristic_privilege_surface_stays_candidate_without_repeat_signal() -> None:
    execution_notes = [
        {
            "url": "http://127.0.0.1:8888/account/settings",
            "vuln_type": "api",
            "status": "completed",
            "duration_seconds": 0.03,
            "tested_params": ["role", "is_admin"],
            "probe_sent": True,
            "blind_correlation": {},
        },
    ]

    candidates = _build_heuristic_findings_from_execution_notes(
        execution_notes,
        target="http://127.0.0.1:8888/",
        scenario_coverage={},
    )

    assert candidates
    info = candidates[0].get("additional_info", {})
    assert info.get("heuristic_candidate") is True
    assert info.get("verification_required") is True
    assert info.get("detection_mode") == "heuristic_fallback"
    assert "not yet confirmed" in str(candidates[0].get("impact", "")).lower()


def test_heuristic_privilege_surface_does_not_promote_on_duplicate_note_rows() -> None:
    duplicated_note = {
        "url": "http://127.0.0.1:8888/account/settings",
        "vuln_type": "api",
        "status": "completed",
        "duration_seconds": 0.03,
        "tested_params": ["role", "is_admin"],
        "probe_sent": True,
        "blind_correlation": {},
    }
    execution_notes = [duplicated_note, dict(duplicated_note)]

    candidates = _build_heuristic_findings_from_execution_notes(
        execution_notes,
        target="http://127.0.0.1:8888/",
        scenario_coverage={},
    )

    assert candidates
    info = candidates[0].get("additional_info", {})
    repeat_signal = info.get("repeat_signal", {})
    assert info.get("detection_mode") == "heuristic_fallback"
    assert info.get("heuristic_candidate") is True
    assert int(repeat_signal.get("privilege_probe", 0) or 0) == 1


def test_heuristic_privilege_surface_respects_custom_promotion_thresholds() -> None:
    execution_notes = [
        {
            "url": "http://127.0.0.1:8888/account/settings",
            "vuln_type": "api",
            "status": "completed",
            "duration_seconds": 0.03,
            "tested_params": ["role", "is_admin"],
            "probe_sent": True,
            "blind_correlation": {},
        },
    ]

    promoted = _build_heuristic_findings_from_execution_notes(
        execution_notes,
        target="http://127.0.0.1:8888/",
        scenario_coverage={},
        promote_privilege_probe_min=1,
        promote_completed_probe_min=1,
    )
    assert promoted
    promoted_info = promoted[0].get("additional_info", {})
    promoted_repeat = promoted_info.get("repeat_signal", {})
    assert promoted_info.get("detection_mode") == "heuristic_promoted"
    assert int(promoted_repeat.get("privilege_probe_min", 0) or 0) == 1
    assert int(promoted_repeat.get("completed_with_probe_min", 0) or 0) == 1

    fallback = _build_heuristic_findings_from_execution_notes(
        execution_notes,
        target="http://127.0.0.1:8888/",
        scenario_coverage={},
        promote_privilege_probe_min=2,
        promote_completed_probe_min=2,
    )
    assert fallback
    fallback_info = fallback[0].get("additional_info", {})
    fallback_repeat = fallback_info.get("repeat_signal", {})
    assert fallback_info.get("detection_mode") == "heuristic_fallback"
    assert int(fallback_repeat.get("privilege_probe_min", 0) or 0) == 2
    assert int(fallback_repeat.get("completed_with_probe_min", 0) or 0) == 2


def test_merge_heuristic_candidates_keeps_confirmed_and_appends_candidates() -> None:
    confirmed = [
        {
            "title": "Potential Unauthenticated API Access",
            "vuln_type": "broken_access_control",
            "target_url": "http://127.0.0.1:8888/chatbot/genai/state",
            "severity": "medium",
        }
    ]
    heuristic_candidates = [
        {
            "title": "Potential privilege parameter tampering surface",
            "vuln_type": "api",
            "target_url": "http://127.0.0.1:8888/account/settings",
            "severity": "medium",
            "additional_info": {"heuristic_candidate": True, "verification_required": True},
        }
    ]

    merged = _merge_heuristic_candidates_into_findings(
        confirmed_findings=confirmed,
        heuristic_candidates=heuristic_candidates,
        max_append=3,
    )

    assert len(merged) == 2
    assert any(item.get("title") == "Potential Unauthenticated API Access" for item in merged)
    assert any(item.get("title") == "Potential privilege parameter tampering surface" for item in merged)


def test_merge_heuristic_candidates_skips_duplicate_signature() -> None:
    confirmed = [
        {
            "title": "Potential privilege parameter tampering surface",
            "vuln_type": "api",
            "target_url": "http://127.0.0.1:8888/account/settings",
            "severity": "medium",
        }
    ]
    heuristic_candidates = [
        {
            "title": "Potential privilege parameter tampering surface",
            "vuln_type": "api",
            "target_url": "http://127.0.0.1:8888/account/settings",
            "severity": "medium",
            "additional_info": {"heuristic_candidate": True, "verification_required": True},
        }
    ]

    merged = _merge_heuristic_candidates_into_findings(
        confirmed_findings=confirmed,
        heuristic_candidates=heuristic_candidates,
        max_append=3,
    )

    assert len(merged) == 1


def test_merge_heuristic_candidates_skips_same_target_as_confirmed() -> None:
    confirmed = [
        {
            "title": "Potential Unauthenticated API Access",
            "vuln_type": "broken_access_control",
            "target_url": "http://127.0.0.1:8888/chatbot/genai/state",
            "severity": "medium",
        }
    ]
    heuristic_candidates = [
        {
            "title": "Potential privilege parameter tampering surface",
            "vuln_type": "api",
            "target_url": "http://127.0.0.1:8888/chatbot/genai/state",
            "severity": "medium",
            "additional_info": {"heuristic_candidate": True, "verification_required": True},
        },
        {
            "title": "Potential privilege parameter tampering surface",
            "vuln_type": "api",
            "target_url": "http://127.0.0.1:8888/account/settings",
            "severity": "medium",
            "additional_info": {"heuristic_candidate": True, "verification_required": True},
        },
    ]

    merged = _merge_heuristic_candidates_into_findings(
        confirmed_findings=confirmed,
        heuristic_candidates=heuristic_candidates,
        max_append=3,
    )

    assert len(merged) == 2
    assert any(item.get("target_url") == "http://127.0.0.1:8888/account/settings" for item in merged)
    assert not any(
        item.get("title") == "Potential privilege parameter tampering surface"
        and item.get("target_url") == "http://127.0.0.1:8888/chatbot/genai/state"
        for item in merged
    )


def test_merge_heuristic_candidates_allows_promoted_on_same_target_with_different_vuln_type() -> None:
    confirmed = [
        {
            "title": "Potential Unauthenticated API Access",
            "vuln_type": "broken_access_control",
            "target_url": "http://127.0.0.1:8888/chatbot/genai/state",
            "severity": "medium",
        }
    ]
    heuristic_candidates = [
        {
            "title": "Potential privilege parameter tampering surface",
            "vuln_type": "mass_assignment",
            "target_url": "http://127.0.0.1:8888/chatbot/genai/state",
            "severity": "medium",
            "additional_info": {
                "heuristic_candidate": False,
                "verification_required": False,
                "detection_mode": "heuristic_promoted",
            },
        }
    ]

    merged = _merge_heuristic_candidates_into_findings(
        confirmed_findings=confirmed,
        heuristic_candidates=heuristic_candidates,
        max_append=3,
    )

    assert len(merged) == 2
    assert any(item.get("vuln_type") == "broken_access_control" for item in merged)
    assert any(
        item.get("vuln_type") == "mass_assignment"
        and item.get("target_url") == "http://127.0.0.1:8888/chatbot/genai/state"
        for item in merged
    )
