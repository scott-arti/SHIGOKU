from src.core.agents.swarm.injection.manager_internal.target_selection import (
    extract_form_field_names,
    prioritize_targets,
)


def test_extract_form_field_names_handles_fields_and_inputs() -> None:
    forms = [
        {"fields": [{"name": "is_admin"}, {"name": "role"}]},
        {"inputs": ["token", {"name": "account_id"}]},
        {"fields": [{"name": ""}]},
        "ignored",
    ]

    assert extract_form_field_names(forms) == {"is_admin", "role", "token", "account_id"}


def test_prioritize_targets_matches_existing_behavior() -> None:
    targets = [
        "http://example.com/healthz",
        "http://example.com/api/account/update?id=1&role=user",
    ]
    forms_by_url = {
        "http://example.com/api/account/update?id=1&role=user": [
            {"fields": [{"name": "is_admin"}]},
        ]
    }
    url_evidence_by_url = {
        "http://example.com/api/account/update?id=1&role=user": {
            "method": "PATCH",
            "response_headers": {"Content-Type": "application/json"},
            "response_body_snippet": '{"role":"user","is_admin":false}',
        }
    }

    prioritized = prioritize_targets(
        targets,
        forms_by_url=forms_by_url,
        url_evidence_by_url=url_evidence_by_url,
        category="api_candidate",
    )

    assert prioritized
    top_url, top_score, top_signals = prioritized[0]
    assert top_url == "http://example.com/api/account/update?id=1&role=user"
    assert top_score > prioritized[-1][1]
    assert "method:PATCH" in top_signals
    assert "json_surface" in top_signals
    assert "high_signal_param" in top_signals
    assert "auth_boundary_surface" in top_signals
