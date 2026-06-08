from src.core.agents.swarm.injection.manager import InjectionManagerAgent


def test_injection_manager_prioritize_targets_character() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
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

    prioritized = manager._prioritize_targets(
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
