from src.core.agents.swarm.injection.manager_internal.api_probe_read_probe import (
    build_fallback_read_probe_url,
)


def test_build_fallback_read_probe_url_adds_default_probe_query_params():
    assert build_fallback_read_probe_url("http://example.com/api/users") == (
        "http://example.com/api/users?__shigoku_probe=mass_assignment_read_probe&role=admin&is_admin=true"
    )


def test_build_fallback_read_probe_url_preserves_existing_query_values():
    assert build_fallback_read_probe_url(
        "http://example.com/api/users?id=1&role=staff"
    ) == (
        "http://example.com/api/users?id=1&role=staff&__shigoku_probe=mass_assignment_read_probe&is_admin=true"
    )
