from src.core.agents.swarm.injection.manager_internal.api_probe_auth_context import (
    resolve_auth_b_context,
)


def test_resolve_auth_b_context_prefers_explicit_auth_b_headers():
    headers, role = resolve_auth_b_context(
        auth={
            "auth_b_headers": {"authorization": "Bearer alt", "cookie": "sid=2"},
            "auth_b_role": "reviewer",
        },
        auth_headers={"Authorization": "Bearer token"},
    )

    assert headers == {"Authorization": "Bearer alt", "Cookie": "sid=2"}
    assert role == "reviewer"


def test_resolve_auth_b_context_uses_first_distinct_multi_session_candidate():
    headers, role = resolve_auth_b_context(
        auth={"auth_matrix_from_multi_session": True},
        auth_headers={"Authorization": "Bearer token", "Cookie": "sid=1"},
        alternative_sessions={
            "same_user": {"headers": {"authorization": "Bearer token", "cookie": "sid=1"}},
            "empty_user": {"headers": {}},
            "user_b": {"headers": {"authorization": "Bearer alt", "cookie": "sid=2"}},
        },
    )

    assert headers == {"Authorization": "Bearer alt", "Cookie": "sid=2"}
    assert role == "user_b"
