from src.core.agents.swarm.injection.manager_internal.api_probe_auth_matrix import (
    finalize_auth_context_matrix,
)


def test_finalize_auth_context_matrix_marks_available_and_adds_success_signals():
    matrix = finalize_auth_context_matrix(
        rows=[
            {"actor": "unauth", "status": 401},
            {"actor": "authA", "status": 200},
            {"actor": "authB", "status": 200},
        ],
        auth_status=200,
        unauth_status=401,
    )

    assert matrix["available"] is True
    assert matrix["signals"] == [
        "authA_success",
        "auth_boundary_observed",
        "authB_success",
        "authA_authB_both_success",
    ]


def test_finalize_auth_context_matrix_keeps_rows_and_handles_two_way_context():
    rows = [
        {"actor": "unauth", "status": 200},
        {"actor": "authA", "status": 200},
    ]
    matrix = finalize_auth_context_matrix(
        rows=rows,
        auth_status=200,
        unauth_status=200,
    )

    assert matrix["available"] is False
    assert matrix["rows"] == rows
    assert matrix["signals"] == ["authA_success", "unauth_success"]
