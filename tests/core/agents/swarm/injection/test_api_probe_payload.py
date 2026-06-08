from src.core.agents.swarm.injection.manager_internal.api_probe_payload import (
    build_mass_assignment_probe_payload,
)


def test_build_mass_assignment_probe_payload_includes_marker_and_candidate_params():
    payload, params = build_mass_assignment_probe_payload(
        {
            "role": "admin",
            "is_admin": True,
            "__shigoku_probe": "ignored",
        }
    )

    assert payload == {
        "__shigoku_probe": "mass_assignment",
        "role": "admin",
        "is_admin": True,
    }
    assert params == ["role", "is_admin"]
