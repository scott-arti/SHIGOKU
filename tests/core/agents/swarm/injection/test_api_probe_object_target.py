from src.core.agents.swarm.injection.manager_internal.api_probe_object_target import (
    build_object_ab_target,
)


def test_build_object_ab_target_mutates_query_id_first():
    assert build_object_ab_target("http://example.com/api/users?id=1") == {
        "param": "id",
        "resource_a": "1",
        "resource_b": "2",
        "mutated_url": "http://example.com/api/users?id=2",
        "location": "query",
    }


def test_build_object_ab_target_mutates_last_numeric_path_segment():
    assert build_object_ab_target("http://example.com/api/users/41/profile") == {
        "param": "path_id",
        "resource_a": "41",
        "resource_b": "42",
        "mutated_url": "http://example.com/api/users/42/profile",
        "location": "path",
    }
