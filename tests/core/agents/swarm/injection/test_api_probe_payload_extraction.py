"""Unit tests for extracted API probe payload helper functions."""

from src.core.agents.swarm.injection.manager_internal.api_probe_payload import (
    parse_json_dict,
    mutate_schema_candidate_value,
    extract_mass_assignment_schema_candidates,
    build_mass_assignment_variant_payload,
)


# ── parse_json_dict ──

def test_parse_json_dict_empty():
    assert parse_json_dict("") == {}
    assert parse_json_dict("   ") == {}


def test_parse_json_dict_valid_dict():
    assert parse_json_dict('{"key": "value"}') == {"key": "value"}


def test_parse_json_dict_valid_array_returns_empty():
    assert parse_json_dict("[1, 2, 3]") == {}


def test_parse_json_dict_invalid_json():
    assert parse_json_dict("not json") == {}


def test_parse_json_dict_none_or_non_string():
    assert parse_json_dict(None) == {}


# ── mutate_schema_candidate_value ──

def test_mutate_schema_bool_flips():
    assert mutate_schema_candidate_value("is_admin", True) is False
    assert mutate_schema_candidate_value("is_admin", False) is True


def test_mutate_schema_int_increments():
    assert mutate_schema_candidate_value("quota", 100) == 101
    assert mutate_schema_candidate_value("quota", -5) == 1


def test_mutate_schema_empty_list_role_token():
    result = mutate_schema_candidate_value("role", [])
    assert result == ["admin"]


def test_mutate_schema_nonempty_list_mutates_first():
    result = mutate_schema_candidate_value("role", ["user"])
    assert result == ["admin"]


def test_mutate_schema_string_role_returns_admin():
    assert mutate_schema_candidate_value("role", "user") == "admin"


def test_mutate_schema_string_status_returns_active():
    assert mutate_schema_candidate_value("status", "inactive") == "active"


def test_mutate_schema_string_plan_returns_premium():
    assert mutate_schema_candidate_value("plan", "free") == "premium"


def test_mutate_schema_string_quota_returns_99999():
    assert mutate_schema_candidate_value("quota", "0") == "99999"


def test_mutate_schema_string_verified_returns_true():
    assert mutate_schema_candidate_value("verified", "false") == "true"


def test_mutate_schema_unknown_key_returns_none():
    assert mutate_schema_candidate_value("unknown_field", "value") is None


def test_mutate_schema_empty_token_returns_none():
    assert mutate_schema_candidate_value("", "value") is None


def test_mutate_schema_list_nested_mutation():
    result = mutate_schema_candidate_value("roles", [False])
    assert result == [True]


def test_mutate_schema_non_risk_key_empty_list_returns_none():
    assert mutate_schema_candidate_value("tags", []) is None


# ── extract_mass_assignment_schema_candidates ──

EXCLUDED = {"url", "method", "params", "body", "headers", "id"}


def test_extract_mass_assignment_basic():
    bodies = ['{"role": "user", "is_admin": false}']
    result = extract_mass_assignment_schema_candidates(
        response_bodies=bodies, excluded_params=EXCLUDED,
    )
    assert "role" in result
    assert result["role"] == "admin"
    assert "is_admin" in result


def test_extract_mass_assignment_nested_container():
    bodies = ['{"data": {"role": "user", "status": "inactive"}}']
    result = extract_mass_assignment_schema_candidates(
        response_bodies=bodies, excluded_params=EXCLUDED,
    )
    assert "role" in result
    assert result["role"] == "admin"
    assert "status" in result


def test_extract_mass_assignment_respects_cap():
    bodies = ['{"role": "user", "status": "active", "plan": "free", "quota": "5", "verified": "false", "type": "basic", "flag": "0"}']
    result = extract_mass_assignment_schema_candidates(
        response_bodies=bodies, cap=3, excluded_params=EXCLUDED,
    )
    assert len(result) <= 3


def test_extract_mass_assignment_empty_bodies():
    result = extract_mass_assignment_schema_candidates(
        response_bodies=[], excluded_params=EXCLUDED,
    )
    assert result == {"role": "admin", "is_admin": True}


def test_extract_mass_assignment_excluded_params_skipped():
    bodies = ['{"url": "test", "method": "GET"}']
    result = extract_mass_assignment_schema_candidates(
        response_bodies=bodies, excluded_params=EXCLUDED,
    )
    assert "url" not in result
    assert "method" not in result


# ── build_mass_assignment_variant_payload ──

def test_build_variant_bool_flips():
    probe = {"is_admin": False, "active": True}
    result = build_mass_assignment_variant_payload(probe, "marker")
    assert result["is_admin"] is True
    assert result["active"] is False
    assert result["__shigoku_probe"] == "marker"


def test_build_variant_int_increments():
    probe = {"limit": 10}
    result = build_mass_assignment_variant_payload(probe, "marker")
    assert result["limit"] == 11


def test_build_variant_str_admin_flips():
    probe = {"role": "admin"}
    result = build_mass_assignment_variant_payload(probe, "marker")
    assert result["role"] == "auditor"


def test_build_variant_list_mutates():
    probe = {"roles": ["user"]}
    result = build_mass_assignment_variant_payload(probe, "marker")
    assert result["roles"] == ["admin"]


def test_build_variant_skips_probe_key():
    probe = {"__shigoku_probe": "old", "role": "user"}
    result = build_mass_assignment_variant_payload(probe, "marker")
    assert result["__shigoku_probe"] == "marker"
    assert result["role"] == "admin"


def test_build_variant_empty_list():
    probe = {"roles": []}
    result = build_mass_assignment_variant_payload(probe, "marker")
    assert result["roles"] == ["auditor"]


def test_build_variant_other_type_preserved():
    probe = {"unknown": None}
    result = build_mass_assignment_variant_payload(probe, "marker")
    assert result["unknown"] is None


def test_build_variant_int_list():
    probe = {"ids": [10]}
    result = build_mass_assignment_variant_payload(probe, "marker")
    assert result["ids"] == [11]
