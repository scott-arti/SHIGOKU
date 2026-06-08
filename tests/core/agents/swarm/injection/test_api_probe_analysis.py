from src.core.agents.swarm.injection.manager_internal.api_probe_analysis import (
    build_authz_differential,
)


def test_build_authz_differential_includes_expected_signals_and_confidence_for_close_successful_bodies():
    result = build_authz_differential(
        scenario="unauthenticated_api_access",
        baseline_status=200,
        test_status=200,
        baseline_body='{"user":"demo"}',
        test_body='{"user":"demo"}',
        baseline_json_like=True,
        test_json_like=True,
        length_close=True,
    )

    assert result == {
        "scenario": "unauthenticated_api_access",
        "confidence": 0.85,
        "baseline_status": 200,
        "test_status": 200,
        "signals": [
            "auth_success",
            "unauth_success",
            "auth_json_like",
            "unauth_json_like",
            "body_length_close",
        ],
        "auth_body_length": 15,
        "test_body_length": 15,
        "body_length_delta": 0,
        "body_length_delta_ratio": 0.0,
    }


def test_build_authz_differential_adds_extra_signals_once_and_caps_confidence():
    result = build_authz_differential(
        scenario="authenticated_overposting_requires_auth_context",
        baseline_status=401,
        test_status=200,
        baseline_body='{"error":"unauthorized"}',
        test_body='{"ok":true,"role":"admin"}',
        baseline_json_like=True,
        test_json_like=True,
        length_close=False,
        extra_signals=["status_improved_with_auth", "status_improved_with_auth", ""],
    )

    assert result["scenario"] == "authenticated_overposting_requires_auth_context"
    assert result["confidence"] == 0.75
    assert result["signals"] == [
        "unauth_success",
        "auth_json_like",
        "unauth_json_like",
        "status_improved_with_auth",
    ]
