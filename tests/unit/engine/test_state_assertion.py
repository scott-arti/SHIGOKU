"""
Phase 7 Task 1: State Assertion Evaluator tests.

Tests:
  - mutating/aggressive lanes require precondition + postcondition
  - fresh_auth_context precondition validates auth_context_version
  - read_only / stateful_read lanes skip assertion
"""
from src.core.engine.state_assertion import evaluate_state_assertion


def test_mutating_assertion_requires_pre_and_post_conditions():
    result = evaluate_state_assertion(
        lane="mutating",
        assertion={"precondition": "fresh_auth_context"},
        task_metadata={"auth_context_version": 3},
        current_versions={"auth_context_version": 3},
    )

    assert result.allowed is False
    assert result.reason_code == "state_assertion_postcondition_missing"


def test_mutating_assertion_passes_with_fresh_auth_and_postcondition():
    result = evaluate_state_assertion(
        lane="mutating",
        assertion={
            "precondition": "fresh_auth_context",
            "postcondition": "no_persistent_side_effect",
        },
        task_metadata={"auth_context_version": 3},
        current_versions={"auth_context_version": 3},
    )

    assert result.allowed is True
    assert result.reason_code == ""
    assert result.audit["assertion_result"] == "passed"


def test_stale_auth_context_fails_precondition():
    result = evaluate_state_assertion(
        lane="mutating",
        assertion={
            "precondition": "fresh_auth_context",
            "postcondition": "no_persistent_side_effect",
        },
        task_metadata={"auth_context_version": 2},
        current_versions={"auth_context_version": 3},
    )

    assert result.allowed is False
    assert result.reason_code == "state_assertion_stale_auth_context"


def test_aggressive_lane_also_requires_state_assertion():
    result = evaluate_state_assertion(
        lane="aggressive_exclusive",
        assertion={
            "precondition": "fresh_auth_context",
            "postcondition": "low_noise_attested",
        },
        task_metadata={"auth_context_version": 3},
        current_versions={"auth_context_version": 3},
    )

    assert result.allowed is True


def test_read_only_lane_skips_assertion():
    result = evaluate_state_assertion(
        lane="read_only",
        assertion=None,
        task_metadata={},
        current_versions={},
    )

    assert result.allowed is True
    assert result.audit["assertion_result"] == "not_required"


def test_stateful_read_lane_skips_assertion():
    result = evaluate_state_assertion(
        lane="stateful_read",
        assertion=None,
        task_metadata={},
        current_versions={},
    )

    assert result.allowed is True
    assert result.audit["assertion_result"] == "not_required"


def test_missing_precondition_rejected():
    result = evaluate_state_assertion(
        lane="mutating",
        assertion={"postcondition": "no_persistent_side_effect"},
        task_metadata={"auth_context_version": 3},
        current_versions={"auth_context_version": 3},
    )

    assert result.allowed is False
    assert result.reason_code == "state_assertion_precondition_missing"


def test_none_assertion_treated_as_missing():
    result = evaluate_state_assertion(
        lane="mutating",
        assertion=None,
        task_metadata={"auth_context_version": 3},
        current_versions={"auth_context_version": 3},
    )

    assert result.allowed is False
    assert result.reason_code == "state_assertion_precondition_missing"


def test_current_auth_zero_skips_stale_check():
    """When current auth_context_version is 0 (unknown), stale check is skipped."""
    result = evaluate_state_assertion(
        lane="mutating",
        assertion={
            "precondition": "fresh_auth_context",
            "postcondition": "no_persistent_side_effect",
        },
        task_metadata={"auth_context_version": 2},
        current_versions={"auth_context_version": 0},
    )

    assert result.allowed is True
