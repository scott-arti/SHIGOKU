from __future__ import annotations

from src.core.observability.phase2_classification import (
    classify_failure_pattern,
    classify_schema_mismatch_severity,
)
from src.core.observability.flaky_quarantine import (
    FlakyQuarantinePolicy,
    FlakyQuarantineTracker,
    resolve_flaky_policy_from_settings,
)


def test_classify_failure_pattern() -> None:
    assert classify_failure_pattern(reason_code="TIMEOUT_PHASE2") == "timeout"
    assert classify_failure_pattern(reason_code="UNAUTHORIZED", error_message="network timeout") == "auth"
    assert classify_failure_pattern(error_message="401 unauthorized") == "auth"
    assert classify_failure_pattern(error_message="dns failure connection reset") == "network"
    assert classify_failure_pattern(error_message="schema mismatch at response") == "schema_mismatch"


def test_classify_schema_mismatch_severity() -> None:
    critical = classify_schema_mismatch_severity(removed=1, type_changed=2, missing_required_fields=1)
    assert critical["severity"] == "critical"

    high = classify_schema_mismatch_severity(type_changed=1)
    assert high["severity"] == "high"

    low = classify_schema_mismatch_severity(added=1)
    assert low["severity"] == "low"


def test_flaky_quarantine_tracker() -> None:
    tracker = FlakyQuarantineTracker(policy=FlakyQuarantinePolicy(window_size=5, min_failures=2))
    for outcome in [True, False, True, False, True]:
        tracker.record(outcome)
    verdict = tracker.evaluate()
    assert verdict["status"] == "quarantine"
    assert verdict["observed_failures"] == 2


def test_resolve_flaky_policy_from_settings_env_profile() -> None:
    class _Settings:
        flaky_quarantine_window_size = 20
        flaky_quarantine_min_failures = 2
        flaky_quarantine_release_success_streak = 3
        flaky_quarantine_environment = "prod"
        flaky_quarantine_env_profiles_json = (
            '{"prod": {"window_size": 30, "min_failures": 3, "release_success_streak": 5}}'
        )

    policy = resolve_flaky_policy_from_settings(_Settings())
    assert policy.window_size == 30
    assert policy.min_failures == 3
    assert policy.release_success_streak == 5
