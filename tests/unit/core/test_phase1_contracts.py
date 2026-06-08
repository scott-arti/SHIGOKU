from __future__ import annotations

from src.core.observability.phase1_contracts import (
    REQUIRED_OBSERVABILITY_FIELDS,
    ensure_observability_fields,
    evaluate_minimum_sample_size,
    generate_correlation_ids,
    validate_event_required_fields,
)


def test_generate_correlation_ids_has_required_keys() -> None:
    ids = generate_correlation_ids(build_id="build-123")
    assert ids["build_id"] == "build-123"
    assert ids["trace_id"]
    assert ids["request_id"]
    assert ids["test_case_id"] == "unassigned"


def test_validate_event_required_fields_missing() -> None:
    verdict = validate_event_required_fields({"trace_id": "t1"})
    assert verdict["status"] == "missing_fields"
    assert verdict["required_count"] == len(REQUIRED_OBSERVABILITY_FIELDS)
    assert "request_id" in verdict["missing_fields"]


def test_evaluate_minimum_sample_size_hold_then_ok() -> None:
    hold = evaluate_minimum_sample_size(10, 200)
    assert hold["status"] == "hold"
    assert hold["decision"] == "defer_alert"

    ok = evaluate_minimum_sample_size(250, 200)
    assert ok["status"] == "ok"
    assert ok["decision"] == "evaluate_alert"


def test_ensure_observability_fields_populates_required_defaults() -> None:
    payload = ensure_observability_fields(
        {"task_id": "t1"},
        correlation={"trace_id": "trace-a", "request_id": "req-a", "build_id": "b1"},
        endpoint="/graphql",
        error_type="none",
        timeout_ms=30,
        retry_count=1,
        test_case_id="tc-1",
    )
    verdict = validate_event_required_fields(payload)
    assert verdict["status"] == "ok"
    assert payload["trace_id"] == "trace-a"
    assert payload["endpoint"] == "/graphql"
