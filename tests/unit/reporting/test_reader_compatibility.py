"""T-5.1: Reader compatibility tests.

Tests for src/reporting/reader_compatibility.py:
  - check_reader_compatibility with old and new artifact types
"""

from src.reporting.reader_compatibility import check_reader_compatibility


# -- T-5.1 test 1: old_session_artifact_readable -------------------------------

def test_old_session_artifact_readable():
    """Pre-Phase 6 session artifact with standard keys must be readable."""
    artifacts = [
        {
            "_artifact_type": "session",
            "completed_tasks": [
                {"id": "task-1", "result": {"findings": []}},
            ],
            "session_id": "sess-001",
            "status": "completed",
            "metadata": {"started_at": "2025-01-01T00:00:00Z"},
        }
    ]
    result = check_reader_compatibility(artifacts)
    assert result["reader_compatibility_status"] == "pass"
    assert len(result["errors"]) == 0


def test_old_session_missing_standard_keys_fails():
    """A session artifact with no standard keys should produce an error."""
    artifacts = [
        {
            "_artifact_type": "session",
            "custom_field": "custom_value",
        }
    ]
    result = check_reader_compatibility(artifacts)
    assert result["reader_compatibility_status"] == "fail"
    assert any("no standard session keys" in e for e in result["errors"])


# -- T-5.1 test 2: phase6_decision_traces_readable -----------------------------

def test_phase6_decision_traces_readable():
    """Phase 6 decision_traces with TASK_RETIRED/TASK_SUPERSEDED/TASK_INVALIDATED must be readable."""
    for dtype in ("task_retired", "task_superseded", "task_invalidated"):
        artifacts = [
            {
                "_artifact_type": "decision_trace",
                "decision_type": dtype,
                "decision_id": "dec_0001",
                "timestamp": "2025-06-01T00:00:00Z",
                "reasoning": "pruned because snapshot expired",
            }
        ]
        result = check_reader_compatibility(artifacts)
        assert result["reader_compatibility_status"] == "pass", f"failed for {dtype}"


def test_phase6_decision_trace_with_standard_types():
    """Phase 6 decision_traces with standard dispatch types must be readable."""
    standard_types = [
        "recon_dispatch", "vuln_hunter_dispatch", "recipe_injection",
        "replan", "priority_boost", "target_escalate", "skip_task", "fallback",
    ]
    for dtype in standard_types:
        artifacts = [
            {
                "_artifact_type": "decision_trace",
                "decision_type": dtype,
                "decision_id": "dec_0001",
                "timestamp": "2025-06-01T00:00:00Z",
            }
        ]
        result = check_reader_compatibility(artifacts)
        assert result["reader_compatibility_status"] == "pass", f"failed for {dtype}"


def test_phase6_decision_trace_missing_decision_type():
    """Missing decision_type should produce an error."""
    artifacts = [
        {
            "_artifact_type": "decision_trace",
            "decision_id": "dec_0001",
        }
    ]
    result = check_reader_compatibility(artifacts)
    assert result["reader_compatibility_status"] == "fail"
    assert any("missing decision_type" in e for e in result["errors"])


# -- T-5.1 test 3: phase8_shadow_decisions_readable ----------------------------

def test_phase8_shadow_decisions_readable():
    """Phase 8 SwarmResult with shadow_decisions field must be readable."""
    artifacts = [
        {
            "_artifact_type": "swarm_result",
            "swarm_name": "xss_test",
            "status": "success",
            "findings": [],
            "shadow_decisions": [
                {"url": "https://example.com/page?id=1", "dispatch": "parallel"},
                {"url": "https://example.com/page?id=2", "dispatch": "serial"},
            ],
        }
    ]
    result = check_reader_compatibility(artifacts)
    assert result["reader_compatibility_status"] == "pass"
    assert len(result["errors"]) == 0


def test_phase8_shadow_decisions_missing_field():
    """Missing shadow_decisions field should produce an error."""
    artifacts = [
        {
            "_artifact_type": "swarm_result",
            "swarm_name": "xss_test",
            "status": "success",
        }
    ]
    result = check_reader_compatibility(artifacts)
    assert result["reader_compatibility_status"] == "fail"
    assert any("missing shadow_decisions" in e for e in result["errors"])


def test_phase8_shadow_decisions_not_a_list():
    """shadow_decisions that is not a list should produce an error."""
    artifacts = [
        {
            "_artifact_type": "swarm_result",
            "shadow_decisions": "not-a-list",
        }
    ]
    result = check_reader_compatibility(artifacts)
    assert result["reader_compatibility_status"] == "fail"
    assert any("not a list" in e for e in result["errors"])


# -- T-5.1 test 4: phase9_evidence_bundle_readable -----------------------------

def test_phase9_evidence_bundle_readable():
    """Phase 9 evidence bundle with extended metrics must be readable."""
    artifacts = [
        {
            "_artifact_type": "evidence_bundle",
            "rollback_drill_status": "pass",
            "reader_compatibility_status": "pass",
            "config_diff": {},
            "operator_command": "SET parallelism.kill_switch = true",
            "verification_result": {"serial_path_confirmed": True},
            "reason_code": "ROLLBACK_DRILL_PASS",
            "timestamp": "2026-06-30T00:00:00Z",
            # Extended metrics (optional)
            "extended_metrics": {
                "serial_latency_ms": 120,
                "gated_latency_ms": 45,
            },
        }
    ]
    result = check_reader_compatibility(artifacts)
    assert result["reader_compatibility_status"] == "pass"
    assert len(result["errors"]) == 0


def test_phase9_evidence_bundle_minimal():
    """Phase 9 evidence bundle with minimal fields should pass."""
    artifacts = [
        {
            "_artifact_type": "evidence_bundle",
            "rollback_drill_status": "fail",
            "reason_code": "SERIAL_PATH_NOT_CONFIRMED",
        }
    ]
    result = check_reader_compatibility(artifacts)
    assert result["reader_compatibility_status"] == "pass"
    assert len(result["errors"]) == 0


# -- T-5.1 test 5: unknown_schema_version_not_blocking -------------------------

def test_unknown_schema_version_not_blocking():
    """Unknown _artifact_type should NOT block (skipped with no error)."""
    artifacts = [
        {
            "_artifact_type": "future_schema_v99",
            "some_field": "some_value",
        }
    ]
    result = check_reader_compatibility(artifacts)
    assert result["reader_compatibility_status"] == "pass"
    assert len(result["errors"]) == 0


# -- Mixed / edge case tests ---------------------------------------------------

def test_mixed_artifacts_all_pass():
    """A mix of valid artifacts should all pass."""
    artifacts = [
        {
            "_artifact_type": "session",
            "session_id": "s1",
            "completed_tasks": [],
            "status": "completed",
        },
        {
            "_artifact_type": "decision_trace",
            "decision_type": "task_retired",
            "decision_id": "d1",
        },
        {
            "_artifact_type": "swarm_result",
            "shadow_decisions": [],
        },
        {
            "_artifact_type": "evidence_bundle",
            "rollback_drill_status": "pass",
        },
    ]
    result = check_reader_compatibility(artifacts)
    assert result["reader_compatibility_status"] == "pass"
    assert len(result["errors"]) == 0


def test_mixed_artifacts_one_fails():
    """If one artifact fails, overall status is fail."""
    artifacts = [
        {
            "_artifact_type": "session",
            "session_id": "s1",
            "completed_tasks": [],
            "status": "completed",
        },
        {
            "_artifact_type": "swarm_result",
            # missing shadow_decisions -> fail
        },
    ]
    result = check_reader_compatibility(artifacts)
    assert result["reader_compatibility_status"] == "fail"
    assert len(result["errors"]) == 1


def test_non_dict_artifact_errors():
    """Non-dict artifacts should produce errors."""
    artifacts = [
        {"_artifact_type": "session", "session_id": "ok"},
        "not-a-dict",  # type: ignore[arg-type]
    ]
    result = check_reader_compatibility(artifacts)
    assert result["reader_compatibility_status"] == "fail"
    assert any("not a dict" in e for e in result["errors"])


def test_missing_artifact_type_errors():
    """Artifacts without _artifact_type should produce errors."""
    artifacts = [
        {"session_id": "no-type"},
    ]
    result = check_reader_compatibility(artifacts)
    assert result["reader_compatibility_status"] == "fail"
    assert any("missing _artifact_type" in e for e in result["errors"])


def test_empty_artifacts_list():
    """Empty list should pass."""
    result = check_reader_compatibility([])
    assert result["reader_compatibility_status"] == "pass"
    assert len(result["errors"]) == 0
