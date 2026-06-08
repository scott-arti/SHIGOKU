from __future__ import annotations

from pathlib import Path

import pytest

from src.core.engine.master_conductor import MasterConductor
from src.core.intelligence.chain_builder import AttackChainBuilder
from src.core.reporting.platform_integration import ReportDraft


PLAN_PATH = (
    Path(__file__).resolve().parents[3]
    / "docs"
    / "shigoku"
    / "plans"
    / "2026-06-01_task_plan.md"
)


def _read_plan_text() -> str:
    return PLAN_PATH.read_text(encoding="utf-8")


def test_phase2_plan_documents_benchmark_manifest_and_gate_metrics() -> None:
    text = _read_plan_text()

    assert "Phase 2（運用安定化 / Step 19〜27）" in text
    assert "benchmark_manifest" in text
    assert "Cost per actionable chain" in text
    assert "監査ログ再現性" in text
    assert "Phase 2終了判定" in text


def test_phase2_benchmark_manifest_freezes_reproducibility_contract() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    create_benchmark_manifest = getattr(builder, "create_benchmark_manifest", None)
    assert callable(create_benchmark_manifest)

    manifest = create_benchmark_manifest(
        {
            "corpus": ["juice-shop", "crapi"],
            "seed": 4242,
            "headers": {"X-Test-Mode": "phase2"},
            "session_policy": "relogin-per-chain",
            "label_snapshot": "labels-2026-06-02",
            "comparison_period": "2026-Q2",
        }
    )

    assert manifest["manifest_id"].startswith("bm-")
    assert manifest["corpus"] == ["juice-shop", "crapi"]
    assert manifest["seed"] == 4242
    assert manifest["headers"] == {"X-Test-Mode": "phase2"}
    assert manifest["session_policy"] == "relogin-per-chain"
    assert manifest["label_snapshot"] == "labels-2026-06-02"
    assert manifest["comparison_period"] == "2026-Q2"


def test_phase2_kpi_evaluation_requires_same_manifest_for_baseline_comparison() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    create_benchmark_manifest = getattr(builder, "create_benchmark_manifest", None)
    evaluate_phase2_kpis = getattr(builder, "evaluate_phase2_kpis", None)
    assert callable(create_benchmark_manifest)
    assert callable(evaluate_phase2_kpis)

    baseline_manifest = create_benchmark_manifest(
        {
            "corpus": ["juice-shop"],
            "seed": 7,
            "headers": {"X-Test-Mode": "baseline"},
            "session_policy": "sticky",
            "label_snapshot": "labels-a",
            "comparison_period": "2026-Q2",
        }
    )
    current_manifest = create_benchmark_manifest(
        {
            "corpus": ["juice-shop"],
            "seed": 8,
            "headers": {"X-Test-Mode": "baseline"},
            "session_policy": "sticky",
            "label_snapshot": "labels-a",
            "comparison_period": "2026-Q2",
        }
    )

    with pytest.raises(ValueError, match="manifest"):
        evaluate_phase2_kpis(
            manifest=current_manifest,
            baseline_manifest=baseline_manifest,
            current_metrics={
                "valid_submission_rate": 0.62,
                "expected_bounty_at_5": 1500,
                "cost_per_actionable_chain": 18,
                "precision_at_5": 0.82,
                "cpu_time_per_confirmed_chain": 1.08,
            },
            baseline_metrics={
                "valid_submission_rate": 0.50,
                "expected_bounty_at_5": 1200,
                "cost_per_actionable_chain": 20,
                "precision_at_5": 0.76,
                "cpu_time_per_confirmed_chain": 1.00,
            },
        )


def test_phase2_kpi_evaluation_splits_go_no_go_and_diagnostic_metrics() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    create_benchmark_manifest = getattr(builder, "create_benchmark_manifest", None)
    evaluate_phase2_kpis = getattr(builder, "evaluate_phase2_kpis", None)
    assert callable(create_benchmark_manifest)
    assert callable(evaluate_phase2_kpis)

    manifest = create_benchmark_manifest(
        {
            "corpus": ["juice-shop", "crapi"],
            "seed": 4242,
            "headers": {"X-Test-Mode": "phase2"},
            "session_policy": "relogin-per-chain",
            "label_snapshot": "labels-2026-06-02",
            "comparison_period": "2026-Q2",
        }
    )

    result = evaluate_phase2_kpis(
        manifest=manifest,
        baseline_manifest=manifest,
        current_metrics={
            "valid_submission_rate": 0.63,
            "expected_bounty_at_5": 1500,
            "cost_per_actionable_chain": 16,
            "precision_at_5": 0.84,
            "cpu_time_per_confirmed_chain": 1.06,
            "audit_log_reproducibility": 1.0,
        },
        baseline_metrics={
            "valid_submission_rate": 0.50,
            "expected_bounty_at_5": 1200,
            "cost_per_actionable_chain": 20,
            "precision_at_5": 0.76,
            "cpu_time_per_confirmed_chain": 1.00,
            "audit_log_reproducibility": 0.92,
        },
    )

    assert result["manifest_id"] == manifest["manifest_id"]
    assert result["baseline_id"] == manifest["manifest_id"]
    assert result["go_no_go"]["valid_submission_rate"]["passed"] is True
    assert result["go_no_go"]["expected_bounty_at_5"]["passed"] is True
    assert result["go_no_go"]["cost_per_actionable_chain"]["passed"] is True
    assert result["diagnostic"]["precision_at_5"]["delta"] > 0
    assert result["diagnostic"]["cpu_time_per_confirmed_chain"]["delta"] > 0


def test_phase2_audit_log_links_actionable_chain_to_decision_trace() -> None:
    conductor = MasterConductor.__new__(MasterConductor)

    class _StubAuditLogger:
        def __init__(self) -> None:
            self.events = []

        def log(self, event):
            self.events.append(event)

    class _StubDecisionTracer:
        def __init__(self) -> None:
            self.traces = []

        def trace(self, **kwargs):
            trace = type("Trace", (), {"decision_id": "dec_9999", "to_dict": lambda self: {"decision_id": "dec_9999"}})()
            self.traces.append(kwargs)
            return trace

    conductor.audit_logger = _StubAuditLogger()
    conductor.decision_tracer = _StubDecisionTracer()

    emit_chain_audit_record = getattr(conductor, "emit_chain_audit_record", None)
    assert callable(emit_chain_audit_record)

    record = emit_chain_audit_record(
        chain={
            "chain_key": "abc123def456",
            "rule_id": "ato_chain",
            "state": "actionable",
            "excluded_reasons": [],
        },
        audit_context={
            "scope_basis": "program_scope_tag",
            "input_fingerprint": "fp-001",
            "override": False,
            "stop_reason": "",
        },
    )

    assert record["audit_event_id"].startswith("audit-")
    assert record["decision_id"] == "dec_9999"
    assert record["final_state"] == "actionable"
    assert conductor.audit_logger.events
    assert conductor.audit_logger.events[0].details["decision_id"] == "dec_9999"


def test_phase2_operational_mode_maps_fail_open_fail_closed_and_defer() -> None:
    conductor = MasterConductor.__new__(MasterConductor)
    evaluate_phase2_operational_mode = getattr(conductor, "evaluate_phase2_operational_mode", None)
    assert callable(evaluate_phase2_operational_mode)

    blocked = evaluate_phase2_operational_mode(
        failure_mode="scope_violation",
        policy={"scope_violation": "blocked", "dependency_failure": "defer", "rate_limit": "continue"},
    )
    deferred = evaluate_phase2_operational_mode(
        failure_mode="dependency_failure",
        policy={"scope_violation": "blocked", "dependency_failure": "defer", "rate_limit": "continue"},
    )
    allowed = evaluate_phase2_operational_mode(
        failure_mode="rate_limit",
        policy={"scope_violation": "blocked", "dependency_failure": "defer", "rate_limit": "continue"},
    )

    assert blocked == {"state": "blocked", "reason": "scope_violation"}
    assert deferred == {"state": "defer", "reason": "dependency_failure"}
    assert allowed == {"state": "continue", "reason": "rate_limit"}


def test_phase2_degrade_policy_isolated_component_failure_does_not_stop_all() -> None:
    conductor = MasterConductor.__new__(MasterConductor)
    resolve_component_degradation = getattr(conductor, "resolve_component_degradation", None)
    assert callable(resolve_component_degradation)

    result = resolve_component_degradation(
        {
            "program_memory": "degraded",
            "audit_logger": "healthy",
            "report_adapter": "healthy",
        }
    )

    assert result["state"] == "continue"
    assert result["degraded_components"] == ["program_memory"]
    assert result["fallbacks"]["program_memory"] == "in_memory_only"
    assert result["submit_blocked"] is False
    assert result["replay_verdict"] == "not_required"


def test_phase2_degrade_policy_multiple_components_require_defer_and_recovery_metadata() -> None:
    conductor = MasterConductor.__new__(MasterConductor)
    resolve_component_degradation = getattr(conductor, "resolve_component_degradation", None)
    assert callable(resolve_component_degradation)

    result = resolve_component_degradation(
        {
            "program_memory": "degraded",
            "audit_logger": "dependency_failure",
            "report_adapter": "degraded",
        }
    )

    assert result["state"] == "defer"
    assert result["reason"] == "dependency_failure"
    assert result["degraded_components"] == ["program_memory", "audit_logger", "report_adapter"]
    assert result["fallbacks"] == {
        "program_memory": "in_memory_only",
        "audit_logger": "buffered_events",
        "report_adapter": "canonical_payload_only",
    }
    assert result["submit_blocked"] is True
    assert result["replay_verdict"] == "required"
    assert result["recovery_actions"]["audit_logger"] == "restore_audit_pipeline"
    assert result["component_contract"]["report_adapter"]["recovery_precondition"] == "adapter_health_restored"


def test_phase2_degrade_policy_unknown_component_stays_best_effort() -> None:
    conductor = MasterConductor.__new__(MasterConductor)
    resolve_component_degradation = getattr(conductor, "resolve_component_degradation", None)
    assert callable(resolve_component_degradation)

    result = resolve_component_degradation(
        {
            "cache_layer": "degraded",
            "program_memory": "healthy",
        }
    )

    assert result["state"] == "continue"
    assert result["degraded_components"] == ["cache_layer"]
    assert result["fallbacks"]["cache_layer"] == "best_effort"
    assert result["component_contract"]["cache_layer"]["allowed_fallback"] == "best_effort"
    assert result["component_contract"]["cache_layer"]["ttl"] == "inherit_default"


def test_phase2_degrade_policy_scope_violation_overrides_dependency_failure() -> None:
    conductor = MasterConductor.__new__(MasterConductor)
    resolve_component_degradation = getattr(conductor, "resolve_component_degradation", None)
    assert callable(resolve_component_degradation)

    result = resolve_component_degradation(
        {
            "program_memory": "degraded",
            "audit_logger": "dependency_failure",
            "report_adapter": "scope_violation",
        }
    )

    assert result["state"] == "blocked"
    assert result["reason"] == "scope_violation"
    assert result["submit_blocked"] is True
    assert result["replay_verdict"] == "not_allowed"
    assert "scope_violation" in result["no_go_conditions"]


def test_phase2_degrade_policy_report_adapter_blocks_submit_and_requires_replay() -> None:
    conductor = MasterConductor.__new__(MasterConductor)
    resolve_component_degradation = getattr(conductor, "resolve_component_degradation", None)
    assert callable(resolve_component_degradation)

    result = resolve_component_degradation(
        {
            "program_memory": "healthy",
            "audit_logger": "healthy",
            "report_adapter": "degraded",
        }
    )

    assert result["state"] == "continue"
    assert result["reason"] == "report_adapter_degraded"
    assert result["submit_blocked"] is True
    assert result["replay_verdict"] == "required"
    assert result["recovery_actions"]["report_adapter"] == "replay_canonical_payload"


def test_phase2_degrade_policy_ttl_expiry_requires_rollback() -> None:
    conductor = MasterConductor.__new__(MasterConductor)
    resolve_component_degradation = getattr(conductor, "resolve_component_degradation", None)
    assert callable(resolve_component_degradation)

    result = resolve_component_degradation(
        {
            "program_memory": "ttl_expired",
            "audit_logger": "healthy",
            "report_adapter": "healthy",
        }
    )

    assert result["state"] == "defer"
    assert result["reason"] == "ttl_expired"
    assert result["recovery_actions"]["program_memory"] == "rollback_to_last_consistent_snapshot"
    assert result["component_contract"]["program_memory"]["rollback_trigger"] == "ttl_expired"


def test_phase2_degradation_audit_record_links_audit_and_decision_trace() -> None:
    conductor = MasterConductor.__new__(MasterConductor)

    class _StubAuditLogger:
        def __init__(self) -> None:
            self.events = []

        def log(self, event):
            self.events.append(event)

    class _StubDecisionTracer:
        def __init__(self) -> None:
            self.traces = []

        def trace(self, **kwargs):
            trace = type("Trace", (), {"decision_id": "dec_4242", "to_dict": lambda self: {"decision_id": "dec_4242"}})()
            self.traces.append(kwargs)
            return trace

    conductor.audit_logger = _StubAuditLogger()
    conductor.decision_tracer = _StubDecisionTracer()

    emit_degradation_audit_record = getattr(conductor, "emit_degradation_audit_record", None)
    assert callable(emit_degradation_audit_record)

    verdict = emit_degradation_audit_record(
        component_status={
            "program_memory": "healthy",
            "audit_logger": "healthy",
            "report_adapter": "degraded",
        },
        degradation_result={
            "state": "continue",
            "reason": "report_adapter_degraded",
            "fallbacks": {"report_adapter": "canonical_payload_only"},
            "submit_blocked": True,
            "replay_verdict": "required",
            "recovery_actions": {"report_adapter": "replay_canonical_payload"},
        },
        audit_context={
            "correlation_id": "corr-001",
            "policy_version": "phase2_degrade_v1",
        },
    )

    assert verdict["audit_event_id"].startswith("audit-")
    assert verdict["decision_id"] == "dec_4242"
    assert verdict["final_state"] == "continue"
    assert verdict["submit_blocked"] is True
    assert conductor.audit_logger.events
    assert conductor.audit_logger.events[0].details["correlation_id"] == "corr-001"
    assert conductor.audit_logger.events[0].details["replay_verdict"] == "required"


def test_phase2_metric_rollup_reduces_high_cardinality_labels() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    aggregate_phase2_metrics = getattr(builder, "aggregate_phase2_metrics", None)
    assert callable(aggregate_phase2_metrics)

    result = aggregate_phase2_metrics(
        [
            {"metric": "cpu_time_per_confirmed_chain", "label": "chain:a", "value": 1.0},
            {"metric": "cpu_time_per_confirmed_chain", "label": "chain:b", "value": 1.4},
            {"metric": "cpu_time_per_confirmed_chain", "label": "chain:c", "value": 1.6},
        ]
    )

    assert result["cpu_time_per_confirmed_chain"]["count"] == 3
    assert result["cpu_time_per_confirmed_chain"]["avg"] == pytest.approx(1.333333, rel=1e-4)
    assert "labels" not in result["cpu_time_per_confirmed_chain"]


def test_phase2_platform_adapter_requires_canonical_payload_route() -> None:
    validate_platform_submission_payload = getattr(ReportDraft, "validate_platform_submission_payload", None)
    assert callable(validate_platform_submission_payload)

    verdict = validate_platform_submission_payload(
        platform="hackerone",
        payload={
            "title": "ATO chain",
            "business_impact_sentence": "Victim account takeover is possible.",
            "reproduction_steps": ["1. login", "2. trigger chain"],
            "boundary_cross_proof": "cross-user password reset confirmed",
            "victim_impact": "victim loses account access",
            "remediation": "add CSRF protection",
            "falsification_result": "re-login replay reproduced",
            "goal_state_assertions": {"privilege_changed": True},
        },
        source="manual_draft",
    )

    assert verdict["accepted"] is False
    assert verdict["reason"] == "canonical_payload_required"


def test_phase2_platform_adapter_blocks_missing_platform_fields() -> None:
    validate_platform_submission_payload = getattr(ReportDraft, "validate_platform_submission_payload", None)
    assert callable(validate_platform_submission_payload)

    verdict = validate_platform_submission_payload(
        platform="bugcrowd",
        payload={
            "title": "ATO chain",
            "business_impact_sentence": "Victim account takeover is possible.",
            "reproduction_steps": ["1. login"],
            "boundary_cross_proof": "",
            "victim_impact": "",
            "remediation": "",
            "falsification_result": "",
            "goal_state_assertions": {"privilege_changed": True},
        },
        source="canonical_report_payload",
    )

    assert verdict["accepted"] is False
    assert set(verdict["missing_fields"]) == {
        "boundary_cross_proof",
        "victim_impact",
        "remediation",
        "falsification_result",
    }
