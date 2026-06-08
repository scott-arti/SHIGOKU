from src.core.intelligence.chain_builder import AttackChainBuilder
from src.core.intelligence.phase2_benchmark import (
    evaluate_feasibility_solver_profiles,
    build_current_submission_candidate,
    build_legacy_submission_candidate,
    build_phase2_benchmark_scenarios,
    summarize_phase2_profile_metrics,
)
from src.core.reporting.platform_integration import ReportDraft


def test_phase2_benchmark_scenarios_cover_fixed_manifest_corpus() -> None:
    scenarios = build_phase2_benchmark_scenarios()

    assert [scenario["corpus_id"] for scenario in scenarios] == [
        "verify_chaining_flow:idor",
        "verify_chaining_flow:secret_leak",
    ]

    builder = AttackChainBuilder(enforce_data_contract=True)
    for scenario in scenarios:
        chains = builder.analyze(scenario["findings"])
        assert len(chains) == 1


def test_current_submission_candidate_is_report_ready_for_phase2_gate() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    scenario = build_phase2_benchmark_scenarios()[0]
    chain = builder.analyze(scenario["findings"])[0]

    payload = build_current_submission_candidate(builder, scenario, chain)
    validation = ReportDraft.validate_platform_submission_payload(
        platform="hackerone",
        payload=payload,
        source="canonical_report_payload",
    )

    assert validation["accepted"] is True
    assert payload["business_impact_sentence"]
    assert payload["goal_state_assertions"]["cross_user_data_access"] is True


def test_legacy_submission_candidate_stays_below_phase2_platform_gate() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    scenario = build_phase2_benchmark_scenarios()[1]
    chain = builder.analyze(scenario["findings"])[0]

    payload = build_legacy_submission_candidate(scenario, chain.to_finding())
    validation = ReportDraft.validate_platform_submission_payload(
        platform="bugcrowd",
        payload=payload,
        source="legacy_phase1_payload",
    )

    assert validation["accepted"] is False
    assert validation["reason"] == "canonical_payload_required"


def test_phase2_profile_metrics_roll_up_submission_readiness() -> None:
    metrics = summarize_phase2_profile_metrics(
        [
            {
                "accepted": True,
                "estimated_bounty": 1500.0,
                "manual_fix_units": 1.0,
                "elapsed_seconds": 0.8,
                "audit_reproducible": 1.0,
            },
            {
                "accepted": False,
                "estimated_bounty": 0.0,
                "manual_fix_units": 4.0,
                "elapsed_seconds": 1.2,
                "audit_reproducible": 0.0,
            },
        ]
    )

    assert metrics["valid_submission_rate"] == 0.5
    assert metrics["expected_bounty_at_5"] == 1500.0
    assert metrics["cost_per_actionable_chain"] == 2.5
    assert metrics["precision_at_5"] == 0.5
    assert metrics["cpu_time_per_confirmed_chain"] == 1.0
    assert metrics["audit_log_reproducibility"] == 0.5


def test_feasibility_solver_profiles_cover_normal_budget_and_infeasible_cases() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)

    result = evaluate_feasibility_solver_profiles(builder)

    assert result["records"]
    assert {record["scenario_id"] for record in result["records"]} == {
        "normal_feasible",
        "budget_fallback",
        "infeasible_constraints",
    }
    assert result["metrics"]["used_fallback_count"] >= 1
    assert result["metrics"]["solver_timeout_count"] >= 1
    assert result["metrics"]["blocked_infeasible_count"] == 1
    assert result["metrics"]["avg_solver_latency_ms"] >= 0.0
