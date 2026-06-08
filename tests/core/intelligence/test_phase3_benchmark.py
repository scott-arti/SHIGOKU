from __future__ import annotations

from src.core.intelligence.chain_builder import AttackChainBuilder
from src.core.intelligence.phase3_benchmark import (
    build_phase3_benchmark_manifest,
    build_phase3_benchmark_scenarios,
    evaluate_phase3_profiles,
    summarize_phase3_gate_metrics,
)


def test_phase3_benchmark_manifest_uses_fixed_contract() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)

    manifest = build_phase3_benchmark_manifest(builder)

    assert manifest["manifest_id"].startswith("bm-")
    assert manifest["seed"] == 20260602
    assert manifest["session_policy"] == "phase3-shadow-compare"
    assert manifest["corpus"]


def test_phase3_profile_evaluation_reports_required_metric_families() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)

    result = evaluate_phase3_profiles(builder)

    assert "baseline_metrics" in result
    assert "current_metrics" in result
    assert "records" in result
    assert "mcts_success_rate" in result["current_metrics"]
    assert "belief_state_accuracy" in result["current_metrics"]
    assert "ece" in result["current_metrics"]


def test_phase3_gate_metrics_show_improvement_over_baseline() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    evaluation = evaluate_phase3_profiles(builder)

    gate = summarize_phase3_gate_metrics(
        baseline_metrics=evaluation["baseline_metrics"],
        current_metrics=evaluation["current_metrics"],
    )

    assert gate["mcts_success_rate_improvement"]["passed"] is True
    assert gate["ece"]["passed"] is True
    assert gate["causal_intervention_validity"]["passed"] is True
    assert gate["fallback_independence_gain"]["passed"] is True


def test_phase3_scenarios_cover_steps_28_to_37() -> None:
    scenarios = build_phase3_benchmark_scenarios()
    scenario_ids = {item["scenario_id"] for item in scenarios}

    assert "belief_state_partial" in scenario_ids
    assert "mcts_branching" in scenario_ids
    assert "precondition_filter" in scenario_ids
    assert "probability_calibration" in scenario_ids
