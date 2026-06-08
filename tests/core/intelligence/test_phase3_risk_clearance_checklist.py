from __future__ import annotations

from pathlib import Path

import pytest

from src.core.intelligence.chain_builder import AttackChainBuilder
from src.core.models.finding import Finding, Severity, VulnType

PLAN_PATH = (
    Path(__file__).resolve().parents[3]
    / "docs"
    / "shigoku"
    / "plans"
    / "2026-06-01_task_plan.md"
)


def _read_plan_text() -> str:
    return PLAN_PATH.read_text(encoding="utf-8")


def _sample_candidates() -> list[dict]:
    return [
        {
            "rule_id": "chain_fast_high",
            "success_probability": 0.78,
            "impact_score": 0.91,
            "trial_cost": 1.2,
            "matched_signals": ["idor", "open_redirect"],
            "goal_state_assertions": {"cross_user_data_access": True},
            "fallback_paths": [["idor", "token_reuse"], ["cache_poison", "idor"]],
        },
        {
            "rule_id": "chain_slow_medium",
            "success_probability": 0.66,
            "impact_score": 0.72,
            "trial_cost": 3.1,
            "matched_signals": ["xss", "csrf"],
            "goal_state_assertions": {"privilege_changed": True},
            "fallback_paths": [["xss", "oauth_redirect"]],
        },
    ]


def test_phase3_plan_documents_advanced_chaining_steps() -> None:
    text = _read_plan_text()

    assert "Phase 3（高度最適化 / Step 28〜37）" in text
    assert "MCTS" in text
    assert "Goal-state 強度評価" in text
    assert "成功確率校正" in text


def test_phase3_step28_belief_state_retains_partial_chain_candidates() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    findings = [
        Finding(
            vuln_type=VulnType.IDOR,
            severity=Severity.HIGH,
            title="Cross-user invoice IDOR",
            description="Cross-user invoice read is possible.",
            target_url="https://example.com/api/invoices/42",
            additional_info={
                "auth_level": "user",
                "user_interaction": "none",
                "same_origin": True,
                "asset_scope": "in_scope",
                "primitive": "read",
            },
        )
    ]

    state = builder.update_belief_state(findings)

    assert state["candidate_rules"]
    assert state["candidate_rules"][0]["state"] == "partial_observation"


def test_phase3_step29_mcts_prefers_high_value_low_cost_path() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)

    ranked = builder.select_chain_paths_with_mcts(_sample_candidates(), iterations=24)

    assert ranked[0]["rule_id"] == "chain_fast_high"
    assert ranked[0]["mcts_score"] >= ranked[1]["mcts_score"]


def test_phase3_step30_precondition_model_flags_only_low_confidence_checks() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)

    result = builder.evaluate_preconditions(
        {
            "rule_id": "tenant_chain",
            "preconditions": {
                "csrf_token_reusable": 0.42,
                "victim_session_present": 0.88,
                "redirect_followed": 0.35,
            },
        },
        threshold=0.6,
    )

    assert result["verify_only"] == ["csrf_token_reusable", "redirect_followed"]
    assert "victim_session_present" not in result["verify_only"]


def test_phase3_step31_ablation_identifies_required_step() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)

    result = builder.run_step_ablation(
        {
            "path": ["xss", "csrf", "password_change"],
            "step_contributions": {
                "xss": 0.25,
                "csrf": 0.55,
                "password_change": 0.90,
            },
        }
    )

    assert "password_change" in result["required_steps"]
    assert result["ablation_passed"] is True


def test_phase3_step32_fallback_independence_penalizes_correlated_paths() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)

    result = builder.assess_fallback_independence(
        primary_path=["idor", "redirect"],
        fallback_paths=[["idor", "token_reuse"], ["redirect", "cache_poison"]],
        failure_history={"idor": 3, "redirect": 2},
    )

    assert result["independent_fallbacks"] == []
    assert result["independence_score"] < 0.5


def test_phase3_step33_race_orchestrator_selects_best_profile() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)

    result = builder.optimize_race_execution(
        [
            {"profile": {"mode": "interval", "burst": 1, "interval_ms": 250}, "success_rate": 0.45, "latency_ms": 280},
            {"profile": {"mode": "burst", "burst": 3, "interval_ms": 0}, "success_rate": 0.72, "latency_ms": 90},
        ]
    )

    assert result["selected_profile"]["mode"] == "burst"
    assert result["orchestrator_state"] == "optimized"


def test_phase3_step34_adaptive_mutation_switches_on_waf_signal() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)

    result = builder.adapt_mutation_strategy(
        waf_signal={"status_code": 403, "waf_name": "cloudflare", "reaction": "header_block"},
        previous_results=[{"mutation_type": "header_case", "success": False}],
        available_mutations=["header_case", "url_encode", "alt_path"],
    )

    assert result["selected_mutations"][0] == "url_encode"
    assert result["strategy_state"] == "adaptive"


def test_phase3_step35_goal_state_strength_promotes_persistent_control() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)

    result = builder.score_goal_state_strength(
        {
            "goal_state_assertions": {
                "cross_user_data_access": True,
                "privilege_changed": True,
                "persistent_control": True,
            }
        }
    )

    assert result["goal_state_strength"] == "persistent_control"
    assert result["goal_state_bonus"] > 0.2


def test_phase3_step36_similarity_transfer_boosts_near_program_candidates() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)

    ranked = builder.transfer_program_memory_prior(
        program="target-program",
        program_profile={"industry": "fintech", "auth_model": "oauth", "surface": "graphql"},
        candidates=[
            {"rule_id": "tenant_idor_chain"},
            {"rule_id": "generic_xss_chain"},
        ],
        neighbor_memories=[
            {"rule_id": "tenant_idor_chain", "success": 3, "failure": 0, "profile": {"industry": "fintech", "auth_model": "oauth", "surface": "rest"}},
            {"rule_id": "generic_xss_chain", "success": 1, "failure": 1, "profile": {"industry": "media", "auth_model": "session", "surface": "web"}},
        ],
    )

    assert ranked[0]["rule_id"] == "tenant_idor_chain"
    assert ranked[0]["program_prior"] > ranked[1]["program_prior"]


def test_phase3_step37_calibration_reduces_probability_error() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)

    result = builder.calibrate_success_probabilities(
        [
            {"predicted": 0.9, "actual": 1},
            {"predicted": 0.8, "actual": 1},
            {"predicted": 0.7, "actual": 0},
            {"predicted": 0.3, "actual": 0},
            {"predicted": 0.2, "actual": 0},
        ]
    )

    assert result["ece"] <= 0.2
    assert result["calibrated_points"]
    assert result["calibrated_points"][0]["calibrated"] <= 1.0
