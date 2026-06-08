"""XCTO-10 (confidence bandit/UCB1) RED tests.

These tests codify the target behavior described in:
`docs/shigoku/plans/2026-05-24_xss-hunter-enhancement_plan.md` section 5.3.6.
They are expected to fail until XCTO-10 is implemented.
"""

from __future__ import annotations

import inspect

from src.core.payloads import xss_waf_evasion as mod
from src.core.payloads.xss_waf_evasion import XSSContextOptimizer, XSSPayload


# 5.3.6.1 SRE / Infra

def test_xcto10_requires_learning_state_persistence_contract():
    """5.3.6.1-SRE: learning state persistence and restore contract must exist."""
    assert hasattr(XSSContextOptimizer, "save_learning_state"), "save_learning_state() is required by XCTO-10"
    assert hasattr(XSSContextOptimizer, "load_learning_state"), "load_learning_state() is required by XCTO-10"


def test_xcto10_requires_log_policy_controls_for_ucb1_observability():
    """5.3.6.1-SRE: INFO summary / DEBUG details log policy controls must exist."""
    assert hasattr(XSSContextOptimizer, "set_ucb1_log_policy"), "set_ucb1_log_policy() is required by XCTO-10"


def test_xcto10_requires_concurrency_safe_update_contract():
    """5.3.6.1-SRE: concurrent updates must be guarded by explicit API contract."""
    assert hasattr(XSSContextOptimizer, "update_payload_outcome_atomic"), "atomic outcome update API is required"


def test_xcto10_requires_degraded_mode_when_persistence_is_unavailable():
    """5.3.6.1-SRE: degraded mode fallback contract is required on persistence failure."""
    assert hasattr(XSSContextOptimizer, "set_degraded_mode"), "set_degraded_mode() is required by XCTO-10"


# 5.3.6.2 Architect

def test_xcto10_requires_payload_stats_model_separated_from_payload_definition():
    """5.3.6.2-architect: static payload definition and dynamic stats must be separated."""
    assert hasattr(mod, "PayloadStats"), "PayloadStats model is required by XCTO-10"


def test_xcto10_requires_order_optimization_only_contract_boundary():
    """5.3.6.2-architect: optimizer must expose explicit order-only optimization boundary."""
    assert hasattr(XSSContextOptimizer, "optimize_order_only"), "optimize_order_only() is required by XCTO-10"


def test_xcto10_requires_externalized_ucb1_tuning_parameters():
    """5.3.6.2-architect: exploration/tuning parameters must be configurable."""
    sig = inspect.signature(XSSContextOptimizer.__init__)
    assert "exploration_coefficient" in sig.parameters, "exploration_coefficient must be configurable"
    assert "min_trials_before_exploit" in sig.parameters, "min_trials_before_exploit must be configurable"
    assert "context_weight" in sig.parameters, "context_weight must be configurable"


def test_xcto10_requires_context_payload_stats_key_contract():
    """5.3.6.2-architect: stats key must be context + payload_id contract."""
    assert hasattr(XSSContextOptimizer, "build_stats_key"), "build_stats_key() is required by XCTO-10"


# 5.3.6.3 Debugger

def test_xcto10_requires_ranking_snapshot_for_reproducible_debugging():
    """5.3.6.3-debugger: ranking snapshots (trials/successes/score/rank) must be exported."""
    assert hasattr(XSSContextOptimizer, "build_ranking_snapshot"), "build_ranking_snapshot() is required"


def test_xcto10_requires_outcome_classification_contract():
    """5.3.6.3-debugger: success/soft_fail/hard_fail classification contract must exist."""
    assert hasattr(mod, "OutcomeType"), "OutcomeType enum is required by XCTO-10"
    assert hasattr(XSSContextOptimizer, "classify_outcome"), "classify_outcome() is required by XCTO-10"


def test_xcto10_requires_payload_dataclass_trials_successes_fields():
    """5.3.6.3-debugger: XSSPayload must carry trials/successes fields for UCB1 state."""
    fields = XSSPayload.__dataclass_fields__
    assert "trials" in fields, "XSSPayload.trials is required by XCTO-10"
    assert "successes" in fields, "XSSPayload.successes is required by XCTO-10"


def test_xcto10_requires_shadow_ab_compare_report_with_fixed_baseline_hash():
    """5.3.6.3-debugger: shadow A/B report with fixed baseline hash must exist."""
    assert hasattr(XSSContextOptimizer, "run_shadow_ab_compare"), "run_shadow_ab_compare() is required"
    sig = inspect.signature(XSSContextOptimizer.run_shadow_ab_compare)
    assert "baseline_hash" in sig.parameters, "baseline_hash parameter is required for reproducibility"


# 5.3.6.4 CTO

def test_xcto10_requires_go_nogo_decision_contract():
    """5.3.6.4-CTO: go/no-go decision API must exist for rollout decisions."""
    assert hasattr(XSSContextOptimizer, "evaluate_go_nogo_for_ranking"), "evaluate_go_nogo_for_ranking() is required"


def test_xcto10_requires_rollout_mode_controls_off_shadow_enforce():
    """5.3.6.4-CTO: rollout mode off/shadow/enforce must be configurable."""
    assert hasattr(XSSContextOptimizer, "set_ranking_mode"), "set_ranking_mode() is required"
    assert hasattr(XSSContextOptimizer, "get_ranking_mode"), "get_ranking_mode() is required"


def test_xcto10_requires_fail_safe_auto_off_guardrail_contract():
    """5.3.6.4-CTO: fail-safe auto-off guardrail contract must exist."""
    assert hasattr(XSSContextOptimizer, "evaluate_fail_safe_trigger"), "evaluate_fail_safe_trigger() is required"
    assert hasattr(XSSContextOptimizer, "apply_fail_safe_if_needed"), "apply_fail_safe_if_needed() is required"


def test_xcto10_requires_high_priority_payload_initial_detection_guard():
    """5.3.6.4-CTO: high-priority payload initial-detection KPI guard must exist."""
    assert hasattr(XSSContextOptimizer, "evaluate_high_priority_initial_detection"), (
        "evaluate_high_priority_initial_detection() is required"
    )
