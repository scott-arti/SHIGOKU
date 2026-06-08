"""Wave C: Lane-2 promotion and budget control tests."""

from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.agents.swarm.injection.manager_internal.execution_policy import (
    cap_phase2_budget,
    is_lane2_score_eligible,
    should_force_phase2_by_risk,
)
from src.core.agents.swarm.injection.manager_internal.phase1_results import (
    has_actionable_blind_signal,
)

LANE2_THRESHOLD = InjectionManagerAgent.LANE2_SCORE_THRESHOLD


def test_lane2_not_promoted_when_score_64_and_no_override():
    assert is_lane2_score_eligible(64, False, lane2_score_threshold=LANE2_THRESHOLD) is False


def test_lane2_promoted_when_score_65_and_no_override():
    assert is_lane2_score_eligible(65, False, lane2_score_threshold=LANE2_THRESHOLD) is True


def test_lane2_promoted_when_risk_override_true_even_if_score_below_65():
    assert is_lane2_score_eligible(10, True, lane2_score_threshold=LANE2_THRESHOLD) is True


def test_risk_forced_not_triggered_when_tool_error_is_true():
    should_force = should_force_phase2_by_risk(
        phase1_findings=[],
        phase1_signals={"tool_error": True, "weak_signal": False},
        high_risk_requires_phase2=True,
    )
    assert should_force is False


def test_empty_blind_correlation_does_not_break_phase_decision():
    assert has_actionable_blind_signal({}) is False


def test_phase2_budget_respects_risk_forced_and_normal_caps():
    params = {"phase2_max_seconds_risk_forced": 120, "phase2_max_seconds": 240}
    risk_forced_budget = cap_phase2_budget(
        remaining_budget=500,
        phase2_forced_by_risk=True,
        task_params=params,
    )
    normal_budget = cap_phase2_budget(
        remaining_budget=500,
        phase2_forced_by_risk=False,
        task_params=params,
    )

    assert risk_forced_budget <= 120
    assert normal_budget <= 240
