"""Wave C: Lane-2 promotion and budget control tests."""

from src.core.agents.swarm.injection.manager import InjectionManagerAgent


def test_lane2_not_promoted_when_score_64_and_no_override():
    assert InjectionManagerAgent._is_lane2_score_eligible(64, False) is False


def test_lane2_promoted_when_score_65_and_no_override():
    assert InjectionManagerAgent._is_lane2_score_eligible(65, False) is True


def test_lane2_promoted_when_risk_override_true_even_if_score_below_65():
    assert InjectionManagerAgent._is_lane2_score_eligible(10, True) is True


def test_risk_forced_not_triggered_when_tool_error_is_true():
    should_force = InjectionManagerAgent._should_force_phase2_by_risk(
        phase1_findings=[],
        phase1_signals={"tool_error": True, "weak_signal": False},
        high_risk_requires_phase2=True,
    )
    assert should_force is False


def test_empty_blind_correlation_does_not_break_phase_decision():
    assert InjectionManagerAgent._has_actionable_blind_signal({}) is False


def test_phase2_budget_respects_risk_forced_and_normal_caps():
    params = {"phase2_max_seconds_risk_forced": 120, "phase2_max_seconds": 240}
    risk_forced_budget = InjectionManagerAgent._cap_phase2_budget(
        remaining_budget=500,
        phase2_forced_by_risk=True,
        task_params=params,
    )
    normal_budget = InjectionManagerAgent._cap_phase2_budget(
        remaining_budget=500,
        phase2_forced_by_risk=False,
        task_params=params,
    )

    assert risk_forced_budget <= 120
    assert normal_budget <= 240
