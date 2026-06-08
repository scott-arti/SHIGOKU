from types import SimpleNamespace

from src.core.agents.swarm.injection.manager_internal.execution_policy import (
    cap_phase2_budget,
    is_lane2_score_eligible,
    resolve_per_url_timeout,
    resolve_risk_force_allowlist,
    should_auto_early_return,
    should_force_phase2_by_risk,
)


def test_resolve_per_url_timeout_matches_existing_behavior() -> None:
    task = SimpleNamespace(
        params={
            "per_url_timeout_seconds": 100,
            "per_url_timeout_by_type": {"xss": 150},
            "per_url_timeout_xss_stored_seconds": 240,
        }
    )

    timeout = resolve_per_url_timeout(
        task,
        "http://example.com/vulnerabilities/xss_s/",
        "xss",
        default_timeout_seconds=120,
        timeout_by_type={"xss": 210},
        blind_sqli_timeout_seconds=240,
    )

    assert timeout == 240


def test_phase2_policy_helpers_match_existing_behavior() -> None:
    task = SimpleNamespace(params={"phase1_auto_early_return_on_findings": True})

    assert is_lane2_score_eligible(65, False, lane2_score_threshold=65) is True
    assert should_force_phase2_by_risk(
        phase1_findings=[],
        phase1_signals={"tool_error": False, "weak_signal": False},
        high_risk_requires_phase2=True,
    ) is True
    assert cap_phase2_budget(
        remaining_budget=500,
        phase2_forced_by_risk=True,
        task_params={"phase2_max_seconds_risk_forced": 120, "phase2_max_seconds": 240},
    ) == 120
    assert should_auto_early_return(
        task,
        phase1_findings=[object()],
        phase1_signals={"tool_error": False},
        phase1_vuln_types={"api"},
        coerce_bool=lambda value, default: bool(default if value is None else value),
    ) is True


def test_resolve_risk_force_allowlist_matches_existing_behavior() -> None:
    task = SimpleNamespace(params={"phase2_risk_force_vuln_types": [" csrf ", "API", "", None]})

    allow = resolve_risk_force_allowlist(task, scan_profile="bbpt")

    assert allow == {"csrf", "api"}
