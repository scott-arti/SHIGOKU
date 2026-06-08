from types import SimpleNamespace

from src.core.agents.swarm.injection.manager import InjectionManagerAgent


def test_injection_manager_resolve_per_url_timeout_character() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    task = SimpleNamespace(
        params={
            "per_url_timeout_seconds": 100,
            "per_url_timeout_by_type": {"xss": 150},
            "per_url_timeout_xss_stored_seconds": 240,
        }
    )

    timeout = manager._resolve_per_url_timeout(
        task,
        "http://example.com/vulnerabilities/xss_s/",
        "xss",
    )

    assert timeout == 240


def test_injection_manager_phase2_policy_character() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    task = SimpleNamespace(params={"phase1_auto_early_return_on_findings": True})

    should_return = manager._should_auto_early_return(
        task,
        phase1_findings=[object()],
        phase1_signals={"tool_error": False},
        phase1_vuln_types={"api"},
    )

    assert should_return is True
