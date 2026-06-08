from types import SimpleNamespace

from src.core.agents.swarm.injection.manager_internal.execution_policy import (
    resolve_per_url_timeout,
    should_auto_early_return,
)


def test_resolve_per_url_timeout_character() -> None:
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
        timeout_by_type={"xss": 150},
        blind_sqli_timeout_seconds=120,
    )

    assert timeout == 240


def _coerce_bool(value, *, default=True):
    """bool() 互換の keyword argument を受け付けるヘルパー"""
    return bool(value) if value is not None else default


def test_phase2_policy_character() -> None:
    task = SimpleNamespace(params={"phase1_auto_early_return_on_findings": True})

    should_return = should_auto_early_return(
        task,
        phase1_findings=[object()],
        phase1_signals={"tool_error": False},
        phase1_vuln_types={"api"},
        coerce_bool=_coerce_bool,
    )

    assert should_return is True
