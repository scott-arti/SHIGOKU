import pytest
from unittest.mock import AsyncMock
from types import SimpleNamespace

from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.agents.swarm.injection.manager_internal.execution_policy import (
    resolve_risk_force_allowlist,
)
from src.core.agents.swarm.injection.manager_internal.phase1_results import (
    summarize_low_ssrf_score_breakdown,
)
from src.core.models.finding import Finding, VulnType, Severity


@pytest.mark.asyncio
async def test_run_lfi_check_returns_metadata():
    agent = InjectionManagerAgent(config={"model": "test-model"})
    agent.current_context = {"params": {}, "auth_headers": {}, "findings": []}

    finding = Finding(
        vuln_type=VulnType.LFI,
        severity=Severity.HIGH,
        title="LFI detected",
        description="LFI confirmed",
        target_url="http://example.com/view.php?file=a",
        additional_info={
            "parameter": "file",
            "tested_params": ["file"],
            "payload": "../../../../etc/passwd",
        },
    )
    agent.specialists["lfi"].execute_with_retry = AsyncMock(return_value=[finding])

    result = await agent.run_lfi_check("http://example.com/view.php?file=a", params={"file": "a"})

    assert result["findings_count"] == 1
    assert result["tested_params"] == ["file"]
    assert result["parameter"] == "file"


@pytest.mark.asyncio
async def test_run_cmd_ssrf_hunter_returns_blind_metadata():
    agent = InjectionManagerAgent(config={"model": "test-model"})
    agent.current_context = {"params": {}, "auth_headers": {}, "findings": []}

    finding = Finding(
        vuln_type=VulnType.OS_COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        title="Command injection detected",
        description="Time-based command injection confirmed",
        target_url="http://example.com/ping?host=1",
        additional_info={
            "parameter": "host",
            "tested_params": ["host"],
            "payload": "1;sleep 5",
            "blind_correlation": {
                "time_based": {"confirmed": True, "observed_latency_seconds": 5.0},
                "oob": {"confirmed": False, "hits": []},
                "correlated": False,
            },
        },
    )
    agent.specialists["cmd_ssrf"].execute_with_retry = AsyncMock(return_value=[finding])

    result = await agent.run_cmd_ssrf_hunter("http://example.com/ping?host=1", params={"host": "1"})

    assert result["findings_count"] == 1
    assert result["tested_params"] == ["host"]
    assert result["blind_correlation"]["time_based"]["confirmed"] is True


def test_resolve_risk_force_allowlist_defaults_cover_core_coverage():
    agent = InjectionManagerAgent(config={"model": "test-model"})
    task = SimpleNamespace(params={})

    allow = resolve_risk_force_allowlist(task, scan_profile="bbpt")

    expected = {"sqli", "cmd_ssrf", "lfi", "csrf", "api", "redirect"}
    assert expected.issubset(allow)


def test_resolve_risk_force_allowlist_empty_list_disables_risk_force():
    agent = InjectionManagerAgent(config={"model": "test-model"})
    task = SimpleNamespace(params={"phase2_risk_force_vuln_types": []})

    allow = resolve_risk_force_allowlist(task, scan_profile="bbpt")

    assert allow == set()


def test_resolve_risk_force_allowlist_uses_explicit_values():
    agent = InjectionManagerAgent(config={"model": "test-model"})
    task = SimpleNamespace(params={"phase2_risk_force_vuln_types": [" csrf ", "API", "", None]})

    allow = resolve_risk_force_allowlist(task, scan_profile="bbpt")

    assert allow == {"csrf", "api"}


def test_summarize_phase1_signals_blind_structure_without_confirmation_is_not_weak_signal():
    agent = InjectionManagerAgent(config={"model": "test-model"})
    phase1_url_results = [
        {
            "url": "http://example.com/rest/products/search?q=",
            "status": "completed",
            "blind_correlation": {
                "time_based": {
                    "confirmed": False,
                    "payload": "",
                    "expected_delay_seconds": 0.0,
                    "observed_latency_seconds": 0.0,
                    "max_observed_latency_seconds": 0.01,
                },
                "oob": {"tested_tokens": [], "confirmed": False, "hits": []},
                "correlated": False,
            },
            "reflection_observed": False,
            "xss_evidence": "",
        }
    ]

    signals = agent._summarize_phase1_signals(phase1_url_results, "http://example.com/rest/products/search?q=")

    assert signals["weak_signal"] is False


def test_summarize_phase1_signals_confirmed_blind_signal_sets_weak_signal_true():
    agent = InjectionManagerAgent(config={"model": "test-model"})
    phase1_url_results = [
        {
            "url": "http://example.com/api/v1/users?id=1",
            "status": "completed",
            "blind_correlation": {
                "time_based": {"confirmed": True},
                "oob": {"confirmed": False, "hits": []},
                "correlated": False,
            },
            "reflection_observed": False,
            "xss_evidence": "",
        }
    ]

    signals = agent._summarize_phase1_signals(phase1_url_results, "http://example.com/api/v1/users?id=1")

    assert signals["weak_signal"] is True


def test_summarize_low_ssrf_score_breakdown_counts_missing_features():
    phase1_url_results = [
        {
            "status": "skipped",
            "skip_reason": "low_ssrf_score",
            "score_breakdown": {
                "query_url_param": 0,
                "body_url_param": 20,
                "graphql_variables": 0,
                "header_context": 0,
                "path_context": 14,
            },
        },
        {
            "status": "skipped",
            "skip_reason": "low_ssrf_score",
            "score_breakdown": {
                "query_url_param": 0,
                "body_url_param": 0,
                "graphql_variables": 10,
                "header_context": 0,
                "path_context": 0,
            },
        },
    ]

    out = summarize_low_ssrf_score_breakdown(phase1_url_results)
    assert out["query_url_param"] == 2
    assert out["body_url_param"] == 1
    assert out["graphql_variables"] == 1
    assert out["header_context"] == 2
    assert out["path_context"] == 1


def test_summarize_low_ssrf_score_breakdown_counts_dynamic_features():
    phase1_url_results = [
        {
            "status": "skipped",
            "skip_reason": "low_ssrf_score",
            "score_breakdown": {
                "query_url_param": 0,
                "dns_rebinding_hint": 0,
                "oob_signal_strength": 1,
            },
        }
    ]
    out = summarize_low_ssrf_score_breakdown(phase1_url_results)
    assert out["query_url_param"] == 1
    assert out["dns_rebinding_hint"] == 1
    assert "oob_signal_strength" not in out
