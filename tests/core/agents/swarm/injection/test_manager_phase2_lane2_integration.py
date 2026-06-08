import pytest
import asyncio
from unittest.mock import AsyncMock, patch

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.base_manager import BaseManagerAgent
from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.models.swarm import SwarmResult


@pytest.mark.asyncio
async def test_dispatch_triggers_phase2_risk_forced_on_ssrf_candidate_score_boundary():
    agent = InjectionManagerAgent(config={"model": "test-model"})
    target = "http://example.com/api/fetch?url=http://127.0.0.1"
    task = Task(
        id="t_wavec_lane2_fire",
        name="SSRF candidate wave-c trigger",
        target=target,
        params={
            "targets": [target],
            "category": "ssrf_candidate",
            "phase1_early_return_on_findings": False,
            "phase2_on_empty_phase1": False,
            "_context": {
                "url_evidence_by_url": {
                    target: {
                        "method": "GET",
                        "ssrf_score": 65,
                        "score_breakdown": {"query_url_param": 30},
                    }
                }
            },
        },
    )

    async def _mock_process_single_url(*_args, **_kwargs):
        return {
            "findings_count": 0,
            "vuln_type": "ssrf",
            "tested_params": ["url"],
            "blind_correlation": {},
            "detection_mode": "phase1",
        }

    phase2_result = SwarmResult(
        findings=[],
        status="success",
        execution_log=[{"phase": "phase2", "reason": "mocked"}],
        swarm_name="InjectionManager",
        total_specialists=1,
        successful_specialists=1,
    )

    with patch.object(agent, "_process_single_url", side_effect=_mock_process_single_url), patch.object(
        BaseManagerAgent, "dispatch", new=AsyncMock(return_value=phase2_result)
    ) as mock_super_dispatch:
        result = await agent.dispatch(task)

    assert result.status == "success"
    assert mock_super_dispatch.await_count == 1
    assert agent._phase2_detection_mode == "risk_forced"
    assert any(log.get("phase") == "phase2" for log in result.execution_log)


@pytest.mark.asyncio
async def test_dispatch_skips_phase2_when_ssrf_score_below_lane2_threshold_without_override():
    agent = InjectionManagerAgent(config={"model": "test-model"})
    target = "http://example.com/api/fetch?url=http://127.0.0.1"
    task = Task(
        id="t_wavec_lane2_no_fire",
        name="SSRF candidate wave-c no trigger",
        target=target,
        params={
            "targets": [target],
            "category": "ssrf_candidate",
            "phase1_early_return_on_findings": False,
            "phase2_on_empty_phase1": False,
            "_context": {
                "url_evidence_by_url": {
                    target: {
                        "method": "GET",
                        "ssrf_score": 64,
                        "score_breakdown": {"query_url_param": 30},
                    }
                }
            },
        },
    )

    async def _mock_process_single_url(*_args, **_kwargs):
        return {
            "findings_count": 0,
            "vuln_type": "ssrf",
            "tested_params": ["url"],
            "blind_correlation": {},
            "detection_mode": "phase1",
        }

    with patch.object(agent, "_process_single_url", side_effect=_mock_process_single_url), patch.object(
        BaseManagerAgent, "dispatch", new=AsyncMock(return_value=SwarmResult(status="success"))
    ) as mock_super_dispatch:
        result = await agent.dispatch(task)

    assert result.status == "success"
    assert mock_super_dispatch.await_count == 0
    assert agent._phase2_detection_mode == "phase2"
    assert result.execution_log
    assert result.execution_log[0].get("reason") == "phase1_safe_skip_no_signal"
    assert result.execution_log[0].get("max_ssrf_score") == 64
    assert result.execution_log[0].get("lane2_score_eligible") is False


@pytest.mark.asyncio
async def test_dispatch_phase1_dedup_execution_key_skips_duplicate_target():
    agent = InjectionManagerAgent(config={"model": "test-model"})
    target = "http://example.com/api/fetch?url=http://127.0.0.1"
    task = Task(
        id="t_wavec_dedupe",
        name="dedupe guard",
        target=target,
        params={
            "targets": [target, target],
            "category": "ssrf_candidate",
            "phase1_early_return_on_findings": False,
            "phase2_on_empty_phase1": False,
            "_context": {
                "url_evidence_by_url": {
                    target: {"method": "GET", "ssrf_score": 64, "score_breakdown": {"query_url_param": 30}}
                }
            },
        },
    )

    async def _mock_process_single_url(*_args, **_kwargs):
        return {"findings_count": 0, "vuln_type": "ssrf", "tested_params": ["url"], "blind_correlation": {}}

    with patch.object(agent, "_process_single_url", side_effect=_mock_process_single_url) as mock_proc, patch.object(
        BaseManagerAgent, "dispatch", new=AsyncMock(return_value=SwarmResult(status="success"))
    ):
        await agent.dispatch(task)

    assert mock_proc.await_count == 1
    skipped = [r for r in agent.current_context.get("url_results", []) if r.get("skip_reason") == "dedupe_execution_key"]
    assert skipped


@pytest.mark.asyncio
async def test_dispatch_timeout_circuit_breaker_opens_after_threshold():
    agent = InjectionManagerAgent(config={"model": "test-model"})
    base = "http://example.com/api/fetch?url=http://127.0.0.1"
    targets = [
        f"{base}&probe=1",
        f"{base}&probe=2",
        f"{base}&probe=3",
    ]
    task = Task(
        id="t_wavec_breaker",
        name="timeout breaker",
        target=targets[0],
        params={
            "targets": targets,
            "category": "ssrf_candidate",
            "phase1_early_return_on_findings": False,
            "phase2_on_empty_phase1": False,
            "phase1_timeout_retries": 0,
            "_context": {
                "url_evidence_by_url": {
                    u: {"method": "GET", "ssrf_score": 65, "score_breakdown": {"query_url_param": 30}}
                    for u in targets
                }
            },
        },
    )

    async def _timeout_process(*_args, **_kwargs):
        raise asyncio.TimeoutError("simulated timeout")

    with patch.object(agent, "_process_single_url", side_effect=_timeout_process), patch.object(
        BaseManagerAgent, "dispatch", new=AsyncMock(return_value=SwarmResult(status="success"))
    ):
        await agent.dispatch(task)

    skipped = [
        r for r in agent.current_context.get("url_results", [])
        if r.get("skip_reason") == "timeout_circuit_breaker_open"
    ]
    assert skipped


@pytest.mark.asyncio
async def test_dispatch_phase2_timeout_includes_skip_reason_metrics_in_partial_return():
    agent = InjectionManagerAgent(config={"model": "test-model"})
    target = "http://example.com/api/fetch?url=http://127.0.0.1"
    task = Task(
        id="t_phase2_timeout_metrics",
        name="phase2 timeout includes metrics",
        target=target,
        params={
            "targets": [target],
            "category": "ssrf_candidate",
            "phase1_early_return_on_findings": False,
            "phase1_auto_early_return_on_findings": False,
            "phase2_on_empty_phase1": True,
            "_context": {
                "url_evidence_by_url": {
                    target: {
                        "method": "GET",
                        "ssrf_score": 64,
                        "score_breakdown": {
                            "query_url_param": 0,
                            "body_url_param": 0,
                            "graphql_variables": 0,
                            "header_context": 0,
                            "path_context": 0,
                        },
                    }
                }
            },
        },
    )

    async def _mock_process_single_url(*_args, **_kwargs):
        return {
            "findings_count": 0,
            "vuln_type": "ssrf",
            "tested_params": ["url"],
            "blind_correlation": {},
            "detection_mode": "phase1",
        }

    with patch.object(agent, "_process_single_url", side_effect=_mock_process_single_url), patch.object(
        BaseManagerAgent,
        "dispatch",
        new=AsyncMock(side_effect=asyncio.TimeoutError("simulated phase2 timeout")),
    ):
        result = await agent.dispatch(task)

    assert result.status == "failed"
    assert result.execution_log
    log = result.execution_log[0]
    assert log.get("phase") == "phase1_partial_return"
    assert log.get("reason") == "phase2_timeout"
    assert "skip_reason_counts" in log
    assert "low_ssrf_score_breakdown" in log
    assert isinstance(log.get("skip_reason_counts"), dict)
    assert isinstance(log.get("low_ssrf_score_breakdown"), dict)
