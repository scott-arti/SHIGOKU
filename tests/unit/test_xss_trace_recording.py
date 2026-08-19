"""SGK-2026-0454 T1（trace記録）: manager の recording-only な xss:dom_browser_validation 記録。

- specialist の _dom_browser_validation_attempted が True のときだけ
  attempt_traces に xss:dom_browser_validation 段階が1件 mark される。
- False（到達しなかった）ときは mark されない（recording-only・判定に影響なし）。
"""
import pytest
from unittest.mock import AsyncMock, MagicMock

from src.core.agents.swarm.injection.manager import InjectionManagerAgent


@pytest.fixture
def manager():
    return InjectionManagerAgent(config={"model": "test-model"})


def _mk_specialist(attempted: bool):
    sp = MagicMock()
    sp._dom_browser_validation_attempted = attempted
    return sp


@pytest.mark.asyncio
async def test_xss_dom_validation_stage_marked_when_attempted(manager):
    manager.specialists["xss"] = _mk_specialist(attempted=True)
    manager.run_xss_hunter = AsyncMock(
        return_value={
            "findings_count": 0,
            "tested_params": ["q"],
            "reflection_observed": False,
            "evidence": "",
        }
    )

    trace_context = manager._new_attempt_trace(
        target_url="http://localhost:3000/rest/products/search?q=",
        vuln_type="xss",
        retry_count=0,
        timeout_seconds=120,
        quick_mode=False,
        detection_mode="phase1",
    )

    await manager._process_single_url(
        "http://localhost:3000/rest/products/search?q=",
        "xss",
        {"targets": ["http://localhost:3000/rest/products/search?q="]},
        quick_mode=False,
        trace_context=trace_context,
    )

    stages = [entry.get("stage") for entry in trace_context["history"]]
    assert "xss:start" in stages
    assert "xss:dom_browser_validation" in stages


@pytest.mark.asyncio
async def test_xss_dom_validation_stage_not_marked_when_not_attempted(manager):
    manager.specialists["xss"] = _mk_specialist(attempted=False)
    manager.run_xss_hunter = AsyncMock(
        return_value={
            "findings_count": 0,
            "tested_params": ["q"],
            "reflection_observed": False,
            "evidence": "",
        }
    )

    trace_context = manager._new_attempt_trace(
        target_url="http://localhost:3000/rest/products/search?q=",
        vuln_type="xss",
        retry_count=0,
        timeout_seconds=120,
        quick_mode=False,
        detection_mode="phase1",
    )

    await manager._process_single_url(
        "http://localhost:3000/rest/products/search?q=",
        "xss",
        {"targets": ["http://localhost:3000/rest/products/search?q="]},
        quick_mode=False,
        trace_context=trace_context,
    )

    stages = [entry.get("stage") for entry in trace_context["history"]]
    assert "xss:start" in stages
    assert "xss:dom_browser_validation" not in stages


@pytest.mark.asyncio
async def test_xss_dom_validation_stage_safe_when_specialist_missing(manager):
    # specialist が無い場合（run_xss_hunter は早期 return する前提）でも
    # getattr フォールバックで mark されず例外にならない。
    if "xss" in manager.specialists:
        del manager.specialists["xss"]
    manager.run_xss_hunter = AsyncMock(
        return_value={"findings_count": 0, "tested_params": [], "reflection_observed": False, "evidence": ""}
    )

    trace_context = manager._new_attempt_trace(
        target_url="http://localhost:3000/rest/products/search?q=",
        vuln_type="xss",
        retry_count=0,
        timeout_seconds=120,
        quick_mode=False,
        detection_mode="phase1",
    )

    await manager._process_single_url(
        "http://localhost:3000/rest/products/search?q=",
        "xss",
        {"targets": ["http://localhost:3000/rest/products/search?q="]},
        quick_mode=False,
        trace_context=trace_context,
    )

    stages = [entry.get("stage") for entry in trace_context["history"]]
    assert "xss:dom_browser_validation" not in stages
