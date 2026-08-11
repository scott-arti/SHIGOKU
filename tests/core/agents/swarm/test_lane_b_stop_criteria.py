"""
Lane B (SGK-2026-0441): Phase-2 validation loop stop criteria tests.

- base_manager: phase2 time budget (phase2_time_budget_exhausted) and
  payout-grade early stop (payout_grade_obtained); budget=None stays legacy.
- thought_loop: time_budget_seconds (time_budget_exhausted status) and
  payout-grade should_stop (COMPLETED early); legacy defaults unchanged.

The Lane A judge module (src/core/agents/swarm/injection/payout_grade.py) does
not exist yet, so tests inject a stub module into sys.modules — the production
code imports it lazily with a fail-closed guard.
"""
import asyncio
import sys
import types
from types import SimpleNamespace
from typing import Any, Tuple
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.agents.swarm.base_manager import BaseManagerAgent
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.thought_loop import ThoughtLoop, LoopStatus, ThoughtStep

PAYOUT_GRADE_MODULE = "src.core.agents.swarm.injection.payout_grade"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def payout_grade_judge(monkeypatch):
    """Stub Lane A's evaluate_payout_grade in sys.modules.

    Returns a mutable state dict; set state["payout_grade"] to control verdicts.
    """
    mod = types.ModuleType(PAYOUT_GRADE_MODULE)
    state = {"payout_grade": False}

    def evaluate(finding):
        return SimpleNamespace(
            payout_grade=state["payout_grade"],
            reason="stub",
            evidence_refs=[],
            marker=None,
        )

    mod.evaluate_payout_grade = evaluate
    monkeypatch.setitem(sys.modules, PAYOUT_GRADE_MODULE, mod)
    return state


def _make_llm_response(content: str) -> MagicMock:
    resp = MagicMock()
    resp.choices = [MagicMock()]
    resp.choices[0].message.content = content
    return resp


def _make_manager(max_turns: int = 5):
    manager = BaseManagerAgent(config={"model": "test-model"})
    manager.max_turns = max_turns
    mock_llm = MagicMock()
    manager.set_llm_client(mock_llm)
    return manager, mock_llm


class MockLoop(ThoughtLoop):
    """Concrete ThoughtLoop for testing (no should_stop override)."""

    def __init__(self, max_turns: int = 5, **kwargs):
        super().__init__(max_turns, **kwargs)
        self.decide_count = 0

    async def decide(self, turn: int) -> Tuple[str, str, Any]:
        self.decide_count += 1
        return f"Thinking {turn}", "mock_action", {"input": turn}

    async def act(self, action: str, action_input: Any) -> str:
        if isinstance(action_input, dict):
            val = action_input.get('input', 'N/A')
        else:
            val = str(action_input)
        return f"Result {val}"


class SlowDecideLoop(MockLoop):
    """decide() sleeps so a small time budget trips mid-loop."""

    async def decide(self, turn: int) -> Tuple[str, str, Any]:
        await asyncio.sleep(0.05)
        return await super().decide(turn)


# ---------------------------------------------------------------------------
# base_manager: time budget
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_base_manager_time_budget_exhausted_stops_loop():
    manager, mock_llm = _make_manager()

    async def slow_agenerate(messages):
        await asyncio.sleep(0.05)
        return _make_llm_response("Thought: probe.\nAction: test_tool(param='value')")

    mock_llm.agenerate = slow_agenerate
    mock_tool = MagicMock(return_value={"status": "ok"})
    manager.register_tool("test_tool", mock_tool, "A test tool")

    task = Task(id="t1", name="Test", target="http://example.com")
    task.params["phase2_time_budget_seconds"] = 0.01

    result = await manager.dispatch(task)

    assert getattr(result, "stop_reason", None) == "phase2_time_budget_exhausted"
    assert result.status == "running"  # existing shape preserved (no Final Answer)
    assert mock_tool.call_count == 1  # stopped before turn 2


@pytest.mark.asyncio
async def test_base_manager_no_budget_runs_to_max_turns_legacy():
    manager, mock_llm = _make_manager(max_turns=3)
    mock_llm.agenerate = AsyncMock(
        side_effect=[
            _make_llm_response("Thought.\nAction: test_tool(param='value')"),
            _make_llm_response("Thought.\nAction: test_tool(param='value')"),
            _make_llm_response("Thought.\nAction: test_tool(param='value')"),
        ]
    )
    mock_tool = MagicMock(return_value={"status": "ok"})
    manager.register_tool("test_tool", mock_tool, "A test tool")

    task = Task(id="t2", name="Test", target="http://example.com")
    # no phase2_time_budget_seconds in params

    result = await manager.dispatch(task)

    assert getattr(result, "stop_reason", None) is None
    assert result.status == "running"
    assert mock_tool.call_count == 3  # max_turns safety ceiling intact


# ---------------------------------------------------------------------------
# base_manager: payout-grade early stop
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_base_manager_payout_grade_true_stops_success(payout_grade_judge):
    payout_grade_judge["payout_grade"] = True
    manager, mock_llm = _make_manager()
    mock_llm.agenerate = AsyncMock(
        side_effect=[_make_llm_response("Thought.\nAction: test_tool(param='value')")]
    )
    mock_tool = MagicMock(return_value={"candidate_findings": [{"title": "sqli", "evidence": "..."}]})
    manager.register_tool("test_tool", mock_tool, "A test tool")

    task = Task(id="t3", name="Test", target="http://example.com")
    result = await manager.dispatch(task)

    assert result.status == "success"
    assert getattr(result, "stop_reason", None) == "payout_grade_obtained"
    assert mock_tool.call_count == 1


@pytest.mark.asyncio
async def test_base_manager_payout_grade_false_continues(payout_grade_judge):
    payout_grade_judge["payout_grade"] = False
    manager, mock_llm = _make_manager(max_turns=3)
    mock_llm.agenerate = AsyncMock(
        side_effect=[
            _make_llm_response("Thought.\nAction: test_tool(param='value')"),
            _make_llm_response("Thought.\nAction: test_tool(param='value')"),
            _make_llm_response("Thought.\nAction: test_tool(param='value')"),
        ]
    )
    mock_tool = MagicMock(return_value={"candidate_findings": [{"title": "sqli", "evidence": "..."}]})
    manager.register_tool("test_tool", mock_tool, "A test tool")

    task = Task(id="t4", name="Test", target="http://example.com")
    result = await manager.dispatch(task)

    assert getattr(result, "stop_reason", None) is None
    assert result.status == "running"
    assert mock_tool.call_count == 3


@pytest.mark.asyncio
async def test_base_manager_no_judge_module_is_noop(monkeypatch):
    """Judge module import failure (None in sys.modules) → fail-closed no-op."""
    monkeypatch.setitem(sys.modules, PAYOUT_GRADE_MODULE, None)
    manager, mock_llm = _make_manager(max_turns=2)
    mock_llm.agenerate = AsyncMock(
        side_effect=[
            _make_llm_response("Thought.\nAction: test_tool(param='value')"),
            _make_llm_response("Thought.\nAction: test_tool(param='value')"),
        ]
    )
    mock_tool = MagicMock(return_value={"candidate_findings": [{"title": "sqli"}]})
    manager.register_tool("test_tool", mock_tool, "A test tool")

    task = Task(id="t5", name="Test", target="http://example.com")
    result = await manager.dispatch(task)

    assert getattr(result, "stop_reason", None) is None
    assert mock_tool.call_count == 2


# ---------------------------------------------------------------------------
# thought_loop: time budget
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_thought_loop_time_budget_exhausted():
    loop = SlowDecideLoop(max_turns=5, time_budget_seconds=0.01)
    result = await loop.run_loop({})

    assert result["status"] == LoopStatus.TIME_BUDGET_EXHAUSTED.value
    assert result["stop_reason"] == "time_budget_exhausted"
    assert result["turns"] == 1


@pytest.mark.asyncio
async def test_thought_loop_no_budget_runs_to_max_turns_legacy():
    loop = MockLoop(max_turns=3)
    result = await loop.run_loop({})

    assert result["status"] == LoopStatus.ABORTED.value
    assert result["stop_reason"] is None
    assert result["turns"] == 3


# ---------------------------------------------------------------------------
# thought_loop: payout-grade early stop
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_thought_loop_payout_grade_completes_early(payout_grade_judge):
    payout_grade_judge["payout_grade"] = True
    loop = MockLoop(max_turns=5)
    result = await loop.run_loop({"candidate_finding": {"title": "sqli", "evidence": "..."}})

    assert result["status"] == LoopStatus.COMPLETED.value
    assert result["stop_reason"] == "payout_grade_obtained"
    assert result["turns"] == 1


@pytest.mark.asyncio
async def test_thought_loop_payout_grade_false_continues(payout_grade_judge):
    payout_grade_judge["payout_grade"] = False
    loop = MockLoop(max_turns=3)
    result = await loop.run_loop({"candidate_findings": [{"title": "sqli"}]})

    assert result["status"] == LoopStatus.ABORTED.value
    assert result["stop_reason"] is None
    assert result["turns"] == 3


@pytest.mark.asyncio
async def test_thought_loop_no_candidate_no_judge_is_noop(monkeypatch):
    """Legacy defaults: no candidate in context, judge import fails → unchanged."""
    monkeypatch.setitem(sys.modules, PAYOUT_GRADE_MODULE, None)
    loop = MockLoop(max_turns=3)
    result = await loop.run_loop({"target": "http://example.com"})

    assert result["status"] == LoopStatus.ABORTED.value
    assert result["stop_reason"] is None
    assert result["turns"] == 3


# ---------------------------------------------------------------------------
# Contract reconciliation with the real Lane A module (when present on disk)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_real_judge_contract_payout_grade_true():
    """Smoke: real evaluate_payout_grade + PayoutGradeResult attribute access.

    Validates the assumed contract (evaluate_payout_grade(finding).payout_grade
    attribute access against the actual Lane A dataclass) end-to-end through the
    base_manager loop. Skips when Lane A's module is not on disk yet.
    """
    from pathlib import Path
    judge_path = (
        Path(__file__).resolve().parents[4]
        / "src" / "core" / "agents" / "swarm" / "injection" / "payout_grade.py"
    )
    if not judge_path.exists():
        pytest.skip("Lane A payout_grade.py not present on disk")

    manager, mock_llm = _make_manager()
    mock_llm.agenerate = AsyncMock(
        side_effect=[_make_llm_response("Thought.\nAction: test_tool(param='value')")]
    )
    finding = {
        "vuln_type": "sqli",
        "impact": "SQL injection allows reading the users table.",
        "reproduction_steps": ["Send payload", "Observe DB error"],
        "evidence": {
            "request_method": "GET",
            "request_url": "http://example.com/item?id=1'",
            "response_status": 500,
            "response_body": "SQL syntax error near '1'",
        },
    }
    mock_tool = MagicMock(return_value={"candidate_findings": [finding]})
    manager.register_tool("test_tool", mock_tool, "A test tool")

    task = Task(id="t6", name="Test", target="http://example.com")
    result = await manager.dispatch(task)

    assert result.status == "success"
    assert getattr(result, "stop_reason", None) == "payout_grade_obtained"
    assert mock_tool.call_count == 1
