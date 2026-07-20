import os

import pytest

os.environ.setdefault("SHIGOKU_NEO4J_PASSWORD", "dummy_password_for_tests")
os.environ.setdefault("SHIGOKU_NEO4J_USER", "neo4j")
os.environ.setdefault("SHIGOKU_NEO4J_URI", "bolt://localhost:7687")

from src.core.conductor import interactive_bridge


@pytest.mark.asyncio
async def test_execution_safeguard_hitl_callback_observe_auto_allows_without_prompt(monkeypatch):
    prompts: list[str] = []

    def fail_if_prompted(prompt: str, default: bool = False) -> bool:
        prompts.append(prompt)
        return False

    monkeypatch.setattr(
        interactive_bridge.InteractiveBridge,
        "ask_for_approval",
        fail_if_prompted,
    )

    callback = interactive_bridge._build_execution_safeguard_hitl_callback("observe")

    approved = await callback({"prompt": "should not be displayed"})

    assert approved is True
    assert prompts == []


@pytest.mark.asyncio
async def test_execution_safeguard_hitl_callback_enforce_uses_prompt(monkeypatch):
    prompts: list[tuple[str, bool]] = []

    def approve(prompt: str, default: bool = False) -> bool:
        prompts.append((prompt, default))
        return True

    monkeypatch.setattr(
        interactive_bridge.InteractiveBridge,
        "ask_for_approval",
        approve,
    )

    callback = interactive_bridge._build_execution_safeguard_hitl_callback("enforce_hitl")

    approved = await callback({"prompt": "confirm request"})

    assert approved is True
    assert prompts == [("confirm request", True)]


def test_current_intervention_gate_mode_reads_runtime_settings(monkeypatch):
    monkeypatch.setattr(
        interactive_bridge.runtime_settings,
        "intervention_gate_mode",
        "enforce_human_preferred",
        raising=False,
    )

    assert interactive_bridge._current_intervention_gate_mode() == "enforce_human_preferred"


def test_current_intervention_gate_mode_invalid_falls_back_to_observe(monkeypatch):
    monkeypatch.setattr(
        interactive_bridge.runtime_settings,
        "intervention_gate_mode",
        "unexpected",
        raising=False,
    )

    assert interactive_bridge._current_intervention_gate_mode() == "observe"
