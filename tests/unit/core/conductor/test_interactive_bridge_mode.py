from __future__ import annotations

from types import SimpleNamespace

import src.core.conductor.interactive_bridge as interactive_bridge


class _FakeQueue:
    def __init__(self) -> None:
        self.batches: list[tuple[list[object], str]] = []
        self.items: list[object] = []

    def is_empty(self) -> bool:
        return not self.batches and not self.items

    def add_batch(self, tasks: list[object], source: str) -> None:
        self.batches.append((tasks, source))

    def add(self, task: object) -> None:
        self.items.append(task)


class _FakeMasterConductor:
    last_instance: "_FakeMasterConductor | None" = None

    def __init__(self, *args, **kwargs) -> None:
        self.context = SimpleNamespace(target_info={})
        self.task_queue = _FakeQueue()
        self.recipe_loader = SimpleNamespace(load_recipe=lambda _: None)
        self.executed = False
        _FakeMasterConductor.last_instance = self

    def plan(self, goal: str, target: str) -> list[object]:
        return [SimpleNamespace(goal=goal, target=target)]

    def execute_with_replan(self) -> dict[str, object]:
        self.executed = True
        return {"success": True}

    def close(self) -> None:
        return None


class _FakeEntryGateFacade:
    async def run_once(self, context) -> SimpleNamespace:
        return SimpleNamespace(failed=False, failures=[], context=context)


def test_start_interactive_session_persists_mode_in_target_info(monkeypatch) -> None:
    monkeypatch.setattr(
        interactive_bridge,
        "get_settings",
        lambda: SimpleNamespace(caido=SimpleNamespace(url="", token="")),
    )
    monkeypatch.setattr(
        interactive_bridge,
        "get_config_manager",
        lambda: SimpleNamespace(config=SimpleNamespace(mode=None, safe_mode=False)),
    )
    monkeypatch.setattr(interactive_bridge, "EntryGateFacade", _FakeEntryGateFacade)
    monkeypatch.setattr(interactive_bridge, "ProjectManager", lambda target: SimpleNamespace(project_name="test-project"))
    monkeypatch.setattr(interactive_bridge, "MasterConductor", _FakeMasterConductor)
    monkeypatch.setattr(interactive_bridge, "print_banner", lambda: None)
    monkeypatch.setattr(interactive_bridge, "print_step", lambda *args, **kwargs: None)
    monkeypatch.setattr(interactive_bridge, "print_result", lambda *args, **kwargs: None)
    monkeypatch.setattr(interactive_bridge, "get_execution_safeguard", lambda **kwargs: object(), raising=False)

    interactive_bridge.start_interactive_session(
        mode="vulntest",
        auto_goal="Attack",
        auto_target="http://127.0.0.1:4280",
        cookies="PHPSESSID=test; security=low",
    )

    mc = _FakeMasterConductor.last_instance
    assert mc is not None
    assert mc.executed is True
    assert mc.context.target_info["mode"] == "vulntest"
    assert mc.context.target_info["scan_profile"] == "bbpt"
    assert mc.context.target_info["profile"] == "bbpt"


def test_start_interactive_session_progress_messages_are_japanese(monkeypatch) -> None:
    captured_steps: list[str] = []

    monkeypatch.setattr(
        interactive_bridge,
        "get_settings",
        lambda: SimpleNamespace(caido=SimpleNamespace(url="", token="")),
    )
    monkeypatch.setattr(
        interactive_bridge,
        "get_config_manager",
        lambda: SimpleNamespace(config=SimpleNamespace(mode=None, safe_mode=False)),
    )
    monkeypatch.setattr(interactive_bridge, "EntryGateFacade", _FakeEntryGateFacade)
    monkeypatch.setattr(interactive_bridge, "ProjectManager", lambda target: SimpleNamespace(project_name="test-project"))
    monkeypatch.setattr(interactive_bridge, "MasterConductor", _FakeMasterConductor)
    monkeypatch.setattr(interactive_bridge, "print_banner", lambda: None)
    monkeypatch.setattr(interactive_bridge, "print_step", lambda _icon, text: captured_steps.append(text))
    monkeypatch.setattr(interactive_bridge, "print_result", lambda *args, **kwargs: None)
    monkeypatch.setattr(interactive_bridge, "get_execution_safeguard", lambda **kwargs: object(), raising=False)

    interactive_bridge.start_interactive_session(
        mode="vulntest",
        auto_goal="Attack",
        auto_target="http://127.0.0.1:4280",
        cookies="PHPSESSID=test; security=low",
    )

    joined = "\n".join(captured_steps)
    assert "セッションを開始" in joined
    assert "対象を計画中" in joined
    assert "タスクを実行中" in joined
    assert "Starting session" not in joined
    assert "Planning for target" not in joined
    assert "Executing tasks" not in joined
