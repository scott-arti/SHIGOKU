from types import SimpleNamespace

from src.core.domain.model.task import Task
from src.core.engine.recipe_contracts import validate_action_schema, validate_task_schema


def test_validate_action_schema_accepts_known_action():
    result = validate_action_schema("scan")
    assert result["ok"] is True
    assert result["error"] == ""


def test_validate_action_schema_rejects_unknown_action():
    result = validate_action_schema("unknown_action")
    assert result["ok"] is False
    assert result["error"] == "unsupported_action:unknown_action"


def test_validate_task_schema_requires_core_fields():
    task = SimpleNamespace(id="", name="", agent_type="", action="", params={})
    result = validate_task_schema(task)
    assert result["ok"] is False
    assert "missing:id" in result["errors"]
    assert "missing:name" in result["errors"]
    assert "missing:agent_type" in result["errors"]
    assert "missing:action" in result["errors"]
