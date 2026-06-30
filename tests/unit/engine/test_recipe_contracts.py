from types import SimpleNamespace

from src.core.domain.model.task import Task
from src.core.engine.recipe_contracts import (
    validate_action_schema,
    validate_task_schema,
    validate_recipe_schema,
    ALLOWED_RECIPE_STEP_ACTIONS,
)
from src.core.engine.recipe_loader import Recipe, RecipeStep


def test_validate_action_schema_accepts_known_action():
    result = validate_action_schema("scan")
    assert result["ok"] is True
    assert result["error"] == ""


def test_validate_action_schema_rejects_unknown_action():
    result = validate_action_schema("unknown_action")
    assert result["ok"] is False
    assert result["error"] == "unsupported_action:unknown_action"


def test_validate_action_schema_accepts_check_takeover():
    """check_takeover must be in the allowlist for takeover v2 recipe support."""
    result = validate_action_schema("check_takeover")
    assert result["ok"] is True, f"check_takeover should be allowed; got {result['error']}"


def test_validate_action_schema_accepts_dns_check():
    result = validate_action_schema("dns_check")
    assert result["ok"] is True


def test_validate_action_schema_rejects_empty_action():
    result = validate_action_schema("")
    assert result["ok"] is False
    assert "unsupported_action" in result["error"]


def test_validate_action_schema_with_custom_allowed():
    result = validate_action_schema("custom_op", allowed=["custom_op", "standard"])
    assert result["ok"] is True


def test_validate_task_schema_requires_core_fields():
    task = SimpleNamespace(id="", name="", agent_type="", action="", params={})
    result = validate_task_schema(task)
    assert result["ok"] is False
    assert "missing:id" in result["errors"]
    assert "missing:name" in result["errors"]
    assert "missing:agent_type" in result["errors"]
    assert "missing:action" in result["errors"]


# ── validate_recipe_schema (new) ────────────────────────────────────────

def test_validate_recipe_schema_rejects_zero_steps():
    recipe = Recipe(name="r", description="d", agent="swarm", steps=[])
    result = validate_recipe_schema(recipe)
    assert result["ok"] is False
    assert "zero_steps" in result["error"]


def test_validate_recipe_schema_rejects_unsupported_step_action():
    recipe = Recipe(
        name="r", description="d", agent="swarm",
        steps=[RecipeStep(id="s1", name="Bad", action="not_allowed")],
    )
    result = validate_recipe_schema(recipe)
    assert result["ok"] is False
    assert "unsupported_action" in result["error"]


def test_validate_recipe_schema_accepts_valid_recipe():
    recipe = Recipe(
        name="r", description="d", agent="swarm",
        steps=[RecipeStep(id="s1", name="Good", action="scan")],
    )
    result = validate_recipe_schema(recipe)
    assert result["ok"] is True
    assert result["error"] == ""


def test_validate_recipe_schema_reports_multiple_unsupported_actions():
    recipe = Recipe(
        name="r", description="d", agent="swarm",
        steps=[
            RecipeStep(id="s1", name="Bad1", action="not_allowed_1"),
            RecipeStep(id="s2", name="Bad2", action="not_allowed_2"),
        ],
    )
    result = validate_recipe_schema(recipe)
    assert result["ok"] is False
    assert "unsupported_action" in result["error"]
    assert "not_allowed_1" in result["error"]
    assert "not_allowed_2" in result["error"]


def test_validate_recipe_schema_validates_check_takeover_action():
    """check_takeover must pass recipe-level validation."""
    recipe = Recipe(
        name="takeover", description="d", agent="swarm",
        steps=[RecipeStep(id="s1", name="Check", action="check_takeover")],
    )
    result = validate_recipe_schema(recipe)
    assert result["ok"] is True, f"check_takeover recipe should pass; got {result['error']}"
