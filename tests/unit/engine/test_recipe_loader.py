"""Tests for RecipeLoader — recipe loading, schema validation, and pre-selection gate."""
import pytest
import tempfile
import os
from pathlib import Path

from src.core.engine.recipe_loader import RecipeLoader, Recipe, RecipeStep


# ---------------------------------------------------------------------------
# Helper: write a minimal YAML recipe to a temp file
# ---------------------------------------------------------------------------
def _write_recipe(recipe: dict) -> str:
    """Write a recipe dict as YAML to a temp file and return the path."""
    import yaml
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(recipe, f)
    return path


# ── load_recipe: basic YAML parsing ──────────────────────────────────────

def test_load_recipe_parses_steps():
    """A valid YAML recipe should load with steps > 0."""
    loader = RecipeLoader()
    path = _write_recipe({
        "name": "test_recipe",
        "description": "Test",
        "agent": "swarm",
        "steps": [
            {"id": "step_1", "name": "Check", "action": "recon", "params": {}}
        ],
    })
    loader.load_recipe(path)
    recipe = loader.recipes["test_recipe"]
    assert len(recipe.steps) == 1
    assert recipe.steps[0].id == "step_1"
    assert recipe.steps[0].action == "recon"
    os.unlink(path)


def test_load_recipe_auto_assigns_step_ids():
    """Steps without explicit 'id' should get auto-assigned ids."""
    loader = RecipeLoader()
    path = _write_recipe({
        "name": "auto_id",
        "agent": "swarm",
        "steps": [
            {"name": "A", "action": "scan"},
            {"name": "B", "action": "report"},
        ],
    })
    loader.load_recipe(path)
    recipe = loader.recipes["auto_id"]
    assert recipe.steps[0].id == "step_0"
    assert recipe.steps[1].id == "step_1"
    os.unlink(path)


# ── schema validation: step_count > 0 ────────────────────────────────────

def test_recipe_with_zero_steps_is_rejected():
    """A recipe with no steps must be rejected during load."""
    loader = RecipeLoader()
    path = _write_recipe({
        "name": "empty_steps",
        "agent": "swarm",
        "steps": [],
    })
    with pytest.raises(ValueError, match="zero_steps"):
        loader.load_recipe(path)
    assert "empty_steps" not in loader.recipes
    os.unlink(path)


def test_recipe_with_missing_steps_key_is_rejected():
    """A recipe YAML without a 'steps' key must be rejected."""
    loader = RecipeLoader()
    path = _write_recipe({
        "name": "no_steps_key",
        "agent": "swarm",
    })
    with pytest.raises(ValueError, match="zero_steps"):
        loader.load_recipe(path)
    assert "no_steps_key" not in loader.recipes
    os.unlink(path)


# ── schema validation: supported actions only ────────────────────────────

def test_recipe_with_unsupported_action_is_rejected():
    """A recipe whose step uses an unsupported action must be rejected at load."""
    loader = RecipeLoader()
    path = _write_recipe({
        "name": "bad_action",
        "agent": "swarm",
        "steps": [
            {"id": "s1", "name": "Bad", "action": "totally_not_allowed"},
        ],
    })
    with pytest.raises(ValueError, match="unsupported_action"):
        loader.load_recipe(path)
    assert "bad_action" not in loader.recipes
    os.unlink(path)


def test_recipe_with_check_takeover_action_loads():
    """check_takeover (newly added) must be in the allowlist and loadable."""
    loader = RecipeLoader()
    path = _write_recipe({
        "name": "takeover_recipe",
        "agent": "swarm",
        "steps": [
            {
                "id": "step_0",
                "name": "Takeover Check",
                "action": "check_takeover",
                "params": {"target": "{{target}}"},
            },
        ],
    })
    loader.load_recipe(path)
    recipe = loader.recipes["takeover_recipe"]
    assert len(recipe.steps) == 1
    assert recipe.steps[0].action == "check_takeover"
    os.unlink(path)


def test_takeover_yaml_file_loads():
    """The real recipes/recon/takeover.yaml must load with steps > 0."""
    loader = RecipeLoader()
    real_path = Path(__file__).resolve().parents[3] / "recipes" / "recon" / "takeover.yaml"
    # Only run if the real file exists
    if not real_path.exists():
        pytest.skip("takeover.yaml not found — skipping integration test")
    loader.load_recipe(str(real_path))
    recipe = loader.recipes.get("subdomain_takeover")
    assert recipe is not None, "recipe must be registered under 'subdomain_takeover'"
    assert len(recipe.steps) >= 1, "takeover recipe must have at least 1 step"
    # All step actions must be in the allowlist
    from src.core.engine.recipe_contracts import validate_action_schema
    for step in recipe.steps:
        val = validate_action_schema(step.action)
        assert val["ok"], f"action '{step.action}' must be allowed; got {val['error']}"


# ── match_recipes_to_context (current behavior) ─────────────────────────

def test_match_recipes_returns_loaded_recipes():
    """All loaded recipes are returned as RecipeCandidate objects."""
    loader = RecipeLoader()
    p1 = _write_recipe({
        "name": "r1",
        "agent": "swarm",
        "steps": [{"name": "A", "action": "scan"}],
    })
    loader.load_recipe(p1)
    matches = loader.match_recipes_to_context({})
    assert len(matches) == 1
    assert matches[0].recipe.name == "r1"
    os.unlink(p1)


# ── Trigger success_condition / stop_condition (plan 3.1, 4.4) ───────────

def test_takeover_recipe_loads_with_success_stop_conditions():
    """The real takeover.yaml should load with success_condition and stop_condition."""
    loader = RecipeLoader()
    real_path = Path(__file__).resolve().parents[3] / "recipes" / "recon" / "takeover.yaml"
    if not real_path.exists():
        pytest.skip("takeover.yaml not found — skipping integration test")
    loader.load_recipe(str(real_path))
    recipe = loader.recipes.get("subdomain_takeover")
    assert recipe is not None
    # trigger should have success_condition and stop_condition
    trigger = recipe.trigger
    assert "success_condition" in trigger, "trigger must have success_condition"
    assert "stop_condition" in trigger, "trigger must have stop_condition"
    assert isinstance(trigger["success_condition"], str)
    assert isinstance(trigger["stop_condition"], str)
    assert len(trigger["success_condition"]) > 0
    assert len(trigger["stop_condition"]) > 0


def test_recipe_success_stop_conditions_accessible_from_trigger():
    """Recipe.trigger dict should expose success_condition/stop_condition."""
    import yaml
    recipe_yaml = {
        "name": "test_takeover",
        "description": "Test",
        "agent": "swarm",
        "trigger": {
            "type": "signal",
            "required_signals": ["dns_dead"],
            "success_condition": "provider_identified_and_dangling_evidence_collected",
            "stop_condition": "provider_unknown_or_signal_stale",
        },
        "steps": [
            {"id": "step_1", "name": "Check", "action": "scan"}
        ],
    }
    path = _write_recipe(recipe_yaml)
    loader = RecipeLoader()
    loader.load_recipe(path)
    recipe = loader.recipes["test_takeover"]
    assert recipe.trigger.get("success_condition") == "provider_identified_and_dangling_evidence_collected"
    assert recipe.trigger.get("stop_condition") == "provider_unknown_or_signal_stale"
    os.unlink(path)


def test_recipe_without_success_stop_conditions_loads():
    """A recipe without success_condition/stop_condition should load fine (backward compat)."""
    recipe_yaml = {
        "name": "no_conditions",
        "description": "Test",
        "agent": "swarm",
        "trigger": {
            "type": "signal",
            "required_signals": ["dns_dead"],
        },
        "steps": [
            {"id": "step_1", "name": "Check", "action": "recon"}
        ],
    }
    path = _write_recipe(recipe_yaml)
    loader = RecipeLoader()
    loader.load_recipe(path)  # must not raise
    recipe = loader.recipes["no_conditions"]
    assert recipe is not None
    # trigger may not have success_condition/stop_condition
    assert len(recipe.steps) == 1
    os.unlink(path)
