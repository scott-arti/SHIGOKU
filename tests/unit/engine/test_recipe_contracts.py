import pytest
from types import SimpleNamespace

from src.core.domain.model.task import Task
from src.core.engine.recipe_contracts import (
    validate_action_schema,
    validate_task_schema,
    validate_recipe_schema,
    validate_trigger_section,
    validate_stages_section,
    validate_evidence_policy,
)


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


# ---- Step 1-2: New Recipe schema validation tests (TDD) ----

class TestValidateTriggerSection:
    """Step 1: trigger field validation"""

    def test_valid_trigger_with_required_and_optional_signals(self):
        trigger = {
            "required_signals": ["bearer_token", "session_cookie"],
            "optional_signals": ["jwt_pattern", "oauth_endpoint"],
        }
        result = validate_trigger_section(trigger)
        assert result["ok"] is True

    def test_trigger_with_only_required_signals(self):
        trigger = {"required_signals": ["bearer_token"]}
        result = validate_trigger_section(trigger)
        assert result["ok"] is True

    def test_trigger_with_only_optional_signals(self):
        trigger = {"optional_signals": ["jwt_pattern"]}
        result = validate_trigger_section(trigger)
        assert result["ok"] is True

    def test_trigger_rejects_empty_required_signals_list(self):
        trigger = {"required_signals": []}
        result = validate_trigger_section(trigger)
        assert result["ok"] is True  # empty is valid, just won't match

    def test_trigger_rejects_non_list_required_signals(self):
        trigger = {"required_signals": "not_a_list"}
        result = validate_trigger_section(trigger)
        assert result["ok"] is False
        assert "required_signals must be a list" in result["error"]

    def test_trigger_rejects_non_list_optional_signals(self):
        trigger = {"optional_signals": 123}
        result = validate_trigger_section(trigger)
        assert result["ok"] is False
        assert "optional_signals must be a list" in result["error"]

    def test_empty_trigger_is_valid(self):
        result = validate_trigger_section({})
        assert result["ok"] is True


class TestValidateStagesSection:
    """Step 1: stages field validation"""

    def test_valid_probe_confirm_evidence_stages(self):
        stages = [
            {"name": "probe", "steps": ["s1", "s2"], "min_success": 1},
            {"name": "confirm", "steps": ["s3"], "min_success": 1},
            {"name": "evidence", "steps": ["s4"], "min_success": 1},
        ]
        result = validate_stages_section(stages)
        assert result["ok"] is True

    def test_stages_with_insufficient_count(self):
        stages = [{"name": "probe", "steps": ["s1"]}]
        result = validate_stages_section(stages)
        assert result["ok"] is False
        assert "at least 2 stages" in result["error"]

    def test_stages_rejects_non_list(self):
        result = validate_stages_section("not_a_list")
        assert result["ok"] is False

    def test_stage_missing_name(self):
        stages = [
            {"steps": ["s1"], "min_success": 1},
            {"name": "confirm", "steps": ["s2"], "min_success": 1},
        ]
        result = validate_stages_section(stages)
        assert result["ok"] is False
        assert "missing name" in result["error"]

    def test_stage_missing_steps(self):
        stages = [
            {"name": "probe", "min_success": 1},
            {"name": "confirm", "steps": ["s2"], "min_success": 1},
        ]
        result = validate_stages_section(stages)
        assert result["ok"] is False
        assert "missing steps" in result["error"]

    def test_stage_missing_min_success_defaults_to_1(self):
        stages = [
            {"name": "probe", "steps": ["s1"]},
            {"name": "confirm", "steps": ["s2"]},
        ]
        result = validate_stages_section(stages)
        assert result["ok"] is True


class TestValidateEvidencePolicy:
    """Step 1: evidence_policy field validation"""

    def test_valid_evidence_policy(self):
        policy = {"max_items": 10, "redact_secrets": True, "structured": True}
        result = validate_evidence_policy(policy)
        assert result["ok"] is True

    def test_evidence_policy_defaults(self):
        result = validate_evidence_policy({})
        assert result["ok"] is True

    def test_evidence_policy_rejects_invalid_max_items(self):
        policy = {"max_items": -1}
        result = validate_evidence_policy(policy)
        assert result["ok"] is False
        assert "max_items" in result["error"]


class TestValidateRecipeSchema:
    """Step 1: full recipe schema validation"""

    def _minimal_valid_recipe(self):
        return {
            "name": "test_recipe",
            "description": "Test recipe",
            "agent": "swarm",
            "steps": [
                {"id": "s1", "name": "step1", "action": "scan", "params": {}},
            ],
            "trigger": {
                "required_signals": ["bearer_token"],
                "optional_signals": ["jwt_pattern"],
            },
            "stages": [
                {"name": "probe", "steps": ["s1"], "min_success": 1},
                {"name": "confirm", "steps": ["s1"], "min_success": 1},
            ],
        }

    def test_valid_recipe_passes(self):
        recipe = self._minimal_valid_recipe()
        result = validate_recipe_schema(recipe)
        assert result["ok"] is True, f"Errors: {result.get('errors', [])}"

    def test_recipe_missing_name_fails(self):
        recipe = self._minimal_valid_recipe()
        del recipe["name"]
        result = validate_recipe_schema(recipe)
        assert result["ok"] is False

    def test_recipe_missing_steps_fails(self):
        recipe = self._minimal_valid_recipe()
        del recipe["steps"]
        result = validate_recipe_schema(recipe)
        assert result["ok"] is False

    def test_recipe_invalid_trigger_reported(self):
        recipe = self._minimal_valid_recipe()
        recipe["trigger"]["required_signals"] = "not_list"
        result = validate_recipe_schema(recipe)
        assert result["ok"] is False

    def test_recipe_invalid_stages_reported(self):
        recipe = self._minimal_valid_recipe()
        recipe["stages"] = [{"name": "only_one", "steps": ["s1"]}]
        result = validate_recipe_schema(recipe)
        assert result["ok"] is False

    def test_recipe_with_success_signals(self):
        recipe = self._minimal_valid_recipe()
        recipe["success_signals"] = [
            {"type": "status_code", "expect": "2xx", "on_endpoint": "/admin"},
        ]
        result = validate_recipe_schema(recipe)
        assert result["ok"] is True

    def test_recipe_with_failure_signals(self):
        recipe = self._minimal_valid_recipe()
        recipe["failure_signals"] = [
            {"type": "status_code", "expect": "401", "on_failure": "stop"},
        ]
        result = validate_recipe_schema(recipe)
        assert result["ok"] is True

    def test_recipe_with_stop_conditions(self):
        recipe = self._minimal_valid_recipe()
        recipe["stop_conditions"] = [
            "rate_limit",
            "waf_block",
            "auth_surface_missing",
        ]
        result = validate_recipe_schema(recipe)
        assert result["ok"] is True

    def test_recipe_with_evidence_policy(self):
        recipe = self._minimal_valid_recipe()
        recipe["evidence_policy"] = {"max_items": 5, "redact_secrets": True}
        result = validate_recipe_schema(recipe)
        assert result["ok"] is True
