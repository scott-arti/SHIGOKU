from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor
from src.core.engine.recipe_loader import Recipe, RecipeStep


@pytest.mark.asyncio
async def test_execute_recipe_task_rejects_missing_recipe_name():
    mc = MasterConductor.__new__(MasterConductor)
    mc.recipe_loader = SimpleNamespace(recipes={})
    mc._dispatch = AsyncMock()
    task = Task(
        id="recipe_1",
        name="recipe",
        agent_type="swarm",
        action="run_recipe",
        params={"target": "https://example.com"},
    )
    result = await mc._execute_recipe_task(task)
    assert result["success"] is False
    assert result["error"] == "CONTRACT_ERROR:missing_recipe_name"


@pytest.mark.asyncio
async def test_execute_recipe_task_runs_with_valid_contract():
    mc = MasterConductor.__new__(MasterConductor)
    recipe = Recipe(
        name="r1",
        description="d",
        agent="swarm",
        steps=[RecipeStep(id="s1", name="scan", action="scan", params={})],
    )
    mc.recipe_loader = SimpleNamespace(recipes={"r1": recipe})
    mc._dispatch = AsyncMock(return_value={"success": True, "data": {"ok": True}})

    task = Task(
        id="recipe_2",
        name="recipe",
        agent_type="swarm",
        action="run_recipe",
        params={"recipe_name": "r1", "target": "https://example.com"},
    )
    result = await mc._execute_recipe_task(task)
    assert result["success"] is True
    assert "data" in result
    assert result["data"]["summary"]["total_steps"] == 1

