from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor
from src.core.engine.recipe_loader import Recipe, RecipeStep, RecipeLoader


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


# ---- Step 3: Auth surface metadata passing tests (TDD) ----

class TestRecipeInjectionWithAuthSurface:
    """Step 3: Verify _load_recipe_tasks passes auth surface metadata to match_recipes_to_context."""

    def _make_mc_with_context(self, target_info: dict, recipes: dict = None):
        """Create a MasterConductor instance with mocked context and recipe_loader."""
        mc = MasterConductor.__new__(MasterConductor)
        mc.context = SimpleNamespace(target_info=target_info)

        if recipes is not None:
            mc.recipe_loader = SimpleNamespace(recipes=recipes)
            # We'll mock match_recipes_to_context to verify what context is passed
        else:
            mc.recipe_loader = RecipeLoader()
            for name, recipe in (recipes or {}).items():
                mc.recipe_loader.recipes[name] = recipe

        return mc

    def test_passes_bearer_token_to_match_context(self):
        """bearer_token が context_dict に含まれて match_recipes_to_context に渡される"""
        loader = MagicMock()
        loader.recipes = {}
        loader.match_recipes_to_context = MagicMock(return_value=[])

        mc = self._make_mc_with_context(
            target_info={
                "target": "https://example.com",
                "tech_stack": ["OAuth"],
                "bearer_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.foo",
            }
        )
        mc.recipe_loader = loader

        mc._load_recipe_tasks()

        # Verify context passed to match_recipes_to_context includes bearer_token
        call_args = loader.match_recipes_to_context.call_args
        assert call_args is not None
        context_passed = call_args[0][0]
        assert context_passed.get("bearer_token") == "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.foo"

    def test_passes_cookies_to_match_context(self):
        """cookies が context_dict に含まれて渡される"""
        loader = MagicMock()
        loader.recipes = {}
        loader.match_recipes_to_context = MagicMock(return_value=[])

        mc = self._make_mc_with_context(
            target_info={
                "target": "https://example.com",
                "tech_stack": [],
                "cookies": "session=abc123; HttpOnly",
            }
        )
        mc.recipe_loader = loader

        mc._load_recipe_tasks()

        call_args = loader.match_recipes_to_context.call_args
        context_passed = call_args[0][0]
        assert context_passed.get("cookies") == "session=abc123; HttpOnly"

    def test_passes_discovered_urls_to_match_context(self):
        """discovered_urls が context_dict に含まれて渡される"""
        loader = MagicMock()
        loader.recipes = {}
        loader.match_recipes_to_context = MagicMock(return_value=[])

        urls = ["https://example.com/login", "https://example.com/oauth/callback"]
        mc = self._make_mc_with_context(
            target_info={
                "target": "https://example.com",
                "tech_stack": [],
                "discovered_urls": urls,
            }
        )
        mc.recipe_loader = loader

        mc._load_recipe_tasks()

        call_args = loader.match_recipes_to_context.call_args
        context_passed = call_args[0][0]
        assert context_passed.get("discovered_urls") == urls

    def test_passes_auth_headers_to_match_context(self):
        """auth_headers が context_dict に含まれて渡される"""
        loader = MagicMock()
        loader.recipes = {}
        loader.match_recipes_to_context = MagicMock(return_value=[])

        headers = {"Authorization": "Bearer token123"}
        mc = self._make_mc_with_context(
            target_info={
                "target": "https://example.com",
                "tech_stack": [],
                "auth_headers": headers,
            }
        )
        mc.recipe_loader = loader

        mc._load_recipe_tasks()

        call_args = loader.match_recipes_to_context.call_args
        context_passed = call_args[0][0]
        assert context_passed.get("auth_headers") == headers

    def test_passes_auth_surface_metadata_to_match_context(self):
        """auth_surface_metadata が context_dict に含まれて渡される"""
        loader = MagicMock()
        loader.recipes = {}
        loader.match_recipes_to_context = MagicMock(return_value=[])

        metadata = {"oauth_endpoints": ["/oauth/token"], "jwt_detected": True}
        mc = self._make_mc_with_context(
            target_info={
                "target": "https://example.com",
                "tech_stack": [],
                "auth_surface_metadata": metadata,
            }
        )
        mc.recipe_loader = loader

        mc._load_recipe_tasks()

        call_args = loader.match_recipes_to_context.call_args
        context_passed = call_args[0][0]
        assert context_passed.get("auth_surface_metadata") == metadata

    def test_high_value_recipe_injected_when_auth_surface_exists(self):
        """auth surface がある時だけ高価値Recipeが注入される"""
        loader = RecipeLoader()
        # Auth-required recipe
        auth_recipe = Recipe(
            name="jwt_check",
            description="Check JWT",
            agent="swarm",
            steps=[RecipeStep(id="s1", name="probe", action="scan", params={})],
            required_signals=["bearer_token", "oauth_endpoint"],
            optional_signals=["jwt_pattern"],
            stages=[
                {"name": "probe", "steps": ["s1"], "min_success": 1},
                {"name": "confirm", "steps": ["s1"], "min_success": 1},
            ],
        )
        # No-auth recipe (should still match)
        basic_recipe = Recipe(
            name="basic_check",
            description="Basic",
            agent="swarm",
            steps=[RecipeStep(id="s2", name="scan", action="scan", params={})],
            required_signals=[],
            optional_signals=[],
        )
        loader.recipes = {"jwt_check": auth_recipe, "basic_check": basic_recipe}

        mc = self._make_mc_with_context(
            target_info={
                "target": "https://example.com",
                "tech_stack": ["OAuth"],
                "bearer_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.foo",
                "cookies": "session=abc",
                "discovered_urls": [
                    "https://example.com/login",
                    "https://example.com/oauth/authorize",
                ],
                "auth_headers": {},
            }
        )
        mc.recipe_loader = loader

        tasks = mc._load_recipe_tasks()

        # Both recipes should match since auth surface exists
        assert len(tasks) == 2
        task_names = [t.params["recipe_name"] for t in tasks]
        assert "jwt_check" in task_names
        assert "basic_check" in task_names

    def test_auth_recipe_not_injected_when_no_auth_surface(self):
        """auth surface がない時は高価値Recipeが注入されない"""
        loader = RecipeLoader()
        auth_recipe = Recipe(
            name="jwt_check",
            description="Check JWT",
            agent="swarm",
            steps=[RecipeStep(id="s1", name="probe", action="scan", params={})],
            required_signals=["bearer_token", "oauth_endpoint"],
            optional_signals=[],
            stages=[
                {"name": "probe", "steps": ["s1"], "min_success": 1},
                {"name": "confirm", "steps": ["s1"], "min_success": 1},
            ],
        )
        basic_recipe = Recipe(
            name="basic_check",
            description="Basic",
            agent="swarm",
            steps=[RecipeStep(id="s2", name="scan", action="scan", params={})],
            required_signals=[],
            optional_signals=[],
        )
        loader.recipes = {"jwt_check": auth_recipe, "basic_check": basic_recipe}

        mc = self._make_mc_with_context(
            target_info={
                "target": "https://example.com",
                "tech_stack": [],
                "discovered_urls": ["https://example.com/home"],
                # No bearer_token, no oauth endpoints
            }
        )
        mc.recipe_loader = loader

        tasks = mc._load_recipe_tasks()

        # Only basic recipe should match
        assert len(tasks) == 1
        assert tasks[0].params["recipe_name"] == "basic_check"

    def test_empty_context_still_passes_target(self):
        """空のcontextでもtargetだけは渡される"""
        loader = MagicMock()
        loader.recipes = {}
        loader.match_recipes_to_context = MagicMock(return_value=[])

        mc = self._make_mc_with_context(
            target_info={"target": "https://example.com", "tech_stack": []}
        )
        mc.recipe_loader = loader

        mc._load_recipe_tasks()

        call_args = loader.match_recipes_to_context.call_args
        context_passed = call_args[0][0]
        assert context_passed.get("target") == "https://example.com"
        assert context_passed.get("tech_stack") == []


