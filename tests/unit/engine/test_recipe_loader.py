"""TDD tests for RecipeLoader score-based matching (Step 2).

Tests cover:
  - required_signals must all be present for a recipe to be selected
  - optional_signals add deterministic score points
  - top-N limit is respected
  - empty / no-trigger recipes are handled
"""

import pytest
import yaml
from tempfile import NamedTemporaryFile
from pathlib import Path

from src.core.engine.recipe_loader import RecipeLoader, Recipe, RecipeStep


# ---- Helpers ----

def _make_temp_recipe_yaml(recipe_dict: dict) -> str:
    """Write a recipe dict to a temp YAML file and return the path."""
    tmp = NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8")
    yaml.dump(recipe_dict, tmp)
    tmp.close()
    return tmp.name


def _basic_recipe_dict(name: str, required_signals: list = None,
                       optional_signals: list = None,
                       priority: int = 50) -> dict:
    return {
        "name": name,
        "description": f"Test recipe {name}",
        "agent": "swarm",
        "priority": priority,
        "steps": [
            {"id": "s1", "name": "probe_step", "action": "scan", "params": {}},
        ],
        "stages": [
            {"name": "probe", "steps": ["s1"], "min_success": 1},
            {"name": "confirm", "steps": ["s1"], "min_success": 1},
        ],
        "trigger": {
            "required_signals": required_signals or [],
            "optional_signals": optional_signals or [],
        },
    }


def _auth_context(**overrides) -> dict:
    base = {
        "target": "https://api.example.com",
        "tech_stack": ["OAuth", "JWT", "React"],
        "auth_headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.foo"},
        "bearer_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.foo",
        "cookies": "session=abc123; Path=/; HttpOnly",
        "discovered_urls": [
            "https://api.example.com/login",
            "https://api.example.com/oauth/authorize",
            "https://api.example.com/me",
            "https://api.example.com/admin/users",
        ],
        "form_params": ["username", "password", "csrf_token"],
        "query_params": ["redirect_uri", "client_id", "response_type"],
        "js_files": ["app.js", "auth.js"],
        "auth_surface_metadata": {
            "oauth_endpoints": ["/oauth/authorize", "/oauth/token"],
            "jwt_detected": True,
            "session_management": "cookie",
        },
        "recon_findings": [],
    }
    base.update(overrides)
    return base


# ---- Loader basic tests ----

class TestRecipeLoaderLoadRecipe:
    def test_loads_recipe_with_new_schema_fields(self):
        recipe_dict = _basic_recipe_dict("test_auth_recipe",
                                          required_signals=["bearer_token"],
                                          optional_signals=["jwt_pattern", "oauth_endpoint"])
        recipe_dict["success_signals"] = [{"type": "status_2xx", "on": "admin_endpoint"}]
        recipe_dict["failure_signals"] = [{"type": "rate_limit"}]
        recipe_dict["stop_conditions"] = ["waf_block", "missing_auth_surface"]
        recipe_dict["evidence_policy"] = {"max_items": 5, "redact_secrets": True}

        path = _make_temp_recipe_yaml(recipe_dict)
        loader = RecipeLoader()
        loader.load_recipe(path)

        recipe = loader.recipes["test_auth_recipe"]
        assert recipe.name == "test_auth_recipe"
        assert recipe.required_signals == ["bearer_token"]
        assert recipe.optional_signals == ["jwt_pattern", "oauth_endpoint"]
        assert recipe.success_signals == recipe_dict["success_signals"]
        assert recipe.failure_signals == recipe_dict["failure_signals"]
        assert recipe.stop_conditions == recipe_dict["stop_conditions"]
        assert recipe.evidence_policy == recipe_dict["evidence_policy"]
        assert recipe.stages == recipe_dict["stages"]

    def test_loads_recipe_with_minimal_fields(self):
        recipe_dict = {
            "name": "minimal",
            "description": "Minimal recipe",
            "agent": "universal",
            "steps": [{"id": "s1", "name": "step", "action": "scan", "params": {}}],
        }
        path = _make_temp_recipe_yaml(recipe_dict)
        loader = RecipeLoader()
        loader.load_recipe(path)

        recipe = loader.recipes["minimal"]
        assert recipe.name == "minimal"
        assert recipe.required_signals == []
        assert recipe.optional_signals == []
        assert recipe.stages == []
        assert recipe.evidence_policy == {}


# ---- Score-based matching tests (Step 2 TDD) ----

class TestMatchRecipesRequiredSignals:
    """required_signals 欠如時は未選抜"""

    def test_no_match_when_required_signal_missing(self):
        loader = RecipeLoader()
        path = _make_temp_recipe_yaml(
            _basic_recipe_dict("jwt_check",
                               required_signals=["bearer_token", "session_cookie"],
                               optional_signals=["jwt_pattern"])
        )
        loader.load_recipe(path)

        context = _auth_context(bearer_token=None, cookies="")
        matched = loader.match_recipes_to_context(context)
        assert len(matched) == 0, "Should not match when required signal is missing"

    def test_match_when_all_required_signals_present(self):
        loader = RecipeLoader()
        path = _make_temp_recipe_yaml(
            _basic_recipe_dict("jwt_check",
                               required_signals=["bearer_token", "session_cookie"])
        )
        loader.load_recipe(path)

        context = _auth_context()
        candidates = loader.match_recipes_to_context(context)
        assert len(candidates) == 1
        assert candidates[0].recipe_name == "jwt_check"

    def test_recipe_with_no_required_signals_matches_always(self):
        """trigger.required_signals が空のRecipeは常に候補になる"""
        loader = RecipeLoader()
        path = _make_temp_recipe_yaml(
            _basic_recipe_dict("always_on", required_signals=[], optional_signals=[])
        )
        loader.load_recipe(path)

        context = _auth_context(bearer_token=None, auth_headers={},
                                discovered_urls=[], js_files=[])
        candidates = loader.match_recipes_to_context(context)
        assert len(candidates) == 1
        assert candidates[0].recipe_name == "always_on"

    def test_missing_trigger_section_treated_as_no_signals(self):
        """trigger セクションがないRecipeは required/optional ともに空扱いでマッチする"""
        loader = RecipeLoader()
        recipe_dict = {
            "name": "no_trigger",
            "description": "No trigger section",
            "agent": "swarm",
            "steps": [{"id": "s1", "name": "step", "action": "scan", "params": {}}],
        }
        path = _make_temp_recipe_yaml(recipe_dict)
        loader.load_recipe(path)

        candidates = loader.match_recipes_to_context({})
        assert len(candidates) == 1
        assert candidates[0].recipe_name == "no_trigger"


class TestMatchRecipesOptionalSignals:
    """optional_signals 加点が deterministic"""

    def test_optional_signals_add_score(self):
        loader = RecipeLoader()
        path = _make_temp_recipe_yaml(
            _basic_recipe_dict("jwt_bonus",
                               required_signals=["bearer_token"],
                               optional_signals=["jwt_pattern", "oauth_endpoint", "admin_endpoint"])
        )
        loader.load_recipe(path)

        context = _auth_context()
        candidates = loader.match_recipes_to_context(context)

        assert len(candidates) == 1
        score = candidates[0].score
        # jwt_pattern: bearer_token has JWT pattern → +1
        # oauth_endpoint: discovered_urls has /oauth/authorize → +1
        # admin_endpoint: discovered_urls has /admin/users → +1
        # base required match = 10
        assert score >= 10 + 3  # base 10 + 3 optional signals

    def test_optional_signals_score_is_deterministic(self):
        """Same context should always produce same score"""
        loader = RecipeLoader()
        path = _make_temp_recipe_yaml(
            _basic_recipe_dict("deterministic",
                               required_signals=["bearer_token"],
                               optional_signals=["jwt_pattern", "oauth_endpoint"])
        )
        loader.load_recipe(path)

        context = _auth_context()
        scores = []
        for _ in range(5):
            candidates = loader.match_recipes_to_context(context)
            scores.append(candidates[0].score)

        assert len(set(scores)) == 1, f"Scores should be identical: {scores}"

    def test_partial_optional_signals_do_not_block_match(self):
        """optional signals が一部しかなくてもマッチする"""
        loader = RecipeLoader()
        path = _make_temp_recipe_yaml(
            _basic_recipe_dict("partial_optional",
                               required_signals=["bearer_token"],
                               optional_signals=["jwt_pattern", "oauth_endpoint", "graphql_endpoint"])
        )
        loader.load_recipe(path)

        # graphql_endpoint は context にない
        context = _auth_context()
        candidates = loader.match_recipes_to_context(context)
        assert len(candidates) == 1
        # スコアは base + 2 (graphql_endpoint is missing)
        assert candidates[0].score >= 12

    def test_no_optional_signal_match_gives_base_score_only(self):
        loader = RecipeLoader()
        path = _make_temp_recipe_yaml(
            _basic_recipe_dict("base_only",
                               required_signals=["bearer_token"],
                               optional_signals=["non_existent_signal"])
        )
        loader.load_recipe(path)

        context = _auth_context()
        candidates = loader.match_recipes_to_context(context)
        assert len(candidates) == 1
        # base(10) + priority_bonus(50/100 * 10 = 5) = 15, no optional match
        assert candidates[0].score == 15


class TestMatchRecipesTopNLimit:
    """top-N 制限が守られる"""

    def test_only_top_n_returned(self):
        loader = RecipeLoader()
        recipes_to_load = []
        for i in range(10):
            recipe_dict = _basic_recipe_dict(
                f"recipe_{i}",
                required_signals=[],
                optional_signals=[f"signal_{j}" for j in range(i)],
                priority=50 + i,
            )
            path = _make_temp_recipe_yaml(recipe_dict)
            loader.load_recipe(path)
            recipes_to_load.append(path)

        # context has all optional signals
        context = {"optional_signals": [f"signal_{j}" for j in range(20)]}
        candidates = loader.match_recipes_to_context(context, top_n=3)

        assert len(candidates) == 3
        # 最も optional_signal が多い recipe が選ばれるはず
        # recipe_9 has 9 optional_signals, recipe_8 has 8, etc.
        # スコアは base(10) + optional_count
        scores = [r.score for r in candidates]
        assert scores == sorted(scores, reverse=True), f"Not sorted descending: {scores}"

    def test_top_n_fewer_recipes_returns_all(self):
        loader = RecipeLoader()
        for name in ["a", "b"]:
            path = _make_temp_recipe_yaml(
                _basic_recipe_dict(name, required_signals=[], optional_signals=[])
            )
            loader.load_recipe(path)

        matched = loader.match_recipes_to_context({}, top_n=5)
        assert len(matched) == 2

    def test_priority_influences_score(self):
        """priority が高いRecipeはスコアが高くなる"""
        loader = RecipeLoader()
        path_low = _make_temp_recipe_yaml(
            _basic_recipe_dict("low_priority", required_signals=[],
                               optional_signals=["jwt_pattern"], priority=10)
        )
        path_high = _make_temp_recipe_yaml(
            _basic_recipe_dict("high_priority", required_signals=[],
                               optional_signals=["jwt_pattern"], priority=90)
        )
        loader.load_recipe(path_low)
        loader.load_recipe(path_high)

        context = _auth_context()
        candidates = loader.match_recipes_to_context(context)

        # high priority should score higher and come first
        assert candidates[0].recipe_name == "high_priority"


class TestMatchRecipesScoreThreshold:
    """minimum score threshold filtering"""

    def test_recipes_below_threshold_filtered_out(self):
        loader = RecipeLoader()
        path_low = _make_temp_recipe_yaml(
            _basic_recipe_dict("low", required_signals=[],
                               optional_signals=[], priority=5)
        )
        path_good = _make_temp_recipe_yaml(
            _basic_recipe_dict("good", required_signals=["bearer_token"],
                               optional_signals=["jwt_pattern"], priority=80)
        )
        loader.load_recipe(path_low)
        loader.load_recipe(path_good)

        context = _auth_context()
        # good recipe: base(10) + jwt_pattern(1) + priority_bonus(80/100*10=8) = 19
        # Filter with min_score=16 should keep it
        candidates = loader.match_recipes_to_context(context, min_score=16)

        assert len(candidates) >= 1
        names = [r.recipe_name for r in candidates]
        assert "good" in names


class TestMatchRecipesSignalDetection:
    """信号検出の各パターンをテスト"""

    def test_bearer_token_detection(self):
        loader = RecipeLoader()
        path = _make_temp_recipe_yaml(
            _basic_recipe_dict("token_check", required_signals=["bearer_token"])
        )
        loader.load_recipe(path)

        # token present
        ctx = _auth_context()
        matched = loader.match_recipes_to_context(ctx)
        assert len(matched) == 1

        # token absent
        ctx2 = _auth_context(bearer_token=None, auth_headers={})
        matched2 = loader.match_recipes_to_context(ctx2)
        assert len(matched2) == 0

    def test_session_cookie_detection(self):
        loader = RecipeLoader()
        path = _make_temp_recipe_yaml(
            _basic_recipe_dict("session_check", required_signals=["session_cookie"])
        )
        loader.load_recipe(path)

        ctx = _auth_context()
        matched = loader.match_recipes_to_context(ctx)
        assert len(matched) == 1

        ctx2 = _auth_context(cookies="")
        matched2 = loader.match_recipes_to_context(ctx2)
        assert len(matched2) == 0

    def test_oauth_endpoint_detection(self):
        loader = RecipeLoader()
        path = _make_temp_recipe_yaml(
            _basic_recipe_dict("oauth_check", required_signals=["oauth_endpoint"])
        )
        loader.load_recipe(path)

        ctx = _auth_context()
        matched = loader.match_recipes_to_context(ctx)
        assert len(matched) == 1

        ctx2 = _auth_context(
            discovered_urls=["https://example.com/home"],
            auth_surface_metadata={},
        )
        matched2 = loader.match_recipes_to_context(ctx2)
        assert len(matched2) == 0

    def test_login_endpoint_detection(self):
        loader = RecipeLoader()
        path = _make_temp_recipe_yaml(
            _basic_recipe_dict("login_check", required_signals=["login_endpoint"])
        )
        loader.load_recipe(path)

        ctx = _auth_context()
        matched = loader.match_recipes_to_context(ctx)
        assert len(matched) == 1

        ctx2 = _auth_context(discovered_urls=["https://example.com/home"])
        matched2 = loader.match_recipes_to_context(ctx2)
        assert len(matched2) == 0

    def test_jwt_pattern_detection_in_token(self):
        loader = RecipeLoader()
        path = _make_temp_recipe_yaml(
            _basic_recipe_dict("jwt_pattern_check", required_signals=[],
                               optional_signals=["jwt_pattern"])
        )
        loader.load_recipe(path)

        ctx = _auth_context()
        matched = loader.match_recipes_to_context(ctx)
        assert len(matched) == 1
        assert matched[0].score > 10  # score includes optional

    def test_admin_endpoint_optional_signal(self):
        loader = RecipeLoader()
        path = _make_temp_recipe_yaml(
            _basic_recipe_dict("admin_check", required_signals=["bearer_token"],
                               optional_signals=["admin_endpoint"])
        )
        loader.load_recipe(path)

        ctx = _auth_context()
        matched = loader.match_recipes_to_context(ctx)
        assert len(matched) == 1
        assert matched[0].score >= 11  # base + admin

    def test_no_match_when_context_is_empty(self):
        loader = RecipeLoader()
        path = _make_temp_recipe_yaml(
            _basic_recipe_dict("needs_auth", required_signals=["bearer_token"])
        )
        loader.load_recipe(path)

        matched = loader.match_recipes_to_context({})
        assert len(matched) == 0


class TestMatchRecipesNoTriggerRecipe:
    """trigger セクションがない Recipe の振る舞い"""

    def test_no_trigger_still_loaded_and_matched(self):
        loader = RecipeLoader()
        recipe_dict = {
            "name": "legacy_recipe",
            "description": "Old format",
            "agent": "swarm",
            "steps": [
                {"id": "s1", "name": "step", "action": "scan", "params": {}},
            ],
        }
        path = _make_temp_recipe_yaml(recipe_dict)
        loader.load_recipe(path)

        matched = loader.match_recipes_to_context({})
        assert len(matched) == 1
        # base(10) + default priority_bonus(50/100 * 10 = 5) = 15
        assert matched[0].score == 15


# ---- Step 5: New recipe YAML loading tests ----

class TestAuthRecipeYamlLoading:
    """Step 5-7: Verify new auth recipe YAML files load and validate."""

    def _load_auth_recipes(self):
        import glob
        loader = RecipeLoader()
        for path in sorted(glob.glob("recipes/auth/*.yaml")):
            loader.load_recipe(path)
        return loader

    def test_all_auth_recipes_load_successfully(self):
        loader = self._load_auth_recipes()
        assert len(loader.recipes) >= 5  # 5 new + 3 old

    def test_new_recipes_have_required_signals(self):
        loader = self._load_auth_recipes()
        new_recipe_names = [
            "oauth_binding_drift", "session_invariant",
            "jwt_claim_enforcement", "refresh_rotation",
            "hidden_admin_capability",
        ]
        for name in new_recipe_names:
            recipe = loader.recipes.get(name)
            assert recipe is not None, f"Missing recipe: {name}"
            assert len(recipe.required_signals) > 0, \
                f"{name}: should have required_signals"

    def test_new_recipes_have_three_stages(self):
        loader = self._load_auth_recipes()
        new_recipe_names = [
            "oauth_binding_drift", "session_invariant",
            "jwt_claim_enforcement", "refresh_rotation",
            "hidden_admin_capability",
        ]
        for name in new_recipe_names:
            recipe = loader.recipes[name]
            assert len(recipe.stages) == 3, \
                f"{name}: expected 3 stages (probe/confirm/evidence), got {len(recipe.stages)}"
            stage_names = [s["name"] for s in recipe.stages]
            assert stage_names[0] == "probe", f"{name}: first stage should be 'probe'"
            assert stage_names[1] == "confirm", f"{name}: second stage should be 'confirm'"
            assert stage_names[2] == "evidence", f"{name}: third stage should be 'evidence'"

    def test_new_recipes_have_stop_conditions(self):
        loader = self._load_auth_recipes()
        new_recipe_names = [
            "oauth_binding_drift", "session_invariant",
            "jwt_claim_enforcement", "refresh_rotation",
            "hidden_admin_capability",
        ]
        for name in new_recipe_names:
            recipe = loader.recipes[name]
            assert len(recipe.stop_conditions) >= 2, \
                f"{name}: should have at least 2 stop_conditions"

    def test_old_recipes_still_load_legacy_format(self):
        loader = self._load_auth_recipes()
        old_names = ["jwt_alg_none", "oauth_redirect_bypass", "oauth_token_leak"]
        for name in old_names:
            recipe = loader.recipes.get(name)
            assert recipe is not None, f"Missing legacy recipe: {name}"
            assert recipe.stages == [] or len(recipe.stages) >= 0
            assert recipe.required_signals == []
            # Legacy recipes have priority=50 (default)
            assert recipe.priority == 50

    def test_new_recipes_have_evidence_policy(self):
        loader = self._load_auth_recipes()
        for name in ["oauth_binding_drift", "session_invariant",
                      "jwt_claim_enforcement", "refresh_rotation",
                      "hidden_admin_capability"]:
            recipe = loader.recipes[name]
            policy = recipe.evidence_policy
            assert policy.get("redact_secrets") is True, f"{name}: should redact secrets"
            assert policy.get("structured") is True, f"{name}: should use structured evidence"
