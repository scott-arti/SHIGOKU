import pytest
from src.core.engine.recipe_loader import Recipe, RecipeStep
from src.core.engine.optimized_runner import OptimizedRecipeRunner

@pytest.mark.asyncio
async def test_optimized_runner_dag_execution():
    # 1. 依存関係のあるレシピを作成
    # step_0 -> step_1
    # step_0 -> step_2
    # step_1, step_2 -> step_3
    steps = [
        RecipeStep(id="step_0", name="Start", action="recon"),
        RecipeStep(id="step_1", name="Scan A", action="scan", dependencies=["step_0"]),
        RecipeStep(id="step_2", name="Scan B", action="scan", dependencies=["step_0"]),
        RecipeStep(id="step_3", name="Report", action="report", dependencies=["step_1", "step_2"]),
    ]
    recipe = Recipe(name="Test DAG", description="Test", agent="test", steps=steps)
    
    async def _executor(step, target):
        return {"status": "success", "reason": "ok", "data": {"target": target, "action": step.action}}

    runner = OptimizedRecipeRunner(max_workers=2, step_executor=_executor)
    
    # 2. 実行
    result_bundle = await runner.run_recipe(recipe, target="example.com")
    steps_result = result_bundle["steps"]
    
    # 3. 検証
    assert result_bundle["success"] is True
    assert result_bundle["summary"]["total_steps"] == 4
    assert "step_0" in steps_result
    assert "step_1" in steps_result
    assert "step_2" in steps_result
    assert "step_3" in steps_result
    assert all(v["status"] == "success" for v in steps_result.values())
    
    # 実行順序の論理的整合性はログなどで確認するが、
    # ここでは例外なく完了することを確認。
    print(f"Results: {result_bundle}")

@pytest.mark.asyncio
async def test_optimized_runner_cycle_detection():
    # 循環参照のあるレシピ
    steps = [
        RecipeStep(id="step_0", name="A", action="test", dependencies=["step_1"]),
        RecipeStep(id="step_1", name="B", action="test", dependencies=["step_0"]),
    ]
    recipe = Recipe(name="Cycle", description="Cycle", agent="test", steps=steps)
    
    runner = OptimizedRecipeRunner()
    
    with pytest.raises(ValueError, match="contains a cycle"):
        await runner.run_recipe(recipe, target="example.com")


@pytest.mark.asyncio
async def test_optimized_runner_unsupported_action_fails_fast():
    steps = [
        RecipeStep(id="step_0", name="Unsupported", action="definitely_not_supported"),
    ]
    recipe = Recipe(name="Unsupported Action", description="Test", agent="test", steps=steps)
    runner = OptimizedRecipeRunner(step_executor=None)

    result_bundle = await runner.run_recipe(recipe, target="example.com")
    step = result_bundle["steps"]["step_0"]
    assert result_bundle["success"] is False
    assert step["status"] == "failed"
    assert step["error_code"] == "UNSUPPORTED_ACTION"


# ── SGK-2026-0259: auth recipe execution ──────────────────────────────

@pytest.mark.asyncio
async def test_auth_recipe_probe_confirm_evidence_dag_execution():
    """3-step auth recipe (probe→confirm→evidence DAG), all succeed → success."""
    steps = [
        RecipeStep(id="probe", name="Probe Auth", action="auth_attack"),
        RecipeStep(id="confirm", name="Confirm Vulnerability", action="scan", dependencies=["probe"]),
        RecipeStep(id="evidence", name="Collect Evidence", action="report", dependencies=["confirm"]),
    ]
    recipe = Recipe(
        name="session_invariant",
        description="Auth recipe DAG execution",
        agent="swarm",
        steps=steps,
    )

    async def _executor(step, target):
        return {"status": "success", "reason": "ok", "data": {"target": target, "action": step.action}}

    runner = OptimizedRecipeRunner(max_workers=2, step_executor=_executor)
    result_bundle = await runner.run_recipe(recipe, target="https://app.example.com/login")

    assert result_bundle["success"] is True
    assert result_bundle["summary"]["total_steps"] == 3
    assert result_bundle["summary"]["success_count"] == 3
    steps_result = result_bundle["steps"]
    assert all(v["status"] == "success" for v in steps_result.values())
    assert "probe" in steps_result
    assert "confirm" in steps_result
    assert "evidence" in steps_result


@pytest.mark.asyncio
async def test_auth_recipe_stops_at_confirm_failure():
    """Auth recipe where the only step fails → overall False, failed count > 0."""
    steps = [
        RecipeStep(id="confirm", name="Confirm Auth Vulnerability", action="auth_attack"),
    ]
    recipe = Recipe(
        name="jwt_alg_none",
        description="Auth recipe — all steps fail",
        agent="swarm",
        steps=steps,
    )

    async def _executor(step, target):
        return {"status": "failed", "reason": "jwt_alg_none_confirmed", "error_code": "JWT_ALG_NONE"}

    runner = OptimizedRecipeRunner(step_executor=_executor)
    result_bundle = await runner.run_recipe(recipe, target="https://app.example.com/api")

    assert result_bundle["success"] is False
    assert result_bundle["summary"]["failed_steps"] > 0


@pytest.mark.asyncio
async def test_auth_recipe_unsupported_action_fails_fast():
    """Auth recipe step with action alg_none (not in allowlist) → UNSUPPORTED_ACTION."""
    steps = [
        RecipeStep(id="alg_check", name="Algorithm None Check", action="alg_none"),
    ]
    recipe = Recipe(
        name="jwt_alg_none",
        description="Auth recipe with unsupported step action",
        agent="swarm",
        steps=steps,
    )
    runner = OptimizedRecipeRunner(step_executor=None)
    result_bundle = await runner.run_recipe(recipe, target="https://app.example.com/api")

    assert result_bundle["success"] is False
    step = result_bundle["steps"]["alg_check"]
    assert step["status"] == "failed"
    assert step["error_code"] == "UNSUPPORTED_ACTION"
