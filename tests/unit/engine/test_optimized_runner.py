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


# ---- Step 4: Stage-aware execution tests (TDD) ----

class TestStageAwareExecution:
    """Step 4: Verify probe -> confirm -> evidence stage progression."""

    @pytest.mark.asyncio
    async def test_proceeds_to_confirm_when_probe_succeeds(self):
        """probe 段階が成功すると confirm 段階に進む"""
        steps = [
            RecipeStep(id="probe_1", name="Check token", action="scan", params={}),
            RecipeStep(id="confirm_1", name="Verify drift", action="scan", params={}),
        ]
        stages = [
            {"name": "probe", "steps": ["probe_1"], "min_success": 1},
            {"name": "confirm", "steps": ["confirm_1"], "min_success": 1},
        ]
        recipe = Recipe(
            name="stage_test",
            description="Stage progression test",
            agent="swarm",
            steps=steps,
            stages=stages,
        )

        async def _executor(step, target):
            return {"status": "success", "reason": "ok", "data": {"step": step.id}}

        runner = OptimizedRecipeRunner(max_workers=2, step_executor=_executor)
        result = await runner.run_recipe(recipe, target="example.com")

        assert result["success"] is True
        assert "probe_1" in result["steps"]
        assert "confirm_1" in result["steps"]
        assert result["steps"]["probe_1"]["status"] == "success"
        assert result["steps"]["confirm_1"]["status"] == "success"
        # Stage verdicts
        stages_out = result.get("stages", {})
        assert stages_out.get("probe", {}).get("verdict") == "passed"
        assert stages_out.get("confirm", {}).get("verdict") == "passed"

    @pytest.mark.asyncio
    async def test_does_not_proceed_when_probe_fails(self):
        """probe 段階が失敗すると confirm 段階に進まない"""
        steps = [
            RecipeStep(id="probe_1", name="Check token", action="scan", params={}),
            RecipeStep(id="confirm_1", name="Verify drift", action="scan", params={}),
        ]
        stages = [
            {"name": "probe", "steps": ["probe_1"], "min_success": 1},
            {"name": "confirm", "steps": ["confirm_1"], "min_success": 1},
        ]
        recipe = Recipe(
            name="stage_fail_test",
            description="Stage fail test",
            agent="swarm",
            steps=steps,
            stages=stages,
        )

        async def _executor(step, target):
            if step.id == "probe_1":
                return {"status": "failed", "reason": "no_token", "error_code": "AUTH_MISSING"}
            return {"status": "success", "reason": "ok"}

        runner = OptimizedRecipeRunner(max_workers=2, step_executor=_executor)
        result = await runner.run_recipe(recipe, target="example.com")

        # Probe failed → confirm should NOT execute
        assert "probe_1" in result["steps"]
        assert result["steps"]["probe_1"]["status"] == "failed"
        assert "confirm_1" not in result["steps"]  # never reached
        stages_out = result.get("stages", {})
        assert stages_out.get("probe", {}).get("verdict") == "failed"
        assert "confirm" not in stages_out  # never started

    @pytest.mark.asyncio
    async def test_min_success_threshold_not_met_blocks_next_stage(self):
        """min_success に達しない場合、次段階に進まない"""
        steps = [
            RecipeStep(id="probe_1", name="Probe 1", action="scan", params={}),
            RecipeStep(id="probe_2", name="Probe 2", action="scan", params={}),
            RecipeStep(id="confirm_1", name="Confirm 1", action="scan", params={}),
        ]
        stages = [
            {"name": "probe", "steps": ["probe_1", "probe_2"], "min_success": 2},
            {"name": "confirm", "steps": ["confirm_1"], "min_success": 1},
        ]
        recipe = Recipe(
            name="threshold_test",
            description="Threshold test",
            agent="swarm",
            steps=steps,
            stages=stages,
        )

        async def _executor(step, target):
            if step.id == "probe_2":
                return {"status": "failed", "reason": "network_error"}
            return {"status": "success", "reason": "ok"}

        runner = OptimizedRecipeRunner(max_workers=2, step_executor=_executor)
        result = await runner.run_recipe(recipe, target="example.com")

        # Only 1 of 2 probes succeeded, min_success=2 → confirm not reached
        assert "confirm_1" not in result["steps"]
        stages_out = result.get("stages", {})
        assert stages_out.get("probe", {}).get("verdict") == "failed"

    @pytest.mark.asyncio
    async def test_no_stages_runs_all_steps_as_before(self):
        """stages が未定義の Recipe は既存通り全ステップを実行する"""
        steps = [
            RecipeStep(id="s1", name="Step 1", action="scan", params={}),
            RecipeStep(id="s2", name="Step 2", action="scan", params={}),
        ]
        recipe = Recipe(name="no_stages", description="No stages", agent="swarm", steps=steps)

        async def _executor(step, target):
            return {"status": "success", "reason": "ok"}

        runner = OptimizedRecipeRunner(max_workers=2, step_executor=_executor)
        result = await runner.run_recipe(recipe, target="example.com")

        assert "s1" in result["steps"]
        assert "s2" in result["steps"]
        assert result["steps"]["s1"]["status"] == "success"

    @pytest.mark.asyncio
    async def test_three_stage_probe_confirm_evidence(self):
        """probe -> confirm -> evidence の3段階が順次実行される"""
        steps = [
            RecipeStep(id="p1", name="Probe token", action="scan", params={}),
            RecipeStep(id="c1", name="Confirm drift", action="scan", params={}),
            RecipeStep(id="e1", name="Collect evidence", action="report", params={}),
        ]
        stages = [
            {"name": "probe", "steps": ["p1"], "min_success": 1},
            {"name": "confirm", "steps": ["c1"], "min_success": 1},
            {"name": "evidence", "steps": ["e1"], "min_success": 1},
        ]
        recipe = Recipe(
            name="full_pipeline",
            description="Probe->Confirm->Evidence",
            agent="swarm",
            steps=steps,
            stages=stages,
        )

        async def _executor(step, target):
            return {"status": "success", "reason": "ok", "data": {"step_id": step.id}}

        runner = OptimizedRecipeRunner(max_workers=2, step_executor=_executor)
        result = await runner.run_recipe(recipe, target="example.com")

        assert result["success"] is True
        assert "p1" in result["steps"]
        assert "c1" in result["steps"]
        assert "e1" in result["steps"]
        stages_out = result["stages"]
        assert stages_out["probe"]["verdict"] == "passed"
        assert stages_out["confirm"]["verdict"] == "passed"
        assert stages_out["evidence"]["verdict"] == "passed"


class TestEvidenceAggregation:
    """Step 4: Verify structured evidence aggregation per step and stage."""

    @pytest.mark.asyncio
    async def test_evidence_collected_per_step(self):
        """各ステップの結果に evidence が含まれる"""
        steps = [
            RecipeStep(id="s1", name="Check token", action="scan", params={}),
        ]
        recipe = Recipe(
            name="evidence_test",
            description="Evidence collection",
            agent="swarm",
            steps=steps,
            stages=[
                {"name": "probe", "steps": ["s1"], "min_success": 1},
                {"name": "confirm", "steps": ["s1"], "min_success": 1},
            ],
            evidence_policy={"max_items": 10, "redact_secrets": True},
        )

        async def _executor(step, target):
            return {
                "status": "success",
                "reason": "token_accepted",
                "data": {
                    "response_code": 200,
                    "body_preview": "{\"role\":\"admin\"}",
                },
                "evidence": {
                    "type": "token_drift",
                    "observation": "old token still valid after rotation",
                    "severity": "high",
                },
            }

        runner = OptimizedRecipeRunner(max_workers=2, step_executor=_executor)
        result = await runner.run_recipe(recipe, target="example.com")

        step_result = result["steps"]["s1"]
        assert "evidence" in step_result
        assert step_result["evidence"]["type"] == "token_drift"
        # evidence_policy is reflected
        assert result.get("evidence_policy", {}).get("redact_secrets") is True

    @pytest.mark.asyncio
    async def test_stage_level_evidence_aggregation(self):
        """段階ごとに evidence が集約される"""
        steps = [
            RecipeStep(id="p1", name="Probe", action="scan", params={}),
            RecipeStep(id="p2", name="Probe2", action="scan", params={}),
            RecipeStep(id="c1", name="Confirm", action="scan", params={}),
        ]
        stages = [
            {"name": "probe", "steps": ["p1", "p2"], "min_success": 1},
            {"name": "confirm", "steps": ["c1"], "min_success": 1},
        ]
        recipe = Recipe(
            name="stage_evidence",
            description="Stage evidence",
            agent="swarm",
            steps=steps,
            stages=stages,
        )

        async def _executor(step, target):
            return {
                "status": "success",
                "reason": "ok",
                "evidence": {"step": step.id, "finding": f"finding_from_{step.id}"},
            }

        runner = OptimizedRecipeRunner(max_workers=2, step_executor=_executor)
        result = await runner.run_recipe(recipe, target="example.com")

        stages_out = result["stages"]
        # Stage-level evidence collection
        probe_stage = stages_out["probe"]
        assert "evidence" in probe_stage
        assert len(probe_stage["evidence"]) == 2  # p1 and p2
        evidence_steps = [e.get("step") for e in probe_stage["evidence"]]
        assert "p1" in evidence_steps
        assert "p2" in evidence_steps

    @pytest.mark.asyncio
    async def test_weak_signal_no_confirmed_verdict(self):
        """weak signal だけでは confirmed 判定にならない"""
        steps = [
            RecipeStep(id="p1", name="Weak probe", action="scan", params={}),
            RecipeStep(id="c1", name="Confirm", action="scan", params={}),
            RecipeStep(id="e1", name="Evidence", action="report", params={}),
        ]
        stages = [
            {"name": "probe", "steps": ["p1"], "min_success": 1},
            {"name": "confirm", "steps": ["c1"], "min_success": 1},
            {"name": "evidence", "steps": ["e1"], "min_success": 1},
        ]
        recipe = Recipe(
            name="weak_signal_test",
            description="Weak signal",
            agent="swarm",
            steps=steps,
            stages=stages,
            success_signals=[{"type": "status_2xx", "on": "admin_endpoint"}],
        )

        async def _executor(step, target):
            if step.id == "c1":
                # Confirm returns weak/ambiguous signal
                return {
                    "status": "success",
                    "reason": "ambiguous_response",
                    "evidence": {
                        "type": "weak_signal",
                        "confidence": "low",
                        "observation": "response differs but may be benign",
                    },
                }
            return {"status": "success", "reason": "ok", "evidence": {"type": "info"}}

        runner = OptimizedRecipeRunner(max_workers=2, step_executor=_executor)
        result = await runner.run_recipe(recipe, target="example.com")

        # Overall verdict should NOT be "confirmed" when evidence is weak
        verdict = result.get("verdict", "")
        assert verdict != "confirmed"
        assert verdict in {"draft", "no_signal", "inconclusive"}


class TestStopConditions:
    """Step 4: Verify stop conditions halt execution."""

    @pytest.mark.asyncio
    async def test_stop_condition_rate_limit_stops_execution(self):
        """rate_limit 発生時に後続ステップを停止する"""
        steps = [
            RecipeStep(id="p1", name="Probe", action="scan", params={}),
            RecipeStep(id="p2", name="Probe2", action="scan", params={}),
            RecipeStep(id="c1", name="Confirm", action="scan", params={}),
        ]
        stages = [
            {"name": "probe", "steps": ["p1", "p2"], "min_success": 1},
            {"name": "confirm", "steps": ["c1"], "min_success": 1},
        ]
        recipe = Recipe(
            name="stop_test",
            description="Stop condition test",
            agent="swarm",
            steps=steps,
            stages=stages,
            stop_conditions=["rate_limit", "waf_block"],
        )

        async def _executor(step, target):
            if step.id == "p1":
                return {
                    "status": "failed",
                    "reason": "rate_limited",
                    "error_code": "RATE_LIMIT",
                    "stop_reason": "rate_limit",
                }
            return {"status": "success", "reason": "ok"}

        runner = OptimizedRecipeRunner(max_workers=2, step_executor=_executor)
        result = await runner.run_recipe(recipe, target="example.com")

        # p1 hit rate_limit → execution should stop
        assert result["steps"]["p1"]["status"] == "failed"
        assert result.get("stop_reason") == "rate_limit"
        # p2 and c1 should not execute since p1=rate_limit stopped the stage
        # (p2 may or may not execute depending on parallel scheduling,
        #  but confirm stage should definitely not start)
        assert "confirm" not in result.get("stages", {})

    @pytest.mark.asyncio
    async def test_waf_block_stop_condition(self):
        """WAF block が stop condition に指定されている場合、ブロック時に停止"""
        steps = [
            RecipeStep(id="p1", name="Probe", action="scan", params={}),
            RecipeStep(id="c1", name="Confirm", action="scan", params={}),
        ]
        stages = [
            {"name": "probe", "steps": ["p1"], "min_success": 1},
            {"name": "confirm", "steps": ["c1"], "min_success": 1},
        ]
        recipe = Recipe(
            name="waf_test",
            description="WAF stop test",
            agent="swarm",
            steps=steps,
            stages=stages,
            stop_conditions=["waf_block", "rate_limit"],
        )

        async def _executor(step, target):
            return {
                "status": "blocked",
                "reason": "WAF_block_detected",
                "error_code": "WAF_BLOCK",
                "stop_reason": "waf_block",
            }

        runner = OptimizedRecipeRunner(max_workers=2, step_executor=_executor)
        result = await runner.run_recipe(recipe, target="example.com")

        assert result.get("stop_reason") == "waf_block"
        assert "confirm" not in result.get("stages", {})

    @pytest.mark.asyncio
    async def test_no_stop_conditions_runs_normally(self):
        """stop_conditions が空の Recipe は通常通り全段階を実行"""
        steps = [
            RecipeStep(id="p1", name="Probe", action="scan", params={}),
            RecipeStep(id="c1", name="Confirm", action="scan", params={}),
        ]
        stages = [
            {"name": "probe", "steps": ["p1"], "min_success": 1},
            {"name": "confirm", "steps": ["c1"], "min_success": 1},
        ]
        recipe = Recipe(
            name="no_stop",
            description="No stop conditions",
            agent="swarm",
            steps=steps,
            stages=stages,
            stop_conditions=[],  # empty
        )

        async def _executor(step, target):
            return {"status": "success", "reason": "ok"}

        runner = OptimizedRecipeRunner(max_workers=2, step_executor=_executor)
        result = await runner.run_recipe(recipe, target="example.com")

        assert result["success"] is True
        assert "p1" in result["steps"]
        assert "c1" in result["steps"]


class TestVerdictClassification:
    """Step 4: Verify verdict classification based on evidence density."""

    @pytest.mark.asyncio
    async def test_strong_evidence_yields_confirmed_verdict(self):
        """十分な evidence があると confirmed 判定"""
        steps = [
            RecipeStep(id="p1", name="Probe", action="scan", params={}),
            RecipeStep(id="c1", name="Confirm", action="scan", params={}),
            RecipeStep(id="e1", name="Evidence", action="report", params={}),
        ]
        stages = [
            {"name": "probe", "steps": ["p1"], "min_success": 1},
            {"name": "confirm", "steps": ["c1"], "min_success": 1},
            {"name": "evidence", "steps": ["e1"], "min_success": 1},
        ]
        recipe = Recipe(
            name="strong_evidence",
            description="Strong evidence",
            agent="swarm",
            steps=steps,
            stages=stages,
        )

        async def _executor(step, target):
            return {
                "status": "success",
                "reason": "confirmed_finding",
                "evidence": {
                    "type": "token_drift",
                    "confidence": "high",
                    "observation": "refresh token reuse confirmed; old token grants access after rotation",
                    "reproducible": True,
                },
            }

        runner = OptimizedRecipeRunner(max_workers=2, step_executor=_executor)
        result = await runner.run_recipe(recipe, target="example.com")

        assert result["success"] is True
        verdict = result.get("verdict", "")
        assert verdict == "confirmed"

    @pytest.mark.asyncio
    async def test_single_weak_evidence_not_confirmed(self):
        """単一の弱い差分だけでは confirmed に昇格しない (計画書 5. risk: 単一差分のみでは昇格しない)"""
        steps = [
            RecipeStep(id="p1", name="Probe", action="scan", params={}),
            RecipeStep(id="e1", name="Evidence", action="report", params={}),
        ]
        stages = [
            {"name": "probe", "steps": ["p1"], "min_success": 1},
            {"name": "evidence", "steps": ["e1"], "min_success": 1},
        ]
        recipe = Recipe(
            name="single_weak",
            description="Single weak evidence",
            agent="swarm",
            steps=steps,
            stages=stages,
        )

        async def _executor(step, target):
            return {
                "status": "success",
                "reason": "slight_diff",
                "evidence": {
                    "type": "minor_diff",
                    "confidence": "low",
                    "observation": "response time differed by 50ms",
                    "reproducible": False,
                },
            }

        runner = OptimizedRecipeRunner(max_workers=2, step_executor=_executor)
        result = await runner.run_recipe(recipe, target="example.com")

        verdict = result.get("verdict", "")
        assert verdict != "confirmed"
        assert verdict in {"draft", "no_signal", "inconclusive"}
