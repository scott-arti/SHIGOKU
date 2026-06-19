import asyncio
import logging
import json
from typing import Dict, Any, List, Set, Awaitable, Callable, Optional, Tuple
import networkx as nx

from src.core.engine.recipe_loader import Recipe, RecipeStep
from src.core.engine.recipe_contracts import ALLOWED_RECIPE_STEP_ACTIONS
from src.core.security.ethics_guard import EthicsGuard

logger = logging.getLogger(__name__)


StepExecutor = Callable[[RecipeStep, str], Awaitable[Dict[str, Any]]]


class OptimizedRecipeRunner:
    """
    DAGベースの最適化されたレシピ実行エンジン。
    依存関係を解析し、非同期かつ並列にステップを実行します。

    Step 4: stage-aware execution (probe -> confirm -> evidence).
    """
    ALLOWED_ACTIONS = ALLOWED_RECIPE_STEP_ACTIONS

    # Verdict constants
    VERDICT_CONFIRMED = "confirmed"
    VERDICT_DRAFT = "draft"
    VERDICT_NO_SIGNAL = "no_signal"
    VERDICT_INCONCLUSIVE = "inconclusive"

    def __init__(self, max_workers: int = 8, step_executor: Optional[StepExecutor] = None):
        self.max_workers = max_workers
        self.semaphore = asyncio.Semaphore(max_workers)
        self._tool_cache: Dict[str, Any] = {}
        self.ethics_guard = EthicsGuard()
        self._step_executor = step_executor
        self._results: Dict[str, Dict[str, Any]] = {}
        self._stop_reason: Optional[str] = None
        self._stage_results: Dict[str, Dict[str, Any]] = {}

    async def run_recipe(self, recipe: Recipe, target: str) -> Dict[str, Any]:
        """
        レシピを解析し、依存関係に従って実行。
        stages が定義されている場合、stage-aware execution を使用。
        """
        self._results = {}
        self._stop_reason = None
        self._stage_results = {}

        # Step 4: If stages are defined, use stage-aware execution
        if recipe.stages:
            return await self._run_staged_recipe(recipe, target)

        # Legacy: DAG-based execution (no stages)
        return await self._run_dag_recipe(recipe, target)

    async def _run_dag_recipe(self, recipe: Recipe, target: str) -> Dict[str, Any]:
        """既存のDAGベース実行 (stages 未定義時の legacy path)"""
        dag = self._build_dag(recipe)

        if not nx.is_directed_acyclic_graph(dag):
            raise ValueError(f"Recipe '{recipe.name}' contains a cycle in dependencies.")

        pending_tasks = set(dag.nodes)
        running_tasks: Set[asyncio.Task] = set()
        completed_tasks: Set[str] = set()

        while pending_tasks or running_tasks:
            ready_tasks = [
                node for node in pending_tasks
                if all(dep in completed_tasks for dep in dag.predecessors(node))
            ]

            for node in ready_tasks:
                step = dag.nodes[node]["step"]
                task = asyncio.create_task(self._execute_step_with_semaphore(step, target))
                task.node_id = node
                running_tasks.add(task)
                pending_tasks.remove(node)

            if not running_tasks:
                if pending_tasks:
                    raise RuntimeError("Deadlock detected in recipe execution.")
                break

            done, running_tasks = await asyncio.wait(
                running_tasks, return_when=asyncio.FIRST_COMPLETED
            )

            for task in done:
                try:
                    result = await task
                    node_id = getattr(task, "node_id")
                    self._results[node_id] = result
                    completed_tasks.add(node_id)
                except Exception as e:
                    logger.error(f"Step failed: {e}")

        return self._finalize_results(recipe)

    async def _run_staged_recipe(self, recipe: Recipe, target: str) -> Dict[str, Any]:
        """Step 4: Stage-aware execution.

        Progresses through stages (probe -> confirm -> evidence).
        Each stage only executes if the previous stage met its min_success threshold.
        Stop conditions are checked and halt execution.
        """
        stop_conditions = set(recipe.stop_conditions or [])

        for stage_def in recipe.stages:
            if self._stop_reason:
                break

            stage_name = stage_def.get("name", f"stage_{len(self._stage_results)}")
            stage_step_ids = stage_def.get("steps", [])
            min_success = int(stage_def.get("min_success", 1) or 1)

            # Filter steps that belong to this stage
            stage_steps = [s for s in recipe.steps if s.id in stage_step_ids]
            if not stage_steps:
                logger.warning("Stage '%s' has no matching steps, skipping.", stage_name)
                continue

            # Build DAG for this stage's steps only
            stage_dag = self._build_stage_dag(stage_steps)

            # Execute stage steps
            stage_step_results = await self._execute_stage_steps(
                stage_dag, target, stop_conditions
            )

            # Collect evidence for this stage
            stage_evidence = self._collect_stage_evidence(stage_step_results)

            # Count successes
            successes = sum(
                1 for r in stage_step_results.values()
                if r.get("status") == "success"
            )

            # Check stop conditions
            for r in stage_step_results.values():
                stop_reason = r.get("stop_reason") or ""
                error_code = r.get("error_code") or ""
                if stop_reason and stop_reason in stop_conditions:
                    self._stop_reason = stop_reason
                    break
                if error_code in {"RATE_LIMIT", "WAF_BLOCK"}:
                    self._stop_reason = error_code.lower()
                    break

            # Stage verdict
            stage_passed = successes >= min_success and not self._stop_reason

            self._stage_results[stage_name] = {
                "name": stage_name,
                "verdict": "passed" if stage_passed else "failed",
                "min_success": min_success,
                "successes": successes,
                "total": len(stage_step_results),
                "evidence": stage_evidence,
                "stop_reason": self._stop_reason,
            }

            # Merge step results into global results
            self._results.update(stage_step_results)

            # If stage failed, stop progression
            if not stage_passed or self._stop_reason:
                logger.info(
                    "Stage '%s' verdict=%s, stopping progression.",
                    stage_name,
                    self._stage_results[stage_name]["verdict"],
                )
                break

            logger.info(
                "Stage '%s' passed (%d/%d), proceeding to next stage.",
                stage_name, successes, len(stage_step_results),
            )

        return self._finalize_results(recipe)

    def _build_stage_dag(self, steps: List[RecipeStep]) -> nx.DiGraph:
        """Build DAG for a subset of steps (one stage)."""
        dag = nx.DiGraph()
        step_ids = {s.id for s in steps}
        for step in steps:
            dag.add_node(step.id, step=step)
            for dep in step.dependencies:
                if dep in step_ids:
                    dag.add_edge(dep, step.id)
        return dag

    async def _execute_stage_steps(
        self, dag: nx.DiGraph, target: str, stop_conditions: Set[str]
    ) -> Dict[str, Dict[str, Any]]:
        """Execute steps within a stage using DAG parallelism."""
        results: Dict[str, Dict[str, Any]] = {}
        pending = set(dag.nodes)
        running: Set[asyncio.Task] = set()
        completed: Set[str] = set()

        while pending or running:
            ready = [
                node for node in pending
                if all(dep in completed for dep in dag.predecessors(node))
            ]

            for node in ready:
                step = dag.nodes[node]["step"]
                t = asyncio.create_task(self._execute_step_with_semaphore(step, target))
                t.node_id = node
                running.add(t)
                pending.remove(node)

            if not running:
                if pending:
                    raise RuntimeError("Deadlock detected in stage execution.")
                break

            done, running = await asyncio.wait(
                running, return_when=asyncio.FIRST_COMPLETED
            )

            for t in done:
                try:
                    result = await t
                    node_id = getattr(t, "node_id")
                    results[node_id] = result
                    completed.add(node_id)

                    # Check if this step triggered a stop condition
                    stop_reason = result.get("stop_reason") or ""
                    if stop_reason and stop_reason in stop_conditions:
                        self._stop_reason = stop_reason
                except Exception as e:
                    logger.error(f"Stage step failed: {e}")
                    node_id = getattr(t, "node_id", "unknown")
                    results[node_id] = self._step_result(
                        step=RecipeStep(id=node_id, name="error", action="unknown", params={}),
                        status="failed",
                        error_code="STEP_EXCEPTION",
                        reason=str(e),
                        retryable=False,
                    )

            # If stop condition triggered, cancel remaining running tasks
            if self._stop_reason:
                for t in running:
                    if not t.done():
                        t.cancel()
                break

        return results

    def _collect_stage_evidence(self, step_results: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract evidence items from step results."""
        evidence_list: List[Dict[str, Any]] = []
        for step_id, result in step_results.items():
            evidence = result.get("evidence")
            if evidence and isinstance(evidence, dict):
                evidence_item = dict(evidence)
                evidence_item.setdefault("step_id", step_id)
                evidence_list.append(evidence_item)
        return evidence_list

    def _build_dag(self, recipe: Recipe) -> nx.DiGraph:
        """依存関係グラフの構築"""
        dag = nx.DiGraph()
        for step in recipe.steps:
            dag.add_node(step.id, step=step)
            for dep in step.dependencies:
                dag.add_edge(dep, step.id)
        return dag

    async def _execute_step_with_semaphore(self, step: RecipeStep, target: str) -> Dict[str, Any]:
        """セマフォを使用してステップを実行"""
        async with self.semaphore:
            # 1. スコープチェック
            from src.core.security.ethics_guard import ActionType, ActionResult
            result, reason = self.ethics_guard.check_action(ActionType.HTTP_REQUEST, target)
            if result != ActionResult.ALLOWED:
                logger.warning(f"Target {target} out of scope or rate limited: {reason}. Skipping step {step.id}")
                return self._step_result(
                    step=step,
                    status="blocked",
                    error_code="BLOCKED_SCOPE",
                    reason=str(reason or "blocked_by_scope_guard"),
                    retryable=False,
                )

            if step.action not in self.ALLOWED_ACTIONS:
                return self._step_result(
                    step=step,
                    status="failed",
                    error_code="UNSUPPORTED_ACTION",
                    reason=f"unsupported_action:{step.action}",
                    retryable=False,
                )

            # 2. キャッシュチェック
            cache_key = self._get_cache_key(step, target)
            if cache_key in self._tool_cache:
                logger.info(f"Cache hit for step {step.id}")
                return self._tool_cache[cache_key]

            # 3. 実行（MasterConductor等から注入されたstep_executor経由）
            logger.info(f"Executing step {step.id}: {step.name} on {target}")
            result = await self._execute_step(step, target)

            # 4. キャッシュ保存
            self._tool_cache[cache_key] = result
            return result

    def _get_cache_key(self, step: RecipeStep, target: str) -> str:
        param_str = json.dumps(step.params, sort_keys=True)
        return f"{target}:{step.id}:{step.action}:{param_str}"

    async def _execute_step(self, step: RecipeStep, target: str) -> Dict[str, Any]:
        if self._step_executor is None:
            return self._step_result(
                step=step,
                status="failed",
                error_code="TOOL_ERROR",
                reason="missing_step_executor",
                retryable=True,
            )

        try:
            raw = await self._step_executor(step, target)
        except asyncio.TimeoutError:
            return self._step_result(
                step=step,
                status="failed",
                error_code="TOOL_TIMEOUT",
                reason="step_executor_timeout",
                retryable=True,
            )
        except Exception as exc:
            return self._step_result(
                step=step,
                status="failed",
                error_code="TOOL_ERROR",
                reason=f"step_executor_error:{exc}",
                retryable=True,
            )

        return self._normalize_step_result(step, raw)

    def _normalize_step_result(self, step: RecipeStep, raw: Any) -> Dict[str, Any]:
        if isinstance(raw, dict):
            status = str(raw.get("status", "failed") or "failed")
            error_code = str(raw.get("error_code", "")) if raw.get("error_code") else None
            reason = str(raw.get("reason", "")) if raw.get("reason") else ""
            retryable = bool(raw.get("retryable", False))
            evidence = raw.get("evidence")
            stop_reason = raw.get("stop_reason") or ""

            result = self._step_result(
                step=step,
                status=status,
                error_code=error_code or ("UNKNOWN_ERROR" if status == "failed" else None),
                reason=reason or ("ok" if status == "success" else "step_not_success"),
                retryable=retryable if status == "failed" else False,
                data=raw.get("data", raw),
            )

            # Step 4: Propagate evidence and stop_reason
            if evidence and isinstance(evidence, dict):
                result["evidence"] = dict(evidence)
            if stop_reason:
                result["stop_reason"] = stop_reason

            return result

        return self._step_result(
            step=step,
            status="failed",
            error_code="UNKNOWN_ERROR",
            reason="invalid_step_executor_result",
            retryable=False,
            data={"raw_result": str(raw)},
        )

    def _step_result(
        self,
        step: RecipeStep,
        status: str,
        error_code: Optional[str],
        reason: str,
        retryable: bool,
        data: Any = None,
    ) -> Dict[str, Any]:
        result = {
            "step_id": step.id,
            "action": step.action,
            "status": status,
            "error_code": error_code,
            "reason": reason,
            "retryable": bool(retryable),
        }
        if data is not None:
            result["data"] = data
        return result

    def _finalize_results(self, recipe: Optional[Recipe] = None, recipe_name: str = None) -> Dict[str, Any]:
        """Build final result bundle including stages, verdict, evidence policy,
        and follow-up routing decisions (Step 6: SGK-2026-0260)."""
        steps = dict(self._results)
        total = len(steps)
        failed = sum(1 for r in steps.values() if r.get("status") == "failed")
        blocked = sum(1 for r in steps.values() if r.get("status") == "blocked")
        major_failure = any(
            (r.get("error_code") in {"BLOCKED_SCOPE", "UNSUPPORTED_ACTION"})
            for r in steps.values()
        )
        failed_ratio = (failed / total) if total > 0 else 0.0
        success = (not major_failure) and (not (total >= 5 and failed_ratio > 0.3))

        result: Dict[str, Any] = {
            "recipe_name": recipe_name or (recipe.name if recipe else "unknown"),
            "success": success,
            "summary": {
                "total_steps": total,
                "failed_steps": failed,
                "blocked_steps": blocked,
                "failed_ratio": failed_ratio,
                "major_failure": major_failure,
            },
            "steps": steps,
        }

        # Step 4: Add stage results if stage-aware execution was used
        if self._stage_results:
            result["stages"] = dict(self._stage_results)

        # Step 4: Add stop_reason if execution was halted
        if self._stop_reason:
            result["stop_reason"] = self._stop_reason

        # Step 4: Evidence policy from recipe
        if recipe and recipe.evidence_policy:
            result["evidence_policy"] = dict(recipe.evidence_policy)

        # Step 4: Verdict classification based on evidence
        result["verdict"] = self._classify_verdict(steps)

        # Step 6: Generate follow-up decisions when recipe execution warrants
        # additional exploration (new evidence, adjacent surfaces, stop conditions)
        follow_ups = self._generate_follow_up_decisions(steps, recipe, result)
        if follow_ups:
            result["follow_up_decisions"] = follow_ups

        return result

    def _generate_follow_up_decisions(
        self,
        steps: Dict[str, Dict[str, Any]],
        recipe: Optional[Recipe],
        result: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Generate follow-up decisions when recipe execution warrants further action.

        Conditions that trigger follow-up:
        1. Stop condition halted execution (rate_limit, waf_block)
        2. Verdict is inconclusive — needs broader exploration
        3. New adjacent endpoints/params discovered in step results
        4. Recipe produced draft evidence that warrants swarm exploration

        Returns list of FollowUpDecision-compatible dicts.
        """
        from src.core.engine.recipe_contracts import (
            FOLLOW_UP_REASON_STOP_CONDITION,
            FOLLOW_UP_REASON_INCONCLUSIVE,
            FOLLOW_UP_REASON_ADJACENT_SURFACE,
            FOLLOW_UP_REASON_NEW_EVIDENCE,
        )
        follow_ups: List[Dict[str, Any]] = []

        # 1. Stop condition → follow-up with broader exploration
        if self._stop_reason:
            follow_ups.append({
                "reason": FOLLOW_UP_REASON_STOP_CONDITION,
                "suggested_action": "scan",
                "suggested_tags": ["broad_exploration"],
                "target_url": "",
                "evidence_summary": f"Recipe halted due to stop condition: {self._stop_reason}",
                "priority": 60,
                "source_recipe": result.get("recipe_name", ""),
                "dedup_key": f"stop:{self._stop_reason}:{result.get('recipe_name', '')}",
            })

        # 2. Inconclusive verdict → consider broader exploration
        verdict = result.get("verdict", "")
        if verdict in {OptimizedRecipeRunner.VERDICT_INCONCLUSIVE, OptimizedRecipeRunner.VERDICT_NO_SIGNAL}:
            follow_ups.append({
                "reason": FOLLOW_UP_REASON_INCONCLUSIVE,
                "suggested_action": "scan",
                "suggested_tags": ["broad_exploration"],
                "target_url": "",
                "evidence_summary": f"Recipe verdict: {verdict} — broader exploration recommended",
                "priority": 50,
                "source_recipe": result.get("recipe_name", ""),
                "dedup_key": f"verdict:{verdict}:{result.get('recipe_name', '')}",
            })

        # 3. New evidence / adjacent surfaces from step results
        new_endpoints: List[str] = []
        new_params: List[str] = []
        for step_id, step_result in steps.items():
            data = step_result.get("data") or {}
            if isinstance(data, dict):
                endpoints = data.get("discovered_urls") or data.get("new_endpoints") or []
                params = data.get("discovered_params") or data.get("new_parameters") or []
                if isinstance(endpoints, list):
                    new_endpoints.extend(str(e) for e in endpoints)
                if isinstance(params, list):
                    new_params.extend(str(p) for p in params)

        if new_endpoints or new_params:
            follow_ups.append({
                "reason": FOLLOW_UP_REASON_ADJACENT_SURFACE,
                "suggested_action": "recon",
                "suggested_tags": ["adjacent_surface"],
                "target_url": new_endpoints[0] if new_endpoints else "",
                "evidence_summary": (
                    f"Discovered {len(new_endpoints)} new endpoints, "
                    f"{len(new_params)} new parameters during recipe execution"
                ),
                "priority": 70,
                "source_recipe": result.get("recipe_name", ""),
                "dedup_key": f"adjacent:{':'.join(sorted(new_endpoints[:5]))}",
            })

        # 4. Evidence with stop_reason in individual steps
        evidence_count = sum(
            1 for r in steps.values()
            if r.get("evidence") or r.get("stop_reason")
        )
        if evidence_count > 0 and not self._stop_reason:
            # Some evidence was found but execution completed normally
            follow_ups.append({
                "reason": FOLLOW_UP_REASON_NEW_EVIDENCE,
                "suggested_action": "analyze",
                "suggested_tags": ["evidence_review"],
                "target_url": "",
                "evidence_summary": f"Recipe produced {evidence_count} evidence-bearing steps",
                "priority": 40,
                "source_recipe": result.get("recipe_name", ""),
                "dedup_key": f"evidence:{evidence_count}:{result.get('recipe_name', '')}",
            })

        return follow_ups

    def _classify_verdict(self, steps: Dict[str, Dict[str, Any]]) -> str:
        """Classify overall verdict based on evidence density and quality.

        - confirmed: Multiple high-confidence, reproducible evidence items
        - draft: Some evidence but not sufficient for confirmed
        - no_signal: No meaningful evidence found
        - inconclusive: Mixed or ambiguous evidence
        """
        all_evidence: List[Dict[str, Any]] = []
        for step_result in steps.values():
            evidence = step_result.get("evidence")
            if evidence and isinstance(evidence, dict):
                all_evidence.append(evidence)

        if not all_evidence:
            return self.VERDICT_NO_SIGNAL

        # Count high-confidence evidence
        high_confidence = sum(
            1 for e in all_evidence
            if str(e.get("confidence", "")).lower() in {"high", "confirmed"}
        )
        reproducible = sum(
            1 for e in all_evidence
            if e.get("reproducible") is True
        )

        # Confirmed threshold: multiple high-confidence + reproducible evidence
        if high_confidence >= 2 or (high_confidence >= 1 and reproducible >= 1):
            return self.VERDICT_CONFIRMED

        # Weak evidence: single low-confidence item
        if len(all_evidence) == 1 and high_confidence == 0:
            weak_types = {"minor_diff", "weak_signal", "info"}
            if str(all_evidence[0].get("type", "")).lower() in weak_types:
                return self.VERDICT_DRAFT

        # Some evidence but not strong enough
        return self.VERDICT_INCONCLUSIVE
