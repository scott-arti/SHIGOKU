import asyncio
import logging
import json
from typing import Dict, Any, Set, Awaitable, Callable, Optional
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
    """
    ALLOWED_ACTIONS = ALLOWED_RECIPE_STEP_ACTIONS

    def __init__(self, max_workers: int = 8, step_executor: Optional[StepExecutor] = None):
        self.max_workers = max_workers
        self.semaphore = asyncio.Semaphore(max_workers)
        self._tool_cache: Dict[str, Any] = {}
        self.ethics_guard = EthicsGuard()
        self._step_executor = step_executor
        self._results: Dict[str, Dict[str, Any]] = {}

    async def run_recipe(self, recipe: Recipe, target: str) -> Dict[str, Any]:
        """
        レシピを解析し、依存関係に従って実行。
        """
        self._results = {}
        dag = self._build_dag(recipe)
        
        if not nx.is_directed_acyclic_graph(dag):
            raise ValueError(f"Recipe '{recipe.name}' contains a cycle in dependencies.")

        # 実行待ちタスクの管理
        pending_tasks = set(dag.nodes)
        running_tasks: Set[asyncio.Task] = set()
        completed_tasks: Set[str] = set()
        
        while pending_tasks or running_tasks:
            # 準備ができた（依存関係がすべて完了した）タスクを探す
            ready_tasks = [
                node for node in pending_tasks 
                if all(dep in completed_tasks for dep in dag.predecessors(node))
            ]
            
            for node in ready_tasks:
                step = dag.nodes[node]["step"]
                task = asyncio.create_task(self._execute_step_with_semaphore(step, target))
                task.node_id = node # タスクにノードIDを紐付け
                running_tasks.add(task)
                pending_tasks.remove(node)
                
            if not running_tasks:
                if pending_tasks:
                    raise RuntimeError("Deadlock detected in recipe execution.")
                break
                
            # いずれかのタスクが完了するのを待機
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
                    # 失敗時の戦略（現在はスキップ）
        
        return self._finalize_results(recipe_name=recipe.name)

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
        return f"{target}:{step.action}:{param_str}"

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

            if status == "success":
                return self._step_result(
                    step=step,
                    status="success",
                    error_code=None,
                    reason=reason or "ok",
                    retryable=False,
                    data=raw.get("data", raw),
                )

            if status in {"failed", "blocked", "skipped"}:
                return self._step_result(
                    step=step,
                    status=status,
                    error_code=error_code or ("UNKNOWN_ERROR" if status == "failed" else None),
                    reason=reason or "step_not_success",
                    retryable=retryable if status == "failed" else False,
                    data=raw.get("data"),
                )

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

    def _finalize_results(self, recipe_name: str) -> Dict[str, Any]:
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
        return {
            "recipe_name": recipe_name,
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
