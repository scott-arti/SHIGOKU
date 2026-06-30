import asyncio
import logging
import json
import shutil
from datetime import datetime, timezone, timedelta
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
            infra_state = raw.get("infrastructure_state")  # may be None

            if status == "success":
                return self._step_result(
                    step=step,
                    status="success",
                    error_code=None,
                    reason=reason or "ok",
                    retryable=False,
                    data=raw.get("data", raw),
                    infrastructure_state=infra_state,
                )

            if status in {"failed", "blocked", "skipped"}:
                return self._step_result(
                    step=step,
                    status=status,
                    error_code=error_code or ("UNKNOWN_ERROR" if status == "failed" else None),
                    reason=reason or "step_not_success",
                    retryable=retryable if status == "failed" else False,
                    data=raw.get("data"),
                    infrastructure_state=infra_state,
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
        infrastructure_state: Optional[str] = None,
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
        if infrastructure_state is not None:
            result["infrastructure_state"] = infrastructure_state
        return result

    def _finalize_results(
        self,
        recipe_name: str,
        provider_entry=None,
        evidence_count: int = 0,
        stale_candidate: bool = False,
        cname_chain: Optional[list] = None,
        last_seen_dead: Optional[datetime] = None,
        scope_policy_blocks_takeover: bool = False,
        # trace metadata (plan 4.10)
        source_line: Optional[str] = None,
        producer_step: Optional[str] = None,
        session_id: Optional[str] = None,
        artifact_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Finalize recipe execution results with takeover-aware success gates.

        Plan section 4.7 requirements:
        - ``total_steps > 0``
        - ``major_failure == False``
        - evidence types >= 2 for non-manual success
        - stale candidates cannot reach ``confirmed``
        """
        steps = dict(self._results)
        total = len(steps)
        failed = sum(1 for r in steps.values() if r.get("status") == "failed")
        blocked = sum(1 for r in steps.values() if r.get("status") == "blocked")
        success_count = sum(1 for r in steps.values() if r.get("status") == "success")
        all_blocked = total > 0 and blocked == total

        major_failure = any(
            (r.get("error_code") in {"BLOCKED_SCOPE", "UNSUPPORTED_ACTION"})
            for r in steps.values()
        )
        failed_ratio = (failed / total) if total > 0 else 0.0

        # ── 0-step success prevention (plan 4.7) ────────────────────────
        if total == 0:
            success = False
        elif all_blocked:
            success = False
        elif major_failure:
            success = False
        elif total >= 5 and failed_ratio > 0.3:
            success = False
        elif success_count == 0:
            success = False
        else:
            success = True

        result: Dict[str, Any] = {
            "recipe_name": recipe_name,
            "success": success,
            "summary": {
                "total_steps": total,
                "success_count": success_count,
                "failed_steps": failed,
                "blocked_steps": blocked,
                "failed_ratio": failed_ratio,
                "major_failure": major_failure,
                "all_blocked": all_blocked,
                "stale_candidate": stale_candidate,
            },
            "steps": steps,
            # trace metadata (plan 4.10)
            "source_line": source_line,
            "producer_step": producer_step,
            "session_id": session_id,
            "artifact_hash": artifact_hash,
        }

        # ── infrastructure state classification (plan 3.4.1) ──────────
        infra_state = classify_infrastructure_state(list(steps.values()))
        result["infrastructure_state"] = infra_state

        # ── takeover verdict classification (plan 4.7) ──────────────────
        tool_agreement = _count_tool_disagreement(steps) <= 1
        verdict = classify_takeover_result(
            provider_entry=provider_entry,
            provider_matrix=None,  # matrix not wired at runner level — caller provides entry
            evidence_count=evidence_count or success_count,
            tool_agreement=tool_agreement,
            candidate_is_stale=stale_candidate,
        )

        # Guard: a broken probe should not produce ``no_finding``.
        # If infrastructure is unhealthy we cannot conclude absence of
        # evidence — the probes simply didn't run properly.
        if infra_state != InfrastructureState.OK and verdict == "no_finding":
            verdict = "manual_review_required"

        result["takeover_verdict"] = verdict
        result["manual_review_required"] = verdict == "manual_review_required"
        result["confirmed"] = verdict == "confirmed"

        # ── verdict reason codes (plan 3.4.4 / 4.9 items 3-6) ──────────
        supports_auto = (
            provider_entry is not None
            and bool(getattr(provider_entry, "supports_auto_confirm", False))
        )
        result["verdict_reason_codes"] = compute_verdict_reasons(
            cname_chain=cname_chain,
            last_seen_dead=last_seen_dead,
            tool_agreement=tool_agreement,
            provider_supports_auto_confirm=supports_auto,
            scope_policy_blocks_takeover=scope_policy_blocks_takeover,
            evidence_count=evidence_count or success_count,
            infrastructure_state=infra_state,
        )

        return result


# ── Module-level takeover helpers (plan 4.7) ────────────────────────────

_STALE_DAYS = 30
_MIN_EVIDENCE_FOR_CONFIRMED = 2


def is_candidate_stale(candidate) -> bool:
    """Return True if the candidate's ``last_seen_dead`` is older than ``_STALE_DAYS``."""
    try:
        last = candidate.last_seen_dead
    except AttributeError:
        return False
    if last is None:
        return True
    now = datetime.now(timezone.utc)
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (now - last).days > _STALE_DAYS


def compute_verdict_reasons(
    cname_chain: Optional[list],
    last_seen_dead: Optional[datetime],
    tool_agreement: bool,
    provider_supports_auto_confirm: bool,
    scope_policy_blocks_takeover: bool,
    evidence_count: int,
    infrastructure_state: str,
) -> list:
    """Compute structured reason codes explaining WHY a candidate reached its verdict.

    Returns a list of reason code strings (plan section 3.4.4):
      - ``"missing_cname"``           — no CNAME chain found (empty or None)
      - ``"stale_candidate"``         — candidate > ``_STALE_DAYS`` old or never seen
      - ``"tool_disagreement"``       — subjack vs subzy disagree
      - ``"provider_no_auto_confirm"`` — provider doesn't support auto-confirm
      - ``"scope_policy_blocks_claim"`` — scope policy blocks automated claim
      - ``"insufficient_evidence"``   — evidence_count < ``_MIN_EVIDENCE_FOR_CONFIRMED``
      - ``"infrastructure_unhealthy"`` — resolver/tool/probe failure

    An empty list means all conditions are met and the verdict can be ``confirmed``.
    """
    reasons: list[str] = []

    # ── missing CNAME chain ────────────────────────────────────────────
    if not cname_chain:
        reasons.append("missing_cname")

    # ── stale candidate ────────────────────────────────────────────────
    if last_seen_dead is None:
        reasons.append("stale_candidate")
    else:
        if last_seen_dead.tzinfo is None:
            last_seen_dead = last_seen_dead.replace(tzinfo=timezone.utc)
        if (datetime.now(timezone.utc) - last_seen_dead).days > _STALE_DAYS:
            reasons.append("stale_candidate")

    # ── tool disagreement ──────────────────────────────────────────────
    if not tool_agreement:
        reasons.append("tool_disagreement")

    # ── provider doesn't support auto-confirm ──────────────────────────
    if not provider_supports_auto_confirm:
        reasons.append("provider_no_auto_confirm")

    # ── scope policy blocks takeover ───────────────────────────────────
    if scope_policy_blocks_takeover:
        reasons.append("scope_policy_blocks_claim")

    # ── insufficient evidence ──────────────────────────────────────────
    if evidence_count < _MIN_EVIDENCE_FOR_CONFIRMED:
        reasons.append("insufficient_evidence")

    # ── infrastructure unhealthy ───────────────────────────────────────
    if infrastructure_state != InfrastructureState.OK:
        reasons.append("infrastructure_unhealthy")

    return reasons


def compute_takeover_verdict(
    provider_supports_auto_confirm: bool,
    evidence_count: int,
    tool_agreement: bool,
    stale: bool,
    scope_policy_blocks_takeover: bool = False,
    cname_chain: Optional[list] = None,
    last_seen_dead: Optional[datetime] = None,
    infrastructure_state: str = "ok",
) -> str:
    """Compute a takeover verdict from atomic signals.

    Returns one of: ``confirmed``, ``high_priority_manual_check``,
    ``manual_review_required``, ``no_finding``.

    Uses ``compute_verdict_reasons()`` internally (plan sections 3.4.4, 4.7, 4.9).
    For backward compatibility, when ``cname_chain`` or ``last_seen_dead`` are
    not provided they default to values that do not trigger reason codes.

    Verdict mapping:
      - ``evidence_count == 0 AND infrastructure_state == "ok"``: ``no_finding``
      - ``evidence_count == 0 AND infrastructure_state != "ok"``: ``manual_review_required``
      - ``verdict_reason_codes`` empty AND evidence > 0: ``confirmed``
      - else: ``manual_review_required``
    """
    # Backward-compatible defaults: when callers don't provide cname_chain
    # or last_seen_dead, use sentinel values that won't trigger reason codes
    # (unless the old ``stale`` flag signals staleness).
    _cname = cname_chain if cname_chain is not None else ["_compat_default"]
    _explicit_last = last_seen_dead is not None
    _last: Optional[datetime] = last_seen_dead if _explicit_last else datetime.now(timezone.utc)

    reasons = compute_verdict_reasons(
        cname_chain=_cname,
        last_seen_dead=_last,
        tool_agreement=tool_agreement,
        provider_supports_auto_confirm=provider_supports_auto_confirm,
        scope_policy_blocks_takeover=scope_policy_blocks_takeover,
        evidence_count=evidence_count,
        infrastructure_state=infrastructure_state,
    )

    # When the old ``stale`` flag is used without an explicit ``last_seen_dead``,
    # ensure ``stale_candidate`` is still reflected in the reason codes.
    if stale and not _explicit_last and "stale_candidate" not in reasons:
        reasons.append("stale_candidate")

    # ── verdict mapping (plan 3.3, 3.4.4, 4.11, 4.12) ─────────────────
    if evidence_count == 0:
        if infrastructure_state == InfrastructureState.OK:
            return "no_finding"
        return "manual_review_required"

    if not reasons:
        return "confirmed"

    # ── high_priority_manual_check (plan 4.11, formerly likely_reclaimable) ──
    # Strong evidence: provider match + error token + fresh + multi-tool
    # agreement, but provider does not support auto-confirm → high priority
    # for a human to verify the claim on the provider side.
    # The only blocking reason is ``provider_no_auto_confirm`` and evidence
    # is otherwise solid (2+ types, tools agree, not stale, cname present,
    # infrastructure healthy, scope does not block).
    _high_priority_blockers = {
        "stale_candidate", "insufficient_evidence", "tool_disagreement",
        "missing_cname", "infrastructure_unhealthy", "scope_policy_blocks_claim",
    }
    if (
        "provider_no_auto_confirm" in reasons
        and not _high_priority_blockers.intersection(reasons)
        and evidence_count >= _MIN_EVIDENCE_FOR_CONFIRMED
        and tool_agreement
    ):
        return "high_priority_manual_check"

    return "manual_review_required"


def classify_takeover_result(
    provider_entry,
    provider_matrix,
    evidence_count: int,
    tool_agreement: bool,
    candidate_is_stale: bool,
    scope_policy_blocks_takeover: bool = False,
    cname_chain: Optional[list] = None,
    last_seen_dead: Optional[datetime] = None,
    infrastructure_state: str = "ok",
) -> str:
    """Classify a takeover recipe result using provider matrix data.

    Convenience wrapper around ``compute_takeover_verdict`` that derives
    ``provider_supports_auto_confirm`` from a ``ProviderEntry``.
    """
    supports_auto = (
        provider_entry is not None and bool(provider_entry.supports_auto_confirm)
    )
    return compute_takeover_verdict(
        provider_supports_auto_confirm=supports_auto,
        evidence_count=evidence_count,
        tool_agreement=tool_agreement,
        stale=candidate_is_stale,
        scope_policy_blocks_takeover=scope_policy_blocks_takeover,
        cname_chain=cname_chain,
        last_seen_dead=last_seen_dead,
        infrastructure_state=infrastructure_state,
    )


def _count_tool_disagreement(steps: dict) -> int:
    """Count how many distinct tool sources disagree across steps.

    Simplistic heuristic: counts steps with ``status == "failed"`` where
    the error_code is ``TOOL_ERROR``. In a full implementation this would
    cross-reference tool outputs.
    """
    count = 0
    for step in steps.values():
        if step.get("status") == "failed" and step.get("error_code") == "TOOL_ERROR":
            count += 1
    return count


# ── Infrastructure state guardrails (plan 3.4.1 / 3.4.4) ──────────────


class InfrastructureState:
    """String constants for infrastructure health classification.

    These codes distinguish infrastructure problems from genuine
    no-finding outcomes. Do not confuse a missing tool binary with
    absence of takeover evidence.
    """

    OK = "ok"
    TOOL_UNAVAILABLE = "tool_unavailable"
    PROBE_FAILED = "probe_failed"
    RESOLVER_DEGRADED = "resolver_degraded"
    TIMEOUT = "timeout"
    MISSING_BINARY = "missing_binary"


def classify_infrastructure_state(step_results: list) -> str:
    """Inspect step error codes and return an InfrastructureState value.

    Priority order (most critical first):
      - ``MISSING_BINARY`` → ``InfrastructureState.MISSING_BINARY``
      - ``TOOL_TIMEOUT``   → ``InfrastructureState.TIMEOUT``
      - ``TOOL_ERROR``     → ``InfrastructureState.PROBE_FAILED``
      - No infrastructure errors → ``InfrastructureState.OK``

    ``step_results`` should be a list of result dicts from
    ``_step_result()`` / ``_normalize_step_result()``.
    """
    if not step_results:
        return InfrastructureState.OK

    error_codes = {r.get("error_code") for r in step_results}

    if "MISSING_BINARY" in error_codes:
        return InfrastructureState.MISSING_BINARY
    if "TOOL_TIMEOUT" in error_codes:
        return InfrastructureState.TIMEOUT
    if "TOOL_ERROR" in error_codes:
        return InfrastructureState.PROBE_FAILED

    return InfrastructureState.OK


def check_tool_availability(tool_name: str) -> bool:
    """Return ``True`` when *tool_name* is found on ``PATH`` via ``shutil.which``.

    Preflight check to use before attempting a takeover recipe so that
    infrastructure problems are caught early.
    """
    return shutil.which(tool_name) is not None
