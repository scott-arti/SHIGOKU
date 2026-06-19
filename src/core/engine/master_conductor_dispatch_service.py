"""Dispatch Service

_dispatch と agent routing の分割先候補。
scope guard / worker route / swarm fallback / recon duplicate skip /
AgentFactory fallback / recipe dispatch を含む。

注意: _dispatch 本体の移行は character tests 追加後に本格着手予定。
現時点では scope verification fast path、recon pipeline execution 切り出し済み。
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from typing import Any
from urllib.parse import urlparse

from src.core.security.ethics_guard import ScopeDefinition

logger = logging.getLogger(__name__)


def dispatch_scope_verification_fast_path(
    task: Any,
    *,
    context_target_info: dict[str, Any],
    allow_post_exploit: bool = False,
) -> dict:
    """
    Scope Verification の軽量フォールバック。

    ScopeParser の LLM/外部依存を介さずに、最低限のスコープを確定して
    初期フェーズの timeout 連鎖を防ぐ。

    Returns:
        dict with scope_definition (ScopeDefinition) and target_info_update
        to be applied by the facade.
    """
    raw_target = str(
        task.params.get("target")
        or context_target_info.get("target")
        or ""
    ).strip()
    if not raw_target:
        return {
            "success": False,
            "task_id": task.id,
            "agent": "scope_parser",
            "error": "Target not specified for scope verification",
        }

    normalized_target = raw_target if "://" in raw_target else f"http://{raw_target}"
    parsed = urlparse(normalized_target)
    host = (parsed.hostname or parsed.netloc or "").strip().lower()

    in_scope_domains = [host] if host else []
    scope = ScopeDefinition(
        program_name=f"Auto Scope ({host or 'target'})",
        in_scope_domains=in_scope_domains,
        max_requests_per_minute=60,
        strict_mode=False,
        allow_post_exploit=bool(allow_post_exploit),
    )

    target_info_update: dict[str, Any] = {
        "target": normalized_target,
        "scope_source": "fast_path_auto",
    }
    if host:
        target_info_update["host"] = host
    if parsed.scheme:
        target_info_update["scheme"] = parsed.scheme
    if in_scope_domains:
        target_info_update["in_scope_domains"] = in_scope_domains

    return {
        "success": True,
        "task_id": task.id,
        "agent": "scope_parser",
        "message": "Scope verification completed via fast-path",
        "data": {
            "target": normalized_target,
            "in_scope_domains": in_scope_domains,
            "out_of_scope_domains": [],
            "strict_mode": False,
        },
        "context": {"target_info": target_info_update},
        "findings": [],
        "_scope_definition": scope,  # facade が set_scope() に使う
    }


class DispatchService:
    """タスクの agent routing / dispatch 境界。"""

    pass


async def run_recon_pipeline_isolated(
    pipeline: Any,
    target: str,
    *,
    start_step: int = 1,
    end_step: int = 8,
) -> Any:
    """ReconPipeline を別スレッドの独立 event loop で実行する。

    facade が構築した ReconPipeline を受け取り、isolated thread で
    実行して raw state を返す。PhaseGate 反映や attack task 生成は
    facade 側の責務とする。

    Returns:
        ReconPipeline state object (with live_subs, tech_stack, results, etc.)
    """
    def _run_isolated():
        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        try:
            return new_loop.run_until_complete(
                pipeline.run(target, start_step=start_step, end_step=end_step)
            )
        finally:
            new_loop.close()

    return await asyncio.to_thread(_run_isolated)


def dispatch_post_exploit_guard(
    task: Any,
    *,
    current_mode: str,
    settings_allow_post_exploit: bool,
    scope_allow_post_exploit: bool | None = None,
) -> dict | None:
    """Check if a post-exploit task should be skipped in bugbounty mode.

    Returns the skip dict if the task should be blocked, or None if it should proceed.
    """
    is_pe_type = task.agent_type in [
        "post_exploit", "secret_looter", "internal_recon", "pivot_scan",
    ] or getattr(task, "action", "") in ["secret_looting", "internal_recon"]

    if not is_pe_type:
        return None

    # Resolve allow_pe: scope value takes priority when available
    allow_pe = (
        scope_allow_post_exploit
        if scope_allow_post_exploit is not None
        else settings_allow_post_exploit
    )

    if current_mode.lower() == "bugbounty" and not allow_pe:
        logger.info(
            "Skipping post-exploit task %s (%s) due to strict bugbounty scope rules.",
            task.id,
            task.agent_type,
        )
        return {
            "success": True,
            "task_id": task.id,
            "agent": task.agent_type,
            "data": {
                "skipped": True,
                "reason": "Post-exploitation not allowed in current scope",
            },
            "error": None,
            "findings": [],
        }

    return None


def dispatch_ctf_filter(
    task: Any,
    *,
    current_mode: str,
) -> dict | None:
    """CTF mode agent filter.

    Returns an error dict if the agent is filtered, or None if it should proceed.
    """
    if current_mode != "ctf":
        return None

    from src.core.engine.agent_registry import is_agent_available

    context_tag = "web"
    if not is_agent_available(task.agent_type, context_tag):
        logger.warning(
            "Agent '%s' is not available in CTF %s context. "
            "Filtering applied to prevent context pollution.",
            task.agent_type,
            context_tag,
        )
        return {
            "success": False,
            "task_id": task.id,
            "agent": task.agent_type,
            "error": f"Agent filtered: not available in {context_tag} context",
        }

    return None


async def dispatch_worker(
    task: Any,
    *,
    accumulated_context: Any,
    llm_client: Any,
    network_client: Any,
) -> dict | None:
    """Worker factory dispatch.

    Returns a result dict if a worker was found, or None if no worker was available
    (so the facade falls through to the next branch).
    """
    from src.core.swarm.worker.factory import get_worker_factory

    worker_factory = get_worker_factory(accumulated_context, llm_client, network_client)
    worker = worker_factory.create_worker(task.agent_type)

    if not worker:
        return None

    logger.info(
        "Dispatching to Worker: %s (Unified Architecture)", task.agent_type
    )

    # Worker.execute は同期、将来的に非同期化される可能性を考慮
    res = worker.execute(task)
    if inspect.isawaitable(res):
        worker_result = await res
    else:
        worker_result = res

    return {
        "success": worker_result.success,
        "task_id": task.id,
        "agent": task.agent_type,
        "data": worker_result.data,
        "error": worker_result.error,
        "findings": worker_result.findings,
        "is_swarm": True,
    }


async def dispatch_swarm(
    task: Any,
    *,
    project_manager_config: dict | None,
    network_client: Any,
    llm_client: Any,
    event_bus: Any,
    recipe_loader: Any | None,
    rag: Any | None,
    agentic_rag: Any | None,
) -> dict | None:
    """Swarm dispatcher.

    Returns a result dict if the swarm handled the task, or None to fall through.
    """
    task_params = task.params if isinstance(task.params, dict) else {}
    normalized_agent_type = str(task.agent_type or "").strip().lower()
    has_tags = bool(task_params.get("tags"))

    if not (normalized_agent_type == "swarm" or (not normalized_agent_type and has_tags)):
        return None

    try:
        from src.core.engine.swarm_dispatcher import get_swarm_dispatcher

        dispatcher = get_swarm_dispatcher(
            config=project_manager_config if project_manager_config else {},
            network_client=network_client,
            llm_client=llm_client,
            loop=asyncio.get_running_loop(),
            event_bus=event_bus,
        )

        if recipe_loader:
            dispatcher.set_recipe_loader(recipe_loader)
        if rag:
            dispatcher.set_rag(rag)

        # Agentic RAG / RAG context retrieval
        target = task.params.get("target", "")
        rag_results = []
        # SGK-2026-0262: policy に基づき RAG 利用判断
        _use_rag = True
        try:
            from src.core.rag_module.rag_policy import should_use_rag_for_component, get_default_policy
            _policy = get_default_policy()
            _decision = should_use_rag_for_component("swarm", policy=_policy)
            _use_rag = _decision != "no_rag"  # NO_RAG 以外なら RAG 利用可
        except ImportError:
            pass

        if _use_rag:
            if agentic_rag:
                logger.info("[MasterConductor] Using Agentic RAG for initial context...")
                rag_results = await agentic_rag.retrieve_with_feedback(
                    query=target,
                    goal=f"Initial reconnaissance and attack surface mapping for {target}",
                )
            elif rag:
                rag_results = rag.retrieve(target)

        # SGK-2026-0262: RAG 結果を dispatcher に渡す（params 経由）
        if rag_results:
            enriched_params = dict(task.params)
            enriched_params["_rag_context"] = rag_results
            task.params = enriched_params

        tags = task.params.get("tags", [])
        target = task.params.get("target", "")

        try:
            result = await dispatcher.dispatch(
                tags=tags,
                target=target,
                task_name=task.name,
                params=task.params,
            )
        except Exception as e:
            logger.error("Swarm execution error: %s", e)
            result = None

        if result:
            return {
                "success": result.status in ["success", "partial_success"],
                "task_id": task.id,
                "agent": result.swarm_name,
                "data": {
                    "findings": [f.to_dict() for f in result.findings],
                    "execution_log": result.execution_log,
                    "total_specialists": result.total_specialists,
                    "successful_specialists": result.successful_specialists,
                },
                "findings": result.findings,
            }

        logger.info(
            "No matching swarm for task %s, falling back to agent dispatch", task.id
        )

    except Exception as e:
        logger.error("Swarm dispatch error: %s", e)

    return None


async def dispatch_cartographer(
    task: Any,
    *,
    network_client: Any,
    workspace_root: str | None = None,
) -> dict:
    """Cartographer dispatch — maps site structure via network_client.

    Returns a result dict directly (always handles the task, never falls through).
    """
    try:
        from src.core.intel.cartographer import Cartographer

        target = task.params.get("target", "")
        logger.info("Dispatching Cartographer (Async/Shared) for target: %s", target)

        cartographer = Cartographer(
            target,
            network_client=network_client,
            max_depth=3,
            max_pages=100,
        )
        try:
            sitemap = await cartographer.map_site()
        finally:
            cartographer.close()

        return {
            "success": True,
            "task_id": task.id,
            "agent": "cartographer",
            "data": {
                "nodes_count": len(sitemap.nodes),
                "endpoints": sitemap.get_endpoints()[:20],
            },
            "new_assets": sitemap.get_endpoints(),
        }
    except Exception as e:
        logger.error("Cartographer execution error: %s", e)
        return {
            "success": False,
            "task_id": task.id,
            "agent": "cartographer",
            "error": str(e),
        }


async def dispatch_fingerprinter(
    task: Any,
    *,
    network_client: Any,
    workspace_root: str | None = None,
) -> dict:
    """Fingerprinter dispatch — identifies technologies from the response.

    Returns a result dict directly (always handles the task, never falls through).
    """
    try:
        from src.core.intel.fingerprinter import Fingerprinter

        target = task.params.get("target", "")
        logger.info(
            "Dispatching Fingerprinter (Shared Session) for target: %s", target
        )

        fingerprinter = Fingerprinter()
        resp = await network_client.request("GET", target, timeout=15)

        if resp and resp.is_success:
            techs = fingerprinter.identify(resp.body, resp.headers)
            tech_names = [t.name for t in techs] if techs else []
            return {
                "success": True,
                "task_id": task.id,
                "agent": "fingerprinter",
                "data": {
                    "technologies": tech_names,
                    "tech_details": [vars(t) for t in techs],
                },
                "findings": tech_names,
            }
        else:
            return {
                "success": False,
                "task_id": task.id,
                "agent": "fingerprinter",
                "error": f"Failed to fetch target: {target}",
            }
    except Exception as e:
        logger.error("Fingerprinter execution error: %s", e)
        return {
            "success": False,
            "task_id": task.id,
            "agent": "fingerprinter",
            "error": str(e),
        }


def dispatch_recipe_check(task: Any) -> bool:
    """Check if a task is a recipe execution request.

    Returns True if task.action == 'run_recipe'.
    The facade then calls self._execute_recipe_task(task).
    """
    return task.action == "run_recipe"


async def execute_agent_dispatch(
    agent: Any,
    task: Any,
    *,
    resolved_target: str,
) -> dict:
    """Execute an agent via execute/run/process with signature mismatch fallback.

    Takes a pre-constructed agent (from AgentFactory.create_agent) and executes it.
    Does NOT handle cookie injection, agent creation, or cleanup — those stay in the facade.

    Args:
        agent: Pre-constructed agent from AgentFactory
        task: Task with resolved target in params
        resolved_target: Resolved target URL string

    Returns:
        result_data dict (may contain error on failure)
    """
    import json
    import traceback as _traceback

    result_data: dict = {}

    # 1. Swarm agent (has execute() method)
    if hasattr(agent, 'execute'):
        logger.debug("Using execute() method for %s", task.agent_type)
        try:
            logger.info("Executing %s.execute() for task %s", task.agent_type, task.id)
            result = await agent.execute(
                target=resolved_target or task.params.get("target"),
                params=task.params,
            )
            logger.info("%s.execute() completed for task %s", task.agent_type, task.id)
        except TypeError as e:
            # Agent-specific execute signature mismatch fallback
            error_msg = str(e)
            handled = False

            if "unexpected keyword argument" in error_msg:
                try:
                    from src.tools.builtin.handoff import HandoffContext
                    context_payload = dict(task.params or {})
                    context_target = context_payload.get("target") or task.target
                    if context_target:
                        context_payload["target"] = context_target
                    logger.warning(
                        "%s execute signature mismatch (%s). Retrying with HandoffContext.",
                        task.agent_type, error_msg,
                    )
                    result = await agent.execute(HandoffContext.from_params(context_payload))
                    handled = True
                except Exception as context_exc:
                    logger.debug("HandoffContext fallback failed for %s: %s", task.agent_type, context_exc)

            if not handled and "unexpected keyword argument 'params'" in error_msg:
                logger.warning("%s does not accept 'params'. Retrying without it.", task.agent_type)
                result = await agent.execute(target=resolved_target or task.params.get("target"))
                handled = True

            if not handled and "unexpected keyword argument 'target'" in error_msg:
                logger.warning("%s does not accept 'target'. Retrying with params only.", task.agent_type)
                result = await agent.execute(params=task.params)
                handled = True

            if not handled:
                raise

        # Convert HandoffContext / object result to dict
        if hasattr(result, 'to_dict'):
            result_data = result.to_dict()
        elif hasattr(result, '__dict__'):
            result_data = vars(result)
        else:
            result_data = {"result": str(result)}

    # 1.5. New run() method (ToolExecutorAgent etc.)
    elif hasattr(agent, 'run') and not getattr(agent, 'force_process', False):
        logger.debug("Using run() method for %s", task.agent_type)
        try:
            task_dict = task.to_dict()
            if "params" not in task_dict:
                task_dict["params"] = task.params
            if not task_dict.get("target"):
                task_dict["target"] = resolved_target
            task_params = task_dict.get("params", {})
            if isinstance(task_params, dict) and resolved_target and not task_params.get("target"):
                task_params["target"] = resolved_target

            logger.info("Executing %s.run() for task %s", task.agent_type, task.id)
            result_data = await agent.run(task_dict)
            logger.info("%s.run() completed for task %s", task.agent_type, task.id)

            if not isinstance(result_data, dict):
                if hasattr(result_data, 'to_dict'):
                    result_data = result_data.to_dict()
                elif hasattr(result_data, '__dict__'):
                    result_data = vars(result_data)
                else:
                    result_data = {"output": str(result_data), "task_params": task.params}
        except Exception as e:
            logger.error("Async execution error in run(): %s\n%s", e, _traceback.format_exc())
            result_data = {"error": str(e), "task_params": task.params}

    # 2. BaseAgent family (has process() method)
    elif hasattr(agent, 'process'):
        logger.debug("Using process() method for %s", task.agent_type)
        task_input = json.dumps(task.params)
        try:
            logger.info("Executing %s.process() for task %s", task.agent_type, task.id)
            result_text = await agent.process(task_input)
            logger.info("%s.process() completed for task %s", task.agent_type, task.id)
        except Exception as e:
            logger.error("Async execution error: %s\n%s", e, _traceback.format_exc())
            result_text = "Error: {}".format(e)

        result_data = {
            "output": result_text,
            "task_params": task.params,
        }

    else:
        # Unknown agent type
        logger.warning("Agent %s has no execute() or process() method", task.agent_type)
        result_data = {
            "error": "Unsupported agent type",
            "agent_type": task.agent_type,
        }

    return result_data
