"""run_*_hunter 系メソッドの共通 boilerplate 抽出。

各 hunter に共通する「パラメータ正規化→auth構築→Task生成」を集約する。
結果フォーマットは vuln type ごとに固有性が強いため manager.py 側に残す。
"""

from typing import Any, Callable, Dict, List, Optional, Tuple

from src.core.agents.swarm.base import Task


def build_hunter_task(
    *,
    url: str,
    specialist_key: str,
    task_name: str,
    tags: List[str],
    params: Optional[Dict[str, Any]],
    kwargs: Dict[str, Any],
    current_context: Dict[str, Any],
    phase2_detection_mode: str,
    normalize_tool_supplied_params: Callable[[Optional[Dict[str, Any]], Dict[str, Any]], Dict[str, Any]],
    resolve_detection_mode: Callable[[Dict[str, Any], str], str],
) -> Tuple[Task, str]:
    effective_params = normalize_tool_supplied_params(params, kwargs)
    detection_mode = resolve_detection_mode(effective_params, phase2_detection_mode)

    if "method" not in effective_params:
        effective_params["method"] = kwargs.get("method", "GET")

    cookies_str = kwargs.get("cookies") or current_context.get("params", {}).get("cookies", "")
    effective_params["_auth"] = {
        "auth_headers": kwargs.get("auth_headers", current_context.get("auth_headers", {})),
        "cookies": cookies_str,
    }

    target_task = Task(
        id=f"inj_{specialist_key}_{id(url)}",
        name=task_name,
        target=url,
        params=effective_params,
        tags=tags,
    )
    return target_task, detection_mode
