from typing import Any, Dict, Iterable, List

from src.core.domain.model.task import Task


ALLOWED_RECIPE_STEP_ACTIONS = {
    "recon",
    "scan",
    "report",
    "execute",
    "auth_attack",
    "sqli_scan",
    "xss_scan",
    "run",
    "analyze",
    "verify_scope",
    "parallel_recon",
}


def validate_action_schema(action: str, *, allowed: Iterable[str] = ALLOWED_RECIPE_STEP_ACTIONS) -> Dict[str, Any]:
    normalized = str(action or "").strip()
    allowed_set = set(str(a).strip() for a in allowed)
    ok = bool(normalized) and normalized in allowed_set
    return {
        "ok": ok,
        "action": normalized,
        "allowed": sorted(allowed_set),
        "error": "" if ok else f"unsupported_action:{normalized or '<empty>'}",
    }


def validate_task_schema(task: Task) -> Dict[str, Any]:
    errors: List[str] = []
    if not str(getattr(task, "id", "") or "").strip():
        errors.append("missing:id")
    if not str(getattr(task, "name", "") or "").strip():
        errors.append("missing:name")
    if not str(getattr(task, "agent_type", "") or "").strip():
        errors.append("missing:agent_type")
    if not str(getattr(task, "action", "") or "").strip():
        errors.append("missing:action")
    if not isinstance(getattr(task, "params", None), dict):
        errors.append("invalid:params_not_dict")

    return {
        "ok": len(errors) == 0,
        "errors": errors,
    }

