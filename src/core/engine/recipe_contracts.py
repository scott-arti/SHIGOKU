from __future__ import annotations

from typing import Any, Dict, Iterable, List, TYPE_CHECKING

from src.core.domain.model.task import Task

if TYPE_CHECKING:
    from src.core.engine.recipe_loader import Recipe


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
    # ── takeover v2 actions ──────────────────────────
    "check_takeover",
    "dns_check",
    "cname_resolve",
    "http_probe",
    "takeover_scan",
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


def validate_recipe_schema(
    recipe: "Recipe",
    *,
    allowed: Iterable[str] = ALLOWED_RECIPE_STEP_ACTIONS,
) -> Dict[str, Any]:
    """Validate a Recipe before it enters the candidate pool.

    Checks performed:
      - step_count > 0
      - every step.action is in ``allowed``

    Returns a dict with ``ok`` (bool), ``error`` (str), and ``details`` (list).
    """
    details: List[str] = []
    ok = True

    if not recipe.steps:
        return {
            "ok": False,
            "error": "recipe_validation_failed:zero_steps",
            "details": ["recipe_has_zero_steps"],
        }

    allowed_set = set(str(a).strip() for a in allowed)
    for step in recipe.steps:
        action = str(step.action or "").strip()
        if action not in allowed_set:
            details.append(f"unsupported_action:{action} in step:{step.id}")
            ok = False

    if not ok:
        return {
            "ok": False,
            "error": "recipe_validation_failed:" + "; ".join(details),
            "details": details,
        }

    return {
        "ok": True,
        "error": "",
        "details": [],
    }

