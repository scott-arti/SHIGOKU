from __future__ import annotations

from typing import Any, Dict, Iterable, List, TYPE_CHECKING

from src.core.domain.model.task import Task

if TYPE_CHECKING:
    from src.core.engine.recipe_loader import Recipe


# ── Allowed recipe step actions ───────────────────────────────────────────

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

# ── Fixed decision trace vocabulary (SGK-2026-0260) ──────────────────────

# Reasons a RecipeCandidate was NOT selected — it falls to direct swarm instead.
# These codes appear in task params as ``recipe_to_swarm_reason`` /
# ``recipe_to_swarm_reasons`` and in ``RecipeCandidate`` trace metadata.
RECIPE_TO_SWARM_REASON_CODES = {
    # deterministic selector decided this signal needs human review
    "manual_review_required",
    # no recipe matched the signal's required signals
    "no_recipe_match",
    # signal confidence too low for deterministic routing
    "low_confidence",
    # all matching recipes contain at least one unsupported step action
    "unsupported_action",
    # an active suppression key blocks re-execution
    "suppression_active",
    # the same recipe was already executed for this signal/endpoint
    "previous_run_exists",
    # scope or ethics guard blocks execution
    "scope_blocked",
}

# Reasons applied during recipe candidate scoring (why points were added or
# suppressed). These populate ``RecipeCandidate.reasons``.
RECIPE_ADDITIVE_REASONS = {
    "fresh_signal",               # signal is recent (<7 days)
    "high_confidence",            # signal confidence >= 0.9
    "nearby_finding_confirms",    # nearby endpoint has a confirmed finding
    "nearby_auth_surface",        # nearby endpoint is an auth surface
    "nearby_endpoint_corroborates",  # nearby endpoint shares same attack surface type
    "tech_stack_match",           # recipe trigger matches known tech stack
    "high_freshness_score",       # KG freshness score is high
    "previous_recipe_succeeded",  # same recipe previously confirmed on related endpoint
    "multi_label_match",          # signal matches multiple required signals
}

RECIPE_SUPPRESSIVE_REASONS = {
    "stale_signal",               # signal is old (>30 days)
    "low_confidence",             # signal confidence < 0.5
    "previous_recipe_run_exists", # same recipe+signal already executed
    "previous_recipe_failed",     # same recipe previously failed on this signal
    "nearby_finding_mitigated",   # nearby finding was already patched/mitigated
    "unsupported_step_action",    # recipe has step actions not in allowlist
    "blocking_signal_present",    # trigger.blocking_signals matched
    "signal_manual_review",       # signal.status is "needs_swarm_review"
    "kg_context_stale",           # KG supporting context is out of date
    "suppression_key_active",     # explicit suppression key is active
}

# Fixed vocabulary for follow-up decision after recipe execution.
RECIPE_FOLLOW_UP_REASONS = {
    "new_signal_discovered",      # recipe execution revealed new attack surface
    "adjacent_endpoint_exposed",  # nearby endpoint warrants further investigation
    "evidence_insufficient",      # recipe completed but evidence is weak
    "recipe_partial_success",     # some steps succeeded, some failed
    "recipe_failed",              # recipe execution failed entirely
    "recommend_specialized_swarm", # follow-up needs LLM/Swarm exploration
    "recommend_manual_review",    # results need human triage
    "recommend_deepened_recipe",  # run a more specific follow-up recipe
    "no_follow_up_needed",        # nothing further required
    "recipe_completed_cleanly",   # all steps succeeded, no new signals
    "recipe_completely_blocked",  # all steps blocked by scope/guard
}

# Suppression key format for deduplication.
# Keys are formatted as ``{prefix}:{recipe_name}:{identity}`` where
# ``{prefix}`` is ``signal`` or ``endpoint``.
SUPPRESSION_KEY_PREFIX_SIGNAL = "signal"
SUPPRESSION_KEY_PREFIX_ENDPOINT = "endpoint"

# Decision outcome constants for recipe routing.
RECIPE_DECISION_RUN_RECIPE = "run_recipe"
RECIPE_DECISION_DIRECT_SWARM = "direct_swarm"
RECIPE_DECISION_DEFER = "defer"

RECIPE_DECISION_OUTCOMES = {
    RECIPE_DECISION_RUN_RECIPE,
    RECIPE_DECISION_DIRECT_SWARM,
    RECIPE_DECISION_DEFER,
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

