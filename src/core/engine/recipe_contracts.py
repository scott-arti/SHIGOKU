from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from src.core.domain.model.task import Task


# ======================================================================
# Step 1: Signal Vocabulary — Recon → Recipe selection input contract
# ======================================================================
#
# Recipe plan (SGK-2026-0260) CONSUMES AttackSurfaceSignal from Recon plan
# (SGK-2026-0261).  Until the Recon-side implementation is complete,
# RecipeLoader uses its own _SIGNAL_DETECTORS to derive these signals from
# the context dict passed by MasterConductor._load_recipe_tasks().
#
# Correspondence table: Raw Recon source → Recipe-ready signal
# ┌──────────────────────────┬────────────────────────────────────────────┐
# │ Recipe-ready signal      │ Raw source in context dict                 │
# ├──────────────────────────┼────────────────────────────────────────────┤
# │ bearer_token             │ context["bearer_token"], auth_headers      │
# │ session_cookie           │ context["cookies"]                         │
# │ login_endpoint           │ discovered_urls, auth_surface_metadata     │
# │ oauth_endpoint           │ discovered_urls, auth_surface_metadata     │
# │ jwt_pattern              │ bearer_token, auth_surface_metadata,       │
# │                          │ auth_headers                               │
# │ admin_endpoint           │ discovered_urls                            │
# │ refresh_endpoint         │ discovered_urls                            │
# │ graphql_endpoint         │ discovered_urls                            │
# │ auth_related_capability  │ js_files, query_params                     │
# │ has_params               │ form_params or query_params non-empty      │
# │ has_forms                │ form_params with action URL                │
# │ api_endpoint             │ discovered_urls matching /api/,/v1/,/rest/  │
# │ web_socket               │ discovered_urls matching ws://, wss://     │
# └──────────────────────────┴────────────────────────────────────────────┘
#
# Future: when Recon plan implements AttackSurfaceSignal generation, the
# RecipeLoader will consume AttackSurfaceSignal objects directly instead of
# deriving signals from the raw context dict.

# All recipe-ready signal names that RecipeLoader can detect.
# Recipes reference these in trigger.required_signals / trigger.optional_signals.
RECIPE_SIGNAL_VOCABULARY: List[str] = [
    "bearer_token",
    "session_cookie",
    "login_endpoint",
    "oauth_endpoint",
    "jwt_pattern",
    "admin_endpoint",
    "refresh_endpoint",
    "graphql_endpoint",
    "auth_related_capability",
    "has_params",
    "has_forms",
    "api_endpoint",
    "web_socket",
]


@dataclass
class AttackSurfaceSignal:
    """Normalized attack surface signal (consumed by Recipe selection).

    Owned by Recon plan (SGK-2026-0261).  Recipe plan (SGK-2026-0260)
    consumes these as input to recipe candidate scoring.

    Until Recon implements this as a persisted entity, RecipeLoader
    derives equivalent boolean signals from the raw context dict.
    """
    signal_id: str
    entity_type: str                           # endpoint, parameter, auth_surface, workflow_surface, technology
    primary_label: str                         # Main classification (e.g. "login_endpoint")
    labels: List[str] = field(default_factory=list)  # Multi-label candidates
    confidence: int = 0                        # 0-100
    normalized_key: str = ""                   # Dedup key (url+method+param normalized)
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    seen_count: int = 0
    source_url: str = ""                       # Originating URL/endpoint
    source_method: str = "GET"
    evidence_summary: str = ""                 # Why this signal was raised
    kg_node_id: Optional[str] = None           # Link to KG node


@dataclass
class RecipeCandidate:
    """Selected recipe candidate with score, reasons, and context.

    Owned by Recipe plan (SGK-2026-0260).  Returned by RecipeLoader
    when matching signals to recipes.
    """
    recipe_name: str
    score: int
    reasons: List[str] = field(default_factory=list)
    required_signals: List[str] = field(default_factory=list)
    optional_signals_matched: List[str] = field(default_factory=list)
    supporting_context: Dict[str, Any] = field(default_factory=dict)
    # Decision metadata
    selection_timestamp: Optional[datetime] = None
    signal_ids: List[str] = field(default_factory=list)  # Which AttackSurfaceSignals triggered this


# ======================================================================
# Step 6: Follow-up routing contracts (SGK-2026-0260)
# ======================================================================

# Reasons a recipe execution may trigger follow-up swarm tasks
FOLLOW_UP_REASON_ADJACENT_SURFACE = "adjacent_attack_surface"    # New endpoint/param discovered
FOLLOW_UP_REASON_NEW_EVIDENCE = "new_evidence"                    # Recipe found additional evidence
FOLLOW_UP_REASON_BROAD_EXPANSION = "broad_expansion"              # Deterministic done, explore wider
FOLLOW_UP_REASON_STOP_CONDITION = "stop_condition"                # Halted early (rate_limit, waf_block)
FOLLOW_UP_REASON_INCONCLUSIVE = "inconclusive"                    # Recipe ran but verdict unclear

FOLLOW_UP_REASONS = [
    FOLLOW_UP_REASON_ADJACENT_SURFACE,
    FOLLOW_UP_REASON_NEW_EVIDENCE,
    FOLLOW_UP_REASON_BROAD_EXPANSION,
    FOLLOW_UP_REASON_STOP_CONDITION,
    FOLLOW_UP_REASON_INCONCLUSIVE,
]


@dataclass
class FollowUpDecision:
    """Decision to spawn a follow-up swarm task after recipe execution.

    Generated by OptimizedRecipeRunner when recipe execution produces
    evidence that warrants additional exploration.  Consumed by
    MasterConductor to create new swarm tasks.
    """
    reason: str                                  # One of FOLLOW_UP_REASONS
    suggested_action: str                        # E.g. "auth_attack", "sqli_scan", "xss_scan"
    suggested_tags: List[str] = field(default_factory=list)
    target_url: str = ""                         # The URL/endpoint to follow up on
    evidence_summary: str = ""                   # Why follow-up is recommended
    priority: int = 50                           # Suggested task priority
    source_recipe: str = ""                      # Which recipe generated this
    dedup_key: str = ""                          # Suppression key to prevent duplicates


# ======================================================================
# Step 7: Suppression / dedup contracts (SGK-2026-0260)
# ======================================================================

@dataclass
class SuppressionDecision:
    """Decision to suppress a recipe candidate or follow-up task.

    Owned partially by Recon plan (low-value suppression) and partially
    by Recipe plan (re-run suppression).
    """
    suppression_id: str                          # Unique ID for traceability
    reason_code: str                             # E.g. "low_value", "duplicate_run", "stale_signal"
    scope: str = "recipe_candidate"              # What is being suppressed
    created_at: Optional[datetime] = None
    source: str = "recipe"                       # "recon" or "recipe"
    details: str = ""                            # Human-readable explanation


# Recipe execution dedup key: encoded as "{recipe_name}:{target}:{normalized_param}"
RECIPE_DEDUP_KEY_SEPARATOR = ":"


def build_recipe_dedup_key(recipe_name: str, target: str, params: Optional[Dict[str, Any]] = None) -> str:
    """Build a deterministic dedup key for recipe execution suppression."""
    parts = [recipe_name, target]
    if params:
        # Include only stable param names (exclude tokens, timestamps)
        stable_keys = sorted(k for k in params if k not in ("token", "timestamp", "bearer_token", "cookies"))
        parts.append("|".join(f"{k}={params[k]}" for k in stable_keys if isinstance(params[k], (str, int, float, bool))))
    return RECIPE_DEDUP_KEY_SEPARATOR.join(parts)


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


# ======== Step 1: New Recipe schema validation ========

def validate_trigger_section(trigger: Any) -> Dict[str, Any]:
    """Validate a recipe's trigger section.

    Returns {"ok": bool, "error": str}
    """
    if not isinstance(trigger, dict):
        return {"ok": True, "error": ""}  # missing trigger is not an error

    errors: List[str] = []

    required = trigger.get("required_signals")
    if required is not None:
        if not isinstance(required, list):
            errors.append("required_signals must be a list")

    optional = trigger.get("optional_signals")
    if optional is not None:
        if not isinstance(optional, list):
            errors.append("optional_signals must be a list")

    if errors:
        return {"ok": False, "error": "; ".join(errors)}
    return {"ok": True, "error": ""}


def validate_stages_section(stages: Any) -> Dict[str, Any]:
    """Validate a recipe's stages section.

    Returns {"ok": bool, "error": str}
    """
    if not isinstance(stages, list):
        return {"ok": False, "error": "stages must be a list"}

    if len(stages) < 2:
        return {"ok": False, "error": "at least 2 stages required (e.g. probe -> confirm)"}

    errors: List[str] = []
    for i, stage in enumerate(stages):
        if not isinstance(stage, dict):
            errors.append(f"stage[{i}] must be a dict")
            continue
        if not stage.get("name"):
            errors.append(f"stage[{i}] missing name")
        if not stage.get("steps"):
            errors.append(f"stage[{i}] missing steps")
        min_success = stage.get("min_success", 1)
        if not isinstance(min_success, int) or min_success < 1:
            errors.append(f"stage[{i}] min_success must be a positive integer")

    if errors:
        return {"ok": False, "error": "; ".join(errors)}
    return {"ok": True, "error": ""}


def validate_evidence_policy(policy: Any) -> Dict[str, Any]:
    """Validate a recipe's evidence_policy section.

    Returns {"ok": bool, "error": str}
    """
    if not isinstance(policy, dict):
        return {"ok": True, "error": ""}

    errors: List[str] = []

    max_items = policy.get("max_items")
    if max_items is not None:
        if not isinstance(max_items, int) or max_items < 0:
            errors.append("max_items must be a non-negative integer")

    if errors:
        return {"ok": False, "error": "; ".join(errors)}
    return {"ok": True, "error": ""}


def validate_recipe_schema(recipe_data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a full recipe dictionary against the new schema.

    Checks required fields, trigger, stages, and evidence_policy.
    Returns {"ok": bool, "errors": list[str]}
    """
    errors: List[str] = []

    # Required top-level fields
    if not str(recipe_data.get("name", "") or "").strip():
        errors.append("missing:name")
    if not isinstance(recipe_data.get("steps"), list):
        errors.append("missing:steps or steps not a list")

    # Validate sub-sections
    trigger_result = validate_trigger_section(recipe_data.get("trigger", {}))
    if not trigger_result["ok"]:
        errors.append(f"trigger: {trigger_result['error']}")

    stages = recipe_data.get("stages")
    if stages is not None:
        stages_result = validate_stages_section(stages)
        if not stages_result["ok"]:
            errors.append(f"stages: {stages_result['error']}")

    evidence_policy = recipe_data.get("evidence_policy")
    if evidence_policy is not None:
        policy_result = validate_evidence_policy(evidence_policy)
        if not policy_result["ok"]:
            errors.append(f"evidence_policy: {policy_result['error']}")

    return {
        "ok": len(errors) == 0,
        "errors": errors,
    }

