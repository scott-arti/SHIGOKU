import pytest

from types import SimpleNamespace

from src.core.domain.model.task import Task
from src.core.engine.recipe_contracts import (
    validate_action_schema,
    validate_task_schema,
    validate_recipe_schema,
    validate_vdp_action_class,
    ALLOWED_RECIPE_STEP_ACTIONS,
    RECIPE_TO_SWARM_REASON_CODES,
    RECIPE_ADDITIVE_REASONS,
    RECIPE_SUPPRESSIVE_REASONS,
    RECIPE_FOLLOW_UP_REASONS,
    RECIPE_DECISION_OUTCOMES,
    SUPPRESSION_KEY_PREFIX_SIGNAL,
    SUPPRESSION_KEY_PREFIX_ENDPOINT,
    RECIPE_DECISION_RUN_RECIPE,
    RECIPE_DECISION_DIRECT_SWARM,
    RECIPE_DECISION_DEFER,
    VDP_ACTION_CLASSES,
    VDP_RISK_CLASSES,
    VDP_STOP_CONDITIONS,
    VDP_SCOPE_VERDICTS,
    VDP_REASON_CODES,
)
from src.core.engine.recipe_loader import Recipe, RecipeStep


def test_validate_action_schema_accepts_known_action():
    result = validate_action_schema("scan")
    assert result["ok"] is True
    assert result["error"] == ""


def test_validate_action_schema_rejects_unknown_action():
    result = validate_action_schema("unknown_action")
    assert result["ok"] is False
    assert result["error"] == "unsupported_action:unknown_action"


def test_validate_action_schema_accepts_check_takeover():
    """check_takeover must be in the allowlist for takeover v2 recipe support."""
    result = validate_action_schema("check_takeover")
    assert result["ok"] is True, f"check_takeover should be allowed; got {result['error']}"


def test_validate_action_schema_accepts_dns_check():
    result = validate_action_schema("dns_check")
    assert result["ok"] is True


def test_validate_action_schema_rejects_empty_action():
    result = validate_action_schema("")
    assert result["ok"] is False
    assert "unsupported_action" in result["error"]


def test_validate_action_schema_with_custom_allowed():
    result = validate_action_schema("custom_op", allowed=["custom_op", "standard"])
    assert result["ok"] is True


def test_validate_task_schema_requires_core_fields():
    task = SimpleNamespace(id="", name="", agent_type="", action="", params={})
    result = validate_task_schema(task)
    assert result["ok"] is False
    assert "missing:id" in result["errors"]
    assert "missing:name" in result["errors"]
    assert "missing:agent_type" in result["errors"]
    assert "missing:action" in result["errors"]


# ── validate_recipe_schema (new) ────────────────────────────────────────

def test_validate_recipe_schema_rejects_zero_steps():
    recipe = Recipe(name="r", description="d", agent="swarm", steps=[])
    result = validate_recipe_schema(recipe)
    assert result["ok"] is False
    assert "zero_steps" in result["error"]


def test_validate_recipe_schema_rejects_unsupported_step_action():
    recipe = Recipe(
        name="r", description="d", agent="swarm",
        steps=[RecipeStep(id="s1", name="Bad", action="not_allowed")],
    )
    result = validate_recipe_schema(recipe)
    assert result["ok"] is False
    assert "unsupported_action" in result["error"]


def test_validate_recipe_schema_accepts_valid_recipe():
    recipe = Recipe(
        name="r", description="d", agent="swarm",
        steps=[RecipeStep(id="s1", name="Good", action="scan")],
    )
    result = validate_recipe_schema(recipe)
    assert result["ok"] is True
    assert result["error"] == ""


def test_validate_recipe_schema_reports_multiple_unsupported_actions():
    recipe = Recipe(
        name="r", description="d", agent="swarm",
        steps=[
            RecipeStep(id="s1", name="Bad1", action="not_allowed_1"),
            RecipeStep(id="s2", name="Bad2", action="not_allowed_2"),
        ],
    )
    result = validate_recipe_schema(recipe)
    assert result["ok"] is False
    assert "unsupported_action" in result["error"]
    assert "not_allowed_1" in result["error"]
    assert "not_allowed_2" in result["error"]


def test_validate_recipe_schema_validates_check_takeover_action():
    """check_takeover must pass recipe-level validation."""
    recipe = Recipe(
        name="takeover", description="d", agent="swarm",
        steps=[RecipeStep(id="s1", name="Check", action="check_takeover")],
    )
    result = validate_recipe_schema(recipe)
    assert result["ok"] is True, f"check_takeover recipe should pass; got {result['error']}"


# ── SGK-2026-0259: auth recipe schema validation ─────────────────────

def test_validate_auth_recipe_schema_passes_for_valid_step_actions():
    """Auth recipe with allowed actions (auth_attack, scan, analyze, report) passes."""
    recipe = Recipe(
        name="session_invariant",
        description="Auth recipe",
        agent="swarm",
        steps=[
            RecipeStep(id="s1", name="Probe Auth", action="auth_attack"),
            RecipeStep(id="s2", name="Scan Surface", action="scan"),
            RecipeStep(id="s3", name="Analyze Results", action="analyze"),
            RecipeStep(id="s4", name="Report Finding", action="report"),
        ],
    )
    result = validate_recipe_schema(recipe)
    assert result["ok"] is True, f"Auth recipe validation failed: {result['error']}"


def test_validate_auth_recipe_schema_rejects_unsupported_actions():
    """Auth recipe with step action alg_none fails validation."""
    recipe = Recipe(
        name="jwt_alg_none",
        description="Auth recipe with unsupported action",
        agent="swarm",
        steps=[
            RecipeStep(id="s1", name="Alg None Check", action="alg_none"),
        ],
    )
    result = validate_recipe_schema(recipe)
    assert result["ok"] is False
    assert "unsupported_action" in result["error"]
    assert "alg_none" in result["error"]


def test_validate_auth_recipe_schema_rejects_redirect_bypass_action():
    """Auth recipe with step action redirect_bypass fails validation."""
    recipe = Recipe(
        name="oauth_redirect_bypass",
        description="Auth recipe with redirect_bypass action",
        agent="swarm",
        steps=[
            RecipeStep(id="s1", name="Redirect Bypass", action="redirect_bypass"),
        ],
    )
    result = validate_recipe_schema(recipe)
    assert result["ok"] is False
    assert "unsupported_action" in result["error"]
    assert "redirect_bypass" in result["error"]


def test_validate_auth_recipe_rejects_zero_steps():
    """Auth recipe with empty steps list fails schema validation."""
    recipe = Recipe(
        name="oauth_binding_drift",
        description="Auth recipe with no steps",
        agent="swarm",
        steps=[],
    )
    result = validate_recipe_schema(recipe)
    assert result["ok"] is False
    assert "zero_steps" in result["error"]


def test_validate_all_auth_recipe_names_schema_pass():
    """All 7 auth recipe names pass schema validation with valid steps."""
    auth_recipe_names = [
        "oauth_binding_drift",
        "session_invariant",
        "jwt_claim_enforcement",
        "refresh_rotation",
        "jwt_alg_none",
        "oauth_token_leak",
        "oauth_redirect_bypass",
    ]
    for name in auth_recipe_names:
        recipe = Recipe(
            name=name,
            description=f"Auth recipe: {name}",
            agent="swarm",
            steps=[
                RecipeStep(id="probe", name="Probe", action="auth_attack"),
                RecipeStep(id="confirm", name="Confirm", action="scan", dependencies=["probe"]),
                RecipeStep(id="report", name="Report", action="report", dependencies=["confirm"]),
            ],
        )
        result = validate_recipe_schema(recipe)
        assert result["ok"] is True, f"Auth recipe {name} failed validation: {result['error']}"


# ── VDP hypothesis vocabulary (SGK-2026-0420, public) ────────────────


def test_vdp_action_classes_contains_4_values():
    assert VDP_ACTION_CLASSES == {
        "follow_up_probe",
        "re_evaluate",
        "manual_review",
        "terminal",
    }


def test_vdp_risk_classes_contains_3_values():
    assert VDP_RISK_CLASSES == {
        "read_only",
        "state_changing",
        "out_of_band",
    }


def test_validate_vdp_action_class_accepts_known():
    result = validate_vdp_action_class("follow_up_probe")
    assert result["ok"] is True
    assert result["normalized"] == "follow_up_probe"
    assert result["allowed"] is True
    assert result["reason"] == ""


def test_validate_vdp_action_class_rejects_unknown():
    result = validate_vdp_action_class("unknown_action")
    assert result["ok"] is False
    assert result["normalized"] == "unknown_action"
    assert result["allowed"] is False
    assert "unknown_action" in result["reason"]


def test_validate_vdp_action_class_rejects_empty():
    result = validate_vdp_action_class("")
    assert result["ok"] is False
    assert result["normalized"] == ""
    assert result["allowed"] is False
    assert "unknown action_class" in result["reason"].lower()


def test_validate_vdp_action_class_rejects_none():
    result = validate_vdp_action_class(None)
    assert result["ok"] is False
    assert result["normalized"] == ""
    assert result["allowed"] is False


def test_validate_vdp_action_class_accepts_all_known():
    for action in VDP_ACTION_CLASSES:
        result = validate_vdp_action_class(action)
        assert result["ok"] is True, f"{action!r} should be valid; got {result['reason']}"


def test_vdp_stop_conditions_contains_fixed_strings():
    assert VDP_STOP_CONDITIONS == {
        "evidence_gap_resolved_or_budget_exhausted",
        "scope_revalidation_blocked",
        "no_follow_up_needed",
        "max_retries_exceeded",
    }


def test_vdp_scope_verdicts_contains_fixed_strings():
    assert VDP_SCOPE_VERDICTS == {
        "allowed",
        "out_of_scope",
        "redirect_out_of_scope",
        "scope_revalidation_blocked",
    }


def test_vdp_reason_codes_contains_fixed_strings():
    assert VDP_REASON_CODES == {
        "label_leakage_detected",
        "scope_revalidation_blocked",
        "duplicate_dedup_key",
        "diversity_budget_exceeded",
        "no_observations",
        "generator_exception",
        "budget_estimate_missing",
        "generated_candidate",
    }


# ── Existing constants unchanged (guardrail) ─────────────────────────


def test_existing_recipe_constants_unchanged():
    """Existing constants must remain identical after VDP vocabulary addition."""
    assert ALLOWED_RECIPE_STEP_ACTIONS == {
        "recon", "scan", "report", "execute", "auth_attack",
        "sqli_scan", "xss_scan", "run", "analyze", "verify_scope",
        "parallel_recon", "check_takeover", "dns_check",
        "cname_resolve", "http_probe", "takeover_scan",
    }

    assert RECIPE_TO_SWARM_REASON_CODES == {
        "manual_review_required", "no_recipe_match", "low_confidence",
        "unsupported_action", "suppression_active", "previous_run_exists",
        "scope_blocked",
    }

    assert RECIPE_ADDITIVE_REASONS == {
        "fresh_signal", "high_confidence", "nearby_finding_confirms",
        "nearby_auth_surface", "nearby_endpoint_corroborates",
        "tech_stack_match", "high_freshness_score",
        "previous_recipe_succeeded", "multi_label_match",
    }

    assert RECIPE_SUPPRESSIVE_REASONS == {
        "stale_signal", "low_confidence", "previous_recipe_run_exists",
        "previous_recipe_failed", "nearby_finding_mitigated",
        "unsupported_step_action", "blocking_signal_present",
        "signal_manual_review", "kg_context_stale", "suppression_key_active",
    }

    assert RECIPE_FOLLOW_UP_REASONS == {
        "new_signal_discovered", "adjacent_endpoint_exposed",
        "evidence_insufficient", "recipe_partial_success", "recipe_failed",
        "recommend_specialized_swarm", "recommend_manual_review",
        "recommend_deepened_recipe", "no_follow_up_needed",
        "recipe_completed_cleanly", "recipe_completely_blocked",
    }

    assert RECIPE_DECISION_OUTCOMES == {"run_recipe", "direct_swarm", "defer"}
    assert SUPPRESSION_KEY_PREFIX_SIGNAL == "signal"
    assert SUPPRESSION_KEY_PREFIX_ENDPOINT == "endpoint"
    assert RECIPE_DECISION_RUN_RECIPE == "run_recipe"
    assert RECIPE_DECISION_DIRECT_SWARM == "direct_swarm"
    assert RECIPE_DECISION_DEFER == "defer"
