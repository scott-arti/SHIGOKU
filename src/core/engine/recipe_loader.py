import yaml
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from src.core.policy.takeover_scope_policy import TakeoverScopePolicy

logger = logging.getLogger(__name__)


# ── Core dataclasses ─────────────────────────────────────────────────────

@dataclass
class RecipeStep:
    id: str
    name: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)


@dataclass
class Recipe:
    name: str
    description: str
    agent: str
    steps: List[RecipeStep] = field(default_factory=list)
    trigger: Dict[str, Any] = field(default_factory=dict)
    raw_data: Dict[str, Any] = field(default_factory=dict)


# ── Takeover candidate schema (plan 4.5) ────────────────────────────────

@dataclass
class TakeoverCandidate:
    """Normalized takeover candidate modeled after plan section 4.5.

    This is the single source of truth flowing from recon/dead_subs
    into the recipe selector and eventual recipe execution.
    """
    subdomain: str
    candidate_id: str
    observed_at: datetime
    first_seen_dead: datetime
    last_seen_dead: datetime
    cname_chain: List[str] = field(default_factory=list)
    provider_guess: Optional[str] = None
    freshness_score: float = 0.0
    required_signals: Dict[str, bool] = field(default_factory=dict)
    blocking_signals: Set[str] = field(default_factory=set)
    raw_evidence: Dict[str, Any] = field(default_factory=dict)
    manual_claim_review_required: bool = False
    # optional probe timestamps
    last_dns_probe: Optional[datetime] = None
    last_http_probe: Optional[datetime] = None
    # trace metadata (plan 4.10)
    source_line: Optional[str] = None
    producer_step: Optional[str] = None
    session_id: Optional[str] = None
    artifact_hash: Optional[str] = None


# ── RecipeCandidate: selector output (plan 4.5) ─────────────────────────

@dataclass
class RecipeCandidate:
    """A recipe that matched the current context with scoring metadata.

    Replaces the former bare ``List[Recipe]`` return from
    ``match_recipes_to_context`` so that callers can trace *why* a recipe
    was selected and what signals supported the decision.
    """
    recipe: Recipe
    score: float = 0.0
    reasons: List[str] = field(default_factory=list)
    required_signals: Dict[str, bool] = field(default_factory=dict)
    supporting_evidence: Dict[str, Any] = field(default_factory=dict)
    manual_review_required: bool = False
    # recipe trigger conditions (plan 3.1, 4.4)
    success_condition: Optional[str] = None
    stop_condition: Optional[str] = None
    # ── SGK-2026-0260: suppression / allowlist ───────────────────────────
    suppressed: bool = False
    suppression_reason: Optional[str] = None


# ── Freshness helpers ────────────────────────────────────────────────────

_STALE_THRESHOLD_DAYS = 30
_STALE_PENALTY_DAYS = 7


def compute_freshness_score(
    first_seen_dead: Optional[datetime],
    last_seen_dead: Optional[datetime],
    last_dns_probe: Optional[datetime] = None,
    last_http_probe: Optional[datetime] = None,
    now: Optional[datetime] = None,
) -> float:
    """Compute a 0.0–1.0 freshness score for a dead-subdomain candidate.

    Rules (conservative, per plan section 4.5):
      - ``now - last_seen_dead <= 7 days`` → score >= 0.9
      - ``now - last_seen_dead > 30 days`` → score < 0.2
      - stale probe timestamps further reduce score
      - None or missing dates → 0.0 (no data = no confidence)
    """
    if now is None:
        now = datetime.now(timezone.utc)

    if first_seen_dead is None or last_seen_dead is None:
        return 0.0

    # Ensure timezone-aware for safe subtraction
    def _utc(dt: datetime) -> datetime:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    first = _utc(first_seen_dead)
    last = _utc(last_seen_dead)

    # Base score from last_seen_dead recency
    age_days = (now - last).total_seconds() / 86400.0
    if age_days <= _STALE_PENALTY_DAYS:
        base = max(0.9, 1.0 - age_days * 0.01)  # 0.9–1.0 for ≤ 7 days
    elif age_days <= _STALE_THRESHOLD_DAYS:
        base = 0.9 - (age_days - _STALE_PENALTY_DAYS) * 0.03  # linear decay
    else:
        base = max(0.05, 0.2 - (age_days - _STALE_THRESHOLD_DAYS) * 0.005)

    base = max(0.0, min(1.0, base))

    # Penalise stale probe timestamps
    probe_penalty = 0.0
    for probe_ts in (last_dns_probe, last_http_probe):
        if probe_ts is not None:
            probe_age = (now - _utc(probe_ts)).total_seconds() / 86400.0
            if probe_age > _STALE_PENALTY_DAYS:
                probe_penalty += min(0.4, (probe_age - _STALE_PENALTY_DAYS) * 0.02)

    return round(max(0.0, base - probe_penalty), 4)


def extract_signals(candidate: TakeoverCandidate) -> Dict[str, Any]:
    """Derive a flat signal dict from a ``TakeoverCandidate``.

    Used by the recipe selector to match against
    ``trigger.required_signals`` and ``trigger.blocking_signals``.
    """
    signals: Dict[str, Any] = {}

    signals["subdomain"] = candidate.subdomain
    signals["candidate_id"] = candidate.candidate_id

    # freshness
    signals["freshness_score"] = compute_freshness_score(
        first_seen_dead=candidate.first_seen_dead,
        last_seen_dead=candidate.last_seen_dead,
        last_dns_probe=candidate.last_dns_probe,
        last_http_probe=candidate.last_http_probe,
    )

    # dns_dead: any candidate that was ever seen dead
    signals["dns_dead"] = candidate.first_seen_dead is not None

    # cname_dangling: has a CNAME chain pointing to a potential target
    signals["cname_dangling"] = bool(candidate.cname_chain)

    # provider_match: provider was fingerprinted
    signals["provider_match"] = candidate.provider_guess is not None
    if candidate.provider_guess:
        signals["provider"] = candidate.provider_guess

    # manual review flag
    signals["manual_claim_review_required"] = candidate.manual_claim_review_required

    # merge any candidate-supplied signals
    if candidate.required_signals:
        signals.update(candidate.required_signals)

    # propagate blocking signals so selector can filter them
    for bs in candidate.blocking_signals:
        signals[bs] = True

    return signals


def extract_attack_surface_signal_map(signal: Dict[str, Any]) -> Dict[str, Any]:
    """Derive a flat selector signal map from an AttackSurfaceSignal-like dict.

    The recon signal bundle uses structured fields (`entity_type`,
    `candidate_labels`, `auth_context`, `params`). Recipe matching still
    operates on flat `required_signals` names, so this helper normalizes the
    structured signal into recipe-friendly boolean flags.
    """
    normalized: Dict[str, Any] = {}

    entity_type = str(signal.get("entity_type", "") or "").strip()
    if entity_type:
        normalized[entity_type] = True
        normalized[f"entity_type.{entity_type}"] = True

    primary_label = str(signal.get("primary_label", "") or "").strip()
    if primary_label:
        normalized[primary_label] = True
        normalized[f"label.{primary_label}"] = True

    labels = signal.get("candidate_labels", [])
    if isinstance(labels, list):
        for label in labels:
            label_name = str(label or "").strip()
            if not label_name:
                continue
            normalized[label_name] = True
            normalized[f"label.{label_name}"] = True

    auth_required = signal.get("auth_required")
    if auth_required is not None:
        normalized["auth_required"] = bool(auth_required)

    auth_context = signal.get("auth_context", {})
    if isinstance(auth_context, dict):
        for key, value in auth_context.items():
            key_name = str(key or "").strip()
            if not key_name:
                continue
            normalized[key_name] = bool(value)
            normalized[f"auth_context.{key_name}"] = bool(value)

    params = signal.get("params", [])
    if isinstance(params, list) and params:
        normalized["has_params"] = True
        for param in params:
            if not isinstance(param, dict):
                continue
            location = str(param.get("location", "") or "").strip()
            if location:
                normalized[f"param_location.{location}"] = True
            name = str(param.get("name", "") or "").strip()
            if name:
                normalized[f"param.{name}"] = True

    source_observations = signal.get("source_observations", [])
    if isinstance(source_observations, list):
        for source in source_observations:
            source_name = str(source or "").strip()
            if source_name:
                normalized[f"source.{source_name}"] = True

    status = str(signal.get("status", "") or "").strip()
    if status:
        normalized[f"status.{status}"] = True

    confidence = signal.get("confidence")
    if isinstance(confidence, (int, float)):
        normalized["confidence"] = float(confidence)

    return normalized


# ── RecipeLoader ─────────────────────────────────────────────────────────

class RecipeLoader:
    def __init__(self):
        self.recipes: Dict[str, Recipe] = {}

    def load_recipe(self, filepath: str) -> None:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            name = data.get("name", "unnamed_recipe")

            steps_data = data.get("steps", [])
            steps = []
            for i, s in enumerate(steps_data):
                steps.append(RecipeStep(
                    id=s.get("id", f"step_{i}"),
                    name=s.get("name", f"Step {i}"),
                    action=s.get("action", ""),
                    params=s.get("params", {}),
                    dependencies=s.get("dependencies", [])
                ))

            recipe = Recipe(
                name=name,
                description=data.get("description", ""),
                agent=data.get("agent", "universal"),
                trigger=data.get("trigger", {}),
                raw_data=data,
                steps=steps
            )

            # ── Pre-selection schema validation ──────────────────────────
            from src.core.engine.recipe_contracts import validate_recipe_schema
            validation = validate_recipe_schema(recipe)
            if not validation["ok"]:
                raise ValueError(
                    f"Recipe '{name}' failed schema validation: {validation['error']}"
                )

            self.recipes[name] = recipe
            logger.info("Loaded recipe: %s from %s", name, filepath)

        except Exception as e:
            logger.error("Failed to load recipe %s: %s", filepath, e)
            raise

    def match_recipes_to_context(
        self,
        context: Dict[str, Any],
        scope_policy: Optional["TakeoverScopePolicy"] = None,
        *,
        kg_context: Optional[Dict[str, Any]] = None,
        active_suppression_keys: Optional[Set[str]] = None,
    ) -> List[RecipeCandidate]:
        """Match loaded recipes against the execution context using signal-based selection.

        Selection rules:
          - Recipes with ``trigger.type == "signal"`` are matched against
            ``context["takeover_candidates"]``. They are selected only when
            every entry in ``trigger.required_signals`` is present and truthy
            in the candidate's derived signal map AND no entry in
            ``trigger.blocking_signals`` is present.
          - If ``scope_policy`` is provided, candidates for targets where
            ``is_takeover_allowed`` returns False are skipped entirely
            BEFORE any signal evaluation (plan sections 3.3, 3.4.3, 4.5).
          - Recipes with any other trigger type (or none) are matched
            unconditionally with score 0.0 (backward-compatible behaviour).
          - The same recipe may yield multiple ``RecipeCandidate`` objects
            for different takeover candidates.
          - SGK-2026-0260: Recipes with unsupported step actions are
            reported as suppressed with reason ``unsupported_action``.
          - SGK-2026-0260: active_suppression_keys blocks re-execution
            per (recipe_name, signal_identity).

        Args:
            context: Execution context dict, expected to contain
                ``takeover_candidates`` (List[TakeoverCandidate]) and/or
                ``attack_surface_signals`` (List[Dict]).
            scope_policy: Optional ``TakeoverScopePolicy`` for per-target
                scope blocking. Default ``None`` is permissive (all
                targets allowed).
            kg_context: Optional KnowledgeGraph context dict for score
                enrichment and suppression checks (SGK-2026-0260).
            active_suppression_keys: Optional set of suppression keys to
                block re-execution (SGK-2026-0260).

        Returns a list of ``RecipeCandidate`` (may be empty).
        """
        results: List[RecipeCandidate] = []
        takeover_candidates: List[TakeoverCandidate] = context.get(
            "takeover_candidates", []
        )
        attack_surface_signals: List[Dict[str, Any]] = context.get(
            "attack_surface_signals",
            context.get("endpoint_signals", []),
        )
        active_suppression_keys = active_suppression_keys or set()

        # ── Early scope-policy filtering (plan 3.3, 3.4.3, 4.5) ─────────
        if scope_policy is not None:
            from src.core.policy.takeover_scope_policy import evaluate_scope_signals

            filtered: List[TakeoverCandidate] = []
            for candidate in takeover_candidates:
                scope_signals = evaluate_scope_signals(
                    candidate.subdomain, scope_policy
                )
                if scope_signals["scope_policy_blocks_takeover"]:
                    # Propagate scope blocking signal to candidate
                    candidate.blocking_signals.add("scope_policy_blocks_takeover")
                    continue  # skip — scope blocks this candidate
                filtered.append(candidate)
            takeover_candidates = filtered

        for recipe in self.recipes.values():
            trigger = recipe.trigger or {}
            trigger_type = str(trigger.get("type", "")).strip().lower()

            # ── SGK-2026-0260: action allowlist pre-check ────────────────
            allowlist_check = check_recipe_action_allowlist(recipe)
            recipe_actions_ok = allowlist_check["ok"]
            unsupported_actions = allowlist_check["unsupported_actions"]

            if trigger_type == "signal":
                # ── signal-based matching (takeover / provider recipes) ──
                required = _normalise_signal_list(trigger.get("required_signals", []))
                blocking = set(_normalise_signal_list(trigger.get("blocking_signals", [])))

                if not required and not blocking:
                    # No signal constraints → match unconditionally
                    rc = RecipeCandidate(recipe=recipe)
                    if not recipe_actions_ok:
                        rc.suppressed = True
                        rc.suppression_reason = (
                            "unsupported_action:" + ",".join(unsupported_actions)
                        )
                    results.append(rc)
                    continue

                for candidate in takeover_candidates:
                    signals = extract_signals(candidate)

                    # Check blocking signals first
                    if _any_signal_present(blocking, signals):
                        continue  # blocked → skip

                    # Check required signals
                    matched, missing = _check_required_signals(required, signals)
                    if not matched:
                        continue

                    # Compute score from signal match ratio × freshness
                    signal_ratio = len(required) / max(len(required), 1)
                    freshness = signals.get("freshness_score", 0.0)
                    score = round(signal_ratio * freshness, 4)

                    # ── SGK-2026-0260: KG enrichment ─────────────────
                    signal_map_for_kg = signals.copy()
                    signal_map_for_kg["_recipe_name"] = recipe.name
                    kg_score, kg_additive, kg_suppressive = (
                        _enrich_score_with_kg_context(score, signal_map_for_kg, kg_context)
                    )

                    # ── SGK-2026-0260: reasons construction ──────────
                    candidate_reasons = sorted(required)
                    if freshness >= 0.9:
                        candidate_reasons.append("fresh_signal")
                    candidate_reasons.extend(kg_additive)
                    suppressive_notes: List[str] = list(kg_suppressive)
                    candidate_suppressed = False
                    suppression_reason: Optional[str] = None

                    if not recipe_actions_ok:
                        score = max(0.0, score - 0.3)
                        suppressive_notes.append("unsupported_step_action")
                        candidate_suppressed = True
                        suppression_reason = "unsupported_action:" + ",".join(unsupported_actions)

                    # ── SGK-2026-0260: suppression key check ────────
                    if not candidate_suppressed:
                        signal_key = candidate.candidate_id or candidate.subdomain
                        if is_recipe_suppressed(
                            active_suppression_keys, recipe.name, signal_key,
                            also_check_endpoint=candidate.subdomain,
                        ):
                            candidate_suppressed = True
                            suppression_reason = "suppression_key_active"

                    rc = RecipeCandidate(
                        recipe=recipe,
                        score=round(max(0.0, min(1.0, score + kg_score - score)), 4)
                        if kg_additive or kg_suppressive else score,
                        reasons=candidate_reasons + suppressive_notes,
                        required_signals={k: bool(signals.get(k)) for k in required},
                        supporting_evidence={
                            "candidate_id": candidate.candidate_id,
                            "subdomain": candidate.subdomain,
                            "freshness_score": freshness,
                            "provider_guess": candidate.provider_guess,
                            # trace metadata (plan 4.10)
                            "producer_step": candidate.producer_step,
                            "session_id": candidate.session_id,
                            "source_line": candidate.source_line,
                            "artifact_hash": candidate.artifact_hash,
                            # SGK-2026-0260: KG enrichment trace
                            "_kg_additive_reasons": kg_additive,
                            "_kg_suppressive_reasons": kg_suppressive,
                            "_kg_adjusted_score": kg_score,
                        },
                        manual_review_required=(
                            candidate.manual_claim_review_required or
                            bool(signals.get("manual_claim_review_required"))
                        ),
                        success_condition=trigger.get("success_condition"),
                        stop_condition=trigger.get("stop_condition"),
                        suppressed=candidate_suppressed,
                        suppression_reason=suppression_reason,
                    )
                    results.append(rc)

                for signal in attack_surface_signals:
                    if not isinstance(signal, dict):
                        continue

                    signal_map = extract_attack_surface_signal_map(signal)

                    if _any_signal_present(blocking, signal_map):
                        continue

                    matched, missing = _check_required_signals(required, signal_map)
                    if not matched:
                        continue

                    confidence = float(signal.get("confidence", 0.0) or 0.0)
                    score = round(max(0.0, min(1.0, confidence)), 4)

                    # ── SGK-2026-0260: KG enrichment ─────────────────
                    signal_map_for_kg = signal_map.copy()
                    signal_map_for_kg["_recipe_name"] = recipe.name
                    signal_map_for_kg["entity_type"] = signal.get("entity_type", "")
                    kg_score, kg_additive, kg_suppressive = (
                        _enrich_score_with_kg_context(score, signal_map_for_kg, kg_context)
                    )

                    # ── SGK-2026-0260: reasons construction ──────────
                    candidate_reasons = sorted(required)
                    if confidence >= 0.9:
                        candidate_reasons.append("high_confidence")
                    candidate_reasons.extend(kg_additive)
                    suppressive_notes: List[str] = list(kg_suppressive)
                    candidate_suppressed = False
                    suppression_reason: Optional[str] = None

                    if not recipe_actions_ok:
                        score = max(0.0, score - 0.3)
                        suppressive_notes.append("unsupported_step_action")
                        candidate_suppressed = True
                        suppression_reason = "unsupported_action:" + ",".join(unsupported_actions)

                    # ── SGK-2026-0260: suppression key check ────────
                    if not candidate_suppressed:
                        signal_id = str(signal.get("signal_id", "") or "").strip()
                        signal_url = str(signal.get("url", "") or "").strip()
                        signal_identity = signal_id or signal_url
                        if signal_identity and is_recipe_suppressed(
                            active_suppression_keys, recipe.name, signal_identity,
                            also_check_endpoint=signal_url if signal_url else None,
                        ):
                            candidate_suppressed = True
                            suppression_reason = "suppression_key_active"

                    rc = RecipeCandidate(
                        recipe=recipe,
                        score=round(max(0.0, min(1.0, score + kg_score - score)), 4)
                        if kg_additive or kg_suppressive else score,
                        reasons=candidate_reasons + suppressive_notes,
                        required_signals={k: bool(signal_map.get(k)) for k in required},
                        supporting_evidence={
                            "signal_id": signal.get("signal_id"),
                            "url": signal.get("url", ""),
                            "method": signal.get("method", "GET"),
                            "entity_type": signal.get("entity_type", ""),
                            "primary_label": signal.get("primary_label", ""),
                            "candidate_labels": list(signal.get("candidate_labels", [])),
                            "why_suspicious": signal.get("why_suspicious", ""),
                            "source_observations": list(signal.get("source_observations", [])),
                            "confidence": confidence,
                            "params": list(signal.get("params", [])),
                            # SGK-2026-0260: KG enrichment trace
                            "_kg_additive_reasons": kg_additive,
                            "_kg_suppressive_reasons": kg_suppressive,
                            "_kg_adjusted_score": kg_score,
                        },
                        manual_review_required=(
                            str(signal.get("status", "") or "").strip() == "needs_swarm_review"
                        ),
                        success_condition=trigger.get("success_condition"),
                        stop_condition=trigger.get("stop_condition"),
                        suppressed=candidate_suppressed,
                        suppression_reason=suppression_reason,
                    )
                    results.append(rc)

            else:
                # ── backward-compatible unconditional match ──────────────
                rc = RecipeCandidate(recipe=recipe)
                if not recipe_actions_ok:
                    rc.suppressed = True
                    rc.suppression_reason = (
                        "unsupported_action:" + ",".join(unsupported_actions)
                    )
                results.append(rc)

        return results


# ── Allowlist filtering (SGK-2026-0260) ──────────────────────────────────


def check_recipe_action_allowlist(
    recipe: "Recipe",
    *,
    allowed: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Check whether every step action in *recipe* is in the action allowlist.

    Returns a dict with:
      - ``ok`` (bool): True when every action is allowed.
      - ``unsupported_actions`` (List[str]): disallowed action names found.
      - ``error`` (str): empty when ok, else a concatenated reason note.
    """
    if allowed is None:
        from src.core.engine.recipe_contracts import ALLOWED_RECIPE_STEP_ACTIONS
        allowed = ALLOWED_RECIPE_STEP_ACTIONS

    allowed_set = {str(a).strip() for a in allowed}
    unsupported: List[str] = []
    for step in recipe.steps:
        action = str(step.action or "").strip()
        if action and action not in allowed_set:
            unsupported.append(action)

    ok = len(unsupported) == 0
    error = ""
    if not ok:
        error = "unsupported_actions:" + ",".join(sorted(set(unsupported)))
    return {
        "ok": ok,
        "unsupported_actions": sorted(set(unsupported)),
        "error": error,
    }


# ── Suppression key helpers (SGK-2026-0260) ──────────────────────────────


def build_suppression_key(
    recipe_name: str,
    signal_identity: str,
    *,
    prefix: str = "signal",
) -> str:
    """Build a standard suppression key for recipe deduplication.

    Format: ``{prefix}:{recipe_name}:{signal_identity}``

    *prefix* should be ``"signal"`` or ``"endpoint"`` (use
    ``SUPPRESSION_KEY_PREFIX_SIGNAL`` / ``SUPPRESSION_KEY_PREFIX_ENDPOINT``).
    """
    return f"{prefix}:{recipe_name}:{signal_identity}"


def is_recipe_suppressed(
    active_suppression_keys: Set[str],
    recipe_name: str,
    signal_identity: str,
    *,
    also_check_endpoint: Optional[str] = None,
) -> bool:
    """Return True when *recipe_name* + *signal_identity* (or endpoint) is
    present in *active_suppression_keys*."""
    signal_key = build_suppression_key(recipe_name, signal_identity)
    if signal_key in active_suppression_keys:
        return True
    if also_check_endpoint:
        ep_key = build_suppression_key(
            recipe_name, also_check_endpoint,
            prefix="endpoint",
        )
        if ep_key in active_suppression_keys:
            return True
    return False


# ── KG enrichment helpers (SGK-2026-0260) ────────────────────────────────


def _enrich_score_with_kg_context(
    base_score: float,
    signal_map: Dict[str, Any],
    kg_context: Optional[Dict[str, Any]],
) -> tuple[float, List[str], List[str]]:
    """Adjust *base_score* using KnowledgeGraph context and return
    (adjusted_score, additive_reasons, suppressive_reasons).

    *kg_context* is expected to be a dict with optional keys:
      - ``previous_recipe_runs``: List[str] of recipe names already run
      - ``previous_recipe_outcomes``: Dict[str, str] mapping recipe_name → outcome
      - ``nearby_findings``: List[Dict] of findings on adjacent endpoints
      - ``nearby_endpoints``: List[Dict] of endpoints near this signal
      - ``kg_freshness_score``: float (0.0–1.0) freshness from KG perspective
      - ``tech_stack_context``: Dict[str, Any] of tech stack KG data
    """
    from src.core.engine.recipe_contracts import (
        RECIPE_ADDITIVE_REASONS,
        RECIPE_SUPPRESSIVE_REASONS,
    )

    additive: List[str] = []
    suppressive: List[str] = []
    adjusted = base_score

    if not kg_context or not isinstance(kg_context, dict):
        return adjusted, additive, suppressive

    # ── KG freshness ─────────────────────────────────────────────────────
    kg_freshness = kg_context.get("kg_freshness_score")
    if isinstance(kg_freshness, (int, float)):
        ff = float(kg_freshness)
        if ff >= 0.8:
            adjusted += 0.1
            additive.append("high_freshness_score")
        elif ff < 0.3:
            adjusted -= 0.15
            suppressive.append("kg_context_stale")

    # ── Previous recipe runs ─────────────────────────────────────────────
    previous_runs = kg_context.get("previous_recipe_runs", [])
    previous_outcomes = kg_context.get("previous_recipe_outcomes", {})

    recipe_name = signal_map.get("_recipe_name", "")
    if isinstance(previous_runs, list) and recipe_name and recipe_name in previous_runs:
        outcome = previous_outcomes.get(recipe_name, "unknown")
        if outcome == "confirmed" or outcome == "success":
            adjusted += 0.05
            additive.append("previous_recipe_succeeded")
        else:
            adjusted -= 0.2
            suppressive.append("previous_recipe_run_exists")
            suppressive.append("previous_recipe_failed")

    # ── Nearby findings ──────────────────────────────────────────────────
    nearby_findings = kg_context.get("nearby_findings", [])
    if isinstance(nearby_findings, list) and nearby_findings:
        confirmed_nearby = any(
            isinstance(f, dict) and f.get("status") == "confirmed"
            for f in nearby_findings
        )
        if confirmed_nearby:
            adjusted += 0.1
            additive.append("nearby_finding_confirms")
        else:
            # mitigated or draft findings → slight penalty
            mitigated_nearby = any(
                isinstance(f, dict) and f.get("status") == "mitigated"
                for f in nearby_findings
            )
            if mitigated_nearby:
                adjusted -= 0.1
                suppressive.append("nearby_finding_mitigated")

    # ── Nearby endpoints ─────────────────────────────────────────────────
    nearby_endpoints = kg_context.get("nearby_endpoints", [])
    if isinstance(nearby_endpoints, list) and nearby_endpoints:
        auth_nearby = any(
            isinstance(ep, dict) and ep.get("surface_type") == "auth_surface"
            for ep in nearby_endpoints
        )
        if auth_nearby:
            adjusted += 0.05
            additive.append("nearby_auth_surface")

        same_surface = any(
            isinstance(ep, dict)
            and ep.get("surface_type")
            and signal_map.get("entity_type")
            and ep.get("surface_type") == signal_map.get("entity_type")
            for ep in nearby_endpoints
        )
        if same_surface:
            adjusted += 0.05
            additive.append("nearby_endpoint_corroborates")

    # ── Tech stack context ───────────────────────────────────────────────
    tech_ctx = kg_context.get("tech_stack_context", {})
    if isinstance(tech_ctx, dict):
        tech_keywords = set(
            str(k).lower() for k in tech_ctx.keys()
        )
        if tech_keywords:
            adjusted += 0.02
            additive.append("tech_stack_match")

    # Clamp and round
    adjusted = round(max(0.0, min(1.0, adjusted)), 4)
    return adjusted, additive, suppressive


# ── signal helpers (module-private) ──────────────────────────────────────

def _normalise_signal_list(raw: Any) -> List[str]:
    """Normalise a YAML signal list into a flat list of strings."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(s).strip() for s in raw if s is not None]
    return []


def _any_signal_present(signals: Set[str], signal_map: Dict[str, Any]) -> bool:
    """Return True if *any* of the named signals is present and truthy in ``signal_map``."""
    for sig in signals:
        value = signal_map.get(sig)
        if value is True or (isinstance(value, str) and value.strip()):
            return True
    return False


def _check_required_signals(
    required: List[str],
    signal_map: Dict[str, Any],
) -> tuple[bool, List[str]]:
    """Return (all_present, [missing_signals])."""
    missing = []
    for sig in required:
        value = signal_map.get(sig)
        ok = value is True or (isinstance(value, (int, float)) and value > 0)
        if not ok:
            missing.append(sig)
    return len(missing) == 0, missing
