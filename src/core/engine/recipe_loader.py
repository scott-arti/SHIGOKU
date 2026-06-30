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

        Args:
            context: Execution context dict, expected to contain
                ``takeover_candidates`` (List[TakeoverCandidate]).
            scope_policy: Optional ``TakeoverScopePolicy`` for per-target
                scope blocking. Default ``None`` is permissive (all
                targets allowed).

        Returns a list of ``RecipeCandidate`` (may be empty).
        """
        results: List[RecipeCandidate] = []
        takeover_candidates: List[TakeoverCandidate] = context.get(
            "takeover_candidates", []
        )

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

            if trigger_type == "signal":
                # ── signal-based matching (takeover / provider recipes) ──
                required = _normalise_signal_list(trigger.get("required_signals", []))
                blocking = set(_normalise_signal_list(trigger.get("blocking_signals", [])))

                if not required and not blocking:
                    # No signal constraints → match unconditionally
                    results.append(RecipeCandidate(recipe=recipe))
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

                    rc = RecipeCandidate(
                        recipe=recipe,
                        score=score,
                        reasons=sorted(required),
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
                        },
                        manual_review_required=(
                            candidate.manual_claim_review_required or
                            bool(signals.get("manual_claim_review_required"))
                        ),
                        # recipe trigger conditions (plan 3.1, 4.4)
                        success_condition=trigger.get("success_condition"),
                        stop_condition=trigger.get("stop_condition"),
                    )
                    results.append(rc)

            else:
                # ── backward-compatible unconditional match ──────────────
                results.append(RecipeCandidate(recipe=recipe))

        return results


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
