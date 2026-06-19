

import yaml
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Dict, Any, Optional

from src.core.engine.recipe_contracts import (
    validate_recipe_schema,
    RecipeCandidate,
    AttackSurfaceSignal,
    ALLOWED_RECIPE_STEP_ACTIONS,
    RECIPE_SIGNAL_VOCABULARY,
)

logger = logging.getLogger(__name__)

# ---- Signal detection helpers ----

# Known auth-related URL patterns
_AUTH_URL_PATTERNS = re.compile(
    r'(?:/login|/signin|/auth|/oauth|/callback|/refresh'
    r'|/session|/me|/settings|/account|/profile'
    r'|/register|/signup|/logout|/token|/jwt'
    r'|/admin|/manage|/api/admin|/dashboard'
    r')',
    re.IGNORECASE,
)

_JWT_TOKEN_PATTERN = re.compile(
    r'^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
)

# ---- Signal definition: name -> detector function ----
# A detector receives the context dict and returns True/False.
_SIGNAL_DETECTORS: Dict[str, Callable[[dict], bool]] = {}


def _register_signal(name: str):
    """Decorator to register a signal detector function."""
    def decorator(fn):
        _SIGNAL_DETECTORS[name] = fn
        return fn
    return decorator


@_register_signal("bearer_token")
def _detect_bearer_token(ctx: dict) -> bool:
    token = ctx.get("bearer_token") or ""
    return bool(str(token).strip())


@_register_signal("session_cookie")
def _detect_session_cookie(ctx: dict) -> bool:
    cookies = ctx.get("cookies") or ""
    return bool(str(cookies).strip())


@_register_signal("login_endpoint")
def _detect_login_endpoint(ctx: dict) -> bool:
    urls = ctx.get("discovered_urls") or []
    for url in urls:
        if _AUTH_URL_PATTERNS.search(str(url)):
            return True
    # Also check auth_surface_metadata
    meta = ctx.get("auth_surface_metadata") or {}
    if meta.get("has_login_endpoint"):
        return True
    return False


@_register_signal("oauth_endpoint")
def _detect_oauth_endpoint(ctx: dict) -> bool:
    urls = ctx.get("discovered_urls") or []
    for url in urls:
        url_str = str(url).lower()
        if "/oauth" in url_str or "/callback" in url_str:
            return True
    meta = ctx.get("auth_surface_metadata") or {}
    oauth_eps = meta.get("oauth_endpoints") or []
    if oauth_eps:
        return True
    return False


@_register_signal("jwt_pattern")
def _detect_jwt_pattern(ctx: dict) -> bool:
    token = ctx.get("bearer_token") or ""
    if _JWT_TOKEN_PATTERN.match(str(token).strip()):
        return True
    meta = ctx.get("auth_surface_metadata") or {}
    if meta.get("jwt_detected"):
        return True
    # Check auth_headers for JWT (Bearer prefix を strip してマッチ)
    headers = ctx.get("auth_headers") or {}
    for val in headers.values():
        raw = str(val).strip()
        # 「Bearer eyJ...」形式の場合、prefix を除去してからマッチ
        if raw.lower().startswith("bearer "):
            raw = raw[7:].strip()
        if _JWT_TOKEN_PATTERN.match(raw):
            return True
    return False


@_register_signal("admin_endpoint")
def _detect_admin_endpoint(ctx: dict) -> bool:
    urls = ctx.get("discovered_urls") or []
    for url in urls:
        url_str = str(url).lower()
        if "/admin" in url_str or "/manage" in url_str or "/dashboard" in url_str:
            return True
    return False


@_register_signal("refresh_endpoint")
def _detect_refresh_endpoint(ctx: dict) -> bool:
    urls = ctx.get("discovered_urls") or []
    for url in urls:
        url_str = str(url).lower()
        if "/refresh" in url_str:
            return True
    return False


@_register_signal("graphql_endpoint")
def _detect_graphql_endpoint(ctx: dict) -> bool:
    urls = ctx.get("discovered_urls") or []
    for url in urls:
        url_str = str(url).lower()
        if "/graphql" in url_str:
            return True
    return False


@_register_signal("auth_related_capability")
def _detect_auth_related_capability(ctx: dict) -> bool:
    """Detect auth-related capability from JS files, query params, etc."""
    js_files = ctx.get("js_files") or []
    auth_keywords = ["auth", "jwt", "oauth", "token", "session", "role", "permission"]
    for js in js_files:
        js_str = str(js).lower()
        if any(kw in js_str for kw in auth_keywords):
            return True

    params = ctx.get("query_params") or []
    for p in params:
        p_str = str(p).lower()
        if any(kw in p_str for kw in ["redirect_uri", "client_id", "token", "state", "nonce"]):
            return True

    return False


# ---- Dataclasses ----

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
    # Step 1: New schema fields
    required_signals: List[str] = field(default_factory=list)
    optional_signals: List[str] = field(default_factory=list)
    stages: List[Dict[str, Any]] = field(default_factory=list)
    success_signals: List[Dict[str, Any]] = field(default_factory=list)
    failure_signals: List[Dict[str, Any]] = field(default_factory=list)
    stop_conditions: List[str] = field(default_factory=list)
    evidence_policy: Dict[str, Any] = field(default_factory=dict)
    priority: int = 50
    # Step 3: Attack surface / vulnerability tags for selection scoring
    tags: List[str] = field(default_factory=list)
    severity: str = "medium"
    # Runtime: set by match_recipes_to_context
    _match_score: int = field(default=0, repr=False)
    # Step 5: Lifecycle tracking
    _loaded_at: Optional[datetime] = field(default=None, repr=False)
    _last_matched_at: Optional[datetime] = field(default=None, repr=False)

    def get_required_signals(self) -> List[str]:
        return self.required_signals

    def get_optional_signals(self) -> List[str]:
        return self.optional_signals

    def get_supported_actions(self) -> set:
        """Return the set of action names this recipe's steps use."""
        return {s.action for s in self.steps if s.action}

    def has_allowlisted_actions(self) -> bool:
        """Check that all step actions are in the allowed set."""
        actions = self.get_supported_actions()
        return actions.issubset(ALLOWED_RECIPE_STEP_ACTIONS)


class RecipeLoader:
    # Base score for a recipe that matches all required signals
    BASE_MATCH_SCORE = 10
    # Points per matched optional signal
    OPTIONAL_SIGNAL_SCORE = 1
    # Default top-N limit
    DEFAULT_TOP_N = 5
    # Default minimum score threshold
    DEFAULT_MIN_SCORE = 0

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

            # Step 1: Parse new schema fields from trigger section
            trigger_data = data.get("trigger") or {}
            required_signals = trigger_data.get("required_signals") or []
            optional_signals = trigger_data.get("optional_signals") or []

            # Step 1: Parse stages
            stages = data.get("stages") or []

            recipe = Recipe(
                name=name,
                description=data.get("description", ""),
                agent=data.get("agent", "universal"),
                trigger=trigger_data,
                raw_data=data,
                steps=steps,
                required_signals=list(required_signals),
                optional_signals=list(optional_signals),
                stages=list(stages),
                success_signals=data.get("success_signals") or [],
                failure_signals=data.get("failure_signals") or [],
                stop_conditions=data.get("stop_conditions") or [],
                evidence_policy=data.get("evidence_policy") or {},
                priority=int(data.get("priority", 50) or 50),
                # Step 3: Parse attack surface / vulnerability tags
                tags=list(data.get("tags", [])) if isinstance(data.get("tags"), list) else [],
                severity=str(data.get("severity", "medium") or "medium"),
            )

            # Validate against new schema (non-fatal: logs warning on failure)
            schema_result = validate_recipe_schema(data)
            if not schema_result["ok"]:
                logger.warning(
                    "Recipe %s schema validation warnings: %s",
                    name,
                    schema_result.get("errors", []),
                )

            self.recipes[name] = recipe
            recipe._loaded_at = datetime.utcnow()
            logger.info("Loaded recipe: %s from %s (priority=%d)", name, filepath, recipe.priority)

        except Exception as e:
            logger.error("Failed to load recipe %s: %s", filepath, e)
            raise

    def match_recipes_to_context(
        self,
        context: Dict[str, Any],
        top_n: Optional[int] = None,
        min_score: Optional[int] = None,
    ) -> List[RecipeCandidate]:
        """Score-based recipe matching against execution context.

        Each recipe is scored based on:
        - Base score (BASE_MATCH_SCORE) if all required_signals are present
        - +OPTIONAL_SIGNAL_SCORE per matched optional_signal
        - +TAG_MATCH_SCORE per recipe tag found in context signals
        - Priority bonus: (priority / 100) * BASE_MATCH_SCORE

        Recipes are excluded if:
        - Any required_signal is missing
        - Any step action is not in ALLOWED_RECIPE_STEP_ACTIONS (with reason logged)
        - Score is below min_score threshold

        Results are sorted by descending score and limited to top_n.

        Args:
            context: Dict with target_info fields (bearer_token, cookies,
                     discovered_urls, auth_headers, auth_surface_metadata, etc.)
            top_n: Max candidates to return (default: DEFAULT_TOP_N)
            min_score: Minimum score threshold (default: DEFAULT_MIN_SCORE)

        Returns:
            Scored and sorted list of RecipeCandidate objects with reasons.
        """
        from datetime import datetime

        top_n = top_n if top_n is not None else self.DEFAULT_TOP_N
        min_score = min_score if min_score is not None else self.DEFAULT_MIN_SCORE

        candidates: List[RecipeCandidate] = []

        for recipe in self.recipes.values():
            score, reasons, optional_matched = self._score_recipe(recipe, context)
            if score is None:
                continue  # required signals missing or allowlist violation
            if score < min_score:
                continue

            # Step 5: Track recipe match timestamp for lifecycle management
            recipe._match_score = score
            recipe._last_matched_at = datetime.utcnow()

            # Step 3: Build supporting context for decision trace
            supporting_context = self._build_supporting_context(recipe, context, optional_matched)

            recipe._match_score = score
            candidates.append(RecipeCandidate(
                recipe_name=recipe.name,
                score=score,
                reasons=reasons,
                required_signals=recipe.get_required_signals(),
                optional_signals_matched=list(optional_matched),
                supporting_context=supporting_context,
                selection_timestamp=datetime.utcnow(),
                signal_ids=[],  # Will be populated when consuming AttackSurfaceSignal
            ))

        # Sort by score descending, then priority (via recipe lookup) descending
        candidates.sort(key=lambda c: (c.score, self.recipes.get(c.recipe_name, Recipe(name="", description="", agent="")).priority), reverse=True)

        return candidates[:top_n]

    def _build_supporting_context(
        self,
        recipe: Recipe,
        context: Dict[str, Any],
        optional_matched: List[str],
    ) -> Dict[str, Any]:
        """Build supporting context dict for RecipeCandidate.

        Includes contextual information that helps explain why this recipe
        was selected and provides decision trace data for the conductor.
        """
        ctx: Dict[str, Any] = {}

        # Include recipe metadata relevant to the selection
        ctx["recipe_priority"] = recipe.priority
        ctx["recipe_severity"] = recipe.severity
        ctx["recipe_tags"] = list(recipe.tags)

        # Include matched signal details
        if optional_matched:
            ctx["optional_signals_matched"] = list(optional_matched)

        # Include tag overlap between recipe tags and context
        context_tags = set()
        for key in ("tech_stack", "discovered_urls"):
            val = context.get(key, [])
            if isinstance(val, list):
                for item in val:
                    context_tags.add(str(item).lower())

        recipe_tag_set = {t.lower() for t in recipe.tags}
        tag_overlap = recipe_tag_set & context_tags
        if tag_overlap:
            ctx["tag_overlap"] = sorted(tag_overlap)

        # Include allowlist validation result
        ctx["all_actions_allowlisted"] = recipe.has_allowlisted_actions()
        ctx["supported_actions"] = sorted(recipe.get_supported_actions())

        return ctx

    # Step 3: Tag match score bonus
    TAG_MATCH_SCORE = 2

    def _score_recipe(
        self, recipe: Recipe, context: Dict[str, Any]
    ) -> tuple:
        """Compute match score for a recipe against the context.

        Returns (score, reasons, optional_matched) or (None, [], []) if:
        - Required signals are not satisfied
        - Recipe step actions are not allowlisted
        """
        required = recipe.get_required_signals()
        optional = recipe.get_optional_signals()

        reasons: List[str] = []
        optional_matched: List[str] = []

        # Step 3: Check allowlist (exclude recipes with unsupported actions)
        if not recipe.has_allowlisted_actions():
            unsupported = recipe.get_supported_actions() - ALLOWED_RECIPE_STEP_ACTIONS
            logger.debug(
                "Recipe %s excluded: unsupported actions %s",
                recipe.name, unsupported,
            )
            return (None, [f"UNSUPPORTED_ACTIONS: {sorted(unsupported)}"], [])

        # Check required signals (ALL must match)
        missing_required: List[str] = []
        for sig in required:
            if not self._detect_signal(sig, context):
                missing_required.append(sig)

        if missing_required:
            return (None, [f"MISSING_REQUIRED_SIGNALS: {missing_required}"], [])

        # Base score
        score = self.BASE_MATCH_SCORE
        reasons.append(f"BASE_SCORE({self.BASE_MATCH_SCORE}): all {len(required)} required signals matched")

        # Optional signal bonus
        for sig in optional:
            if self._detect_signal(sig, context):
                score += self.OPTIONAL_SIGNAL_SCORE
                optional_matched.append(sig)
        if optional_matched:
            reasons.append(f"OPTIONAL_SIGNALS({len(optional_matched)}): {optional_matched}")

        # Step 3: Tag-based scoring
        # Match recipe tags against context signals / tech stack / discovered data
        context_signal_set: set = set()
        for key in ("tech_stack",):
            val = context.get(key, [])
            if isinstance(val, list):
                for item in val:
                    context_signal_set.add(str(item).lower())
        # Also include signal names that were detected
        for sig_name in RECIPE_SIGNAL_VOCABULARY:
            if self._detect_signal(sig_name, context):
                context_signal_set.add(sig_name.lower())

        recipe_tag_lower = {t.lower() for t in recipe.tags}
        tag_overlap = recipe_tag_lower & context_signal_set
        if tag_overlap:
            tag_bonus = len(tag_overlap) * self.TAG_MATCH_SCORE
            score += tag_bonus
            reasons.append(f"TAG_MATCH({len(tag_overlap)} tags: {sorted(tag_overlap)}, +{tag_bonus})")

        # Priority bonus
        priority = getattr(recipe, "priority", 50) or 50
        priority_bonus = int((priority / 100.0) * self.BASE_MATCH_SCORE)
        score += priority_bonus
        reasons.append(f"PRIORITY_BONUS(priority={priority}, +{priority_bonus})")

        return (score, reasons, optional_matched)

    def _detect_signal(self, signal_name: str, context: Dict[str, Any]) -> bool:
        """Detect a named signal in the context using registered detectors.

        Falls back to checking context keys directly if no detector is registered.
        """
        detector = _SIGNAL_DETECTORS.get(signal_name)
        if detector is not None:
            try:
                return bool(detector(context))
            except Exception as e:
                logger.debug("Signal detector %s failed: %s", signal_name, e)
        return False

    # ====================================================================
    # Step 5: Recipe lifecycle management (SGK-2026-0260)
    # ====================================================================
    # Rules:
    #   1. Recipes are loaded once and retained for the session.
    #   2. Each call to match_recipes_to_context() produces a fresh per-run
    #      candidate set — previously matched candidates do NOT accumulate.
    #   3. Recipes not matched recently (stale beyond TTL) may be unloaded
    #      to prevent irrelevant YAML from polluting candidate pools.
    #   4. unload_recipe() removes a recipe from memory entirely.
    #   5. clear_session() resets match timestamps without unloading recipes.
    # ====================================================================

    # Default staleness TTL in seconds (24 hours = 86400)
    RECIPE_STALENESS_TTL_SECONDS = 86400

    def unload_recipe(self, name: str) -> bool:
        """Remove a recipe from the loaded set.

        Use for recipes that are no longer relevant to the current target
        or have been superseded by newer versions.

        Returns True if the recipe was unloaded, False if not found.
        """
        if name in self.recipes:
            del self.recipes[name]
            logger.info("Unloaded recipe: %s", name)
            return True
        return False

    def clear_session(self) -> None:
        """Reset match timestamps for all loaded recipes.

        Does NOT unload recipes — only clears the lifecycle tracking state.
        Use between runs on different targets to ensure freshness tracking
        is per-target.
        """
        for recipe in self.recipes.values():
            recipe._last_matched_at = None
            recipe._match_score = 0
        logger.info("Cleared session state for %d recipes", len(self.recipes))

    def get_stale_recipes(self, ttl_seconds: Optional[int] = None) -> List[str]:
        """Return names of recipes not matched within the staleness TTL.

        Args:
            ttl_seconds: Maximum age since last match (default: RECIPE_STALENESS_TTL_SECONDS).

        Returns:
            List of recipe names that are considered stale.
        """
        ttl = ttl_seconds if ttl_seconds is not None else self.RECIPE_STALENESS_TTL_SECONDS
        now = datetime.utcnow()
        stale: List[str] = []
        for name, recipe in self.recipes.items():
            if recipe._last_matched_at is None:
                # Never matched — consider based on load time
                if recipe._loaded_at is not None:
                    age = (now - recipe._loaded_at).total_seconds()
                    if age > ttl:
                        stale.append(name)
            else:
                age = (now - recipe._last_matched_at).total_seconds()
                if age > ttl:
                    stale.append(name)
        return stale

    def unload_stale_recipes(self, ttl_seconds: Optional[int] = None) -> int:
        """Unload all recipes not matched within the staleness TTL.

        Returns the number of recipes unloaded.
        """
        stale = self.get_stale_recipes(ttl_seconds)
        for name in stale:
            self.unload_recipe(name)
        if stale:
            logger.info("Unloaded %d stale recipes: %s", len(stale), stale)
        return len(stale)

    def recipe_count(self) -> int:
        """Return the number of currently loaded recipes."""
        return len(self.recipes)

    def get_loaded_recipe_names(self) -> List[str]:
        """Return names of all currently loaded recipes."""
        return sorted(self.recipes.keys())

        # Fallback: check if signal_name appears as a truthy key in context
        val = context.get(signal_name)
        if val is not None:
            if isinstance(val, bool):
                return val
            if isinstance(val, (list, dict, str)):
                return bool(val)
            return True

        return False