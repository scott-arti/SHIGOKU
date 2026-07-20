"""
TaskPruningPolicy: decision engine for retiring/superseding/invalidating
pending tasks that are no longer needed.

SGK-2026-0287: Steps 1-3 (data model, shadow mode, conductor integration).
SGK-2026-0287 Steps 4-5: pruning_mode contract, single authority, fail-closed,
                         decision trace schema, reason_code mappings.
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
# pruning_mode resolution: single source of truth (SGK-2026-0287 Step 4-1)
# ────────────────────────────────────────────────────────────────────────────

VALID_PRUNING_MODES: Set[str] = {"shadow", "active"}


def resolve_pruning_mode(
    raw: Optional[str] = None,
    killswitch_enabled: bool = False,
) -> str:
    """Resolve the effective pruning mode from config.

    **This is the single authority for pruning_mode.**  Callers MUST NOT
    re-interpret ``shadow`` / ``active`` locally.

    Args:
        raw: Raw value from config (``settings.pruning_mode``).
             Any value outside ``{shadow, active}`` is fail-closed to ``shadow``.
        killswitch_enabled: If ``True``, the result is always ``shadow``.
            Candidate traces are still recorded; deletion count is guaranteed 0.

    Returns:
        ``"shadow"`` or ``"active"``.

    Session-level override contract (SGK-2026-0287 Step 4-2):
        - The **only** allowed configuration path is via the global config
          (``config/shigoku.yaml`` / ``SHIGOKU_PRUNING_MODE`` env var).
        - Session artifacts and resume paths MUST NOT override ``pruning_mode``.
        - On resume, the stored session mode is ignored; the current config
          value from ``resolve_pruning_mode()`` takes precedence.
    """
    if killswitch_enabled:
        logger.info("Pruning killswitch active — forcing shadow mode")
        return "shadow"

    mode = str(raw or "").strip().lower()
    if mode not in VALID_PRUNING_MODES:
        logger.warning(
            "Invalid pruning_mode %r; fail-closed to shadow", raw,
        )
        return "shadow"

    return mode


COVERAGE_CRITICAL_SOURCE_CATEGORIES: Set[str] = {
    "scenario_probe_planner",
    "scenario_probe_guard",
    "coverage_backfill",
    "coverage_backfill_guard",
    "tagged_meta_observability",
}

COVERAGE_CRITICAL_CATEGORIES: Set[str] = {
    "csrf_candidate",
    "meta_observability",
    "file_exposure_upload",
    "debug_info",
}

COVERAGE_CRITICAL_TAGS: Set[str] = {
    "manual_verify",
    "coverage_guard_forced",
}

SCN06_DATA_EXPOSURE_SCENARIO_ID = "scn_06_data_exposure_diff"

UNCAPPED_DERIVED_TASK_SOURCES: Set[str] = {
    "recon_result",
    "dynamic_recipe",
    "pending_fuzz",
}


def is_coverage_critical_task(task: Any) -> bool:
    params = getattr(task, "params", None)
    if not isinstance(params, dict):
        params = {}

    source_category = str(params.get("source_category", "") or "").strip().lower()
    if source_category in COVERAGE_CRITICAL_SOURCE_CATEGORIES:
        return True

    category = str(params.get("category", "") or "").strip().lower()
    if category in COVERAGE_CRITICAL_CATEGORIES:
        return True

    if str(params.get("scenario_id", "") or "").strip().lower() == SCN06_DATA_EXPOSURE_SCENARIO_ID:
        return True

    if params.get("scenario_probe"):
        return True

    if bool(params.get("_coverage_guard_forced", False)):
        return True

    tags = getattr(task, "tags", None) or []
    tags_lower = {str(tag).strip().lower() for tag in tags}
    if tags_lower & COVERAGE_CRITICAL_TAGS:
        return True

    task_name = str(getattr(task, "name", "") or "").upper()
    return task_name.startswith("SCN")


def should_apply_derived_task_limit(source: str) -> bool:
    normalized_source = str(source or "").strip().lower()
    return normalized_source not in UNCAPPED_DERIVED_TASK_SOURCES


# =============================================================================
# TaskPruningDecision
# =============================================================================

@dataclass
class TaskPruningDecision:
    """
    A single pruning decision for a task.

    Mandatory fields (SGK-2026-0287 Step 5-1):
        task_id: The task being considered for pruning.
        lifecycle_status: "retired" | "superseded" | "invalidated".
        reason_code: Machine-readable reason (see REASON_CODE_TO_REASONING).
        before_count: Queue size before pruning (from caller).
        after_count: Queue size after pruning (from caller).
        mode: "shadow" | "active" — effective pruning_mode at decision time.
        timestamp: When the decision was made.

    Optional fields:
        trigger_task_id: Task whose completion triggered this decision.
        trigger_event_id: Optional event that triggered this decision.
        evidence_key: Optional key for tracing back the evidence (e.g.
                      finding ID, snapshot version).
        finding_ids: Related finding IDs that informed this decision.
        protected: Whether this task is protected from actual deletion
                   (always True for shadow mode; may be False for active).
    """
    task_id: str
    lifecycle_status: str
    reason_code: str
    before_count: int = 0
    after_count: int = 0
    trigger_task_id: Optional[str] = None
    trigger_event_id: Optional[str] = None
    evidence_key: Optional[str] = None
    finding_ids: List[str] = field(default_factory=list)
    protected: bool = False
    mode: str = "shadow"
    timestamp: datetime = field(default_factory=datetime.now)

    # -- Backward-compat alias kept during migration --
    @property
    def shadow_only(self) -> bool:
        """True if mode == "shadow" (backward compat)."""
        return self.mode == "shadow"

    def to_dict(self) -> dict:
        """Serialize to a dict compatible with decision_traces sink."""
        return {
            "decision_type": f"task_{self.lifecycle_status}",
            "task_id": self.task_id,
            "lifecycle_status": self.lifecycle_status,
            "reason_code": self.reason_code,
            "trigger_task_id": self.trigger_task_id,
            "trigger_event_id": self.trigger_event_id,
            "evidence_key": self.evidence_key,
            "finding_ids": self.finding_ids,
            "protected": self.protected,
            "before_count": self.before_count,
            "after_count": self.after_count,
            "mode": self.mode,
            "shadow_only": self.shadow_only,
            "timestamp": self.timestamp.isoformat(),
        }


# =============================================================================
# Reason-code mapping (SGK-2026-0287 Step 5-2)
# =============================================================================

# Machine-readable reason_code  ->  Human-readable reasoning for reports.
# The report formatter reads ``reason_code`` from the decision dict and maps
# it through this table. Downstream consumers MUST NOT re-interpret reason_code
# outside of this mapping.
REASON_CODE_TO_REASONING: Dict[str, str] = {
    "duplicate": "Duplicate task (same agent_type + target + action); "
                 "lower-priority copy was pruned.",
    "out_of_scope": "Task targets an asset or URL that the scope parser "
                    "determined to be out-of-scope.",
    "chain_low_value": "Chain follow-up task superseded by existing findings; "
                       "no remaining attack value.",
    "stale_snapshot": "Task was based on a snapshot that is now outdated.",
    "chain_completed": "Parent chain task completed successfully; "
                       "follow-up is no longer needed.",
    "low_value_static_asset": "Task targets a static asset (image, font, etc.) "
                              "with negligible security value.",
    "protected_skip": "Task was a pruning candidate but protected from deletion "
                      "(coverage-critical or gate-essential).",
    "eval_failure_skip": "Pruning evaluation failed; deletion was stopped "
                         "(fail-closed in active mode).",
    "killswitch_active": "Pruning killswitch is enabled; "
                         "deletion suppressed, candidate recorded.",
    "unsupported_task_type": "Task type is not yet approved for active deletion; "
                             "observed in shadow mode.",
}


def get_reasoning(reason_code: str) -> str:
    """Return the human-readable reasoning for a reason_code.

    Falls back to the raw reason_code if no mapping exists.
    """
    return REASON_CODE_TO_REASONING.get(
        reason_code, f"Pruned (reason: {reason_code})"
    )


# =============================================================================
# TaskPruningPolicy
# =============================================================================

class TaskPruningPolicy:
    """
    Conservative task pruning policy.

    Initial implementation (SGK-2026-0287):
    - Shadow-only mode by default (no actual queue deletion).
    - Protected list prevents pruning of critical agent types.
    - Conservative rules: duplicates, out-of-scope, chain-low-value.

    Aggressive actual deletion is deferred to Phase 7 / SGK-2026-0287 step 4-6.
    """

    # Agent types that are NEVER candidates for pruning
    PROTECTED_AGENT_TYPES: Set[str] = {
        "scope_parser",
        "coverage_guard",
        "scenario_probe",
        "scenario_probe_planner",
        "scenario_probe_guard",
        "manual_verify",
        "report",
        "evidence",
    }

    # Tags that indicate out-of-scope
    OUT_OF_SCOPE_TAGS: Set[str] = {
        "out_of_scope",
        "scope_rejected",
    }

    # Task states that are in-flight (not candidates for pruning)
    IN_FLIGHT_STATES: Set[str] = {
        "running",
        "admitted",
        "waiting_dependency",
    }

    # SGK-2026-0287 Step 8-2: Low-value static asset heuristics
    # Tasks matching these patterns are candidates for pruning.
    LOW_VALUE_STATIC_EXTENSIONS: Set[str] = {
        ".jpg", ".jpeg", ".png", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".svg",
        ".mp4", ".webp", ".pdf", ".zip", ".gz", ".tar",
    }

    LOW_VALUE_EXCLUDE_PATTERNS: Set[str] = {
        "/node_modules/", "/static/javascript/", "/assets/images/",
        "jquery", "bootstrap", "font-awesome", "google-analytics",
    }

    # SGK-2026-0287 Step 8-3: Competition ordering.
    # When a task is eligible for both boosting and pruning, boost takes
    # priority. Tasks with priority at or above this threshold are treated
    # as boosted and excluded from pruning candidates. This prevents
    # a task being pruned after an earlier boost (boost runs first in
    # StrategyOptimizer.review_strategy, prune runs later in
    # _evaluate_pruning_policy).
    BOOST_PRIORITY_THRESHOLD: int = 200

    def __init__(self, mode: str = "shadow"):
        """
        Args:
            mode: Effective pruning mode from ``resolve_pruning_mode()``.
                  "shadow": record decisions only, no actual deletion.
                  "active": apply actual deletions (requires gate).
        """
        resolved = resolve_pruning_mode(raw=mode)
        self.mode = resolved

    # -- Backward compat --
    @property
    def shadow_only(self) -> bool:
        """True if mode == "shadow" (backward compat)."""
        return self.mode == "shadow"

    # ----------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------

    def evaluate(
        self,
        queue_snapshot: Any,
        completed_task: Optional[Any] = None,
        findings: Optional[List[Any]] = None,
    ) -> List[TaskPruningDecision]:
        """
        Evaluate the task queue for prune candidates.

        Args:
            queue_snapshot: The current task queue (or list of pending tasks).
            completed_task: A task that just completed (may trigger chain logic).
            findings: Recent findings (may invalidate certain tasks).

        Returns:
            List of TaskPruningDecision (shadow-only by default).
        """
        decisions: List[TaskPruningDecision] = []

        # Get pending tasks from queue
        pending_tasks = self._get_pending_tasks(queue_snapshot)
        if not pending_tasks:
            return decisions

        findings = findings or []

        # Filter out in-flight tasks (F3: running/admitted/waiting_dependency)
        pending_tasks = [t for t in pending_tasks if not self._is_in_flight(t)]

        # SGK-2026-0287 Step 8-3: Boost takes priority over prune.
        # Tasks with boosted priority are excluded from pruning candidates.
        pending_tasks = [t for t in pending_tasks if not self._is_boosted(t)]

        # Build a map for quick lookups
        task_map = {self._task_id(t): t for t in pending_tasks}

        # ---- Rule 1: Duplicate detection ----
        self._detect_duplicates(pending_tasks, task_map, decisions)

        # ---- Rule 2: Out-of-scope ----
        self._detect_out_of_scope(pending_tasks, decisions)

        # ---- Rule 3: Chain completed / low-value follow-up ----
        self._detect_chain_low_value(pending_tasks, completed_task, findings, decisions)

        # ---- Rule 4: Low-value static asset (SGK-2026-0287 Step 8-2) ----
        self._detect_low_value_static_asset(pending_tasks, decisions)

        return decisions

    # ----------------------------------------------------------------
    # Protected checks
    # ----------------------------------------------------------------

    def _is_protected(self, task: Any) -> bool:
        """
        Check if a task is protected from pruning.

        Protection criteria (OR):
        1. agent_type in PROTECTED_AGENT_TYPES
        2. task matches shared coverage-critical protection rules
        """
        agent_type = str(getattr(task, "agent_type", "") or "").strip().lower()
        if agent_type in self.PROTECTED_AGENT_TYPES:
            return True

        if is_coverage_critical_task(task):
            return True

        return False

    def _is_in_flight(self, task: Any) -> bool:
        """
        Check if a task is in-flight (running/admitted/waiting_dependency).
        In-flight tasks are excluded from pruning candidates (F3).
        """
        state = getattr(task, "state", None)
        if state is None:
            return False  # No state attribute → treat as pending
        state_str = str(getattr(state, "value", state) or "").strip().lower()
        return state_str in self.IN_FLIGHT_STATES

    def _is_boosted(self, task: Any) -> bool:
        """Check if a task's priority exceeds the boost threshold.

        SGK-2026-0287 Step 8-3: Boost takes priority over prune.
        Tasks boosted by ``StrategyOptimizer.boost_priority_for_assets()``
        (priority += 500) will exceed this threshold and be excluded from
        pruning.
        """
        return getattr(task, "priority", 0) >= self.BOOST_PRIORITY_THRESHOLD

    # ----------------------------------------------------------------
    # Private rule implementations
    # ----------------------------------------------------------------

    def _detect_duplicates(
        self,
        pending_tasks: List[Any],
        task_map: Dict[str, Any],
        decisions: List[TaskPruningDecision],
    ) -> None:
        """
        Rule 1: Detect duplicate tasks.
        Two tasks are duplicates if they share (agent_type, target, action)
        and one has strictly lower priority. The lower-priority one is
        marked as superseded.
        """
        # Group by dedupe key
        groups: Dict[str, List[Any]] = {}
        for t in pending_tasks:
            if self._is_protected(t):
                continue
            key = self._dedupe_key(t)
            if key:
                groups.setdefault(key, []).append(t)

        for key, tasks in groups.items():
            if len(tasks) < 2:
                continue
            # Sort by priority descending; keep highest, supersede rest
            tasks.sort(key=lambda t: getattr(t, "priority", 0), reverse=True)
            for t in tasks[1:]:
                decisions.append(TaskPruningDecision(
                    task_id=self._task_id(t),
                    lifecycle_status="superseded",
                    reason_code="duplicate",
                    evidence_key=f"dedupe:{key}",
                    protected=False,
                    mode=self.mode,
                ))

    def _detect_out_of_scope(
        self,
        pending_tasks: List[Any],
        decisions: List[TaskPruningDecision],
    ) -> None:
        """
        Rule 2: Detect out-of-scope tasks.
        Tasks with out_of_scope tags or params.out_of_scope=True.
        """
        for t in pending_tasks:
            if self._is_protected(t):
                continue

            params = getattr(t, "params", None) or {}
            tags = getattr(t, "tags", None) or []
            tags_lower = {str(tag).strip().lower() for tag in tags}

            is_oos = False
            if isinstance(params, dict) and params.get("out_of_scope"):
                is_oos = True
            if tags_lower & self.OUT_OF_SCOPE_TAGS:
                is_oos = True

            if is_oos:
                decisions.append(TaskPruningDecision(
                    task_id=self._task_id(t),
                    lifecycle_status="retired",
                    reason_code="out_of_scope",
                    evidence_key=None,
                    protected=False,
                    mode=self.mode,
                ))

    def _detect_chain_low_value(
        self,
        pending_tasks: List[Any],
        completed_task: Optional[Any],
        findings: List[Any],
        decisions: List[TaskPruningDecision],
    ) -> None:
        """
        Rule 3: Detect chain-completed / low-value follow-up tasks.
        Follow-up tasks generated by vulnerability chaining that are
        superseded by findings or completed exploration.

        F5 fix: Only retires a chaining task when there is a relevant
        finding that supersedes the task's parent_vuln_type.
        Without findings, chaining tasks are kept (they may still have value).
        """
        # Build a set of finding vuln_types that have been covered
        finding_vuln_types = set()
        for f in findings:
            if isinstance(f, dict) and f.get("vuln_type"):
                finding_vuln_types.add(str(f["vuln_type"]).strip().lower())
            elif hasattr(f, "vuln_type"):
                finding_vuln_types.add(str(getattr(f, "vuln_type", "")).strip().lower())

        for t in pending_tasks:
            if self._is_protected(t):
                continue

            params = getattr(t, "params", None) or {}
            if not isinstance(params, dict):
                continue

            generation_reason = str(params.get("generation_reason", "") or "").strip().lower()

            # Vulnerability chaining follow-up tasks are retired only when
            # a finding supersedes their parent vuln_type
            if generation_reason == "vulnerability_chaining":
                parent_vuln = str(params.get("parent_vuln_type", "") or "").strip().lower()
                # Only retire if a finding with the same vuln_type exists
                if parent_vuln and parent_vuln in finding_vuln_types:
                    priority = getattr(t, "priority", 0)
                    if priority <= 2:
                        decisions.append(TaskPruningDecision(
                            task_id=self._task_id(t),
                            lifecycle_status="retired",
                            reason_code="chain_low_value",
                            evidence_key=parent_vuln,
                            protected=False,
                            mode=self.mode,
                        ))

    def _detect_low_value_static_asset(
        self,
        pending_tasks: List[Any],
        decisions: List[TaskPruningDecision],
    ) -> None:
        """Rule 4: Detect tasks targeting low-value static assets.

        Tasks whose target URL ends with a known static extension or
        matches a low-value exclude pattern are candidates for pruning.
        Duplicate base-path variants (query-param diffs) are also
        flagged when not tagged as injection/auth/logic.

        SGK-2026-0287 Step 8-2: This rule was migrated from
        ``StrategyOptimizer._identify_low_value_assets()``.
        """
        already_decided: Set[str] = {d.task_id for d in decisions}
        seen_paths: Set[str] = set()
        for t in pending_tasks:
            if self._is_protected(t):
                continue

            tid = self._task_id(t)
            if tid in already_decided:
                continue

            target = str(getattr(t, "target", "") or "").strip().lower()
            if not target:
                continue

            # Check static extension
            if any(target.endswith(ext) for ext in self.LOW_VALUE_STATIC_EXTENSIONS):
                decisions.append(TaskPruningDecision(
                    task_id=self._task_id(t),
                    lifecycle_status="retired",
                    reason_code="low_value_static_asset",
                    evidence_key=target,
                    protected=False,
                    mode=self.mode,
                ))
                continue

            # Check exclude patterns
            if any(pat in target for pat in self.LOW_VALUE_EXCLUDE_PATTERNS):
                decisions.append(TaskPruningDecision(
                    task_id=self._task_id(t),
                    lifecycle_status="retired",
                    reason_code="low_value_static_asset",
                    evidence_key=target,
                    protected=False,
                    mode=self.mode,
                ))
                continue

            # Duplicate base-path check (query param variants)
            base_path = target.split("?")[0]
            if base_path in seen_paths:
                tags = getattr(t, "tags", None) or []
                if not any(tag in tags for tag in ["injection", "auth", "logic"]):
                    decisions.append(TaskPruningDecision(
                        task_id=self._task_id(t),
                        lifecycle_status="retired",
                        reason_code="low_value_static_asset",
                        evidence_key=base_path,
                        protected=False,
                        mode=self.mode,
                    ))
                    continue
            seen_paths.add(base_path)

    # ----------------------------------------------------------------
    # Utility helpers
    # ----------------------------------------------------------------

    @staticmethod
    def _task_id(task: Any) -> str:
        return str(getattr(task, "id", "unknown"))

    @staticmethod
    def _get_pending_tasks(queue_snapshot: Any) -> List[Any]:
        """Extract pending tasks from a queue snapshot."""
        if hasattr(queue_snapshot, "get_all"):
            return queue_snapshot.get_all()
        if hasattr(queue_snapshot, "to_list"):
            return queue_snapshot.to_list()
        if isinstance(queue_snapshot, list):
            return queue_snapshot
        return []

    @staticmethod
    def _dedupe_key(task: Any) -> Optional[str]:
        """Build a deduplication key from agent_type + target + action."""
        agent_type = str(getattr(task, "agent_type", "") or "").strip().lower()
        target = str(getattr(task, "target", "") or "").strip().lower()
        action = str(getattr(task, "action", "") or "").strip().lower()
        if not agent_type or not target or not action:
            return None
        return f"{agent_type}|{target}|{action}"
