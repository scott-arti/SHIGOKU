"""
TaskPruningPolicy: shadow decision engine for retiring/superseding/invalidating
pending tasks that are no longer needed.

SGK-2026-0287 Step 1: Minimal data model + shadow mode.
Phase 6 will connect decisions to DecisionType enum and decision_traces sink.
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# =============================================================================
# TaskPruningDecision
# =============================================================================

@dataclass
class TaskPruningDecision:
    """
    A single pruning decision for a task.

    Fields:
        task_id: The task being considered for pruning.
        lifecycle_status: "retired" | "superseded" | "invalidated".
        reason_code: Machine-readable reason (e.g. "duplicate", "out_of_scope",
                     "stale_snapshot", "chain_completed", "chain_low_value").
        trigger_event_id: Optional event that triggered this decision.
        evidence_key: Optional key for tracing back the evidence (e.g.
                      finding ID, snapshot version).
        protected: Whether this task is protected from actual deletion.
        timestamp: When the decision was made.
        shadow_only: True = record only, do not remove from queue.
    """
    task_id: str
    lifecycle_status: str
    reason_code: str
    trigger_event_id: Optional[str] = None
    evidence_key: Optional[str] = None
    protected: bool = False
    timestamp: datetime = field(default_factory=datetime.now)
    shadow_only: bool = True

    def to_dict(self) -> dict:
        """Serialize to a dict compatible with decision_traces sink."""
        return {
            "decision_type": f"task_{self.lifecycle_status}",
            "task_id": self.task_id,
            "lifecycle_status": self.lifecycle_status,
            "reason_code": self.reason_code,
            "trigger_event_id": self.trigger_event_id,
            "evidence_key": self.evidence_key,
            "protected": self.protected,
            "timestamp": self.timestamp.isoformat(),
            "shadow_only": self.shadow_only,
        }


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

    # Source categories in params that indicate protection
    PROTECTED_SOURCE_CATEGORIES: Set[str] = {
        "scenario_probe_planner",
        "scenario_probe_guard",
        "coverage_backfill",
        "coverage_backfill_guard",
    }

    # Tags that indicate protection
    PROTECTED_TAGS: Set[str] = {
        "manual_verify",
        "coverage_guard_forced",
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

    def __init__(self, shadow_only: bool = True):
        """
        Args:
            shadow_only: If True, only record decisions; do not delete.
        """
        self.shadow_only = shadow_only

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

        # Build a map for quick lookups
        task_map = {self._task_id(t): t for t in pending_tasks}

        # ---- Rule 1: Duplicate detection ----
        self._detect_duplicates(pending_tasks, task_map, decisions)

        # ---- Rule 2: Out-of-scope ----
        self._detect_out_of_scope(pending_tasks, decisions)

        # ---- Rule 3: Chain completed / low-value follow-up ----
        self._detect_chain_low_value(pending_tasks, completed_task, findings, decisions)

        return decisions

    # ----------------------------------------------------------------
    # Protected checks
    # ----------------------------------------------------------------

    def _is_protected(self, task: Any) -> bool:
        """
        Check if a task is protected from pruning.

        Protection criteria (OR):
        1. agent_type in PROTECTED_AGENT_TYPES
        2. params.source_category in PROTECTED_SOURCE_CATEGORIES
        3. tags contain manual_verify or coverage_guard_forced
        4. params.scenario_probe is truthy
        5. params._coverage_guard_forced is truthy
        6. Task name starts with "SCN"
        """
        agent_type = str(getattr(task, "agent_type", "") or "").strip().lower()
        if agent_type in self.PROTECTED_AGENT_TYPES:
            return True

        params = getattr(task, "params", None) or {}
        if isinstance(params, dict):
            source_cat = str(params.get("source_category", "") or "").strip().lower()
            if source_cat in self.PROTECTED_SOURCE_CATEGORIES:
                return True
            if params.get("scenario_probe"):
                return True
            if bool(params.get("_coverage_guard_forced", False)):
                return True

        tags = getattr(task, "tags", None) or []
        tags_lower = {str(t).strip().lower() for t in tags}
        if tags_lower & self.PROTECTED_TAGS:
            return True

        task_name = str(getattr(task, "name", "") or "").upper()
        if task_name.startswith("SCN"):
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
                    shadow_only=self.shadow_only,
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
                    shadow_only=self.shadow_only,
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
                            shadow_only=self.shadow_only,
                        ))

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
