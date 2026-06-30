"""
PostBatchFeedback dataclass: typed container for deferred shared-state mutations.

Phase 6 M3 (C3/FU-2): Replaces string-key dict with a typed @dataclass.
Phase 5 added the mechanism; Phase 6 adds event/pruning fields and migrates
to dataclass to prevent typo bugs and field collisions.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PostBatchFeedback:
    """
    Collected feedback from a single task execution, replayed on main
    thread after batch join in _apply_post_batch_feedback.

    Phase 5 fields (8):
        deferred_findings, deferred_critical_actions, deferred_boost_event,
        deferred_new_assets, deferred_react_tasks, deferred_handoff,
        deferred_new_context, deferred_decision_enhancer_tasks

    Phase 6 additions (reserved, populated in later milestones):
        event_emissions, pruning_decisions
    """

    # --- Phase 5: Original 8 fields ---
    deferred_findings: List[Any] = field(default_factory=list)
    deferred_critical_actions: List[Dict[str, Any]] = field(default_factory=list)
    deferred_boost_event: Optional[Dict[str, Any]] = None
    deferred_new_assets: Optional[List[str]] = None
    deferred_react_tasks: Optional[List[Any]] = None
    deferred_handoff: Optional[Dict[str, Any]] = None
    deferred_new_context: Any = None
    deferred_decision_enhancer_tasks: List[Any] = field(default_factory=list)

    # --- Phase 6: Event-driven chaining fields ---
    event_emissions: List[Dict[str, Any]] = field(default_factory=list)
    pruning_decisions: List[Dict[str, Any]] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Return True if no feedback was collected."""
        return (
            not self.deferred_findings
            and not self.deferred_critical_actions
            and self.deferred_boost_event is None
            and not self.deferred_new_assets
            and not self.deferred_react_tasks
            and self.deferred_handoff is None
            and self.deferred_new_context is None
            and not self.deferred_decision_enhancer_tasks
            and not self.event_emissions
            and not self.pruning_decisions
        )
