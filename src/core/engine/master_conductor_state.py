"""
ConductorState: MasterConductor mutable state owner (SGK-2026-0289 Step 1).

This dataclass groups the mutable state that the facade owns.
Coordinators/services read state through this dataclass but do NOT
mutate it directly. Final mutation is always via the facade.

Ownership rules:
- task_queue, completed_tasks, pending_hitl: facade mutates via ConductorState
- _state_lock: facade acquires before mutation
- context, event_bus: facade reads/writes
- execution_log: facade appends
- react state: facade owns, coordinators read-only
"""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from typing import Any


@dataclass
class ConductorState:
    """Mutable state owned by MasterConductor facade.

    Coordinators receive a read-only view. Final mutation
    (task_queue enqueue/dequeue, completed_tasks extend,
    pending_hitl append/remove, execution_log append,
    context update) is performed by the facade through
    ConductorState methods.
    """

    # Core mutable collections
    task_queue: Any = None          # DynamicTaskQueue
    completed_tasks: list[Any] = field(default_factory=list)
    pending_hitl: list[dict[str, Any]] = field(default_factory=list)

    # Thread safety
    _state_lock: RLock = field(default_factory=RLock, repr=False)

    # Context + event infrastructure
    context: Any = None             # ExecutionContext
    event_bus: Any = None           # EventBus
    execution_log: Any = None       # TaskExecutionLog

    # Runtime flags
    shutdown_requested: bool = False
    _recon_executed: bool = False
    auto_checkpoint: bool = True

    # React observation state (read by _observe_and_rethink)
    react_cache: dict[str, Any] = field(default_factory=dict)
    react_observation_executed_total: int = 0
    react_observation_executed_by_target: dict[str, int] = field(default_factory=dict)
    react_observation_metrics: dict[str, Any] = field(default_factory=lambda: {
        "attempted": 0,
        "executed": 0,
        "skipped": 0,
        "skip_reasons": {},
    })
    react_observation_retry_used: int = 0
    react_observation_cb_failures: int = 0
    react_observation_cb_open_until: float = 0.0
    react_observation_inflight: int = 0
    react_observation_pending_queue: Any = field(default_factory=lambda: __import__("collections").deque())
