"""
Execution Budget Policy — Phase 2 (SGK-2026-0311).

Per-origin budget enforcement: tracks requests per origin and rejects
when the burst budget is exceeded. Budget resets after cooldown.

Thread-safety is NOT guaranteed (serial mode assumption).
Thread-safe enforcement is deferred to Phase 5 (SGK-2026-0314, D-6).
"""

import time
from dataclasses import dataclass, field


class BudgetReasonCode:
    """Structured reason codes for budget decisions."""
    BUDGET_EXCEEDED: str = "budget_exceeded"


@dataclass
class BudgetDecision:
    """Result of a budget consumption check."""
    allowed: bool
    wait_seconds: float = 0.0
    reason_code: str = ""

    @classmethod
    def allow(cls) -> "BudgetDecision":
        return cls(allowed=True)

    @classmethod
    def reject(cls, wait_seconds: float, reason_code: str) -> "BudgetDecision":
        return cls(allowed=False, wait_seconds=wait_seconds, reason_code=reason_code)


@dataclass
class _OriginBudget:
    """Internal tracking for a single origin's budget window."""
    count: int = 0
    window_start: float = field(default_factory=time.monotonic)


class ExecutionBudgetPolicy:
    """
    Per-origin budget policy.

    Tracks request count per normalized origin key within a burst window.
    When the burst budget is exhausted within the cooldown window,
    further requests are rejected until the window resets.

    Config fields (from ParallelismSettings.per_origin_budget):
        rpm:        Requests per minute (informational, not enforced at this layer)
        burst:      Maximum requests per cooldown window
        max_inflight: Max concurrent inflight (schema only, enforced in Phase 5)
        cooldown_seconds: Window duration after which budget resets
    """

    def __init__(
        self,
        rpm: int = 30,
        burst: int = 10,
        cooldown_seconds: float = 1.0,
    ):
        self.rpm = rpm
        self.burst = burst
        self.cooldown_seconds = cooldown_seconds
        self._budgets: dict[str, _OriginBudget] = {}

    def consume(self, origin_key: str) -> BudgetDecision:
        """Attempt to consume one budget token for the given origin.

        Returns:
            BudgetDecision — allowed=True if within budget, False with wait_seconds otherwise.
        """
        now = time.monotonic()
        budget = self._budgets.get(origin_key)

        # Reset window if cooldown has elapsed
        if budget is not None and (now - budget.window_start) >= self.cooldown_seconds:
            budget.count = 0
            budget.window_start = now

        if budget is None:
            budget = _OriginBudget(count=0, window_start=now)
            self._budgets[origin_key] = budget

        if budget.count < self.burst:
            budget.count += 1
            return BudgetDecision.allow()

        # Budget exceeded — compute remaining wait time
        remaining = self.cooldown_seconds - (now - budget.window_start)
        wait = max(0.0, remaining)
        return BudgetDecision.reject(
            wait_seconds=wait,
            reason_code=BudgetReasonCode.BUDGET_EXCEEDED,
        )

    def get_usage(self, origin_key: str) -> int:
        """Return current request count for an origin (0 if unknown)."""
        budget = self._budgets.get(origin_key)
        if budget is None:
            return 0
        now = time.monotonic()
        if (now - budget.window_start) >= self.cooldown_seconds:
            return 0
        return budget.count
