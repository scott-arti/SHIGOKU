"""
T-4.1 / T-4.2 / T-4.3: ExecutionBudgetPolicy tests.

Tests:
  - T-4.1: Same origin budget exceeded → reject
  - T-4.1-threadsafe: Parallel consume() calls do not cause lost updates (Phase 5 LB-4)
  - T-4.2: Different origins have independent budgets
  - T-4.3: Cooldown resets budget
"""
import threading
import time
import pytest
from src.core.engine.budget_policy import (
    BudgetDecision,
    ExecutionBudgetPolicy,
    BudgetReasonCode,
)


class TestBudgetDecision:
    def test_allowed(self):
        d = BudgetDecision(allowed=True)
        assert d.allowed is True
        assert d.wait_seconds == 0.0

    def test_rejected_with_wait(self):
        d = BudgetDecision(allowed=False, wait_seconds=1.5, reason_code="budget_exceeded")
        assert d.allowed is False
        assert d.wait_seconds == 1.5
        assert d.reason_code == "budget_exceeded"


class TestExecutionBudgetPolicy:
    """T-4.1 to T-4.3: Per-origin budget enforcement."""

    def test_budget_not_exceeded_allows(self):
        """Within budget → allowed."""
        policy = ExecutionBudgetPolicy(rpm=60, burst=10)
        for _ in range(5):
            decision = policy.consume("https://example.com")
            assert decision.allowed is True

    def test_budget_exceeded_rejects(self):
        """T-4.1: Same origin exceeded → rejected."""
        # Low budget to trigger quickly
        policy = ExecutionBudgetPolicy(rpm=60, burst=3)
        for _ in range(3):
            decision = policy.consume("https://example.com")
            assert decision.allowed is True
        # 4th request should be rejected
        decision = policy.consume("https://example.com")
        assert decision.allowed is False
        assert decision.reason_code == BudgetReasonCode.BUDGET_EXCEEDED
        assert decision.wait_seconds > 0

    def test_different_origins_independent(self):
        """T-4.2: Different origins have independent budgets."""
        policy = ExecutionBudgetPolicy(rpm=60, burst=3)
        # Fill budget for origin A
        for _ in range(3):
            assert policy.consume("https://example.com").allowed is True
        assert policy.consume("https://example.com").allowed is False

        # Origin B still has full budget
        for _ in range(3):
            assert policy.consume("https://other.com").allowed is True
        assert policy.consume("https://other.com").allowed is False

    def test_cooldown_resets_budget(self):
        """T-4.3: After cooldown, budget resets."""
        policy = ExecutionBudgetPolicy(rpm=600, burst=3, cooldown_seconds=0.01)
        for _ in range(3):
            assert policy.consume("https://example.com").allowed is True
        assert policy.consume("https://example.com").allowed is False

        # Wait for cooldown
        time.sleep(0.02)

        # Budget should be reset
        decision = policy.consume("https://example.com")
        assert decision.allowed is True

    def test_consume_updates_counter(self):
        """Each consume increments the request counter."""
        policy = ExecutionBudgetPolicy(rpm=600, burst=10)
        assert policy.get_usage("https://example.com") == 0
        policy.consume("https://example.com")
        assert policy.get_usage("https://example.com") == 1

    def test_get_usage_unknown_origin_returns_zero(self):
        """Unknown origin returns 0 usage."""
        policy = ExecutionBudgetPolicy()
        assert policy.get_usage("https://nonexistent.com") == 0


# ============================================================
# Phase 5 T-4.1: Thread-safety under parallel dispatch (LB-4)
# ============================================================

class TestBudgetConsumeThreadsafeUnderParallelism:
    """T-4.1 (Phase 5): Concurrent consume() does not cause lost updates.

    When N threads call consume() simultaneously on the same origin,
    exactly BURST requests are allowed and BURST+1 is rejected.
    No lost update due to race conditions.
    """

    def test_concurrent_consume_no_lost_updates(self):
        """N threads → exactly burst allowed, no budget violation."""
        burst = 10
        n_threads = 20  # more than burst to force contention
        policy = ExecutionBudgetPolicy(rpm=60000, burst=burst)

        allowed_count = 0
        rejected_count = 0
        lock = threading.Lock()
        barrier = threading.Barrier(n_threads)

        def worker():
            nonlocal allowed_count, rejected_count
            barrier.wait()  # synchronize all threads at the start
            decision = policy.consume("https://example.com")
            with lock:
                if decision.allowed:
                    allowed_count += 1
                else:
                    rejected_count += 1

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # With a burst of 10, exactly 10 requests must be allowed
        # and at least (n_threads - burst) must be rejected.
        # If there's a lost update, allowed_count > burst.
        assert allowed_count == burst, (
            f"Thread-safe budget: expected exactly {burst} allowed, got {allowed_count} "
            f"(lost update detected if > {burst})"
        )
        assert rejected_count >= (n_threads - burst)

    def test_concurrent_different_origins_independent(self):
        """Concurrent access to different origins does not interfere."""
        burst = 5
        policy = ExecutionBudgetPolicy(rpm=60000, burst=burst)
        barrier = threading.Barrier(2)

        results: dict[str, int] = {}
        rlock = threading.Lock()

        def worker_a():
            barrier.wait()
            for _ in range(burst + 2):
                d = policy.consume("https://a.example.com")
                with rlock:
                    results[f"a_{d.allowed}"] = results.get(f"a_{d.allowed}", 0) + 1

        def worker_b():
            barrier.wait()
            for _ in range(burst + 2):
                d = policy.consume("https://b.example.com")
                with rlock:
                    results[f"b_{d.allowed}"] = results.get(f"b_{d.allowed}", 0) + 1

        ta = threading.Thread(target=worker_a)
        tb = threading.Thread(target=worker_b)
        ta.start()
        tb.start()
        ta.join()
        tb.join()

        # Each origin independently allows exactly burst requests
        allowed_a = results.get("a_True", 0)
        allowed_b = results.get("b_True", 0)
        assert allowed_a == burst, f"Origin A: expected {burst} allowed, got {allowed_a}"
        assert allowed_b == burst, f"Origin B: expected {burst} allowed, got {allowed_b}"
