"""
T-4.1 / T-4.2 / T-4.3: ExecutionBudgetPolicy tests.

Tests:
  - T-4.1: Same origin budget exceeded → reject
  - T-4.2: Different origins have independent budgets
  - T-4.3: Cooldown resets budget
"""
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
