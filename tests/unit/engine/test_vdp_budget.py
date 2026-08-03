"""
SGK-2026-0419 Step 2: Execution budget tests at asset/actor/hypothesis level.

Tests cover:
- Asset/actor/hypothesis-level budget enforcement
- Strictest-of-policy-and-local-config
- Budget exhaustion with structured reason codes
- Circuit breaker tracking (429, 5xx, timeout, latency)
- Budget consumption and snapshot
- Per-asset burst with cooldown
- Per-actor burst with cooldown
- Per-hypothesis burst with cooldown
- Combined budget sync with ExecutionBudgetV1 model
"""
from __future__ import annotations

import time

import pytest


# ============================================================================
# T-0419-B01: Multi-level budget enforcement
# ============================================================================

class TestMultiLevelBudgetEnforcement:
    """Budget must be enforced at asset, actor, and hypothesis levels."""

    def test_asset_level_budget_exhausted(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget, BudgetReasonCodeV1

        budget = VdpExecutionBudget(
            per_asset_burst=3,
            per_asset_cooldown_seconds=60.0,
        )
        asset = "https://api.example.com"

        for _ in range(3):
            assert budget.consume(asset_key=asset).allowed is True

        result = budget.consume(asset_key=asset)
        assert result.allowed is False
        assert result.reason_code == BudgetReasonCodeV1.ASSET_BUDGET_EXHAUSTED

    def test_actor_level_budget_exhausted(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget, BudgetReasonCodeV1

        budget = VdpExecutionBudget(
            per_actor_burst=2,
            per_actor_cooldown_seconds=60.0,
        )
        actor = "unauthenticated"
        asset = "https://api.example.com"

        for _ in range(2):
            assert budget.consume(asset_key=asset, actor_key=actor).allowed is True

        result = budget.consume(asset_key=asset, actor_key=actor)
        assert result.allowed is False
        assert result.reason_code == BudgetReasonCodeV1.ACTOR_BUDGET_EXHAUSTED

    def test_hypothesis_level_budget_exhausted(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget, BudgetReasonCodeV1

        budget = VdpExecutionBudget(
            per_hypothesis_burst=2,
            per_hypothesis_cooldown_seconds=60.0,
        )
        hypothesis = "hyp-001"

        for _ in range(2):
            assert budget.consume(hypothesis_key=hypothesis).allowed is True

        result = budget.consume(hypothesis_key=hypothesis)
        assert result.allowed is False
        assert result.reason_code == BudgetReasonCodeV1.HYPOTHESIS_BUDGET_EXHAUSTED

    def test_asset_budget_cooldown_resets(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget

        budget = VdpExecutionBudget(
            per_asset_burst=2,
            per_asset_cooldown_seconds=0.01,
        )
        asset = "https://api.example.com"

        for _ in range(2):
            assert budget.consume(asset_key=asset).allowed is True
        assert budget.consume(asset_key=asset).allowed is False

        time.sleep(0.02)
        assert budget.consume(asset_key=asset).allowed is True

    def test_different_assets_independent(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget

        budget = VdpExecutionBudget(
            per_asset_burst=3,
            per_asset_cooldown_seconds=60.0,
        )

        # Exhaust asset A
        for _ in range(3):
            assert budget.consume(asset_key="https://a.com").allowed is True
        assert budget.consume(asset_key="https://a.com").allowed is False

        # Asset B still has full budget
        for _ in range(3):
            assert budget.consume(asset_key="https://b.com").allowed is True
        assert budget.consume(asset_key="https://b.com").allowed is False

    def test_combined_limits_strictest_wins(self):
        """When all three levels are specified, the strictest (first exhausted) blocks."""
        from src.core.engine.vdp_budget import VdpExecutionBudget, BudgetReasonCodeV1

        budget = VdpExecutionBudget(
            per_asset_burst=10,
            per_actor_burst=3,
            per_hypothesis_burst=5,
            per_asset_cooldown_seconds=60.0,
            per_actor_cooldown_seconds=60.0,
            per_hypothesis_cooldown_seconds=60.0,
        )

        actor = "unauthenticated"
        asset = "https://api.example.com"
        hypothesis = "hyp-001"

        # Actor budget (3) is strictest
        for i in range(3):
            assert budget.consume(asset_key=asset, actor_key=actor, hypothesis_key=hypothesis).allowed is True
        result = budget.consume(asset_key=asset, actor_key=actor, hypothesis_key=hypothesis)
        assert result.allowed is False
        assert result.reason_code == BudgetReasonCodeV1.ACTOR_BUDGET_EXHAUSTED


# ============================================================================
# T-0419-B02: ExecutionBudgetV1 model integration
# ============================================================================

class TestBudgetModelIntegration:
    """VdpExecutionBudget must be constructible from ExecutionBudgetV1 model."""

    def test_from_execution_budget_v1_model(self):
        from src.core.models.vdp_contract import ExecutionBudgetV1
        from src.core.engine.vdp_budget import VdpExecutionBudget

        model = ExecutionBudgetV1(
            max_requests=100,
            max_follow_ups=10,
            max_retries=3,
            max_concurrency=5,
            max_runtime_seconds=3600,
            max_artifact_bytes=10 * 1024 * 1024,
            per_asset_burst=20,
            per_actor_burst=15,
            per_hypothesis_burst=10,
        )
        budget = VdpExecutionBudget.from_model(model)

        assert budget.max_requests == 100
        assert budget.per_asset_burst == 20
        assert budget.per_actor_burst == 15
        assert budget.per_hypothesis_burst == 10

    def test_strictest_config_wins(self):
        from src.core.models.vdp_contract import ExecutionBudgetV1
        from src.core.engine.vdp_budget import VdpExecutionBudget

        vdp_policy = ExecutionBudgetV1(
            per_asset_burst=100,
            per_actor_burst=50,
        )
        local_config = ExecutionBudgetV1(
            per_asset_burst=10,
            per_actor_burst=5,
        )
        strictest = ExecutionBudgetV1.strictest(vdp_policy, local_config)
        budget = VdpExecutionBudget.from_model(strictest)

        assert budget.per_asset_burst == 10
        assert budget.per_actor_burst == 5

    def test_budget_snapshot(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget

        budget = VdpExecutionBudget(
            per_asset_burst=10,
            per_actor_burst=5,
            max_requests=100,
            max_follow_ups=10,
        )
        budget.consume(asset_key="a1", actor_key="u1")
        budget.consume(asset_key="a1", actor_key="u1")

        snapshot = budget.snapshot()
        assert snapshot["requests_used"] == 2
        assert isinstance(snapshot, dict)


# ============================================================================
# T-0419-B03: Circuit breaker tracking
# ============================================================================

class TestCircuitBreaker:
    """Circuit breaker must track 429, 5xx, timeout, and latency events."""

    def test_circuit_breaker_429_opens(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget, BudgetReasonCodeV1

        budget = VdpExecutionBudget(
            circuit_breaker_429_threshold=3,
            per_asset_burst=100,
        )
        asset = "https://api.example.com"

        for _ in range(3):
            budget.record_response(asset_key=asset, status_code=429)

        result = budget.consume(asset_key=asset)
        assert result.allowed is False
        assert result.reason_code == BudgetReasonCodeV1.CIRCUIT_OPEN_429

    def test_circuit_breaker_5xx_opens(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget, BudgetReasonCodeV1

        budget = VdpExecutionBudget(
            circuit_breaker_5xx_threshold=3,
            per_asset_burst=100,
        )
        asset = "https://api.example.com"

        for _ in range(3):
            budget.record_response(asset_key=asset, status_code=500)

        result = budget.consume(asset_key=asset)
        assert result.allowed is False
        assert result.reason_code == BudgetReasonCodeV1.CIRCUIT_OPEN_5XX

    def test_circuit_breaker_timeout_opens(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget, BudgetReasonCodeV1

        budget = VdpExecutionBudget(
            circuit_breaker_timeout_threshold=2,
            per_asset_burst=100,
        )
        asset = "https://api.example.com"

        for _ in range(2):
            budget.record_timeout(asset_key=asset)

        result = budget.consume(asset_key=asset)
        assert result.allowed is False
        assert result.reason_code == BudgetReasonCodeV1.CIRCUIT_OPEN_TIMEOUT

    def test_circuit_breaker_latency_opens(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget, BudgetReasonCodeV1

        budget = VdpExecutionBudget(
            circuit_breaker_latency_ms_threshold=100,
            per_asset_burst=100,
        )
        asset = "https://api.example.com"

        # Record high latency responses
        budget.record_response(asset_key=asset, status_code=200, latency_ms=150)
        # One high latency shouldn't open the breaker unless we have a counter
        # Implement rolling window tracking
        for _ in range(5):
            budget.record_response(asset_key=asset, status_code=200, latency_ms=150)

        # After repeated high latency, circuit should open
        result = budget.consume(asset_key=asset)
        assert result.allowed is False
        assert result.reason_code == BudgetReasonCodeV1.CIRCUIT_OPEN_LATENCY

    def test_circuit_breaker_resets_after_cooldown(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget

        budget = VdpExecutionBudget(
            circuit_breaker_429_threshold=2,
            per_asset_burst=100,
            circuit_breaker_cooldown_seconds=0.01,
        )
        asset = "https://api.example.com"

        for _ in range(2):
            budget.record_response(asset_key=asset, status_code=429)
        assert budget.consume(asset_key=asset).allowed is False

        time.sleep(0.02)
        # Circuit should reset
        assert budget.consume(asset_key=asset).allowed is True

    def test_non_error_responses_dont_trigger_circuit(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget

        budget = VdpExecutionBudget(
            circuit_breaker_429_threshold=3,
            per_asset_burst=100,
        )
        asset = "https://api.example.com"

        for _ in range(5):
            budget.record_response(asset_key=asset, status_code=200)

        assert budget.consume(asset_key=asset).allowed is True

    def test_runtime_budget_exhausted(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget, BudgetReasonCodeV1

        budget = VdpExecutionBudget(
            max_runtime_seconds=0.01,
            per_asset_burst=100,
        )
        budget.mark_start()
        time.sleep(0.02)

        result = budget.consume(asset_key="test")
        assert result.allowed is False
        assert result.reason_code == BudgetReasonCodeV1.RUNTIME_EXCEEDED

    def test_request_count_budget_exhausted(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget, BudgetReasonCodeV1

        budget = VdpExecutionBudget(
            max_requests=3,
            per_asset_burst=10,
        )

        for _ in range(3):
            assert budget.consume(asset_key="test").allowed is True

        result = budget.consume(asset_key="test")
        assert result.allowed is False
        assert result.reason_code == BudgetReasonCodeV1.REQUESTS_EXHAUSTED


# ============================================================================
# T-0419-B04: Concurrency enforcement
# ============================================================================

class TestConcurrencyEnforcement:
    """Concurrency budget must track inflight count."""

    def test_concurrency_within_limit_allowed(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget

        budget = VdpExecutionBudget(
            max_concurrency=5,
            per_asset_burst=100,
        )
        assert budget.acquire_concurrency() is True
        assert budget._inflight == 1
        budget.release_concurrency()
        assert budget._inflight == 0

    def test_concurrency_exceeded_rejected(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget, BudgetReasonCodeV1

        budget = VdpExecutionBudget(
            max_concurrency=1,
            per_asset_burst=100,
        )
        assert budget.acquire_concurrency() is True
        result = budget.consume(asset_key="test")
        assert result.allowed is False
        assert result.reason_code == BudgetReasonCodeV1.CONCURRENCY_EXCEEDED


# ============================================================================
# T-0419-B05: Follow-up and retry budgets
# ============================================================================

class TestFollowUpAndRetryBudgets:
    """Follow-up and retry counters must be independent from request budget."""

    def test_follow_up_budget_exhausted(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget, BudgetReasonCodeV1

        budget = VdpExecutionBudget(
            max_follow_ups=2,
            per_asset_burst=100,
        )
        hypothesis = "hyp-001"

        for _ in range(2):
            assert budget.consume_follow_up(hypothesis_key=hypothesis).allowed is True

        result = budget.consume_follow_up(hypothesis_key=hypothesis)
        assert result.allowed is False
        assert result.reason_code == BudgetReasonCodeV1.FOLLOW_UPS_EXHAUSTED

    def test_follow_up_separate_from_requests(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget

        budget = VdpExecutionBudget(
            max_requests=10,
            max_follow_ups=3,
            per_asset_burst=100,
        )

        # Consume some follow-ups
        budget.consume_follow_up("hyp-001")
        # Requests should still have full budget
        assert budget.consume(asset_key="test").allowed is True
        assert budget._follow_ups_used == 1
        assert budget._requests_used >= 1  # consume() also counts as a request

    def test_retry_budget_exhausted(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget, BudgetReasonCodeV1

        budget = VdpExecutionBudget(
            max_retries=2,
            per_asset_burst=100,
        )
        attempt = "att-001"

        for _ in range(2):
            assert budget.consume_retry(attempt_key=attempt).allowed is True

        result = budget.consume_retry(attempt_key=attempt)
        assert result.allowed is False
        assert result.reason_code == BudgetReasonCodeV1.RETRIES_EXHAUSTED

    def test_retry_per_attempt_independent(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget

        budget = VdpExecutionBudget(
            max_retries=3,
            per_asset_burst=100,
        )

        # Exhaust retries for attempt A
        for _ in range(3):
            budget.consume_retry("att-a")
        assert budget.consume_retry("att-a").allowed is False

        # Attempt B still has retries
        assert budget.consume_retry("att-b").allowed is True


# ============================================================================
# T-0419-B06: Artifact byte budget
# ============================================================================

class TestArtifactByteBudget:
    """Artifact byte budget must be tracked and enforced."""

    def test_artifact_bytes_within_budget(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget

        budget = VdpExecutionBudget(
            max_artifact_bytes=1024,
            per_asset_burst=100,
        )
        assert budget.consume_artifact_bytes(500) is True
        assert budget._artifact_bytes_used == 500

    def test_artifact_bytes_exceeded(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget, BudgetReasonCodeV1

        budget = VdpExecutionBudget(
            max_artifact_bytes=1024,
            per_asset_burst=100,
        )
        assert budget.consume_artifact_bytes(500) is True
        assert budget.consume_artifact_bytes(500) is True
        # Next byte should exceed
        result = budget.consume(asset_key="test")
        # The budget check should still allow request but track artifact exhaustion
        assert budget._artifact_bytes_used >= 1000

        # Consume more artifact bytes — should fail
        assert budget.consume_artifact_bytes(100) is False


# ============================================================================
# T-0419-B07: Budget checkpoint save/restore
# ============================================================================


class TestBudgetCheckpoint:
    """Budget state must be fully serializable and restorable from checkpoint."""

    def test_to_checkpoint_dict_includes_all_state(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget

        budget = VdpExecutionBudget(
            max_requests=100,
            per_asset_burst=5,
            per_asset_cooldown_seconds=60.0,
            circuit_breaker_429_threshold=3,
        )
        budget.consume(asset_key="a1", actor_key="u1")
        budget.consume(asset_key="a1", actor_key="u1")
        budget.record_response(asset_key="a1", status_code=429, latency_ms=100)

        ck = budget.to_checkpoint_dict()

        # Config section
        assert ck["config"]["max_requests"] == 100
        assert ck["config"]["per_asset_burst"] == 5
        assert ck["config"]["circuit_breaker_429_threshold"] == 3

        # Counters
        assert ck["counters"]["requests_used"] == 2

        # Per-key budgets
        assert "a1" in ck["per_key"]["assets"]
        assert ck["per_key"]["assets"]["a1"]["count"] == 2

        # Circuit breaker state
        assert "a1" in ck["circuits"]
        assert ck["circuits"]["a1"]["error_429_count"] == 1

    def test_from_checkpoint_dict_full_roundtrip(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget, BudgetReasonCodeV1

        # Create and populate a budget
        budget = VdpExecutionBudget(
            max_requests=50,
            per_asset_burst=3,
            per_actor_burst=2,
            per_asset_cooldown_seconds=30.0,
            circuit_breaker_429_threshold=2,
        )
        budget.consume(asset_key="a1", actor_key="u1")
        budget.consume(asset_key="a1", actor_key="u1")
        budget.record_response(asset_key="a1", status_code=429)
        budget.record_response(asset_key="a1", status_code=429)
        budget.mark_start()

        # Serialize
        ck = budget.to_checkpoint_dict()

        # Restore
        restored = VdpExecutionBudget.from_checkpoint_dict(ck)

        # Verify config restored
        assert restored.max_requests == 50
        assert restored.per_asset_burst == 3
        assert restored.per_actor_burst == 2

        # Verify counters restored
        assert restored._requests_used == 2

        # Verify per-key budget state
        assert "a1" in restored._assets
        assert "u1" in restored._actors

        # Verify circuit breaker state — should be open
        result = restored.consume(asset_key="a1")
        assert result.allowed is False
        assert result.reason_code == BudgetReasonCodeV1.CIRCUIT_OPEN_429

    def test_from_checkpoint_dict_unknown_budget_continues(self):
        """Budget from checkpoint must continue from where it left off."""
        from src.core.engine.vdp_budget import VdpExecutionBudget

        budget = VdpExecutionBudget(
            max_requests=3,
            per_asset_burst=10,
        )
        # Consume 2 of 3
        budget.consume(asset_key="test")
        budget.consume(asset_key="test")

        ck = budget.to_checkpoint_dict()
        restored = VdpExecutionBudget.from_checkpoint_dict(ck)

        # Should have only 1 request remaining
        assert restored.consume(asset_key="test").allowed is True
        assert restored.consume(asset_key="test").allowed is False

    def test_checkpoint_roundtrip_preserves_retry_state(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget

        budget = VdpExecutionBudget(max_retries=3, per_asset_burst=100)
        budget.consume_retry("att-1")
        budget.consume_retry("att-1")

        ck = budget.to_checkpoint_dict()
        restored = VdpExecutionBudget.from_checkpoint_dict(ck)

        # Should have 1 retry left for att-1
        assert restored.consume_retry("att-1").allowed is True
        assert restored.consume_retry("att-1").allowed is False

    def test_checkpoint_empty_budget_roundtrip(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget

        budget = VdpExecutionBudget()
        ck = budget.to_checkpoint_dict()
        restored = VdpExecutionBudget.from_checkpoint_dict(ck)

        assert restored.max_requests == 1000
        assert restored._requests_used == 0
        assert restored.consume(asset_key="test").allowed is True
