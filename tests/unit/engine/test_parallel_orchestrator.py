"""
T-0.1 Characterization test: Capture existing category-based rate limit + semaphore behavior.

This test fixes the current baseline BEFORE any admission/budget code is introduced.
If this test breaks after implementation, it signals a backward-compatibility violation
and the implementation is No-Go.

Tests:
  - _get_semaphore("default") returns the correct worker-count Semaphore
  - _get_rate_limiter("intel_passive") returns the correct category limiter
  - CATEGORY_CONFIGS["default"].workers is 3
  - RATE_LIMIT_PRESETS["intel_passive"].initial_rps is 50
"""
import asyncio
import pytest
from src.core.engine.parallel_orchestrator import (
    ParallelOrchestrator,
    ParallelTask,
    CATEGORY_CONFIGS,
    create_parallel_task,
)
from src.core.engine.adaptive_rate_limiter import AdaptiveRateLimiter, RATE_LIMIT_PRESETS


class TestExistingParallelOrchestratorBaseline:
    """T-0.1: Characterization test for existing baseline behavior."""

    def test_default_semaphore_workers(self):
        """_get_semaphore('default') returns a Semaphore with workers=3."""
        orch = ParallelOrchestrator()
        sem = orch._get_semaphore("default")
        assert isinstance(sem, asyncio.Semaphore)
        # In Python 3.10+, Semaphore._value gives approximate count.
        # For a freshly created semaphore, _value == workers (3).
        assert sem._value == 3

    def test_intel_passive_rate_limiter(self):
        """_get_rate_limiter('intel_passive') returns the correct limiter."""
        orch = ParallelOrchestrator()
        limiter = orch._get_rate_limiter("intel_passive")
        assert isinstance(limiter, AdaptiveRateLimiter)
        assert limiter.initial_rps == 50.0

    def test_category_config_default_workers(self):
        """CATEGORY_CONFIGS['default'].workers is 3."""
        assert CATEGORY_CONFIGS["default"].workers == 3

    def test_rate_limit_preset_intel_passive(self):
        """RATE_LIMIT_PRESETS['intel_passive'].initial_rps is 50."""
        assert RATE_LIMIT_PRESETS["intel_passive"].initial_rps == 50.0

    def test_unknown_category_falls_back_to_default_semaphore(self):
        """Unknown category → _get_config returns 'default' config."""
        orch = ParallelOrchestrator()
        config = orch._get_config("nonexistent")
        assert config.category == "default"
        assert config.workers == 3

    def test_create_parallel_task_minimal_defaults(self):
        """create_parallel_task with minimal args returns ParallelTask with defaults."""
        def dummy_func(x):
            return x

        ptask = create_parallel_task("test-1", dummy_func, 42)
        assert ptask.id == "test-1"
        assert ptask.func == dummy_func
        assert ptask.args == (42,)
        assert ptask.category == "default"
        assert ptask.kwargs == {}

    def test_create_parallel_task_with_category(self):
        """create_parallel_task with explicit category preserves it."""
        def dummy_func():
            pass

        ptask = create_parallel_task("test-2", dummy_func, category="intel_passive")
        assert ptask.category == "intel_passive"

    def test_semaphore_is_lazy_cached(self):
        """Repeated _get_semaphore calls return the same object (lazy cache)."""
        orch = ParallelOrchestrator()
        sem1 = orch._get_semaphore("default")
        sem2 = orch._get_semaphore("default")
        assert sem1 is sem2


# ---------------------------------------------------------------
# T-1.1: origin_key bridge + category→lane mapping
# ---------------------------------------------------------------

class TestParallelTaskOriginKeyBridge:
    """T-1.1: origin_key / target_key / lane / scope_verdict bridge tests."""

    def dummy_func(self, *args, **kwargs):
        return args, kwargs

    def test_origin_key_propagates_to_parallel_task(self):
        """origin_key kwarg propagates to ParallelTask.origin_key."""
        ptask = create_parallel_task(
            "t1", self.dummy_func, origin_key="https://example.com"
        )
        assert ptask.origin_key == "https://example.com"

    def test_origin_key_defaults_to_none(self):
        """origin_key defaults to None when not provided (backward compat)."""
        ptask = create_parallel_task("t2", self.dummy_func)
        assert ptask.origin_key is None

    def test_target_key_propagates(self):
        """target_key kwarg propagates to ParallelTask.target_key."""
        ptask = create_parallel_task(
            "t3", self.dummy_func, target_key="https://example.com/api"
        )
        assert ptask.target_key == "https://example.com/api"

    def test_lane_propagates(self):
        """lane kwarg propagates to ParallelTask.lane."""
        ptask = create_parallel_task("t4", self.dummy_func, lane="read_only")
        assert ptask.lane == "read_only"

    def test_lane_auto_inferred_from_category(self):
        """lane is auto-inferred from category (default→read_only) when not provided."""
        ptask = create_parallel_task("t5", self.dummy_func)
        assert ptask.lane == "read_only"  # auto-inferred from category="default"

    def test_scope_verdict_defaults_to_unknown(self):
        """scope_verdict defaults to 'unknown'."""
        ptask = create_parallel_task("t6", self.dummy_func)
        assert ptask.scope_verdict == "unknown"

    def test_scope_verdict_explicit(self):
        """scope_verdict can be set explicitly."""
        ptask = create_parallel_task(
            "t7", self.dummy_func, scope_verdict="in_scope"
        )
        assert ptask.scope_verdict == "in_scope"

    def test_existing_args_still_work(self):
        """Positional *args still work with new kwargs."""
        ptask = create_parallel_task(
            "t8", self.dummy_func, 1, 2, 3, category="intel_passive"
        )
        assert ptask.args == (1, 2, 3)
        assert ptask.category == "intel_passive"

    def test_category_to_lane_read_only(self):
        """Category 'intel_passive' → lane 'read_only'."""
        ptask = create_parallel_task(
            "t9", self.dummy_func, category="intel_passive"
        )
        assert ptask.lane == "read_only"

    def test_category_to_lane_mutating(self):
        """Category 'attack_auth' → lane 'mutating'."""
        ptask = create_parallel_task(
            "t10", self.dummy_func, category="attack_auth"
        )
        assert ptask.lane == "mutating"

    def test_category_to_lane_default(self):
        """Category 'default' → lane 'read_only'."""
        ptask = create_parallel_task(
            "t11", self.dummy_func, category="default"
        )
        assert ptask.lane == "read_only"

    def test_unknown_category_falls_back_to_read_only(self):
        """Unknown category → lane 'read_only' (safe fallback)."""
        ptask = create_parallel_task(
            "t12", self.dummy_func, category="nonexistent_cat"
        )
        assert ptask.lane == "read_only"

    def test_explicit_lane_overrides_category(self):
        """Explicit lane overrides category→lane inference."""
        ptask = create_parallel_task(
            "t13", self.dummy_func, category="attack_auth", lane="aggressive_exclusive"
        )
        assert ptask.lane == "aggressive_exclusive"

    def test_admitted_defaults_to_true(self):
        """admitted field defaults to True (backward compat)."""
        ptask = create_parallel_task("t14", self.dummy_func)
        assert ptask.admitted is True

    def test_reject_reason_defaults_to_empty(self):
        """reject_reason defaults to empty string."""
        ptask = create_parallel_task("t15", self.dummy_func)
        assert ptask.reject_reason == ""

    def test_admission_rejected_task_has_flags(self):
        """When admission is set to reject, parallel_task gets admitted=False."""
        from src.core.engine.parallel_orchestrator import admission_policy
        import src.core.engine.admission_policy as ap

        # Temporarily make the policy reject mutating tasks
        original_state = (admission_policy.mutating_enabled,
                          admission_policy.mutating_allowlist)
        try:
            admission_policy.mutating_enabled = True
            admission_policy.mutating_allowlist = set()  # empty allowlist

            ptask = create_parallel_task(
                "t-reject", self.dummy_func,
                category="attack_auth",  # → lane=mutating
                origin_key="https://evil.com",
                scope_verdict="in_scope",
            )
            assert ptask.admitted is False
            assert ptask.reject_reason == ap.ReasonCode.MUTATING_NOT_ALLOWLISTED
        finally:
            admission_policy.mutating_enabled = original_state[0]
            admission_policy.mutating_allowlist = original_state[1]
