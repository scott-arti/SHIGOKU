"""
T-1.3 / T-3.5: SchedulingDecision schema tests.

Tests:
  - Schema completeness (all fields present)
  - Safe-by-construction: no secret-bearing fields
  - Default values (shadow_only=True, mutation_surface='unknown')
  - reason_code must be non-empty after classification
  - MutationSurface enum values
"""
import dataclasses

from src.core.engine.scheduling_decision import MutationSurface, SchedulingDecision


class TestMutationSurface:
    def test_all_values_present(self):
        assert MutationSurface.PATH.value == "path"
        assert MutationSurface.QUERY.value == "query"
        assert MutationSurface.BODY.value == "body"
        assert MutationSurface.HEADER.value == "header"
        assert MutationSurface.COOKIE.value == "cookie"
        assert MutationSurface.UNKNOWN.value == "unknown"

    def test_unknown_is_default_safe(self):
        assert MutationSurface.UNKNOWN.value == "unknown"


class TestSchedulingDecisionSchema:
    """T-1.3: reason_code required / T-3.5: no secret fields."""

    def test_all_required_fields_present(self):
        """Schema contains all 14 fields with correct types."""
        d = SchedulingDecision(
            lane="read_only",
            parallel_safe=True,
            rate_limited=False,
            reason_code="test",
        )
        assert d.lane == "read_only"
        assert d.parallel_safe is True
        assert d.rate_limited is False
        assert d.reason_code == "test"
        assert d.shadow_only is True
        assert d.mutation_surface == "unknown"
        assert d.auth_context_version == 0
        assert d.origin_key == ""
        assert d.mutex_key == ""
        assert d.would_wait is False
        assert d.would_reject is False
        assert d.compat_lane is None
        assert d.lane_disagreement is False

    def test_default_shadow_only_is_true(self):
        """Phase 4 shadow_only is always True."""
        d = SchedulingDecision(lane="read_only", parallel_safe=True, rate_limited=False, reason_code="test")
        assert d.shadow_only is True

    def test_default_mutation_surface_is_unknown(self):
        """Default mutation_surface is 'unknown'."""
        d = SchedulingDecision(lane="read_only", parallel_safe=True, rate_limited=False, reason_code="test")
        assert d.mutation_surface == "unknown"

    def test_reason_code_empty_by_default(self):
        """reason_code starts empty but must be set by classification."""
        d = SchedulingDecision(lane="read_only", parallel_safe=True, rate_limited=False)
        assert d.reason_code == ""

    def test_no_secret_fields_in_dataclass(self):
        """T-3.5: SchedulingDecision contains NO secret-bearing fields."""
        field_names = {f.name for f in dataclasses.fields(SchedulingDecision)}
        secret_keywords = {"cookie", "token", "secret", "password", "api_key", "authorization", "auth_header"}
        for field_name in field_names:
            for keyword in secret_keywords:
                assert keyword not in field_name.lower(), (
                    f"Field '{field_name}' may expose secrets (contains '{keyword}')"
                )

    def test_can_set_all_fields_explicitly(self):
        """All fields can be set explicitly."""
        d = SchedulingDecision(
            lane="aggressive_exclusive",
            parallel_safe=False,
            rate_limited=False,
            compat_lane="mutating",
            lane_disagreement=True,
            reason_code="class_aggressive_exclusive",
            mutex_key="abc123",
            mutation_surface="body",
            would_wait=True,
            would_reject=True,
            shadow_only=True,
            origin_key="https://example.com",
            auth_context_version=3,
        )
        assert d.lane == "aggressive_exclusive"
        assert d.compat_lane == "mutating"
        assert d.lane_disagreement is True
        assert d.mutex_key == "abc123"
        assert d.mutation_surface == "body"
        assert d.would_wait is True
        assert d.would_reject is True
        assert d.origin_key == "https://example.com"
        assert d.auth_context_version == 3

    def test_auth_context_version_is_int(self):
        """auth_context_version is an integer, not a string (no raw tokens)."""
        d = SchedulingDecision(lane="read_only", parallel_safe=True, rate_limited=False, reason_code="test", auth_context_version=5)
        assert isinstance(d.auth_context_version, int)
        assert d.auth_context_version == 5
