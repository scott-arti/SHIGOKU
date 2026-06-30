"""
T-3.1 / T-3.2 / T-3.3: ParallelismSettings config tests.

Tests:
  - T-3.1: parallelism section missing → safe defaults
  - T-3.2: invalid values (workers=0, rpm=-1) → Pydantic ValidationError
  - T-3.3: full YAML roundtrip → all values correct
"""
import pytest
from pydantic import ValidationError
from src.core.config.settings import (
    ParallelismSettings,
    PerOriginBudgetSettings,
    MutatingLaneSettings,
    AggressiveLaneSettings,
)


class TestParallelismConfigDefaultSafe:
    """T-3.1: Safe defaults when parallelism section is absent."""

    def test_default_enabled_is_false(self):
        s = ParallelismSettings()
        assert s.enabled is False

    def test_default_shadow_mode_is_true(self):
        s = ParallelismSettings()
        assert s.shadow_mode is True

    def test_default_executor_is_serial(self):
        s = ParallelismSettings()
        assert s.default_executor == "serial"

    def test_default_mutating_disabled(self):
        s = ParallelismSettings()
        assert s.mutating.enabled is False

    def test_default_aggressive_disabled(self):
        s = ParallelismSettings()
        assert s.aggressive_exclusive.enabled is False

    def test_default_per_origin_budget_rpm(self):
        s = ParallelismSettings()
        assert s.per_origin_budget.rpm == 30

    def test_default_per_origin_budget_burst(self):
        s = ParallelismSettings()
        assert s.per_origin_budget.burst == 10

    def test_default_per_origin_budget_max_inflight(self):
        s = ParallelismSettings()
        assert s.per_origin_budget.max_inflight == 2

    def test_default_cooldown_seconds(self):
        s = ParallelismSettings()
        assert s.per_origin_budget.cooldown_seconds == 1.0

    def test_empty_lane_workers(self):
        s = ParallelismSettings()
        assert s.lane_workers == {}

    def test_empty_allowlists(self):
        s = ParallelismSettings()
        assert s.mutating.allowlist == []
        assert s.aggressive_exclusive.allowlist == []

    def test_from_empty_dict_produces_defaults(self):
        """T-3.1: Empty YAML → default safe values."""
        s = ParallelismSettings()
        assert s.enabled is False
        assert s.shadow_mode is True
        assert s.mutating.enabled is False
        assert s.aggressive_exclusive.enabled is False


class TestParallelismConfigInvalidFailClosed:
    """T-3.2: Invalid values → Pydantic ValidationError (fail-closed)."""

    def test_workers_zero_raises(self):
        """workers=0 → ValidationError (ge=1)."""
        with pytest.raises(ValidationError):
            ParallelismSettings(**{"lane_workers": {"default": 0}})

    def test_rpm_negative_raises(self):
        """rpm=-1 → ValidationError (ge=0)."""
        with pytest.raises(ValidationError):
            PerOriginBudgetSettings(rpm=-1)

    def test_rpm_zero_is_valid(self):
        """rpm=0 is valid (ge=0)."""
        s = PerOriginBudgetSettings(rpm=0)
        assert s.rpm == 0

    def test_burst_negative_raises(self):
        """burst=-1 → ValidationError."""
        with pytest.raises(ValidationError):
            PerOriginBudgetSettings(burst=-1)

    def test_max_inflight_zero_raises(self):
        """max_inflight=0 → ValidationError (ge=1)."""
        with pytest.raises(ValidationError):
            PerOriginBudgetSettings(max_inflight=0)

    def test_cooldown_negative_raises(self):
        """cooldown_seconds=-1 → ValidationError (ge=0)."""
        with pytest.raises(ValidationError):
            PerOriginBudgetSettings(cooldown_seconds=-1.0)


class TestParallelismConfigYamlRoundtrip:
    """T-3.3: Full field YAML → parse → all values correct."""

    def test_full_config_parse(self):
        """All fields defined → parsed correctly."""
        s = ParallelismSettings(
            enabled=True,
            shadow_mode=False,
            default_executor="thread",
            lane_workers={"read_only": 10, "mutating": 2},
            per_origin_budget=PerOriginBudgetSettings(
                rpm=60, burst=20, max_inflight=5, cooldown_seconds=2.0,
            ),
            mutating=MutatingLaneSettings(
                enabled=True, allowlist=["https://example.com"],
            ),
            aggressive_exclusive=AggressiveLaneSettings(
                enabled=False, allowlist=[],
            ),
        )

        assert s.enabled is True
        assert s.shadow_mode is False
        assert s.default_executor == "thread"
        assert s.lane_workers == {"read_only": 10, "mutating": 2}
        assert s.per_origin_budget.rpm == 60
        assert s.per_origin_budget.burst == 20
        assert s.per_origin_budget.max_inflight == 5
        assert s.per_origin_budget.cooldown_seconds == 2.0
        assert s.mutating.enabled is True
        assert s.mutating.allowlist == ["https://example.com"]
        assert s.aggressive_exclusive.enabled is False

    def test_yaml_style_dict_parse(self):
        """Config passed as dict (YAML-like) parses correctly."""
        s = ParallelismSettings(**{
            "enabled": True,
            "per_origin_budget": {"rpm": 50, "burst": 15},
            "mutating": {"enabled": True, "allowlist": ["https://a.com"]},
        })
        assert s.enabled is True
        assert s.shadow_mode is True  # default
        assert s.per_origin_budget.rpm == 50
        assert s.mutating.enabled is True


# ============================================================
# Phase 5 (SGK-2026-0314): kill_switch field (LB-1)
# ============================================================

class TestParallelismKillSwitch:
    """Phase 5 LB-1: kill_switch field on ParallelismSettings."""

    def test_kill_switch_default_is_false(self):
        """kill_switch defaults to False (safe default)."""
        s = ParallelismSettings()
        assert s.kill_switch is False

    def test_kill_switch_can_be_set_true(self):
        """kill_switch can be set to True for emergency serial revert."""
        s = ParallelismSettings(kill_switch=True)
        assert s.kill_switch is True

    def test_kill_switch_with_enabled_false(self):
        """kill_switch=False with enabled=False is safe (already serial)."""
        s = ParallelismSettings(enabled=False, kill_switch=False)
        assert s.enabled is False
        assert s.kill_switch is False
