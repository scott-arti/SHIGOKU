"""Tests for the tool-check module in the preflight entry gate.

Verifies:
- bbot is required for recon/full goals regardless of profile
- katana/nuclei/httpx/bbot are excluded for interactive goal
- Tool matrix filtering logic across goal/profile combinations
"""

import pytest
from src.core.preflight.tool_check import ToolChecker
from src.core.preflight.models import ToolRequirement, ToolCategory


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tool_names(tools: list[ToolRequirement]) -> list[str]:
    """Return sorted tool names from a list of ToolRequirement."""
    return sorted(t.name for t in tools)


# ---------------------------------------------------------------------------
# bbot in tool matrix
# ---------------------------------------------------------------------------

class TestBbotInToolMatrix:
    """Regression tests ensuring bbot is included for recon/full goals."""

    def test_bbot_required_for_recon_goal_any_profile(self):
        """goal='recon' with any profile (including empty) must include bbot."""
        checker = ToolChecker()
        tools = checker._filter_tools(goal="recon", profile="")
        names = _tool_names(tools)
        assert "bbot" in names, (
            f"bbot should be required for goal='recon', got: {names}"
        )

    def test_bbot_required_for_full_goal(self):
        """goal='full' must include bbot."""
        checker = ToolChecker()
        tools = checker._filter_tools(goal="full", profile="full")
        names = _tool_names(tools)
        assert "bbot" in names, (
            f"bbot should be required for goal='full', got: {names}"
        )

    def test_bbot_required_for_recon_goal_full_profile(self):
        """goal='recon' with profile='full' must include bbot."""
        checker = ToolChecker()
        tools = checker._filter_tools(goal="recon", profile="full")
        names = _tool_names(tools)
        assert "bbot" in names


# ---------------------------------------------------------------------------
# interactive goal exclusion
# ---------------------------------------------------------------------------

class TestInteractiveGoalExclusion:
    """Regression tests: interactive goal excludes katana/nuclei/httpx/bbot."""

    EXCLUDED_FOR_INTERACTIVE = {"katana", "nuclei", "httpx", "bbot"}

    def test_katana_not_required_for_interactive(self):
        """goal='interactive' must exclude katana, nuclei, httpx, and bbot."""
        checker = ToolChecker()
        tools = checker._filter_tools(goal="interactive", profile="")
        names = _tool_names(tools)
        for excluded in self.EXCLUDED_FOR_INTERACTIVE:
            assert excluded not in names, (
                f"{excluded} should NOT be required for interactive goal, got: {names}"
            )

    def test_no_tools_required_for_interactive_goal(self):
        """goal='interactive' should require zero tools from the default matrix."""
        checker = ToolChecker()
        tools = checker._filter_tools(goal="interactive", profile="")
        assert len(tools) == 0, (
            f"Expected 0 tools for interactive, got: {_tool_names(tools)}"
        )
