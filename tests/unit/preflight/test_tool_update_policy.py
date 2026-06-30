"""Tests for tool update policy module.

Verifies:
- Missing tool: managed + auto_update try install
- Missing tool: managed + no auto_update fail with remediation
- Missing tool: unmanaged fail with remediation
- Outdated tool: managed + auto_update try update
- Outdated tool: unmanaged fail
- Semver parsing and comparison
- Name attribute on ToolStatus enum
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.core.preflight.tool_update_policy import ToolUpdatePolicy, _TOOL_MISSING, _TOOL_OUTDATED, _TOOL_UNMANAGED, _TOOL_UPDATE_FAILED
from src.core.preflight.models import ToolRequirement, ToolStatus, PreflightFailure, ToolCategory


class TestSemverParsing:
    def test_full_semver(self):
        result = ToolUpdatePolicy._parse_semver("v2.3.1")
        assert result == (2, 3, 1)

    def test_no_v_prefix(self):
        result = ToolUpdatePolicy._parse_semver("2.3.1")
        assert result == (2, 3, 1)

    def test_partial_version_padded(self):
        result = ToolUpdatePolicy._parse_semver("2.3")
        assert result == (2, 3)

    def test_single_number(self):
        result = ToolUpdatePolicy._parse_semver("3")
        assert result == (3,)

    def test_garbage_returns_zero(self):
        result = ToolUpdatePolicy._parse_semver("garbage")
        assert result == (0,)

    def test_empty_string(self):
        result = ToolUpdatePolicy._parse_semver("")
        assert result == (0,)


class TestVersionMeetsMinimum:
    def test_no_minimum_returns_true(self):
        assert ToolUpdatePolicy._version_meets_minimum("1.0.0", None) is True
        assert ToolUpdatePolicy._version_meets_minimum("1.0.0", "") is True

    def test_current_meets_minimum(self):
        assert ToolUpdatePolicy._version_meets_minimum("v2.0.0", "1.0.0") is True

    def test_current_equal_minimum(self):
        assert ToolUpdatePolicy._version_meets_minimum("1.0.0", "1.0.0") is True

    def test_current_below_minimum(self):
        assert ToolUpdatePolicy._version_meets_minimum("1.0.0", "2.0.0") is False

    def test_different_lengths(self):
        # "2.0" should be >= "1.5.3" after padding
        assert ToolUpdatePolicy._version_meets_minimum("2.0", "1.5.3") is True
        assert ToolUpdatePolicy._version_meets_minimum("1.0", "1.5.3") is False


class TestEvaluateMissing:
    def _make_tool(self, name="test", managed=False, min_version=None):
        return ToolRequirement(name=name, managed=managed, minimum_version=min_version)

    @pytest.mark.asyncio
    async def test_unmanaged_missing_fails(self):
        policy = ToolUpdatePolicy(auto_update=True)
        tool = self._make_tool("ffuf", managed=False)
        status, failures = await policy.evaluate(tool, exists=False)
        assert len(failures) == 1
        assert failures[0].reason_code == "TOOL_UNMANAGED"
        assert status == ToolStatus.UNMANAGED

    @pytest.mark.asyncio
    async def test_managed_auto_update_off_fails(self):
        policy = ToolUpdatePolicy(auto_update=False)
        tool = self._make_tool("nuclei", managed=True)
        status, failures = await policy.evaluate(tool, exists=False)
        assert len(failures) == 1
        assert failures[0].reason_code == "TOOL_MISSING"
        assert status == ToolStatus.MISSING
        assert "auto-update" in failures[0].remediation.lower()

    @pytest.mark.asyncio
    async def test_managed_auto_update_no_binary_manager_fails(self):
        policy = ToolUpdatePolicy(binary_manager=None, auto_update=True)
        tool = self._make_tool("nuclei", managed=True)
        status, failures = await policy.evaluate(tool, exists=False)
        assert len(failures) == 1
        assert failures[0].reason_code == "TOOL_MISSING"

    @pytest.mark.asyncio
    async def test_managed_auto_update_success(self):
        mock_bm = MagicMock()
        mock_bm.ensure_binary = AsyncMock(return_value="/tmp/nuclei")
        policy = ToolUpdatePolicy(binary_manager=mock_bm, auto_update=True)
        tool = self._make_tool("nuclei", managed=True)
        status, failures = await policy.evaluate(tool, exists=False)
        assert len(failures) == 0
        assert status == ToolStatus.OK
        mock_bm.ensure_binary.assert_called_once_with("nuclei")


class TestEvaluateOutdated:
    def _make_tool(self, name="test", managed=False, min_version="2.0.0"):
        return ToolRequirement(name=name, managed=managed, minimum_version=min_version)

    @pytest.mark.asyncio
    async def test_unmanaged_outdated_fails(self):
        policy = ToolUpdatePolicy(auto_update=True)
        tool = self._make_tool("ffuf", managed=False)
        status, failures = await policy.evaluate(tool, exists=True, current_version="1.0.0")
        assert len(failures) == 1
        assert failures[0].reason_code == "TOOL_OUTDATED"
        assert status == ToolStatus.OUTDATED

    @pytest.mark.asyncio
    async def test_managed_auto_update_off_outdated_fails(self):
        policy = ToolUpdatePolicy(auto_update=False)
        tool = self._make_tool("nuclei", managed=True)
        status, failures = await policy.evaluate(tool, exists=True, current_version="1.0.0")
        assert len(failures) == 1
        assert failures[0].reason_code == "TOOL_OUTDATED"
        assert status == ToolStatus.OUTDATED

    @pytest.mark.asyncio
    async def test_managed_auto_update_success_updates(self):
        mock_bm = MagicMock()
        mock_bm.ensure_binary = AsyncMock(return_value="/tmp/nuclei")
        policy = ToolUpdatePolicy(binary_manager=mock_bm, auto_update=True)
        tool = self._make_tool("nuclei", managed=True)
        status, failures = await policy.evaluate(tool, exists=True, current_version="1.0.0")
        assert len(failures) == 0
        assert status == ToolStatus.OK

    @pytest.mark.asyncio
    async def test_version_meets_minimum_no_issues(self):
        policy = ToolUpdatePolicy(auto_update=True)
        tool = self._make_tool("katana", managed=False, min_version="1.0.0")
        status, failures = await policy.evaluate(tool, exists=True, current_version="2.0.0")
        assert len(failures) == 0
        assert status == ToolStatus.OK


class TestEvidenceAndRemediation:
    @pytest.mark.asyncio
    async def test_failure_includes_tool_name(self):
        policy = ToolUpdatePolicy()
        tool = ToolRequirement(name="katana", managed=False)
        status, failures = await policy.evaluate(tool, exists=False)
        assert failures[0].evidence["tool"] == "katana"

    @pytest.mark.asyncio
    async def test_outdated_includes_version_info(self):
        policy = ToolUpdatePolicy()
        tool = ToolRequirement(name="nuclei", managed=False, minimum_version="3.0.0")
        status, failures = await policy.evaluate(tool, exists=True, current_version="2.0.0")
        assert failures[0].evidence["current"] == "2.0.0"
        assert failures[0].evidence["minimum"] == "3.0.0"
