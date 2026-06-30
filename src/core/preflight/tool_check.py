"""
Tool existence and version verification for the preflight entry gate.

Provides ToolChecker: checks required external tools exist on PATH,
verifies versions (when minimum_version is configured), handles
nuclei templates, and reports structured PreflightFailures.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
from pathlib import Path
from typing import Optional

from src.core.preflight.models import (
    PreflightFailure,
    ToolCategory,
    ToolRequirement,
    ToolStatus,
)
from src.core.preflight.tool_update_policy import ToolUpdatePolicy

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Reason codes
# ---------------------------------------------------------------------------

TOOL_MISSING = "TOOL_MISSING"
TOOL_OUTDATED = "TOOL_OUTDATED"
TOOL_UNMANAGED = "TOOL_UNMANAGED"
NUCLEI_TEMPLATES_MISSING = "NUCLEI_TEMPLATES_MISSING"

# ---------------------------------------------------------------------------
# Tool matrix
# ---------------------------------------------------------------------------

REQUIRED_TOOLS: list[ToolRequirement] = [
    ToolRequirement(
        name="katana",
        category=ToolCategory.NETWORK,
        managed=True,
        minimum_version="1.0.0",
        required_for_goals=["recon", "crawl", "analyze", "full"],
        required_for_profiles=["*"],
    ),
    ToolRequirement(
        name="nuclei",
        category=ToolCategory.SCANNING,
        managed=True,
        minimum_version="3.1.0",
        required_for_goals=["recon", "crawl", "analyze", "full", "xss", "injection"],
        required_for_profiles=["*"],
        needs_templates=True,
    ),
    ToolRequirement(
        name="bbot",
        category=ToolCategory.RECON,
        managed=False,
        required_for_goals=["recon", "full"],
        required_for_profiles=["*"],
    ),
    ToolRequirement(
        name="httpx",
        category=ToolCategory.NETWORK,
        managed=True,
        minimum_version="1.3.0",
        required_for_goals=["recon", "crawl", "analyze", "full"],
        required_for_profiles=["*"],
    ),
    ToolRequirement(
        name="subfinder",
        category=ToolCategory.ENUMERATION,
        managed=True,
        required_for_goals=["recon", "full"],
        required_for_profiles=["full"],
    ),
    ToolRequirement(
        name="gau",
        category=ToolCategory.ENUMERATION,
        managed=True,
        required_for_goals=["recon", "full"],
        required_for_profiles=["full"],
    ),
    ToolRequirement(
        name="ffuf",
        category=ToolCategory.FUZZING,
        managed=True,
        required_for_goals=["fuzzing", "full"],
        required_for_profiles=["full"],
    ),
    ToolRequirement(
        name="dalfox",
        category=ToolCategory.DAST,
        managed=False,
        required_for_goals=["xss", "injection", "full"],
        required_for_profiles=["full"],
    ),
    ToolRequirement(
        name="gospider",
        category=ToolCategory.RECON,
        managed=False,
        required_for_goals=["recon", "full"],
        required_for_profiles=["full"],
    ),
    ToolRequirement(
        name="amass",
        category=ToolCategory.ENUMERATION,
        managed=False,
        required_for_goals=["recon", "full"],
        required_for_profiles=["full"],
    ),
    ToolRequirement(
        name="subzy",
        category=ToolCategory.ENUMERATION,
        managed=False,
        required_for_goals=["recon", "full"],
        required_for_profiles=["full"],
    ),
    ToolRequirement(
        name="nmap",
        category=ToolCategory.NETWORK,
        managed=False,
        required_for_goals=["recon", "full"],
        required_for_profiles=["full"],
    ),
]


# ---------------------------------------------------------------------------
# ToolChecker
# ---------------------------------------------------------------------------


class ToolChecker:
    """Validates required external tools for the preflight entry gate.

    Checks existence on PATH, verifies versions against configured
    minimums, handles nuclei templates, and returns structured
    PreflightFailures.

    Usage::

        checker = ToolChecker()
        all_ok, failures = await checker.check(goal="full", profile="full")
        if not all_ok:
            for failure in failures:
                print(failure.reason_code, failure.remediation)

        # Per-tool status after check:
        for name, status in checker.results.items():
            print(name, status)
    """

    REQUIRED_TOOLS: list[ToolRequirement] = REQUIRED_TOOLS

    def __init__(
        self,
        tool_matrix: Optional[list[ToolRequirement]] = None,
        update_policy: Optional[ToolUpdatePolicy] = None,
    ) -> None:
        """Initialise the tool checker.

        Args:
            tool_matrix: Optional custom tool matrix.  Defaults to
                ``REQUIRED_TOOLS``.
            update_policy: Optional ``ToolUpdatePolicy`` for managed
                auto-install/update decisions.  When ``None``, the
                checker falls back to manual-only checks.
        """
        self._tool_matrix = tool_matrix if tool_matrix is not None else self.REQUIRED_TOOLS
        self._update_policy = update_policy
        self._results: dict[str, ToolStatus] = {}

    # ------------------------------------------------------------------
    # Public property
    # ------------------------------------------------------------------

    @property
    def results(self) -> dict[str, ToolStatus]:
        """Per-tool status map populated by the last ``check()`` call."""
        return dict(self._results)

    # ------------------------------------------------------------------
    # Top-level entry point
    # ------------------------------------------------------------------

    async def check(
        self,
        goal: str = "",
        profile: str = "",
    ) -> tuple[bool, list[PreflightFailure]]:
        """Execute the full tool-check gate.

        Filters the tool matrix by *goal* and *profile*, then checks
        each required tool for existence, version, and (for nuclei)
        templates.

        Args:
            goal: The execution goal (e.g. ``'recon'``, ``'xss'``,
                ``'full'``).
            profile: The execution profile (e.g. ``'full'``).

        Returns:
            Tuple of ``(all_ok, failures)``.  ``all_ok`` is ``True``
            when no failures were detected.
        """
        tools = self._filter_tools(goal, profile)

        self._results.clear()
        failures: list[PreflightFailure] = []

        if not tools:
            logger.info(
                "No tools required for goal=%r profile=%r", goal, profile
            )
            return True, []

        for tool in tools:
            status, tool_failures = await self._check_single_tool(tool)
            self._results[tool.name] = status
            failures.extend(tool_failures)

        all_ok = len(failures) == 0
        logger.info(
            "Tool check complete: ok=%s failures=%d statuses=%d",
            all_ok,
            len(failures),
            len(self._results),
        )
        return all_ok, failures

    # ------------------------------------------------------------------
    # Context filtering
    # ------------------------------------------------------------------

    def _filter_tools(
        self, goal: str, profile: str
    ) -> list[ToolRequirement]:
        """Filter the tool matrix by *goal* and *profile*.

        A tool is required when its ``required_for_goals`` list contains
        ``"*"`` or the specific *goal* value **and** its
        ``required_for_profiles`` list contains ``"*"`` or the specific
        *profile* value.

        Args:
            goal: The execution goal.
            profile: The execution profile.

        Returns:
            List of required ``ToolRequirement`` objects.
        """
        required: list[ToolRequirement] = []

        for tool in self._tool_matrix:
            goal_match = (
                "*" in tool.required_for_goals
                or goal in tool.required_for_goals
            )
            profile_match = (
                "*" in tool.required_for_profiles
                or profile in tool.required_for_profiles
            )
            if goal_match and profile_match:
                required.append(tool)

        logger.debug(
            "Filtered %d tools for goal=%r profile=%r (from %d total)",
            len(required),
            goal,
            profile,
            len(self._tool_matrix),
        )
        return required

    # ------------------------------------------------------------------
    # Single-tool check
    # ------------------------------------------------------------------

    async def _check_single_tool(
        self, tool: ToolRequirement,
    ) -> tuple[ToolStatus, list[PreflightFailure]]:
        """Run all checks for a single tool requirement.

        Checks existence, version, and consults ``ToolUpdatePolicy`` when
        available.  Falls back to manual-only checks when no policy is
        configured.

        Args:
            tool: The ``ToolRequirement`` to verify.

        Returns:
            Tuple of ``(status, failures)``.  *failures* is an empty
            list when all checks pass.
        """
        # 1. Check existence
        exists, bin_path = await self._check_tool_exists(tool.name)

        # 2. Check version
        version_str = "unknown"
        if exists:
            _, version_str = await self._check_tool_version(tool.name)

        # 3. If update_policy is available, delegate to it
        if self._update_policy is not None:
            status, failures = await self._update_policy.evaluate(
                tool, exists, version_str,
            )
            # When the policy reports OK, still verify nuclei templates
            if status == ToolStatus.OK:
                if tool.needs_templates:
                    templates_ok, _ = await self._check_nuclei_templates()
                    if not templates_ok:
                        return (
                            ToolStatus.TEMPLATES_MISSING,
                            [
                                PreflightFailure(
                                    reason_code=NUCLEI_TEMPLATES_MISSING,
                                    severity="critical",
                                    category="tool",
                                    remediation=(
                                        "Run 'nuclei -update-templates' or "
                                        "clone https://github.com/"
                                        "projectdiscovery/nuclei-templates "
                                        "to ~/nuclei-templates"
                                    ),
                                    evidence={"tool": tool.name},
                                )
                            ],
                        )
                return ToolStatus.OK, []
            # Policy returned a non-OK status with failures
            return status, failures

        # 4. Fallback: manual-only checks (no update policy available)
        if not exists:
            return (
                ToolStatus.MISSING,
                [
                    PreflightFailure(
                        reason_code=TOOL_MISSING,
                        severity="critical",
                        category="tool",
                        remediation=(
                            f"Install {tool.name} or ensure it is on "
                            "PATH. Refer to the project documentation "
                            "for installation instructions."
                        ),
                        evidence={"tool": tool.name},
                    )
                ],
            )

        # Version check (only when minimum_version is configured)
        if tool.minimum_version is not None:
            version_semver = _extract_semver(version_str)
            if version_semver and _version_less_than(
                version_semver, tool.minimum_version
            ):
                return (
                    ToolStatus.OUTDATED,
                    [
                        PreflightFailure(
                            reason_code=TOOL_OUTDATED,
                            severity="critical",
                            category="tool",
                            remediation=(
                                f"{tool.name} version {version_semver} "
                                f"is below the required minimum "
                                f"{tool.minimum_version}. Please update."
                            ),
                            evidence={
                                "tool": tool.name,
                                "current_version": version_semver,
                                "minimum_version": tool.minimum_version,
                            },
                        )
                    ],
                )

        # Nuclei templates
        if tool.needs_templates:
            templates_ok, _ = await self._check_nuclei_templates()
            if not templates_ok:
                return (
                    ToolStatus.TEMPLATES_MISSING,
                    [
                        PreflightFailure(
                            reason_code=NUCLEI_TEMPLATES_MISSING,
                            severity="critical",
                            category="tool",
                            remediation=(
                                "Run 'nuclei -update-templates' or clone "
                                "https://github.com/projectdiscovery/"
                                "nuclei-templates to ~/nuclei-templates"
                            ),
                            evidence={"tool": tool.name},
                        )
                    ],
                )

        return ToolStatus.OK, []

    # ------------------------------------------------------------------
    # Existence check
    # ------------------------------------------------------------------

    async def _check_tool_exists(
        self, tool_name: str
    ) -> tuple[bool, Optional[str]]:
        """Check whether a tool binary exists on PATH.

        Args:
            tool_name: Name of the tool binary (e.g. ``'nuclei'``).

        Returns:
            Tuple of ``(found, path)``.  *path* is ``None`` when the
            tool is not found.
        """
        system_path = shutil.which(tool_name)
        if system_path:
            logger.debug("Found %s on PATH at %s", tool_name, system_path)
            return True, system_path

        logger.debug("Tool %s not found", tool_name)
        return False, None

    # ------------------------------------------------------------------
    # Version check
    # ------------------------------------------------------------------

    async def _check_tool_version(
        self, tool_name: str,
    ) -> tuple[bool, str]:
        """Check the version of a tool binary.

        Runs ``{tool_name} --version`` then ``{tool_name} -version`` if
        the first attempt produces no output.  Times out after 3
        seconds.

        Args:
            tool_name: Name of the tool binary.

        Returns:
            Tuple of ``(ok, version_string)``.  On failure returns
            ``(False, "unknown")``.
        """
        version_flags = ["--version", "-version"]

        for flag in version_flags:
            try:
                proc = await asyncio.create_subprocess_exec(
                    tool_name,
                    flag,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=3.0
                )

                output = stdout.decode("utf-8", errors="replace").strip()
                if not output:
                    output = stderr.decode("utf-8", errors="replace").strip()

                if output:
                    logger.debug(
                        "Version for %s (flag=%s, rc=%d): %s",
                        tool_name,
                        flag,
                        proc.returncode,
                        output,
                    )
                    return True, output

            except asyncio.TimeoutError:
                logger.warning(
                    "Version check timed out for %s (flag=%s)",
                    tool_name,
                    flag,
                )
                continue
            except FileNotFoundError:
                logger.debug(
                    "Binary %s not found for version check", tool_name,
                )
                return False, "unknown"
            except OSError as exc:
                logger.warning(
                    "Version check error for %s (flag=%s): %s",
                    tool_name,
                    flag,
                    exc,
                )
                continue

        logger.warning("All version checks failed for %s", tool_name)
        return False, "unknown"

    # ------------------------------------------------------------------
    # Nuclei templates
    # ------------------------------------------------------------------

    async def _check_nuclei_templates(
        self,
    ) -> tuple[bool, Optional[str]]:
        """Verify that nuclei templates are present on disk.

        Checks common template directories for ``*.yaml`` / ``*.yml``
        files and falls back to querying the nuclei binary for its
        template version.

        Returns:
            Tuple of ``(ok, templates_path)``.  *templates_path* is
            ``None`` when templates cannot be located.
        """
        home = Path.home()
        candidate_paths: list[Path] = [
            home / "nuclei-templates",
            home / ".config" / "nuclei" / "templates",
            Path(os.environ.get("HOME", str(home))) / "nuclei-templates",
        ]

        # 1. Check known directories for template files
        for templates_dir in candidate_paths:
            if not templates_dir.is_dir():
                continue
            try:
                yaml_files = list(templates_dir.rglob("*.yaml")) + list(
                    templates_dir.rglob("*.yml")
                )
                if yaml_files:
                    logger.debug(
                        "Nuclei templates found at %s (%d templates)",
                        templates_dir,
                        len(yaml_files),
                    )
                    return True, str(templates_dir)
            except OSError as exc:
                logger.debug(
                    "Cannot scan nuclei templates directory %s: %s",
                    templates_dir,
                    exc,
                )
                continue

        # 2. Ask the nuclei binary for template count
        try:
            proc = await asyncio.create_subprocess_exec(
                "nuclei",
                "-templates-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _stderr = await asyncio.wait_for(
                proc.communicate(), timeout=3.0
            )
            output = stdout.decode("utf-8", errors="replace").strip()
            if output and proc.returncode == 0:
                logger.debug("nuclei templates version: %s", output)
                return True, "nuclei-managed"
        except asyncio.TimeoutError:
            logger.debug("nuclei templates-version check timed out")
        except FileNotFoundError:
            logger.debug("nuclei binary not found for template check")
        except OSError as exc:
            logger.debug("nuclei templates check error: %s", exc)

        logger.warning("Nuclei templates not found")
        return False, None


# ---------------------------------------------------------------------------
# Internal helpers (module-level to avoid unnecessary coupling)
# ---------------------------------------------------------------------------


def _extract_semver(raw: str) -> str:
    """Extract a semver-like substring from a raw version string.

    Handles common prefixes like ``v`` (e.g. ``v2.9.3`` → ``2.9.3``).

    Returns:
        The semver substring, or an empty string if no match.
    """
    match = re.search(r"(\d+\.\d+(?:\.\d+)?)", raw)
    return match.group(1) if match else ""


def _version_less_than(current: str, minimum: str) -> bool:
    """Return ``True`` when *current* is strictly less than *minimum*.

    Both arguments are expected to be semver-like strings
    (``MAJOR.MINOR`` or ``MAJOR.MINOR.PATCH``).
    """

    def _parse(v: str) -> tuple[int, ...]:
        return tuple(int(p) for p in v.split(".") if p.isdigit())

    try:
        return _parse(current) < _parse(minimum)
    except Exception:
        return False
