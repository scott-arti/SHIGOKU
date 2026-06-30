"""
Tool Update Policy for the preflight entry gate.

Decides when to auto-update, when to fail, and what remediation to suggest
for each tool during preflight tool-matrix checks.

Reason codes produced:
  TOOL_MISSING     — tool not found and cannot be auto-installed
  TOOL_OUTDATED    — tool present but below minimum version
  TOOL_UNMANAGED   — tool not managed by BinaryManager; manual install needed
  TOOL_UPDATE_FAILED — auto-update attempted but failed
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from src.core.preflight.models import PreflightFailure, ToolRequirement, ToolStatus
from src.core.adapters.external.binary_manager import (
    BinaryDownloadError,
    BinaryManager,
    BinaryVerificationError,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Reason-code constants (namespaced TOOL_* per the spec)
# ---------------------------------------------------------------------------

_TOOL_MISSING = "TOOL_MISSING"
_TOOL_OUTDATED = "TOOL_OUTDATED"
_TOOL_UNMANAGED = "TOOL_UNMANAGED"
_TOOL_UPDATE_FAILED = "TOOL_UPDATE_FAILED"


class ToolUpdatePolicy:
    """Policy engine: decide whether to install, update, or fail a tool.

    Encapsulates the decision tree for the tool-matrix checker so that
    the logic is reusable and testable independently of the gate loop.

    Usage::

        policy = ToolUpdatePolicy(binary_manager=bm, auto_update=True)
        status, failures = await policy.evaluate(tool_req, exists=True,
                                                  current_version="2.1.0")
    """

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(
        self,
        binary_manager: BinaryManager | None = None,
        auto_update: bool = True,
    ) -> None:
        """Initialise the policy.

        Args:
            binary_manager: The project's BinaryManager instance.  May be
                ``None`` (auto-install / auto-update become no-ops).
            auto_update: Whether automatic downloads are permitted.
                Should be ``False`` in strict-dev mode.
        """
        self.binary_manager = binary_manager
        self.auto_update = auto_update

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def evaluate(
        self,
        tool: ToolRequirement,
        exists: bool,
        current_version: str = "",
    ) -> tuple[ToolStatus, list[PreflightFailure]]:
        """Evaluate one tool and produce a status with any failures.

        Args:
            tool: The ``ToolRequirement`` describing what is needed.
            exists: Whether a binary with this name was located on the system.
            current_version: Detected version string (e.g. ``"v2.3.1"``).

        Returns:
            A ``(status, failures)`` pair.  When *status* is ``ToolStatus.OK``
            the failure list is guaranteed empty.
        """
        # -- Not present --
        if not exists:
            return await self._evaluate_missing(tool)

        # -- Present but version check required --
        if not self._version_meets_minimum(current_version, tool.minimum_version):
            return await self._evaluate_outdated(tool, current_version)

        # All good
        return (ToolStatus.OK, [])

    # ------------------------------------------------------------------
    # Private helpers: evaluate branches
    # ------------------------------------------------------------------

    async def _evaluate_missing(
        self, tool: ToolRequirement
    ) -> tuple[ToolStatus, list[PreflightFailure]]:
        """Handle the branch where the tool binary was not found."""
        if tool.managed and self.auto_update:
            return await self._try_install(tool)

        if tool.managed:
            # Managed but auto_update is off
            return (
                ToolStatus.MISSING,
                [
                    PreflightFailure(
                        reason_code=_TOOL_MISSING,
                        severity="critical",
                        category="Tool Not Found",
                        remediation=(
                            "Run with auto-update enabled or install "
                            f"'{tool.name}' manually."
                        ),
                        evidence={"tool": tool.name},
                    )
                ],
            )

        # Unmanaged — user must install themselves
        return (
            ToolStatus.UNMANAGED,
            [
                PreflightFailure(
                    reason_code=_TOOL_UNMANAGED,
                    severity="critical",
                    category="Unmanaged Tool",
                    remediation=(
                        f"Install '{tool.name}' via system package manager "
                        "or from the official site."
                    ),
                    evidence={"tool": tool.name},
                )
            ],
        )

    async def _evaluate_outdated(
        self, tool: ToolRequirement, current_version: str
    ) -> tuple[ToolStatus, list[PreflightFailure]]:
        """Handle the branch where the tool exists but is outdated."""
        min_ver = tool.minimum_version or "(no minimum)"

        if tool.managed and self.auto_update:
            return await self._try_update(tool, min_ver)

        evidence: dict = {
            "tool": tool.name,
            "current": current_version,
            "minimum": min_ver,
        }

        if tool.managed:
            return (
                ToolStatus.OUTDATED,
                [
                    PreflightFailure(
                        reason_code=_TOOL_OUTDATED,
                        severity="critical",
                        category="Tool Outdated",
                        remediation=(
                            f"Update '{tool.name}' to version {min_ver} "
                            "or enable auto-update."
                        ),
                        evidence=evidence,
                    )
                ],
            )

        # Unmanaged
        return (
            ToolStatus.OUTDATED,
            [
                PreflightFailure(
                    reason_code=_TOOL_OUTDATED,
                    severity="critical",
                    category="Tool Outdated",
                    remediation=(
                        f"Update '{tool.name}' to version {min_ver} manually."
                    ),
                    evidence=evidence,
                )
            ],
        )

    # ------------------------------------------------------------------
    # Private helpers: BinaryManager interactions
    # ------------------------------------------------------------------

    async def _try_install(
        self, tool: ToolRequirement
    ) -> tuple[ToolStatus, list[PreflightFailure]]:
        """Attempt ``ensure_binary`` for a missing managed tool."""
        if self.binary_manager is None:
            return (
                ToolStatus.MISSING,
                [
                    PreflightFailure(
                        reason_code=_TOOL_MISSING,
                        severity="critical",
                        category="Tool Not Found",
                        remediation=(
                            f"Install '{tool.name}' manually or configure "
                            "BinaryManager."
                        ),
                        evidence={"tool": tool.name},
                    )
                ],
            )

        try:
            await self.binary_manager.ensure_binary(tool.name)
            return (ToolStatus.OK, [])
        except (BinaryDownloadError, BinaryVerificationError) as exc:
            logger.error("Auto-install failed for %s: %s", tool.name, exc)
            return (
                ToolStatus.MISSING,
                [
                    PreflightFailure(
                        reason_code=_TOOL_MISSING,
                        severity="critical",
                        category="Tool Not Found",
                        remediation=(
                            f"Auto-install failed for '{tool.name}'. "
                            "Check network connectivity, tool configuration, "
                            "or install manually."
                        ),
                        evidence={"tool": tool.name, "error": str(exc)},
                    )
                ],
            )
        except Exception as exc:
            logger.error(
                "Unexpected error installing %s: %s", tool.name, exc
            )
            return (
                ToolStatus.MISSING,
                [
                    PreflightFailure(
                        reason_code=_TOOL_MISSING,
                        severity="critical",
                        category="Tool Not Found",
                        remediation=(
                            f"Unexpected error installing '{tool.name}'. "
                            "Check logs for details."
                        ),
                        evidence={"tool": tool.name, "error": str(exc)},
                    )
                ],
            )

    async def _try_update(
        self, tool: ToolRequirement, min_ver: str
    ) -> tuple[ToolStatus, list[PreflightFailure]]:
        """Attempt ``ensure_binary`` for an existing-but-outdated managed tool."""
        if self.binary_manager is None:
            return (
                ToolStatus.OUTDATED,
                [
                    PreflightFailure(
                        reason_code=_TOOL_OUTDATED,
                        severity="critical",
                        category="Tool Outdated",
                        remediation=(
                            f"Update '{tool.name}' to {min_ver} or configure "
                            "BinaryManager for auto-update."
                        ),
                        evidence={"tool": tool.name, "minimum": min_ver},
                    )
                ],
            )

        try:
            await self.binary_manager.ensure_binary(tool.name)
            return (ToolStatus.OK, [])
        except (BinaryDownloadError, BinaryVerificationError) as exc:
            logger.error("Auto-update failed for %s: %s", tool.name, exc)
            return (
                ToolStatus.UPDATE_FAILED,
                [
                    PreflightFailure(
                        reason_code=_TOOL_UPDATE_FAILED,
                        severity="critical",
                        category="Tool Update Failed",
                        remediation=(
                            f"Auto-update failed for '{tool.name}'. "
                            "Try manual update or install the latest version."
                        ),
                        evidence={
                            "tool": tool.name,
                            "minimum": min_ver,
                            "error": str(exc),
                        },
                    )
                ],
            )
        except Exception as exc:
            logger.error(
                "Unexpected error updating %s: %s", tool.name, exc
            )
            return (
                ToolStatus.UPDATE_FAILED,
                [
                    PreflightFailure(
                        reason_code=_TOOL_UPDATE_FAILED,
                        severity="critical",
                        category="Tool Update Failed",
                        remediation=(
                            f"Unexpected error updating '{tool.name}'. "
                            "Check logs for details."
                        ),
                        evidence={
                            "tool": tool.name,
                            "minimum": min_ver,
                            "error": str(exc),
                        },
                    )
                ],
            )

    # ------------------------------------------------------------------
    # Semver utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_semver(version_str: str) -> tuple[int, ...]:
        """Parse a semver-ish string into a tuple of ints.

        Examples::

            'v2.3.1'    -> (2, 3, 1)
            '2.3.1'     -> (2, 3, 1)
            '2.3'       -> (2, 3, 0)   ← padded for comparison
            '3'         -> (3,)
            'garbage'   -> (0,)         ← parse failure sentinel

        Args:
            version_str: Raw version string, optionally with a ``v`` prefix.

        Returns:
            Tuple of integers.  Returns ``(0,)`` when parsing fails.
        """
        if not version_str:
            return (0,)

        # Strip leading 'v' / 'V'
        stripped = version_str.lstrip("vV").strip()

        # Split on anything that is not a digit
        parts = re.split(r"\D+", stripped)
        # Discard empty strings from leading/trailing separators
        parts = [p for p in parts if p]

        if not parts:
            return (0,)

        try:
            return tuple(int(p) for p in parts)
        except (ValueError, TypeError):
            logger.debug("Failed to parse version string: %r", version_str)
            return (0,)

    @classmethod
    def _version_meets_minimum(
        cls, current: str, minimum: Optional[str]
    ) -> bool:
        """Check whether *current* satisfies the *minimum* version.

        Args:
            current: Detected version string.
            minimum: Required minimum semver.  ``None`` or empty means
                any version is acceptable.

        Returns:
            ``True`` if ``current >= minimum`` (element-wise tuple comparison)
            or when no minimum is enforced.
        """
        if not minimum:
            return True

        cur = cls._parse_semver(current)
        req = cls._parse_semver(minimum)

        # Pad the shorter tuple with zeros so element-wise comparison works
        max_len = max(len(cur), len(req))
        cur_padded = tuple(cur) + (0,) * (max_len - len(cur))
        req_padded = tuple(req) + (0,) * (max_len - len(req))

        return cur_padded >= req_padded
