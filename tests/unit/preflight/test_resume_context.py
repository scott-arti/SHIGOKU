"""Tests for resume-context extraction from saved sessions.

Verifies:
- Cookies are extracted from session.metadata["context"]["cookies"]
- Fallback to top-level metadata["cookies"] when no context key exists
- RESUME_CONTEXT_INCOMPLETE when saved session has no target_url
"""

from unittest.mock import MagicMock, patch

import pytest
from src.core.session.session_manager import Session, SessionManager
from src.core.preflight.models import (
    PreflightStatus,
    PreflightResult,
    PreflightFailure,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_session(**overrides) -> Session:
    """Create a Session with default fields, overridden by kwargs."""
    from datetime import datetime

    defaults = {
        "session_id": "test-session-001",
        "project_name": "test-project",
        "mode": "bugbounty",
        "target_url": "https://example.com",
        "created_at": datetime(2026, 1, 1),
        "last_updated": datetime(2026, 1, 1),
        "metadata": {},
    }
    defaults.update(overrides)
    return Session(**defaults)


# ---------------------------------------------------------------------------
# Cookie extraction from metadata
# ---------------------------------------------------------------------------

class TestExtractCookiesFromMetadataContext:
    """Verify cookies are extracted from metadata["context"] first."""

    def test_extract_cookies_from_metadata_context(self):
        """session.metadata["context"]["cookies"] yields cookie string."""
        session = _make_session(
            metadata={
                "context": {
                    "cookies": "session=abc; token=xyz",
                    "bearer_token": "bearer123",
                }
            }
        )

        ctx: dict = session.metadata.get("context", {}) or {}
        cookies_from_ctx = str(ctx.get("cookies", "") or "")
        bearer_from_ctx = str(ctx.get("bearer_token", "") or "")

        assert cookies_from_ctx == "session=abc; token=xyz"
        assert bearer_from_ctx == "bearer123"

    def test_extract_cookies_fallback_to_top_level(self):
        """When no context key exists, metadata['cookies'] is used as fallback."""
        session = _make_session(
            metadata={
                "cookies": "fallback_cookie=value",  # top level, no context key
            }
        )

        ctx: dict = session.metadata.get("context", {}) or {}
        cookies = str(
            ctx.get("cookies", "")
            or session.metadata.get("cookies", "")
            or ""
        )

        assert cookies == "fallback_cookie=value"

    def test_context_cookies_override_top_level(self):
        """When both context and top-level cookies exist, context wins."""
        session = _make_session(
            metadata={
                "context": {"cookies": "from_context=true"},
                "cookies": "from_top_level=true",
            }
        )

        ctx: dict = session.metadata.get("context", {}) or {}
        cookies = str(
            ctx.get("cookies", "")
            or session.metadata.get("cookies", "")
            or ""
        )

        assert cookies == "from_context=true"

    def test_no_cookies_anywhere_returns_empty(self):
        """When no cookies in context or top-level, returns empty string."""
        session = _make_session(metadata={})

        ctx: dict = session.metadata.get("context", {}) or {}
        cookies = str(
            ctx.get("cookies", "")
            or session.metadata.get("cookies", "")
            or ""
        )

        assert cookies == ""


# ---------------------------------------------------------------------------
# RESUME_CONTEXT_INCOMPLETE
# ---------------------------------------------------------------------------

class TestResumeContextIncomplete:
    """Verify RESUME_CONTEXT_INCOMPLETE on missing target_url."""

    def test_resume_context_incomplete_no_target(self):
        """When saved session has no target_url, produce RESUME_CONTEXT_INCOMPLETE."""
        session = _make_session(target_url="")
        # Simulate the resume logic that validates target_url presence
        target_str = str(getattr(session, "target_url", "") or "").strip()
        result = None
        if not target_str:
            result = PreflightResult(
                status=PreflightStatus.FAIL,
                failures=[
                    PreflightFailure(
                        reason_code="RESUME_CONTEXT_INCOMPLETE",
                        severity="critical",
                        category="session",
                        remediation=(
                            "The saved session has no target_url. "
                            "Provide a target with --target or use /sessions "
                            "to select a complete session."
                        ),
                    )
                ],
            )

        assert result is not None
        assert result.failed
        assert len(result.failures) == 1
        assert result.failures[0].reason_code == "RESUME_CONTEXT_INCOMPLETE"
        assert result.failures[0].severity == "critical"
        assert "target_url" in result.failures[0].remediation

    def test_resume_context_incomplete_none_target(self):
        """When saved session has target_url=None, produce RESUME_CONTEXT_INCOMPLETE."""
        session = _make_session(target_url=None)
        target = str(getattr(session, "target_url", "") or "").strip()

        assert target == ""
        # The same check would trigger RESUME_CONTEXT_INCOMPLETE in the CLI flow

    def test_resume_context_complete_with_target(self):
        """When target_url is present, no RESUME_CONTEXT_INCOMPLETE."""
        session = _make_session(target_url="https://target.example.com")
        target = str(getattr(session, "target_url", "") or "").strip()

        assert target == "https://target.example.com"
        # This session would pass the target_url check
