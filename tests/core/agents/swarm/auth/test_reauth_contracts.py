"""
Test Reauth Contracts — payload validation and schema enforcement.

Tests for:
  - SessionExpiredPayload mandatory fields
  - ReauthSuccessPayload mandatory fields
  - ReauthFailedPayload mandatory fields + reason codes
  - AuthContext version bump
  - generate_reauth_attempt_id uniqueness
"""

import time
import pytest

from src.core.agents.swarm.auth.reauth_contracts import (
    AuthContext,
    SessionExpiredPayload,
    ReauthSuccessPayload,
    ReauthFailedPayload,
    generate_reauth_attempt_id,
    default_cooldown_until,
    is_valid_reason_code,
    REASON_CODES,
)


class TestAuthContext:
    """AuthContext unit tests."""

    def test_default_version_is_zero(self) -> None:
        ac = AuthContext()
        assert ac.auth_context_version == 0

    def test_bump_version_increments(self) -> None:
        ac = AuthContext()
        v1 = ac.bump_version()
        v2 = ac.bump_version()
        assert v1 == 1
        assert v2 == 2
        assert ac.auth_context_version == 2

    def test_from_dict_filters_unknown_keys(self) -> None:
        ac = AuthContext.from_dict(
            {
                "auth_context_version": 5,
                "refresh_url": "https://example.com/refresh",
                "unknown_field": "should be ignored",
            }
        )
        assert ac.auth_context_version == 5
        assert ac.refresh_url == "https://example.com/refresh"

    def test_to_dict_is_roundtrip(self) -> None:
        ac = AuthContext(
            login_request={"url": "/login", "method": "POST"},
            refresh_url="https://example.com/refresh",
            auth_context_version=3,
        )
        d = ac.to_dict()
        restored = AuthContext.from_dict(d)
        assert restored.auth_context_version == 3
        assert restored.refresh_url == "https://example.com/refresh"
        assert restored.login_request == {"url": "/login", "method": "POST"}

    def test_empty_auth_context_to_dict(self) -> None:
        ac = AuthContext()
        d = ac.to_dict()
        assert d["auth_context_version"] == 0
        assert d["login_request"] is None


class TestSessionExpiredPayload:
    """SESSION_EXPIRED payload contract tests."""

    def _valid_payload(self) -> SessionExpiredPayload:
        return SessionExpiredPayload(
            url="https://target.example/api/endpoint",
            method="GET",
            request_headers={"Authorization": "Bearer old_token"},
            origin_task_id="task_001",
            reauth_attempt_id=generate_reauth_attempt_id(),
            auth_context_version=1,
        )

    def test_to_dict_contains_all_fields(self) -> None:
        p = self._valid_payload()
        d = p.to_dict()
        assert d["url"] == "https://target.example/api/endpoint"
        assert d["method"] == "GET"
        assert d["request_headers"] == {"Authorization": "Bearer old_token"}
        assert d["origin_task_id"] == "task_001"
        assert d["reauth_attempt_id"].startswith("reauth_")
        assert d["auth_context_version"] == 1

    def test_validate_no_missing_on_complete_payload(self) -> None:
        p = self._valid_payload()
        missing = p.validate()
        assert missing == []

    def test_validate_missing_url(self) -> None:
        p = self._valid_payload()
        p.url = ""
        missing = p.validate()
        assert "url" in missing

    def test_validate_missing_method(self) -> None:
        p = self._valid_payload()
        p.method = ""
        missing = p.validate()
        assert "method" in missing

    def test_validate_missing_reauth_attempt_id(self) -> None:
        p = self._valid_payload()
        p.reauth_attempt_id = ""
        missing = p.validate()
        assert "reauth_attempt_id" in missing

    def test_validate_non_dict_headers(self) -> None:
        p = self._valid_payload()
        p.request_headers = "not_a_dict"  # type: ignore[assignment]
        missing = p.validate()
        assert "request_headers" in missing


class TestReauthSuccessPayload:
    """REAUTH_SUCCESS payload contract tests."""

    def _valid_payload(self) -> ReauthSuccessPayload:
        return ReauthSuccessPayload(
            target="https://target.example",
            reauth_attempt_id=generate_reauth_attempt_id(),
            method="token_refresh",
            new_tokens={"access_token": "new_access_123"},
            updated_cookies={"session": "new_session_cookie"},
            auth_context_version=2,
            success_evidence={"probe_url": "https://target.example/auth/me", "probe_status": 200},
        )

    def test_to_dict_contains_all_fields(self) -> None:
        p = self._valid_payload()
        d = p.to_dict()
        assert d["target"] == "https://target.example"
        assert d["method"] == "token_refresh"
        assert d["new_tokens"] == {"access_token": "new_access_123"}
        assert d["updated_cookies"] == {"session": "new_session_cookie"}
        assert d["success_evidence"]["probe_status"] == 200
        assert d["reauth_attempt_id"].startswith("reauth_")

    def test_validate_no_missing(self) -> None:
        p = self._valid_payload()
        assert p.validate() == []

    def test_validate_missing_target(self) -> None:
        p = self._valid_payload()
        p.target = ""
        missing = p.validate()
        assert "target" in missing

    def test_validate_missing_new_tokens(self) -> None:
        p = self._valid_payload()
        p.new_tokens = "not_a_dict"  # type: ignore[assignment]
        missing = p.validate()
        assert "new_tokens" in missing

    def test_validate_missing_reauth_attempt_id(self) -> None:
        p = self._valid_payload()
        p.reauth_attempt_id = ""
        missing = p.validate()
        assert "reauth_attempt_id" in missing


class TestReauthFailedPayload:
    """REAUTH_FAILED payload contract tests."""

    def _valid_payload(self) -> ReauthFailedPayload:
        return ReauthFailedPayload(
            target="https://target.example",
            reauth_attempt_id=generate_reauth_attempt_id(),
            reason_code="missing_refresh_url",
            reason_detail="No refresh_url found in auth context",
            attempted_strategies=["token_refresh"],
            cooldown_until=default_cooldown_until(seconds=30),
        )

    def test_to_dict_contains_all_fields(self) -> None:
        p = self._valid_payload()
        d = p.to_dict()
        assert d["target"] == "https://target.example"
        assert d["reason_code"] == "missing_refresh_url"
        assert d["reason_detail"] == "No refresh_url found in auth context"
        assert "token_refresh" in d["attempted_strategies"]

    def test_validate_no_missing(self) -> None:
        p = self._valid_payload()
        assert p.validate() == []

    def test_validate_invalid_reason_code(self) -> None:
        p = self._valid_payload()
        p.reason_code = "not_a_real_code"
        missing = p.validate()
        assert any("reason_code" in m for m in missing)

    def test_validate_missing_target(self) -> None:
        p = self._valid_payload()
        p.target = ""
        missing = p.validate()
        assert "target" in missing

    def test_validate_missing_reason_detail(self) -> None:
        p = self._valid_payload()
        p.reason_detail = ""
        missing = p.validate()
        assert "reason_detail" in missing

    def test_every_canonical_reason_code_is_valid(self) -> None:
        for code in REASON_CODES:
            assert is_valid_reason_code(code), f"{code} should be valid"

    def test_canonical_reason_codes_count(self) -> None:
        """Section 3.6 defines minimum 8 codes."""
        assert len(REASON_CODES) >= 8


class TestHelpers:
    """Test helper functions."""

    def test_generate_reauth_attempt_id_is_unique(self) -> None:
        ids = {generate_reauth_attempt_id() for _ in range(100)}
        assert len(ids) == 100

    def test_generate_reauth_attempt_id_prefix(self) -> None:
        aid = generate_reauth_attempt_id()
        assert aid.startswith("reauth_")

    def test_default_cooldown_until_future(self) -> None:
        now = time.time()
        cd = default_cooldown_until(seconds=30)
        assert cd > now
        # Should be roughly now+30, allow 5 second drift
        assert abs(cd - (now + 30)) < 5

    def test_default_cooldown_until_custom(self) -> None:
        now = time.time()
        cd = default_cooldown_until(seconds=120)
        assert abs(cd - (now + 120)) < 5
