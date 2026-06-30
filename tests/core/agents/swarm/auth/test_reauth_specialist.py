"""
Test AutoReauthSpecialist — real token extraction, preflight, reason codes.

SGK-2026-0280 Section 3.4, 3.5, 3.6.

Tests:
  - Token refresh with real HTTP response extraction
  - Login replay with preflight CSRF token injection
  - Success evidence (Set-Cookie, endpoint probe, schema validation)
  - Failure reason codes (missing_refresh_url, network_client_unavailable,
    token_extraction_failed, login_replay_non_200)
  - Synthetic tokens NOT used as success evidence
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Any

from src.core.agents.swarm.auth.reauth_specialist import (
    AutoReauthSpecialist,
    _extract_token_from_body,
    _extract_cookies_from_response,
    _build_refresh_url,
)
from src.core.agents.swarm.base import Task
from src.core.infra.event_bus import Event, EventType
from src.core.agents.swarm.auth.reauth_contracts import (
    generate_reauth_attempt_id,
    REASON_CODES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_token_refresh_response(
    status=200,
    body: str = '{"access_token":"new_jwt_token_abc123","refresh_token":"new_refresh_xyz"}',
    cookies: dict[str, str] | None = None,
) -> MagicMock:
    """Create a mock NetworkResponse for a token refresh endpoint."""
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    resp.cookies = cookies or {}
    return resp


def _make_login_replay_response(
    status=200,
    body: str = "",
    cookies: dict[str, str] | None = None,
) -> MagicMock:
    """Create a mock NetworkResponse for a login replay."""
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    resp.cookies = cookies or {}
    return resp


def _make_reauth_task(
    target: str = "https://target.example",
    auth_tokens: dict[str, Any] | None = None,
    login_request: dict[str, Any] | None = None,
) -> Task:
    """Create a Task for reauth testing."""
    return Task(
        id=f"reauth_test_{id(auth_tokens)}",
        name="auto_reauth",
        target=target,
        params={
            "auth_tokens": auth_tokens or {},
            "login_request": login_request,
            "reauth_attempt_id": generate_reauth_attempt_id(),
        },
        tags=["auth", "reauth"],
    )


# ---------------------------------------------------------------------------
# Token extraction unit tests
# ---------------------------------------------------------------------------

class TestTokenExtraction:
    """Test _extract_token_from_body with real regex patterns."""

    def test_extract_json_access_token(self) -> None:
        body = '{"access_token":"abc123","token_type":"bearer"}'
        from src.core.agents.swarm.auth.reauth_specialist import _ACCESS_TOKEN_PATTERNS
        token = _extract_token_from_body(body, _ACCESS_TOKEN_PATTERNS)
        assert token == "abc123"

    def test_extract_url_encoded_token(self) -> None:
        body = "access_token=xyz789&expires_in=3600"
        from src.core.agents.swarm.auth.reauth_specialist import _ACCESS_TOKEN_PATTERNS
        token = _extract_token_from_body(body, _ACCESS_TOKEN_PATTERNS)
        assert token == "xyz789"

    def test_extract_refresh_token_json(self) -> None:
        body = '{"refresh_token":"ref456"}'
        from src.core.agents.swarm.auth.reauth_specialist import _REFRESH_TOKEN_PATTERNS
        token = _extract_token_from_body(body, _REFRESH_TOKEN_PATTERNS)
        assert token == "ref456"

    def test_extract_none_on_empty_body(self) -> None:
        from src.core.agents.swarm.auth.reauth_specialist import _ACCESS_TOKEN_PATTERNS
        assert _extract_token_from_body("", _ACCESS_TOKEN_PATTERNS) is None
        assert _extract_token_from_body(None, _ACCESS_TOKEN_PATTERNS) is None  # type: ignore[arg-type]

    def test_extract_csrf_from_html(self) -> None:
        from src.core.agents.swarm.auth.reauth_specialist import _CSRF_TOKEN_PATTERNS
        html = '<form><input type="hidden" name="csrf_token" value="csrf_val_123"></form>'
        token = _extract_token_from_body(html, _CSRF_TOKEN_PATTERNS)
        assert token == "csrf_val_123"

    def test_extract_csrf_meta(self) -> None:
        from src.core.agents.swarm.auth.reauth_specialist import _CSRF_TOKEN_PATTERNS
        html = '<meta name="csrf-token" content="meta_csrf_456">'
        token = _extract_token_from_body(html, _CSRF_TOKEN_PATTERNS)
        assert token == "meta_csrf_456"


# ---------------------------------------------------------------------------
# Build refresh URL
# ---------------------------------------------------------------------------

class TestBuildRefreshUrl:
    def test_explicit_full_url_used(self) -> None:
        assert _build_refresh_url("https://app.example/api", "https://auth.example/refresh") == "https://auth.example/refresh"

    def test_relative_path_joined(self) -> None:
        assert _build_refresh_url("https://app.example", "/auth/refresh") == "https://app.example/auth/refresh"

    def test_no_hint_returns_fallback(self) -> None:
        result = _build_refresh_url("https://app.example")
        assert result is not None
        assert result.startswith("https://app.example")

    def test_none_hint_returns_fallback(self) -> None:
        result = _build_refresh_url("https://app.example", None)
        assert result is not None


# ---------------------------------------------------------------------------
# Cookie extraction
# ---------------------------------------------------------------------------

class TestCookieExtraction:
    def test_extract_from_network_response(self) -> None:
        resp = MagicMock()
        resp.cookies = {"session": "sess_abc", "csrf": "csrf_xyz"}
        cookies = _extract_cookies_from_response(resp)
        assert cookies == {"session": "sess_abc", "csrf": "csrf_xyz"}

    def test_extract_from_dict(self) -> None:
        cookies = _extract_cookies_from_response({"cookies": {"a": "1"}})
        assert cookies == {"a": "1"}

    def test_empty_when_no_cookies(self) -> None:
        resp = MagicMock()
        resp.cookies = {}
        cookies = _extract_cookies_from_response(resp)
        assert cookies == {}


# ---------------------------------------------------------------------------
# AutoReauthSpecialist — Token Refresh (with mocked NetworkClient)
# ---------------------------------------------------------------------------

class TestTokenRefreshStrategy:
    """Test Strategy 1: Token Refresh with real HTTP responses."""

    @pytest.mark.asyncio
    async def test_token_refresh_success_with_real_extraction(self) -> None:
        specialist = AutoReauthSpecialist()
        specialist.network_client = AsyncMock()
        specialist.network_client.request = AsyncMock(
            return_value=_make_token_refresh_response(
                status=200,
                body='{"access_token":"extracted_real_token","refresh_token":"extracted_refresh"}',
                cookies={"session": "new_session"},
            )
        )

        task = _make_reauth_task(
            target="https://target.example",
            auth_tokens={
                "refresh_url": "https://target.example/api/refresh",
                "refresh_token": "old_refresh",
            },
        )

        # Capture event bus emissions
        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        findings = await specialist.execute(task)
        assert findings == []
        assert len(emitted_events) == 1
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_SUCCESS
        assert event.payload.get("method") == "token_refresh"
        # Synthetic token check: must not contain placeholder
        assert "placeholder" not in str(event.payload.get("new_tokens", {}))
        assert "recovered_" not in str(event.payload.get("new_tokens", {}))
        # Must have real extracted token
        assert event.payload["new_tokens"].get("access_token") == "extracted_real_token"
        assert event.payload["updated_cookies"] == {"session": "new_session"}

    @pytest.mark.asyncio
    async def test_token_refresh_none_200_fails_with_reason_code(self) -> None:
        specialist = AutoReauthSpecialist()
        specialist.network_client = AsyncMock()
        specialist.network_client.request = AsyncMock(
            return_value=_make_token_refresh_response(status=500, body="Internal Error")
        )

        task = _make_reauth_task(
            target="https://target.example",
            auth_tokens={
                "refresh_url": "https://target.example/api/refresh",
                "refresh_token": "old_refresh",
            },
        )

        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_FAILED
        assert event.payload["reason_code"] == "login_replay_non_200"
        assert "500" in event.payload["reason_detail"]

    @pytest.mark.asyncio
    async def test_token_refresh_no_extracted_token_fails(self) -> None:
        specialist = AutoReauthSpecialist()
        specialist.network_client = AsyncMock()
        specialist.network_client.request = AsyncMock(
            return_value=_make_token_refresh_response(status=200, body="OK", cookies={})
        )

        task = _make_reauth_task(
            target="https://target.example",
            auth_tokens={
                "refresh_url": "https://target.example/api/refresh",
                "refresh_token": "old_refresh",
            },
        )

        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_FAILED
        assert event.payload["reason_code"] == "token_extraction_failed"

    @pytest.mark.asyncio
    async def test_token_refresh_missing_refresh_url(self) -> None:
        specialist = AutoReauthSpecialist()
        task = _make_reauth_task(
            target="https://target.example",
            auth_tokens={"refresh_token": "token_only"},
        )

        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        # No refresh_url → falls through to login_replay; if no login_request, fails
        assert event.type == EventType.REAUTH_FAILED
        assert event.payload["reason_code"] in REASON_CODES

    @pytest.mark.asyncio
    async def test_token_refresh_none_network_client(self) -> None:
        specialist = AutoReauthSpecialist()
        specialist.network_client = None  # No client set

        task = _make_reauth_task(
            target="https://target.example",
            auth_tokens={
                "refresh_url": "https://target.example/api/refresh",
                "refresh_token": "old_refresh",
            },
        )

        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_FAILED
        assert event.payload["reason_code"] == "network_client_unavailable"


# ---------------------------------------------------------------------------
# AutoReauthSpecialist — Login Replay (with preflight)
# ---------------------------------------------------------------------------

class TestLoginReplayStrategy:
    """Test Strategy 2: Login Replay with preflight."""

    @pytest.mark.asyncio
    async def test_login_replay_success(self) -> None:
        specialist = AutoReauthSpecialist()
        specialist.network_client = AsyncMock()

        # First request = preflight GET, second = login POST
        preflight_resp = MagicMock()
        preflight_resp.status_code = 200
        preflight_resp.text = ""
        preflight_resp.cookies = {}

        login_resp = MagicMock()
        login_resp.status_code = 200
        login_resp.text = '{"access_token":"login_extracted_token"}'
        login_resp.cookies = {"auth_cookie": "cookie_val"}

        specialist.network_client.request = AsyncMock(side_effect=[preflight_resp, login_resp])

        task = _make_reauth_task(
            target="https://target.example",
            auth_tokens={},  # No refresh_token → falls back to login replay
            login_request={
                "method": "POST",
                "url": "https://target.example/login",
                "headers": {"Content-Type": "application/json"},
                "body": {"username": "user", "password": "pass"},
            },
        )

        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_SUCCESS
        assert event.payload["method"] == "login_replay"
        assert event.payload["new_tokens"]["access_token"] == "login_extracted_token"
        assert event.payload["updated_cookies"] == {"auth_cookie": "cookie_val"}
        # Synthetic token check
        assert "placeholder" not in str(event.payload["new_tokens"])
        assert "replayed_token" not in str(event.payload.get("new_tokens", {}))

    @pytest.mark.asyncio
    async def test_login_replay_non_200_fails(self) -> None:
        specialist = AutoReauthSpecialist()
        specialist.network_client = AsyncMock()

        preflight_resp = MagicMock(status_code=200, text="", cookies={})
        login_resp = MagicMock(status_code=403, text="Forbidden", cookies={})

        specialist.network_client.request = AsyncMock(side_effect=[preflight_resp, login_resp])

        task = _make_reauth_task(
            target="https://target.example",
            auth_tokens={},
            login_request={
                "method": "POST",
                "url": "https://target.example/login",
                "headers": {},
                "body": {},
            },
        )

        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_FAILED
        assert event.payload["reason_code"] == "login_replay_non_200"

    @pytest.mark.asyncio
    async def test_login_replay_preflight_extracts_csrf(self) -> None:
        specialist = AutoReauthSpecialist()
        specialist.network_client = AsyncMock()

        preflight_html = '<html><form><input type="hidden" name="csrf_token" value="csrf_preflight_123"></form></html>'
        preflight_resp = MagicMock(status_code=200, text=preflight_html, cookies={})

        login_resp = MagicMock(status_code=200, text='{"access_token":"token_ok"}', cookies={"session": "sess"})

        specialist.network_client.request = AsyncMock(side_effect=[preflight_resp, login_resp])

        task = _make_reauth_task(
            target="https://target.example",
            auth_tokens={},
            login_request={
                "method": "POST",
                "url": "https://target.example/login",
                "headers": {"Content-Type": "application/json"},
                "body": {"username": "user"},
            },
        )

        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_SUCCESS
        assert event.payload["method"] == "login_replay"

    @pytest.mark.asyncio
    async def test_login_replay_none_network_client(self) -> None:
        specialist = AutoReauthSpecialist()
        specialist.network_client = None

        task = _make_reauth_task(
            target="https://target.example",
            auth_tokens={},
            login_request={
                "method": "POST",
                "url": "https://target.example/login",
                "headers": {},
                "body": {},
            },
        )

        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_FAILED
        assert event.payload["reason_code"] == "network_client_unavailable"


# ---------------------------------------------------------------------------
# AutoReauthSpecialist — Edge cases
# ---------------------------------------------------------------------------

class TestReauthEdgeCases:
    """Edge case tests for AutoReauthSpecialist."""

    @pytest.mark.asyncio
    async def test_all_reason_codes_are_defined(self) -> None:
        """Section 3.6: Minimum 8 reason codes defined."""
        assert len(REASON_CODES) >= 8
        expected = {
            "missing_refresh_url", "missing_login_request",
            "network_client_unavailable", "csrf_token_missing",
            "token_extraction_failed", "login_replay_non_200",
            "reauth_storm_suppressed", "unsupported_auth_scheme",
        }
        assert expected.issubset(REASON_CODES)

    @pytest.mark.asyncio
    async def test_failure_includes_attempted_strategies(self) -> None:
        specialist = AutoReauthSpecialist()
        specialist.network_client = None  # Causes both strategies to fail

        task = _make_reauth_task(
            target="https://target.example",
            auth_tokens={"refresh_token": "t"},
            login_request={"method": "POST", "url": "https://target.example/login"},
        )

        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_FAILED
        assert "token_refresh" in event.payload["attempted_strategies"]
        assert "login_replay" in event.payload["attempted_strategies"]

    @pytest.mark.asyncio
    async def test_failure_includes_cooldown_until(self) -> None:
        specialist = AutoReauthSpecialist()
        specialist.network_client = None

        task = _make_reauth_task(
            target="https://target.example",
            auth_tokens={"refresh_token": "t"},
        )

        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_FAILED
        assert isinstance(event.payload["cooldown_until"], float)
        assert event.payload["cooldown_until"] > 0

    @pytest.mark.asyncio
    async def test_success_includes_reauth_attempt_id(self) -> None:
        specialist = AutoReauthSpecialist()
        specialist.network_client = AsyncMock()
        specialist.network_client.request = AsyncMock(
            return_value=_make_token_refresh_response(
                status=200,
                body='{"access_token":"tok"}',
            )
        )

        task = _make_reauth_task(
            target="https://target.example",
            auth_tokens={
                "refresh_url": "https://target.example/api/refresh",
                "refresh_token": "tok",
            },
        )

        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_SUCCESS
        assert event.payload["reauth_attempt_id"].startswith("reauth_")


# ---------------------------------------------------------------------------
# Unsupported auth scheme detection (Section 3.5)
# ---------------------------------------------------------------------------

class TestUnsupportedAuthScheme:
    """OIDC/SAML/MFA detection tests."""

    @pytest.mark.asyncio
    async def test_oidc_url_detected_as_unsupported(self) -> None:
        specialist = AutoReauthSpecialist()
        # Login URL contains OIDC indicators
        task = _make_reauth_task(
            target="https://sso.example.com",
            auth_tokens={},
            login_request={
                "method": "POST",
                "url": "https://sso.example.com/authorize?response_type=code+id_token&nonce=abc",
                "headers": {},
                "body": {},
            },
        )
        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_FAILED
        assert event.payload["reason_code"] == "unsupported_auth_scheme"
        assert "oidc" in event.payload.get("reason_detail", "").lower()

    @pytest.mark.asyncio
    async def test_saml_in_preflight_detected_as_unsupported(self) -> None:
        specialist = AutoReauthSpecialist()
        specialist.network_client = AsyncMock()

        preflight_resp = MagicMock()
        preflight_resp.status_code = 200
        preflight_resp.text = '<html><form action="/saml2/login"><input type="hidden" name="SAMLRequest" value="..."></form></html>'
        preflight_resp.cookies = {}
        preflight_resp.headers = {}

        specialist.network_client.request = AsyncMock(return_value=preflight_resp)

        task = _make_reauth_task(
            target="https://sso.example.com",
            auth_tokens={},
            login_request={
                "method": "POST",
                "url": "https://sso.example.com/login",
                "headers": {},
                "body": {},
            },
        )
        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_FAILED
        assert event.payload["reason_code"] == "unsupported_auth_scheme"
        assert "saml" in event.payload.get("reason_detail", "").lower()

    @pytest.mark.asyncio
    async def test_mfa_url_detected_as_unsupported(self) -> None:
        specialist = AutoReauthSpecialist()
        specialist.network_client = AsyncMock()

        preflight_resp = MagicMock()
        preflight_resp.status_code = 200
        preflight_resp.text = '<html><form action="/mfa/verify"><input type="text" name="totp"></form></html>'
        preflight_resp.cookies = {}
        preflight_resp.headers = {}

        specialist.network_client.request = AsyncMock(return_value=preflight_resp)

        task = _make_reauth_task(
            target="https://secure.example.com",
            auth_tokens={},
            login_request={
                "method": "POST",
                "url": "https://secure.example.com/2fa/",
                "headers": {},
                "body": {},
            },
        )
        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_FAILED
        assert event.payload["reason_code"] == "unsupported_auth_scheme"


# ---------------------------------------------------------------------------
# CSRF token missing detection (Section 3.5)
# ---------------------------------------------------------------------------

class TestCsrfMissing:
    """CSRF token required but not found tests."""

    @pytest.mark.asyncio
    async def test_form_login_without_csrf_fails(self) -> None:
        specialist = AutoReauthSpecialist()
        specialist.network_client = AsyncMock()

        # Preflight returns no CSRF token
        preflight_resp = MagicMock()
        preflight_resp.status_code = 200
        preflight_resp.text = "<html><form><input type='password' name='password'></form></html>"
        preflight_resp.cookies = {}
        preflight_resp.headers = {}
        specialist.network_client.request = AsyncMock(return_value=preflight_resp)

        task = _make_reauth_task(
            target="https://target.example",
            auth_tokens={},
            login_request={
                "method": "POST",
                "url": "https://target.example/login",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": {"username": "user", "password": "pass"},
            },
        )
        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_FAILED
        assert event.payload["reason_code"] == "csrf_token_missing"


# ---------------------------------------------------------------------------
# validated_by enforcement (Section 3.5)
# ---------------------------------------------------------------------------

class TestValidatedBy:
    """success_evidence.validated_by must be present and non-'none'."""

    @pytest.mark.asyncio
    async def test_token_refresh_sets_validated_by_refresh_schema(self) -> None:
        specialist = AutoReauthSpecialist()
        specialist.network_client = AsyncMock()
        specialist.network_client.request = AsyncMock(
            return_value=_make_token_refresh_response(
                status=200,
                body='{"access_token":"real_token"}',
            )
        )
        task = _make_reauth_task(
            target="https://target.example",
            auth_tokens={
                "refresh_url": "https://target.example/api/refresh",
                "refresh_token": "tok",
            },
        )
        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_SUCCESS
        assert event.payload["success_evidence"]["validated_by"] == "refresh_schema"

    @pytest.mark.asyncio
    async def test_login_replay_sets_validated_by_set_cookie(self) -> None:
        specialist = AutoReauthSpecialist()
        specialist.network_client = AsyncMock()

        preflight_resp = MagicMock(status_code=200, text="", cookies={}, headers={})
        login_resp = MagicMock(status_code=200, text="", cookies={"session": "sess_val"})
        specialist.network_client.request = AsyncMock(side_effect=[preflight_resp, login_resp])

        task = _make_reauth_task(
            target="https://target.example",
            auth_tokens={},
            login_request={
                "method": "POST",
                "url": "https://target.example/login",
                "headers": {},
                "body": {},
            },
        )
        emitted_events: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted_events.append(e))

        await specialist.execute(task)
        event = emitted_events[0]
        assert event.type == EventType.REAUTH_SUCCESS
        assert event.payload["success_evidence"]["validated_by"] == "set_cookie"
