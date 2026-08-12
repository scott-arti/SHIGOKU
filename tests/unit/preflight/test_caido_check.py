"""Tests for Caido mandatory connectivity checks.

Verifies:
- TCP reachability check (success and failure modes)
- HTTP check (GraphQL with token, identity verification without token)
- Full run() collecting failures
- Token masking
- Timeout handling
- Caido/GraphQL identity heuristics
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.core.preflight.caido_check import (
    CaidoCheck,
    _has_caido_schema_fields,
    _looks_like_caido,
    _looks_like_graphql,
    _mask_token,
)
from src.core.preflight.models import PreflightFailure


class TestMaskToken:
    def test_empty_token(self):
        assert _mask_token("") == "<none>"

    def test_short_token(self):
        assert _mask_token("short") == "***"

    def test_long_token(self):
        result = _mask_token("abcdefghijklmnop")
        assert result.endswith("***")
        assert "..." in result
        assert "abcde" in result

    def test_exactly_eight(self):
        assert _mask_token("abcdefgh") == "***"


class TestCaidoCheckInit:
    def test_default_url(self):
        ck = CaidoCheck()
        assert ck.caido_url == "http://127.0.0.1:8080"

    def test_custom_url(self):
        ck = CaidoCheck(caido_url="http://localhost:9090")
        assert ck.caido_url == "http://localhost:9090"

    def test_trailing_slash_removed(self):
        ck = CaidoCheck(caido_url="http://127.0.0.1:8080/")
        assert ck.caido_url == "http://127.0.0.1:8080"

    def test_token_stored(self):
        ck = CaidoCheck(caido_token="caido_test_token_12345")
        assert ck.caido_token == "caido_test_token_12345"


class TestCaidoCheckTCP:
    @pytest.mark.asyncio
    async def test_tcp_success(self):
        """TCP check should return True when connection succeeds."""
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()      # synchronous – avoids coroutine-never-awaited warning
            mock_writer.wait_closed = AsyncMock()
            mock_conn.return_value = (mock_reader, mock_writer)

            ck = CaidoCheck()
            ok, reason = await ck.check_tcp()
            assert ok is True
            assert reason == ""

    @pytest.mark.asyncio
    async def test_tcp_timeout(self):
        """TCP check should return CAIDO_TCP_UNREACHABLE on timeout."""
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = asyncio.TimeoutError()

            ck = CaidoCheck()
            ok, reason = await ck.check_tcp()
            assert ok is False
            assert reason == "CAIDO_TCP_UNREACHABLE"

    @pytest.mark.asyncio
    async def test_tcp_connection_refused(self):
        """TCP check should return CAIDO_TCP_UNREACHABLE on refused."""
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = ConnectionRefusedError()

            ck = CaidoCheck()
            ok, reason = await ck.check_tcp()
            assert ok is False
            assert reason == "CAIDO_TCP_UNREACHABLE"

    @pytest.mark.asyncio
    async def test_tcp_os_error(self):
        """TCP check should handle OSError gracefully."""
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = OSError("Network unreachable")

            ck = CaidoCheck()
            ok, reason = await ck.check_tcp()
            assert ok is False
            assert reason == "CAIDO_TCP_UNREACHABLE"


class TestCaidoCheckHTTP:
    """Tests for check_http() — identity verification without token."""

    def _make_mock_response(self, status=200, headers=None, body=""):
        """Helper to build a realistic mock response."""
        resp = MagicMock()
        resp.status = status
        resp.headers = headers or {}
        resp.body = body
        return resp

    def _setup_client(self, mock_client_cls, responses):
        """Configure the mocked AsyncNetworkClient to return a sequence of
        responses from client.request()."""
        mock_client = MagicMock()
        mock_client.start = AsyncMock()
        mock_client.close = AsyncMock()
        mock_client.request = AsyncMock(side_effect=responses)
        mock_client_cls.return_value = mock_client
        return mock_client

    @pytest.mark.asyncio
    async def test_identity_graphql_json_with_caido_header(self):
        """/graphql with JSON content-type AND Caido header → pass."""
        with patch(
            "src.core.preflight.caido_check.AsyncNetworkClient"
        ) as m:
            m.return_value = self._setup_client(
                m,
                [self._make_mock_response(
                    status=200,
                    headers={"Content-Type": "application/json", "Server": "Caido/0.45.0"},
                    body='{"data": {}}',
                )],
            )
            ck = CaidoCheck(caido_url="http://127.0.0.1:8080")
            ok, reason = await ck.check_http()
            assert ok is True
            assert reason == ""
            m.return_value.request.assert_awaited_once_with(
                "GET",
                "http://127.0.0.1:8080/graphql",
                timeout=5,
                retries=0,
                use_proxy=False,
                follow_redirects=True,
            )

    @pytest.mark.asyncio
    async def test_identity_graphql_json_with_caido_body(self):
        """/graphql with JSON content-type AND 'Caido' in body → pass."""
        with patch(
            "src.core.preflight.caido_check.AsyncNetworkClient"
        ) as m:
            m.return_value = self._setup_client(
                m,
                [self._make_mock_response(
                    status=200,
                    headers={"Content-Type": "application/json"},
                    body='{"message": "Caido GraphQL API"}',
                )],
            )
            ck = CaidoCheck(caido_url="http://127.0.0.1:8080")
            ok, reason = await ck.check_http()
            assert ok is True
            assert reason == ""

    @pytest.mark.asyncio
    async def test_identity_graphql_json_with_caido_schema_fields(self):
        """/graphql with JSON content-type AND Caido-specific schema fields → pass."""
        with patch(
            "src.core.preflight.caido_check.AsyncNetworkClient"
        ) as m:
            m.return_value = self._setup_client(
                m,
                [self._make_mock_response(
                    status=200,
                    headers={"Content-Type": "application/json"},
                    body='{"sitemap": {"id": "1"}, "requests": [], "intercept": true, "scope": {}}',
                )],
            )
            ck = CaidoCheck(caido_url="http://127.0.0.1:8080")
            ok, reason = await ck.check_http()
            assert ok is True
            assert reason == ""

    @pytest.mark.asyncio
    async def test_identity_non_caido_graphql_fails(self):
        """Non-Caido GraphQL service (JSON but no Caido signals) → UNVERIFIED."""
        with patch(
            "src.core.preflight.caido_check.AsyncNetworkClient"
        ) as m:
            non_caido_gql = self._make_mock_response(
                status=200,
                headers={"Content-Type": "application/json"},
                body='{"data": {"hello": "world"}}',
            )
            non_caido_base = self._make_mock_response(
                status=200,
                headers={"Server": "nginx"},
                body="GraphQL Playground",
            )
            m.return_value = self._setup_client(m, [non_caido_gql, non_caido_base])
            ck = CaidoCheck(caido_url="http://127.0.0.1:8080")
            ok, reason = await ck.check_http()
            assert ok is False
            assert reason == "CAIDO_IDENTITY_UNVERIFIED"

    @pytest.mark.asyncio
    async def test_identity_json_no_caido_fallback_caido(self):
        """/graphql JSON but no Caido signal; base URL has Caido → pass."""
        with patch(
            "src.core.preflight.caido_check.AsyncNetworkClient"
        ) as m:
            gql_resp = self._make_mock_response(
                status=200,
                headers={"Content-Type": "application/json"},
                body='{"data": {"generic": "api"}}',
            )
            base_resp = self._make_mock_response(
                status=200,
                headers={"X-Powered-By": "Caido"},
                body="",
            )
            m.return_value = self._setup_client(m, [gql_resp, base_resp])
            ck = CaidoCheck(caido_url="http://127.0.0.1:8080")
            ok, reason = await ck.check_http()
            assert ok is True
            assert reason == ""

    @pytest.mark.asyncio
    async def test_identity_fallback_caido_header(self):
        """/graphql not GraphQL-like, but base URL has Caido header → pass."""
        with patch(
            "src.core.preflight.caido_check.AsyncNetworkClient"
        ) as m:
            non_gql = self._make_mock_response(
                status=404,
                headers={"Content-Type": "text/html"},
                body="Not Found",
            )
            caido_base = self._make_mock_response(
                status=200,
                headers={"X-Powered-By": "Caido"},
                body="",
            )
            m.return_value = self._setup_client(m, [non_gql, caido_base])
            ck = CaidoCheck(caido_url="http://127.0.0.1:8080")
            ok, reason = await ck.check_http()
            assert ok is True
            assert reason == ""

    @pytest.mark.asyncio
    async def test_identity_fallback_caido_body(self):
        """/graphql not GraphQL-like, but base URL body mentions Caido → pass."""
        with patch(
            "src.core.preflight.caido_check.AsyncNetworkClient"
        ) as m:
            non_gql = self._make_mock_response(
                status=404,
                headers={"Content-Type": "text/html"},
                body="Not Found",
            )
            caido_base = self._make_mock_response(
                status=200,
                headers={},
                body="<html>Caido Proxy</html>",
            )
            m.return_value = self._setup_client(m, [non_gql, caido_base])
            ck = CaidoCheck(caido_url="http://127.0.0.1:8080")
            ok, reason = await ck.check_http()
            assert ok is True
            assert reason == ""

    @pytest.mark.asyncio
    async def test_identity_unverified(self):
        """Neither /graphql nor base URL confirms Caido → CAIDO_IDENTITY_UNVERIFIED."""
        with patch(
            "src.core.preflight.caido_check.AsyncNetworkClient"
        ) as m:
            non_gql = self._make_mock_response(
                status=404,
                headers={"Content-Type": "text/html"},
                body="Not Found",
            )
            unknown_base = self._make_mock_response(
                status=200,
                headers={"Server": "nginx"},
                body="Welcome to nginx!",
            )
            m.return_value = self._setup_client(m, [non_gql, unknown_base])
            ck = CaidoCheck(caido_url="http://127.0.0.1:8080")
            ok, reason = await ck.check_http()
            assert ok is False
            assert reason == "CAIDO_IDENTITY_UNVERIFIED"

    @pytest.mark.asyncio
    async def test_identity_graphql_caido_header_fallback(self):
        """/graphql has Caido header but is not JSON; base URL also Caido → pass via fallback."""
        with patch(
            "src.core.preflight.caido_check.AsyncNetworkClient"
        ) as m:
            gql_resp = self._make_mock_response(
                status=200,
                headers={"Content-Type": "text/html", "Server": "Caido/0.45.0"},
                body="<html>Caido</html>",
            )
            base_resp = self._make_mock_response(
                status=200,
                headers={"Server": "Caido/0.45.0"},
                body="<html>Caido Proxy</html>",
            )
            m.return_value = self._setup_client(m, [gql_resp, base_resp])
            ck = CaidoCheck(caido_url="http://127.0.0.1:8080")
            ok, reason = await ck.check_http()
            assert ok is True
            assert reason == ""

    @pytest.mark.asyncio
    async def test_identity_timeout(self):
        """Identity check should fail with CAIDO_HTTP_UNREACHABLE on timeout."""
        with patch(
            "src.core.preflight.caido_check.AsyncNetworkClient"
        ) as m:
            mock_client = MagicMock()
            mock_client.start = AsyncMock()
            mock_client.close = AsyncMock()
            mock_client.request = AsyncMock(
                side_effect=asyncio.TimeoutError()
            )
            m.return_value = mock_client

            ck = CaidoCheck()
            ok, reason = await ck.check_http()
            assert ok is False
            assert reason == "CAIDO_HTTP_UNREACHABLE"

    @pytest.mark.asyncio
    async def test_graphql_token_invalid(self):
        """GraphQL check should detect invalid token (401/403)."""
        with patch(
            "src.core.preflight.caido_check.AsyncNetworkClient"
        ) as mock_client_cls:
            mock_client = MagicMock()
            mock_client.start = AsyncMock()
            mock_client.close = AsyncMock()
            mock_response = MagicMock()
            mock_response.status = 401
            mock_response.is_success = False
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            ck = CaidoCheck(caido_token="caido_test_token_12345")
            ok, reason = await ck.check_http()
            assert ok is False
            assert reason == "CAIDO_TOKEN_INVALID"
            mock_client.request.assert_awaited_once()
            assert mock_client.request.await_args.kwargs["follow_redirects"] is True

    @pytest.mark.asyncio
    async def test_graphql_403(self):
        """GraphQL check should detect 403 as token invalid."""
        with patch(
            "src.core.preflight.caido_check.AsyncNetworkClient"
        ) as mock_client_cls:
            mock_client = MagicMock()
            mock_client.start = AsyncMock()
            mock_client.close = AsyncMock()
            mock_response = MagicMock()
            mock_response.status = 403
            mock_response.is_success = False
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            ck = CaidoCheck(caido_token="caido_test_token_12345")
            ok, reason = await ck.check_http()
            assert ok is False
            assert reason == "CAIDO_TOKEN_INVALID"


class TestCaidoCheckRun:
    @pytest.mark.asyncio
    async def test_run_all_pass(self):
        """run() should return (True, []) when both checks pass."""
        ck = CaidoCheck()
        with patch.object(ck, "check_tcp", new_callable=AsyncMock) as mock_tcp:
            with patch.object(ck, "check_http", new_callable=AsyncMock) as mock_http:
                mock_tcp.return_value = (True, "")
                mock_http.return_value = (True, "")

                all_ok, failures = await ck.run()
                assert all_ok is True
                assert failures == []

    @pytest.mark.asyncio
    async def test_run_tcp_fail(self):
        """run() should collect TCP failure."""
        ck = CaidoCheck()
        with patch.object(ck, "check_tcp", new_callable=AsyncMock) as mock_tcp:
            with patch.object(ck, "check_http", new_callable=AsyncMock) as mock_http:
                mock_tcp.return_value = (False, "CAIDO_TCP_UNREACHABLE")
                mock_http.return_value = (True, "")

                all_ok, failures = await ck.run()
                assert all_ok is False
                assert len(failures) == 1
                assert failures[0].reason_code == "CAIDO_TCP_UNREACHABLE"
                assert failures[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_run_both_fail(self):
        """run() should collect both failures."""
        ck = CaidoCheck()
        with patch.object(ck, "check_tcp", new_callable=AsyncMock) as mock_tcp:
            with patch.object(ck, "check_http", new_callable=AsyncMock) as mock_http:
                mock_tcp.return_value = (False, "CAIDO_TCP_UNREACHABLE")
                mock_http.return_value = (False, "CAIDO_HTTP_UNREACHABLE")

                all_ok, failures = await ck.run()
                assert all_ok is False
                assert len(failures) == 2

    @pytest.mark.asyncio
    async def test_run_http_runs_even_when_tcp_fails(self):
        """HTTP check should still run even if TCP fails."""
        ck = CaidoCheck()
        with patch.object(ck, "check_tcp", new_callable=AsyncMock) as mock_tcp:
            with patch.object(ck, "check_http", new_callable=AsyncMock) as mock_http:
                mock_tcp.return_value = (False, "CAIDO_TCP_UNREACHABLE")
                mock_http.return_value = (False, "CAIDO_HTTP_UNREACHABLE")

                await ck.run()
                # Both should have been called
                mock_tcp.assert_called_once()
                mock_http.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_identity_unverified(self):
        """run() should collect CAIDO_IDENTITY_UNVERIFIED with proper remediation."""
        ck = CaidoCheck()
        with patch.object(ck, "check_tcp", new_callable=AsyncMock) as mock_tcp:
            with patch.object(ck, "check_http", new_callable=AsyncMock) as mock_http:
                mock_tcp.return_value = (True, "")
                mock_http.return_value = (False, "CAIDO_IDENTITY_UNVERIFIED")

                all_ok, failures = await ck.run()
                assert all_ok is False
                assert len(failures) == 1
                f = failures[0]
                assert f.reason_code == "CAIDO_IDENTITY_UNVERIFIED"
                assert f.severity == "critical"
                assert "Caido identity" in f.remediation

    @pytest.mark.asyncio
    async def test_run_identity_unverified_reports_configured_port(self):
        """The remediation must name the actual configured Caido port."""
        ck = CaidoCheck(caido_url="http://127.0.0.1:8081")
        with patch.object(ck, "check_tcp", new_callable=AsyncMock) as mock_tcp:
            with patch.object(ck, "check_http", new_callable=AsyncMock) as mock_http:
                mock_tcp.return_value = (True, "")
                mock_http.return_value = (False, "CAIDO_IDENTITY_UNVERIFIED")

                _, failures = await ck.run()

        assert "Port 8081" in failures[0].remediation

    @pytest.mark.asyncio
    async def test_run_token_invalid_remediation(self):
        """run() should include token-specific remediation for CAIDO_TOKEN_INVALID."""
        ck = CaidoCheck(caido_token="test12345678")
        with patch.object(ck, "check_tcp", new_callable=AsyncMock) as mock_tcp:
            with patch.object(ck, "check_http", new_callable=AsyncMock) as mock_http:
                mock_tcp.return_value = (True, "")
                mock_http.return_value = (False, "CAIDO_TOKEN_INVALID")

                all_ok, failures = await ck.run()
                assert all_ok is False
                assert len(failures) == 1
                assert "token was rejected" in failures[0].remediation


# ---------------------------------------------------------------------------
# Identity heuristics
# ---------------------------------------------------------------------------


class TestLooksLikeGraphql:
    """Tests for _looks_like_graphql helper."""

    def _resp(self, content_type=None, body=""):
        resp = MagicMock()
        resp.headers = {}
        if content_type:
            resp.headers["Content-Type"] = content_type
        resp.body = body
        return resp

    # -- Strict GraphQL detection: requires valid JSON with GraphQL structure --

    def test_graphql_response_with_data_key(self):
        """Valid GraphQL response with 'data' key → True."""
        resp = self._resp(
            content_type="application/json",
            body='{"data": {"__schema": {"queryType": {"name": "Query"}}}}',
        )
        assert _looks_like_graphql(resp) is True

    def test_graphql_response_with_errors_key(self):
        """Valid GraphQL response with 'errors' key → True."""
        resp = self._resp(
            content_type="application/json",
            body='{"errors": [{"message": "Unauthorized"}]}',
        )
        assert _looks_like_graphql(resp) is True

    def test_graphql_introspection_schema(self):
        """GraphQL introspection result with __schema → True."""
        resp = self._resp(
            content_type="application/json",
            body='{"__schema": {"types": []}}',
        )
        assert _looks_like_graphql(resp) is True

    def test_graphql_with_query_type(self):
        """Response with queryType key → True."""
        resp = self._resp(
            content_type="application/json",
            body='{"queryType": {"name": "Query"}, "mutationType": null}',
        )
        assert _looks_like_graphql(resp) is True

    def test_non_json_body(self):
        """Plain text body (not JSON) → False."""
        resp = self._resp(content_type="text/html", body="query { __schema }")
        assert _looks_like_graphql(resp) is False

    def test_json_without_graphql_structure(self):
        """Valid JSON but no GraphQL keys → False."""
        resp = self._resp(
            content_type="application/json",
            body='{"hello": "world", "status": "ok"}',
        )
        assert _looks_like_graphql(resp) is False

    def test_empty_body(self):
        """Empty body → False (can't parse as JSON)."""
        resp = self._resp(content_type="application/json", body="")
        assert _looks_like_graphql(resp) is False

    def test_json_array(self):
        """JSON array (not object) → False."""
        resp = self._resp(
            content_type="application/json",
            body='[{"data": "nested"}]',
        )
        assert _looks_like_graphql(resp) is False


class TestLooksLikeCaido:
    """Tests for _looks_like_caido helper."""

    def _resp(self, headers=None, body=""):
        resp = MagicMock()
        resp.headers = headers or {}
        resp.body = body
        return resp

    def test_header_name_contains_caido(self):
        resp = self._resp(
            headers={"X-Caido-Version": "0.45.0"},
            body="",
        )
        assert _looks_like_caido(resp) is True

    def test_header_value_contains_caido(self):
        resp = self._resp(
            headers={"Server": "Caido/0.45.0"},
            body="",
        )
        assert _looks_like_caido(resp) is True

    def test_body_contains_caido(self):
        resp = self._resp(
            headers={"Server": "nginx"},
            body="<html><title>Caido Proxy</title></html>",
        )
        assert _looks_like_caido(resp) is True

    def test_case_insensitive(self):
        resp = self._resp(
            headers={"server": "CAIDO"},
            body="",
        )
        assert _looks_like_caido(resp) is True

    def test_no_caido_indicators(self):
        resp = self._resp(
            headers={"Server": "nginx", "X-Powered-By": "Express"},
            body="<html>Hello World</html>",
        )
        assert _looks_like_caido(resp) is False

    def test_header_name_case_insensitive(self):
        resp = self._resp(
            headers={"x-caido-version": "1.0"},
            body="",
        )
        assert _looks_like_caido(resp) is True


class TestHasCaidoSchemaFields:
    """Tests for _has_caido_schema_fields helper."""

    def _resp(self, body=""):
        resp = MagicMock()
        resp.headers = {}
        resp.body = body
        return resp

    def test_sitemap_in_json_keys(self):
        """JSON with 'sitemap' key → True."""
        resp = self._resp(body='{"sitemap": {"id": "1"}}')
        assert _has_caido_schema_fields(resp) is True

    def test_requests_in_json_keys(self):
        """JSON with 'requests' key → True."""
        resp = self._resp(body='{"requests": []}')
        assert _has_caido_schema_fields(resp) is True

    def test_intercept_in_json_keys(self):
        """JSON with 'intercept' key → True."""
        resp = self._resp(body='{"intercept": true}')
        assert _has_caido_schema_fields(resp) is True

    def test_scope_in_json_keys(self):
        """JSON with 'scope' key → True."""
        resp = self._resp(body='{"scope": {"rules": []}}')
        assert _has_caido_schema_fields(resp) is True

    def test_nested_caido_field(self):
        """Nested JSON with Caido field deep in structure → True."""
        resp = self._resp(
            body='{"data": {"__type": {"fields": [{"name": "sitemap"}]}}}'
        )
        assert _has_caido_schema_fields(resp) is True

    def test_non_json_body(self):
        """Non-JSON body → False."""
        resp = self._resp(body="Not a JSON body")
        assert _has_caido_schema_fields(resp) is False

    def test_generic_graphql_no_caido(self):
        """Generic GraphQL introspection (no Caido fields) → False."""
        resp = self._resp(
            body='{"data": {"__schema": {"queryType": {"name": "Query"}}}}'
        )
        assert _has_caido_schema_fields(resp) is False

    def test_empty_body(self):
        """Empty body → False."""
        resp = self._resp(body="")
        assert _has_caido_schema_fields(resp) is False


# ---------------------------------------------------------------------------
# Forwarding check (SGK-2026-0447)
# ---------------------------------------------------------------------------


# Additive imports for the forwarding-check tests only (existing imports and
# test classes above are left untouched).
from contextlib import contextmanager  # noqa: E402
from types import SimpleNamespace  # noqa: E402

from src.core.infra.proxy_manager import ProxyChainManager  # noqa: E402
from src.core.preflight.caido_check import (  # noqa: E402
    _CANNED_BODY_MAX_BYTES,
    _FORWARD_TIMEOUT,
)
from tests.fixtures.proxy_fakes import (  # noqa: E402
    start_dummy_proxy,
    start_forwarding_proxy,
)


class TestCaidoCheckForwarding:
    """Mock-based tests for check_forwarding() (SGK-2026-0447)."""

    @staticmethod
    def _canned(body: bytes = b'{"kind":"canned"}') -> SimpleNamespace:
        return SimpleNamespace(status=200, body=body)

    @staticmethod
    def _setup_client(mock_cls, responses):
        """Configure the mocked AsyncNetworkClient with a response sequence."""
        client = MagicMock()
        client.start = AsyncMock()
        client.close = AsyncMock()
        client.request = AsyncMock(side_effect=responses)
        mock_cls.return_value = client
        return client

    @pytest.mark.asyncio
    async def test_identical_short_bodies_fail_closed(self):
        """(a) All probes identical short canned body → PROXY_NOT_FORWARDING."""
        with patch("src.core.preflight.caido_check.AsyncNetworkClient") as m:
            client = self._setup_client(
                m, [self._canned(), self._canned(), self._canned()]
            )
            ck = CaidoCheck(target="http://origin.test/")
            ok, reason = await ck.check_forwarding()
            assert ok is False
            assert reason == "PROXY_NOT_FORWARDING"
            assert client.request.await_count == 3

    @pytest.mark.asyncio
    async def test_path_dependent_responses_pass(self):
        """(b) Path-dependent responses → forwarding confirmed, PASS."""
        responses = [
            SimpleNamespace(status=200, body=b"<html>root page</html>"),
            SimpleNamespace(status=404, body=b'{"error":"no such resource"}'),
            SimpleNamespace(status=404, body=b'{"error":"no such resource"}'),
        ]
        with patch("src.core.preflight.caido_check.AsyncNetworkClient") as m:
            client = self._setup_client(m, responses)
            ck = CaidoCheck(target="http://origin.test")
            ok, reason = await ck.check_forwarding()
            assert ok is True
            assert reason == ""
            assert client.request.await_count == 3

    @pytest.mark.asyncio
    async def test_probe_exception_fails_closed(self):
        """(c) Probe exception (TimeoutError) → PROXY_FORWARD_CHECK_FAILED."""
        with patch("src.core.preflight.caido_check.AsyncNetworkClient") as m:
            client = MagicMock()
            client.start = AsyncMock()
            client.close = AsyncMock()
            client.request = AsyncMock(side_effect=asyncio.TimeoutError())
            m.return_value = client
            ck = CaidoCheck(target="http://origin.test")
            ok, reason = await ck.check_forwarding()
            assert ok is False
            assert reason == "PROXY_FORWARD_CHECK_FAILED"

    @pytest.mark.asyncio
    async def test_empty_target_skips(self):
        """(d) Empty target → skip (True, "") and no requests sent."""
        with patch("src.core.preflight.caido_check.AsyncNetworkClient") as m:
            client = self._setup_client(m, [])
            ck = CaidoCheck()
            ok, reason = await ck.check_forwarding()
            assert ok is True
            assert reason == ""
            client.request.assert_not_awaited()
            m.assert_not_called()

    @pytest.mark.asyncio
    async def test_env_kill_switch_skips(self, monkeypatch):
        """(e) SHIGOKU_SKIP_FORWARD_CHECK=1 → skip and no requests sent."""
        monkeypatch.setenv("SHIGOKU_SKIP_FORWARD_CHECK", "1")
        with patch("src.core.preflight.caido_check.AsyncNetworkClient") as m:
            client = self._setup_client(m, [])
            ck = CaidoCheck(target="http://origin.test")
            ok, reason = await ck.check_forwarding()
            assert ok is True
            assert reason == ""
            client.request.assert_not_awaited()
            m.assert_not_called()

    @pytest.mark.asyncio
    async def test_long_identical_bodies_pass(self):
        """(f) Identical but long bodies (>512B) → PASS (SPA fallback guard)."""
        long_body = b"A" * (_CANNED_BODY_MAX_BYTES + 1)
        with patch("src.core.preflight.caido_check.AsyncNetworkClient") as m:
            client = self._setup_client(
                m,
                [
                    SimpleNamespace(status=200, body=long_body),
                    SimpleNamespace(status=200, body=long_body),
                    SimpleNamespace(status=200, body=long_body),
                ],
            )
            ck = CaidoCheck(target="http://origin.test")
            ok, reason = await ck.check_forwarding()
            assert ok is True
            assert reason == ""

    @pytest.mark.asyncio
    async def test_probe_uses_proxy_path_without_retries(self):
        """Probes must use the proxied path, no retries/redirects, live cache off."""
        with patch("src.core.preflight.caido_check.AsyncNetworkClient") as m:
            client = self._setup_client(
                m, [self._canned(), self._canned(), self._canned()]
            )
            ck = CaidoCheck(target="http://origin.test/")
            await ck.check_forwarding()
            assert client.request.await_count == 3
            for call in client.request.await_args_list:
                assert call.kwargs["use_proxy"] is True
                assert call.kwargs["retries"] == 0
                assert call.kwargs["follow_redirects"] is False
                assert call.kwargs["use_cache"] is False
                assert call.kwargs["timeout"] == _FORWARD_TIMEOUT
                # The ONLY sanctioned skip_guard call site is this probe.
                assert call.kwargs["skip_guard"] is True

    @pytest.mark.asyncio
    async def test_identical_302_redirects_pass(self):
        """All-identical 302 (short body) → PASS (http→https redirect pattern)."""
        body = b"Redirecting..."
        responses = [
            SimpleNamespace(status=302, body=body),
            SimpleNamespace(status=302, body=body),
            SimpleNamespace(status=302, body=body),
        ]
        with patch("src.core.preflight.caido_check.AsyncNetworkClient") as m:
            client = self._setup_client(m, responses)
            ck = CaidoCheck(target="http://origin.test")
            ok, reason = await ck.check_forwarding()
            assert ok is True
            assert reason == ""

    @pytest.mark.asyncio
    async def test_identical_404_api_pass(self):
        """All-identical 404 (short body) → PASS (route-less API 404 pattern)."""
        body = b'{"detail":"Not Found"}'
        responses = [
            SimpleNamespace(status=404, body=body),
            SimpleNamespace(status=404, body=body),
            SimpleNamespace(status=404, body=body),
        ]
        with patch("src.core.preflight.caido_check.AsyncNetworkClient") as m:
            client = self._setup_client(m, responses)
            ck = CaidoCheck(target="http://origin.test")
            ok, reason = await ck.check_forwarding()
            assert ok is True
            assert reason == ""

    @pytest.mark.asyncio
    async def test_long_identical_200_warns_and_passes(self, caplog):
        """200 identical >512B → PASS with a false-negative visibility warning."""
        long_body = b"A" * 600
        responses = [
            SimpleNamespace(status=200, body=long_body),
            SimpleNamespace(status=200, body=long_body),
            SimpleNamespace(status=200, body=long_body),
        ]
        with patch("src.core.preflight.caido_check.AsyncNetworkClient") as m:
            client = self._setup_client(m, responses)
            ck = CaidoCheck(target="http://origin.test")
            with caplog.at_level("WARNING", logger="src.core.preflight.caido_check"):
                ok, reason = await ck.check_forwarding()
            assert ok is True
            assert reason == ""
            assert any(
                "possible large canned dummy" in r.message for r in caplog.records
            )

    @pytest.mark.asyncio
    async def test_mixed_200_404_pass(self):
        """Mixed 200/404 responses → PASS (path-dependent origin behavior)."""
        responses = [
            SimpleNamespace(status=200, body=b"<html>root</html>"),
            SimpleNamespace(status=404, body=b'{"detail":"Not Found"}'),
            SimpleNamespace(status=404, body=b'{"detail":"Not Found"}'),
        ]
        with patch("src.core.preflight.caido_check.AsyncNetworkClient") as m:
            client = self._setup_client(m, responses)
            ck = CaidoCheck(target="http://origin.test")
            ok, reason = await ck.check_forwarding()
            assert ok is True
            assert reason == ""


class TestCaidoCheckForwardingRealProxy:
    """Forwarding check against real stdlib fixture proxy servers.

    Exercises the full AsyncNetworkClient → ProxyChainManager → fixture
    proxy path with plain-HTTP targets (aiohttp sends absolute-form requests
    to an HTTP proxy, no CONNECT needed).
    """

    @staticmethod
    @contextmanager
    def _route_via_proxy(proxy_url: str):
        """Context routing AsyncNetworkClient through *proxy_url*.

        - ``get_proxy_manager`` in network_client: attach a ProxyChainManager
          whose single proxy is the fixture server.
        - ``get_settings`` in settings: proxy URL + mode used by the client
          (reachability pre-check and run-mode resolution).

        The compiled guard is deliberately NOT patched here: the forwarding
        probe runs with ``skip_guard=True`` (SGK-2026-0447), so it must reach
        the proxy with the guard untouched — this proves the bypass works in
        the production path (policy=None would otherwise fail-closed).
        """
        settings_mock = MagicMock()
        settings_mock.get_proxy_url.return_value = proxy_url
        settings_mock.mode = "bugbounty"
        manager = ProxyChainManager(proxy_urls=[proxy_url])
        with (
            patch(
                "src.core.infra.network_client.get_proxy_manager",
                return_value=manager,
                create=True,
            ),
            patch(
                "src.core.config.settings.get_settings",
                return_value=settings_mock,
            ),
        ):
            yield

    @pytest.mark.asyncio
    async def test_dummy_proxy_detected(self):
        """Real canned dummy proxy → PROXY_NOT_FORWARDING (fail-closed)."""
        ok: bool = False
        reason: str = ""
        with start_dummy_proxy() as (server, proxy_url):
            with self._route_via_proxy(proxy_url):
                ck = CaidoCheck(target="http://origin.test/")
                ok, reason = await ck.check_forwarding()
        assert ok is False
        assert reason == "PROXY_NOT_FORWARDING"

    @pytest.mark.asyncio
    async def test_forwarding_proxy_passes(self):
        """Real path-dependent forwarding proxy → PASS."""
        ok: bool = False
        reason: str = ""
        with start_forwarding_proxy() as (server, proxy_url):
            with self._route_via_proxy(proxy_url):
                ck = CaidoCheck(target="http://origin.test/")
                ok, reason = await ck.check_forwarding()
        assert ok is True
        assert reason == ""
