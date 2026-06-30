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
