"""Unit tests for src.core.agents.swarm.injection.form_harvester."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.core.agents.swarm.injection.form_harvester import (
    fetch_and_parse_form,
    _parse_forms_from_html,
    _urllib_fetch,
)
from src.core.infra.network_client import NetworkResponse


# ---------------------------------------------------------------------------
# Sample HTML fixtures
# ---------------------------------------------------------------------------

DVWA_SQLI_HTML = """\
<!DOCTYPE html>
<html>
<head><title>DVWA - SQL Injection</title></head>
<body>
<div class="menu">
  <a href="?page=home">Home</a>
  <!-- Long menu items to simulate pag that has form deep in DOM -->
</div>
<div class="body_padded">
<h1>Vulnerability: SQL Injection</h1>
<form action="#" method="GET">
<p>User ID: <input type="text" name="id" size="15" /></p>
<p><input type="submit" value="Submit" /></p>
</form>
</div>
</body>
</html>"""

FORM_WITH_POST = """\
<html><body>
<form action="/login" method="POST">
  <input type="text" name="username" value="" />
  <input type="password" name="password" value="" />
  <textarea name="comment">Hello</textarea>
  <select name="role"><option value="admin">Admin</option></select>
</form>
</body></html>"""

NO_FORMS_HTML = "<html><body><p>No forms here</p></body></html>"

EMPTY_BODY = ""

# ---------------------------------------------------------------------------
# Unit tests: _parse_forms_from_html (pure helper)
# ---------------------------------------------------------------------------


class TestParseFormsFromHtml:
    def test_dvwa_style_form(self):
        forms = _parse_forms_from_html(DVWA_SQLI_HTML)
        assert len(forms) == 1
        assert forms[0]["method"] == "GET"
        assert forms[0]["action"] == "#"
        inputs = forms[0]["inputs"]
        assert len(inputs) >= 1
        names = {inp["name"] for inp in inputs}
        assert "id" in names

    def test_post_form_with_textarea_and_select(self):
        forms = _parse_forms_from_html(FORM_WITH_POST)
        assert len(forms) == 1
        assert forms[0]["method"] == "POST"
        inputs = {inp["name"]: inp for inp in forms[0]["inputs"]}
        assert set(inputs.keys()) == {"username", "password", "comment", "role"}
        assert inputs["comment"]["type"] == "text"
        assert inputs["role"]["value"] == "1"  # <select> has no value attr, default

    def test_no_forms(self):
        assert _parse_forms_from_html(NO_FORMS_HTML) == []

    def test_empty_body(self):
        assert _parse_forms_from_html(EMPTY_BODY) == []


# ---------------------------------------------------------------------------
# Integration tests: fetch_and_parse_form (primary + fallback paths)
# ---------------------------------------------------------------------------


class TestFetchAndParseForm:
    @pytest.fixture
    def auth_headers(self):
        return {"Cookie": "PHPSESSID=abc123; security=low"}

    @pytest.fixture
    def mock_network_response(self):
        """Create a NetworkResponse with DVWA HTML."""
        return NetworkResponse(
            status=200,
            headers={"Content-Type": "text/html"},
            body=DVWA_SQLI_HTML,
            elapsed=0.1,
            url="http://127.0.0.1:4280/vulnerabilities/sqli/",
        )

    # -- Primary path -------------------------------------------------------

    async def test_primary_path_extracts_forms(
        self, auth_headers, mock_network_response
    ):
        """Mock AsyncNetworkClient.request to return valid HTML."""
        with patch(
            "src.core.agents.swarm.injection.form_harvester.AsyncNetworkClient"
        ) as mock_client_cls:
            mock_client = MagicMock()
            mock_client.request = AsyncMock(return_value=mock_network_response)
            mock_client.close = AsyncMock()
            mock_client_cls.return_value = mock_client

            forms = await fetch_and_parse_form(
                "http://127.0.0.1:4280/vulnerabilities/sqli/", auth_headers
            )

        assert len(forms) == 1
        assert forms[0]["method"] == "GET"
        input_names = {inp["name"] for inp in forms[0]["inputs"]}
        assert "id" in input_names

        # Verify AsyncNetworkClient was used with correct params
        mock_client.request.assert_awaited_once()
        call_args = mock_client.request.await_args
        # Positional: (method, url)
        assert call_args.args[0] == "GET"
        assert call_args.args[1] == "http://127.0.0.1:4280/vulnerabilities/sqli/"
        # Keyword: headers, use_cache, timeout
        assert call_args.kwargs["headers"] == auth_headers
        assert call_args.kwargs["use_cache"] is False
        assert call_args.kwargs["timeout"] == 20

    # -- Fallback path: primary returns empty body --------------------------

    async def test_fallback_to_urllib_when_primary_empty(self, auth_headers):
        """AsyncNetworkClient returns empty body → urllib fallback kicks in."""
        empty_response = NetworkResponse(
            status=200,
            headers={},
            body="",  # empty!
            elapsed=0.1,
            url="http://127.0.0.1:4280/vulnerabilities/sqli/",
        )

        with patch(
            "src.core.agents.swarm.injection.form_harvester.AsyncNetworkClient"
        ) as mock_client_cls:
            mock_client = MagicMock()
            mock_client.request = AsyncMock(return_value=empty_response)
            mock_client.close = AsyncMock()
            mock_client_cls.return_value = mock_client

            with patch(
                "src.core.agents.swarm.injection.form_harvester._urllib_fetch",
                return_value=DVWA_SQLI_HTML,
            ) as mock_urllib:
                forms = await fetch_and_parse_form(
                    "http://127.0.0.1:4280/vulnerabilities/sqli/", auth_headers
                )

        # Fallback was invoked
        mock_urllib.assert_called_once_with(
            "http://127.0.0.1:4280/vulnerabilities/sqli/", auth_headers
        )
        assert len(forms) == 1
        assert forms[0]["method"] == "GET"

    # -- Fallback path: primary raises --------------------------------------

    async def test_fallback_to_urllib_when_primary_raises(self, auth_headers):
        """AsyncNetworkClient.request raises → urllib fallback kicks in."""
        with patch(
            "src.core.agents.swarm.injection.form_harvester.AsyncNetworkClient"
        ) as mock_client_cls:
            mock_client = MagicMock()
            mock_client.request = AsyncMock(
                side_effect=ConnectionError("refused")
            )
            mock_client.close = AsyncMock()
            mock_client_cls.return_value = mock_client

            with patch(
                "src.core.agents.swarm.injection.form_harvester._urllib_fetch",
                return_value=DVWA_SQLI_HTML,
            ) as mock_urllib:
                forms = await fetch_and_parse_form(
                    "http://127.0.0.1:4280/vulnerabilities/sqli/", auth_headers
                )

        mock_urllib.assert_called_once()
        assert len(forms) == 1

    async def test_both_paths_fail_returns_empty(self, auth_headers):
        """Both primary and fallback raise → returns []"""
        with patch(
            "src.core.agents.swarm.injection.form_harvester.AsyncNetworkClient"
        ) as mock_client_cls:
            mock_client = MagicMock()
            mock_client.request = AsyncMock(
                side_effect=ConnectionError("refused")
            )
            mock_client.close = AsyncMock()
            mock_client_cls.return_value = mock_client

            with patch(
                "src.core.agents.swarm.injection.form_harvester._urllib_fetch",
                side_effect=OSError("network unreachable"),
            ):
                forms = await fetch_and_parse_form(
                    "http://127.0.0.1:4280/vulnerabilities/sqli/", auth_headers
                )

        assert forms == []

    async def test_both_paths_return_empty_body(self, auth_headers):
        """Both paths return empty body → returns []"""
        empty_response = NetworkResponse(
            status=200, headers={}, body="", elapsed=0.1, url="http://x"
        )

        with patch(
            "src.core.agents.swarm.injection.form_harvester.AsyncNetworkClient"
        ) as mock_client_cls:
            mock_client = MagicMock()
            mock_client.request = AsyncMock(return_value=empty_response)
            mock_client.close = AsyncMock()
            mock_client_cls.return_value = mock_client

            with patch(
                "src.core.agents.swarm.injection.form_harvester._urllib_fetch",
                return_value="",
            ):
                forms = await fetch_and_parse_form(
                    "http://127.0.0.1:4280/vulnerabilities/sqli/", auth_headers
                )

        assert forms == []

    # -- Auth header propagation --------------------------------------------

    async def test_auth_headers_passed_to_urllib(self, auth_headers):
        """urllib fallback receives auth_headers."""
        empty_response = NetworkResponse(
            status=200, headers={}, body="", elapsed=0.1, url="http://x"
        )

        with patch(
            "src.core.agents.swarm.injection.form_harvester.AsyncNetworkClient"
        ) as mock_client_cls:
            mock_client = MagicMock()
            mock_client.request = AsyncMock(return_value=empty_response)
            mock_client.close = AsyncMock()
            mock_client_cls.return_value = mock_client

            with patch(
                "src.core.agents.swarm.injection.form_harvester._urllib_fetch",
                return_value=DVWA_SQLI_HTML,
            ) as mock_urllib:
                await fetch_and_parse_form(
                    "http://127.0.0.1:4280/vulnerabilities/sqli/", auth_headers
                )

            mock_urllib.assert_called_once_with(
                "http://127.0.0.1:4280/vulnerabilities/sqli/", auth_headers
            )

    # -- Edge cases --------------------------------------------------------

    async def test_no_forms_in_page(self, auth_headers):
        """Primary succeeds but page has no forms."""
        no_form_response = NetworkResponse(
            status=200,
            headers={},
            body=NO_FORMS_HTML,
            elapsed=0.1,
            url="http://x",
        )

        with patch(
            "src.core.agents.swarm.injection.form_harvester.AsyncNetworkClient"
        ) as mock_client_cls:
            mock_client = MagicMock()
            mock_client.request = AsyncMock(return_value=no_form_response)
            mock_client.close = AsyncMock()
            mock_client_cls.return_value = mock_client

            forms = await fetch_and_parse_form("http://x/page", auth_headers)

        assert forms == []


# ---------------------------------------------------------------------------
# Unit test: _urllib_fetch
# ---------------------------------------------------------------------------


class TestUrllibFetch:
    def test_urllib_fetch_constructs_request_with_headers(self):
        """Verify _urllib_fetch passes headers to urllib.request.Request."""
        auth_headers = {"Cookie": "PHPSESSID=abc123"}

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = DVWA_SQLI_HTML.encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            mock_urlopen.return_value = mock_resp

            body = _urllib_fetch("http://127.0.0.1/vulns/", auth_headers)

        assert "Vulnerability: SQL Injection" in body
        # Check that the Request was created correctly
        mock_urlopen.assert_called_once()
        request_arg = mock_urlopen.call_args[0][0]
        assert isinstance(request_arg, __import__("urllib").request.Request)  # type: ignore[arg-type]
        assert request_arg.get_header("Cookie") == "PHPSESSID=abc123"
