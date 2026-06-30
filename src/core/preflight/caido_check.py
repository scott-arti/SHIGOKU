"""
Caido mandatory connectivity validation for the SHIGOKU preflight gate.

Verifies:
1. TCP reachability to the Caido proxy
2. HTTP/GraphQL response validity (with optional token auth)
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from src.core.infra.network_client import AsyncNetworkClient, NetworkResponse
from src.core.preflight.models import PreflightFailure

logger = logging.getLogger(__name__)

# GraphQL introspection query to verify the Caido API is responsive.
_GRAPHQL_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
  }
}
"""

_TCP_TIMEOUT = 2.0
_HTTP_TIMEOUT = 5


# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------


@dataclass
class _CaidoState:
    """Hold parsed configuration and pre-computed masked token for logging."""

    url: str = "http://127.0.0.1:8080"
    token: str = ""
    masked_token: str = ""


# ---------------------------------------------------------------------------
# CaidoCheck
# ---------------------------------------------------------------------------


class CaidoCheck:
    """Validates Caido proxy connectivity (TCP + HTTP/GraphQL).

    Usage::

        check = CaidoCheck(caido_url="http://127.0.0.1:8080", caido_token="...")
        all_ok, failures = await check.run()

    Reason codes produced:

    - ``CAIDO_TCP_UNREACHABLE`` — TCP connection to the proxy failed.
    - ``CAIDO_HTTP_UNREACHABLE`` — HTTP response could not be obtained.
    - ``CAIDO_GRAPHQL_FAILED`` — GraphQL introspection returned an error or
      unexpected payload.
    - ``CAIDO_TOKEN_INVALID`` — The configured token was rejected (HTTP 401/403).
    - ``CAIDO_IDENTITY_UNVERIFIED`` — Port is reachable but Caido identity
      could not be confirmed without a token.
    """

    def __init__(
        self,
        caido_url: str = "http://127.0.0.1:8080",
        caido_token: str = "",
    ) -> None:
        self._state = _CaidoState(
            url=caido_url.rstrip("/"),
            token=caido_token,
            masked_token=_mask_token(caido_token),
        )

    @property
    def caido_url(self) -> str:
        """The configured Caido proxy URL."""
        return self._state.url

    @property
    def caido_token(self) -> str:
        """The configured Caido API token (raw — do not log)."""
        return self._state.token

    # --------------------------------------------------
    # TCP connectivity
    # --------------------------------------------------

    async def check_tcp(self) -> tuple[bool, str]:
        """Test TCP connectivity to the Caido proxy host:port.

        Opens a raw TCP connection to the host and port parsed from *caido_url*
        with a *{_TCP_TIMEOUT}s* timeout.

        Returns:
            ``(True, "")`` on success, ``(False, "CAIDO_TCP_UNREACHABLE")`` on
            any connection failure (timeout, refused, DNS error, OS error).
        """
        parsed = urlparse(self._state.url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 8080

        logger.debug(
            "CaidoCheck TCP: connecting to %s:%s (timeout=%ss, token=%s)",
            host,
            port,
            _TCP_TIMEOUT,
            self._state.masked_token,
        )

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=_TCP_TIMEOUT,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.info("CaidoCheck TCP: %s:%s reachable", host, port)
            return True, ""
        except asyncio.TimeoutError:
            logger.warning("CaidoCheck TCP: timeout connecting to %s:%s", host, port)
        except ConnectionRefusedError:
            logger.warning("CaidoCheck TCP: connection refused at %s:%s", host, port)
        except OSError as exc:
            logger.warning("CaidoCheck TCP: OS error for %s:%s: %s", host, port, exc)
        except Exception as exc:
            logger.warning(
                "CaidoCheck TCP: unexpected error for %s:%s: %s", host, port, exc
            )
        return False, "CAIDO_TCP_UNREACHABLE"

    # --------------------------------------------------
    # HTTP / GraphQL
    # --------------------------------------------------

    async def check_http(self) -> tuple[bool, str]:
        """Test HTTP/GraphQL response from the Caido proxy.

        - If a *caido_token* is configured, sends a GraphQL introspection
          query via ``POST`` to ``<caido_url>/graphql`` with a ``Bearer``
          authorization header.  Validates the JSON response contains
          expected introspection keys.
        - Otherwise, probes the Caido-specific endpoints and response
          indicators to confirm Caido identity without authentication.
          Returns ``CAIDO_IDENTITY_UNVERIFIED`` if the service on the port
          cannot be confirmed as Caido.

        Returns:
            ``(True, "")`` on success, ``(False, reason_code)`` otherwise.
        """
        if self._state.token:
            return await self._check_graphql()
        return await self._check_caido_identity()

    async def _check_caido_identity(self) -> tuple[bool, str]:
        """Confirm Caido identity without a token.

        Strategy:
        1. GET ``<caido_url>/graphql`` (no auth).  Only passes if the
           response has BOTH JSON content-type AND at least one Caido-specific
           signal (Caido in headers/body, or Caido-specific GraphQL schema 
           fields like ``sitemap``, ``requests``, ``intercept``, ``scope``).
        2. Fallback: GET the base URL.  Passes if headers or body contain
           ``Caido`` (case-insensitive).
        3. If neither confirms Caido identity, return
           ``CAIDO_IDENTITY_UNVERIFIED``.
        """
        base_url = self._state.url
        graphql_url = urljoin(base_url + "/", "graphql")

        logger.debug(
            "CaidoCheck Identity: probing %s (token=%s)",
            graphql_url,
            self._state.masked_token,
        )

        try:
            client = AsyncNetworkClient()
            await client.start()
            try:
                # Step 1: Try /graphql endpoint
                response = await asyncio.wait_for(
                    client.request(
                        "GET",
                        graphql_url,
                        timeout=_HTTP_TIMEOUT,
                        retries=0,
                        use_proxy=False,
                    ),
                    timeout=_HTTP_TIMEOUT + 3,
                )
                logger.debug(
                    "CaidoCheck Identity: /graphql returned %s",
                    response.status,
                )

                is_json = "json" in response.headers.get(
                    "Content-Type", ""
                ).lower()
                has_caido_signal = _looks_like_caido(
                    response
                ) or _has_caido_schema_fields(response)

                if is_json and has_caido_signal:
                    logger.info(
                        "CaidoCheck Identity: /graphql confirms Caido identity"
                    )
                    return True, ""

                # Step 2: Fallback to base URL with Caido indicators
                logger.debug(
                    "CaidoCheck Identity: /graphql not Caido-confirmed; "
                    "probing base URL %s",
                    base_url,
                )
                base_response = await asyncio.wait_for(
                    client.request(
                        "GET",
                        base_url,
                        timeout=_HTTP_TIMEOUT,
                        retries=0,
                        use_proxy=False,
                    ),
                    timeout=_HTTP_TIMEOUT + 3,
                )
                logger.debug(
                    "CaidoCheck Identity: %s returned %s",
                    base_url,
                    base_response.status,
                )

                if _looks_like_caido(base_response):
                    logger.info(
                        "CaidoCheck Identity: Caido indicator found in "
                        "base URL response"
                    )
                    return True, ""

                # Neither step confirmed Caido
                logger.warning(
                    "CaidoCheck Identity: port reachable but Caido "
                    "identity unverified"
                )
                return False, "CAIDO_IDENTITY_UNVERIFIED"
            finally:
                await client.close()
        except asyncio.TimeoutError:
            logger.warning("CaidoCheck Identity: request timed out")
        except Exception as exc:
            logger.warning("CaidoCheck Identity: request failed: %s", exc)
        return False, "CAIDO_HTTP_UNREACHABLE"

    async def _check_graphql(self) -> tuple[bool, str]:
        """GraphQL introspection check — token required.

        POSTs an introspection query to ``<caido_url>/graphql`` and validates:

        1. HTTP status is 2xx (401/403 → token invalid).
        2. Response body is valid JSON.
        3. JSON contains ``data`` (or ``errors`` that we surface).
        """
        graphql_url = urljoin(self._state.url + "/", "graphql")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._state.token}" if self._state.token else "",
        }

        logger.debug(
            "CaidoCheck GraphQL: POST %s (token=%s)",
            graphql_url,
            self._state.masked_token,
        )

        try:
            client = AsyncNetworkClient()
            await client.start()
            try:
                response = await asyncio.wait_for(
                    client.request(
                        "POST",
                        graphql_url,
                        headers=headers,
                        json={"query": _GRAPHQL_INTROSPECTION_QUERY},
                        timeout=_HTTP_TIMEOUT,
                        retries=0,
                        use_proxy=False,
                    ),
                    timeout=_HTTP_TIMEOUT + 3,
                )

                logger.info(
                    "CaidoCheck GraphQL: POST %s returned %s",
                    graphql_url,
                    response.status,
                )

                # Token-specific errors
                if response.status in (401, 403):
                    logger.warning(
                        "CaidoCheck GraphQL: token rejected (HTTP %s)",
                        response.status,
                    )
                    return False, "CAIDO_TOKEN_INVALID"

                # Non-success but not token-related
                if not response.is_success:
                    logger.warning(
                        "CaidoCheck GraphQL: non-success status %s",
                        response.status,
                    )
                    return False, "CAIDO_GRAPHQL_FAILED"

                # Validate JSON structure
                try:
                    body = response.json()
                except Exception:
                    logger.warning(
                        "CaidoCheck GraphQL: response is not valid JSON"
                    )
                    return False, "CAIDO_GRAPHQL_FAILED"

                if "data" not in body and "errors" not in body:
                    logger.warning(
                        "CaidoCheck GraphQL: response missing 'data'/'errors' keys"
                    )
                    return False, "CAIDO_GRAPHQL_FAILED"

                if "errors" in body:
                    logger.warning(
                        "CaidoCheck GraphQL: GraphQL errors in response: %s",
                        body.get("errors"),
                    )
                    return False, "CAIDO_GRAPHQL_FAILED"

                logger.info("CaidoCheck GraphQL: introspection succeeded")
                return True, ""
            finally:
                await client.close()
        except asyncio.TimeoutError:
            logger.warning("CaidoCheck GraphQL: POST %s timed out", graphql_url)
        except Exception as exc:
            logger.warning(
                "CaidoCheck GraphQL: POST %s failed: %s", graphql_url, exc
            )
        return False, "CAIDO_HTTP_UNREACHABLE"

    # --------------------------------------------------
    # Full run
    # --------------------------------------------------

    async def run(self) -> tuple[bool, list[PreflightFailure]]:
        """Run both TCP and HTTP checks.

        Collects all failures (never raises).  Even when TCP fails, the HTTP
        check is still attempted to gather more evidence.

        Returns:
            ``(all_ok, failures)`` where *all_ok* is ``True`` when no
            failures were collected.
        """
        failures: list[PreflightFailure] = []
        logger.info(
            "CaidoCheck: starting preflight for %s (token=%s)",
            self._state.url,
            self._state.masked_token,
        )

        # --- TCP check ---
        try:
            tcp_ok, tcp_reason = await self.check_tcp()
        except Exception:
            logger.exception("CaidoCheck: unexpected error in check_tcp")
            tcp_ok = False
            tcp_reason = "CAIDO_TCP_UNREACHABLE"

        if not tcp_ok:
            failures.append(
                PreflightFailure(
                    reason_code=tcp_reason,
                    severity="critical",
                    category="Caido Proxy",
                    remediation=(
                        "Ensure Caido is running and listening on "
                        f"{self._state.url}. Check firewall rules."
                    ),
                    evidence={"url": self._state.url},
                )
            )

        # --- HTTP check ---
        # Always run, even if TCP failed, so we surface the specific HTTP
        # failure mode (e.g. token invalid vs. GraphQL error).
        try:
            http_ok, http_reason = await self.check_http()
        except Exception:
            logger.exception("CaidoCheck: unexpected error in check_http")
            http_ok = False
            http_reason = "CAIDO_HTTP_UNREACHABLE"

        if not http_ok:
            remediation = "Check Caido server status and network connectivity."
            if http_reason == "CAIDO_TOKEN_INVALID":
                remediation = (
                    "The configured Caido API token was rejected. "
                    "Verify the token in your settings."
                )
            elif http_reason == "CAIDO_GRAPHQL_FAILED":
                remediation = (
                    "Caido is reachable but the GraphQL API returned an "
                    "unexpected response. Check Caido server logs."
                )
            elif http_reason == "CAIDO_IDENTITY_UNVERIFIED":
                remediation = (
                    "Port 8080 is reachable but Caido identity could not "
                    "be confirmed. Ensure Caido is running and accessible."
                )

            failures.append(
                PreflightFailure(
                    reason_code=http_reason,
                    severity="critical",
                    category="Caido Proxy",
                    remediation=remediation,
                    evidence={"url": self._state.url},
                )
            )

        all_ok = len(failures) == 0
        if all_ok:
            logger.info("CaidoCheck: all checks passed for %s", self._state.url)
        else:
            logger.warning(
                "CaidoCheck: %d failure(s) for %s",
                len(failures),
                self._state.url,
            )

        return all_ok, failures


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mask_token(token: str) -> str:
    """Return a masked version of the token safe for logging.

    Examples:
        ``""`` → ``"<none>"``, ``"abc123..."`` → ``"abc12...***"``,
        ``"short"`` → ``"***"``.
    """
    if not token:
        return "<none>"
    if len(token) <= 8:
        return "***"
    return f"{token[:5]}...***"


def _looks_like_graphql(response: "NetworkResponse") -> bool:
    """Check if a response looks like it came from a GraphQL endpoint.

    Only returns True when the body is valid JSON with actual GraphQL
    structure — ``data`` / ``errors`` keys (standard GraphQL response),
    or schema introspection fields (``__schema``, ``__type``, ``types``,
    ``queryType``, ``mutationType``).  Mere JSON or text containing the
    word ``query`` / ``schema`` no longer qualifies.
    """
    import json

    try:
        body_json = json.loads(response.body)
    except (json.JSONDecodeError, ValueError):
        return False

    if not isinstance(body_json, dict):
        return False

    # Standard GraphQL response: must have 'data' and/or 'errors'
    if "data" in body_json or "errors" in body_json:
        return True

    # Schema introspection fields
    _SCHEMA_INTROSPECTION_FIELDS = {
        "__schema",
        "__type",
        "types",
        "queryType",
        "mutationType",
        "subscriptionType",
    }
    if body_json.keys() & _SCHEMA_INTROSPECTION_FIELDS:
        return True

    return False


def _looks_like_caido(response: "NetworkResponse") -> bool:
    """Check if a response contains Caido-specific indicators.

    Heuristics:
    - Any response header name or value contains ``Caido`` (case-insensitive).
    - Response body contains ``Caido`` (case-insensitive).
    """
    for name, value in response.headers.items():
        if "caido" in name.lower() or "caido" in value.lower():
            return True
    return "caido" in response.body.lower()


def _has_caido_schema_fields(response: "NetworkResponse") -> bool:
    """Check if the response body contains Caido-specific GraphQL schema fields.

    Parses the body as JSON and recursively searches for Caido-specific
    identifiers (``sitemap``, ``requests``, ``intercept``, ``scope``) in
    object keys or string values.  These are schema fields unique to Caido's
    GraphQL API and unlikely to appear in a generic GraphQL service.
    """
    _CAIDO_SCHEMA_TERMS = frozenset({"sitemap", "requests", "intercept", "scope"})

    import json

    try:
        body_json = json.loads(response.body)
    except (json.JSONDecodeError, ValueError):
        return False

    def _search(obj) -> bool:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in _CAIDO_SCHEMA_TERMS:
                    return True
                if _search(value):
                    return True
        elif isinstance(obj, list):
            for item in obj:
                if _search(item):
                    return True
        elif isinstance(obj, str):
            if obj in _CAIDO_SCHEMA_TERMS:
                return True
        return False

    return _search(body_json)
