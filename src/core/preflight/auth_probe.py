"""
Authenticated reachability preflight for the SHIGOKU preflight gate.

Performs a deterministic probe of the target URL with optional credentials
(cookies, bearer token, custom auth headers). When the response cannot be
classified deterministically, a lightweight AI classifier can be invoked
as a supplementary fallback.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
from aiohttp import (
    ClientConnectorDNSError,
    ClientConnectorError,
    ClientError,
    ClientOSError,
    ClientSession,
    ClientTimeout,
    ServerTimeoutError,
)

from src.core.preflight.models import (
    AuthClassification,
    AuthProbeResult,
    PreflightFailure,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Body marker sets (case-insensitive matching)
# ---------------------------------------------------------------------------

_LOGIN_MARKERS: tuple[str, ...] = (
    "login",
    "sign in",
    "log in",
    "password",
    "username",
    "email address",
)

_CHALLENGE_MARKERS: tuple[str, ...] = (
    "captcha",
    "challenge",
    "verify you are human",
    "cloudflare",
    "attention required",
    "blocked",
)

_SESSION_EXPIRED_MARKERS: tuple[str, ...] = (
    "session expired",
    "session timed out",
    "please log in again",
    "your session has ended",
)

_WAF_MARKERS: tuple[str, ...] = (
    "request blocked",
    "firewall",
    "security check",
    "bot detection",
    "access denied",
)

_AUTHENTICATED_MARKERS: tuple[str, ...] = (
    "account",
    "dashboard",
    "profile",
    "welcome",
    "logout",
    "settings",
)

# Regex to extract <title> text
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Maximum number of manual redirect hops
_MAX_REDIRECT_HOPS = 5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mask_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Return a copy of *headers* with sensitive values masked.

    Fields whose names contain ``cookie``, ``auth``, ``token``, ``secret``,
    ``key``, or ``jwt`` are replaced with ``'***'``.  Other values pass
    through unchanged.
    """
    _sensitive = {"cookie", "auth", "token", "secret", "key", "jwt"}
    masked: Dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        if any(hint in lower for hint in _sensitive):
            masked[key] = "***"
        else:
            masked[key] = value
    return masked


def _build_cookie_header(cookies: Dict[str, str]) -> str:
    """Build a ``Cookie`` header value from a dict of key/value pairs."""
    if not cookies:
        return ""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def _scan_markers(body: str, markers: tuple[str, ...]) -> List[str]:
    """Return which *markers* appear (case-insensitive) in *body*."""
    body_lower = body.lower()
    return [m for m in markers if m in body_lower]


def _is_dns_error(exc: BaseException) -> bool:
    """Return True if *exc* indicates a DNS resolution failure."""
    if isinstance(exc, ClientConnectorDNSError):
        return True
    # Some older aiohttp versions or edge cases may wrap DNS errors
    # differently; fall back to string inspection.
    msg = str(exc).lower()
    if "nodename nor servname" in msg or "getaddrinfo" in msg or "name resolution" in msg:
        return True
    return False


# ---------------------------------------------------------------------------
# AuthProbe
# ---------------------------------------------------------------------------

class AuthProbe:
    """Probes authenticated reachability to the target URL.

    Performs a deterministic HTTP request (with optional credentials) and
    classifies the response characteristics. Optionally invokes an AI
    classifier as a supplementary fallback for ambiguous responses.

    Usage::

        probe = AuthProbe()
        result = await probe.probe(
            target="https://example.com",
            cookies={...},
            bearer_token="...",
            auth_headers={...},
            ai_classifier=ai_classifier,
            auth_required=True,
        )

    Reason codes produced:

    - ``AUTH_LOGIN_PAGE`` — response appears to be a login/challenge page.
    - ``AUTH_SESSION_EXPIRED`` — session appears to have expired.
    - ``AUTH_WAF_CHALLENGE`` — WAF or bot-detection challenge detected.
    - ``AUTH_APP_FORBIDDEN`` — app-level forbidden (HTTP 403).
    - ``AUTH_RATE_LIMITED`` — rate limiting detected.
    - ``AUTH_UNKNOWN`` — response could not be classified.
    - ``TARGET_DNS_FAILURE`` — DNS resolution failed.
    - ``TARGET_CONNECTION_FAILURE`` — TCP/TLS connection failed.
    """

    def __init__(
        self,
        network_client: Optional[object] = None,
    ) -> None:
        """Initialise the auth probe.

        Args:
            network_client: Optional AsyncNetworkClient instance for shared
                session reuse. If not provided, a dedicated
                ``aiohttp.ClientSession`` is created per probe.
        """
        # Store for reference, but the probe uses its own session by default.
        # This keeps the implementation self-contained and avoids coupling
        # to AsyncNetworkClient internals (proxy rotation, WAF bypass, etc.)
        self._network_client = network_client
        self._last_result: Optional[AuthProbeResult] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def probe(
        self,
        target: str = "",
        cookies: Optional[Dict[str, str]] = None,
        bearer_token: str = "",
        auth_headers: Optional[Dict[str, str]] = None,
        ai_classifier: Optional[object] = None,
        auth_required: bool = False,
    ) -> AuthProbeResult:
        """Probe authenticated reachability to *target*.

        Performs a deterministic HTTP request and classifies the result.
        If the classification is ``UNKNOWN`` and an *ai_classifier* is
        provided and available, the AI fallback is invoked.

        Args:
            target: Target URL to probe.
            cookies: Session cookies to attach.
            bearer_token: Bearer token for Authorization header.
            auth_headers: Additional authentication headers.
            ai_classifier: Optional AIClassifier for fallback classification.
            auth_required: If ``True`` (authenticated target), ``UNKNOWN``
                classification is treated as a failure.  If ``False``
                (public recon without credentials), ``UNKNOWN`` is an
                acceptable outcome that passes the gate.

        Returns:
            AuthProbeResult with classification details.
        """
        if not target:
            logger.debug("AuthProbe: no target, skipping probe")
            return AuthProbeResult(classification=AuthClassification.UNKNOWN)

        parsed = urlparse(target)
        if not parsed.scheme or not parsed.netloc:
            return AuthProbeResult(
                classification=AuthClassification.UNKNOWN,
                probed_url=target,
            )

        # --- Perform deterministic probe ---
        result = await self._do_probe(
            target=target,
            cookies=cookies or {},
            bearer_token=bearer_token,
            auth_headers=auth_headers or {},
            auth_required=auth_required,
        )

        # --- AI fallback if needed ---
        if (
            result.classification == AuthClassification.UNKNOWN
            and ai_classifier is not None
            and hasattr(ai_classifier, "can_classify")
            and ai_classifier.can_classify()
        ):
            result = await self._ai_fallback(result, ai_classifier)

        self._last_result = result
        return result

    async def probe_and_validate(
        self,
        target: str = "",
        cookies: Optional[Dict[str, str]] = None,
        bearer_token: str = "",
        auth_headers: Optional[Dict[str, str]] = None,
        ai_classifier: Optional[object] = None,
        auth_required: bool = False,
    ) -> tuple[bool, list[PreflightFailure]]:
        """Probe and return structured pass/fail with failures.

        A convenience wrapper that calls :meth:`probe` and translates
        non-authenticated classifications into structured failures.

        When *auth_required* is ``False`` (public recon without credentials),
        an ``UNKNOWN`` classification is treated as acceptable (pass).
        When *auth_required* is ``True`` (authenticated target), only
        ``AUTHENTICATED`` passes.

        Returns:
            ``(all_ok, failures)`` tuple.
        """
        result = await self.probe(
            target=target,
            cookies=cookies,
            bearer_token=bearer_token,
            auth_headers=auth_headers,
            ai_classifier=ai_classifier,
            auth_required=auth_required,
        )

        failures: list[PreflightFailure] = []
        if result.classification == AuthClassification.AUTHENTICATED:
            return True, []

        if not auth_required and result.classification == AuthClassification.UNKNOWN:
            return True, []

        # All other cases → fail
        reason_code = self._reason_code_for(result.classification)
        failures.append(
            PreflightFailure(
                reason_code=reason_code,
                severity="critical",
                category="Auth Probe",
                remediation=self._remediation_for(result.classification),
                evidence={
                    "classification": result.classification.value,
                    "probed_url": result.probed_url,
                    "status_code": result.status_code,
                    "ai_used": result.ai_used,
                    "ai_confidence": result.ai_confidence,
                },
            )
        )

        return len(failures) == 0, failures

    @property
    def last_result(self) -> Optional[AuthProbeResult]:
        """The most recent probe result, or None if not yet probed."""
        return self._last_result

    # ------------------------------------------------------------------
    # Core deterministic probe
    # ------------------------------------------------------------------

    async def _do_probe(
        self,
        target: str,
        cookies: Dict[str, str],
        bearer_token: str,
        auth_headers: Dict[str, str],
        auth_required: bool = False,
    ) -> AuthProbeResult:
        """Perform the deterministic HTTP probe.

        Builds request headers from *auth_headers*, *bearer_token*, and
        *cookies*, then issues a GET request with manual redirect-following
        (up to ``_MAX_REDIRECT_HOPS`` hops).  The final response body is
        analysed for markers, the page title is extracted, and the result
        is classified deterministically via :meth:`_classify_deterministic`.
        """
        masked = _mask_headers(auth_headers)
        logger.info(
            "AuthProbe: probing %s (cookies=%d, has_bearer=%s, auth_headers=%s)",
            target,
            len(cookies),
            bool(bearer_token),
            masked,
        )

        headers: Dict[str, str] = {}
        # Merge custom auth_headers first (so explicit Authorization/Cookie
        # below can override them intentionally).
        headers.update(auth_headers)

        # Bearer token
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"

        # Cookie header (build from dict, can override auth_headers cookies)
        cookie_header = _build_cookie_header(cookies)
        if cookie_header:
            headers["Cookie"] = cookie_header

        now = time.monotonic()
        redirect_chain: List[Dict[str, Any]] = []
        final_url = target
        final_status = 0
        final_body = ""
        dns_failure = False
        connection_failure = False

        timeout = ClientTimeout(total=8)

        try:
            async with ClientSession(timeout=timeout) as session:
                async with asyncio.timeout(8):
                    final_status, final_url, final_body, redirect_chain = (
                        await self._request_with_redirects(
                            session=session,
                            url=target,
                            headers=headers,
                            max_hops=_MAX_REDIRECT_HOPS,
                        )
                    )
        except ServerTimeoutError:
            logger.warning("AuthProbe: server timed out for %s", target)
            connection_failure = True
        except asyncio.TimeoutError:
            logger.warning("AuthProbe: total timeout (8s) reached for %s", target)
            connection_failure = True
        except ClientConnectorDNSError:
            logger.warning("AuthProbe: DNS resolution failed for %s", target)
            dns_failure = True
        except ClientConnectorError as exc:
            # Covers connection-refused, network-unreachable, etc.
            # Check if it is actually a DNS failure wrapped generically.
            if _is_dns_error(exc):
                logger.warning("AuthProbe: DNS resolution failed for %s: %s", target, exc)
                dns_failure = True
            else:
                logger.warning("AuthProbe: connection failed for %s: %s", target, exc)
                connection_failure = True
        except ClientOSError as exc:
            logger.warning("AuthProbe: OS-level connection error for %s: %s", target, exc)
            connection_failure = True
        except ClientError as exc:
            logger.warning("AuthProbe: client error for %s: %s", target, exc)
            connection_failure = True
        except Exception as exc:
            logger.warning(
                "AuthProbe: unexpected error during probe of %s: %s",
                target,
                exc,
                exc_info=True,
            )
            connection_failure = True

        elapsed_ms = (time.monotonic() - now) * 1000.0

        if dns_failure:
            result = AuthProbeResult(
                classification=AuthClassification.DNS_FAILURE,
                status_code=0,
                probed_url=final_url,
                elapsed_ms=elapsed_ms,
            )
            return result

        if connection_failure:
            result = AuthProbeResult(
                classification=AuthClassification.CONNECTION_FAILURE,
                status_code=0,
                probed_url=final_url,
                elapsed_ms=elapsed_ms,
            )
            return result

        # --- Analyse response body ---
        title = self._extract_title(final_body)
        login_markers = _scan_markers(final_body, _LOGIN_MARKERS)
        challenge_markers = _scan_markers(final_body, _CHALLENGE_MARKERS)
        session_expired_markers = _scan_markers(final_body, _SESSION_EXPIRED_MARKERS)
        waf_markers = _scan_markers(final_body, _WAF_MARKERS)
        authenticated_markers = _scan_markers(final_body, _AUTHENTICATED_MARKERS)

        # Merge challenge + WAF markers for has_challenge
        all_challenge_markers = list({*challenge_markers, *waf_markers})
        has_challenge = bool(all_challenge_markers)

        # is_login_page heuristic:
        #   has login markers AND (title suggests login OR no authenticated markers)
        title_lower = title.lower()
        has_login_markers = bool(login_markers)
        title_suggests_login = any(
            word in title_lower for word in ("login", "sign in", "log in")
        )
        is_login_page = has_login_markers and (
            title_suggests_login or not bool(authenticated_markers)
        )

        # Collect all body markers found, deduplicated and sorted
        _marker_lists = (
            login_markers,
            challenge_markers,
            session_expired_markers,
            waf_markers,
            authenticated_markers,
        )
        all_body_markers = sorted(set(
            marker for marker_list in _marker_lists for marker in marker_list
        ))

        result = AuthProbeResult(
            classification=AuthClassification.UNKNOWN,  # will be set below
            status_code=final_status,
            redirect_chain=redirect_chain,
            title=title,
            body_markers=all_body_markers,
            is_login_page=is_login_page,
            has_challenge=has_challenge,
            probed_url=final_url,
            elapsed_ms=elapsed_ms,
        )

        # --- Deterministic classification ---
        result = self._classify_deterministic(
            result,
            has_login_markers=has_login_markers,
            has_session_expired_markers=bool(session_expired_markers),
            has_authenticated_markers=bool(authenticated_markers),
        )

        logger.debug(
            "AuthProbe: result=%s status=%d title=%r is_login=%s has_challenge=%s "
            "elapsed=%.0fms",
            result.classification.value,
            result.status_code,
            result.title[:100] if result.title else "",
            result.is_login_page,
            result.has_challenge,
            result.elapsed_ms,
        )
        return result

    # ------------------------------------------------------------------
    # Manual redirect-following
    # ------------------------------------------------------------------

    async def _request_with_redirects(
        self,
        session: ClientSession,
        url: str,
        headers: Dict[str, str],
        max_hops: int,
    ) -> tuple[int, str, str, List[Dict[str, Any]]]:
        """Send GET to *url* and manually follow redirects up to *max_hops*.

        Returns:
            ``(final_status, final_url, final_body, redirect_chain)``.
        """
        current_url = url
        chain: List[Dict[str, Any]] = []
        last_status = 0
        last_body = ""

        for _hop in range(max_hops):
            async with session.get(
                current_url,
                headers=headers,
                allow_redirects=False,
            ) as response:
                last_status = response.status
                last_body = await response.text(errors="replace")

                if last_status in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location", "")
                    chain.append({
                        "status": last_status,
                        "url": current_url,
                        "location": location,
                    })
                    if location:
                        # Resolve relative URLs against the current base.
                        current_url = str(response.url.join(
                            response.url.origin().join(
                                aiohttp.URL(location)
                            )
                        ) if location.startswith("/") else location)
                        continue
                    else:
                        # Redirect without Location — treat as terminal.
                        return last_status, current_url, last_body, chain
                else:
                    # Non-redirect status — terminal response.
                    return last_status, current_url, last_body, chain

        # Exhausted max_hops; return whatever we received on the last hop.
        return last_status, current_url, last_body, chain

    # ------------------------------------------------------------------
    # Body analysis
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_title(body: str) -> str:
        """Extract ``<title>`` text from *body* using a simple regex.

        Returns an empty string if no title is found.
        """
        match = _TITLE_RE.search(body)
        if match:
            return match.group(1).strip()
        return ""

    # ------------------------------------------------------------------
    # Deterministic classifier
    # ------------------------------------------------------------------

    def _classify_deterministic(
        self,
        result: AuthProbeResult,
        has_login_markers: bool,
        has_session_expired_markers: bool,
        has_authenticated_markers: bool,
    ) -> AuthProbeResult:
        """Classify *result* using deterministic rules.

        Rules (applied in priority order):

        1. status_code == 0 → CONNECTION_FAILURE
        2. DNS failure → DNS_FAILURE (already handled in caller)
        3. 302/301 redirect to URL containing ``/login`` → LOGIN_PAGE
        4. status_code == 401 → SESSION_EXPIRED
        5. status_code == 403 → APP_FORBIDDEN
        6. status_code == 429 → RATE_LIMITED
        7. has_challenge → WAF_CHALLENGE
        8. has session-expired body markers → SESSION_EXPIRED
        9. is_login_page → LOGIN_PAGE
        10. status_code == 200 AND has authenticated markers AND not is_login_page → AUTHENTICATED
        11. Otherwise → UNKNOWN
        """
        # DNS_FAILURE / CONNECTION_FAILURE already set by caller; skip if set.
        if result.classification in (
            AuthClassification.DNS_FAILURE,
            AuthClassification.CONNECTION_FAILURE,
        ):
            return result

        # Rule 1: status_code == 0 → CONNECTION_FAILURE
        if result.status_code == 0:
            result.classification = AuthClassification.CONNECTION_FAILURE
            return result

        # Rule 3: redirect chain contains a /login location
        for hop in result.redirect_chain:
            location = hop.get("location", "")
            if "/login" in str(location).lower():
                result.classification = AuthClassification.LOGIN_PAGE
                return result

        # Rule 4: 401 → SESSION_EXPIRED
        if result.status_code == 401:
            result.classification = AuthClassification.SESSION_EXPIRED
            return result

        # Rule 5: 403 → APP_FORBIDDEN
        if result.status_code == 403:
            result.classification = AuthClassification.APP_FORBIDDEN
            return result

        # Rule 6: 429 → RATE_LIMITED
        if result.status_code == 429:
            result.classification = AuthClassification.RATE_LIMITED
            return result

        # Rule 7: has_challenge → WAF_CHALLENGE
        if result.has_challenge:
            result.classification = AuthClassification.WAF_CHALLENGE
            return result

        # Rule 8: session-expired body markers → SESSION_EXPIRED
        if has_session_expired_markers:
            result.classification = AuthClassification.SESSION_EXPIRED
            return result

        # Rule 9: is_login_page → LOGIN_PAGE
        if result.is_login_page:
            result.classification = AuthClassification.LOGIN_PAGE
            return result

        # Rule 10: 200 + authenticated markers + not login page → AUTHENTICATED
        if (
            result.status_code == 200
            and has_authenticated_markers
            and not result.is_login_page
        ):
            result.classification = AuthClassification.AUTHENTICATED
            return result

        # Rule 11: fallback
        result.classification = AuthClassification.UNKNOWN
        return result

    # ------------------------------------------------------------------
    # AI fallback
    # ------------------------------------------------------------------

    async def _ai_fallback(
        self,
        result: AuthProbeResult,
        ai_classifier: object,
    ) -> AuthProbeResult:
        """Invoke the AI classifier as a supplementary fallback.

        Builds a ResponseClassificationInput from the probe result, sends it
        to the classifier, and updates the result with the AI label/confidence.
        """
        from src.core.preflight.models import ResponseClassificationInput

        input_data = ResponseClassificationInput(
            title=result.title,
            redirect_summary=str(len(result.redirect_chain)),
            top_markers=result.body_markers[:5],
            status_code=result.status_code,
            response_fragment="",
        )

        try:
            ai_result = await ai_classifier.classify(input_data)
        except Exception as exc:
            logger.warning("AuthProbe: AI fallback failed: %s", exc)
            return result

        # Map AI label to AuthClassification
        label_map: Dict[str, AuthClassification] = {
            "authenticated": AuthClassification.AUTHENTICATED,
            "login_page": AuthClassification.LOGIN_PAGE,
            "session_expired": AuthClassification.SESSION_EXPIRED,
            "waf_challenge": AuthClassification.WAF_CHALLENGE,
            "rate_limited": AuthClassification.RATE_LIMITED,
            "unknown": AuthClassification.UNKNOWN,
        }
        classification = label_map.get(ai_result.label, AuthClassification.UNKNOWN)

        result.classification = classification
        result.ai_used = True
        result.ai_confidence = ai_result.confidence
        result.ai_label = ai_result.label
        return result

    # ------------------------------------------------------------------
    # Reason code / remediation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _reason_code_for(classification: AuthClassification) -> str:
        """Map an AuthClassification to a structured reason code."""
        mapping: Dict[AuthClassification, str] = {
            AuthClassification.LOGIN_PAGE: "AUTH_LOGIN_PAGE",
            AuthClassification.SESSION_EXPIRED: "AUTH_SESSION_EXPIRED",
            AuthClassification.WAF_CHALLENGE: "AUTH_WAF_CHALLENGE",
            AuthClassification.APP_FORBIDDEN: "AUTH_APP_FORBIDDEN",
            AuthClassification.RATE_LIMITED: "AUTH_RATE_LIMITED",
            AuthClassification.DNS_FAILURE: "TARGET_DNS_FAILURE",
            AuthClassification.CONNECTION_FAILURE: "TARGET_CONNECTION_FAILURE",
        }
        return mapping.get(classification, "AUTH_UNKNOWN")

    @staticmethod
    def _remediation_for(classification: AuthClassification) -> str:
        """Return a human-readable remediation suggestion."""
        mapping: Dict[AuthClassification, str] = {
            AuthClassification.LOGIN_PAGE: (
                "Target is redirecting to a login page. "
                "Provide valid session cookies or bearer token."
            ),
            AuthClassification.SESSION_EXPIRED: (
                "Session appears to have expired. "
                "Refresh your session cookies/token and retry."
            ),
            AuthClassification.WAF_CHALLENGE: (
                "A WAF or bot-detection challenge is blocking the request. "
                "Consider adjusting the request headers or using a proxy bypass."
            ),
            AuthClassification.APP_FORBIDDEN: (
                "Target returned HTTP 403 (forbidden). "
                "Verify your credentials and access permissions."
            ),
            AuthClassification.RATE_LIMITED: (
                "Target is rate-limiting requests. "
                "Add delays or reduce request concurrency."
            ),
            AuthClassification.DNS_FAILURE: (
                "DNS resolution failed for the target. "
                "Check the target URL and network connectivity."
            ),
            AuthClassification.CONNECTION_FAILURE: (
                "TCP/TLS connection to the target failed. "
                "Verify the target is reachable and the port is correct."
            ),
        }
        return mapping.get(classification, "Target authentication status could not be determined.")
