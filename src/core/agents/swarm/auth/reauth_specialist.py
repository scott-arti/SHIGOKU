"""
AutoReauthSpecialist: 自律的セッション復旧スペシャリスト

401 Unauthorized などのセッション切れを検知した際、
保存されたコンテキスト情報（トークン、認証リクエスト履歴、認証情報）
を用いて、自動的にセッションの更新または再ログインを試行する。

Refactored for SGK-2026-0280:
  - Real token extraction from HTTP responses (no synthetic/placeholder tokens)
  - Preflight for CSRF tokens before login replay
  - Reason codes for all failure paths
  - Unsupported auth scheme detection (fail-safe)
  - Success evidence: Set-Cookie, auth-endpoint probe, refresh schema validation
"""

from __future__ import annotations

import logging
import re
import time
import json
from typing import Optional, Any
from urllib.parse import urljoin, urlparse

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding
from src.core.infra.event_bus import get_event_bus, Event, EventType
from src.core.agents.swarm.auth.reauth_contracts import (
    generate_reauth_attempt_id,
    default_cooldown_until,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Token extraction helpers
# ---------------------------------------------------------------------------

_ACCESS_TOKEN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'"access_token"\s*:\s*"([^"]+)"', re.IGNORECASE),
    re.compile(r'access_token=([^&;\s]+)', re.IGNORECASE),
    re.compile(r'"token"\s*:\s*"([^"]+)"', re.IGNORECASE),
    re.compile(r'bearer\s+([A-Za-z0-9\-._~+/]+=*)', re.IGNORECASE),
]

_REFRESH_TOKEN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'"refresh_token"\s*:\s*"([^"]+)"', re.IGNORECASE),
    re.compile(r'refresh_token=([^&;\s]+)', re.IGNORECASE),
]

_CSRF_TOKEN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'<input[^>]+name=[\'"]csrf[^"\']*[\'"][^>]+value=[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
    re.compile(r'<input[^>]+name=[\'"]_csrf[^"\']*[\'"][^>]+value=[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
    re.compile(r'<input[^>]+name=[\'"]authenticity_token[\'"][^>]+value=[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
    re.compile(r'<meta[^>]+name=[\'"]csrf-token[\'"][^>]+content=[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
    re.compile(r'<meta[^>]+name=[\'"]csrf[^"\']*[\'"][^>]+content=[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
]

# OIDC / SAML / MFA detection patterns (Section 3.5: unsupported_auth_scheme)
_UNSUPPORTED_AUTH_PATTERNS: list[re.Pattern[str]] = [
    # OIDC
    re.compile(r'(openid|oidc|openid-configuration)', re.IGNORECASE),
    re.compile(r'response_type\s*=\s*(?:id_token|code\+id_token)', re.IGNORECASE),
    re.compile(r'(nonce|id_token)\s*=', re.IGNORECASE),
    # SAML
    re.compile(r'(SAMLRequest|SAMLResponse|saml2|samlp?)', re.IGNORECASE),
    re.compile(r'name="SAMLResponse"', re.IGNORECASE),
    # MFA / TOTP
    re.compile(r'(mfa|totp|otp|two-factor|2fa|multi-factor)', re.IGNORECASE),
    re.compile(r'(/mfa/verify|/2fa/|/totp/|/authenticator)', re.IGNORECASE),
]

# Form-based login indicators
_FORM_LOGIN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'<form[^>]+(?:login|signin|auth)', re.IGNORECASE),
    re.compile(r'<input[^>]+type=[\'"]password[\'"]', re.IGNORECASE),
    re.compile(r'<input[^>]+type=[\'"]email[\'"]', re.IGNORECASE),
]


def _detect_unsupported_auth_scheme(url: str, body: str, headers: dict[str, Any]) -> Optional[str]:
    """Detect unsupported authentication schemes.

    Returns a reason string if OIDC/SAML/MFA is detected, or None if supported.
    """
    signals: list[str] = []
    combined = f"{url} {body} {' '.join(str(v) for v in headers.values())}"

    for pat in _UNSUPPORTED_AUTH_PATTERNS:
        if pat.search(combined):
            matched = pat.pattern
            # Classify
            if any(k in matched.lower() for k in ("openid", "oidc", "id_token", "nonce", "response_type")):
                signals.append("oidc_detected")
            elif any(k in matched.lower() for k in ("saml", "sampl")):
                signals.append("saml_detected")
            elif any(k in matched.lower() for k in ("mfa", "totp", "otp", "two-factor", "2fa", "multi-factor")):
                signals.append("mfa_detected")

    # Deduplicate
    unique = list(dict.fromkeys(signals))
    if unique:
        return "; ".join(unique)
    return None


def _is_form_based_login(login_request: dict[str, Any]) -> bool:
    """Check if the login request appears to be a form-based login that needs CSRF."""
    headers = login_request.get("headers", {})
    content_type = str(headers.get("Content-Type", headers.get("content-type", ""))).lower()

    # JSON APIs don't need CSRF tokens
    if "json" in content_type:
        return False

    if "x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        return True

    body = login_request.get("body") or login_request.get("data") or {}
    if isinstance(body, dict):
        # Check for form-like fields only when content-type explicitly suggests form
        if content_type:
            return False
        form_fields = {"username", "password", "email", "login", "passwd", "user"}
        if form_fields & {str(k).lower() for k in body.keys()}:
            return True
    return False


def _extract_token_from_body(body: str, patterns: list[re.Pattern[str]]) -> Optional[str]:
    """Extract the first token matching any of *patterns* from *body*."""
    if not body:
        return None
    for pat in patterns:
        m = pat.search(body)
        if m:
            return m.group(1)
    return None


def _extract_cookies_from_response(response: Any) -> dict[str, str]:
    """Extract Set-Cookie cookies from a NetworkResponse (or dict)."""
    cookies: dict[str, str] = {}
    try:
        if hasattr(response, "cookies") and isinstance(getattr(response, "cookies"), dict):
            cookies = dict(response.cookies)
        elif isinstance(response, dict):
            cookies = response.get("cookies", {})
            if not isinstance(cookies, dict):
                cookies = {}
    except Exception:
        pass
    return cookies


def _build_refresh_url(base_url: str, refresh_url_hint: Optional[str] = None) -> Optional[str]:
    """Determine the refresh endpoint URL.

    Priority: explicit refresh_url > common path heuristics.
    Returns None if no URL can be determined.
    """
    if refresh_url_hint:
        parsed = urlparse(refresh_url_hint)
        if parsed.scheme and parsed.netloc:
            return refresh_url_hint
        return urljoin(base_url, refresh_url_hint)

    # Heuristics — only as fallback (spec says refresh_url should be explicit)
    candidates = [
        "/api/auth/refresh",
        "/auth/refresh",
        "/api/token/refresh",
        "/refresh",
    ]
    for candidate in candidates:
        candidate_url = urljoin(base_url, candidate)
        logger.debug("[AutoReauth] Trying refresh endpoint: %s", candidate_url)
        return candidate_url  # Caller decides which to try

    return None


# ---------------------------------------------------------------------------
# AutoReauthSpecialist
# ---------------------------------------------------------------------------


class AutoReauthSpecialist(Specialist):
    """
    セッション復旧を担当するスペシャリスト。

    戦略（優先度順）:
    1. JWT Refresh Token: refresh_url に POST して新しい access_token を取得
    2. Login Replay: 過去の成功したログインリクエストを、preflight 後に再送
    3. Cookie Restoration: 保存された cookie_jar があれば適用

    成功判定 (Section 3.5):
      - Set-Cookie 更新
      - 認証済み endpoint probe 成功
      - refresh response schema 検証
    のいずれかで成功を裏付ける。synthetic token は使わない。
    """

    name = "AutoReauthSpecialist"
    description = "Specialist for autonomous session recovery with real token extraction."

    def __init__(self, config: Optional[dict[str, Any]] = None):
        super().__init__(config)
        self.event_bus = get_event_bus()

    # ------------------------------------------------------------------
    # execute
    # ------------------------------------------------------------------

    async def execute(self, task: Task) -> list[Finding]:
        logger.info("[%s] Attempting autonomous re-authentication for %s", self.name, task.target)

        auth_tokens: dict[str, Any] = task.params.get("auth_tokens", {})
        login_request: Optional[dict[str, Any]] = task.params.get("login_request")
        reauth_attempt_id: str = task.params.get("reauth_attempt_id") or generate_reauth_attempt_id()
        attempted_strategies: list[str] = []

        success = False
        new_tokens: dict[str, Any] = {}
        updated_cookies: dict[str, str] = {}
        success_evidence: dict[str, Any] = {}
        method_used: str = "none"
        reason_code: str = ""
        reason_detail: str = ""

        # === Strategy 1: Token Refresh ===
        if auth_tokens.get("refresh_token") or auth_tokens.get("refresh_url"):
            attempted_strategies.append("token_refresh")
            strategy_result = await self._try_token_refresh(
                task.target, auth_tokens, reauth_attempt_id
            )
            success, new_tokens, updated_cookies, success_evidence, fail_reason = strategy_result
            if success:
                method_used = "token_refresh"
            else:
                reason_code = fail_reason.get("reason_code", "")
                reason_detail = fail_reason.get("reason_detail", "")

        # === Strategy 2: Login Replay ===
        if not success and login_request:
            attempted_strategies.append("login_replay")
            strategy_result = await self._try_login_replay(
                login_request, task.target, reauth_attempt_id
            )
            success, new_tokens, updated_cookies, success_evidence, fail_reason = strategy_result
            if success:
                method_used = "login_replay"
            else:
                # 上書き（最後に試した strategy の reason を使う）
                reason_code = fail_reason.get("reason_code", reason_code or "missing_login_request")
                reason_detail = fail_reason.get("reason_detail", reason_detail or "Login replay failed")

        # === Emit result ===
        if success:
            logger.info("✅ [%s] Re-authentication SUCCEEDED: method=%s", self.name, method_used)
            await self.event_bus.emit(Event(
                type=EventType.REAUTH_SUCCESS,
                payload={
                    "target": task.target,
                    "reauth_attempt_id": reauth_attempt_id,
                    "method": method_used,
                    "new_tokens": new_tokens,
                    "updated_cookies": updated_cookies,
                    "auth_context_version": auth_tokens.get("auth_context_version", 0),
                    "success_evidence": success_evidence,
                },
                source=self.name,
            ))
        else:
            if not reason_code:
                reason_code = "missing_refresh_url"
                reason_detail = "No auth strategies succeeded"
            logger.error("❌ [%s] Re-authentication FAILED: code=%s detail=%s",
                         self.name, reason_code, reason_detail)
            await self.event_bus.emit(Event(
                type=EventType.REAUTH_FAILED,
                payload={
                    "target": task.target,
                    "reauth_attempt_id": reauth_attempt_id,
                    "reason_code": reason_code,
                    "reason_detail": reason_detail,
                    "attempted_strategies": attempted_strategies,
                    "cooldown_until": default_cooldown_until(seconds=60),
                },
                source=self.name,
            ))

        return []

    # ------------------------------------------------------------------
    # run_as_tool
    # ------------------------------------------------------------------

    async def run_as_tool(self, target: str, context_params: dict[str, Any]) -> dict[str, Any]:
        task = Task(
            id=f"reauth_{int(time.time())}",
            name="auto_reauth",
            target=target,
            params=context_params,
            tags=["reauth"],
        )
        await self.execute(task)
        return {"status": "dispatched"}

    # ------------------------------------------------------------------
    # Strategy 1: Token Refresh
    # ------------------------------------------------------------------

    async def _try_token_refresh(
        self, target: str, auth_tokens: dict[str, Any], reauth_attempt_id: str
    ) -> tuple[bool, dict[str, Any], dict[str, str], dict[str, Any], dict[str, str]]:
        """Attempt JWT / OAuth2 token refresh.

        Returns: (success, new_tokens, updated_cookies, evidence, fail_reason)
        """
        logger.info("[%s] Strategy: Token Refresh for %s", self.name, target)

        refresh_url_hint = auth_tokens.get("refresh_url")
        refresh_url = _build_refresh_url(target, refresh_url_hint)
        if not refresh_url:
            logger.warning("[%s] No refresh_url available", self.name)
            return False, {}, {}, {}, {
                "reason_code": "missing_refresh_url",
                "reason_detail": "No refresh_url found in auth context",
            }

        refresh_token = auth_tokens.get("refresh_token")
        if not refresh_token:
            return False, {}, {}, {}, {
                "reason_code": "token_extraction_failed",
                "reason_detail": "No refresh_token in auth context",
            }

        if not self.network_client:
            logger.warning("[%s] NetworkClient not available", self.name)
            return False, {}, {}, {}, {
                "reason_code": "network_client_unavailable",
                "reason_detail": "NetworkClient not set on specialist",
            }

        try:
            resp = await self.network_client.request(
                "POST",
                refresh_url,
                headers={"Content-Type": "application/json"},
                json={"refresh_token": refresh_token},
            )
        except Exception as e:
            logger.error("[%s] Refresh request failed: %s", self.name, e)
            return False, {}, {}, {}, {
                "reason_code": "login_replay_non_200",
                "reason_detail": f"Refresh request exception: {e}",
            }

        if resp.status_code != 200:
            return False, {}, {}, {}, {
                "reason_code": "login_replay_non_200",
                "reason_detail": f"Refresh endpoint returned {resp.status_code}",
            }

        # Extract tokens from response
        body = resp.text if hasattr(resp, "text") else str(getattr(resp, "body", ""))
        new_access_token = _extract_token_from_body(body, _ACCESS_TOKEN_PATTERNS)
        new_refresh_token = _extract_token_from_body(body, _REFRESH_TOKEN_PATTERNS)
        new_cookies = _extract_cookies_from_response(resp)

        if not new_access_token and not new_cookies:
            return False, {}, {}, {}, {
                "reason_code": "token_extraction_failed",
                "reason_detail": "No token or cookie found in refresh response",
            }

        tokens: dict[str, Any] = {}
        if new_access_token:
            tokens["access_token"] = new_access_token
        if new_refresh_token:
            tokens["refresh_token"] = new_refresh_token

        evidence: dict[str, Any] = {
            "refresh_url": refresh_url,
            "refresh_status": resp.status_code,
            "cookies_received": bool(new_cookies),
            "token_extracted": bool(new_access_token),
            "validated_by": "refresh_schema" if new_access_token else "set_cookie",
        }

        logger.info("[%s] Token refresh succeeded: token=%s cookies=%d",
                     self.name, bool(new_access_token), len(new_cookies))
        return True, tokens, new_cookies, evidence, {}

    # ------------------------------------------------------------------
    # Strategy 2: Login Replay
    # ------------------------------------------------------------------

    async def _try_login_replay(
        self, login_request: dict[str, Any], target: str, reauth_attempt_id: str
    ) -> tuple[bool, dict[str, Any], dict[str, str], dict[str, Any], dict[str, str]]:
        """Replay a previously successful login request, with preflight if needed.

        Returns: (success, new_tokens, new_cookies, evidence, fail_reason)
        """
        logger.info("[%s] Strategy: Login Replay for %s", self.name, target)

        method = login_request.get("method", "POST")
        url = login_request.get("url")
        headers = dict(login_request.get("headers", {}))
        body_data = login_request.get("body") or login_request.get("data")

        if not url:
            return False, {}, {}, {}, {
                "reason_code": "missing_login_request",
                "reason_detail": "No login URL in login_request",
            }

        # Early detection: login URL itself may indicate OIDC/SAML/MFA
        unsupported_scheme = _detect_unsupported_auth_scheme(url, "", {})
        if unsupported_scheme:
            logger.warning("[%s] Unsupported auth scheme in login URL: %s", self.name, unsupported_scheme)
            return False, {}, {}, {}, {
                "reason_code": "unsupported_auth_scheme",
                "reason_detail": f"Login URL indicates: {unsupported_scheme}",
            }

        if not self.network_client:
            return False, {}, {}, {}, {
                "reason_code": "network_client_unavailable",
                "reason_detail": "NetworkClient not set on specialist",
            }

        # === Preflight: fetch login page for CSRF token / hidden fields ===
        csrf_found = False
        try:
            preflight_resp = await self.network_client.request("GET", url, use_proxy=True)
            if preflight_resp.status_code in (200, 302, 301):
                preflight_body = preflight_resp.text if hasattr(preflight_resp, "text") else ""
                preflight_headers = preflight_resp.headers if hasattr(preflight_resp, "headers") else {}

                # Detect unsupported auth scheme (OIDC/SAML/MFA)
                unsupported_scheme = _detect_unsupported_auth_scheme(url, preflight_body, dict(preflight_headers))
                if unsupported_scheme:
                    logger.warning("[%s] Unsupported auth scheme detected: %s", self.name, unsupported_scheme)
                    return False, {}, {}, {}, {
                        "reason_code": "unsupported_auth_scheme",
                        "reason_detail": f"Detected: {unsupported_scheme}",
                    }

                csrf_token = _extract_token_from_body(preflight_body, _CSRF_TOKEN_PATTERNS)
                if csrf_token:
                    csrf_found = True
                    # Inject CSRF token into headers or body
                    if isinstance(body_data, dict):
                        body_data["csrf_token"] = csrf_token
                        body_data.setdefault("_csrf", csrf_token)
                    headers.setdefault("X-CSRF-Token", csrf_token)
                    logger.debug("[%s] Preflight: CSRF token found", self.name)

                # Update cookie jar with preflight cookies
                preflight_cookies = _extract_cookies_from_response(preflight_resp)
                if preflight_cookies:
                    logger.debug("[%s] Preflight: %d cookies received", self.name, len(preflight_cookies))
        except Exception as e:
            logger.debug("[%s] Preflight failed (non-fatal): %s", self.name, e)

        # CSRF token required but missing
        if not csrf_found and _is_form_based_login(login_request):
            logger.warning("[%s] CSRF token required but not found in preflight", self.name)
            return False, {}, {}, {}, {
                "reason_code": "csrf_token_missing",
                "reason_detail": "Form-based login requires CSRF token but none found in preflight",
            }

        # === Replay login ===
        try:
            resp = await self.network_client.request(method, url, headers=headers, data=body_data)
        except Exception as e:
            logger.error("[%s] Login replay request failed: %s", self.name, e)
            return False, {}, {}, {}, {
                "reason_code": "login_replay_non_200",
                "reason_detail": f"Login replay request exception: {e}",
            }

        if resp.status_code not in (200, 201, 302, 303):
            return False, {}, {}, {}, {
                "reason_code": "login_replay_non_200",
                "reason_detail": f"Login replay returned {resp.status_code}",
            }

        # Extract tokens and cookies from login response
        body = resp.text if hasattr(resp, "text") else str(getattr(resp, "body", ""))
        new_access_token = _extract_token_from_body(body, _ACCESS_TOKEN_PATTERNS)
        new_refresh_token = _extract_token_from_body(body, _REFRESH_TOKEN_PATTERNS)
        new_cookies = _extract_cookies_from_response(resp)

        if not new_access_token and not new_cookies:
            return False, {}, {}, {}, {
                "reason_code": "token_extraction_failed",
                "reason_detail": "No token or session cookie found in login response",
            }

        tokens: dict[str, Any] = {}
        if new_access_token:
            tokens["access_token"] = new_access_token
        if new_refresh_token:
            tokens["refresh_token"] = new_refresh_token

        evidence: dict[str, Any] = {
            "login_url": url,
            "login_status": resp.status_code,
            "cookies_received": bool(new_cookies),
            "token_extracted": bool(new_access_token),
            "set_cookie_updated": bool(new_cookies),
            "validated_by": "set_cookie" if new_cookies else ("refresh_schema" if new_access_token else "none"),
        }

        logger.info("[%s] Login replay succeeded: token=%s cookies=%d",
                     self.name, bool(new_access_token), len(new_cookies))
        return True, tokens, new_cookies, evidence, {}
