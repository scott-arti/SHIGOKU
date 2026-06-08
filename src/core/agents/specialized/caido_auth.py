import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlencode, urlparse

import aiohttp

from src.core.infra.network_client import AsyncNetworkClient

logger = logging.getLogger(__name__)


START_AUTHENTICATION_FLOW_QUERY = """
mutation StartAuthenticationFlow {
  startAuthenticationFlow {
    request {
      id
      userCode
      verificationUrl
      expiresAt
    }
    error {
      __typename
      ... on AuthenticationUserError {
        code
        reason
      }
      ... on CloudUserError {
        code
        reason
      }
      ... on InternalUserError {
        code
        message
      }
      ... on OtherUserError {
        code
      }
    }
  }
}
"""

REFRESH_AUTHENTICATION_TOKEN_QUERY = """
mutation RefreshAuthenticationToken($refreshToken: Token!) {
  refreshAuthenticationToken(refreshToken: $refreshToken) {
    token {
      accessToken
      refreshToken
      expiresAt
      scopes
    }
    error {
      __typename
      ... on AuthenticationUserError {
        code
        reason
      }
      ... on CloudUserError {
        code
        reason
      }
      ... on InternalUserError {
        code
        message
      }
      ... on OtherUserError {
        code
      }
    }
  }
}
"""

LOGIN_AS_GUEST_QUERY = """
mutation LoginAsGuest {
  loginAsGuest {
    token {
      accessToken
      refreshToken
      expiresAt
      scopes
    }
    error {
      __typename
      ... on PermissionDeniedUserError {
        __typename
      }
      ... on OtherUserError {
        code
      }
    }
  }
}
"""

CREATED_AUTHENTICATION_TOKEN_SUBSCRIPTION = """
subscription CreatedAuthenticationToken($requestId: ID!) {
  createdAuthenticationToken(requestId: $requestId) {
    token {
      accessToken
      refreshToken
      expiresAt
      scopes
    }
    error {
      __typename
      ... on AuthenticationUserError {
        code
        reason
      }
      ... on InternalUserError {
        code
        message
      }
      ... on OtherUserError {
        code
      }
    }
  }
}
"""


class CaidoAuthError(RuntimeError):
    """Raised when PAT -> access token exchange or refresh fails."""


@dataclass
class _TokenState:
    access_token: str
    refresh_token: Optional[str] = None
    expires_at: Optional[str] = None
    scopes: list[str] | None = None

    def is_expired(self, leeway_seconds: int = 60) -> bool:
        if not self.expires_at:
            return False
        expires_dt = _parse_iso_datetime(self.expires_at)
        if not expires_dt:
            return False
        return expires_dt <= (datetime.now(timezone.utc).timestamp() + leeway_seconds)


def _parse_iso_datetime(value: str) -> Optional[float]:
    token = str(value or "").strip()
    if not token:
        return None
    # datetime.fromisoformat does not accept trailing "Z" directly.
    normalized = token[:-1] + "+00:00" if token.endswith("Z") else token
    try:
        return datetime.fromisoformat(normalized).timestamp()
    except Exception:
        return None


def _extract_error_message(error: dict[str, Any]) -> str:
    code = str(error.get("code", "") or "").strip()
    reason = str(error.get("reason", "") or "").strip()
    message = str(error.get("message", "") or "").strip()
    typename = str(error.get("__typename", "") or "").strip()
    for part in (reason, message, code, typename):
        if part:
            return part
    return "unknown"


class CaidoAuthResolver:
    """
    Resolve and refresh Caido access tokens.

    - If configured token is a direct access token: return as-is.
    - If configured token is a PAT (`caido_...`): exchange to access token using
      startAuthenticationFlow + cloud device approval + subscription callback.
    """

    def __init__(
        self,
        instance_url: str,
        configured_token: str,
        *,
        timeout_seconds: int = 30,
        cloud_api_url: str = "https://api.caido.io",
        cache_path: Optional[Path] = None,
    ) -> None:
        self.instance_url = str(instance_url or "").rstrip("/")
        self.configured_token = str(configured_token or "").strip()
        self.timeout_seconds = int(timeout_seconds)
        self.cloud_api_url = str(cloud_api_url or "https://api.caido.io").rstrip("/")
        self.cache_path = cache_path or (Path.home() / ".shigoku" / "caido_auth_tokens.json")
        self._state: Optional[_TokenState] = None
        self._lock = asyncio.Lock()

    @property
    def is_pat(self) -> bool:
        return self.configured_token.startswith("caido_")

    @property
    def websocket_url(self) -> str:
        parsed = urlparse(self.instance_url)
        scheme = "wss" if parsed.scheme == "https" else "ws"
        return f"{scheme}://{parsed.netloc}/ws/graphql"

    async def get_access_token(self, *, force_refresh: bool = False) -> Optional[str]:
        if not self.configured_token:
            return None
        if not self.is_pat:
            return self.configured_token

        async with self._lock:
            if self._state is None:
                self._state = self._load_cached_state()

            if not force_refresh and self._state and not self._state.is_expired(leeway_seconds=180):
                return self._state.access_token

            if self._state and self._state.refresh_token:
                refreshed = await self._refresh_from_refresh_token(self._state.refresh_token)
                if refreshed:
                    self._state = refreshed
                    self._save_cached_state(refreshed)
                    return refreshed.access_token

            try:
                exchanged = await self._exchange_pat_for_access_token()
            except Exception as exc:
                logger.warning(
                    "PAT-based Caido auth exchange failed: %s. Trying guest token fallback for read-only sitemap extraction.",
                    exc,
                )
                guest_state = await self._login_as_guest_token()
                if guest_state:
                    self._state = guest_state
                    self._save_cached_state(guest_state)
                    return guest_state.access_token
                if isinstance(exc, CaidoAuthError):
                    raise
                raise CaidoAuthError(str(exc))

            self._state = exchanged
            self._save_cached_state(exchanged)
            return exchanged.access_token

    async def _exchange_pat_for_access_token(self) -> _TokenState:
        response = await self._post_graphql(
            START_AUTHENTICATION_FLOW_QUERY,
            variables={},
            access_token=None,
        )
        self._raise_if_graphql_errors(response, context="startAuthenticationFlow")

        payload = (response.get("data") or {}).get("startAuthenticationFlow") or {}
        if payload.get("error"):
            message = _extract_error_message(payload["error"])
            raise CaidoAuthError(f"startAuthenticationFlow failed: {message}")

        request_info = payload.get("request") or {}
        request_id = str(request_info.get("id", "") or "").strip()
        user_code = str(request_info.get("userCode", "") or "").strip()
        expires_at = str(request_info.get("expiresAt", "") or "").strip()
        if not request_id or not user_code:
            raise CaidoAuthError("startAuthenticationFlow returned incomplete request metadata")

        try:
            await self._approve_device_with_pat(user_code=user_code)
        except CaidoAuthError:
            raise
        except Exception as exc:
            raise CaidoAuthError(f"Failed to approve device with PAT: {exc}") from exc
        token = await self._wait_for_created_token(request_id=request_id, request_expires_at=expires_at)
        return token

    async def _refresh_from_refresh_token(self, refresh_token: str) -> Optional[_TokenState]:
        token = str(refresh_token or "").strip()
        if not token:
            return None

        try:
            response = await self._post_graphql(
                REFRESH_AUTHENTICATION_TOKEN_QUERY,
                variables={"refreshToken": token},
                access_token=None,
            )
            self._raise_if_graphql_errors(response, context="refreshAuthenticationToken")
            payload = (response.get("data") or {}).get("refreshAuthenticationToken") or {}
            if payload.get("error"):
                logger.warning(
                    "refreshAuthenticationToken returned error: %s",
                    _extract_error_message(payload["error"]),
                )
                return None
            token_payload = payload.get("token") or {}
            state = self._token_state_from_payload(token_payload)
            if not state:
                return None
            return state
        except Exception as exc:
            logger.warning("Failed to refresh Caido access token: %s", exc)
            return None

    async def _login_as_guest_token(self) -> Optional[_TokenState]:
        try:
            response = await self._post_graphql(
                LOGIN_AS_GUEST_QUERY,
                variables={},
                access_token=None,
            )
            self._raise_if_graphql_errors(response, context="loginAsGuest")
            payload = (response.get("data") or {}).get("loginAsGuest") or {}
            if payload.get("error"):
                logger.warning("loginAsGuest returned error: %s", payload["error"])
                return None
            token_payload = payload.get("token") or {}
            state = self._token_state_from_payload(token_payload)
            if not state:
                return None
            return state
        except Exception as exc:
            logger.warning("Guest fallback auth failed: %s", exc)
            return None

    async def _approve_device_with_pat(self, *, user_code: str) -> None:
        params = urlencode({"user_code": user_code})
        info_url = f"{self.cloud_api_url}/oauth2/device/information?{params}"

        async with AsyncNetworkClient() as client:
            info_resp = await client.request(
                "GET",
                info_url,
                headers={
                    "Authorization": f"Bearer {self.configured_token}",
                    "Accept": "application/json",
                },
                use_proxy=False,
                auto_waf_bypass=False,
                timeout=self.timeout_seconds,
            )

        if info_resp.status_code >= 400:
            detail = _safe_error_text(info_resp)
            raise CaidoAuthError(
                f"Failed to get device information from Caido Cloud: HTTP {info_resp.status_code} ({detail})"
            )

        info_data = _safe_json(info_resp)
        raw_scopes = info_data.get("scopes") if isinstance(info_data, dict) else None
        scopes: list[str] = []
        if isinstance(raw_scopes, list):
            for scope in raw_scopes:
                if isinstance(scope, dict):
                    name = str(scope.get("name", "") or "").strip()
                    if name:
                        scopes.append(name)
                elif isinstance(scope, str):
                    if scope.strip():
                        scopes.append(scope.strip())

        approve_params = urlencode({"user_code": user_code, "scope": ",".join(scopes)})
        approve_url = f"{self.cloud_api_url}/oauth2/device/approve?{approve_params}"

        async with AsyncNetworkClient() as client:
            approve_resp = await client.request(
                "POST",
                approve_url,
                headers={
                    "Authorization": f"Bearer {self.configured_token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                use_proxy=False,
                auto_waf_bypass=False,
                timeout=self.timeout_seconds,
            )

        if approve_resp.status_code >= 400:
            detail = _safe_error_text(approve_resp)
            raise CaidoAuthError(
                f"Failed to approve device with PAT: HTTP {approve_resp.status_code} ({detail})"
            )

    async def _wait_for_created_token(self, *, request_id: str, request_expires_at: str) -> _TokenState:
        timeout_seconds = max(self.timeout_seconds, 20)
        expires_ts = _parse_iso_datetime(request_expires_at)
        if expires_ts is None:
            deadline = time.time() + timeout_seconds
        else:
            deadline = min(expires_ts, time.time() + max(timeout_seconds, 60))

        ws_timeout = aiohttp.ClientTimeout(total=None)
        async with aiohttp.ClientSession(timeout=ws_timeout) as session:
            async with session.ws_connect(
                self.websocket_url,
                protocols=("graphql-transport-ws",),
                heartbeat=15,
            ) as ws:
                await ws.send_json({"type": "connection_init", "payload": {}})

                await self._await_connection_ack(ws, deadline=deadline)

                operation_id = "auth-flow"
                await ws.send_json(
                    {
                        "id": operation_id,
                        "type": "subscribe",
                        "payload": {
                            "query": CREATED_AUTHENTICATION_TOKEN_SUBSCRIPTION,
                            "variables": {"requestId": request_id},
                        },
                    }
                )

                while True:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        raise CaidoAuthError("Timed out waiting for createdAuthenticationToken")

                    message = await ws.receive(timeout=remaining)
                    if message.type == aiohttp.WSMsgType.TEXT:
                        envelope = _safe_ws_json(message.data)
                        msg_type = str(envelope.get("type", "") or "")
                        if msg_type == "ping":
                            await ws.send_json({"type": "pong"})
                            continue
                        if msg_type == "pong":
                            continue
                        if msg_type == "error":
                            raise CaidoAuthError(
                                f"Subscription error: {json.dumps(envelope.get('payload', {}), ensure_ascii=False)}"
                            )
                        if msg_type == "complete":
                            raise CaidoAuthError("Subscription ended before token was issued")
                        if msg_type != "next":
                            continue

                        payload = envelope.get("payload") or {}
                        if payload.get("errors"):
                            first = payload["errors"][0] if isinstance(payload["errors"], list) else payload["errors"]
                            raise CaidoAuthError(f"Subscription GraphQL error: {first}")

                        event_payload = (payload.get("data") or {}).get("createdAuthenticationToken") or {}
                        if event_payload.get("error"):
                            raise CaidoAuthError(
                                f"createdAuthenticationToken returned error: {_extract_error_message(event_payload['error'])}"
                            )

                        token_payload = event_payload.get("token") or {}
                        state = self._token_state_from_payload(token_payload)
                        if state:
                            await ws.send_json({"id": operation_id, "type": "complete"})
                            return state

                    elif message.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED):
                        raise CaidoAuthError("WebSocket closed while waiting for token")
                    elif message.type == aiohttp.WSMsgType.ERROR:
                        raise CaidoAuthError(f"WebSocket error: {ws.exception()}")

    async def _await_connection_ack(self, ws: aiohttp.ClientWebSocketResponse, *, deadline: float) -> None:
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise CaidoAuthError("Timed out waiting for websocket connection_ack")
            message = await ws.receive(timeout=remaining)
            if message.type == aiohttp.WSMsgType.TEXT:
                envelope = _safe_ws_json(message.data)
                msg_type = str(envelope.get("type", "") or "")
                if msg_type == "connection_ack":
                    return
                if msg_type == "ping":
                    await ws.send_json({"type": "pong"})
                    continue
                if msg_type == "connection_error":
                    raise CaidoAuthError(
                        f"WebSocket connection error: {json.dumps(envelope.get('payload', {}), ensure_ascii=False)}"
                    )
            elif message.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED):
                raise CaidoAuthError("WebSocket closed before connection_ack")
            elif message.type == aiohttp.WSMsgType.ERROR:
                raise CaidoAuthError(f"WebSocket error before connection_ack: {ws.exception()}")

    async def _post_graphql(
        self,
        query: str,
        *,
        variables: dict[str, Any],
        access_token: Optional[str],
    ) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"

        async with AsyncNetworkClient() as client:
            response = await client.request(
                "POST",
                f"{self.instance_url}/graphql",
                json={"query": query, "variables": variables},
                headers=headers,
                use_proxy=False,
                auto_waf_bypass=False,
                timeout=max(self.timeout_seconds, 15),
            )

        if response.status_code >= 400:
            detail = _safe_error_text(response)
            raise CaidoAuthError(
                f"Caido GraphQL HTTP error ({response.status_code}) while posting auth query: {detail}"
            )

        data = _safe_json(response)
        if not isinstance(data, dict):
            raise CaidoAuthError("Caido GraphQL returned non-object payload")
        return data

    def _raise_if_graphql_errors(self, response: dict[str, Any], *, context: str) -> None:
        errors = response.get("errors")
        if not isinstance(errors, list) or not errors:
            return
        first = errors[0] if isinstance(errors[0], dict) else {"message": str(errors[0])}
        message = str(first.get("message", "unknown GraphQL error"))
        raise CaidoAuthError(f"{context} GraphQL error: {message}")

    def _token_state_from_payload(self, payload: dict[str, Any]) -> Optional[_TokenState]:
        access_token = str(payload.get("accessToken", "") or "").strip()
        if not access_token:
            return None
        refresh_token = str(payload.get("refreshToken", "") or "").strip() or None
        expires_at = str(payload.get("expiresAt", "") or "").strip() or None
        raw_scopes = payload.get("scopes")
        scopes = [str(s).strip() for s in raw_scopes] if isinstance(raw_scopes, list) else None
        return _TokenState(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at,
            scopes=scopes,
        )

    def _cache_instance_key(self) -> str:
        parsed = urlparse(self.instance_url)
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")

    def _cache_pat_fingerprint(self) -> str:
        return hashlib.sha256(self.configured_token.encode("utf-8")).hexdigest()

    def _load_cached_state(self) -> Optional[_TokenState]:
        try:
            if not self.cache_path.exists():
                return None
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return None
            instances = data.get("instances")
            if not isinstance(instances, dict):
                return None
            cached = instances.get(self._cache_instance_key())
            if not isinstance(cached, dict):
                return None
            if cached.get("pat_sha256") != self._cache_pat_fingerprint():
                return None
            access_token = str(cached.get("access_token", "") or "").strip()
            if not access_token:
                return None
            state = _TokenState(
                access_token=access_token,
                refresh_token=str(cached.get("refresh_token", "") or "").strip() or None,
                expires_at=str(cached.get("expires_at", "") or "").strip() or None,
                scopes=[str(s).strip() for s in cached.get("scopes", [])] if isinstance(cached.get("scopes"), list) else None,
            )
            return state
        except Exception as exc:
            logger.debug("Failed to load Caido auth cache: %s", exc)
            return None

    def _save_cached_state(self, state: _TokenState) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            if self.cache_path.exists():
                current = json.loads(self.cache_path.read_text(encoding="utf-8"))
                if not isinstance(current, dict):
                    current = {}
            else:
                current = {}

            instances = current.get("instances")
            if not isinstance(instances, dict):
                instances = {}

            instances[self._cache_instance_key()] = {
                "pat_sha256": self._cache_pat_fingerprint(),
                "access_token": state.access_token,
                "refresh_token": state.refresh_token,
                "expires_at": state.expires_at,
                "scopes": state.scopes or [],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

            current["version"] = 1
            current["instances"] = instances
            self.cache_path.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")
            try:
                self.cache_path.chmod(0o600)
            except Exception:
                # chmod can fail on some filesystems. Cache remains usable.
                pass
        except Exception as exc:
            logger.debug("Failed to save Caido auth cache: %s", exc)


def _safe_json(response: Any) -> dict[str, Any]:
    try:
        data = response.json()
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        return {}


def _safe_error_text(response: Any) -> str:
    payload = _safe_json(response)
    if payload:
        return json.dumps(payload, ensure_ascii=False)
    return str(getattr(response, "text", "") or "")


def _safe_ws_json(raw_text: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw_text)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}
