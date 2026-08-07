"""
VDP Observation Adapter — SGK-2026-0420.

Boundary adapter between raw recon signals and the VDP hypothesis generator.

Responsibilities:
- Strip secrets (Authorization, Cookie, token, API key values) at the input
  boundary. Only safe booleans (``has_auth_header`` / ``has_cookie``) are
  passed on. Saving-time redaction is a second line of defense, NOT a
  replacement for this boundary.
- Exclude per-run UUIDs (``signal_id``) and current timestamps
  (``created_at``) from all deterministic inputs. Raw signal_id / timestamps
  are dropped entirely; they are not part of the deterministic snapshot.
- Normalize URLs (scheme + hostname required, fragment removed, query
  parameter names sorted) and derive deterministic observation IDs from
  canonical JSON (see ``deterministic_id`` in ``vdp_contract``).
- Identify each observation source via ``ObservationSourceKind``.
  SGK-2026-0420 wires ``recon_signal_bundle`` only; other sources are
  reported as unavailable in the generation status trace (tracking task:
  SGK-2026-0421).

Pure module: no network, no LLM, no random/UUID/time in outputs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from src.core.models.vdp_contract import deterministic_id


class ObservationSourceKind(Enum):
    """Semantic identification of an observation source."""

    RECON_SIGNAL_BUNDLE = "recon_signal_bundle"
    CRAWLER = "crawler"
    FORM = "form"
    JAVASCRIPT = "javascript"
    API_SCHEMA = "api_schema"
    GRAPHQL = "graphql"
    BROWSER_TRAFFIC = "browser_traffic"
    PROXY_HISTORY = "proxy_history"
    UNAVAILABLE = "unavailable"


# Header / credential keys that carry secret material. Matching signal keys
# are converted to booleans and their values are DISCARDED.
_AUTH_HEADER_KEYS_LOWER = {
    "authorization",
    "proxy-authorization",
    "proxy_authorization",
    "x-api-key",
    "x_api_key",
    "x-auth-token",
    "x_auth_token",
    "api_key",
    "apikey",
    "bearer",
    "jwt",
}
_COOKIE_KEYS_LOWER = {"cookie", "set-cookie", "set_cookie"}
_TOKEN_KEYS_LOWER = {
    "token",
    "access_token",
    "refresh_token",
    "auth_token",
    "session_token",
    "password",
    "passwd",
    "secret",
    "credential",
    "credentials",
    "private_key",
    "ssh_key",
}

_URL_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*$")

# Path segments that introduce a following secret segment (reset tokens,
# session IDs, activation links, ...). The segment AFTER one of these
# keywords is replaced with the opaque marker.
_SECRET_PATH_KEYWORDS = {
    "reset", "token", "confirm", "activate", "activation", "verify",
    "verification", "session", "invite", "callback", "password", "secret",
    "key", "auth", "signup", "recover", "recovery", "validate",
}

# Token-like path segment shapes: UUIDs and long hex/base64-ish strings.
_UUID_SEGMENT_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_HEX_SEGMENT_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
_B64URL_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]{24,}$")

# Path elements that ARE secret values themselves, e.g. token-abc123,
# secret-xyz, session-id-123, key_abc, csrf_token_value, ...
_SECRET_PREFIXED_SEGMENT_RE = re.compile(
    r"^(?:token|secret|session|key|id|auth|reset|confirm|activate|activation|"
    r"verify|verification|invite|callback|password|passwd|signature|sig|hash|"
    r"nonce|csrf)[-_][A-Za-z0-9._~-]+$",
    re.IGNORECASE,
)

_OPAQUE_SEGMENT = ":opaque"


def _sanitize_path_segments(path: str) -> str:
    """Replace secret-looking path segments with the fixed ``:opaque`` marker.

    A segment is treated as a secret when:
    - it looks like a UUID, a long hex string, or a long base64url string, or
    - it is itself a secret-prefixed value (token-abc123, secret-xyz,
      session-id-..., key_..., csrf-..., ...), or
    - the previous segment is a secret-context keyword (reset/token/session/
      confirm/activate/verify/invite/callback/password/secret/key/...).

    The replacement is deterministic and fixed, so the same raw URL always
    maps to the same normalized URL and no secret value reaches artifacts.
    """
    segments = path.split("/")
    result: list[str] = []
    prev_was_secret_keyword = False
    for seg in segments:
        if not seg:
            result.append(seg)
            prev_was_secret_keyword = False
            continue
        if (
            prev_was_secret_keyword
            or _UUID_SEGMENT_RE.match(seg)
            or _HEX_SEGMENT_RE.match(seg)
            or _B64URL_SEGMENT_RE.match(seg)
            or _SECRET_PREFIXED_SEGMENT_RE.match(seg)
        ):
            result.append(_OPAQUE_SEGMENT)
            prev_was_secret_keyword = False
            continue
        if seg.lower() in _SECRET_PATH_KEYWORDS:
            prev_was_secret_keyword = True
        else:
            prev_was_secret_keyword = False
        result.append(seg)
    return "/".join(result)


def normalize_url(url: str) -> str:
    """Normalize a URL for deterministic comparison.

    - Raises ValueError when scheme or hostname is missing.
    - Raises ValueError when the URL contains userinfo (user:password@host)
      — userinfo is treated as secret material and rejected fail-closed.
    - Drops the fragment.
    - Sorts query parameter NAMES (values are dropped — they may carry
      tokens or secrets).
    - Replaces secret-looking path segments (reset tokens, session IDs,
      long hex/base64 segments, segments after secret keywords) with the
      fixed ``:opaque`` marker.
    - Preserves path, netloc, and scheme lower-cased.

    Args:
        url: Raw URL string.

    Returns:
        Normalized URL string.

    Raises:
        ValueError: If scheme or hostname is missing/malformed, or if the
            URL carries userinfo (credential material).
    """
    raw = str(url or "").strip()
    if not raw:
        raise ValueError("URL is empty")
    parsed = urlparse(raw)
    if not parsed.scheme or not _URL_SCHEME_RE.match(parsed.scheme):
        raise ValueError("URL missing valid scheme")
    if not parsed.hostname:
        raise ValueError("URL missing hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL carries userinfo (credentials) — rejected")

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = _sanitize_path_segments(parsed.path or "/")

    query_names = sorted({k for k in parse_qs(parsed.query).keys() if k})
    query_part = "&".join(query_names) if query_names else ""

    normalized = f"{scheme}://{netloc}{path}"
    if query_part:
        normalized += f"?{query_part}"
    return normalized


def _looks_like_auth_header_key(key: str) -> bool:
    return key.lower().replace(" ", "_").replace("-", "_") in _AUTH_HEADER_KEYS_LOWER


def _looks_like_cookie_key(key: str) -> bool:
    return key.lower().replace(" ", "_").replace("-", "_") in _COOKIE_KEYS_LOWER


def _looks_like_token_key(key: str) -> bool:
    return key.lower().replace(" ", "_").replace("-", "_") in _TOKEN_KEYS_LOWER


def _split_auth_flags(auth_context: Any) -> Tuple[bool, bool]:
    """Convert a raw auth context dict into safe booleans.

    Secret VALUES are discarded at this boundary. Only two booleans survive:
    has_auth_header (authorization / api-key style credentials) and
    has_cookie (cookie / set-cookie style credentials).

    Args:
        auth_context: Raw auth context dict (e.g. from Caido) or None.

    Returns:
        Tuple (has_auth_header, has_cookie).
    """
    if not isinstance(auth_context, dict):
        return (False, False)
    has_auth_header = False
    has_cookie = False
    for key in auth_context.keys():
        if _looks_like_auth_header_key(key) or _looks_like_token_key(key):
            has_auth_header = True
        if _looks_like_cookie_key(key):
            has_cookie = True
    return (has_auth_header, has_cookie)


def _split_actor_evidence(auth_context: Any) -> Tuple[bool, bool]:
    """Derive safe multi-actor booleans from auth context keys.

    Secret values are NEVER inspected — only key names are matched
    against safe patterns.

    Returns:
        Tuple (has_second_actor_evidence, has_admin_evidence).
    """
    if not isinstance(auth_context, dict):
        return (False, False)
    has_second = False
    has_admin = False
    for key in auth_context.keys():
        kl = key.lower().replace(" ", "_").replace("-", "_")
        if any(
            p in kl for p in (
                "authb", "actor_b", "user_b", "account_b",
                "second_actor", "second_user", "secondary",
            )
        ):
            has_second = True
        if "admin" in kl:
            has_admin = True
    return (has_second, has_admin)


def _extract_param_names(params: Any) -> Tuple[str, ...]:
    """Extract sorted parameter names from a signal's params list.

    Values are discarded (they may contain secrets). Names are de-duplicated
    and sorted for deterministic output.
    """
    names: set[str] = set()
    if not isinstance(params, list):
        return ()
    for p in params:
        if isinstance(p, dict):
            name = str(p.get("name", "") or "").strip()
            if name:
                names.add(name)
    return tuple(sorted(names))


def _extract_param_locations(params: Any) -> Tuple[str, ...]:
    """Extract sorted parameter locations (query/form/...) from a signal.

    SGK-2026-0421: ``location == "form"`` marks form-derived parameters
    produced by the recon pipeline (``_endpoint_signals[*].params[*]``).
    Values are never inspected — only the safe ``location`` key.
    """
    locations: set[str] = set()
    if not isinstance(params, list):
        return ()
    for p in params:
        if isinstance(p, dict):
            loc = str(p.get("location", "") or "").strip().lower()
            if loc:
                locations.add(loc)
    return tuple(sorted(locations))


def _canonical_observation_payload(
    url: str,
    method: str,
    entity_type: str,
    primary_label: str,
    param_names: Tuple[str, ...],
    param_locations: Tuple[str, ...],
    source_kind: ObservationSourceKind,
    has_auth_header: bool,
    has_cookie: bool,
    candidate_labels: Tuple[str, ...],
    has_second_actor_evidence: bool = False,
    has_admin_evidence: bool = False,
) -> Dict[str, Any]:
    """Deterministic payload for the observation ID.

    Excludes: signal_id (per-run UUID), created_at (current time), raw
    secret values, and any provenance. Order is fixed by canonical JSON.
    """
    return {
        "url": url,
        "method": method,
        "entity_type": entity_type,
        "primary_label": primary_label,
        "param_names": list(param_names),
        "param_locations": list(param_locations),
        "source_kind": source_kind.value,
        "has_auth_header": has_auth_header,
        "has_cookie": has_cookie,
        "candidate_labels": list(candidate_labels),
        "has_second_actor_evidence": has_second_actor_evidence,
        "has_admin_evidence": has_admin_evidence,
    }


@dataclass(frozen=True)
class Observation:
    """Typed, deterministic observation — the ONLY form passed to the generator.

    No secret values, no per-run UUIDs, no timestamps are present.
    """

    observation_id: str
    url: str
    method: str
    entity_type: str
    primary_label: str
    param_names: Tuple[str, ...] = ()
    param_locations: Tuple[str, ...] = ()
    source_kind: ObservationSourceKind = ObservationSourceKind.RECON_SIGNAL_BUNDLE
    has_auth_header: bool = False
    has_cookie: bool = False
    candidate_labels: Tuple[str, ...] = ()
    freshness_days: int = 0
    freshness_basis: str = ""  # SGK-2026-0421: e.g. "recon_artifact" (no wall-clock in IDs)
    has_second_actor_evidence: bool = False
    has_admin_evidence: bool = False

    @property
    def has_form_params(self) -> bool:
        """True when any param came from an HTML form (location == "form").

        SGK-2026-0421: form provenance is derived from the existing signal
        bundle (recon pipeline ``_endpoint_signals[*].params[*].location``)
        — no new crawl or communication is performed.
        """
        return "form" in self.param_locations

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "url": self.url,
            "method": self.method,
            "entity_type": self.entity_type,
            "primary_label": self.primary_label,
            "param_names": list(self.param_names),
            "param_locations": list(self.param_locations),
            "source_kind": self.source_kind.value,
            "has_auth_header": self.has_auth_header,
            "has_cookie": self.has_cookie,
            "candidate_labels": list(self.candidate_labels),
            "freshness_days": self.freshness_days,
            "freshness_basis": self.freshness_basis,
            "has_second_actor_evidence": self.has_second_actor_evidence,
            "has_admin_evidence": self.has_admin_evidence,
        }


@dataclass
class AdapterSkipRecord:
    """A signal that was skipped during adaptation, with a deterministic reason."""

    reason: str
    detail: str = ""


@dataclass
class AdapterResult:
    """Result of adapting a signal bundle."""

    observations: List[Observation] = field(default_factory=list)
    skipped: List[AdapterSkipRecord] = field(default_factory=list)

    @property
    def has_observations(self) -> bool:
        return bool(self.observations)


class ObservationAdapter:
    """Adapts raw recon signals into typed Observations at the VDP boundary."""

    def __init__(self, source_kind: ObservationSourceKind = ObservationSourceKind.RECON_SIGNAL_BUNDLE):
        self._source_kind = source_kind

    def adapt_signal_bundle(self, signal_bundle: Any) -> AdapterResult:
        """Adapt a full ``_signal_bundle`` dict (SGK-2026-0261 format).

        Args:
            signal_bundle: The recon ``_signal_bundle`` dict containing
                ``_endpoint_signals`` (list of endpoint/param signal dicts).

        Returns:
            AdapterResult with typed Observations and skip records.
        """
        result = AdapterResult()
        if not isinstance(signal_bundle, dict):
            result.skipped.append(AdapterSkipRecord("not_a_dict", str(type(signal_bundle).__name__)))
            return result

        endpoint_signals = signal_bundle.get("_endpoint_signals")
        if not isinstance(endpoint_signals, list):
            result.skipped.append(AdapterSkipRecord("missing_endpoint_signals"))
            return result

        for i, signal in enumerate(endpoint_signals):
            try:
                observation = self.adapt_endpoint_signal(signal)
            except (ValueError, TypeError) as exc:
                result.skipped.append(AdapterSkipRecord("invalid_signal", str(exc)))
                continue
            if observation is not None:
                result.observations.append(observation)
        return result

    def adapt_endpoint_signal(self, signal: Any) -> Optional[Observation]:
        """Adapt a single endpoint/param signal dict into an Observation.

        Returns None when the signal has no usable URL (e.g. param signals
        inheriting from a broken endpoint). Raises ValueError/TypeError for
        structurally invalid input.
        """
        if not isinstance(signal, dict):
            raise TypeError(f"signal must be a dict, got {type(signal).__name__}")

        raw_url = str(signal.get("url", "") or "").strip()
        if not raw_url:
            return None
        url = normalize_url(raw_url)

        method = str(signal.get("method", "") or "GET").strip().upper() or "GET"
        entity_type = str(signal.get("entity_type", "") or "").strip()
        primary_label = str(signal.get("primary_label", "") or "").strip()

        has_auth_header, has_cookie = _split_auth_flags(signal.get("auth_context"))
        has_second, has_admin = _split_actor_evidence(signal.get("auth_context"))
        param_names = _extract_param_names(signal.get("params"))
        param_locations = _extract_param_locations(signal.get("params"))
        source_kind = (
            ObservationSourceKind.FORM
            if "form" in param_locations
            else self._source_kind
        )

        labels = signal.get("candidate_labels")
        candidate_labels = tuple(
            sorted(str(l) for l in (labels or []) if str(l).strip())
        )

        payload = _canonical_observation_payload(
            url=url,
            method=method,
            entity_type=entity_type,
            primary_label=primary_label,
            param_names=param_names,
            param_locations=param_locations,
            source_kind=source_kind,
            has_auth_header=has_auth_header,
            has_cookie=has_cookie,
            candidate_labels=candidate_labels,
            has_second_actor_evidence=has_second,
            has_admin_evidence=has_admin,
        )
        observation_id = deterministic_id("obs", payload)

        return Observation(
            observation_id=observation_id,
            url=url,
            method=method,
            entity_type=entity_type,
            primary_label=primary_label,
            param_names=param_names,
            param_locations=param_locations,
            source_kind=source_kind,
            has_auth_header=has_auth_header,
            has_cookie=has_cookie,
            candidate_labels=candidate_labels,
            freshness_basis="recon_artifact",
            has_second_actor_evidence=has_second,
            has_admin_evidence=has_admin,
        )
