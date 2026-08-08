#!/usr/bin/env python3
"""SGK-2026-0433 — sealed auth-setup provisioning (A/B register/login ONLY).

Pre-run provisioning phase for the sealed disposable target. Creates the two
VDP comparison accounts (A and B) so the m3a run itself stays 100% GET-only:
auth-setup is the ONLY state-changing traffic in the whole harness, and it is
strictly limited to register + login POSTs for accounts A and B against the
sealed local target.

Isolation contract
------------------
- FAIL-CLOSED GUARD: ``AuthSetupGuard`` is the single outbound choke point.
  Its allowlist is built EXCLUSIVELY from ``auth_setup_config.json`` — exactly
  register A / register B / login A / login B. Any request with a different
  method, path, or body shape raises ``AuthSetupRejected`` BEFORE the
  transport is invoked. Nothing else can ever be sent.
- SECRETS: account ids and secrets come from the environment when provided
  (VDP_ACCOUNT_A_ID / VDP_ACCOUNT_A_SECRET / VDP_ACCOUNT_B_ID /
  VDP_ACCOUNT_B_SECRET) or are generated via the config id_factory. Partial
  pairs (id without secret, or vice versa) fail closed. The SECRET consumed
  by the engine is the session token from the login response (Bearer), not
  the account password. Values are written ONLY to the --out env file
  (chmod 600, atomic replace) and are never echoed: log output references
  sha256 digests only, and error messages never include response bodies.
- NO REDIRECTS: the default transport never follows a 3xx response (a
  307/308 would re-send the POST body — the credentials — to an
  unvalidated Location) and verifies the response URL equals the requested
  URL (belt and braces).
- STDLIB ONLY: urllib.request transport; no third-party dependencies.

Usage
-----
    python3 auth_setup.py --config auth_setup_config.json \
        --out <session_env_path> --target http://localhost:3000 \
        [--env-file <user_env>]

Exits non-zero on any failure (the harness must abort before the run).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets as _secrets
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

SCHEMA_VERSION = 1
ACCOUNTS = ("a", "b")
ENV_ID = {"a": "VDP_ACCOUNT_A_ID", "b": "VDP_ACCOUNT_B_ID"}
ENV_SECRET = {"a": "VDP_ACCOUNT_A_SECRET", "b": "VDP_ACCOUNT_B_SECRET"}
ENV_KEYS = (
    ENV_ID["a"],
    ENV_SECRET["a"],
    ENV_ID["b"],
    ENV_SECRET["b"],
)
SESSION_ENV_KEYS = (
    ("VDP_ACCOUNT_A_ID", "a", "id"),
    ("VDP_ACCOUNT_A_SECRET", "a", "token"),
    ("VDP_ACCOUNT_B_ID", "b", "id"),
    ("VDP_ACCOUNT_B_SECRET", "b", "token"),
)
REQUIRED_SECTIONS = ("register", "login", "token_extraction", "token_scheme", "id_factory")
DEFAULT_TIMEOUT = 15.0


class AuthSetupError(Exception):
    """Provisioning failure (transport, unexpected status, bad response)."""


class AuthSetupRejected(Exception):
    """Fail-closed guard rejection: request not in the A/B register/login allowlist."""


class ConfigSchemaError(Exception):
    """Malformed or unsafe provisioning config."""


# --- redaction helpers (values may only ever leave via digests) -----------------


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _emit(message: str) -> None:
    """Log a diagnostic line. Callers must NEVER pass credential/token values."""
    sys.stderr.write(f"auth-setup: {message}\n")
    sys.stderr.flush()


# --- config loading + schema validation ------------------------------------------


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return validate_config(data)


def validate_config(cfg: Any) -> dict:
    """Small schema check: required sections, POST-only methods, int statuses.

    Returns a normalized copy of the config (defaults filled in).
    """
    if not isinstance(cfg, dict):
        raise ConfigSchemaError("config must be a JSON object")
    missing = sorted(set(REQUIRED_SECTIONS) - set(cfg))
    if missing:
        raise ConfigSchemaError(f"missing required keys: {missing}")
    if cfg.get("schema_version") != SCHEMA_VERSION:
        raise ConfigSchemaError(
            f"unsupported schema_version {cfg.get('schema_version')!r} (expected {SCHEMA_VERSION})"
        )

    register = _validate_endpoint_block(cfg, "register", require_already_exists=True)
    login = _validate_endpoint_block(cfg, "login", require_already_exists=False)

    token_extraction = cfg.get("token_extraction")
    if not isinstance(token_extraction, dict):
        raise ConfigSchemaError("token_extraction must be an object")
    json_path = token_extraction.get("json_path")
    if not isinstance(json_path, str) or not json_path.strip():
        raise ConfigSchemaError("token_extraction.json_path must be a non-empty string")

    if cfg.get("token_scheme") != "bearer":
        raise ConfigSchemaError(
            f"token_scheme must be 'bearer', got {cfg.get('token_scheme')!r}"
        )

    id_factory = cfg.get("id_factory")
    if not isinstance(id_factory, dict):
        raise ConfigSchemaError("id_factory must be an object")
    pattern = id_factory.get("account_id_pattern")
    if (
        not isinstance(pattern, str)
        or "{account}" not in pattern
        or "{suffix}" not in pattern
    ):
        raise ConfigSchemaError(
            "id_factory.account_id_pattern must be a string containing "
            "'{account}' and '{suffix}' placeholders"
        )
    for key, minimum in (("suffix_length", 8), ("secret_length", 8)):
        length = id_factory.get(key)
        if not isinstance(length, int) or isinstance(length, bool) or length < minimum:
            raise ConfigSchemaError(f"id_factory.{key} must be an int >= {minimum}")
    for key in ("suffix_charset", "secret_charset"):
        charset = id_factory.get(key)
        if not isinstance(charset, str) or not charset:
            raise ConfigSchemaError(f"id_factory.{key} must be a non-empty string")

    normalized = dict(cfg)
    normalized["register"] = register
    normalized["login"] = login
    normalized["token_extraction"] = {"json_path": json_path.strip()}
    normalized["token_scheme"] = "bearer"
    normalized["id_factory"] = dict(id_factory)
    return normalized


def _validate_endpoint_block(cfg: Mapping[str, Any], name: str, require_already_exists: bool) -> dict:
    block = cfg.get(name)
    if not isinstance(block, dict):
        raise ConfigSchemaError(f"{name} must be an object")
    if block.get("method") != "POST":
        raise ConfigSchemaError(f"{name}.method must be 'POST', got {block.get('method')!r}")
    path = block.get("path")
    if not isinstance(path, str) or not path.startswith("/"):
        raise ConfigSchemaError(f"{name}.path must be an absolute path string")

    body_fields = block.get("body_fields")
    if not isinstance(body_fields, dict):
        raise ConfigSchemaError(f"{name}.body_fields must be an object")
    for role in ("account_id", "secret"):
        field = body_fields.get(role)
        if not isinstance(field, str) or not field:
            raise ConfigSchemaError(f"{name}.body_fields.{role} must be a non-empty string")
    if len(set(body_fields.values())) != len(body_fields):
        raise ConfigSchemaError(f"{name}.body_fields must map to distinct field names")

    for key in ("success_statuses",):
        statuses = block.get(key)
        if (
            not isinstance(statuses, list)
            or not statuses
            or not all(isinstance(s, int) and not isinstance(s, bool) for s in statuses)
        ):
            raise ConfigSchemaError(f"{name}.{key} must be a non-empty list of ints")
    if require_already_exists:
        statuses = block.get("already_exists_statuses")
        if (
            not isinstance(statuses, list)
            or not statuses
            or not all(isinstance(s, int) and not isinstance(s, bool) for s in statuses)
        ):
            raise ConfigSchemaError(f"{name}.already_exists_statuses must be a non-empty list of ints")

    normalized = dict(block)
    normalized["allowed"] = bool(block.get("allowed", True))
    normalized["body_fields"] = {"account_id": body_fields["account_id"], "secret": body_fields["secret"]}
    return normalized


# --- transport -------------------------------------------------------------------


class _Resp:
    """Transport result: HTTP status + decoded text body."""

    __slots__ = ("status", "text")

    def __init__(self, status: int, text: str):
        self.status = status
        self.text = text


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Fail-closed: never follow a 3xx redirect.

    A 307/308 would re-send the POST body (the account credentials) to the
    Location URL, which has never passed allowlist validation. ANY 3xx raises
    AuthSetupError instead of following.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuthSetupError(
            f"redirect not allowed (status {code}) — refusing to follow {newurl!r}"
        )


_OPENER = urllib.request.build_opener(_NoRedirectHandler())


def _urllib_transport(req: Mapping[str, Any]) -> _Resp:
    request = urllib.request.Request(
        req["url"],
        data=req["body"],
        headers=dict(req["headers"]),
        method=req["method"],
    )
    try:
        with _OPENER.open(request, timeout=req["timeout"]) as resp:
            if resp.geturl() != req["url"]:
                # Belt and braces: the response must come from the exact URL
                # the guard allowlisted (no redirects, no rewrites).
                raise AuthSetupError(
                    f"response url mismatch: got {resp.geturl()!r} expected {req['url']!r}"
                )
            return _Resp(resp.status, resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        # Non-2xx is a normal provisioning outcome (e.g. login denied), not a
        # transport failure. The body is kept only for status handling.
        return _Resp(exc.code, exc.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise AuthSetupError(f"transport error: {exc}") from exc


def _normalize_path(path: str) -> str:
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path
    while len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


# --- fail-closed guard -------------------------------------------------------------


class AuthSetupGuard:
    """Fail-closed outbound choke point: ONLY the config's A/B register/login.

    The allowlist is built exclusively from the config: per account (a, b) and
    per kind (register when ``register.allowed``, login always). Every request
    must match one allowlisted spec exactly — method POST, normalized path
    equal to the config path, body keys exactly the configured field names,
    non-empty string values. Any deviation raises :class:`AuthSetupRejected`
    before the transport is invoked.

    ``transport`` is injectable for tests (callable receiving a request dict
    with keys method/url/headers/body/timeout and returning an object with
    ``status`` and ``text``). The default is the real urllib sender.
    """

    def __init__(
        self,
        cfg: Mapping[str, Any],
        base_url: str,
        transport: Optional[Callable[[Mapping[str, Any]], Any]] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self._transport: Callable[[Mapping[str, Any]], Any] = (
            transport if transport is not None else _urllib_transport
        )
        self._base_url = base_url.rstrip("/")
        self._timeout = float(timeout)
        self._specs: Dict[Tuple[str, str], Dict[str, Any]] = {}
        register = cfg["register"]
        login = cfg["login"]
        for account in ACCOUNTS:
            if register["allowed"]:
                self._specs[(account, "register")] = {
                    "account": account,
                    "kind": "register",
                    "method": "POST",
                    "path": _normalize_path(register["path"]),
                    "body_fields": frozenset(register["body_fields"].values()),
                }
            self._specs[(account, "login")] = {
                "account": account,
                "kind": "login",
                "method": "POST",
                "path": _normalize_path(login["path"]),
                "body_fields": frozenset(login["body_fields"].values()),
            }

    @property
    def allowlisted_specs(self) -> List[Dict[str, Any]]:
        return [dict(spec) for spec in self._specs.values()]

    def request(
        self,
        account: str,
        kind: str,
        method: str,
        path: str,
        body: Mapping[str, Any],
    ) -> Any:
        spec = self._specs.get((account, kind))
        if spec is None:
            raise AuthSetupRejected(
                f"request not allowlisted: account={account!r} kind={kind!r}"
            )
        if method != spec["method"]:
            raise AuthSetupRejected(
                f"method {method!r} not allowed for {account}/{kind} "
                f"(allowlist: {spec['method']})"
            )
        if _normalize_path(path) != spec["path"]:
            raise AuthSetupRejected(
                f"path {path!r} not allowed for {account}/{kind} "
                f"(allowlist: {spec['path']})"
            )
        if not isinstance(body, Mapping):
            raise AuthSetupRejected("body must be a JSON object")
        body_keys = frozenset(body)
        if body_keys != spec["body_fields"]:
            missing = sorted(spec["body_fields"] - body_keys)
            extra = sorted(body_keys - spec["body_fields"])
            raise AuthSetupRejected(
                f"body fields mismatch for {account}/{kind}: missing={missing} extra={extra}"
            )
        for key, value in body.items():
            if not isinstance(value, str) or not value:
                raise AuthSetupRejected(
                    f"body field {key!r} must be a non-empty string"
                )
        req = {
            "method": "POST",
            "url": f"{self._base_url}{spec['path']}",
            "headers": {
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            "body": json.dumps(dict(body), sort_keys=True).encode("utf-8"),
            "timeout": self._timeout,
        }
        return self._transport(req)


# --- provisioning ----------------------------------------------------------------


def generate_account_identity(cfg: Mapping[str, Any], account: str) -> Tuple[str, str]:
    """Generate (account_id, account_secret) from the config id_factory."""
    factory = cfg["id_factory"]
    suffix = "".join(
        _secrets.choice(factory["suffix_charset"]) for _ in range(factory["suffix_length"])
    )
    secret = "".join(
        _secrets.choice(factory["secret_charset"]) for _ in range(factory["secret_length"])
    )
    account_id = factory["account_id_pattern"].format(account=account, suffix=suffix)
    return account_id, secret


def _dot_get(payload: Mapping[str, Any], json_path: str, account: str) -> Any:
    current: Any = payload
    for part in json_path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            raise AuthSetupError(
                f"login response for account {account} missing token path {json_path!r}"
            )
        current = current[part]
    return current


def _login(
    cfg: Mapping[str, Any],
    guard: AuthSetupGuard,
    account: str,
    account_id: str,
    secret: str,
) -> Optional[str]:
    """Returns the session token on success, None when the server denies login.

    Raises AuthSetupError on transport errors or a malformed success response.
    Error messages never contain the response body or any credential values.
    """
    body = {
        cfg["login"]["body_fields"]["account_id"]: account_id,
        cfg["login"]["body_fields"]["secret"]: secret,
    }
    resp = guard.request(account, "login", "POST", cfg["login"]["path"], body)
    if resp.status not in cfg["login"]["success_statuses"]:
        return None
    try:
        payload = json.loads(resp.text)
    except (TypeError, ValueError) as exc:
        raise AuthSetupError(
            f"login response for account {account} was not JSON (status {resp.status})"
        ) from exc
    token = _dot_get(payload, cfg["token_extraction"]["json_path"], account)
    if not isinstance(token, str) or not token:
        raise AuthSetupError(
            f"login response for account {account} carried no token at "
            f"{cfg['token_extraction']['json_path']!r}"
        )
    return token


def _register(
    cfg: Mapping[str, Any],
    guard: AuthSetupGuard,
    account: str,
    account_id: str,
    secret: str,
) -> None:
    """Register the account. Already-exists is accepted (login still runs).

    Raises AuthSetupError on any other unexpected status. The message carries
    the status + a fixed label only — response bodies are NEVER included
    (they could echo credential fragments).
    """
    body = {
        cfg["register"]["body_fields"]["account_id"]: account_id,
        cfg["register"]["body_fields"]["secret"]: secret,
    }
    resp = guard.request(account, "register", "POST", cfg["register"]["path"], body)
    if resp.status in cfg["register"]["success_statuses"]:
        return
    if resp.status in cfg["register"]["already_exists_statuses"]:
        _emit(f"account {account}: register already-exists (status {resp.status})")
        return
    raise AuthSetupError(
        f"register for account {account} unexpected status {resp.status} "
        f"(response body omitted)"
    )


def provision_account(
    cfg: Mapping[str, Any],
    guard: AuthSetupGuard,
    account: str,
    env: Mapping[str, str],
) -> Tuple[str, str]:
    """Provision one account; returns (account_id, session_token).

    - credentials provided via env: try login; on denial fall back to
      register (unless disallowed by config), then login again.
    - no credentials: generate id+secret via the config id_factory, register
      (already-exists accepted), then login.
    - partial pairs (id without secret, or vice versa) fail closed.
    """
    provided_id = str(env.get(ENV_ID[account], "") or "").strip()
    provided_secret = str(env.get(ENV_SECRET[account], "") or "").strip()
    if bool(provided_id) != bool(provided_secret):
        raise AuthSetupError(
            f"account {account}: partial credentials — provide both "
            f"{ENV_ID[account]} and {ENV_SECRET[account]} (or neither)"
        )
    if provided_id and provided_secret:
        token = _login(cfg, guard, account, provided_id, provided_secret)
        if token is not None:
            _emit(
                f"account {account}: login ok (provided credentials, "
                f"id {_digest(provided_id)})"
            )
            return provided_id, token
        _emit(f"account {account}: login denied — falling back to register")
        if not cfg["register"]["allowed"]:
            raise AuthSetupError(
                f"account {account}: login denied and register is disallowed by config"
            )
        _register(cfg, guard, account, provided_id, provided_secret)
        token = _login(cfg, guard, account, provided_id, provided_secret)
        if token is None:
            raise AuthSetupError(
                f"account {account}: register ok but login still denied"
            )
        _emit(
            f"account {account}: registered + logged in (provided credentials, "
            f"id {_digest(provided_id)})"
        )
        return provided_id, token

    account_id, secret = generate_account_identity(cfg, account)
    _register(cfg, guard, account, account_id, secret)
    token = _login(cfg, guard, account, account_id, secret)
    if token is None:
        raise AuthSetupError(
            f"account {account}: login denied after register (generated credentials)"
        )
    _emit(f"account {account}: registered + logged in (generated, id {_digest(account_id)})")
    return account_id, token


def provision_accounts(
    cfg: Mapping[str, Any],
    guard: AuthSetupGuard,
    env: Mapping[str, str],
) -> Dict[str, Dict[str, str]]:
    records: Dict[str, Dict[str, str]] = {}
    for account in ACCOUNTS:
        account_id, token = provision_account(cfg, guard, account, env)
        records[account] = {"id": account_id, "token": token}
    return records


# --- session store ---------------------------------------------------------------


def write_session_env(path: str, records: Mapping[str, Mapping[str, str]]) -> None:
    """Write the 4 VDP_ACCOUNT_* env lines to a 0600 file. Values never echoed.

    Atomic: content is written to a temp file in the same directory, chmod
    0600, then os.replace()d over the target — a reader never sees a partial
    file, and no readable intermediate state is left behind.
    """
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"{key}={records[account][field]}"
        for key, account, field in SESSION_ENV_KEYS
    ]
    fd, tmp_path = tempfile.mkstemp(dir=str(out_path.parent), prefix=".session_env.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, str(out_path))
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def load_env_file(path: str) -> Dict[str, str]:
    """Parse a KEY=VALUE env file (fallback source for the VDP_ACCOUNT_* vars)."""
    env: Dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, sep, value = line.partition("=")
            if sep and key.strip():
                env[key.strip()] = value
    return env


# --- CLI -------------------------------------------------------------------------


def main(
    argv: Optional[Sequence[str]] = None,
    transport: Optional[Callable[[Mapping[str, Any]], Any]] = None,
) -> int:
    parser = argparse.ArgumentParser(
        prog="auth_setup.py",
        description=(
            "Sealed auth-setup: provision VDP accounts A/B "
            "(register/login only, fail-closed)."
        ),
    )
    parser.add_argument("--config", required=True, help="path to auth_setup_config.json")
    parser.add_argument("--out", required=True, help="path for the 0600 session env file")
    parser.add_argument(
        "--target",
        required=True,
        help="base URL of the sealed target (e.g. http://localhost:3000)",
    )
    parser.add_argument(
        "--env-file",
        default=None,
        help="optional KEY=VALUE env file (fallback source for VDP_ACCOUNT_* vars)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="per-request timeout in seconds",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        cfg = load_config(args.config)
    except (OSError, ValueError, ConfigSchemaError) as exc:
        _emit(f"FAILED: config error: {exc}")
        return 2

    guard = AuthSetupGuard(cfg, base_url=args.target, transport=transport, timeout=args.timeout)
    env: Dict[str, str] = load_env_file(args.env_file) if args.env_file else {}
    # Process environment wins over the env file (docker --env-file semantics).
    env.update({key: value for key, value in os.environ.items() if key in ENV_KEYS})

    try:
        records = provision_accounts(cfg, guard, env)
    except AuthSetupRejected as exc:
        _emit(f"FAILED: guard rejected a request (fail-closed, nothing sent): {exc}")
        return 1
    except AuthSetupError as exc:
        _emit(f"FAILED: {exc}")
        return 1

    try:
        write_session_env(args.out, records)
    except OSError as exc:
        _emit(f"FAILED: could not write session env file: {exc}")
        return 1
    _emit(f"accounts A/B provisioned; session env written to {args.out} (0600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
