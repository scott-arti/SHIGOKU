"""
SGK-2026-0423 Lane P-2 — random/opaque isolated holdout fixture target.

Stdlib-only ``http.server.ThreadingHTTPServer`` serving a RANDOM, OPAQUE
route space generated at startup (15-hex segments — the fixture file itself
contains NO fixed routes, so it is safe to copy into images):

- 1 cross-account record route: the owner (acct-a) reads the record; the
  second account (acct-b) CAN read the same A-owned record (granted).
- 1 denied record route: acct-b gets 403.
- 1 public-data route: any principal gets 200 public data.

Route count 3 is deliberate: the production hypothesis generator caps
same-target (capability, host) hypotheses at 3 (diversity budget), so
exactly these three become hypotheses deterministically; and the M0 gate's
exact-set contract allows ONE confirmed verdict per session (its evaluated
evidence must equal the session evidence set). The 2-granted-route grant
case is covered by the P-1 executor unit suite
(``tests/unit/engine/test_vdp_cross_account.py``).

Account credentials acct-a/acct-b are random secrets; both Basic auth
(user:secret) and Bearer tokens are honored (the runtime's comparison send
uses ``Authorization: Bearer <secret>`` — the executor's P-1 send shape).

Contract:
- GET /                     -> 200 HTML index with GENERIC anchors
                              ("resource-1".."resource-3", href=opaque path)
                              — no capability or route-name hints.
- GET <opaque-public>       -> 200 {"data": "public-<n>"} (any principal).
- GET <opaque-record>[/<id>]-> unauth 401; acct-a -> 200
                              {"id":..,"owner":"acct-a","sensitive":"<random>"};
                              acct-b -> 200 same body (granted) or 403.
- POST/PUT/PATCH/DELETE     -> 405 (never executed).
- Access log: ``method path status`` lines appended to ACCESS_LOG_PATH.

Startup writes the HOLD OUT to SECRETS_OUT_PATH (host private dir, never
the repo)::

    {"routes": [{"opaque": "/<15-hex>", "kind": "record"|"public",
                 "owner": "acct-a", "b_can_read": bool,
                 "capability": "object_read_write_delete"}, ...],
     "accounts": {"acct-a": <secret>, "acct-b": <secret>}}

Run: ``python holdout_fixture_target.py [--host 0.0.0.0] [--port 8000]``
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets as _secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ACCESS_LOG_PATH = os.environ.get("ACCESS_LOG_PATH", "")
SECRETS_OUT_PATH = os.environ.get("SECRETS_OUT_PATH", "")
_ROUTE_COUNT = 3
_ID_RE = re.compile(r"^[a-z0-9-]+$")


def _append_access_log(method: str, path: str, status: int) -> None:
    if not ACCESS_LOG_PATH:
        return
    try:
        with open(ACCESS_LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(f"{method} {path} {status}\n")
            handle.flush()
    except OSError:
        pass  # logging is a side channel; never take the fixture down


def generate_holdout() -> dict:
    """Generate the opaque routes + account secrets and persist the hold
    out to SECRETS_OUT_PATH (random at runtime — no fixed routes)."""
    routes = []
    kinds = [
        {"kind": "record", "b_can_read": True},
        {"kind": "record", "b_can_read": False},
        {"kind": "public", "b_can_read": False},
    ]
    for index, kind in enumerate(kinds, start=1):
        # Random 15-hex segments: opaque (random per startup, no fixed
        # routes) but deliberately SHORTER than the 16+ hex shape the
        # production observation adapter sanitizes as ``:opaque`` (secret-
        # shaped path segments are masked) — 15 hex chars keep the routes
        # distinguishable while carrying no secret-shaped token.
        routes.append({
            "opaque": f"/{_secrets.token_hex(8)[:15]}",
            "kind": kind["kind"],
            "owner": "acct-a" if kind["kind"] == "record" else "",
            "b_can_read": bool(kind["b_can_read"]),
            "capability": "object_read_write_delete",
            "n": index,
            # deterministic per-route sensitive value: the granted non-owner
            # must receive EXACTLY the same body as the owner (the A/B
            # comparison compares the two responses). NOT part of the hold
            # out (the hold out schema carries routes/accounts only).
            "sensitive": _secrets.token_hex(8) if kind["kind"] == "record" else "",
        })
    accounts = {
        "acct-a": _secrets.token_hex(16),
        "acct-b": _secrets.token_hex(16),
    }
    holdout = {"routes": routes, "accounts": accounts}
    if SECRETS_OUT_PATH:
        out = os.path.dirname(SECRETS_OUT_PATH)
        if out:
            os.makedirs(out, exist_ok=True)
        with open(SECRETS_OUT_PATH, "w", encoding="utf-8") as handle:
            json.dump(holdout, handle, indent=2, sort_keys=True)
    return holdout


def _resolve_account(auth_header: str, accounts: dict) -> str:
    """Resolve an account id from a Basic or Bearer Authorization header."""
    header = str(auth_header or "")
    if header.startswith("Bearer "):
        token = header[len("Bearer "):].strip()
        for account, secret in accounts.items():
            if token == secret:
                return account
        return ""
    if header.startswith("Basic "):
        try:
            decoded = base64.b64decode(header[len("Basic "):].strip()).decode(
                "utf-8", errors="replace"
            )
        except Exception:
            return ""
        user, _, password = decoded.partition(":")
        if password == accounts.get(user, ""):
            return user
        return ""
    return ""


class HoldoutHandler(BaseHTTPRequestHandler):
    """Opaque route dispatcher: the route table is generated at startup."""

    routes: list = []  # set by main() before serve_forever
    accounts: dict = {}

    def log_message(self, format, *args):  # silence default stderr logging
        pass

    def _send(self, status: int, body: str, content_type: str = "application/json",
              extra_headers: dict | None = None) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, status: int, data: dict) -> None:
        self._send(status, json.dumps(data, ensure_ascii=False))

    def _record(self, method: str, status: int) -> None:
        _append_access_log(method, self.path, status)

    # ------------------------------------------------------------------
    # GET dispatch (route table driven — no fixed route literals)
    # ------------------------------------------------------------------

    def do_GET(self) -> None:
        from urllib.parse import urlparse

        parsed = urlparse(self.path)
        path = parsed.path
        status = 200
        try:
            if path == "/":
                status = self._route_index()
            else:
                route = self._route_for(path)
                if route is None:
                    self._send_json(404, {"error": "not_found"})
                    status = 404
                elif route["kind"] == "public":
                    self._send_json(
                        200, {"data": f"public-{route['n']}"}
                    )
                else:
                    status = self._route_record(route, path)
        except (BrokenPipeError, ConnectionResetError):
            return  # client went away; nothing to record
        self._record("GET", status)

    def _route_for(self, path: str) -> dict | None:
        for route in self.routes:
            opaque = route["opaque"]
            if path == opaque or path.startswith(f"{opaque}/"):
                return route
        return None

    def _route_index(self) -> int:
        links = [
            (route["opaque"], f"resource-{index}")
            for index, route in enumerate(self.routes, start=1)
        ]
        plain = "\n".join(f"{label}: {href}" for href, label in links)
        anchors = "\n".join(f'<a href="{href}">{label}</a>' for href, label in links)
        html = (
            "<!doctype html><html><head><title>index</title></head>"
            f"<body><h1>index</h1><pre>{plain}</pre>{anchors}</body></html>"
        )
        self._send(200, html, content_type="text/html; charset=utf-8")
        return 200

    def _route_record(self, route: dict, path: str) -> int:
        account = _resolve_account(
            self.headers.get("Authorization", ""), self.accounts
        )
        if not account:
            self._send(
                401,
                '{"error": "unauthorized"}',
                extra_headers={"WWW-Authenticate": 'Basic realm="opaque"'},
            )
            return 401
        if account != route["owner"]:
            if not route["b_can_read"]:
                self._send_json(403, {"error": "forbidden"})
                return 403
            # granted: the non-owner receives the owner's record
        item_id = path[len(route["opaque"]):].strip("/") or "1"
        if not _ID_RE.match(item_id):
            self._send_json(400, {"error": "invalid_item_id"})
            return 400
        self._send_json(200, {
            "id": item_id,
            "owner": route["owner"],
            "sensitive": route["sensitive"],
        })
        return 200

    # ------------------------------------------------------------------
    # non-GET methods: ALWAYS 405, never executed
    # ------------------------------------------------------------------

    def do_POST(self) -> None:
        self._deny("POST")

    def do_PUT(self) -> None:
        self._deny("PUT")

    def do_PATCH(self) -> None:
        self._deny("PATCH")

    def do_DELETE(self) -> None:
        self._deny("DELETE")

    def _deny(self, method: str) -> None:
        self._send_json(405, {"error": "method_not_allowed"})
        self._record(method, 405)


def main() -> None:
    parser = argparse.ArgumentParser(description="Opaque holdout fixture target")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    holdout = generate_holdout()
    HoldoutHandler.routes = holdout["routes"]
    HoldoutHandler.accounts = holdout["accounts"]
    server = ThreadingHTTPServer((args.host, args.port), HoldoutHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
