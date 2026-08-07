"""
Lane O-1 disposable read-only fixture target — SGK-2026-0423.

Stdlib-only ``http.server.ThreadingHTTPServer`` used as the LOCAL,
DISPOSABLE verification target for the VDP M3a read-only path. It serves
GENERIC endpoints only (no product names, no real-world payloads, no
vulnerabilities) and NEVER accepts state-changing methods:

- GET /                            -> 200 HTML index with plain-text + <a>
                                      links to every endpoint below.
- GET /readonly-ok                 -> 200 {"status":"ok","data":"public-test-data"}
- GET /items/<id>                  -> 200 {"id":..,"owner":"public","data":"public-test-data"}
                                      (id must match [a-z0-9-]+; else 400)
- GET /rate-limited                -> 429
- GET /server-error                -> 500
- GET /slow                        -> sleeps 30s then 200 (clients time out first)
- GET /redirect-out-of-scope       -> 302 Location: http://127.0.0.1:9/out-of-scope
                                      (a localhost URL OUTSIDE the allowed scope;
                                       redirects are never followed by the client)
- GET /search?q=<param>            -> 200 echo of the query param
- ANY other method (POST/PUT/PATCH/DELETE) on ANY path -> 405 (never executed)

Access log: every request appends a ``method path status`` line to the file
named by the ACCESS_LOG_PATH environment variable (flushed per line). The
access log is the POST=0 proof used by the runtime driver and the smoke
tests. When ACCESS_LOG_PATH is unset/empty, logging is skipped.

Run: ``python fixture_target.py [--host 0.0.0.0] [--port 8000]``
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ACCESS_LOG_PATH = os.environ.get("ACCESS_LOG_PATH", "")
_ITEM_ID_RE = re.compile(r"^[a-z0-9-]+$")
_SLOW_DELAY_SECONDS = 30


def _append_access_log(method: str, path: str, status: int) -> None:
    """Append ``method path status`` to the access log, flushed per line."""
    if not ACCESS_LOG_PATH:
        return
    try:
        with open(ACCESS_LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(f"{method} {path} {status}\n")
            handle.flush()
    except OSError:
        # Logging must never take the fixture down (it is a side channel).
        pass


class FixtureHandler(BaseHTTPRequestHandler):
    """Read-only endpoint dispatcher (GET only; everything else is 405)."""

    # ------------------------------------------------------------------
    # transport plumbing
    # ------------------------------------------------------------------

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
    # GET routes
    # ------------------------------------------------------------------

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        status: int = 200
        try:
            if path == "/":
                status = self._route_index()
            elif path == "/readonly-ok":
                status = self._route_readonly_ok()
            elif path.startswith("/items/"):
                status = self._route_item(path)
            elif path == "/rate-limited":
                status = self._route_rate_limited()
            elif path == "/server-error":
                status = self._route_server_error()
            elif path == "/slow":
                status = self._route_slow()
            elif path == "/redirect-out-of-scope":
                status = self._route_redirect_out_of_scope()
            elif path == "/search":
                status = self._route_search(parsed)
            else:
                self._send_json(404, {"error": "not_found"})
                status = 404
        except (BrokenPipeError, ConnectionResetError):
            return  # client went away; nothing to record
        self._record("GET", status)

    def _route_index(self) -> int:
        links = [
            ("/readonly-ok", "readonly-ok"),
            ("/items/sample-1", "items/sample-1"),
            ("/rate-limited", "rate-limited"),
            ("/server-error", "server-error"),
            ("/slow", "slow"),
            ("/redirect-out-of-scope", "redirect-out-of-scope"),
            ("/search?q=probe", "search?q=probe"),
        ]
        plain = "\n".join(f"{label}: {href}" for href, label in links)
        anchors = "\n".join(f'<a href="{href}">{label}</a>' for href, label in links)
        html = (
            "<!doctype html><html><head><title>fixture index</title></head>"
            f"<body><h1>fixture index</h1><pre>{plain}</pre>{anchors}</body></html>"
        )
        self._send(200, html, content_type="text/html; charset=utf-8")
        return 200

    def _route_readonly_ok(self) -> int:
        self._send_json(200, {"status": "ok", "data": "public-test-data"})
        return 200

    def _route_item(self, path: str) -> int:
        item_id = path[len("/items/"):]
        if not _ITEM_ID_RE.match(item_id):
            self._send_json(400, {"error": "invalid_item_id"})
            return 400
        self._send_json(200, {
            "id": item_id,
            "owner": "public",
            "data": "public-test-data",
        })
        return 200

    def _route_rate_limited(self) -> int:
        self._send_json(429, {"error": "rate_limited"})
        return 429

    def _route_server_error(self) -> int:
        self._send_json(500, {"error": "internal_error"})
        return 500

    def _route_slow(self) -> int:
        time.sleep(_SLOW_DELAY_SECONDS)
        self._send_json(200, {"status": "ok", "data": "slow-but-fine"})
        return 200

    def _route_redirect_out_of_scope(self) -> int:
        # Localhost target OUTSIDE the allowed scope: recorded, never
        # followed (clients pass allow_redirects=False).
        self._send(302, "", extra_headers={"Location": "http://127.0.0.1:9/out-of-scope"})
        return 302

    def _route_search(self, parsed) -> int:
        query = parse_qs(parsed.query)
        param = query.get("q", [""])[0]
        self._send_json(200, {"echo": param})
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
    parser = argparse.ArgumentParser(description="Disposable read-only fixture target")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), FixtureHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
