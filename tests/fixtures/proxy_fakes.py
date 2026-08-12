"""Product-independent fake proxy servers for the preflight forwarding check.

Used by tests to simulate:

- ``DummyProxyHandler`` — a canned dummy proxy that answers every request
  with the same short body (the SGK-2026-0445 failure mode: identity looks
  right but nothing is forwarded), and
- ``ForwardingProxyHandler`` — a forwarding proxy whose responses depend on
  the request path.

stdlib only — no external dependencies, no product tokens.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

# Short canned body used by the dummy proxy (kept well under
# _CANNED_BODY_MAX_BYTES so the forwarding check flags it).
_CANNED_BODY = b'{"probe":"canned-body"}'


def _extract_path(requestline: str) -> str:
    """Extract the path from an HTTP request line.

    Handles both origin-form (``GET /path HTTP/1.1``) and absolute-form
    (``GET http://host:port/path HTTP/1.1``) request targets — aiohttp sends
    plain-HTTP proxied requests to the proxy in absolute form.
    """
    parts = requestline.split(" ", 2)
    if len(parts) < 2:
        return "/"
    target = parts[1]
    if target.startswith("http://") or target.startswith("https://"):
        return urlsplit(target).path or "/"
    return target.split("?", 1)[0]


class _BaseFakeProxyHandler(BaseHTTPRequestHandler):
    """Shared plumbing: silence per-request log noise and default to close."""

    # HTTP/1.0 → connection close after each response (no keep-alive
    # bookkeeping needed in the fixture).
    protocol_version = "HTTP/1.0"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass


class DummyProxyHandler(_BaseFakeProxyHandler):
    """Answer every GET with the same short canned body (status 200)."""

    def do_GET(self) -> None:
        body = _CANNED_BODY
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ForwardingProxyHandler(_BaseFakeProxyHandler):
    """Simulate a forwarding proxy: responses depend on the request path.

    - ``/`` → 200 with an HTML-ish body
    - ``/__shigoku_fwd_probe_...`` (or any other path) → 404 with a
      different body
    """

    _ROOT_BODY = b"<html><body>forwarded root page</body></html>"
    _MISS_BODY = b'{"error":"no such resource"}'

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header(
            "Content-Type", "text/html" if status == 200 else "application/json"
        )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = _extract_path(self.requestline)
        if path == "/":
            self._respond(200, self._ROOT_BODY)
        else:
            self._respond(404, self._MISS_BODY)


class _FakeProxyServer:
    """Context manager running a ThreadingHTTPServer on a dynamic port.

    Usage::

        with start_dummy_proxy() as (server, url):
            ...
    """

    def __init__(self, handler_cls: type) -> None:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )

    def __enter__(self) -> tuple[ThreadingHTTPServer, str]:
        self._thread.start()
        host, port = self._server.server_address[:2]
        return self._server, f"http://{host}:{port}"

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        return False


def start_dummy_proxy() -> _FakeProxyServer:
    """Start a canned dummy proxy; yields ``(server, url)``."""
    return _FakeProxyServer(DummyProxyHandler)


def start_forwarding_proxy() -> _FakeProxyServer:
    """Start a path-dependent forwarding proxy; yields ``(server, url)``."""
    return _FakeProxyServer(ForwardingProxyHandler)
