#!/usr/bin/env python3
"""SGK-2026-0427 — M5 audit egress allowlist proxy (harness tooling, stdlib only).

Multi-homed forward proxy used to give the isolated audit runner exactly one
path to the outside world, restricted to the approved LLM provider
destinations. Everything else is denied and logged.

- Listens on 0.0.0.0:3128 inside the internal audit network.
- ``ALLOW_DEST`` env: comma-separated ``host:port`` entries. A CONNECT (or
  absolute-form HTTP) request whose host equals an entry, or is a subdomain
  of it, is forwarded; anything else is denied and logged.
- JSON-lines access log written to stdout (captured by ``docker logs``) and
  to ``/var/log/m5proxy/access.log`` when that directory is mounted.
- TLS is tunneled untouched (no MITM, no secrets inspected).
"""
from __future__ import annotations

import json
import os
import socket
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit

LOG_DIR = "/var/log/m5proxy"
LOG_FILE = os.path.join(LOG_DIR, "access.log")


def _log(dst_path: str, entry: dict) -> None:
    line = json.dumps(entry, sort_keys=True)
    print(line, flush=True)
    try:
        with open(dst_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


class Allowlist:
    def __init__(self, raw: str) -> None:
        self.entries: list[tuple[str, int]] = []
        for item in (raw or "").split(","):
            item = item.strip()
            if not item:
                continue
            host, _, port = item.rpartition(":")
            if not host or not port.isdigit():
                raise ValueError(f"invalid ALLOW_DEST entry: {item!r}")
            self.entries.append((host.lower(), int(port)))

    def allows(self, host: str, port: int) -> bool:
        host = (host or "").lower().rstrip(".")
        for allowed_host, allowed_port in self.entries:
            if port != allowed_port:
                continue
            if host == allowed_host or host.endswith("." + allowed_host):
                return True
        return False


ALLOW = Allowlist(os.environ.get("ALLOW_DEST", ""))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # noqa: A002 — silence default logging
        pass

    def _decision(self, method: str, host: str, port: int) -> str:
        return "allow" if ALLOW.allows(host, port) else "deny"

    def _record(self, method: str, host: str, port: int, decision: str, detail: str = "") -> None:
        _log(
            LOG_FILE,
            {
                "ts": time.time(),
                "client": self.client_address[0] if self.client_address else "",
                "method": method,
                "host": host,
                "port": port,
                "decision": decision,
                "detail": detail,
            },
        )

    def do_CONNECT(self):  # noqa: N802 — HTTP method name
        host, _, port = self.path.partition(":")
        port = int(port or 443)
        if self._decision("CONNECT", host, port) != "allow":
            self._record("CONNECT", host, port, "deny")
            self.send_error(403, "destination not allowed")
            return
        self._record("CONNECT", host, port, "allow")
        try:
            upstream = socket.create_connection((host, port), timeout=30)
        except OSError as exc:
            self.send_error(502, f"upstream connect failed: {exc}")
            return
        self.send_response(200, "Connection established")
        self.end_headers()
        self._relay(upstream)

    def _relay(self, upstream: socket.socket) -> None:
        def pump(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    chunk = src.recv(65536)
                    if not chunk:
                        break
                    dst.sendall(chunk)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t = threading.Thread(target=pump, args=(upstream, self.connection), daemon=True)
        t.start()
        try:
            while True:
                chunk = self.connection.recv(65536)
                if not chunk:
                    break
                upstream.sendall(chunk)
        except OSError:
            pass
        finally:
            try:
                upstream.shutdown(socket.SHUT_WR)
                upstream.close()
            except OSError:
                pass
            t.join(timeout=2)

    def _absolute_form(self, method: str) -> None:
        split = urlsplit(self.path)
        host = split.hostname or ""
        port = split.port or (443 if split.scheme == "https" else 80)
        if self._decision(method, host, port) != "allow":
            self._record(method, host, port, "deny")
            self.send_error(403, "destination not allowed")
            return
        self._record(method, host, port, "allow")
        self.send_error(502, "plain http forwarding not needed; use CONNECT")

    do_GET = _absolute_form
    do_POST = _absolute_form
    do_HEAD = _absolute_form


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    os.makedirs(LOG_DIR, exist_ok=True)
    server = ThreadingTCPServer(("0.0.0.0", 3128), Handler)
    _log(LOG_FILE, {"ts": time.time(), "event": "proxy_start", "allowlist": ALLOW.entries})
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
