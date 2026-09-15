"""SGK-2026-0503: HTTP リクエストスマグリング（CL/TE desync）の封印再現（fresh トークンで
desync 要求を再送し、別 victim 応答に混入＋clean に非出現）を検証する。製品非依存・実ネット
依存なし（注入 raw トランスポートで CL.TE desync を模擬）。"""

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import SealedReproductionChecker

_SCOPE = ScopeDefinition(program_name="sealed-smuggle-test", in_scope_domains=["target.example"])


class _FakeDesyncTransport:
    def __init__(self, vulnerable=True):
        self.leftover = b""
        self.vulnerable = vulnerable

    def send(self, host, port, data, timeout):
        head = data.split(b"\r\n\r\n", 1)[0]
        reqline = head.split(b"\r\n", 1)[0]
        is_chunked = b"transfer-encoding: chunked" in head.lower()
        if is_chunked and self.vulnerable:
            body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
            if b"0\r\n\r\n" in body:
                self.leftover = body.split(b"0\r\n\r\n", 1)[1]
            served = reqline
        else:
            served = self.leftover + reqline
            self.leftover = b""
        payload = b"REQLINE=" + served
        return b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(payload), payload)


def _finding():
    return Finding(
        target_url="http://target.example:8080/",
        vuln_type=VulnType.HTTP_REQUEST_SMUGGLING,
        severity=Severity.HIGH,
        title="HTTP Request Smuggling (CLTE)",
        description="desync",
        source_agent="SmartRequestSmugglingHunter",
        evidence=Evidence(
            request_method="POST", request_url="http://target.example:8080/",
            request_headers={}, request_body="POST / ...", response_status=200,
            response_body="REQLINE=GET /smugABC HTTP/1.1",
        ),
        additional_info={
            "smuggling_evidence": {
                "request_url": "http://target.example:8080/",
                "variant": "clte",
                "token": "smugABC",
                "clean_victim_body": "REQLINE=GET / HTTP/1.1",
                "poisoned_victim_body": "REQLINE=GET /smugABC HTTP/1.1",
            },
            "smuggling_replay": {
                "host": "target.example", "port": 8080, "path": "/", "variant": "clte",
            },
            "poc_request": "POST /", "poc_response": "correlation",
        },
    )


def _checker(transport, scope=_SCOPE):
    chk = SealedReproductionChecker(network_client=None, scope_definition=scope, timeout_seconds=5)
    if transport is not None:
        chk._raw_send = transport.send
    return chk


def test_matched_when_poisoning_reproduces():
    out = _checker(_FakeDesyncTransport(vulnerable=True)).check(_finding().to_dict())
    assert out.status == "matched"
    assert "http_request_smuggling_confirmed" in out.reason


def test_mismatched_when_not_vulnerable():
    out = _checker(_FakeDesyncTransport(vulnerable=False)).check(_finding().to_dict())
    assert out.status == "mismatched"


def test_not_run_when_out_of_scope():
    other = ScopeDefinition(program_name="other", in_scope_domains=["example.org"])
    out = _checker(_FakeDesyncTransport(vulnerable=True), scope=other).check(_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_when_replay_descriptor_missing():
    f = _finding().to_dict()
    del f["additional_info"]["smuggling_replay"]
    out = _checker(_FakeDesyncTransport(vulnerable=True)).check(f)
    assert out.status == "not_run"
