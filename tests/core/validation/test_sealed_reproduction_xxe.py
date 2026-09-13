"""SGK-2026-0486: XXE の封印再現（専用 POST 再送パス）を検証する。確定済みの
外部実体ペイロードを 1 回再送し、応答本文にシステムファイル署名が再出現すれば
matched。fail-closed（client なし・スコープ外・外部実体なし記述子）。"""

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import SealedReproductionChecker

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-repro-xxe-test",
    in_scope_domains=["target.example"],
)
_URL = "https://target.example/home"
_PAYLOAD = (
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
    '"file:///etc/passwd">]><items>&x;</items>'
)
_LIVE_WITH_PASSWD = '<items>root:x:0:0:root:/root:/bin/ash</items>'
_LIVE_NO_PASSWD = '<items>&x;</items>'


class FakeResponse:
    def __init__(self, status: int = 200, body: str = ""):
        self.status = status
        self.body = body


class FakeNetworkClient:
    def __init__(self, response=None):
        self.response = response if response is not None else FakeResponse(200, "")
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url})
        return self.response


def _xxe_finding(url: str = _URL) -> Finding:
    served = '<items>root:x:0:0:root:/root:/bin/ash</items>'
    return Finding(
        target_url=url,
        vuln_type=VulnType.XXE,
        severity=Severity.CRITICAL,
        title="XXE local file disclosure",
        description="external entity resolved",
        source_agent="SmartXXEHunter",
        evidence=Evidence(
            request_method="POST",
            request_url=url,
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body="xxe=...",
            response_status=200,
            response_body=served,
        ),
        additional_info={
            "xxe_evidence": {
                "request_method": "POST",
                "request_url": url,
                "param": "xxe",
                "payload": _PAYLOAD,
                "content_type": "application/x-www-form-urlencoded",
                "file_uri": "file:///etc/passwd",
                "response_status": 200,
                "served_body": served,
            },
            "xxe_replay": {
                "method": "POST",
                "url": url,
                "param": "xxe",
                "payload": _PAYLOAD,
                "content_type": "application/x-www-form-urlencoded",
            },
        },
    )


def test_matched_when_file_signature_reobserved():
    client = FakeNetworkClient(FakeResponse(200, _LIVE_WITH_PASSWD))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_xxe_finding().to_dict())
    assert out.status == "matched"
    assert "xxe_file_read" in out.reason


def test_mismatched_when_signature_absent():
    client = FakeNetworkClient(FakeResponse(200, _LIVE_NO_PASSWD))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_xxe_finding().to_dict())
    assert out.status == "mismatched"


def test_not_run_without_client():
    chk = SealedReproductionChecker(network_client=None, scope_definition=TARGET_SCOPE)
    out = chk.check(_xxe_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_out_of_scope():
    client = FakeNetworkClient(FakeResponse(200, _LIVE_WITH_PASSWD))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_xxe_finding(url="https://evil.example/home").to_dict())
    assert out.status == "not_run"


def test_not_run_payload_without_external_entity():
    client = FakeNetworkClient(FakeResponse(200, _LIVE_WITH_PASSWD))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    f = _xxe_finding().to_dict()
    f["additional_info"]["xxe_replay"]["payload"] = "<items>no entity</items>"
    out = chk.check(f)
    assert out.status == "not_run"
