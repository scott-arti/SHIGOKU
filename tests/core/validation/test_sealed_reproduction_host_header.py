"""SGK-2026-0491: Host Header Injection の封印再現（注入ヘッダ付き GET 再送パス）を検証。
注入ヘッダを付けて 1 回再送し制限署名が 2xx 応答に再出現すれば matched。fail-closed
（client なし・スコープ外・記述子不正）。製品非依存（合成データ）。"""

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import SealedReproductionChecker

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-hhi-test",
    in_scope_domains=["target.example"],
)
_URL = "https://target.example/dashboard"
_SIG = "Mr Mark Oney"
_ADMIN = f"<td>{_SIG}</td><td>1000000</td>"


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self.body = body
        self.headers = {}


class FakeHHINetClient:
    """Host が localhost のときだけ署名入り body を返す。"""

    def __init__(self, reflect=True):
        self.reflect = reflect

    def request(self, method, url, **kwargs):
        host = str((kwargs.get("headers") or {}).get("Host") or "").lower()
        if self.reflect and host == "localhost":
            return FakeResponse(200, _ADMIN)
        return FakeResponse(302, "Redirecting...")


def _finding():
    return Finding(
        target_url=_URL,
        vuln_type=VulnType.HOST_HEADER_INJECTION,
        severity=Severity.HIGH,
        title="Host header injection auth bypass",
        description="differential",
        source_agent="SmartHostHeaderHunter",
        evidence=Evidence(
            request_method="GET",
            request_url=_URL,
            request_headers={"Host": "localhost"},
            request_body="",
            response_status=200,
            response_body=_ADMIN,
        ),
        additional_info={
            "host_header_evidence": {
                "request_url": _URL, "injected_header": "Host", "injected_host_value": "localhost",
                "control_host": "shigoku-control.example", "restricted_signature": _SIG,
                "injected_status": 200, "injected_served_body": _ADMIN,
                "control_served_body": "Redirecting...",
            },
            "host_header_replay": {
                "url": _URL, "header": "Host", "value": "localhost", "signature": _SIG,
            },
        },
    )


def test_matched_when_signature_reflected_again():
    client = FakeHHINetClient(reflect=True)
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_finding().to_dict())
    assert out.status == "matched"
    assert "host_header_auth_bypass" in out.reason


def test_mismatched_when_signature_absent():
    client = FakeHHINetClient(reflect=False)
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_finding().to_dict())
    assert out.status == "mismatched"


def test_not_run_when_no_client():
    chk = SealedReproductionChecker(network_client=None, scope_definition=TARGET_SCOPE)
    out = chk.check(_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_when_out_of_scope():
    client = FakeHHINetClient(reflect=True)
    other = ScopeDefinition(program_name="other", in_scope_domains=["example.org"])
    chk = SealedReproductionChecker(network_client=client, scope_definition=other)
    out = chk.check(_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_when_replay_descriptor_incomplete():
    f = _finding().to_dict()
    f["additional_info"]["host_header_replay"]["signature"] = ""
    client = FakeHHINetClient(reflect=True)
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(f)
    assert out.status == "not_run"
