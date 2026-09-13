"""SGK-2026-0485: SSTI の封印再現（専用 GET/POST 再送パス）を検証する。
確定済み算術テンプレートペイロードを 1 回再送し、応答本文に期待積 expected
が再出現すれば matched。fail-closed（client なし・スコープ外・記述子不正）。
製品非依存（合成データ）。"""

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import SealedReproductionChecker

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-repro-ssti-test",
    in_scope_domains=["target.example"],
)
_URL = "https://target.example/x?q=%7B%7B7%2A7%7D%7Ddeadbeef"
_EXPECTED = "49deadbeef"
_LIVE_WITH_PRODUCT = f'<p> https://target.example/x?q={_EXPECTED} </p>'
_LIVE_NO_PRODUCT = '<p> https://target.example/x?q={{7*7}}deadbeef </p>'  # 未評価


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


def _ssti_finding(url: str = _URL) -> Finding:
    served = f'<p> {url}&r={_EXPECTED} </p>'
    return Finding(
        target_url=url,
        vuln_type=VulnType.SSTI,
        severity=Severity.CRITICAL,
        title="SSTI (jinja2) in parameter 'q'",
        description="template evaluated",
        source_agent="SmartSSTIHunter",
        evidence=Evidence(
            request_method="GET",
            request_url=url,
            response_status=404,
            response_body=served,
        ),
        additional_info={
            "ssti_evidence": {
                "parameter": "q",
                "engine": "jinja2",
                "payload": "{{7*7}}deadbeef",
                "expected": _EXPECTED,
                "request_method": "GET",
                "request_url": url,
                "response_status": 404,
                "served_body": served,
            },
            "ssti_replay": {
                "method": "GET",
                "url": url,
                "param": "q",
                "payload": "{{7*7}}deadbeef",
                "body": "",
                "expected": _EXPECTED,
            },
        },
    )


def test_matched_when_product_reobserved():
    client = FakeNetworkClient(FakeResponse(404, _LIVE_WITH_PRODUCT))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_ssti_finding().to_dict())
    assert out.status == "matched"
    assert "template_evaluated" in out.reason


def test_mismatched_when_product_absent():
    client = FakeNetworkClient(FakeResponse(404, _LIVE_NO_PRODUCT))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_ssti_finding().to_dict())
    assert out.status == "mismatched"


def test_not_run_without_client():
    chk = SealedReproductionChecker(network_client=None, scope_definition=TARGET_SCOPE)
    out = chk.check(_ssti_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_out_of_scope():
    client = FakeNetworkClient(FakeResponse(404, _LIVE_WITH_PRODUCT))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_ssti_finding(url="https://evil.example/x?q=%7B%7B7%2A7%7D%7Ddeadbeef").to_dict())
    assert out.status == "not_run"


def test_not_run_bad_replay_descriptor():
    client = FakeNetworkClient(FakeResponse(404, _LIVE_WITH_PRODUCT))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    f = _ssti_finding().to_dict()
    f["additional_info"]["ssti_replay"] = {"method": "GET", "url": _URL}  # expected 欠落
    out = chk.check(f)
    assert out.status == "not_run"
