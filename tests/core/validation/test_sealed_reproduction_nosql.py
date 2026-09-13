"""SGK-2026-0487: NoSQL 演算子注入の封印再現（専用 JSON POST 再送パス）を検証。
演算子ペイロードを 1 回再送し 2xx+データで再び成功すれば matched。fail-closed
（client なし・スコープ外・演算子なし記述子）。製品非依存（合成データ）。"""

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import SealedReproductionChecker

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-repro-nosql-test",
    in_scope_domains=["target.example"],
)
_URL = "https://target.example/api/validate-coupon"
_COUPON = '{"coupon_code":"TRAC075","amount":"75"}'


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


def _nosql_finding(url: str = _URL) -> Finding:
    return Finding(
        target_url=url,
        vuln_type=VulnType.NOSQL_INJECTION,
        severity=Severity.HIGH,
        title="NoSQL operator injection",
        description="operator vs literal differential",
        source_agent="SmartNoSQLHunter",
        evidence=Evidence(
            request_method="POST",
            request_url=url,
            request_headers={"Content-Type": "application/json",
                             "Authorization": "Bearer test-token"},
            request_body='{"coupon_code": {"$ne": null}}',
            response_status=200,
            response_body=_COUPON,
        ),
        additional_info={
            "nosql_evidence": {
                "request_url": url,
                "field": "coupon_code",
                "operator_payload": '{"coupon_code": {"$ne": null}}',
                "operator_status": 200,
                "operator_served_body": _COUPON,
                "control_value": "shigoku_nosql_x",
                "control_status": 500,
                "control_served_body": "{}",
            },
            "nosql_replay": {
                "method": "POST",
                "url": url,
                "body": {"coupon_code": {"$ne": None}},
                "field": "coupon_code",
            },
        },
    )


def test_matched_when_operator_succeeds_again():
    client = FakeNetworkClient(FakeResponse(200, _COUPON))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_nosql_finding().to_dict())
    assert out.status == "matched"
    assert "nosql_operator_injection" in out.reason


def test_mismatched_when_operator_no_data():
    client = FakeNetworkClient(FakeResponse(500, "{}"))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_nosql_finding().to_dict())
    assert out.status == "mismatched"


def test_not_run_without_client():
    chk = SealedReproductionChecker(network_client=None, scope_definition=TARGET_SCOPE)
    out = chk.check(_nosql_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_out_of_scope():
    client = FakeNetworkClient(FakeResponse(200, _COUPON))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_nosql_finding(url="https://evil.example/api/validate-coupon").to_dict())
    assert out.status == "not_run"


def test_not_run_replay_without_operator():
    client = FakeNetworkClient(FakeResponse(200, _COUPON))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    f = _nosql_finding().to_dict()
    f["additional_info"]["nosql_replay"]["body"] = {"coupon_code": "literal"}
    out = chk.check(f)
    assert out.status == "not_run"
