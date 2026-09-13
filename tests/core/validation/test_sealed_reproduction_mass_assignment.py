"""SGK-2026-0488: Mass Assignment の封印再現（専用 JSON POST 再送パス）を検証。
予約済み injection ボディ（fresh 値）を 1 回再送し、応答の同名フィールドが再び
攻撃者値になれば matched。fail-closed（client なし・スコープ外・記述子不正・非2xx）。
製品非依存（合成データ）。"""

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import SealedReproductionChecker

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-repro-ma-test",
    in_scope_domains=["target.example"],
)
_URL = "https://target.example/api/Users"


class FakeResponse:
    def __init__(self, status: int = 201, body: str = ""):
        self.status = status
        self.body = body


class FakeNetworkClient:
    def __init__(self, response=None):
        self.response = response if response is not None else FakeResponse(201, "")
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url})
        return self.response


def _ma_finding(url: str = _URL) -> Finding:
    return Finding(
        target_url=url,
        vuln_type=VulnType.MASS_ASSIGNMENT,
        severity=Severity.HIGH,
        title="Mass assignment: role elevation",
        description="privileged field differential",
        source_agent="SmartMassAssignmentHunter",
        evidence=Evidence(
            request_method="POST",
            request_url=url,
            request_headers={"Content-Type": "application/json",
                             "Authorization": "Bearer test-token"},
            request_body='{"email":"i@target.example","role":"admin"}',
            response_status=201,
            response_body='{"data":{"role":"admin"}}',
        ),
        additional_info={
            "mass_assignment_evidence": {
                "request_url": url,
                "field": "role",
                "injected_value": "admin",
                "injected_status": 201,
                "injected_field_value": "admin",
                "control_field_value": "customer",
            },
            "mass_assignment_replay": {
                "method": "POST",
                "url": url,
                "body": {"email": "rep@target.example", "role": "admin"},
                "field": "role",
                "expected_value": "admin",
            },
        },
    )


def test_matched_when_field_is_attacker_value_again():
    client = FakeNetworkClient(FakeResponse(201, '{"data":{"id":9,"role":"admin"}}'))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_ma_finding().to_dict())
    assert out.status == "matched"
    assert "privileged_field_assigned" in out.reason


def test_mismatched_when_field_is_default():
    client = FakeNetworkClient(FakeResponse(201, '{"data":{"role":"customer"}}'))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_ma_finding().to_dict())
    assert out.status == "mismatched"


def test_mismatched_when_non_2xx():
    client = FakeNetworkClient(FakeResponse(409, '{"error":"exists"}'))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_ma_finding().to_dict())
    assert out.status == "mismatched"


def test_not_run_when_no_client():
    chk = SealedReproductionChecker(network_client=None, scope_definition=TARGET_SCOPE)
    out = chk.check(_ma_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_when_out_of_scope():
    client = FakeNetworkClient(FakeResponse(201, '{"data":{"role":"admin"}}'))
    other_scope = ScopeDefinition(program_name="other", in_scope_domains=["example.org"])
    chk = SealedReproductionChecker(network_client=client, scope_definition=other_scope)
    out = chk.check(_ma_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_when_replay_descriptor_missing_expected_value():
    f = _ma_finding().to_dict()
    f["additional_info"]["mass_assignment_replay"]["expected_value"] = ""
    client = FakeNetworkClient(FakeResponse(201, '{"data":{"role":"admin"}}'))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(f)
    assert out.status == "not_run"


def test_not_run_when_replay_body_not_dict():
    f = _ma_finding().to_dict()
    f["additional_info"]["mass_assignment_replay"]["body"] = "not-a-dict"
    client = FakeNetworkClient(FakeResponse(201, '{"data":{"role":"admin"}}'))
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(f)
    assert out.status == "not_run"
