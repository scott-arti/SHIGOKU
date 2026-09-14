"""SGK-2026-0490: JWT RS256→HS256 キー混同（vuln_type=jwt_rs256_hs256）が既存の
jwt_forgery_accepted 再現パス（_check_jwt_forgery_replay）を共有して matched することを検証。
forged_token を再送し forged_identity 再出現で matched。製品非依存（合成データ）。"""

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import SealedReproductionChecker

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-jwt-keyconf-test",
    in_scope_domains=["target.example"],
)
_URL = "https://target.example/whoami"
_FORGED_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoic2hpZ29rdV9qd3Rmb3JnZV94In19.sig"
_MARK = "shigoku_jwtforge_x"
_FORGED_BODY = f'{{"user":{{"email":"{_MARK}"}}}}'


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self.body = body
        self.headers = {}


class FakeJWTNetClient:
    """forged_token を Authorization に持つ再送に対してのみ forged_identity を反映。"""

    def __init__(self, reflect=True):
        self.reflect = reflect
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url})
        auth = str((kwargs.get("headers") or {}).get("Authorization") or "")
        if self.reflect and _FORGED_TOKEN in auth:
            return FakeResponse(200, _FORGED_BODY)
        return FakeResponse(200, '{"user":{}}')


def _finding():
    return Finding(
        target_url=_URL,
        vuln_type=VulnType.JWT_RS256_HS256,
        severity=Severity.CRITICAL,
        title="JWT RS256->HS256 key confusion",
        description="3-way differential",
        source_agent="SmartJWTForgeryHunter",
        evidence=Evidence(
            request_method="GET",
            request_url=_URL,
            request_headers={"Authorization": f"Bearer {_FORGED_TOKEN}"},
            request_body="",
            response_status=200,
            response_body=_FORGED_BODY,
        ),
        additional_info={
            "jwt_alg": "hs256",
            "jwt_key_confusion": True,
            "unauth_baseline_absent": True,
            "forged_identity": _MARK,
            "forged_identity_reflected": True,
            "forged_token": _FORGED_TOKEN,
            "jwt_forgery_evidence": {
                "observe_url": _URL, "claim": "data.email", "forged_status": 200,
                "forged_served_body": _FORGED_BODY, "control_served_body": '{"user":{}}',
                "wrong_secret_served_body": '{"user":{}}',
            },
        },
    )


def test_matched_via_shared_jwt_forgery_path():
    client = FakeJWTNetClient(reflect=True)
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_finding().to_dict())
    assert out.status == "matched"
    assert "jwt_forgery_accepted" in out.reason


def test_mismatched_when_forged_identity_absent():
    client = FakeJWTNetClient(reflect=False)
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_finding().to_dict())
    assert out.status == "mismatched"


def test_not_run_when_no_client():
    chk = SealedReproductionChecker(network_client=None, scope_definition=TARGET_SCOPE)
    out = chk.check(_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_when_out_of_scope():
    client = FakeJWTNetClient(reflect=True)
    other = ScopeDefinition(program_name="other", in_scope_domains=["example.org"])
    chk = SealedReproductionChecker(network_client=client, scope_definition=other)
    out = chk.check(_finding().to_dict())
    assert out.status == "not_run"
