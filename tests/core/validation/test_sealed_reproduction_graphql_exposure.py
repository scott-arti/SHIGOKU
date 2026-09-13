"""SGK-2026-0484: GraphQL 認可欠陥の封印再現（専用 POST(JSON) 再送パス）を
検証する。トリガクエリを 1 回再送し応答 JSON に機微フィールドキーが再出現
すれば matched。fail-closed（client なし・スコープ外・記述子不正）。
製品非依存（合成データ・実秘密なし）。"""

import json

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import SealedReproductionChecker

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-repro-graphql-exposure-test",
    in_scope_domains=["target.example"],
)
_ENDPOINT = "https://target.example/graphql"
_QUERY = "{users{id username password}}"
# ライブ再取得で返る本文（値 redact 済み・実秘密なし）。
_LIVE_WITH_SECRET = (
    '{"data": {"users": [{"id": "1", "username": "admin", '
    '"password": "fakeval_live"}]}}'
)
_LIVE_NO_SECRET = '{"data": {"users": [{"id": "1", "username": "admin"}]}}'


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


def _graphql_finding(url: str = _ENDPOINT) -> Finding:
    served = (
        '{"data": {"users": [{"id": "1", "username": "admin", '
        '"password": "<redacted len=6>"}]}}'
    )
    return Finding(
        target_url=url,
        vuln_type=VulnType.GRAPHQL_AUTHZ_EXPOSURE,
        severity=Severity.CRITICAL,
        title="GraphQL Broken Authorization",
        description="unauth sensitive data",
        source_agent="SmartGraphQLHunter",
        evidence=Evidence(
            request_method="POST",
            request_url=url,
            request_headers={"Content-Type": "application/json"},
            request_body=json.dumps({"query": _QUERY}),
            response_status=200,
            response_body=served,
        ),
        additional_info={
            "graphql_exposure_evidence": {
                "endpoint": url,
                "query": _QUERY,
                "response_status": 200,
                "matched_fields": ["password"],
                "served_body": served,
            },
            "graphql_bola_replay": {
                "method": "POST",
                "url": url,
                "body": {"query": _QUERY},
                "reflect_fields": ["password"],
            },
        },
    )


def test_matched_when_sensitive_field_reobserved():
    client = FakeNetworkClient(FakeResponse(200, _LIVE_WITH_SECRET))
    chk = SealedReproductionChecker(
        network_client=client, scope_definition=TARGET_SCOPE
    )
    out = chk.check(_graphql_finding().to_dict())
    assert out.status == "matched"
    assert "graphql_sensitive_exposed" in out.reason


def test_mismatched_when_sensitive_field_absent():
    client = FakeNetworkClient(FakeResponse(200, _LIVE_NO_SECRET))
    chk = SealedReproductionChecker(
        network_client=client, scope_definition=TARGET_SCOPE
    )
    out = chk.check(_graphql_finding().to_dict())
    assert out.status == "mismatched"


def test_not_run_without_client():
    chk = SealedReproductionChecker(
        network_client=None, scope_definition=TARGET_SCOPE
    )
    out = chk.check(_graphql_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_out_of_scope():
    client = FakeNetworkClient(FakeResponse(200, _LIVE_WITH_SECRET))
    chk = SealedReproductionChecker(
        network_client=client, scope_definition=TARGET_SCOPE
    )
    out = chk.check(_graphql_finding(url="https://evil.example/graphql").to_dict())
    assert out.status == "not_run"


def test_not_run_bad_replay_descriptor():
    client = FakeNetworkClient(FakeResponse(200, _LIVE_WITH_SECRET))
    chk = SealedReproductionChecker(
        network_client=client, scope_definition=TARGET_SCOPE
    )
    f = _graphql_finding().to_dict()
    f["additional_info"]["graphql_bola_replay"] = {"method": "GET", "url": _ENDPOINT}
    out = chk.check(f)
    assert out.status == "not_run"
