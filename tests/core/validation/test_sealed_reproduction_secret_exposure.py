"""SGK-2026-0483: secret_exposed の封印再現（SealedReproductionChecker）。

取得元URL（evidence.request_url）への単一 GET 再読で、応答本文に資格情報代入
パターンが再出現すれば matched。非出現は mismatched。client None・スコープ外は
not_run（fail-closed）。ライブ再取得本文はここで照合するだけで永続しない。

製品非依存・合成 fixture のみ（再取得本文中の値は合成の偽値）。
"""
from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import SealedReproductionChecker

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-repro-secret-exposure-test",
    in_scope_domains=["target.example"],
)
_URL = "https://target.example/.env"
# 保存形（redact 済み・実秘密なし）。
_SERVED = "DB_USER=<redacted len=7>\nDB_PASSWORD=<redacted len=12>\n"


class FakeResponse:
    def __init__(self, status: int = 200, body: str = ""):
        self.status = status
        self.body = body


class FakeNetworkClient:
    def __init__(self, response=None, error=None):
        self.response = response if response is not None else FakeResponse(200, "")
        self.error = error
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url})
        if self.error is not None:
            raise self.error
        return self.response


def _secret_finding(url: str = _URL) -> Finding:
    return Finding(
        vuln_type=VulnType.SECRET_LEAK,
        severity=Severity.CRITICAL,
        title="Enumerated secret exposure",
        description="Credential-bearing file served at public URL",
        target_url=url,
        evidence=Evidence(
            request_method="GET",
            request_url=url,
            request_headers={},
            response_status=200,
            response_body=_SERVED,
        ),
        impact="公開URLで資格情報が配信されている。",
        reproduction_steps=["GET /.env", "応答本文に *PASSWORD= が含まれる"],
        additional_info={
            "secret_exposure_evidence": {
                "retrieved_url": url,
                "response_status": 200,
                "served_body": _SERVED,
                "matched_keys": ["DB_PASSWORD"],
            }
        },
    )


def _checker(client) -> SealedReproductionChecker:
    return SealedReproductionChecker(
        network_client=client, scope_definition=TARGET_SCOPE
    )


def test_matched_when_credential_reobserved():
    # ライブ再取得本文（合成の偽値）にキー側パターンが再出現 → matched。
    client = FakeNetworkClient(FakeResponse(200, "DB_PASSWORD=fakeval_live\nHOST=db\n"))
    outcome = _checker(client).check(_secret_finding())
    assert outcome.status == "matched"
    assert outcome.reason == "reproduction_marker_matched:secret_exposed"
    assert client.calls[0]["method"] == "GET"
    assert client.calls[0]["url"] == _URL


def test_mismatched_when_credential_absent():
    client = FakeNetworkClient(FakeResponse(200, "<html>not found</html>"))
    outcome = _checker(client).check(_secret_finding())
    assert outcome.status == "mismatched"


def test_not_run_without_client():
    outcome = _checker(None).check(_secret_finding())
    assert outcome.status == "not_run"


def test_not_run_out_of_scope():
    client = FakeNetworkClient(FakeResponse(200, "DB_PASSWORD=x"))
    outcome = _checker(client).check(
        _secret_finding(url="https://out-of-scope.example/.env")
    )
    assert outcome.status == "not_run"
    assert client.calls == []
