"""
SealedReproductionChecker cors テスト — SGK-2026-0475 (A②)

cors_credentialed_reflection マーカーは「1 回の封印 GET で観測可能・ヘッダ
（ACAO/ACAC）経由・Origin 付き再送必須」として扱う（_HEADER_OBSERVABLE_MARKERS
に入れる・本文経路の _send_get は不変）。再送は元 Finding の test_origin を
Origin ヘッダに付けて行い、再送応答の ACAO が test_origin にホスト一致で
反映＋ACAC==true なら matched。

- (a) Origin 再送で ACAO 反映 + ACAC true → matched
- (b) 非反映 / ACAC 非真（応答あり）→ mismatched
- (c) client None → not_run
- (d) 既存 external_redirect / body マーカー経路の非回帰

PRODUCT-INDEPENDENT fixtures のみ（attacker.example / target.example /
trusted.example・汎用ダミー機微データ）。ネットワークなし（FakeNetworkClient）。
"""
import pytest

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import (
    SealedReproductionChecker,
)

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-cors-test",
    in_scope_domains=["target.example"],
)

_SQL_BODY = "SQL syntax error near '1' at line 1"

API_URL = "https://target.example/api/account"
TEST_ORIGIN = "https://attacker.example"
TRUSTED_ORIGIN = "https://trusted.example"
CREDENTIALED_BODY = (
    '{"session_token":"dummy-session-3f2a9c8e1b7d","user_email":"alice@example.test",'
    '"account_role":"admin","account_id":"acct_100042"}'
)

# external_redirect 非回帰確認用の URL / ホスト（SGK-2026-0471 形状）。
EXPLOIT_URL = (
    "https://target.example/redirect?url=https%3A%2F%2F"
    "shigoku-verify-abc.evil.com%2F"
)
ATTACKER_HOST = "shigoku-verify-abc.evil.com"
ATTACKER_LOCATION = f"http://{ATTACKER_HOST}/"


# ---------------------------------------------------------------------------
# Fixtures（既存 sealed/open_redirect テストのスタイルを踏襲）
# ---------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, status: int = 200, body: "str | bytes" = "", headers: "dict | None" = None):
        self.status = status
        self.body = body
        self.headers = headers or {}


class FakeNetworkClient:
    """Synchronous transport fake: records calls, returns a configurable
    response or raises a configurable error (mirrors NetworkResponse shape)."""

    def __init__(self, response: "FakeResponse | None" = None, error: "Exception | None" = None):
        self.response = response if response is not None else FakeResponse(200, "")
        self.error = error
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        if self.error is not None:
            raise self.error
        return self.response


def make_cors_finding(acao: str = TEST_ORIGIN, acac: str = "true") -> Finding:
    """SmartCORSHunter (B) が生成する Finding 形状（to_dict 経由で
    evaluate_payout_grade が cors_credentialed_reflection を返す）。"""
    return Finding(
        vuln_type=VulnType.CORS_MISCONFIGURATION,
        severity=Severity.HIGH,
        title="CORS Misconfiguration: origin_reflection_with_credentials",
        description=(
            f"Origin '{TEST_ORIGIN}' was reflected in Access-Control-Allow-Origin header. "
            "Type: origin_reflection_with_credentials."
        ),
        target_url=API_URL,
        evidence=Evidence(
            request_method="GET",
            request_url=API_URL,
            request_headers={"Origin": TEST_ORIGIN},
            response_status=200,
            response_headers={
                "Access-Control-Allow-Origin": acao,
                "Access-Control-Allow-Credentials": acac,
            },
            response_body=CREDENTIALED_BODY,
        ),
        reproduction_steps=[
            f"1. Send GET {API_URL} with header: Origin: {TEST_ORIGIN}",
            f"2. Observe response header: Access-Control-Allow-Origin: {acao}",
            "3. If Access-Control-Allow-Credentials: true, cross-origin requests "
            "with cookies are possible.",
        ],
        impact=(
            "An attacker can read sensitive cross-origin responses (tokens, PII) "
            "if the victim visits a malicious page while authenticated."
        ),
        additional_info={
            "test_origin": TEST_ORIGIN,
            "acao": acao,
            "acac": acac,
            "misconfiguration": "origin_reflection_with_credentials",
            "credentialed_body_excerpt": CREDENTIALED_BODY,
            "poc_request": f"GET {API_URL} HTTP/1.1\nOrigin: {TEST_ORIGIN}\n",
            "poc_response": (
                "HTTP/1.1 200 OK\n"
                f"Access-Control-Allow-Origin: {acao}\n"
                f"Access-Control-Allow-Credentials: {acac}\n"
            ),
        },
    )


def make_open_redirect_finding() -> Finding:
    """OpenRedirectSpecialist (B) が生成する Finding 形状（非回帰用）。"""
    return Finding(
        vuln_type=VulnType.OPEN_REDIRECT,
        severity=Severity.MEDIUM,
        title="Open Redirect in parameter 'url'",
        description="Attacker can redirect users to arbitrary external URLs.",
        target_url="https://target.example/",
        evidence=Evidence(
            request_method="GET",
            request_url=EXPLOIT_URL,
            response_status=302,
            response_headers={"Location": ATTACKER_LOCATION},
            response_body=f"Redirect location: {ATTACKER_LOCATION}",
        ),
        reproduction_steps=[
            f"GET {EXPLOIT_URL}",
            f"応答 302 / Location: {ATTACKER_LOCATION}",
            "ヘッドレスブラウザで上記URLを開き、攻撃者管理ホストへの遷移を確認",
        ],
        impact="認証済み利用者を攻撃者が管理する外部URLへ誘導可能。",
        additional_info={
            "parameter": "url",
            "payload": f"http://{ATTACKER_HOST}/",
            "payloads_used": [f"http://{ATTACKER_HOST}/"],
            "tested_params": ["url"],
            "redirect_to": ATTACKER_LOCATION,
            "injected_host": ATTACKER_HOST,
        },
    )


def make_sqli_finding() -> Finding:
    """既存 body マーカー種別の非回帰確認用。"""
    return Finding(
        vuln_type=VulnType.SQLI,
        severity=Severity.HIGH,
        title="SQL injection in item lookup",
        description="Generic SQLi finding.",
        target_url="https://target.example/",
        evidence=Evidence(
            request_method="GET",
            request_url="https://target.example/item?id=1",
            response_status=200,
            response_body=_SQL_BODY,
        ),
        reproduction_steps=["Send the probe request", "Observe the SQL error"],
        impact="Database error disclosure.",
    )


def make_checker(**kwargs) -> SealedReproductionChecker:
    kwargs.setdefault("scope_definition", TARGET_SCOPE)
    return SealedReproductionChecker(**kwargs)


def _cors_headers(acao: str = TEST_ORIGIN, acac: str = "true") -> dict:
    return {
        "Access-Control-Allow-Origin": acao,
        "Access-Control-Allow-Credentials": acac,
    }


# ---------------------------------------------------------------------------
# cors_credentialed_reflection replay path
# ---------------------------------------------------------------------------


class TestCorsReplay:
    def test_origin_replay_reflection_matched(self) -> None:
        """(a) Origin 付き再送で ACAO 反映 + ACAC true → matched。"""
        client = FakeNetworkClient(
            FakeResponse(200, body="unused", headers=_cors_headers())
        )
        checker = make_checker(network_client=client)
        outcome = checker.check(make_cors_finding())
        assert outcome.status == "matched"
        assert (
            outcome.reason
            == "reproduction_marker_matched:cors_credentialed_reflection"
        )
        assert client.calls[0]["method"] == "GET"
        assert client.calls[0]["url"] == API_URL
        kwargs = client.calls[0]["kwargs"]
        # 再送は test_origin を Origin ヘッダに付けて送られる
        assert kwargs["headers"]["Origin"] == TEST_ORIGIN
        assert kwargs["allow_redirects"] is False
        assert kwargs["use_cache"] is False
        assert kwargs["retries"] == 0

    def test_origin_replay_empty_body_still_matches(self) -> None:
        """CORS はヘッダ観測型: ボディが空でもヘッダが再現すれば matched。"""
        client = FakeNetworkClient(
            FakeResponse(200, body="", headers=_cors_headers())
        )
        checker = make_checker(network_client=client)
        outcome = checker.check(make_cors_finding())
        assert outcome.status == "matched"
        assert (
            outcome.reason
            == "reproduction_marker_matched:cors_credentialed_reflection"
        )

    def test_replay_host_port_variant_still_matches(self) -> None:
        """ホスト一致は hostname 比較（ポート差は許容）。"""
        client = FakeNetworkClient(
            FakeResponse(200, body="", headers=_cors_headers(acao=f"http://attacker.example:8080"))
        )
        checker = make_checker(network_client=client)
        outcome = checker.check(make_cors_finding())
        assert outcome.status == "matched"

    def test_replay_non_reflection_mismatched(self) -> None:
        """(b) 応答あり・ACAO 非反映（別ホスト固定）→ mismatched。"""
        client = FakeNetworkClient(
            FakeResponse(200, body="", headers=_cors_headers(acao=TRUSTED_ORIGIN))
        )
        checker = make_checker(network_client=client)
        outcome = checker.check(make_cors_finding())
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"

    def test_replay_wildcard_acao_mismatched(self) -> None:
        """応答の ACAO が "*"（テストオリジン非反映）→ mismatched。"""
        client = FakeNetworkClient(
            FakeResponse(200, body="", headers=_cors_headers(acao="*"))
        )
        checker = make_checker(network_client=client)
        outcome = checker.check(make_cors_finding())
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"

    def test_replay_acac_not_true_mismatched(self) -> None:
        """ACAO は反映するが ACAC != true（修正済み/別挙動）→ mismatched。"""
        client = FakeNetworkClient(
            FakeResponse(200, body="", headers=_cors_headers(acac="false"))
        )
        checker = make_checker(network_client=client)
        outcome = checker.check(make_cors_finding())
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"

    def test_replay_original_auth_headers_are_carried(self) -> None:
        """元 evidence.request_headers の Origin 以外（認証情報等）は再送に
        併せて付与され、Origin は test_origin で上書きされる。"""
        finding = make_cors_finding()
        finding.evidence.request_headers = {
            "Origin": TEST_ORIGIN,
            "X-Api-Key": "dummy-key-123456",
        }
        client = FakeNetworkClient(
            FakeResponse(200, body="", headers=_cors_headers())
        )
        checker = make_checker(network_client=client)
        outcome = checker.check(finding)
        assert outcome.status == "matched"
        headers = client.calls[0]["kwargs"]["headers"]
        assert headers["Origin"] == TEST_ORIGIN
        assert headers["X-Api-Key"] == "dummy-key-123456"

    def test_transport_error_not_run(self) -> None:
        """送信例外 → not_run（fail-closed・mismatch にしない）。"""
        client = FakeNetworkClient(error=RuntimeError("connection refused"))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_cors_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_transport_error"

    def test_network_client_none_not_run(self) -> None:
        """(c) network_client=None → not_run（送信不能・fail-closed）。"""
        checker = make_checker(network_client=None)
        outcome = checker.check(make_cors_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_disabled_no_client"

    def test_missing_test_origin_not_run(self) -> None:
        """test_origin が無い finding は再送できない → not_run（fail-closed）。"""
        finding = make_cors_finding()
        finding.additional_info = {
            "acao": TEST_ORIGIN,
            "acac": "true",
            "misconfiguration": "origin_reflection_with_credentials",
            "credentialed_body_excerpt": CREDENTIALED_BODY,
        }
        client = FakeNetworkClient(FakeResponse(200, body="", headers=_cors_headers()))
        checker = make_checker(network_client=client)
        outcome = checker.check(finding)
        assert outcome.status == "not_run"
        assert client.calls == []

    def test_out_of_scope_replay_not_run(self) -> None:
        """スコープ外 URL は再送されない（not_run・fail-closed）。"""
        finding = make_cors_finding()
        finding.evidence.request_url = "https://out-of-scope.example/api/account"
        client = FakeNetworkClient(FakeResponse(200, body="", headers=_cors_headers()))
        checker = make_checker(network_client=client)
        outcome = checker.check(finding)
        assert outcome.status == "not_run"
        assert outcome.reason == "scope_revalidation_blocked"
        assert client.calls == []


# ---------------------------------------------------------------------------
# 既存 external_redirect / body マーカー経路の非回帰（同 checker・同注入 client）
# ---------------------------------------------------------------------------


class TestOtherMarkerPathsUnchanged:
    def test_external_redirect_replay_still_matches(self) -> None:
        """(d) external_redirect（ヘッダ経路・SGK-2026-0471）は従来どおり。"""
        client = FakeNetworkClient(
            FakeResponse(302, body="", headers={"Location": ATTACKER_LOCATION})
        )
        checker = make_checker(network_client=client)
        outcome = checker.check(make_open_redirect_finding())
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:external_redirect"

    def test_sqli_body_marker_still_matches(self) -> None:
        """body マーカー種別（sql_error）は従来どおり matched。"""
        client = FakeNetworkClient(FakeResponse(200, body=_SQL_BODY))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:sql_error"

    def test_sqli_body_marker_still_mismatches_without_fire(self) -> None:
        """body マーカー非発火は従来どおり mismatched。"""
        client = FakeNetworkClient(FakeResponse(200, body="OK"))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"

    def test_cors_replay_sends_no_body_marker_request(self) -> None:
        """CORS 再送は Origin ヘッダ付き GET の 1 回のみ（本文マーカー照合や
        Location 照合に流れない）。"""
        client = FakeNetworkClient(
            FakeResponse(200, body=_SQL_BODY, headers=_cors_headers())
        )
        checker = make_checker(network_client=client)
        outcome = checker.check(make_cors_finding())
        # SQL エラー文字列が本文にあっても CORS 経路はヘッダ照合のみで判定
        assert outcome.status == "matched"
        assert (
            outcome.reason
            == "reproduction_marker_matched:cors_credentialed_reflection"
        )
        assert len(client.calls) == 1
