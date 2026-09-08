"""
SealedReproductionChecker jwt_forgery_accepted テスト — SGK-2026-0476 (A②)

jwt_forgery_accepted マーカーは「1 回の封印 GET で観測可能・forged_token を
Authorization/Cookie に付けた専用再送が必須」として扱う（_send_get 本文経路は
不変）。再送は元 Finding の forged_token を付けて行い、再送応答本文に
forged_identity が再出現すれば matched。

- (a) forged_token 再送で forged_identity 再出現 → matched
- (b) 応答あり・非再出現 → mismatched
- (c) client None / forged_token・forged_identity 欠落 → not_run（送信なし）
- (d) 既存 external_redirect / cors / 本文マーカーの非回帰

PRODUCT-INDEPENDENT fixtures のみ（target.example・reserved example TLD の
fabricated identity）。ネットワークなし（FakeNetworkClient）。
"""
import pytest

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import (
    SealedReproductionChecker,
)

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-jwt-test",
    in_scope_domains=["target.example"],
)

_SQL_BODY = "SQL syntax error near '1' at line 1"

AUTH_URL = "https://target.example/api/identity"
FABRICATED_IDENTITY = "forge-3f2a9c8e@evil.example"
FORGED_BODY = f'{{"user":{{"id":1,"email":"{FABRICATED_IDENTITY}"}}}}'
UNAUTH_BODY = '{"user":{}}'
FORGED_TOKEN = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0."
    "eyJkYXRhIjp7ImlkIjoxLCJlbWFpbCI6ImZvcmdlLTNmMmE5YzhlQGV2aWwuZXhhbXBsZSJ9LCJpYXQiOjEyM30."
)

# external_redirect 非回帰確認用の URL / ホスト（SGK-2026-0471 形状）。
EXPLOIT_URL = (
    "https://target.example/redirect?url=https%3A%2F%2F"
    "shigoku-verify-abc.evil.com%2F"
)
ATTACKER_HOST = "shigoku-verify-abc.evil.com"
ATTACKER_LOCATION = f"http://{ATTACKER_HOST}/"

# cors 非回帰確認用（SGK-2026-0475 形状）。
TEST_ORIGIN = "https://attacker.example"
CORS_URL = "https://target.example/api/account"
CREDENTIALED_BODY = (
    '{"session_token":"dummy-session-3f2a9c8e1b7d","user_email":"alice@example.test",'
    '"account_role":"admin","account_id":"acct_100042"}'
)


# ---------------------------------------------------------------------------
# Fixtures（既存 sealed/cors テストのスタイルを踏襲）
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


def make_jwt_forgery_finding() -> Finding:
    """AuthNinja (B) が生成する Finding 形状（to_dict 経由で
    evaluate_payout_grade が jwt_forgery_accepted を返す・SGK-2026-0476）。"""
    return Finding(
        vuln_type=VulnType.JWT_ALG_NONE,
        severity=Severity.HIGH,
        title="Authentication Bypass: JWT accepts 'none' algorithm (Signature Bypass)",
        description="JWT accepts 'none' algorithm (Signature Bypass)",
        target_url=AUTH_URL,
        evidence=Evidence(
            request_method="GET",
            request_url=AUTH_URL,
            response_status=200,
            response_body=FORGED_BODY,
        ),
        reproduction_steps=[
            "1. GET the identity endpoint with no token (identity absent).",
            "2. Fabricate a local alg=none token with an attacker-chosen identity.",
            "3. GET the same endpoint with the forged token in Authorization/Cookie.",
            "4. Observe the fabricated identity reflected in the response.",
        ],
        impact=(
            "The server accepts unsigned (alg=none) JWT tokens without signature "
            "verification: an attacker can impersonate an arbitrary identity."
        ),
        additional_info={
            "jwt_alg": "none",
            "unauth_baseline_absent": True,
            "forged_identity": FABRICATED_IDENTITY,
            "forged_identity_reflected": True,
            "auth_endpoint": AUTH_URL,
            "forged_token": FORGED_TOKEN,
        },
    )


def make_cors_finding() -> Finding:
    """SmartCORSHunter (B) が生成する Finding 形状（非回帰用・SGK-2026-0475）。"""
    return Finding(
        vuln_type=VulnType.CORS_MISCONFIGURATION,
        severity=Severity.HIGH,
        title="CORS Misconfiguration: origin_reflection_with_credentials",
        description="Origin reflected in Access-Control-Allow-Origin header.",
        target_url=CORS_URL,
        evidence=Evidence(
            request_method="GET",
            request_url=CORS_URL,
            request_headers={"Origin": TEST_ORIGIN},
            response_status=200,
            response_headers={
                "Access-Control-Allow-Origin": TEST_ORIGIN,
                "Access-Control-Allow-Credentials": "true",
            },
            response_body=CREDENTIALED_BODY,
        ),
        reproduction_steps=["Send GET with Origin header", "Observe ACAO reflection"],
        impact="Cross-origin read of sensitive data.",
        additional_info={
            "test_origin": TEST_ORIGIN,
            "acao": TEST_ORIGIN,
            "acac": "true",
            "misconfiguration": "origin_reflection_with_credentials",
            "credentialed_body_excerpt": CREDENTIALED_BODY,
        },
    )


def make_open_redirect_finding() -> Finding:
    """OpenRedirectSpecialist (B) が生成する Finding 形状（非回帰用・SGK-2026-0471）。"""
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
        reproduction_steps=[f"GET {EXPLOIT_URL}", "Observe 302 Location to attacker host"],
        impact="Credentialed users can be redirected to attacker-controlled hosts.",
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


# ---------------------------------------------------------------------------
# jwt_forgery_accepted replay path
# ---------------------------------------------------------------------------


class TestJwtForgeryReplay:
    def test_forged_token_replay_identity_reappears_matched(self) -> None:
        """(a) forged_token 再送で forged_identity が本文に再出現 → matched。"""
        client = FakeNetworkClient(FakeResponse(200, body=FORGED_BODY))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_jwt_forgery_finding())
        assert outcome.status == "matched"
        assert (
            outcome.reason == "reproduction_marker_matched:jwt_forgery_accepted"
        )
        assert len(client.calls) == 1
        assert client.calls[0]["method"] == "GET"
        assert client.calls[0]["url"] == AUTH_URL
        kwargs = client.calls[0]["kwargs"]
        # 再送は forged_token を Authorization: Bearer と Cookie: token= に付ける
        assert kwargs["headers"]["Authorization"] == f"Bearer {FORGED_TOKEN}"
        assert kwargs["headers"]["Cookie"] == f"token={FORGED_TOKEN}"
        assert kwargs["allow_redirects"] is False
        assert kwargs["use_cache"] is False
        assert kwargs["retries"] == 0

    def test_replay_identity_absent_mismatched(self) -> None:
        """(b) 応答あり・forged_identity 非再出現（例: 修正済み/署名検証）→
        mismatched。"""
        client = FakeNetworkClient(FakeResponse(200, body=UNAUTH_BODY))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_jwt_forgery_finding())
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"

    def test_replay_empty_body_mismatched(self) -> None:
        """応答あり・本文が空（identity 非再出現）→ mismatched（唯一の
        mismatch 経路・fail-closed）。"""
        client = FakeNetworkClient(FakeResponse(200, body=""))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_jwt_forgery_finding())
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"

    def test_network_client_none_not_run(self) -> None:
        """(c) network_client=None → not_run（送信不能・fail-closed）。"""
        checker = make_checker(network_client=None)
        outcome = checker.check(make_jwt_forgery_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_disabled_no_client"

    def test_missing_forged_token_not_run(self) -> None:
        """forged_token 欠落 → 再送できない → not_run（送信なし・fail-closed）。"""
        finding = make_jwt_forgery_finding()
        finding.additional_info = {
            "jwt_alg": "none",
            "unauth_baseline_absent": True,
            "forged_identity": FABRICATED_IDENTITY,
            "forged_identity_reflected": True,
            "auth_endpoint": AUTH_URL,
        }
        client = FakeNetworkClient(FakeResponse(200, body=FORGED_BODY))
        checker = make_checker(network_client=client)
        outcome = checker.check(finding)
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_unknown_category"
        assert client.calls == []

    def test_missing_forged_identity_not_run(self) -> None:
        """forged_identity 欠落（再出現の照合対象なし）→ not_run（送信なし）。"""
        finding = make_jwt_forgery_finding()
        finding.additional_info = {
            "jwt_alg": "none",
            "unauth_baseline_absent": True,
            "forged_identity_reflected": True,
            "auth_endpoint": AUTH_URL,
            "forged_token": FORGED_TOKEN,
        }
        client = FakeNetworkClient(FakeResponse(200, body=FORGED_BODY))
        checker = make_checker(network_client=client)
        outcome = checker.check(finding)
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_unknown_category"
        assert client.calls == []

    def test_transport_error_not_run(self) -> None:
        """送信例外 → not_run（fail-closed・mismatch にしない）。"""
        client = FakeNetworkClient(error=RuntimeError("connection refused"))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_jwt_forgery_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_transport_error"

    def test_out_of_scope_replay_not_run(self) -> None:
        """スコープ外 URL は再送されない（not_run・fail-closed）。"""
        finding = make_jwt_forgery_finding()
        finding.evidence.request_url = "https://out-of-scope.example/api/identity"
        client = FakeNetworkClient(FakeResponse(200, body=FORGED_BODY))
        checker = make_checker(network_client=client)
        outcome = checker.check(finding)
        assert outcome.status == "not_run"
        assert outcome.reason == "scope_revalidation_blocked"
        assert client.calls == []


# ---------------------------------------------------------------------------
# 既存 external_redirect / cors / body マーカー経路の非回帰（同 checker・同注入 client）
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

    def test_cors_replay_still_matches(self) -> None:
        """cors（Origin 再送・SGK-2026-0475）は従来どおり。"""
        client = FakeNetworkClient(
            FakeResponse(
                200,
                body="unused",
                headers={
                    "Access-Control-Allow-Origin": TEST_ORIGIN,
                    "Access-Control-Allow-Credentials": "true",
                },
            )
        )
        checker = make_checker(network_client=client)
        outcome = checker.check(make_cors_finding())
        assert outcome.status == "matched"
        assert (
            outcome.reason
            == "reproduction_marker_matched:cors_credentialed_reflection"
        )

    def test_sqli_body_marker_still_matches(self) -> None:
        """body マーカー種別（sql_error）は従来どおり matched。"""
        client = FakeNetworkClient(FakeResponse(200, body=_SQL_BODY))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:sql_error"

    def test_jwt_replay_uses_dedicated_path_not_body_markers(self) -> None:
        """JWT 再送は forged-token 付き GET の 1 回のみ（本文マーカー照合や
        Location/CORS 照合に流れない）。"""
        client = FakeNetworkClient(
            FakeResponse(200, body=FORGED_BODY, headers={"Location": ATTACKER_LOCATION})
        )
        checker = make_checker(network_client=client)
        outcome = checker.check(make_jwt_forgery_finding())
        assert outcome.status == "matched"
        assert (
            outcome.reason == "reproduction_marker_matched:jwt_forgery_accepted"
        )
        assert len(client.calls) == 1
