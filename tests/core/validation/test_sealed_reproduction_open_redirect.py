"""
SealedReproductionChecker open_redirect テスト — SGK-2026-0471 (A②)

external_redirect マーカーは「1 回の封印 GET で観測可能・Location ヘッダ
経由」として扱う（_NON_BODY_MARKERS に入れない）。再送応答が 3xx かつ
Location に元 Finding の攻撃者ホストが再出現し、外部なら matched。

- (a) 3xx + 攻撃者ホスト再出現 → matched（ボディが空の 3xx でも可）
- (b) 応答あり・非再出現 → mismatched
- (c) client None → not_run
- 他種別（既存 body マーカー）経路の非回帰もインラインで確認

PRODUCT-INDEPENDENT fixtures のみ（target.example / evil.com）。
ネットワークなし（FakeNetworkClient）。
"""
import pytest

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import (
    SealedReproductionChecker,
)

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-open-redirect-test",
    in_scope_domains=["target.example"],
)

_SQL_BODY = "SQL syntax error near '1' at line 1"

# OpenRedirectSpecialist (B) が記録する形状の URL / ホスト。
EXPLOIT_URL = (
    "https://target.example/redirect?url=https%3A%2F%2F"
    "shigoku-verify-abc.evil.com%2F"
)
ATTACKER_HOST = "shigoku-verify-abc.evil.com"
ATTACKER_LOCATION = f"http://{ATTACKER_HOST}/"


# ---------------------------------------------------------------------------
# Fixtures（既存 test_sealed_reproduction_checker.py のスタイルを踏襲）
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


def make_open_redirect_finding() -> Finding:
    """OpenRedirectSpecialist (B) が生成する Finding 形状（to_dict 経由で
    evaluate_payout_grade が external_redirect を返す）。"""
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


# ---------------------------------------------------------------------------
# external_redirect replay path
# ---------------------------------------------------------------------------


class TestExternalRedirectReplay:
    def test_replay_3xx_with_attacker_location_matched(self) -> None:
        """(a) 再送応答が 3xx かつ Location に攻撃者ホスト再出現 → matched。
        リダイレクト応答はボディが空でもヘッダ経由で観測できる。"""
        client = FakeNetworkClient(
            FakeResponse(302, body="", headers={"Location": ATTACKER_LOCATION})
        )
        checker = make_checker(network_client=client)
        outcome = checker.check(make_open_redirect_finding())
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:external_redirect"
        assert client.calls[0]["method"] == "GET"
        assert client.calls[0]["url"] == EXPLOIT_URL
        kwargs = client.calls[0]["kwargs"]
        assert kwargs["allow_redirects"] is False
        assert kwargs["use_cache"] is False
        assert kwargs["retries"] == 0

    def test_replay_attacker_host_not_reappearing_mismatched(self) -> None:
        """(b) 応答あり・攻撃者ホスト非再出現 → mismatched（唯一の mismatch 経路）。"""
        client = FakeNetworkClient(
            FakeResponse(302, body="", headers={"Location": "http://legit.example.com/next"})
        )
        checker = make_checker(network_client=client)
        outcome = checker.check(make_open_redirect_finding())
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"

    def test_replay_internal_relative_location_mismatched(self) -> None:
        """同一ホスト内リダイレクト（/path）は外部でない → mismatched。"""
        client = FakeNetworkClient(
            FakeResponse(302, body="", headers={"Location": "/internal/home"})
        )
        checker = make_checker(network_client=client)
        outcome = checker.check(make_open_redirect_finding())
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"

    def test_replay_non_3xx_response_mismatched(self) -> None:
        """応答はあるが 3xx でない（修正済み/別挙動）→ mismatched。"""
        client = FakeNetworkClient(FakeResponse(200, body="OK"))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_open_redirect_finding())
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"

    def test_transport_error_not_run(self) -> None:
        """送信例外 → not_run（fail-closed・mismatch にしない）。"""
        client = FakeNetworkClient(error=RuntimeError("connection refused"))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_open_redirect_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_transport_error"

    def test_network_client_none_not_run(self) -> None:
        """(c) network_client=None → not_run（送信不能・fail-closed）。"""
        checker = make_checker(network_client=None)
        outcome = checker.check(make_open_redirect_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_disabled_no_client"

    def test_out_of_scope_replay_not_run(self) -> None:
        """スコープ外 URL は再送されない（not_run・fail-closed）。"""
        finding = make_open_redirect_finding()
        finding.evidence.request_url = (
            "https://out-of-scope.example/redirect?url=https%3A%2F%2F"
            "shigoku-verify-abc.evil.com%2F"
        )
        client = FakeNetworkClient(FakeResponse(302, headers={"Location": ATTACKER_LOCATION}))
        checker = make_checker(network_client=client)
        outcome = checker.check(finding)
        assert outcome.status == "not_run"
        assert outcome.reason == "scope_revalidation_blocked"
        assert client.calls == []


# ---------------------------------------------------------------------------
# 既存 body マーカー経路の非回帰（同 checker・同注入 client）
# ---------------------------------------------------------------------------


class TestBodyMarkerPathUnchanged:
    def test_sqli_body_marker_still_matches(self) -> None:
        """(d) 他種別（既存 body マーカー）は従来どおり matched。"""
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

    def test_sqli_empty_body_still_not_run(self) -> None:
        """body 種別で空ボディ 3xx は従来どおり not_run（transport_error）。
        （ボディ空で照合できるのは external_redirect のヘッダ経路のみ）"""
        client = FakeNetworkClient(
            FakeResponse(302, body="", headers={"Location": ATTACKER_LOCATION})
        )
        checker = make_checker(network_client=client)
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_transport_error"
