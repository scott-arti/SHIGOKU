"""
SealedReproductionChecker command_execution テスト — SGK-2026-0478 (A②)

command_execution マーカーは「1 回の封印再送で観測可能」だが、POST フォーム
注入（例: form method=POST のパラメータへの ;id 注入）は GET 再送では再現
できない。元 Finding の additional_info.command_replay 記述子
（method/body_params/content_type + 読み取り専用コマンド readonly_command）
が有効なときだけ、元 method（POST）で同一フォームを再送し、再送応答本文に
_CMD_INDICATORS（uid= 等）が再出現すれば matched。

- (a) command_replay（readonly_command=id）で POST 再送 → uid= 再出現 → matched
- (b) 応答あり・非再出現 → mismatched
- (c) 許可外コマンド / 記述子なし / 不正記述子 → GET フォールバック
      （POST 送信なし・fail-closed）
- (d) client None / スコープ外 / 送信例外 → not_run
- (e) 既存 GET-based command_execution・他マーカー（sql_error/cors/jwt/
      external_redirect）の非回帰（byte-identical 経路）

PRODUCT-INDEPENDENT fixtures のみ（target.example・汎用コマンド）。
ネットワークなし（FakeNetworkClient）。
"""
import pytest

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import (
    SealedReproductionChecker,
)

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-cmd-test",
    in_scope_domains=["target.example"],
)

# POST フォーム注入（in-band・読み取り専用コマンド）の generic fixture。
CMD_URL = "https://target.example/exec/"
BODY_PARAMS = {"ip": "127.0.0.1;id", "Submit": "Submit"}
INJECTED_PARAM_VALUE = "127.0.0.1;id"
# _CMD_INDICATORS（uid= 等）を含む in-band 応答（id の出力）。
CMD_BODY = (
    "PING 127.0.0.1 (127.0.0.1): 56 data bytes\n"
    "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
    "--- 127.0.0.1 ping statistics ---"
)
NO_CMD_BODY = "<html><body>host appears to be down</body></html>"
COOKIE_HEADER = "session=abc123"

_SQL_BODY = "SQL syntax error near '1' at line 1"


def make_cmd_post_finding() -> Finding:
    """SmartCmdSSRFHunter（deterministic in-band POST 確定）が生成する Finding
    形状（to_dict 経由で evaluate_payout_grade が command_execution を返す）。"""
    return Finding(
        vuln_type=VulnType.OS_COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        title="Command Injection/SSRF in parameter 'ip'",
        description="Command Injection/SSRF detected.",
        target_url=CMD_URL,
        evidence=Evidence(
            request_method="POST",
            request_url=CMD_URL,
            request_headers={"Cookie": COOKIE_HEADER},
            response_status=200,
            response_body=CMD_BODY,
        ),
        reproduction_steps=[
            "対象フォームのパラメータ 'ip' を method=POST で送信する（認証セッションを使用）。",
            f"パラメータ値に読み取り専用コマンドを注入する: {INJECTED_PARAM_VALUE}",
            "応答本文に OS コマンド出力の指標（uid= 等）が返ることを確認する。",
        ],
        impact=(
            "注入パラメータ経由で任意 OS コマンドを実行可能。"
            "サーバ完全掌握(RCE)の起点。"
        ),
        additional_info={
            "parameter": "ip",
            "tested_params": ["ip"],
            "payload": INJECTED_PARAM_VALUE,
            "command_replay": {
                "method": "POST",
                "url": CMD_URL,
                "body_params": dict(BODY_PARAMS),
                "readonly_command": "id",
                "content_type": "application/x-www-form-urlencoded",
            },
        },
    )


def make_cmd_get_finding() -> Finding:
    """GET-based in-band command_execution（記述子なし・非回帰確認用）。"""
    return Finding(
        vuln_type=VulnType.OS_COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        title="Command Injection in parameter 'host'",
        description="Command Injection detected.",
        target_url="https://target.example/ping",
        evidence=Evidence(
            request_method="GET",
            request_url="https://target.example/ping?host=127.0.0.1%3Bid",
            response_status=200,
            response_body=CMD_BODY,
        ),
        reproduction_steps=["GET で注入し応答本文に uid= が返ることを確認する"],
        impact="任意 OS コマンド実行。",
        additional_info={
            "parameter": "host",
            "payload": "127.0.0.1;id",
            "command_execution_evidence": {
                "output_observed": True,
                "payload": "127.0.0.1;id",
                "command_output": CMD_BODY,
                "response_status": 200,
            },
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


# cors / jwt / external_redirect 非回帰確認用（既存 sealed テストの形状）。
TEST_ORIGIN = "https://attacker.example"
CORS_URL = "https://target.example/api/account"
CREDENTIALED_BODY = (
    '{"session_token":"dummy-session-3f2a9c8e1b7d","user_email":"alice@example.test",'
    '"account_role":"admin","account_id":"acct_100042"}'
)
AUTH_URL = "https://target.example/api/identity"
FABRICATED_IDENTITY = "forge-3f2a9c8e@evil.example"
FORGED_BODY = f'{{"user":{{"id":1,"email":"{FABRICATED_IDENTITY}"}}}}'
FORGED_TOKEN = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0."
    "eyJkYXRhIjp7ImlkIjoxLCJlbWFpbCI6ImZvcmdlLTNmMmE5YzhlQGV2aWwuZXhhbXBsZSJ9LCJpYXQiOjEyM30."
)
EXPLOIT_URL = (
    "https://target.example/redirect?url=https%3A%2F%2F"
    "shigoku-verify-abc.evil.com%2F"
)
ATTACKER_LOCATION = "http://shigoku-verify-abc.evil.com/"


def make_cors_finding() -> Finding:
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


def make_jwt_forgery_finding() -> Finding:
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


def make_open_redirect_finding() -> Finding:
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
            "payload": "http://shigoku-verify-abc.evil.com/",
            "payloads_used": ["http://shigoku-verify-abc.evil.com/"],
            "tested_params": ["url"],
            "redirect_to": ATTACKER_LOCATION,
            "injected_host": "shigoku-verify-abc.evil.com",
        },
    )


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


def make_checker(**kwargs) -> SealedReproductionChecker:
    kwargs.setdefault("scope_definition", TARGET_SCOPE)
    return SealedReproductionChecker(**kwargs)


class TestCommandExecutionPostReplay:
    def test_post_replay_indicator_reappears_matched(self) -> None:
        """(a) command_replay（readonly_command=id）で POST 再送 → 本文に
        uid= 再出現 → matched（GET ではなく元 method=POST が使われる）。"""
        client = FakeNetworkClient(FakeResponse(200, body=CMD_BODY))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_cmd_post_finding())
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:command_execution"
        assert len(client.calls) == 1
        call = client.calls[0]
        assert call["method"] == "POST"
        assert call["url"] == CMD_URL
        kwargs = call["kwargs"]
        # 同一フォーム値一式が再送される（注入値を含む）
        assert kwargs["data"] == BODY_PARAMS
        # 認証ヘッダ/Cookie は元 evidence.request_headers から再利用される
        assert kwargs["headers"]["Cookie"] == COOKIE_HEADER
        assert (
            kwargs["headers"]["Content-Type"]
            == "application/x-www-form-urlencoded"
        )
        assert kwargs["allow_redirects"] is False
        assert kwargs["use_cache"] is False
        assert kwargs["retries"] == 0

    def test_post_replay_indicator_absent_mismatched(self) -> None:
        """(b) 応答あり・_CMD_INDICATORS 非再出現（例: 修正済み/入力フィルタ）
        → mismatched（唯一の mismatch 経路）。"""
        client = FakeNetworkClient(FakeResponse(200, body=NO_CMD_BODY))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_cmd_post_finding())
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"

    def test_post_replay_whoami_allowlisted_matches(self) -> None:
        """readonly_command=whoami（許可リスト内）も POST 再送で matched。"""
        finding = make_cmd_post_finding()
        replay = finding.additional_info["command_replay"]
        replay["readonly_command"] = "whoami"
        replay["body_params"] = {"ip": "127.0.0.1;whoami", "Submit": "Submit"}
        body = "www-data\n"
        client = FakeNetworkClient(FakeResponse(200, body=body))
        checker = make_checker(network_client=client)
        outcome = checker.check(finding)
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:command_execution"
        assert client.calls[0]["method"] == "POST"
        assert client.calls[0]["kwargs"]["data"] == {
            "ip": "127.0.0.1;whoami",
            "Submit": "Submit",
        }

    def test_forbidden_command_falls_back_to_get_only_no_post(self) -> None:
        """(c) 許可外コマンド（cat 等）の記述子は POST 再送しない。
        GET-only フォールバック（POST evidence は fingerprint 不一致 →
        not_run・送信ゼロ・fail-closed）。"""
        finding = make_cmd_post_finding()
        finding.additional_info["command_replay"]["readonly_command"] = "cat"
        client = FakeNetworkClient(FakeResponse(200, body=CMD_BODY))
        checker = make_checker(network_client=client)
        outcome = checker.check(finding)
        assert outcome.status == "not_run"
        assert outcome.reason == "request_fingerprint_mismatch"
        assert client.calls == []

    def test_missing_descriptor_falls_back_to_get_only_no_post(self) -> None:
        """(c) 記述子なし → 専用パスを使わず従来の GET-only 経路へ
        フォールバック（POST evidence は fingerprint 不一致 → not_run・
        送信ゼロ・fail-closed・非回帰）。"""
        finding = make_cmd_post_finding()
        del finding.additional_info["command_replay"]
        client = FakeNetworkClient(FakeResponse(200, body=CMD_BODY))
        checker = make_checker(network_client=client)
        outcome = checker.check(finding)
        assert outcome.status == "not_run"
        assert outcome.reason == "request_fingerprint_mismatch"
        assert client.calls == []

    def test_malformed_descriptor_falls_back_to_get_only(self) -> None:
        """(c) body_params が空/非 dict の不正記述子 → GET フォールバック。"""
        finding = make_cmd_post_finding()
        finding.additional_info["command_replay"]["body_params"] = {}
        client = FakeNetworkClient(FakeResponse(200, body=CMD_BODY))
        checker = make_checker(network_client=client)
        outcome = checker.check(finding)
        assert outcome.status == "not_run"
        assert outcome.reason == "request_fingerprint_mismatch"
        assert client.calls == []

    def test_network_client_none_not_run(self) -> None:
        """(d) network_client=None → not_run（送信不能・fail-closed）。"""
        checker = make_checker(network_client=None)
        outcome = checker.check(make_cmd_post_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_disabled_no_client"

    def test_out_of_scope_replay_not_run(self) -> None:
        """(d) スコープ外 URL の POST 再送は行われない（not_run・fail-closed）。"""
        finding = make_cmd_post_finding()
        finding.evidence.request_url = "https://out-of-scope.example/exec/"
        client = FakeNetworkClient(FakeResponse(200, body=CMD_BODY))
        checker = make_checker(network_client=client)
        outcome = checker.check(finding)
        assert outcome.status == "not_run"
        assert outcome.reason == "scope_revalidation_blocked"
        assert client.calls == []

    def test_transport_error_not_run(self) -> None:
        """(d) 送信例外 → not_run（fail-closed・mismatch にしない）。"""
        client = FakeNetworkClient(error=RuntimeError("connection refused"))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_cmd_post_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_transport_error"

    def test_empty_body_not_run(self) -> None:
        """応答あり・空本文は判定不能 → not_run（mismatch にしない）。"""
        client = FakeNetworkClient(FakeResponse(200, body=""))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_cmd_post_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_transport_error"


class TestOtherMarkerPathsUnchanged:
    def test_get_based_inband_command_execution_still_matches(self) -> None:
        """(e) 既存 GET-based in-band command_execution（記述子なし）は
        従来どおり GET 再送 + 本文 _CMD_INDICATORS 照合で matched。"""
        client = FakeNetworkClient(FakeResponse(200, body=CMD_BODY))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_cmd_get_finding())
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:command_execution"
        assert len(client.calls) == 1
        assert client.calls[0]["method"] == "GET"

    def test_sqli_body_marker_still_matches(self) -> None:
        """他 body マーカー（sql_error）は従来どおり matched。"""
        client = FakeNetworkClient(FakeResponse(200, body=_SQL_BODY))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:sql_error"

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

    def test_jwt_replay_still_matches(self) -> None:
        """jwt（forged-token 再送・SGK-2026-0476）は従来どおり。"""
        client = FakeNetworkClient(FakeResponse(200, body=FORGED_BODY))
        checker = make_checker(network_client=client)
        outcome = checker.check(make_jwt_forgery_finding())
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:jwt_forgery_accepted"

    def test_external_redirect_replay_still_matches(self) -> None:
        """external_redirect（ヘッダ経路）は従来どおり。"""
        client = FakeNetworkClient(
            FakeResponse(302, body="", headers={"Location": ATTACKER_LOCATION})
        )
        checker = make_checker(network_client=client)
        outcome = checker.check(make_open_redirect_finding())
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:external_redirect"
