"""
AuthNinja (auth/auth_ninja.py) の JWT alg=none サーバ側受理の実確証テスト — SGK-2026-0476 (B)

- (a) 受理サーバ stub: baseline（トークン無し GET・identity 不在）→ 偽造
  （alg=none・fabricated identity）GET で identity 反映 → vulnerable + 証拠
  （impact / reproduction_steps / additional_info / evidence 完備）
- (b) 署名検証サーバ stub（401 / 非反映）→ vulnerable=False（fail-closed）
- 送信は GET のみ・偽造トークンはエンジン fabricate（実トークン非複製）・
  値は証拠以外（ログ等）に出さない

PRODUCT-INDEPENDENT: target.example・reserved example TLD の fabricated
identity・ダミーの param token（実トークンではない）。ネットワークなし
（async stub client）。
"""
import base64
import json

import jwt
import pytest

from src.core.agents.swarm.auth.auth_ninja import AuthNinja
from src.core.domain.model.task import Task
from src.core.models.finding import VulnType

AUTH_URL = "https://target.example/api/identity"
ALT_ENDPOINT = "https://target.example/api/account/me"
UNAUTH_BODY = '{"user":{}}'
PARAM_TOKEN = (
    "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.ZmFrZS1zaWduYXR1cmU"
)  # ダミー（実トークンではない）


class FakeResponse:
    def __init__(self, status: int = 200, body: str = ""):
        self.status = status
        self.body = body


def _token_email(token: str) -> str:
    """stub が偽造トークンの payload から fabricated identity を取り出す。"""
    try:
        parts = str(token or "").split(".")
        segment = parts[1] if len(parts) >= 2 else ""
        padded = segment + "=" * (-len(segment) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        return str(data["data"]["email"])
    except Exception:
        return ""


class StubServer:
    """受理/拒否を切替可能な async スタブ。

    - 認証ヘッダ無し → baseline 応答（identity 不在）
    - 認証ヘッダ有り → accept=True: forged token の email を反映して 200 /
      accept=False: 401（署名検証サーバ型） / reflect=False: 200 だが非反映
    """

    def __init__(self, accept: bool = True, reflect: bool = True):
        self.accept = accept
        self.reflect = reflect
        self.calls = []

    async def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        headers = kwargs.get("headers") or {}
        auth = str(headers.get("Authorization") or "")
        cookie = str(headers.get("Cookie") or "")
        if not auth and not cookie:
            return FakeResponse(200, UNAUTH_BODY)  # baseline
        email = _token_email(auth.removeprefix("Bearer "))
        if not email:
            return FakeResponse(401, '{"error":"invalid token"}')
        if not self.accept:
            # 署名を正しく検証するサーバ型: 無署名トークンを拒否（401・非反映）
            return FakeResponse(401, '{"error":"invalid signature"}')
        if not self.reflect:
            return FakeResponse(200, UNAUTH_BODY)
        return FakeResponse(200, f'{{"user":{{"id":1,"email":"{email}"}}}}')


def _make_task(endpoint: str = AUTH_URL, token: str = PARAM_TOKEN) -> Task:
    return Task(
        id="t-jwt-0476",
        name="auth_jwt_check",
        target=endpoint,
        params={"token": token},
    )


@pytest.mark.asyncio
async def test_accepting_server_yields_vulnerable_finding_with_evidence():
    """(a) 受理サーバ stub: baseline 不在 → forged で identity 反映の差分成立
    → vulnerable Finding + 証拠完備。"""
    client = StubServer(accept=True)
    ninja = AuthNinja()
    ninja.set_network_client(client)

    findings = await ninja.execute(_make_task())
    assert len(findings) == 1
    finding = findings[0]

    assert finding.vuln_type == VulnType.JWT_ALG_NONE
    assert str(finding.impact).strip()
    assert len(finding.reproduction_steps) >= 3

    info = finding.additional_info
    assert info["jwt_alg"] == "none"
    assert info["unauth_baseline_absent"] is True
    assert info["auth_endpoint"] == AUTH_URL
    forged_identity = str(info["forged_identity"])
    assert forged_identity.startswith("forge-")
    assert forged_identity.endswith("@evil.example")
    forged_token = str(info["forged_token"])
    # 偽造トークンはエンジン fabricate（実トークン非複製・署名空）
    assert forged_token != PARAM_TOKEN
    assert forged_token.endswith(".")
    assert forged_token.count(".") == 2

    # evidence: GET・実 status・反映本文の抜粋
    assert finding.evidence.request_method == "GET"
    assert finding.evidence.request_url == AUTH_URL
    assert finding.evidence.response_status == 200
    assert forged_identity in finding.evidence.response_body
    # 証拠に実トークン（PARAM_TOKEN）が漏れていない
    assert PARAM_TOKEN not in str(finding.evidence.to_dict())
    assert PARAM_TOKEN not in json.dumps(info)

    # 送信は GET のみ・baseline → forged の 2 回・偽造トークンは
    # Authorization: Bearer と Cookie: token= の両方に載る
    assert [c["method"] for c in client.calls] == ["GET", "GET"]
    assert client.calls[0]["url"] == AUTH_URL
    assert not client.calls[0]["kwargs"].get("headers")
    forged_headers = client.calls[1]["kwargs"]["headers"]
    assert forged_headers["Authorization"] == f"Bearer {forged_token}"
    assert forged_headers["Cookie"] == f"token={forged_token}"
    assert forged_token != PARAM_TOKEN


@pytest.mark.asyncio
async def test_params_auth_endpoint_preferred_over_task_target():
    """params.auth_endpoint が task.target より優先される（エンドポイントは
    ハードコードしない・動的解決）。"""
    client = StubServer(accept=True)
    ninja = AuthNinja()
    ninja.set_network_client(client)

    task = _make_task(endpoint=AUTH_URL)
    task.params["auth_endpoint"] = ALT_ENDPOINT
    findings = await ninja.execute(task)
    assert len(findings) == 1
    assert findings[0].evidence.request_url == ALT_ENDPOINT
    assert findings[0].additional_info["auth_endpoint"] == ALT_ENDPOINT
    assert [c["url"] for c in client.calls] == [ALT_ENDPOINT, ALT_ENDPOINT]


@pytest.mark.asyncio
async def test_signature_verifying_server_yields_no_finding():
    """(b) 署名検証サーバ stub（401・非反映）→ vulnerable=False（fail-closed・
    偽 ◎ を出さない）。"""
    client = StubServer(accept=False)
    ninja = AuthNinja()
    ninja.set_network_client(client)

    findings = await ninja.execute(_make_task())
    assert findings == []


@pytest.mark.asyncio
async def test_non_reflecting_server_yields_no_finding():
    """200 でも identity 非反映（受理されていない）→ vulnerable=False。"""
    client = StubServer(accept=True, reflect=False)
    ninja = AuthNinja()
    ninja.set_network_client(client)

    findings = await ninja.execute(_make_task())
    assert findings == []


@pytest.mark.asyncio
async def test_transport_failure_fails_closed():
    """送信例外（baseline 段階）→ vulnerable=False（クラッシュしない）。"""
    class RaisingServer(StubServer):
        async def request(self, method, url, **kwargs):
            self.calls.append({"method": method, "url": url, "kwargs": kwargs})
            raise ConnectionError("connection refused")

    client = RaisingServer()
    ninja = AuthNinja()
    ninja.set_network_client(client)

    findings = await ninja.execute(_make_task())
    assert findings == []


@pytest.mark.asyncio
async def test_token_param_required_unchanged():
    """既存ゲート非回帰: params.token 無し → Finding 無し（ネットワーク送信も
    しない）。"""
    client = StubServer(accept=True)
    ninja = AuthNinja()
    ninja.set_network_client(client)

    task = _make_task()
    task.params = {}
    findings = await ninja.execute(task)
    assert findings == []
    assert client.calls == []


@pytest.mark.asyncio
async def test_no_endpoint_runs_local_only_without_network():
    """エンドポイント無しの run_as_tool はネットワーク送信せずローカル解析のみ
    （従来挙動・fail-closed）。"""
    client = StubServer(accept=True)
    ninja = AuthNinja()
    ninja.set_network_client(client)

    result = await ninja.run_as_tool(PARAM_TOKEN, "all")
    assert result.get("vulnerable") is False
    assert client.calls == []


@pytest.mark.asyncio
async def test_weak_secret_path_non_regression():
    """既存 weak-secret 経路は非回帰: HS256 辞書ヒットで従来どおり vulnerable
    （エンドポイント不要・値は辞書由来）。"""
    token = jwt.encode({"sub": "t"}, "secret", algorithm="HS256")
    ninja = AuthNinja()
    result = await ninja.run_as_tool(token, "all")
    assert result.get("vulnerable") is True
    assert "weak secret" in str(result.get("description", "")).lower()
