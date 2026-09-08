"""
SmartCORSHunter / CORSTester 認証付きオリジン反映テスト — SGK-2026-0475 (B)

- (a) origin_reflection_with_credentials（acao==test_origin かつ acac==true）
      で credentialed_body_excerpt 非空・実 response_status が Finding に残る。
- (b) `*` / null / 反映なし / 認証なし反映では excerpt を残さない（fail-closed）。
- cors_tester は認証コンテキスト付きのときだけ越境応答本文をキャプチャする。

PRODUCT-INDEPENDENT: generic hosts (attacker.example / target.example) と
汎用ダミー機微データのみ。ネットワークなし（モック/Fake のみ）。
"""
import pytest
from typing import Any
from unittest.mock import AsyncMock, patch

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.smart_cors import SmartCORSHunter
from src.core.attack.cors_tester import CORSTester, CORSResult
from src.core.models.finding import Severity, VulnType

API_URL = "https://target.example/api/account"
TEST_ORIGIN = "https://attacker.example"
CREDENTIALED_BODY = (
    '{"session_token":"dummy-session-3f2a9c8e1b7d","user_email":"alice@example.test",'
    '"account_role":"admin","account_id":"acct_100042"}'
)


def _cors_result(**kwargs: Any) -> CORSResult:
    base: dict[str, Any] = dict(
        url=API_URL,
        test_origin=TEST_ORIGIN,
        vulnerable=True,
        acao_header=TEST_ORIGIN,
        acac_header="true",
        misconfiguration="origin_reflection_with_credentials",
        severity="high",
        status=200,
        body_excerpt="",
    )
    base.update(kwargs)
    return CORSResult(**base)


async def _finding_from(results: list) -> list:
    """execute 経由で Finding 変換するヘルパー（scan_async をモック）。"""
    hunter = SmartCORSHunter()
    task = Task(id="t-cors", name="CORS", target=API_URL, params={}, tags=["cors"])
    with patch.object(CORSTester, "scan_async", new=AsyncMock(return_value=results)):
        return await hunter.execute(task)


class TestSmartCorsCredentialedFinding:
    @pytest.mark.asyncio
    async def test_credentialed_reflection_keeps_excerpt_and_real_status(self) -> None:
        """(a) 反映+creds: credentialed_body_excerpt 非空・実 status・
        evidence.response_body に抜粋が残る。"""
        result = _cors_result(body_excerpt=CREDENTIALED_BODY, status=200)
        findings = await _finding_from([result])
        assert len(findings) == 1
        finding = findings[0]
        assert finding.vuln_type == VulnType.CORS_MISCONFIGURATION
        assert finding.severity == Severity.HIGH
        assert finding.evidence.response_status == 200
        assert finding.evidence.response_body == CREDENTIALED_BODY
        info = finding.additional_info
        assert info["credentialed_body_excerpt"] == CREDENTIALED_BODY
        # 安定フィールド（マーカー・再現が使う）は従来どおり保持
        assert info["test_origin"] == TEST_ORIGIN
        assert info["acao"] == TEST_ORIGIN
        assert info["acac"] == "true"
        assert info["misconfiguration"] == "origin_reflection_with_credentials"
        assert finding.impact
        assert finding.reproduction_steps

    @pytest.mark.asyncio
    async def test_real_observed_status_is_preserved(self) -> None:
        """実観測 status（例 403）がそのまま evidence に残る。"""
        result = _cors_result(body_excerpt=CREDENTIALED_BODY, status=403)
        findings = await _finding_from([result])
        assert findings[0].evidence.response_status == 403

    @pytest.mark.asyncio
    async def test_status_zero_falls_back_to_200(self) -> None:
        """status 未観測（0）のレガシー結果は従来の 200 既定を維持。"""
        result = _cors_result(body_excerpt=CREDENTIALED_BODY, status=0)
        findings = await _finding_from([result])
        assert findings[0].evidence.response_status == 200

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "misconfig, acao, acac",
        [
            ("wildcard_no_credentials", "*", ""),
            ("wildcard_with_credentials", "*", "true"),
            ("null_origin_allowed", "null", ""),
            ("origin_reflection", TEST_ORIGIN, ""),
        ],
    )
    async def test_non_credentialed_misconfigs_keep_excerpt_empty(
        self, misconfig: str, acao: str, acac: str
    ) -> None:
        """(b) `*`/null/反映なし/認証なし反映: body_excerpt が（万一）積まれて
        いても conversion は excerpt を残さない（fail-closed ガード）。"""
        result = _cors_result(
            misconfiguration=misconfig,
            acao_header=acao,
            acac_header=acac,
            body_excerpt=CREDENTIALED_BODY,  # 実経路では積まれないが防御を検証
            status=200,
        )
        findings = await _finding_from([result])
        assert len(findings) == 1
        assert findings[0].additional_info["credentialed_body_excerpt"] == ""
        assert findings[0].evidence.response_body == ""
        assert findings[0].evidence.response_status == 200


# ---------------------------------------------------------------------------
# cors_tester._test_origin の認証付き本文キャプチャ（ネットワークなし）
# ---------------------------------------------------------------------------


class _FakeHTTPXResponse:
    def __init__(self, status_code: int = 200, text: str = "", headers: "dict | None" = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class _FakeHTTPXClient:
    """httpx.Client の with 文互換 Fake。"""

    def __init__(self, response: _FakeHTTPXResponse):
        self.response = response

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, url, headers=None):
        return self.response


def _test_origin_with_fake(fake: _FakeHTTPXResponse, *, auth_headers: "dict | None" = None):
    """httpx.Client を Fake に差し替えて _test_origin を実行する。"""
    tester = CORSTester(auth_headers=auth_headers)
    with patch.object(
        CORSTester, "TIMEOUT", 1, create=True
    ), patch(
        "src.core.attack.cors_tester.httpx.Client", return_value=_FakeHTTPXClient(fake)
    ):
        return tester._test_origin(API_URL, TEST_ORIGIN)


def _reflected_headers(acao: str = TEST_ORIGIN, acac: str = "true") -> dict:
    return {
        "Access-Control-Allow-Origin": acao,
        "Access-Control-Allow-Credentials": acac,
    }


class TestCorstesterCredentialedCapture:
    def test_credentialed_reflection_captures_excerpt_and_status(self) -> None:
        """(a) 認証コンテキスト付き・反映+creds → body_excerpt 非空・実 status。"""
        fake = _FakeHTTPXResponse(200, CREDENTIALED_BODY, _reflected_headers())
        result = _test_origin_with_fake(fake, auth_headers={"Cookie": "session=dummy"})
        assert result is not None
        assert result.vulnerable is True
        assert result.misconfiguration == "origin_reflection_with_credentials"
        assert result.status == 200
        assert result.body_excerpt == CREDENTIALED_BODY

    def test_no_auth_context_captures_no_excerpt(self) -> None:
        """認証コンテキスト無しの反映+creds → excerpt を残さない（fail-closed）。"""
        fake = _FakeHTTPXResponse(200, CREDENTIALED_BODY, _reflected_headers())
        result = _test_origin_with_fake(fake, auth_headers=None)
        assert result is not None
        assert result.vulnerable is True
        assert result.body_excerpt == ""

    @pytest.mark.parametrize(
        "acao, acac, misconfig",
        [
            ("*", "", "wildcard_no_credentials"),
            ("*", "true", "wildcard_with_credentials"),
            ("null", "", "null_origin_allowed"),
            (TEST_ORIGIN, "", "origin_reflection"),
        ],
    )
    def test_non_credentialed_misconfigs_capture_no_excerpt(
        self, acao: str, acac: str, misconfig: str
    ) -> None:
        """(b) `*`/null/認証なし反映 → excerpt を残さない（認証があっても）。"""
        fake = _FakeHTTPXResponse(
            200, CREDENTIALED_BODY, _reflected_headers(acao=acao, acac=acac)
        )
        result = _test_origin_with_fake(fake, auth_headers={"Cookie": "session=dummy"})
        assert result is not None
        assert result.misconfiguration == misconfig
        assert result.body_excerpt == ""

    def test_too_short_body_captures_no_excerpt(self) -> None:
        """定型の短い本文（stub 応答等）は機微データの証拠にしない（fail-closed）。"""
        fake = _FakeHTTPXResponse(200, "ok", _reflected_headers())
        result = _test_origin_with_fake(fake, auth_headers={"Cookie": "session=dummy"})
        assert result is not None
        assert result.vulnerable is True
        assert result.body_excerpt == ""
