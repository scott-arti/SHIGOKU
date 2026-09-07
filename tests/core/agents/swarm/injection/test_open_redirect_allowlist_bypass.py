"""
OpenRedirectSpecialist 許可リスト回避ペイロードテスト — SGK-2026-0471 (B')

飛び先許可リスト（正規値の部分文字列チェック）で守られた redirect パラ
メータに対し、攻撃者ホストを基点に「runtime 観測した元パラメータ値」を
付したペイロードで検出できることを検証する。

- _build_payloads: 素朴テンプレート（既存）→ 許可リスト回避形の順で
  (payload, verify_host) 対を返す。original_value が空なら素朴のみ。
  正規値はハードコードせず runtime のパラメータ値から観測する。
- エンジン発火: 素朴ペイロードを 406 で弾き、正規値部分文字列を含む
  ペイロードだけ 302 + Location 反射する許可リスト風サーバを注入スタブで
  再現し、Finding の injected_host / redirect_to が当該試行の
  verify_host / 観測 Location になることを確認する。

PRODUCT-INDEPENDENT: generic hosts のみ（example.org / evil.com）。
ネットワークなし（_client.request / _verify_with_playwright を注入スタブ
に差し替える既存パターン）。
"""
import re
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from src.core.agents.swarm.injection.open_redirect import OpenRedirectSpecialist
from src.core.domain.model.task import Task

# runtime 観測値として扱う「アプリの正規リダイレクト値」（製品文字列なし）。
CANONICAL_VALUE = "https://accounts.example.org/session/return"
TOKEN_HOST_PATTERN = re.compile(r"shigoku-verify-[0-9a-f]{8}\.evil\.com")

TARGET_URL = (
    "http://example.com/redirect?url=https%3A%2F%2Faccounts.example.org"
    "%2Fsession%2Freturn"
)


def _make_task(target: str = TARGET_URL) -> Task:
    return Task(
        id="sgk0471b-allowlist-bypass-1",
        name="Open redirect allowlist bypass",
        target=target,
        tags=[],
        params={},
    )


# ---------------------------------------------------------------------------
# _build_payloads
# ---------------------------------------------------------------------------


class TestBuildPayloads:
    def test_naive_only_when_original_value_empty(self) -> None:
        specialist = OpenRedirectSpecialist()
        payloads = specialist._build_payloads("")

        assert len(payloads) == len(specialist.REDIRECT_PAYLOAD_TEMPLATES)
        # 素朴テンプレートは既存順・各試行の verify_host と対応する
        hosts = []
        for (payload, verify_host), template in zip(
            payloads, specialist.REDIRECT_PAYLOAD_TEMPLATES
        ):
            assert verify_host in payload
            assert TOKEN_HOST_PATTERN.fullmatch(verify_host)
            assert "{uuid}" not in payload  # uuid は置換済み
            hosts.append(verify_host)
        # 各試行でユニークな verify_host
        assert len(set(hosts)) == len(hosts)

    def test_bypass_payloads_appended_after_naive(self) -> None:
        specialist = OpenRedirectSpecialist()
        payloads = specialist._build_payloads(CANONICAL_VALUE)

        naive = specialist.REDIRECT_PAYLOAD_TEMPLATES
        assert len(payloads) == len(naive) + 3
        hosts = []

        # 素朴分（先頭）: 既存テンプレート順を維持
        for (payload, verify_host), template in zip(payloads[: len(naive)], naive):
            assert verify_host in payload
            hosts.append(verify_host)

        # 許可リスト回避分（後続）: 攻撃者ホスト基点 + 正規値が部分文字列
        bypass = payloads[len(naive):]
        bypass_payloads = [payload for payload, _ in bypass]
        for payload, verify_host in bypass:
            assert payload.startswith(f"https://{verify_host}/")
            assert CANONICAL_VALUE in payload
            assert verify_host not in hosts
            hosts.append(verify_host)
        # 3 形態: query 付き / fragment 付き / path 付き
        assert any("?_ok=" in p for p in bypass_payloads)
        assert any("#" in p.split("/", 3)[-1] for p in bypass_payloads if "?_ok=" not in p)
        assert len(bypass_payloads) == 3

    def test_naive_only_when_original_value_blank(self) -> None:
        specialist = OpenRedirectSpecialist()
        assert len(specialist._build_payloads("   ")) == len(
            specialist.REDIRECT_PAYLOAD_TEMPLATES
        )


# ---------------------------------------------------------------------------
# 許可リスト風サーバ（注入スタブ）でのエンジン発火
# ---------------------------------------------------------------------------


def _allowlist_style_server(*, canonical_value: str):
    """許可リスト風の応答スタブ: リダイレクト先に正規値の部分文字列が
    含まれていなければ 406（弾く）。含んでいれば 302 + Location 反射
    （アプリがそのパラメータ値へリダイレクトする挙動の再現）。"""

    def side_effect(method, url, **kwargs):
        decoded_param = parse_qs(urlparse(url).query).get("url", [""])[0]
        if canonical_value not in decoded_param:
            response = MagicMock()
            response.status = 406
            response.headers = {}
            response.body = "redirect target not allowed"
            return response
        response = MagicMock()
        response.status = 302
        response.headers = {"Location": decoded_param}
        response.body = ""
        return response

    return side_effect


@pytest.mark.asyncio
async def test_bypass_payload_fires_against_allowlist_style_server() -> None:
    """素朴ペイロードが 406 で弾かれても、攻撃者ホスト + 正規値の
    部分文字列を持つ回避ペイロードで発火し、injected_host には「その
    試行の verify_host」が入る。"""
    specialist = OpenRedirectSpecialist()
    with patch.object(
        specialist._client,
        "request",
        new_callable=AsyncMock,
        side_effect=_allowlist_style_server(canonical_value=CANONICAL_VALUE),
    ), patch.object(specialist, "_verify_with_playwright", return_value=True):
        findings = await specialist.execute(_make_task())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vuln_type.value == "open_redirect"

    redirect_to = finding.additional_info["redirect_to"]
    injected_host = finding.additional_info["injected_host"]
    # Location = 当該試行の回避ペイロード（攻撃者ホスト基点・正規値付き）
    assert CANONICAL_VALUE in redirect_to
    assert urlparse(redirect_to).netloc == injected_host
    assert TOKEN_HOST_PATTERN.fullmatch(injected_host)
    # B の証跡（impact / reproduction_steps）も共通経路で埋まる
    assert finding.impact.strip()
    assert len(finding.reproduction_steps) == 3
    assert "302" in finding.reproduction_steps[1]
    # evidence に 3xx / Location が保持される（A①/A② の照合材料）
    assert finding.evidence.response_status == 302
    assert finding.evidence.response_headers.get("Location") == redirect_to


@pytest.mark.asyncio
async def test_naive_payload_still_fires_first_when_server_redirects() -> None:
    """素朴なオープンリダイレクト（回避不要）は従来どおり先頭試行で
    検出される（既存挙動の非回帰）。"""
    specialist = OpenRedirectSpecialist()
    target_url = "http://example.com/redirect?url=http://safe.example.org"

    mock_response = MagicMock()
    mock_response.status = 302
    mock_response.headers = {"Location": "http://shigoku-verify-testuuid.evil.com/"}
    mock_response.body = ""

    class _FakeUuid:
        def __str__(self) -> str:
            return "testuuidXXXXXXXX"

    with patch.object(
        specialist._client, "request", return_value=mock_response
    ), patch.object(specialist, "_verify_with_playwright", return_value=True), patch(
        "src.core.agents.swarm.injection.open_redirect.uuid.uuid4",
        return_value=_FakeUuid(),
    ):
        findings = await specialist.execute(_make_task(target_url))

    assert len(findings) == 1
    finding = findings[0]
    # 素朴テンプレート（最初の試行）で発火: Location は素朴形のまま
    assert finding.additional_info["injected_host"] == "shigoku-verify-testuuid.evil.com"
    assert finding.additional_info["redirect_to"] == "http://shigoku-verify-testuuid.evil.com/"
    assert "_ok=" not in finding.additional_info["redirect_to"]


@pytest.mark.asyncio
async def test_allowlist_style_server_without_bypass_fires_nothing() -> None:
    """正規値部分文字列を含まない攻撃者ホスト直のペイロードしか試せない
    状況（=original_value が空）では発火しない（fail-closed・偽陽性なし）。"""
    specialist = OpenRedirectSpecialist()
    # パラメータ値が空のターゲット: 素朴ペイロードのみ試行される
    target_url = "http://example.com/redirect?url="

    with patch.object(
        specialist._client,
        "request",
        new_callable=AsyncMock,
        side_effect=_allowlist_style_server(canonical_value=CANONICAL_VALUE),
    ), patch.object(specialist, "_verify_with_playwright", return_value=True):
        findings = await specialist.execute(_make_task(target_url))

    assert findings == []
