"""
OpenRedirectSpecialist クロール由来正規値テスト — SGK-2026-0472

検査対象 URL 自身に正規値が無い（original_value 空）とき、manager がクロール在庫
から task.params['allowlisted_redirect_values'] として渡した正規値を部分文字列と
する許可リスト回避ペイロードで検出できることを検証する。

- original_value 非空 → 従来どおり original を優先（SGK-2026-0471 挙動・回帰禁止）。
- どちらも無し → 素朴テンプレートのみ（0471 不変）。
- 発火判定・確定・ホスト一致（_request_host_is）は無改変のまま。

PRODUCT-INDEPENDENT: generic hosts（example.org / evil.com）のみ。
ネットワークなし（_client.request / _verify_with_playwright を注入スタブに
差し替える既存パターン）。
"""
import re
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from src.core.agents.swarm.injection.open_redirect import OpenRedirectSpecialist
from src.core.domain.model.task import Task

# クロール在庫由来の「アプリの正規リダイレクト値」（製品文字列なし）。
CRAWL_VALUE = "https://accounts.example.org/session/return"
OTHER_CRAWL_VALUE = "https://accounts.example.org/other"
TOKEN_HOST_PATTERN = re.compile(r"shigoku-verify-[0-9a-f]{8}\.evil\.com")

# url パラメータ値が空白のみ: パラメータは検出されるが、strip 後の正規値は空。
TARGET_EMPTY_ORIGINAL = "http://example.com/redirect?url=%20"
# 従来どおり対象 URL 自身に正規値が載っているケース（0471 経路）。
TARGET_WITH_ORIGINAL = (
    "http://example.com/redirect?url=https%3A%2F%2Faccounts.example.org"
    "%2Fsession%2Freturn"
)


def _make_task(target: str = TARGET_EMPTY_ORIGINAL, params: dict | None = None) -> Task:
    return Task(
        id="sgk0472-crawled-values-1",
        name="Open redirect crawled values",
        target=target,
        tags=[],
        params=params or {},
    )


def _allowlist_style_server(*, canonical_value: str, seen_values: list | None = None):
    """許可リスト風応答スタブ: リダイレクト先に canonical_value の部分文字列が
    含まれなければ 406（弾く）。含んでいれば 302 + Location 反射。"""

    def side_effect(method, url, **kwargs):
        decoded_param = parse_qs(urlparse(url).query).get("url", [""])[0]
        if seen_values is not None:
            seen_values.append(decoded_param)
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


# ---------------------------------------------------------------------------
# _build_payloads
# ---------------------------------------------------------------------------


class TestBuildPayloadsCrawled:
    def _bypass_slice(self, specialist, payloads):
        """素朴テンプレートの後ろに付く回避形ペイロード列を返す。"""
        return payloads[len(specialist.REDIRECT_PAYLOAD_TEMPLATES):]

    def test_crawled_values_generate_bypass_payloads_when_original_empty(self) -> None:
        specialist = OpenRedirectSpecialist()
        payloads = specialist._build_payloads("", [CRAWL_VALUE])

        naive = len(specialist.REDIRECT_PAYLOAD_TEMPLATES)
        bypass = self._bypass_slice(specialist, payloads)
        assert len(payloads) == naive + 3
        assert len(bypass) == 3
        hosts = []
        for payload, verify_host in payloads:
            assert TOKEN_HOST_PATTERN.fullmatch(verify_host)
            assert verify_host not in hosts
            hosts.append(verify_host)
        for payload, verify_host in bypass:
            # 攻撃者ホスト基点 + クロール正規値が部分文字列として載る
            assert payload.startswith(f"https://{verify_host}/")
            assert CRAWL_VALUE in payload
        # 3 形態: query / fragment / path
        bypass_payloads = [p for p, _ in bypass]
        assert any("?_ok=" in p for p in bypass_payloads)
        assert any("#" in p for p in bypass_payloads if "?_ok=" not in p)
        assert len(bypass_payloads) == 3

    def test_crawled_values_capped_at_first_three(self) -> None:
        specialist = OpenRedirectSpecialist()
        many = [
            f"https://accounts.example.org/legit-{i}"
            for i in range(5)
        ]
        payloads = specialist._build_payloads("", many)

        naive = len(specialist.REDIRECT_PAYLOAD_TEMPLATES)
        bypass = self._bypass_slice(specialist, payloads)
        # 過剰試行回避: 先頭 3 値 × 3 形態のみ
        assert len(payloads) == naive + 9
        joined = "|".join(p for p, _ in bypass)
        assert "legit-0" in joined and "legit-1" in joined and "legit-2" in joined
        assert "legit-3" not in joined and "legit-4" not in joined

    def test_original_value_preferred_over_crawled(self) -> None:
        """original_value 非空ならクロール値は使われない（0471 挙動・優先）。"""
        specialist = OpenRedirectSpecialist()
        payloads = specialist._build_payloads(CRAWL_VALUE, [OTHER_CRAWL_VALUE])

        naive = len(specialist.REDIRECT_PAYLOAD_TEMPLATES)
        bypass = self._bypass_slice(specialist, payloads)
        assert len(payloads) == naive + 3
        joined = "|".join(p for p, _ in bypass)
        assert CRAWL_VALUE in joined
        assert OTHER_CRAWL_VALUE not in joined

    def test_naive_only_when_no_sources(self) -> None:
        specialist = OpenRedirectSpecialist()
        for crawled in (None, [], ["   "], [""]):
            payloads = specialist._build_payloads("", crawled)
            assert len(payloads) == len(specialist.REDIRECT_PAYLOAD_TEMPLATES)
            joined = "|".join(p for p, _ in payloads)
            assert "_ok=" not in joined


# ---------------------------------------------------------------------------
# エンジン発火: クロール由来正規値が部分文字列になった回避ペイロード
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawled_value_bypass_fires_when_original_empty() -> None:
    """対象 URL 自身の正規値が空でも、クロール由来の正規値から生成した
    許可リスト回避ペイロードで発火する（injected_host は当該試行の
    verify_host・redirect_to に正規値が部分文字列として載る）。"""
    specialist = OpenRedirectSpecialist()
    task = _make_task(params={"allowlisted_redirect_values": [CRAWL_VALUE]})

    with patch.object(
        specialist._client,
        "request",
        new_callable=AsyncMock,
        side_effect=_allowlist_style_server(canonical_value=CRAWL_VALUE),
    ), patch.object(specialist, "_verify_with_playwright", return_value=True):
        findings = await specialist.execute(task)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vuln_type.value == "open_redirect"
    redirect_to = finding.additional_info["redirect_to"]
    injected_host = finding.additional_info["injected_host"]
    assert CRAWL_VALUE in redirect_to
    assert "_ok=" in redirect_to  # 確定したのは回避形（クロール正規値流用）
    assert urlparse(redirect_to).netloc == injected_host
    assert TOKEN_HOST_PATTERN.fullmatch(injected_host)
    assert finding.evidence.response_status == 302


@pytest.mark.asyncio
async def test_original_value_still_prioritized_over_crawled() -> None:
    """対象 URL 自身に正規値があるときは従来どおりそれを優先する
    （クロール値は一切試行されない・SGK-2026-0471 挙動の回帰禁止）。"""
    specialist = OpenRedirectSpecialist()
    seen_values: list[str] = []
    task = _make_task(
        target=TARGET_WITH_ORIGINAL,
        params={"allowlisted_redirect_values": [OTHER_CRAWL_VALUE]},
    )

    with patch.object(
        specialist._client,
        "request",
        new_callable=AsyncMock,
        side_effect=_allowlist_style_server(
            canonical_value=CRAWL_VALUE, seen_values=seen_values
        ),
    ), patch.object(specialist, "_verify_with_playwright", return_value=True):
        findings = await specialist.execute(task)

    # 許可リストは「対象 URL 自身の正規値」だけを許可 → original 経路で発火
    assert len(findings) == 1
    finding = findings[0]
    redirect_to = finding.additional_info["redirect_to"]
    assert CRAWL_VALUE in redirect_to
    # クロール値は試行ペイロードにも Location にも一切現れない
    assert OTHER_CRAWL_VALUE not in redirect_to
    assert all(OTHER_CRAWL_VALUE not in seen for seen in seen_values)
    assert urlparse(redirect_to).netloc == finding.additional_info["injected_host"]


@pytest.mark.asyncio
async def test_no_crawl_values_no_bypass_against_allowlist_server() -> None:
    """original_value 空かつクロール値も無し → 素朴のみ。許可リスト風サーバ
    では発火しない（fail-closed・0471 不変）。"""
    specialist = OpenRedirectSpecialist()

    with patch.object(
        specialist._client,
        "request",
        new_callable=AsyncMock,
        side_effect=_allowlist_style_server(canonical_value=CRAWL_VALUE),
    ), patch.object(specialist, "_verify_with_playwright", return_value=True):
        findings = await specialist.execute(_make_task())

    assert findings == []
