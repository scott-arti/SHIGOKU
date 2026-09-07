"""
OpenRedirectSpecialist Finding 証跡テスト — SGK-2026-0471 (B)

発火（result.vulnerable=True）時に、確定バー（機械フロア step3）が要求する
証跡が必ず Finding に載ることを検証する:

- impact が非空
- reproduction_steps（list[str]・3 手順）が非空
- additional_info.injected_host（注入した攻撃者ホスト）が存在
- evidence に Location ヘッダ / 3xx が保持される

ネットワークは行わない（_client.request / _verify_with_playwright を注入
スタブに差し替える既存パターン）。
PRODUCT-INDEPENDENT: generic hosts (example.com / evil.com) のみ。
"""
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from src.core.agents.swarm.injection.open_redirect import (
    OpenRedirectSpecialist,
    _request_host_is,
)
from src.core.domain.model.task import Task

TARGET_URL = "http://example.com/redirect?url=http://safe.example.com"
EXPECTED_ATTACKER_HOST = "shigoku-verify-testuuid.evil.com"
EXPECTED_LOCATION = "http://shigoku-verify-testuuid.evil.com/"


def _make_task(target: str = TARGET_URL) -> Task:
    return Task(
        id="sgk0471-open-redirect-engine-1",
        name="Open redirect engine evidence",
        target=target,
        tags=[],
        params={},
    )


class _FakeUuid:
    """test_id = str(uuid.uuid4())[:8] が "testuuid" になる固定 uuid."""

    def __str__(self) -> str:
        return "testuuidXXXXXXXX"


@pytest.mark.asyncio
async def test_firing_finding_carries_payout_grade_evidence() -> None:
    """302 + Location に攻撃者ホストが反射された発火で、impact /
    reproduction_steps / injected_host が必ず設定される。"""
    specialist = OpenRedirectSpecialist()

    mock_response = MagicMock()
    mock_response.status = 302
    mock_response.headers = {"Location": EXPECTED_LOCATION}
    mock_response.body = ""

    with patch.object(
        specialist._client, "request", return_value=mock_response
    ), patch.object(
        specialist, "_verify_with_playwright", return_value=True
    ), patch(
        "src.core.agents.swarm.injection.open_redirect.uuid.uuid4",
        return_value=_FakeUuid(),
    ):
        findings = await specialist.execute(_make_task())

    assert len(findings) == 1
    finding = findings[0]

    # B: impact / reproduction_steps が空でないこと（機械フロア step3 充足）。
    assert finding.vuln_type.value == "open_redirect"
    assert finding.impact.strip()
    assert len(finding.reproduction_steps) == 3
    assert finding.reproduction_steps[0].startswith("GET ")
    assert "302" in finding.reproduction_steps[1]
    assert EXPECTED_ATTACKER_HOST in finding.reproduction_steps[1]
    assert "ヘッドレスブラウザ" in finding.reproduction_steps[2]

    # B: additional_info の安定フィールド（payout_grade / 再現照合のキー）。
    assert finding.additional_info["injected_host"] == EXPECTED_ATTACKER_HOST
    assert finding.additional_info["redirect_to"] == EXPECTED_LOCATION
    assert EXPECTED_ATTACKER_HOST in str(finding.additional_info["payload"])

    # evidence に 3xx / Location が保持される（A①/A② の照合材料）。
    assert finding.evidence.response_status == 302
    assert finding.evidence.response_headers.get("Location") == EXPECTED_LOCATION


@pytest.mark.asyncio
async def test_non_firing_run_produces_no_findings() -> None:
    """発火しない場合は従来どおり Finding を作らない（回帰なし）。"""
    specialist = OpenRedirectSpecialist()

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.headers = {"Location": "http://safe.example.com/"}
    mock_response.body = "no reflection here"

    with patch.object(
        specialist._client, "request", return_value=mock_response
    ), patch.object(specialist, "_verify_with_playwright", return_value=False):
        findings = await specialist.execute(_make_task())

    assert findings == []


# ---------------------------------------------------------------------------
# 誤検知修正（SGK-2026-0471・実対象 E2E で判明）: 「本文への反射だけ」では
# vulnerable にならない。確定根拠は 3xx + Location(ヘッダ) 実測、または
# Playwright 実遷移のみ。
# ---------------------------------------------------------------------------


def _reflect_only_error_server(*, canonical_value: str):
    """406 エラーページ本文に攻撃者ホスト名を反射するが、リダイレクトは
    しないサーバ（実対象で観測された挙動の再現）。正規値部分文字列を
    含むペイロード（=許可リスト回避形）だけ 302 + Location 反射する。"""

    def side_effect(method, url, **kwargs):
        decoded_param = parse_qs(urlparse(url).query).get("url", [""])[0]
        response = MagicMock()
        if canonical_value in decoded_param:
            response.status = 302
            response.headers = {"Location": decoded_param}
            response.body = ""
            return response
        response.status = 406
        response.headers = {}
        # エラーページ本文に攻撃者ホスト名が反射する（リダイレクト無し）
        response.body = f"Unrecognized target URL for redirect: {decoded_param}"
        return response

    return side_effect


@pytest.mark.asyncio
async def test_body_only_reflection_on_406_is_not_confirmed() -> None:
    """naïve(406・本文反射のみ)では確定せずループが続行し、本物の
    許可リスト回避ペイロード(302)で確定する（誤検知修正の E2E 回帰）。"""
    specialist = OpenRedirectSpecialist()
    with patch.object(
        specialist._client,
        "request",
        new_callable=AsyncMock,
        side_effect=_reflect_only_error_server(
            canonical_value="http://safe.example.com"  # TARGET_URL の観測正規値
        ),
    ), patch.object(
        specialist, "_verify_with_playwright", return_value=False
    ):
        findings = await specialist.execute(_make_task())

    # 406 の本文反射ペイロードでは break せず、bypass(302) まで到達する
    assert len(findings) == 1
    finding = findings[0]
    redirect_to = finding.additional_info["redirect_to"]
    assert "_ok=" in redirect_to  # 確定したのは bypass ペイロード
    assert finding.evidence.response_status == 302
    assert finding.additional_info["injected_host"] == urlparse(redirect_to).netloc


@pytest.mark.asyncio
async def test_body_only_reflection_without_any_redirect_never_confirms() -> None:
    """リダイレクトが一切無い（全応答 406・本文反射のみ）なら vulnerable に
    ならない（本文反射のみで誤検知しない）。"""
    specialist = OpenRedirectSpecialist()

    def never_redirects(method, url, **kwargs):
        decoded_param = parse_qs(urlparse(url).query).get("url", [""])[0]
        response = MagicMock()
        response.status = 406
        response.headers = {}
        response.body = f"Unrecognized target URL for redirect: {decoded_param}"
        return response

    with patch.object(
        specialist._client,
        "request",
        new_callable=AsyncMock,
        side_effect=never_redirects,
    ), patch.object(specialist, "_verify_with_playwright", return_value=False):
        findings = await specialist.execute(_make_task())

    assert findings == []


@pytest.mark.asyncio
async def test_3xx_location_redirect_confirms_without_browser() -> None:
    """素朴な本物オープンリダイレクト（3xx + Location に攻撃者ホスト）は
    Playwright なしでも確定する（フォールバック狭小化の非回帰・既存挙動）。"""
    specialist = OpenRedirectSpecialist()

    mock_response = MagicMock()
    mock_response.status = 302
    mock_response.headers = {"Location": "http://shigoku-verify-testuuid.evil.com/"}
    mock_response.body = ""

    class _FakeUuid:
        def __str__(self) -> str:
            return "testuuidXXXXXXXX"

    with patch.object(
        specialist._client, "request", return_value=mock_response
    ), patch.object(
        specialist, "_verify_with_playwright", return_value=False
    ), patch(
        "src.core.agents.swarm.injection.open_redirect.uuid.uuid4",
        return_value=_FakeUuid(),
    ):
        findings = await specialist.execute(_make_task())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.additional_info["injected_host"] == "shigoku-verify-testuuid.evil.com"
    assert finding.evidence.response_status == 302


# ---------------------------------------------------------------------------
# 真因修正 2 回目（SGK-2026-0471）: 遷移判定を部分文字列から「ホスト一致」へ
# ---------------------------------------------------------------------------

ATTACKER_HOST = "shigoku-verify-abc.evil.com"


class TestRequestHostIs:
    """_request_host_is: リクエスト/リダイレクト先の“ホスト”が攻撃者ホスト
    と一致するときだけ True（部分文字列では誤発火しない）。"""

    def test_absolute_attacker_url_matches(self) -> None:
        assert _request_host_is(ATTACKER_HOST, f"http://{ATTACKER_HOST}/")
        assert _request_host_is(ATTACKER_HOST, f"https://{ATTACKER_HOST}/x?y=1#f")

    def test_host_comparison_is_case_insensitive(self) -> None:
        assert _request_host_is(
            ATTACKER_HOST, "http://SHIGOKU-VERIFY-ABC.EVIL.COM/path"
        )

    def test_scheme_relative_url_matches(self) -> None:
        # スキーム相対 //<attacker>/... はホストとして一致する
        assert _request_host_is(ATTACKER_HOST, f"//{ATTACKER_HOST}/next")

    def test_attacker_only_in_query_of_other_host_never_matches(self) -> None:
        """真因回帰: exploit_url 自身のクエリに攻撃者ホスト名が載るだけ
        （最初のリクエスト・実遷移なし）では遷移とみなさない。"""
        assert not _request_host_is(
            ATTACKER_HOST,
            f"http://example.com/redirect?to=https://{ATTACKER_HOST}/",
        )

    def test_attacker_only_in_path_or_query_of_other_host_never_matches(self) -> None:
        assert not _request_host_is(
            ATTACKER_HOST, f"http://legit.example.com/{ATTACKER_HOST}/x"
        )
        assert not _request_host_is(
            ATTACKER_HOST,
            f"http://legit.example.com/next?cb=https://{ATTACKER_HOST}/",
        )

    def test_internal_or_unparseable_never_matches(self) -> None:
        # 相対パス（内部）・ホスト名のみ文字列・空・パース不能 → False
        assert not _request_host_is(ATTACKER_HOST, "/internal/home")
        assert not _request_host_is(ATTACKER_HOST, ATTACKER_HOST)
        assert not _request_host_is(ATTACKER_HOST, "")
        assert not _request_host_is(ATTACKER_HOST, None)  # type: ignore[arg-type]
        assert not _request_host_is(ATTACKER_HOST, "http://[bad")
        assert not _request_host_is("", f"http://{ATTACKER_HOST}/")


@pytest.mark.asyncio
async def test_3xx_location_query_only_substring_never_confirms() -> None:
    """Location のクエリにだけ攻撃者ホスト名が出る 3xx（実際の飛び先は別
    ホスト）は vulnerable にならない（フォールバックのホスト一致化）。"""
    specialist = OpenRedirectSpecialist()

    mock_response = MagicMock()
    mock_response.status = 302
    mock_response.headers = {
        "Location": "http://legit.example.com/next?cb=http://shigoku-verify-testuuid.evil.com/"
    }
    mock_response.body = ""

    class _FakeUuid:
        def __str__(self) -> str:
            return "testuuidXXXXXXXX"

    with patch.object(
        specialist._client, "request", return_value=mock_response
    ), patch.object(
        specialist, "_verify_with_playwright", return_value=False
    ), patch(
        "src.core.agents.swarm.injection.open_redirect.uuid.uuid4",
        return_value=_FakeUuid(),
    ):
        findings = await specialist.execute(_make_task())

    # 302 だが Location のホストは legit.example.com（攻撃者ホストはクエリ
    # 内のみ）→ リダイレクト実測なし → 全ペイロードで非確定
    assert findings == []
