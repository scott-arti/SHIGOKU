"""
InjectionManagerAgent クロール在庫からの redirect 正規値収集テスト — SGK-2026-0472

- `_crawled_redirect_values`: current_context の url_results / discovery_revisit_urls
  から、検査対象と同一オリジンの URL のクエリに載っている redirect 系パラメータ
  の値（アプリが実際に使う正規の飛び先）を収集する。判定は urlparse の構造比較と
  エンジン _find_redirect_params と同等の「名前ヒント OR 値が http(s):// / // / /
  で始まる」基準のみ。製品名・特定ホスト・特定パスのリテラルは使わない。
- `run_open_redirect_check`: 収集結果を allowlisted_redirect_values として
  OpenRedirectSpecialist の task.params へ渡す（XSS の revisit_candidates と同じ
  流儀・追加のみ・既存キーは不変）。

PRODUCT-INDEPENDENT: generic hosts（example.org）のみ。
"""
from unittest.mock import MagicMock

import pytest

from src.core.agents.swarm.injection.manager import InjectionManagerAgent

TARGET = "http://example.com/redirect?url="
SAME_ORIGIN_CANONICAL = "https://accounts.example.org/session/return"


def _manager_with_inventory(url_results=None, discovery_revisit_urls=None):
    mgr = InjectionManagerAgent.__new__(InjectionManagerAgent)
    mgr.current_context = {
        "url_results": url_results or [],
        "discovery_revisit_urls": discovery_revisit_urls or [],
        "findings": [],
        "params": {},
        "auth_headers": {},
    }
    return mgr


class TestCrawledRedirectValues:
    """_crawled_redirect_values: 同一オリジン在庫の redirect 正規値収集。"""

    def test_collects_same_origin_redirect_param_values(self) -> None:
        mgr = _manager_with_inventory(url_results=[
            # `to` は名前非該当だが、値が https:// で始まるため拾える（値ヒューリスティック）
            {"url": "http://example.com/landing?to=https%3A%2F%2Faccounts.example.org%2Fsession%2Freturn"},
            # `url` は名前ヒット（値も URL 始まり）
            {"url": "http://example.com/back?url=https%3A%2F%2Faccounts.example.org%2Fother"},
            "not-a-dict",  # 非 dict は無視
            None,
        ])
        values = mgr._crawled_redirect_values(TARGET)

        assert values == [
            "https://accounts.example.org/session/return",
            "https://accounts.example.org/other",
        ]

    def test_collects_from_discovery_revisit_urls(self) -> None:
        mgr = _manager_with_inventory(
            discovery_revisit_urls=[
                "http://example.com/extra?return=https%3A%2F%2Faccounts.example.org%2Ffrom-discovery",
                "http://example.com/plain",  # redirect 値なし → 対象外
            ]
        )
        assert mgr._crawled_redirect_values(TARGET) == [
            "https://accounts.example.org/from-discovery"
        ]

    def test_excludes_different_origin_urls(self) -> None:
        """別オリジンの URL に redirect 正規値があっても収集しない。"""
        mgr = _manager_with_inventory(
            url_results=[
                {"url": "http://other.example.com/landing?to=https%3A%2F%2Faccounts.other.example.org%2Fx"},
                {"url": "http://example.com/ok?url=https%3A%2F%2Faccounts.example.org%2Fok"},
            ],
            discovery_revisit_urls=[
                "http://other.example.com/redirect?to=https%3A%2F%2Faccounts.other.example.org%2Fy",
                "http://example.com/extra?return=https%3A%2F%2Faccounts.example.org%2Fextra",
            ],
        )
        values = mgr._crawled_redirect_values(TARGET)

        assert values == [
            "https://accounts.example.org/ok",
            "https://accounts.example.org/extra",
        ]
        assert all("other.example.org" not in v for v in values)

    def test_dedup_and_limit(self) -> None:
        """同一値は順序保持で重複排除し、limit 件で打ち切る。"""
        mgr = _manager_with_inventory(url_results=[
            {"url": "http://example.com/a?to=https%3A%2F%2Faccounts.example.org%2Fdup"},
            {"url": "http://example.com/b?url=https%3A%2F%2Faccounts.example.org%2Fdup"},
            {"url": "http://example.com/c?url=https%3A%2F%2Faccounts.example.org%2Fc1"},
            {"url": "http://example.com/d?url=https%3A%2F%2Faccounts.example.org%2Fc2"},
        ])
        values = mgr._crawled_redirect_values(TARGET, limit=2)

        # 重複は1件に潰れる: dup / c1 / c2 の順で上限 2
        assert values == [
            "https://accounts.example.org/dup",
            "https://accounts.example.org/c1",
        ]

    def test_empty_inventory_returns_empty_list(self) -> None:
        mgr = _manager_with_inventory()
        assert mgr._crawled_redirect_values(TARGET) == []

    def test_non_http_target_or_malformed_inventory_returns_empty_list(self) -> None:
        mgr = _manager_with_inventory(url_results=[
            {"url": "http://example.com/a?url=https%3A%2F%2Faccounts.example.org%2Fx"},
            {"url": "http://[bad"},
        ])
        # 非 http(s) 対象は収集しない
        assert mgr._crawled_redirect_values("ftp://example.com/x") == []
        # 解析不能な在庫 URL はスキップして他は収集する
        assert mgr._crawled_redirect_values(TARGET) == ["https://accounts.example.org/x"]


def _fake_redirect_specialist(captured: dict) -> MagicMock:
    """execute_with_retry で task.params を記録して空結果を返すフェイク。"""

    async def _execute_with_retry(task, quick_mode: bool = False):
        captured["params"] = task.params
        return []

    fake = MagicMock()
    fake.execute_with_retry = _execute_with_retry
    return fake


@pytest.mark.asyncio
async def test_run_open_redirect_check_injects_crawled_values() -> None:
    """run_open_redirect_check がクロール由来の正規値を task.params の
    allowlisted_redirect_values としてエンジンへ渡す。"""
    captured: dict = {}
    mgr = _manager_with_inventory(url_results=[
        {"url": "http://example.com/landing?to=https%3A%2F%2Faccounts.example.org%2Fsession%2Freturn"},
    ])
    mgr.specialists = {"redirect": _fake_redirect_specialist(captured)}
    mgr._phase2_detection_mode = "phase2"

    result = await mgr.run_open_redirect_check(TARGET)

    assert captured["params"]["allowlisted_redirect_values"] == [SAME_ORIGIN_CANONICAL]
    # 既存ハンター結果整形は従来どおり（発火なし = 不検出メッセージ）
    assert result["success"] is False


@pytest.mark.asyncio
async def test_run_open_redirect_check_inventory_empty_passes_empty_list() -> None:
    """在庫が無ければ空リストを渡す（既存挙動を変えない）。"""
    captured: dict = {}
    mgr = _manager_with_inventory()
    mgr.specialists = {"redirect": _fake_redirect_specialist(captured)}
    mgr._phase2_detection_mode = "phase2"

    await mgr.run_open_redirect_check(TARGET)

    assert captured["params"]["allowlisted_redirect_values"] == []


@pytest.mark.asyncio
async def test_run_open_redirect_check_preserves_existing_key() -> None:
    """呼び出し側が allowlisted_redirect_values を明示した場合はそれを尊重
    （上書きしない・既存キー不変）。"""
    explicit = ["https://custom.example.org/explicit"]
    captured: dict = {}
    mgr = _manager_with_inventory(url_results=[
        {"url": "http://example.com/landing?to=https%3A%2F%2Faccounts.example.org%2Fsession%2Freturn"},
    ])
    mgr.specialists = {"redirect": _fake_redirect_specialist(captured)}
    mgr._phase2_detection_mode = "phase2"

    await mgr.run_open_redirect_check(TARGET, params={"allowlisted_redirect_values": explicit})

    assert captured["params"]["allowlisted_redirect_values"] == explicit
