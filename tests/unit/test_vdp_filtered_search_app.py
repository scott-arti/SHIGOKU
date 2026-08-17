"""
SGK-2026-0453: 実証用の的（vdp_filtered_search_app）のスモークテスト。

テスト側のみの harness（FastAPI + SQLite・入力フィルタ切替）。製品コードは
この的を一切参照しない（製品非依存・plan §H）。転送実在性は live 実証
（次段）で 0447 preflight により担保される。
"""
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

_FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "vdp_filtered_search_app"
if str(_FIXTURE_DIR) not in sys.path:
    sys.path.insert(0, str(_FIXTURE_DIR))

import app as demo_app_mod  # noqa: E402

FILTER_STRIP_QUOTE = demo_app_mod.FILTER_STRIP_QUOTE
FILTER_BLOCK_UNION = demo_app_mod.FILTER_BLOCK_UNION


def test_undefended_search_returns_rows(monkeypatch):
    monkeypatch.delenv("SHIGOKU_DEMO_FILTER", raising=False)
    client = TestClient(demo_app_mod.app)
    resp = client.get("/search", params={"q": "alpha"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert any(item["name"] == "alpha" for item in data["data"])


def test_undefended_quote_raises_sqlite_error(monkeypatch):
    """素通しの的では引用が SQLite エラーを起こし、marker 語彙の "SQLite"
    を含む応答になる（payout_grade._SQL_ERROR_PATTERNS の sql_error 発火）。"""
    monkeypatch.delenv("SHIGOKU_DEMO_FILTER", raising=False)
    client = TestClient(demo_app_mod.app)
    resp = client.get("/search", params={"q": "1'"})
    assert resp.status_code == 500
    assert "SQLite" in resp.text


def test_strip_quote_filter_removes_quote(monkeypatch):
    monkeypatch.setenv("SHIGOKU_DEMO_FILTER", FILTER_STRIP_QUOTE)
    assert demo_app_mod.apply_filter("1' OR 1=1 --", {FILTER_STRIP_QUOTE}) == "1 OR 1=1 --"
    client = TestClient(demo_app_mod.app)
    resp = client.get("/search", params={"q": "1'"})
    # 引用が除去され SQL エラーにならない（弾かれた＝妨害の signature）
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"


def test_block_union_filter_blocks_union(monkeypatch):
    monkeypatch.setenv("SHIGOKU_DEMO_FILTER", FILTER_BLOCK_UNION)
    assert demo_app_mod.is_blocked("-1' UNION SELECT 1 --", {FILTER_BLOCK_UNION}) is True
    client = TestClient(demo_app_mod.app)
    resp = client.get("/search", params={"q": "-1' UNION SELECT 1 --"})
    assert resp.status_code == 403
