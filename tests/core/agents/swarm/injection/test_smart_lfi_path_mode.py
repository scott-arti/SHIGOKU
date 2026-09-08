"""
SGK-2026-0474 — smart_lfi パス方式（URL パス LFI）エンジンテスト

PRODUCT-INDEPENDENT fixtures のみ（files.example / example.com・一般ファイル名）。
カバー:
(a) クリーン不可（403）→ バイパス 200 実体の差分で vulnerable=True +
    excerpt / impact / reproduction_steps 非空
(b) クリーンでも 200（差分なし）→ False（バイパス候補に到達しない）
(c) バイパスがエラーページ 200 → False（excerpt 非保存・fail-closed）
(d) 既存パラメータ方式（/etc/passwd 検出）の非回帰 + impact/repro 非空
"""
import pytest
from unittest.mock import AsyncMock

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.smart_lfi import (
    LFI_IMPACT_TEXT,
    SmartLFIHunter,
)

TARGET = "https://files.example/private/report.bak"
LEAK_SUFFIX = "/private/report.bak%2500.md"
LEAK_URL = "https://files.example" + LEAK_SUFFIX

# 漏洩本文（JSON 風・複数行）。実体のある機密ファイル内容を模す。
LEAK_BODY = (
    "{\n"
    '  "quarterly_report": "2026-Q1",\n'
    '  "total_amount": 1250000,\n'
    '  "internal_note": "unaudited draft for board review",\n'
    '  "entries": [\n'
    '    {"region": "emea", "amount": 340000},\n'
    '    {"region": "apac", "amount": 910000}\n'
    "  ]\n"
    "}\n"
)

NOT_FOUND_BODY = (
    "<html><body><h1>404 Not Found</h1>"
    "<p>The requested document was not found on this server.</p></body></html>"
)
ERROR_PAGE_BODY = (
    "<html><head><title>Server Error</title></head><body>"
    "<h1>Internal Server Error</h1>"
    "<p>An error occurred while processing your request.</p></body></html>"
)
PASSWD_BODY = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "bin:x:1:1:bin:/bin:/sbin/nologin\n"
    "daemon:x:2:2:daemon:/sbin:/sbin/nologin\n"
)


def make_hunter(router):
    hunter = SmartLFIHunter(config={"model": "test-model"})
    hunter.smart_client.request = AsyncMock(side_effect=router)
    return hunter


def path_router(*, clean_status=403, seen=None, clean_body=""):
    """パス方式用ルータ: クリーンは clean_status、'%2500.md' サフィックスは
    LEAK_BODY、その他は 404 を返す。発火候補は 'report.bak%2500.md' のみ。"""
    if seen is None:
        seen = []

    async def router(method, url, **kwargs):
        seen.append(url)
        if url == TARGET:
            return {"status": clean_status, "body": clean_body, "error": None}
        if url.endswith(LEAK_SUFFIX):
            return {"status": 200, "body": LEAK_BODY, "error": None}
        return {"status": 404, "body": NOT_FOUND_BODY, "error": None}

    return router, seen


@pytest.mark.asyncio
async def test_path_mode_diff_clean_blocked_bypass_leaks_confirmed():
    """(a) クリーン 403 → %2500 バイパス 200 実体: vulnerable=True かつ
    excerpt / impact / reproduction_steps が非空になる。"""
    router, seen = path_router(clean_status=403)
    hunter = make_hunter(router)

    result = await hunter.run_as_tool(TARGET, params={})

    assert result["vulnerable"] is True
    assert LEAK_URL in seen, "バイパス URL が実際に GET されていること"
    assert seen[-1] == LEAK_URL, "初回の差分成立候補で停止する"
    assert result["file_marker_excerpt"], "差分成立時のみ excerpt が残る"
    assert len(result["file_marker_excerpt"]) >= 40
    assert result["file_marker_excerpt"] == hunter._path_leak_excerpt(LEAK_BODY)
    assert result["impact"] == LFI_IMPACT_TEXT
    steps = result["reproduction_steps"]
    assert isinstance(steps, list) and len(steps) >= 3
    assert all(str(s).strip() for s in steps)
    delivery = result["delivery_evidence"]
    assert delivery["request_url"] == LEAK_URL
    assert delivery["response_status"] == 200
    assert delivery["response_body"]
    assert result["style"] == "path"


@pytest.mark.asyncio
async def test_execute_builds_finding_with_impact_and_repro():
    """(a) execute() 経由の Finding に impact / reproduction_steps /
    file_marker_excerpt が設定され、evidence はバイパス URL を指す。"""
    router, seen = path_router(clean_status=403)
    hunter = make_hunter(router)
    task = Task(id="lfi-path-a", name="lfi", target=TARGET, params={})

    findings = await hunter.execute(task)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vuln_type.value == "lfi"
    assert finding.impact
    assert finding.reproduction_steps and all(
        str(s).strip() for s in finding.reproduction_steps
    )
    info = finding.additional_info
    assert info.get("file_marker_excerpt")
    assert len(info["file_marker_excerpt"]) >= 40
    assert info.get("payload") == LEAK_SUFFIX
    assert finding.evidence.request_url == LEAK_URL
    assert finding.evidence.response_status == 200
    assert finding.evidence.response_body
    assert LEAK_URL in seen


@pytest.mark.asyncio
async def test_path_mode_clean_200_no_diff_false():
    """(b) クリーンでも 200（差分なし）→ False。バイパス候補は試さない。"""
    router, seen = path_router(clean_status=200, clean_body="<html>ok page</html>")
    hunter = make_hunter(router)
    hunter.run_loop = AsyncMock(return_value={"status": "completed"})

    result = await hunter.run_as_tool(TARGET, params={})

    assert result["vulnerable"] is False
    assert result["file_marker_excerpt"] == ""
    assert seen == [TARGET], "クリーン 200 なら追加リクエストを出さない"


@pytest.mark.asyncio
async def test_path_mode_error_page_200_false():
    """(c) バイパスがエラーページ 200 → False（excerpt 非保存・fail-closed）。"""
    seen = []

    async def router(method, url, **kwargs):
        seen.append(url)
        if url == TARGET:
            return {"status": 403, "body": "Forbidden", "error": None}
        return {"status": 200, "body": ERROR_PAGE_BODY, "error": None}

    hunter = make_hunter(router)
    hunter.run_loop = AsyncMock(return_value={"status": "completed"})

    result = await hunter.run_as_tool(TARGET, params={})

    assert result["vulnerable"] is False
    assert result["file_marker_excerpt"] == ""
    assert len(seen) > 1, "エラーページ 200 の候補は評価される"


@pytest.mark.asyncio
async def test_parameter_mode_passwd_detection_non_regression():
    """(d) 既存パラメータ方式 /etc/passwd 検出の非回帰 + impact/repro 非空。"""
    seen = []

    async def router(method, url, **kwargs):
        seen.append(url)
        return {"status": 200, "body": PASSWD_BODY, "error": None}

    hunter = make_hunter(router)
    target = "http://example.com/view.php?file=test.txt"

    result = await hunter.run_as_tool(
        target, params={"method": "GET", "_auth": {"auth_headers": {}, "cookies": ""}}
    )

    assert result["vulnerable"] is True
    assert result["param"] == "file"
    assert result["file_marker_excerpt"].startswith("root:x:0:0:")
    assert result["impact"] == LFI_IMPACT_TEXT
    assert isinstance(result["reproduction_steps"], list) and len(result["reproduction_steps"]) >= 3
    assert all(str(s).strip() for s in result["reproduction_steps"])
    # パラメータ注入経路（path 書き換えではない）で検出されている。
    assert any("file=" in u for u in seen)
