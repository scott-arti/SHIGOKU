"""
SGK-2026-0459: PlaywrightCrawler 能動保存sink発見（4手）+ browser-path GET-only 境界のユニットテスト。

対象: src/tools/custom/playwright_recon.py の
  - 4手: 棚卸し(_inventory_surfaces) → 差分検知で隠れ入力面(_list_click_candidates/_click_and_diff)
    → 面ごと一意マーカー+送信(_try_surface/_submit_surface) → 非GET書き込み捕捉(_derive_save_endpoints)
  - GET-only 境界: _route_guard_decision / _make_route_guard / _path_has_skip_token

製品非依存: 対象 URL・面名・route は stub のみ（特定製品/selector/route の焼き込みなし）。
判断は入力面種別・DOM差分・包含/近接・マーカー往復のみ（テストはそれを直接観測する）。

T1: 4手が任意 stub で機能 + 到達不可は「未発見」(save_endpoints 空)。
T3: browser-path GET-only（許可ホスト限定・危険動詞・機微パス・件数上限）。
T5: 2つ目の stub/別ホストでも機能（Juice Shop 特化でない構造担保）。
"""

import re
from types import SimpleNamespace
from urllib.parse import urljoin

import pytest

from src.tools.custom.playwright_recon import PlaywrightCrawler

MARKER_RE = re.compile(r"^sgk[0-9a-fA-F]{8}$")

DEFAULT_SKIP_TOKENS = ["/admin", "/users", "/profile", "/account", "/settings", "/password"]
ALLOWED_HOSTS = {"localhost", "127.0.0.1"}


def make_budgets(**overrides):
    b = {
        "get_only": False,
        "active_post": True,
        "allowed_hosts": ["127.0.0.1", "localhost"],
        "max_writes": 5,
        "max_writes_per_page": 2,
        "max_reveal_clicks": 8,
        "reveal_depth": 2,
        "reveal_time_budget_ms": 20000,
        "reveal_settle_ms": 2500,
        "submit_attempts": 3,
        "skip_path_tokens": list(DEFAULT_SKIP_TOKENS),
    }
    b.update(overrides)
    return b


def make_results(**overrides):
    r = {
        "urls": {
            "http://localhost:9000/api/save",
            "http://localhost:9000/items",
            "http://evil.example.com/other",
        },
        "write_requests": [],
        "marker_records": [],
        "save_endpoints": [],
        "errors": [],
    }
    r.update(overrides)
    return r


# ---------------------------------------------------------------------------
# Fake Playwright page: JS 文字列の特徴をキーに、4手が使う evaluate を模倣する。
# ---------------------------------------------------------------------------


class FakeElement:
    def __init__(self, click_effect=None):
        self._click_effect = click_effect

    async def click(self, **kwargs):
        if self._click_effect:
            self._click_effect()
        return None


class FakeKeyboard:
    def __init__(self):
        self.pressed = []

    async def press(self, key):
        self.pressed.append(key)


class FakePage:
    """4手が使う Playwright Page の最小 fake。

    - evaluate(js, *args) は JS 文字列の特徴で振る舞いを分岐
    - surfaces / click_candidates / submit_plans / reveal はテストが注入
    - requestSubmit/KeyboardEvent 時は write_requests へ非GET書き込みを追加
      （本物では on_request が捕捉する。ここでは fake が結果 dict へ書き込む）
    """

    def __init__(self, results, *, url="http://localhost:9000/", surfaces=None,
                 click_candidates=None, submit_plans=None, reveal=None,
                 write_on_submit=True, write_url=None, write_method="POST",
                 reveal_delay_timeouts=0, overlay_delay_timeouts=None):
        self.results = results
        self.url = url
        self.surfaces = [dict(s) for s in (surfaces or [])]
        self.click_candidates = [dict(c) for c in (click_candidates or [])]
        self.submit_plans = {k: dict(v) for k, v in (submit_plans or {}).items()}
        self.reveal = {k: [dict(s) for s in v] for k, v in (reveal or {}).items()}
        self.write_on_submit = write_on_submit
        self.write_url = write_url or (url.rstrip("/") + "/api/save")
        self.write_method = write_method
        self.keyboard = FakeKeyboard()
        self.filled = {}
        self.go_back_called = 0
        # SGK-2026-0459 適応待ち検証用: reveal は即時でなく N 回目の
        # wait_for_timeout 後・または overlay が N 回目以降に見える
        self.reveal_delay_timeouts = max(0, int(reveal_delay_timeouts or 0))
        self.overlay_delay_timeouts = overlay_delay_timeouts
        self.overlay_visible = False
        self.timeout_calls = 0
        self._pending_reveals = {}

    async def evaluate(self, js, *args):
        s = str(js)
        # generic dialog/overlay indicator (adaptive wait)
        if 'role="dialog"' in s or "aria-modal" in s or "dialog[open]" in s:
            return bool(self.overlay_visible)
        # sids snapshot (hand b の差分用)
        if "Array.from(document.querySelectorAll('[data-shigoku-surface-id]')" in s:
            return [x["sid"] for x in self.surfaces]
        # inventory (hand a)
        if "data-shigoku-surface-id" in s and "getComputedStyle" in s:
            return [dict(x) for x in self.surfaces]
        # click candidates (hand b)
        if "data-shigoku-click-id" in s and "aria-haspopup" in s:
            return [dict(x) for x in self.click_candidates]
        # submit plan (hand c: form / container / enter)
        if "closest('form')" in s:
            sid = args[0] if args else ""
            return dict(self.submit_plans.get(sid, {"kind": "enter"}))
        # fill (hand c) — 実装は単一引数 [sid, marker] で渡す（Playwright は1引数のみ）
        if "isContentEditable" in s:
            sid, marker = args[0]
            self.filled[sid] = marker
            return True
        # form submit (hand c/d)
        if "requestSubmit" in s:
            sid = args[0] if args else ""
            if self.write_on_submit and sid in self.filled:
                marker = self.filled[sid]
                write_url = self._write_url_for(sid)
                self.results["write_requests"].append({
                    "url": write_url,
                    "method": self.write_method,
                    "post_data": f"message={marker}&author=t",
                    "content_type": "application/x-www-form-urlencoded",
                })
            return True
        # enter submit fallback (hand c/d)
        if "KeyboardEvent" in s:
            sid = args[0] if args else ""
            if self.write_on_submit and sid in self.filled:
                marker = self.filled[sid]
                write_url = self._write_url_for(sid)
                self.results["write_requests"].append({
                    "url": write_url,
                    "method": self.write_method,
                    "post_data": f"message={marker}&author=t",
                    "content_type": "application/x-www-form-urlencoded",
                })
            return True
        return None

    def _write_url_for(self, sid: str) -> str:
        """面の submit plan の action から書き込み URL を導出する（fake 版）。"""
        plan = self.submit_plans.get(sid) or {}
        action = plan.get("action") or ""
        if action:
            return urljoin(self.url.rstrip("/") + "/", action)
        return self.write_url

    async def query_selector(self, selector):
        cid_match = re.search(r"data-shigoku-click-id='([^']+)'", selector or "")
        if cid_match:
            cid = cid_match.group(1)

            def _reveal_effect():
                if self.reveal_delay_timeouts > 0:
                    self._pending_reveals[cid] = [dict(s) for s in self.reveal.get(cid, [])]
                else:
                    for new_surf in self.reveal.get(cid, []):
                        if new_surf not in self.surfaces:
                            self.surfaces.append(dict(new_surf))

            return FakeElement(_reveal_effect)
        sid_match = re.search(r"data-shigoku-submit-id='([^']+)'", selector or "")
        if sid_match:
            def _button_effect():
                for sid, marker in list(self.filled.items()):
                    if self.write_on_submit:
                        self.results["write_requests"].append({
                            "url": self.write_url,
                            "method": self.write_method,
                            "post_data": f"message={marker}&author=t",
                            "content_type": "application/x-www-form-urlencoded",
                        })
            return FakeElement(_button_effect)
        return None

    async def wait_for_load_state(self, *a, **k):
        return None

    async def wait_for_timeout(self, *a, **k):
        self.timeout_calls += 1
        if self._pending_reveals and self.timeout_calls >= self.reveal_delay_timeouts:
            for cid, surfs in list(self._pending_reveals.items()):
                for new_surf in surfs:
                    if new_surf not in self.surfaces:
                        self.surfaces.append(dict(new_surf))
            self._pending_reveals.clear()
        if self.overlay_delay_timeouts is not None and self.timeout_calls >= self.overlay_delay_timeouts:
            self.overlay_visible = True
        return None

    async def go_back(self, *a, **k):
        self.go_back_called += 1
        return None


# ---------------------------------------------------------------------------
# T1: 4手の能動発見が任意 stub で機能する
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_t1_visible_surface_inventory_marker_submit_write_capture():
    """可視 surface（textarea）→ 一意マーカー投入 → form 送信 → 非GET書き込み
    と項目名（message/author）を捕捉し、save_endpoint を1件導出する。"""
    crawler = PlaywrightCrawler()
    results = make_results()
    page = FakePage(
        results,
        url="http://localhost:9000/",
        surfaces=[{"sid": "sgk-surface-1", "tag": "textarea", "type": "",
                   "name": "message", "placeholder": "", "text": ""}],
        submit_plans={"sgk-surface-1": {"kind": "form", "action": "/api/save",
                                        "method": "post"}},
    )
    await crawler._run_active_save_discovery(page, "http://localhost:9000/", results, make_budgets())

    eps = crawler._derive_save_endpoints(results, "http://localhost:9000/", 5)
    assert len(eps) == 1
    ep = eps[0]
    assert ep["url"] == "http://localhost:9000/api/save"
    assert ep["method"] == "POST"
    assert MARKER_RE.fullmatch(ep["marker"]), "一意マーカー sgk<hex> が必要"
    # 項目名 = DOM name + 本文パース（message, author）
    assert "message" in ep["fields"] and "author" in ep["fields"]
    assert ep["source_page"] == "http://localhost:9000/"
    # revisit_urls は同一オリジンのみ・書き込み URL 自身は除外
    assert "http://localhost:9000/items" in ep["revisit_urls"]
    assert "http://evil.example.com/other" not in ep["revisit_urls"]
    assert ep["url"] not in ep["revisit_urls"]


@pytest.mark.asyncio
async def test_t1_reveal_hidden_surface_by_click_diff():
    """クリック前後の入力面集合の差分で隠れ surface が出現 → 面ごとに異なる
    マーカーで送信 → 2件の save_endpoint を捕捉（多段到達）。"""
    crawler = PlaywrightCrawler()
    results = make_results()
    page = FakePage(
        results,
        url="http://localhost:9000/",
        surfaces=[{"sid": "sgk-surface-1", "tag": "textarea", "type": "",
                   "name": "message", "placeholder": "", "text": ""}],
        click_candidates=[{"cid": "sgk-click-1", "tag": "button", "text": "open", "score": 20}],
        reveal={
            "sgk-click-1": [
                {"sid": "sgk-surface-2", "tag": "textarea", "type": "",
                 "name": "comment", "placeholder": "", "text": ""}
            ]
        },
        submit_plans={
            "sgk-surface-1": {"kind": "form", "action": "/api/save", "method": "post"},
            "sgk-surface-2": {"kind": "form", "action": "/api/comments", "method": "post"},
        },
    )
    await crawler._run_active_save_discovery(page, "http://localhost:9000/", results, make_budgets())

    eps = crawler._derive_save_endpoints(results, "http://localhost:9000/", 5)
    assert len(eps) == 2
    urls = {ep["url"] for ep in eps}
    assert "http://localhost:9000/api/save" in urls
    assert "http://localhost:9000/api/comments" in urls
    markers = [ep["marker"] for ep in eps]
    assert len(set(markers)) == 2, "面ごとに異なるマーカーが必要"
    assert all(MARKER_RE.fullmatch(m) for m in markers)
    # 差分検知でクリックした候補が使われている
    assert page.keyboard.pressed == [], "新規入力面が出たため revert していない"
    assert page.go_back_called == 0


@pytest.mark.asyncio
async def test_t1_adaptive_wait_catches_surface_appearing_after_delay():
    """クリック直後には現れず、ポーリング途中（N回目の待ち後）に出現する
    surface を適応待ちが検知する。固定1回待ち（250ms 相当）では取りこぼす
    状況の合成: 待ちが2回目に達して初めて reveal が適用される。"""
    crawler = PlaywrightCrawler()
    results = make_results()
    page = FakePage(
        results,
        url="http://localhost:9000/",
        surfaces=[{"sid": "sgk-surface-1", "tag": "textarea", "type": "",
                   "name": "message", "placeholder": "", "text": ""}],
        click_candidates=[{"cid": "sgk-click-1", "tag": "button", "text": "open", "score": 20}],
        reveal={
            "sgk-click-1": [
                {"sid": "sgk-surface-2", "tag": "textarea", "type": "",
                 "name": "comment", "placeholder": "", "text": ""}
            ]
        },
        submit_plans={
            "sgk-surface-1": {"kind": "form", "action": "/api/save", "method": "post"},
            "sgk-surface-2": {"kind": "form", "action": "/api/comments", "method": "post"},
        },
        reveal_delay_timeouts=2,  # クリック後、2回目のポーリング待ちで初めて出現
    )
    await crawler._run_active_save_discovery(page, "http://localhost:9000/", results,
                                             make_budgets(reveal_settle_ms=2500))

    # 適応待ちが複数回ポーリングした（固定1回待ちでは取りこぼす状況）
    assert page.timeout_calls >= 2

    eps = crawler._derive_save_endpoints(results, "http://localhost:9000/", 5)
    assert len(eps) == 2
    urls = {ep["url"] for ep in eps}
    assert "http://localhost:9000/api/save" in urls
    assert "http://localhost:9000/api/comments" in urls
    assert page.keyboard.pressed == [], "遅延出現の新規入力面を検知したため revert しない"
    assert page.go_back_called == 0


@pytest.mark.asyncio
async def test_t1_adaptive_wait_no_reveal_reverts_escape():
    """クリック後何も出現しない場合は従来どおり空を返し Escape 復帰する
    （適応待ちが上限までポーリングしてから変化なしと判断）。"""
    crawler = PlaywrightCrawler()
    results = make_results()
    page = FakePage(
        results,
        url="http://localhost:9000/",
        surfaces=[],  # 初期 surface なし
        click_candidates=[{"cid": "sgk-click-1", "tag": "button", "text": "open", "score": 20}],
        reveal={},  # クリックしても何も出現しない
        submit_plans={},
    )
    await crawler._run_active_save_discovery(page, "http://localhost:9000/", results,
                                             make_budgets(reveal_settle_ms=300))

    # 適応待ちが上限（ここでは 300ms 相当）までポーリングした
    assert page.timeout_calls >= 2

    eps = crawler._derive_save_endpoints(results, "http://localhost:9000/", 5)
    assert eps == [], "出現なしは未発見（偽の成功を作らない）"
    assert results["write_requests"] == []
    assert page.keyboard.pressed == ["Escape"], "変化なしは Escape で戻る"
    assert page.go_back_called == 0


@pytest.mark.asyncio
async def test_t1_unreachable_returns_no_save_endpoint():
    """書き込みが発生しない（submit しても write_requests が空）場合は
    「未発見」= save_endpoints 空。finding/dialog を捏造しない。"""
    crawler = PlaywrightCrawler()
    results = make_results()
    page = FakePage(
        results,
        url="http://localhost:9000/",
        surfaces=[{"sid": "sgk-surface-1", "tag": "textarea", "type": "",
                   "name": "message", "placeholder": "", "text": ""}],
        submit_plans={"sgk-surface-1": {"kind": "form", "action": "/api/save",
                                        "method": "post"}},
        write_on_submit=False,  # ターゲットが書き込みを受け付けない/届かない
    )
    await crawler._run_active_save_discovery(page, "http://localhost:9000/", results, make_budgets())

    eps = crawler._derive_save_endpoints(results, "http://localhost:9000/", 5)
    assert eps == [], "到達不可は未発見（偽の成功を作らない）"
    assert results["write_requests"] == []


# ---------------------------------------------------------------------------
# T3: browser-path GET-only 境界
# ---------------------------------------------------------------------------


class FakeRoute:
    def __init__(self, method, url):
        self.request = SimpleNamespace(method=method, url=url)
        self.continued = 0
        self.aborted = 0

    async def continue_(self):
        self.continued += 1

    async def abort(self):
        self.aborted += 1


def _decision(method, url, **kw):
    kw.setdefault("get_only", False)
    kw.setdefault("allowed_hosts_set", ALLOWED_HOSTS)
    kw.setdefault("skip_path_tokens", DEFAULT_SKIP_TOKENS)
    return PlaywrightCrawler._route_guard_decision(method, url, **kw)


def test_t3_route_guard_decision_matrix():
    # GET/HEAD は常に許可（get_only でも）
    assert _decision("GET", "http://localhost:9000/") == "continue"
    assert _decision("HEAD", "http://localhost:9000/", get_only=True) == "continue"
    # 許可ホスト + 非GET + 能動投稿モードON → continue（POST/PUT/PATCH）
    assert _decision("POST", "http://localhost:9000/api/save") == "continue"
    assert _decision("PUT", "http://localhost:9000/api/save") == "continue"
    assert _decision("PATCH", "http://localhost:9000/api/save") == "continue"
    # 許可ホストでも get_only=True なら非GETは abort
    assert _decision("POST", "http://localhost:9000/api/save", get_only=True) == "abort"
    # 非許可ホストは非GET abort（get_only でなくても）
    assert _decision("POST", "http://evil.example.com/api/save") == "abort"
    assert _decision("PUT", "http://evil.example.com/api/save") == "abort"
    # 機微パス（/admin /profile 等）は能動投稿スキップ → abort
    assert _decision("POST", "http://localhost:9000/admin/reset") == "abort"
    assert _decision("PUT", "http://localhost:9000/profile/edit") == "abort"
    assert _decision("POST", "http://localhost:9000/users/1") == "abort"
    # 危険動詞 DELETE は常に abort（破壊操作禁止）
    assert _decision("DELETE", "http://localhost:9000/api/save") == "abort"
    assert _decision("DELETE", "http://localhost:9000/api/save", get_only=True) == "abort"
    # ポート付き localhost / 127.0.0.1 も許可ホスト照合（hostname 比較）
    assert _decision("POST", "http://127.0.0.1:3000/api/save") == "continue"


@pytest.mark.asyncio
async def test_t3_route_guard_handler_installs_and_aborts():
    """_make_route_guard のハンドラが continue/abort を正しく発行する。"""
    crawler = PlaywrightCrawler()
    guard = crawler._make_route_guard(
        get_only=True, allowed_hosts_set=ALLOWED_HOSTS, skip_path_tokens=DEFAULT_SKIP_TOKENS
    )
    r = FakeRoute("POST", "http://localhost:9000/api/save")
    await guard(r)
    assert r.aborted == 1 and r.continued == 0

    r = FakeRoute("GET", "http://localhost:9000/")
    await guard(r)
    assert r.continued == 1 and r.aborted == 0

    guard_on = crawler._make_route_guard(
        get_only=False, allowed_hosts_set=ALLOWED_HOSTS, skip_path_tokens=DEFAULT_SKIP_TOKENS
    )
    r = FakeRoute("PUT", "http://localhost:9000/api/save")
    await guard_on(r)
    assert r.continued == 1 and r.aborted == 0

    r = FakeRoute("POST", "http://localhost:9000/admin/x")
    await guard_on(r)
    assert r.aborted == 1 and r.continued == 0


def test_t3_benign_marker_and_host_limited():
    """導出される save_endpoint のマーカーは良性 sgk<hex> のみ・書き込みは
    許可ホストの URL のみ。"""
    crawler = PlaywrightCrawler()
    results = make_results(
        urls={"http://localhost:9000/api/save", "http://localhost:9000/items"}
    )
    results["marker_records"] = [
        {"marker": "sgk12345678", "fields": ["message"], "source_page": "http://localhost:9000/"},
    ]
    results["write_requests"] = [
        {"url": "http://localhost:9000/api/save", "method": "POST",
         "post_data": "message=sgk12345678&author=t",
         "content_type": "application/x-www-form-urlencoded"},
    ]
    eps = crawler._derive_save_endpoints(results, "http://localhost:9000/", 5)
    assert len(eps) == 1
    assert MARKER_RE.fullmatch(eps[0]["marker"])
    assert eps[0]["url"].startswith("http://localhost:9000/")


def test_t3_per_sink_once_and_cap():
    """保存sinkあたり1回・同一マーカー再送スキップ（dedupe (url, method)）と
    件数上限（max_writes）を固定する。"""
    crawler = PlaywrightCrawler()
    results = make_results()
    results["marker_records"] = [
        {"marker": "sgkaaaaaaaa", "fields": ["message"], "source_page": "http://localhost:9000/"},
        {"marker": "sgkbbbbbbbb", "fields": ["message"], "source_page": "http://localhost:9000/"},
    ]
    # 同一 url+method に2マーカー → 保存sink1回（先勝ち）のみ
    results["write_requests"] = [
        {"url": "http://localhost:9000/api/save", "method": "POST",
         "post_data": "message=sgkbbbbbbbb&author=t",
         "content_type": "application/x-www-form-urlencoded"},
        {"url": "http://localhost:9000/api/save", "method": "POST",
         "post_data": "message=sgkbbbbbbbb&author=t",
         "content_type": "application/x-www-form-urlencoded"},
    ]
    eps = crawler._derive_save_endpoints(results, "http://localhost:9000/", 5)
    assert len(eps) == 1
    assert eps[0]["marker"] == "sgkbbbbbbbb"

    # 件数上限 max_writes=1
    results2 = make_results()
    results2["marker_records"] = [
        {"marker": "sgkcccccccc", "fields": ["message"], "source_page": "http://localhost:9000/"},
        {"marker": "sgkdddddddd", "fields": ["message"], "source_page": "http://localhost:9000/"},
    ]
    results2["write_requests"] = [
        {"url": "http://localhost:9000/api/a", "method": "POST",
         "post_data": "message=sgkcccccccc", "content_type": "application/x-www-form-urlencoded"},
        {"url": "http://localhost:9000/api/b", "method": "PUT",
         "post_data": "message=sgkdddddddd", "content_type": "application/x-www-form-urlencoded"},
    ]
    capped = crawler._derive_save_endpoints(results2, "http://localhost:9000/", 1)
    assert len(capped) == 1


def test_t3_dangerous_verbs_excluded_from_save_endpoints():
    """DELETE/PATCH（破壊・上書き）は save_endpoint として確定しない。"""
    crawler = PlaywrightCrawler()
    results = make_results()
    results["marker_records"] = [
        {"marker": "sgk11111111", "fields": ["message"], "source_page": "http://localhost:9000/"},
        {"marker": "sgk22222222", "fields": ["message"], "source_page": "http://localhost:9000/"},
    ]
    results["write_requests"] = [
        {"url": "http://localhost:9000/api/x", "method": "DELETE",
         "post_data": "message=sgk11111111", "content_type": "application/x-www-form-urlencoded"},
        {"url": "http://localhost:9000/api/y", "method": "PATCH",
         "post_data": "message=sgk22222222", "content_type": "application/x-www-form-urlencoded"},
    ]
    eps = crawler._derive_save_endpoints(results, "http://localhost:9000/", 5)
    assert eps == []


def test_t3_get_only_skips_form_exercise_signal():
    """host_allowed（= not get_only and host allowlisted）が OFF のとき
    能動発見・form exercise は走らない（判定関数の整合）。"""
    cfg = PlaywrightCrawler()._resolve_active_post_config(
        get_only=True, active_post=True, allowed_hosts=None,
        max_writes=None, max_writes_per_page=None, max_reveal_clicks=None,
        reveal_depth=2, reveal_time_budget_ms=None, submit_attempts=None,
    )
    assert cfg["get_only"] is True
    assert cfg["active_post"] is True
    # crawl 内の host_allowed = (not get_only) and host in allowed_hosts → False
    host_allowed = (not cfg["get_only"]) and ("localhost" in {h.lower() for h in cfg["allowed_hosts"]})
    assert host_allowed is False, "get_only=True では active-post mode は OFF になるべき"


# ---------------------------------------------------------------------------
# T5: 2つ目の stub / 別ローカル練習台でも機能（製品非依存の構造担保）
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_t5_second_stub_different_host_and_routes():
    """別ホスト（127.0.0.1:9080）・別 surface 名（subject/body）・別 route
    （/v2/comments）でも4手が機能する。Juice Shop 特化でないことを担保。"""
    crawler = PlaywrightCrawler()
    results = make_results(
        urls={"http://127.0.0.1:9080/v2/comments", "http://127.0.0.1:9080/topics"}
    )
    page = FakePage(
        results,
        url="http://127.0.0.1:9080/",
        surfaces=[{"sid": "sgk-surface-9", "tag": "input", "type": "text",
                   "name": "subject", "placeholder": "", "text": ""}],
        submit_plans={"sgk-surface-9": {"kind": "form", "action": "/v2/comments",
                                        "method": "post"}},
        write_url="http://127.0.0.1:9080/v2/comments",
    )
    await crawler._run_active_save_discovery(page, "http://127.0.0.1:9080/", results, make_budgets())

    eps = crawler._derive_save_endpoints(results, "http://127.0.0.1:9080/", 5)
    assert len(eps) == 1
    ep = eps[0]
    assert ep["url"] == "http://127.0.0.1:9080/v2/comments"
    assert ep["method"] == "POST"
    assert "subject" in ep["fields"]
    assert MARKER_RE.fullmatch(ep["marker"])
    assert "http://127.0.0.1:9080/topics" in ep["revisit_urls"]


# ---------------------------------------------------------------------------
# 実ブラウザ回帰（最重要）: _try_surface の fill が page.evaluate の単一引数で
# 動くこと。修正前（(sid, marker) の2引数 evaluate → TypeError が except に握り
# 潰され fill 不発）ではこのテストが赤になる。
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_t1_real_browser_fill_and_submit_captures_write(tmp_path):
    """最小合成ページ（可視 <form><textarea name=comment>）に対し実 Playwright で
    _inventory_surfaces → _try_surface を実行し、
    (i) marker_records 1件, (ii) 非GET write_requests がマーカー付きで1件以上,
    (iii) _derive_save_endpoints が1件返す、ことを検証する。
    Playwright/Chromium 不在環境では skip。"""
    try:
        from playwright.async_api import async_playwright
    except Exception:
        pytest.skip("playwright not installed")

    import functools
    import http.server
    import threading

    # 製品非依存の合成 fixture（汎用 form/textarea のみ・製品名/selector 焼き込みなし）
    fixture_html = (
        "<!doctype html><html><head><meta charset='utf-8'></head><body>"
        "<form action='' method='post'><textarea name='comment'></textarea>"
        "<button type='submit'>Send</button></form></body></html>"
    )
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir(exist_ok=True)
    (fixture_dir / "fixture.html").write_text(fixture_html, encoding="utf-8")

    # ローカル http.server（file:// だと form POST が飛ばない可能性があるため）
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(fixture_dir))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        page_url = f"http://127.0.0.1:{port}/fixture.html"

        crawler = PlaywrightCrawler()
        results = make_results()
        budgets = make_budgets()
        state = {"sent_markers": set(), "confirmed": 0}

        browser = None
        try:
            async with async_playwright() as p:
                try:
                    browser = await p.chromium.launch(headless=True)
                except Exception as e:
                    pytest.skip(f"chromium unavailable: {e}")
                context = await browser.new_context()
                page = await context.new_page()

                # crawl() と同じ write 捕捉（非GET + body のみ）
                async def on_request(request):
                    if request.method in ("GET", "HEAD"):
                        return
                    try:
                        post_data = request.post_data
                    except Exception:
                        post_data = None
                    if post_data:
                        results["write_requests"].append({
                            "url": request.url,
                            "method": request.method,
                            "post_data": post_data,
                            "content_type": str((request.headers or {}).get("content-type", "") or ""),
                        })

                page.on("request", on_request)
                await page.goto(page_url, wait_until="domcontentloaded")

                # (a) 棚卸し（タグ付け）: fixture の textarea が1件見える
                surfaces = await crawler._inventory_surfaces(page)
                assert len(surfaces) == 1, f"fixture textarea を1件検出するはず（実際: {len(surfaces)}）"
                surf = surfaces[0]
                assert surf["name"] == "comment"

                # (c) 一意マーカー投入 + 送信（修正前はここで fill 不発）
                await crawler._try_surface(page, surf, page_url, results, state, budgets)

                # (i) fill 成功 → marker_records 1件
                assert len(results["marker_records"]) == 1, f"marker_records: {results['marker_records']}"
                marker = results["marker_records"][0]["marker"]
                assert MARKER_RE.fullmatch(marker)

                # (ii) 非GET write_requests がマーカー付きで1件以上
                assert results["write_requests"], "write_requests が空（fill 失敗 or 送信不発）"
                assert any(marker in str(wr.get("post_data") or "") for wr in results["write_requests"])
                assert all(wr["method"] in ("POST", "PUT", "PATCH", "DELETE") for wr in results["write_requests"])

                # (iii) save_endpoint が1件導出（marker 往復のみ）
                eps = crawler._derive_save_endpoints(results, page_url, 5)
                assert len(eps) >= 1
                assert eps[0]["method"] == "POST"
                assert MARKER_RE.fullmatch(eps[0]["marker"])
                assert "comment" in eps[0]["fields"]
        finally:
            if browser:
                await browser.close()
    finally:
        server.shutdown()
        server.server_close()
