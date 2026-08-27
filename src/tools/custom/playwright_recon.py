"""
Playwright Reconnaissance Tool
Captures dynamic API endpoints and parameters by intercepting background XHR/Fetch requests.
"""

import sys
import json
import asyncio
import logging
import secrets
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs

try:
    from playwright.async_api import async_playwright
except ImportError:
    pass

logger = logging.getLogger(__name__)

# SGK-2026-0459: generic dialog/overlay reveal indicators for the adaptive
# post-click wait. ARIA roles + native <dialog> only — no product-specific
# or Material-specific selectors baked in.
REVEAL_OVERLAY_JS = (
    "() => {"
    "const dialogs = document.querySelectorAll("
    "'[role=\"dialog\"], [role=\"alertdialog\"], [aria-modal=\"true\"], dialog[open]');"
    "for (const d of dialogs) {"
    "  const rect = d.getBoundingClientRect();"
    "  if (rect.width > 0 || rect.height > 0) return true;"
    "}"
    "return false;"
    "}"
)
REVEAL_POLL_INTERVAL_MS = 100

class PlaywrightCrawler:
    def __init__(self, proxy: Optional[Any] = None):
        # Prevent JSON serialization errors if proxy is an AgentConfig or other object
        if proxy and not isinstance(proxy, str):
            self.proxy = str(proxy)
        else:
            self.proxy = proxy

    def _same_origin(self, base_url: str, candidate_url: str) -> bool:
        base = urlparse(str(base_url or ""))
        candidate = urlparse(str(candidate_url or ""))
        return base.scheme == candidate.scheme and base.netloc == candidate.netloc

    async def _collect_internal_links(self, page, base_url: str, limit: int = 30) -> list[str]:
        links: list[str] = []
        try:
            hrefs = await page.eval_on_selector_all(
                "a[href]",
                "nodes => nodes.map(n => n.getAttribute('href')).filter(Boolean)",
            )
            if not isinstance(hrefs, list):
                return []
            for href in hrefs:
                candidate = urljoin(base_url, str(href or "").strip())
                if not candidate.startswith(("http://", "https://")):
                    continue
                if not self._same_origin(base_url, candidate):
                    continue
                if candidate in links:
                    continue
                links.append(candidate)
                if len(links) >= limit:
                    break
        except Exception:
            return links
        return links

    def _is_logout_like(self, value: str) -> bool:
        token = str(value or "").strip().lower()
        if not token:
            return False
        logout_terms = ("logout", "signout", "sign-out", "log-out", "exit", "disconnect")
        return any(term in token for term in logout_terms)

    def _is_low_value_route(self, route_url: str) -> bool:
        parsed = urlparse(str(route_url or "").strip())
        if parsed.scheme not in {"http", "https"}:
            return True
        path_lower = (parsed.path or "").lower()
        query_keys = {k.lower() for k in parse_qs(parsed.query, keep_blank_values=True).keys()}

        static_path_tokens = ("/_next/", "/static/", "/assets/", "/dist/", "/chunks/")
        static_extensions = (
            ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot",
        )
        interaction_keys = {"q", "query", "search", "id", "redirect", "url", "next", "file", "path", "page", "sort"}
        if any(token in path_lower for token in static_path_tokens):
            return True
        if any(path_lower.endswith(ext) for ext in static_extensions):
            return True
        if (parsed.path or "/").strip("/") == "" and not (query_keys & interaction_keys):
            return True
        return False

    def _score_post_login_route(self, route_url: str, context_text: str = "", method: str = "GET") -> int:
        parsed = urlparse(str(route_url or "").strip())
        if parsed.scheme not in {"http", "https"}:
            return -9999
        if self._is_logout_like(route_url):
            return -9999

        path_lower = (parsed.path or "").lower()
        query_keys = {k.lower() for k in parse_qs(parsed.query, keep_blank_values=True).keys()}
        method_upper = str(method or "GET").upper()
        signal = f"{path_lower} {str(context_text or '').lower()}"

        if self._is_low_value_route(route_url):
            return -40

        score = 0
        high_value_tokens = (
            "dashboard", "profile", "account", "settings", "order", "orders", "history",
            "payment", "wallet", "billing", "checkout", "cart", "basket",
            "message", "notification", "team", "project", "organization",
            "admin", "console", "api", "graphql", "chatbot", "genai", "review",
            "security", "password", "mfa", "2fa", "email", "address", "invoice",
            "transaction", "subscription", "plan", "ticket", "support", "activity",
            "integrations", "developer", "keys", "usage",
        )
        medium_value_tokens = ("search", "filter", "query", "detail", "view", "user")

        for token in high_value_tokens:
            if token in signal:
                score += 16
        for token in medium_value_tokens:
            if token in signal:
                score += 8

        if method_upper in {"POST", "PUT", "PATCH", "DELETE"}:
            score += 18
        if query_keys:
            score += min(10, len(query_keys) * 2)
        if "api" in parsed.path.lower() or "graphql" in parsed.path.lower():
            score += 10
        if (parsed.path or "/").strip("/") != "":
            score += 4

        return score

    async def _collect_post_login_route_hints(self, page, base_url: str, limit: int = 20) -> list[str]:
        if limit <= 0:
            return []

        selector = (
            "a[href], form[action], [data-href], [data-url], [routerlink], "
            "[data-endpoint], [data-api], [data-testid], [aria-label]"
        )
        try:
            raw_nodes = await page.evaluate(
                """(sel) => {
                    const nodes = Array.from(document.querySelectorAll(sel)).slice(0, 800);
                    return nodes.map((node) => {
                        const attrs = [
                            "href", "action", "data-href", "data-url", "routerlink",
                            "data-endpoint", "data-api"
                        ];
                        const values = [];
                        for (const attr of attrs) {
                            if (!node.getAttribute) continue;
                            const v = node.getAttribute(attr);
                            if (v) values.push({ attr, value: String(v) });
                        }
                        const text = String(node.innerText || node.textContent || "").trim().slice(0, 200);
                        const method = node.getAttribute ? String(node.getAttribute("method") || "GET") : "GET";
                        return { values, text, method };
                    });
                }""",
                selector,
            )
        except Exception:
            return []

        if not isinstance(raw_nodes, list):
            return []

        ranked: dict[str, int] = {}
        for node in raw_nodes:
            if not isinstance(node, dict):
                continue
            values = node.get("values", [])
            text = str(node.get("text", "") or "")
            method = str(node.get("method", "GET") or "GET")
            if not isinstance(values, list):
                continue
            for value_item in values:
                if not isinstance(value_item, dict):
                    continue
                attr_name = str(value_item.get("attr", "") or "").strip().lower()
                candidate = str(value_item.get("value", "") or "").strip()
                if not candidate:
                    continue

                # URL属性以外は route hint として扱わない（data-testid/aria-label 等の誤URL化を防止）。
                if attr_name not in {"href", "action", "data-href", "data-url", "routerlink", "data-endpoint", "data-api"}:
                    continue

                # API/route hint 属性の裸相対パスは、現在ページ相対ではなくルート相対として扱う。
                if (
                    attr_name in {"data-href", "data-url", "routerlink", "data-endpoint", "data-api"}
                    and not candidate.startswith(("http://", "https://", "/", "?", "#"))
                ):
                    candidate = f"/{candidate}"

                absolute = urljoin(base_url, candidate)
                if not absolute.startswith(("http://", "https://")):
                    continue
                if not self._same_origin(base_url, absolute):
                    continue
                if self._is_logout_like(absolute) or self._is_logout_like(text):
                    continue
                score = self._score_post_login_route(absolute, context_text=text, method=method)
                if score <= 0:
                    continue
                current = ranked.get(absolute, -10_000)
                if score > current:
                    ranked[absolute] = score

        ranked_items = sorted(
            ranked.items(),
            key=lambda kv: (kv[1], len(urlparse(kv[0]).path or "")),
            reverse=True,
        )
        return [url for url, _ in ranked_items[:limit]]

    async def _exercise_post_login_actions(self, page, max_actions: int = 6) -> None:
        if max_actions <= 0:
            return

        selector = (
            "button, [role='button'], [role='tab'], [aria-haspopup='menu'], "
            "[data-testid], [aria-label], input[type='submit'], [role='menuitem'], nav a[href]"
        )
        keywords = [
            "menu", "nav", "profile", "account", "settings", "order", "cart", "checkout",
            "history", "notification", "message", "dashboard", "wallet", "billing",
            "developer", "console", "api", "chat", "team", "project",
            "security", "password", "mfa", "2fa", "address", "invoice",
            "activity", "support", "ticket", "integrations", "usage", "alerts",
        ]
        try:
            action_ids = await page.evaluate(
                """({sel, maxActions, kws}) => {
                    const nodes = Array.from(document.querySelectorAll(sel)).slice(0, 500);
                    const logoutRe = /(logout|signout|sign-out|log-out|exit|disconnect)/i;
                    const items = [];
                    let idx = 0;
                    for (const node of nodes) {
                        const text = String(node.innerText || node.textContent || "").toLowerCase();
                        const attrs = [
                            node.getAttribute ? (node.getAttribute("aria-label") || "") : "",
                            node.getAttribute ? (node.getAttribute("title") || "") : "",
                            node.getAttribute ? (node.getAttribute("data-testid") || "") : "",
                            node.getAttribute ? (node.getAttribute("id") || "") : "",
                            node.getAttribute ? (node.getAttribute("name") || "") : "",
                            node.getAttribute ? (node.getAttribute("class") || "") : "",
                        ].join(" ").toLowerCase();
                        const signal = `${text} ${attrs}`.trim();
                        if (!signal || logoutRe.test(signal)) continue;
                        let score = 0;
                        for (const kw of kws) {
                            if (signal.includes(kw)) score += 6;
                        }
                        if (node.getAttribute && node.getAttribute("aria-haspopup")) score += 2;
                        const role = (node.getAttribute ? (node.getAttribute("role") || "") : "").toLowerCase();
                        if (role === "tab" || role === "button") score += 1;
                        if (score <= 0) continue;
                        const actionId = `shigoku-postlogin-${idx++}`;
                        if (node.setAttribute) node.setAttribute("data-shigoku-postlogin-id", actionId);
                        items.push({ id: actionId, score });
                    }
                    items.sort((a, b) => b.score - a.score);
                    return items.slice(0, maxActions).map((i) => i.id);
                }""",
                {"sel": selector, "maxActions": max_actions, "kws": keywords},
            )
        except Exception:
            return

        if not isinstance(action_ids, list):
            return

        clicked = 0
        for action_id in action_ids:
            if clicked >= max_actions:
                break
            action_token = str(action_id or "").strip()
            if not action_token:
                continue
            try:
                element = await page.query_selector(f"[data-shigoku-postlogin-id='{action_token}']")
                if not element:
                    continue
                await element.click(timeout=1200, force=True)
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=1200)
                except Exception:
                    pass
                await page.wait_for_timeout(220)
                clicked += 1
            except Exception:
                continue

    async def _exercise_clickables(self, page, max_clicks: int) -> None:
        if max_clicks <= 0:
            return
        selectors = "button, [role='button'], a[href], input[type='submit']"
        try:
            elements = await page.query_selector_all(selectors)
        except Exception:
            return
        clicked = 0
        for element in elements:
            if clicked >= max_clicks:
                break
            try:
                await element.click(timeout=1200, force=True)
                await page.wait_for_timeout(250)
                clicked += 1
            except Exception:
                continue

    async def _exercise_forms(self, page, max_forms: int) -> None:
        if max_forms <= 0:
            return
        try:
            forms = await page.query_selector_all("form")
        except Exception:
            return

        submitted = 0
        for form in forms:
            if submitted >= max_forms:
                break
            try:
                # text-like input にダミー値を入れて submit する
                await form.evaluate(
                    """(f) => {
                        const fields = Array.from(f.querySelectorAll('input, textarea, select'));
                        for (const field of fields) {
                            const tag = (field.tagName || '').toLowerCase();
                            const type = (field.type || '').toLowerCase();
                            if (tag === 'select') {
                                if (field.options && field.options.length > 0) field.selectedIndex = 0;
                                continue;
                            }
                            if (type === 'hidden' || type === 'checkbox' || type === 'radio' || type === 'file') continue;
                            if (type === 'email') field.value = 'test@example.com';
                            else if (type === 'password') field.value = 'Passw0rd!';
                            else if (type === 'number') field.value = '1';
                            else field.value = 'test';
                        }
                    }"""
                )
                await form.evaluate("(f) => f.requestSubmit ? f.requestSubmit() : f.submit()")
                await page.wait_for_timeout(350)
                submitted += 1
            except Exception:
                continue

    # ------------------------------------------------------------------
    # SGK-2026-0459: active save-sink discovery (behavior-based).
    # No product names, no hardcoded routes/selectors beyond generic
    # element-type selectors, no hostnames beyond settings defaults.
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_bool_setting(value: Optional[bool], default: bool) -> bool:
        """Resolve an optional bool override, falling back to the given default."""
        return default if value is None else bool(value)

    def _resolve_active_post_config(
        self,
        get_only: Optional[bool],
        active_post: Optional[bool],
        allowed_hosts: Optional[List[str]],
        max_writes: Optional[int],
        max_writes_per_page: Optional[int],
        max_reveal_clicks: Optional[int],
        reveal_depth: Optional[int],
        reveal_time_budget_ms: Optional[int],
        submit_attempts: Optional[int],
    ) -> Dict[str, Any]:
        """Resolve SGK-2026-0459 config: explicit kwargs win over settings,
        settings win over built-in defaults. Never raises."""
        try:
            from src.core.config.settings import get_settings
            s = get_settings()
        except Exception:
            s = None

        def _s(name: str, default: Any) -> Any:
            if s is None:
                return default
            try:
                return getattr(s, name, default)
            except Exception:
                return default

        return {
            "get_only": self._resolve_bool_setting(get_only, bool(_s("sealed_run_get_only", False))),
            "active_post": self._resolve_bool_setting(active_post, bool(_s("recon_active_post_enabled", False))),
            "allowed_hosts": [
                str(h) for h in (
                    allowed_hosts if allowed_hosts is not None
                    else (_s("active_post_allowed_hosts", None) or ["127.0.0.1", "localhost"])
                )
            ],
            "max_writes": int(max_writes if max_writes is not None else (_s("active_post_max_writes", 5) or 5)),
            "max_writes_per_page": int(
                max_writes_per_page if max_writes_per_page is not None
                else (_s("active_post_max_writes_per_page", 2) or 2)
            ),
            "max_reveal_clicks": int(
                max_reveal_clicks if max_reveal_clicks is not None
                else (_s("active_post_max_reveal_clicks", 8) or 8)
            ),
            "reveal_depth": max(
                1, int(reveal_depth if reveal_depth is not None else (_s("active_post_reveal_depth", 2) or 2))
            ),
            "reveal_time_budget_ms": int(
                reveal_time_budget_ms if reveal_time_budget_ms is not None
                else (_s("active_post_reveal_time_budget_ms", 20000) or 20000)
            ),
            "reveal_settle_ms": max(
                0, int(_s("active_post_reveal_settle_ms", 2500) or 2500)
            ),
            "submit_attempts": int(
                submit_attempts if submit_attempts is not None
                else (_s("active_post_submit_attempts", 3) or 3)
            ),
            "skip_path_tokens": [
                str(t) for t in (
                    _s("active_post_skip_path_tokens", None)
                    or ["/admin", "/users", "/profile", "/account", "/settings", "/password"]
                )
            ],
        }

    @staticmethod
    def _preferred_method(methods) -> str:
        """Deterministic method preference: POST > PUT > PATCH > DELETE > GET."""
        method_set = {str(m or "GET").upper() for m in (methods or set())}
        if not method_set:
            return "GET"
        for m in ("POST", "PUT", "PATCH", "DELETE", "GET"):
            if m in method_set:
                return m
        return "GET"

    @staticmethod
    def _path_has_skip_token(path: str, skip_tokens) -> bool:
        """True when *path* starts with any sensitive-path skip token."""
        path = str(path or "")
        for token in (skip_tokens or []):
            t = str(token or "").strip()
            if not t:
                continue
            if not t.startswith("/"):
                t = f"/{t}"
            if path.startswith(t):
                return True
        return False

    @staticmethod
    def _route_guard_decision(method: Optional[str], url: Optional[str], *,
                              get_only: bool, allowed_hosts_set, skip_path_tokens) -> str:
        """Browser-path GET-only boundary decision (SGK-2026-0459).

        Returns 'continue' (let the request through) or 'abort'. Fail-closed:
        GET/HEAD always pass; any other method passes ONLY when active-post
        mode is ON for the request (not get_only, host allowlisted, path not
        on the sensitive skip list). DELETE (destructive) never passes.
        """
        m = str(method or "GET").upper()
        if m in ("GET", "HEAD"):
            return "continue"
        if m == "DELETE":
            return "abort"
        parsed = urlparse(str(url or ""))
        host = str(parsed.hostname or "").lower()
        if (
            not get_only
            and host in allowed_hosts_set
            and not PlaywrightCrawler._path_has_skip_token(parsed.path or "", skip_path_tokens)
        ):
            return "continue"
        return "abort"

    def _make_route_guard(self, get_only: bool, allowed_hosts_set, skip_path_tokens):
        """Build the page.route guard handler (kept thin for testability)."""
        async def _route_guard(route):
            try:
                decision = self._route_guard_decision(
                    route.request.method,
                    route.request.url,
                    get_only=get_only,
                    allowed_hosts_set=allowed_hosts_set,
                    skip_path_tokens=skip_path_tokens,
                )
                if decision == "continue":
                    await route.continue_()
                    return
                logger.debug(
                    "Active-post GET-only boundary: aborted %s %s",
                    str(route.request.method or "GET").upper(),
                    route.request.url,
                )
                await route.abort()
            except Exception:
                try:
                    await route.abort()
                except Exception:
                    pass
        return _route_guard

    @staticmethod
    def _marker_confirmed(results: Dict[str, Any], marker: str) -> bool:
        """Hand (d): a marker is confirmed only when it round-trips inside a
        captured write request body (exact substring on the marker string)."""
        marker = str(marker or "")
        if not marker:
            return False
        for wr in results.get("write_requests") or []:
            if marker in str(wr.get("post_data") or ""):
                return True
        return False

    def _merge_field_names(self, dom_fields, post_data: str, content_type: str) -> List[str]:
        """Union of DOM name attributes and keys parsed from the write body.
        Dedupe, keep first-seen order."""
        dom = [str(f) for f in (dom_fields or []) if f]
        parsed: List[str] = []
        body = str(post_data or "")
        ct = str(content_type or "").lower()
        if body:
            if "json" in ct:
                try:
                    obj = json.loads(body)
                    if isinstance(obj, dict):
                        parsed = [str(k) for k in obj.keys()]
                except Exception:
                    parsed = []
            else:
                parsed = list(parse_qs(body, keep_blank_values=True).keys())
        out: List[str] = []
        for name in dom + parsed:
            if name and name not in out:
                out.append(name)
        return out

    def _revisit_urls(self, seen_urls, base_url: str, write_url: str, limit: int = 20) -> List[str]:
        """Same-origin URLs (urlparse structure-based) for revisiting, bounded."""
        anchor = str(write_url or base_url or "")
        out: List[str] = []
        for u in sorted(str(x or "") for x in (seen_urls or set())):
            if not u:
                continue
            if u == write_url:
                continue
            if not self._same_origin(anchor, u):
                continue
            out.append(u)
            if len(out) >= limit:
                break
        return out

    def _derive_save_endpoints(self, results: Dict[str, Any], base_url: str, max_writes: int) -> List[Dict[str, Any]]:
        """Hand (d): confirm save endpoints ONLY via marker round-trips.
        No marker in any write body -> no save endpoint (never fabricate)."""
        max_writes = max(0, int(max_writes or 0))
        if max_writes <= 0:
            return []
        write_requests = results.get("write_requests") or []
        marker_records = results.get("marker_records") or []
        seen_urls = results.get("urls") or set()
        save_endpoints: List[Dict[str, Any]] = []
        seen_keys = set()
        for record in marker_records:
            marker = str(record.get("marker") or "")
            if not marker:
                continue
            source_page = str(record.get("source_page") or base_url or "")
            dom_fields = record.get("fields") or []
            for wr in write_requests:
                post_data = str(wr.get("post_data") or "")
                if marker not in post_data:
                    continue
                url_w = str(wr.get("url") or "")
                method = str(wr.get("method") or "POST").upper()
                # Safety (SGK-2026-0459): only confirm create/update verbs as
                # save endpoints; destructive/overwrite verbs (DELETE/PATCH)
                # are never actively posted nor promoted to save endpoints.
                if method not in ("POST", "PUT"):
                    continue
                key = (url_w, method)
                if key in seen_keys:
                    continue
                save_endpoints.append({
                    "url": url_w,
                    "method": method,
                    "fields": self._merge_field_names(dom_fields, post_data, wr.get("content_type")),
                    "marker": marker,
                    "source_page": source_page,
                    "revisit_urls": self._revisit_urls(seen_urls, base_url, url_w, limit=20),
                })
                seen_keys.add(key)
                if len(save_endpoints) >= max_writes:
                    return save_endpoints
        return save_endpoints

    async def _inventory_surfaces(self, page) -> List[Dict[str, Any]]:
        """Hand (a): tag + return the visible input surfaces (textarea /
        text-like input / [contenteditable]). Tags with a unique
        data-shigoku-surface-id before returning so later diffs can compare."""
        try:
            raw = await page.evaluate(
                """() => {
                    const textLike = ['text','email','url','tel','search','password','number','date','datetime-local','time','month','week'];
                    const out = [];
                    if (typeof window.__sgkSurfaceCounter !== 'number') window.__sgkSurfaceCounter = 0;
                    const tag = (el) => {
                        let sid = el.getAttribute('data-shigoku-surface-id');
                        if (sid) return sid;
                        sid = 'sgk-surface-' + (++window.__sgkSurfaceCounter);
                        el.setAttribute('data-shigoku-surface-id', sid);
                        return sid;
                    };
                    const visible = (el) => {
                        if (el.disabled) return false;
                        const style = window.getComputedStyle(el);
                        if (style.display === 'none' || style.visibility === 'hidden') return false;
                        const rect = el.getBoundingClientRect();
                        return rect.width > 0 || rect.height > 0;
                    };
                    document.querySelectorAll('textarea').forEach((el) => {
                        if (!visible(el)) return;
                        out.push({ sid: tag(el), tag: 'textarea', type: '', name: el.getAttribute('name') || '', placeholder: el.getAttribute('placeholder') || '', text: String(el.innerText || el.textContent || '').slice(0, 200) });
                    });
                    document.querySelectorAll('input').forEach((el) => {
                        if (!visible(el)) return;
                        const t = String(el.getAttribute('type') || 'text').toLowerCase();
                        if (!textLike.includes(t)) return;
                        out.push({ sid: tag(el), tag: 'input', type: t, name: el.getAttribute('name') || '', placeholder: el.getAttribute('placeholder') || '', text: '' });
                    });
                    document.querySelectorAll('[contenteditable]').forEach((el) => {
                        if (!visible(el)) return;
                        const ce = String(el.getAttribute('contenteditable') || '').toLowerCase();
                        if (ce === 'false') return;
                        out.push({ sid: tag(el), tag: 'contenteditable', type: '', name: el.getAttribute('name') || '', placeholder: el.getAttribute('placeholder') || '', text: String(el.innerText || el.textContent || '').slice(0, 200) });
                    });
                    return out;
                }"""
            )
        except Exception:
            return []
        if not isinstance(raw, list):
            return []
        out = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            sid = str(item.get("sid") or "")
            if not sid:
                continue
            out.append({
                "sid": sid,
                "tag": str(item.get("tag") or ""),
                "type": str(item.get("type") or ""),
                "name": str(item.get("name") or ""),
                "placeholder": str(item.get("placeholder") or ""),
                "text": str(item.get("text") or ""),
            })
        return out

    async def _surface_sids(self, page) -> set:
        """Fast snapshot of the current tagged surface-id set."""
        try:
            val = await page.evaluate(
                "() => Array.from(document.querySelectorAll('[data-shigoku-surface-id]')).map((n) => n.getAttribute('data-shigoku-surface-id'))"
            )
        except Exception:
            return set()
        if not isinstance(val, list):
            return set()
        return {str(s) for s in val if s}

    async def _list_click_candidates(self, page, clicked_cids: set) -> List[Dict[str, Any]]:
        """Hand (b): scored clickable candidates (generic element types only).
        Stable per-element ids, already-clicked skipped, logout-like penalized."""
        selector = (
            "a[href], button, [role='button'], [role='tab'], [role='menuitem'], "
            "input[type='submit'], [aria-haspopup]"
        )
        try:
            raw = await page.evaluate(
                """(sel) => {
                    const nodes = Array.from(document.querySelectorAll(sel)).slice(0, 500);
                    const items = [];
                    if (typeof window.__sgkClickCounter !== 'number') window.__sgkClickCounter = 0;
                    for (const node of nodes) {
                        const text = String(node.innerText || node.textContent || '').trim();
                        let cid = node.getAttribute('data-shigoku-click-id');
                        if (!cid) {
                            cid = 'sgk-click-' + (++window.__sgkClickCounter);
                            node.setAttribute('data-shigoku-click-id', cid);
                        }
                        const role = String(node.getAttribute ? (node.getAttribute('role') || '') : '').toLowerCase();
                        const tag = String(node.tagName || '').toLowerCase();
                        let score = 0;
                        if (node.hasAttribute && node.hasAttribute('aria-haspopup')) score += 20;
                        if (role === 'tab' || role === 'menuitem' || role === 'button') score += 12;
                        if (tag === 'button' || tag === 'input') score += 8;
                        if (tag === 'a' && node.getAttribute('href')) score += 2;
                        items.push({ cid, tag, text: text.slice(0, 120), score });
                    }
                    return items;
                }""",
                selector,
            )
        except Exception:
            return []
        if not isinstance(raw, list):
            return []
        out = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            cid = str(item.get("cid") or "")
            if not cid or cid in clicked_cids:
                continue
            score = int(item.get("score") or 0)
            if self._is_logout_like(str(item.get("text") or "")):
                score -= 30
            out.append({
                "cid": cid,
                "tag": str(item.get("tag") or ""),
                "text": str(item.get("text") or ""),
                "score": score,
            })
        out.sort(key=lambda x: x["score"], reverse=True)
        return out

    async def _wait_for_reveal(self, page, before_sids: set, settle_ms: int) -> bool:
        """SGK-2026-0459: adaptive post-click wait.

        Polls at a short interval until (i) a new tagged surface appears in
        the surface set or (ii) a generic dialog/overlay indicator becomes
        visible, bounded by settle_ms per click. Returns as soon as either is
        observed so the reveal loop's overall time budget is not consumed by
        fixed waits. The poll runs the tagging inventory (not just the sids
        read) because SPA dialogs render new inputs without any prior tag —
        they only become visible to the sids diff once tagged.
        settle_ms <= 0 -> no polling (immediate return)."""
        settle_ms = max(0, int(settle_ms or 0))
        if settle_ms <= 0:
            return False
        deadline = time.monotonic() + float(settle_ms) / 1000.0
        while True:
            try:
                cur_sids = {s["sid"] for s in await self._inventory_surfaces(page)}
                if cur_sids - before_sids:
                    return True
            except Exception:
                pass
            try:
                overlay = await page.evaluate(REVEAL_OVERLAY_JS)
                if overlay:
                    return True
            except Exception:
                pass
            if time.monotonic() >= deadline:
                return False
            try:
                await page.wait_for_timeout(REVEAL_POLL_INTERVAL_MS)
            except Exception:
                return False

    async def _click_and_diff(self, page, cand: Dict[str, Any], settle_ms: int = 0) -> List[str]:
        """Hand (b): click a candidate, diff the surface set, revert on no change."""
        cid = str(cand.get("cid") or "")
        if not cid:
            return []
        try:
            url_before = page.url
        except Exception:
            url_before = ""
        before_sids = await self._surface_sids(page)
        try:
            element = await page.query_selector(f"[data-shigoku-click-id='{cid}']")
            if not element:
                return []
            await element.click(timeout=1200, force=True)
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=1500)
            except Exception:
                pass
            # SGK-2026-0459: adaptive wait — poll for a new surface or a
            # generic dialog/overlay instead of a fixed 250ms (SPA dialogs
            # render their content without a load event, so a fixed short
            # wait gives up before the input appears).
            await self._wait_for_reveal(page, before_sids, settle_ms)
        except Exception:
            return []
        after_sids = await self._surface_sids(page)
        new_sids = [s for s in after_sids if s not in before_sids]
        if not new_sids:
            # No new surface: revert (Escape first, then go_back if navigated).
            try:
                await page.keyboard.press("Escape")
            except Exception:
                pass
            try:
                if page.url != url_before:
                    await page.go_back(timeout=2000)
            except Exception:
                pass
        return new_sids

    def _submit_target_is_sensitive(self, page, submit_plan, source_url: str, skip_tokens) -> bool:
        """Safety: skip a surface when its structural write target resolves to
        a sensitive path (form action / adjacent href / current page URL)."""
        if not skip_tokens:
            return False
        candidates: List[str] = []
        plan = submit_plan or {}
        if plan.get("kind") == "form":
            action = str(plan.get("action") or "")
            if action:
                candidates.append(action)
            else:
                # action-less form posts to the current page
                try:
                    candidates.append(str(page.url))
                except Exception:
                    pass
        else:
            # container buttons / Enter fallback: unknown target -> current page
            try:
                candidates.append(str(page.url))
            except Exception:
                pass
            for href in (plan.get("hrefs") or []):
                candidates.append(str(href or ""))
        for candidate in candidates:
            if not candidate:
                continue
            try:
                absolute = urljoin(str(source_url or ""), candidate)
                if self._path_has_skip_token(urlparse(absolute).path or "", skip_tokens):
                    return True
            except Exception:
                continue
        return False

    async def _try_surface(self, page, surf: Dict[str, Any], source_url: str,
                           results: Dict[str, Any], state: Dict[str, Any],
                           budgets: Dict[str, Any]) -> None:
        """Hand (c): fill a unique marker, submit structurally, confirm via
        write_requests. Skips sensitive-path targets and already-sent markers."""
        sid = str(surf.get("sid") or "")
        if not sid:
            return
        max_writes_per_page = max(0, int(budgets.get("max_writes_per_page") or 0))
        if state.get("confirmed", 0) >= max_writes_per_page:
            return
        skip_tokens = [str(t) for t in (budgets.get("skip_path_tokens") or []) if t]

        # Structural submit handle: form / contained buttons / Enter fallback.
        submit_plan = None
        try:
            submit_plan = await page.evaluate(
                """(sid) => {
                    const el = document.querySelector('[data-shigoku-surface-id="' + sid + '"]');
                    if (!el) return null;
                    const form = el.closest ? el.closest('form') : null;
                    if (form) {
                        return { kind: 'form', action: form.getAttribute('action') || '', method: form.getAttribute('method') || 'get' };
                    }
                    let node = el.parentElement;
                    let level = 0;
                    while (node && level < 6) {
                        const btns = Array.from(node.querySelectorAll('button, input[type="submit"], [role="button"]')).filter((b) => b !== el);
                        if (btns.length > 0) {
                            const tagged = [];
                            let idx = 0;
                            for (const b of btns) {
                                let cid = b.getAttribute('data-shigoku-submit-id');
                                if (!cid) {
                                    cid = 'sgk-submit-' + Date.now() + '-' + (idx++);
                                    b.setAttribute('data-shigoku-submit-id', cid);
                                }
                                tagged.push(cid);
                            }
                            const hrefs = Array.from(node.querySelectorAll('a[href]')).map((a) => a.getAttribute('href') || '').filter(Boolean);
                            return { kind: 'container', cids: tagged, hrefs };
                        }
                        node = node.parentElement;
                    }
                    return { kind: 'enter' };
                }""",
                sid,
            )
        except Exception:
            submit_plan = None

        if skip_tokens and self._submit_target_is_sensitive(page, submit_plan, source_url, skip_tokens):
            return
        # Safety: destructive/overwrite form verbs (DELETE/PATCH) are never
        # actively posted (SGK-2026-0459: 危険動詞は能動投稿スキップ).
        if submit_plan and submit_plan.get("kind") == "form":
            form_method = str(submit_plan.get("method") or "get").upper()
            if form_method in ("DELETE", "PATCH"):
                return

        # Unique marker per surface (random hex, benign).
        marker = f"sgk{secrets.token_hex(4)}"
        dom_name = str(surf.get("name") or "")
        fields = [dom_name] if dom_name else []

        try:
            filled = await page.evaluate(
                """([sid, marker]) => {
                    const el = document.querySelector('[data-shigoku-surface-id="' + sid + '"]');
                    if (!el) return false;
                    if (el.isContentEditable) {
                        el.textContent = marker;
                        el.dispatchEvent(new Event('input', { bubbles: true }));
                    } else {
                        el.value = marker;
                        el.dispatchEvent(new Event('input', { bubbles: true }));
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                    }
                    return true;
                }""",
                [sid, marker],
            )
        except Exception:
            return
        if not filled:
            return

        # Dedupe: never resend the same marker for the same surface.
        sent = state.setdefault("sent_markers", set())
        if sid in sent:
            return
        sent.add(sid)

        results.setdefault("marker_records", []).append({
            "sid": sid,
            "marker": marker,
            "fields": fields,
            "source_page": source_url,
        })

        confirmed = await self._submit_surface(page, submit_plan, sid, marker, results, budgets)
        if confirmed:
            state["confirmed"] = state.get("confirmed", 0) + 1

    async def _submit_surface(self, page, submit_plan, sid: str, marker: str,
                              results: Dict[str, Any], budgets: Dict[str, Any]) -> bool:
        """Attempt submission in structural order (form -> contained buttons ->
        Enter), bounded by active_post_submit_attempts total attempts."""
        remaining = max(1, int(budgets.get("submit_attempts") or 1))
        confirmed = False

        if submit_plan and submit_plan.get("kind") == "form" and remaining > 0:
            remaining -= 1
            confirmed = await self._submit_via_form(page, sid, marker, results)

        if not confirmed and submit_plan and submit_plan.get("kind") == "container":
            for cid in (submit_plan.get("cids") or []):
                if remaining <= 0:
                    break
                remaining -= 1
                confirmed = await self._submit_via_button(page, cid, marker, results)
                if confirmed:
                    break

        if not confirmed and remaining > 0:
            remaining -= 1
            confirmed = await self._submit_via_enter(page, sid, marker, results)

        return confirmed

    async def _submit_via_form(self, page, sid: str, marker: str, results: Dict[str, Any]) -> bool:
        try:
            await page.evaluate(
                """(sid) => {
                    const el = document.querySelector('[data-shigoku-surface-id="' + sid + '"]');
                    if (!el) return false;
                    const form = el.closest ? el.closest('form') : null;
                    if (!form) return false;
                    if (form.requestSubmit) form.requestSubmit();
                    else form.submit();
                    return true;
                }""",
                sid,
            )
        except Exception:
            return False
        await page.wait_for_timeout(300)
        return self._marker_confirmed(results, marker)

    async def _submit_via_button(self, page, cid: str, marker: str, results: Dict[str, Any]) -> bool:
        try:
            btn = await page.query_selector(f"[data-shigoku-submit-id='{cid}']")
            if not btn:
                return False
            await btn.click(timeout=1200, force=True)
        except Exception:
            return False
        await page.wait_for_timeout(300)
        return self._marker_confirmed(results, marker)

    async def _submit_via_enter(self, page, sid: str, marker: str, results: Dict[str, Any]) -> bool:
        try:
            await page.evaluate(
                """(sid) => {
                    const el = document.querySelector('[data-shigoku-surface-id="' + sid + '"]');
                    if (!el) return false;
                    el.focus();
                    const opts = { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true };
                    el.dispatchEvent(new KeyboardEvent('keydown', opts));
                    el.dispatchEvent(new KeyboardEvent('keyup', opts));
                    return true;
                }""",
                sid,
            )
        except Exception:
            return False
        await page.wait_for_timeout(300)
        return self._marker_confirmed(results, marker)

    async def _run_active_save_discovery(self, page, base_url: str,
                                         results: Dict[str, Any],
                                         budgets: Dict[str, Any]) -> None:
        """SGK-2026-0459 hands (a)+(b)+(c)+(d): behavior-based active
        save-sink discovery. Runs only when active-post mode is ON for the
        target host; never raises."""
        try:
            max_reveal_clicks = max(0, int(budgets.get("max_reveal_clicks") or 0))
            max_writes_per_page = max(0, int(budgets.get("max_writes_per_page") or 0))
            reveal_depth = max(1, int(budgets.get("reveal_depth") or 1))
            time_budget_ms = max(0, int(budgets.get("reveal_time_budget_ms") or 0))
            reveal_settle_ms = max(0, int(budgets.get("reveal_settle_ms") or 2500))
        except Exception:
            return

        state: Dict[str, Any] = {"sent_markers": set(), "confirmed": 0}
        processed_sids: set = set()
        clicked_cids: set = set()
        start_mono = time.monotonic()

        def _time_left_ms() -> float:
            if time_budget_ms <= 0:
                return 1.0
            return max(0.0, time_budget_ms - (time.monotonic() - start_mono) * 1000.0)

        # Hand (a) inventory + (c)+(d) on each visible surface.
        try:
            initial = await self._inventory_surfaces(page)
        except Exception:
            initial = []
        for surf in initial:
            if state["confirmed"] >= max_writes_per_page:
                return
            sid = str(surf.get("sid") or "")
            if sid in processed_sids:
                continue
            processed_sids.add(sid)
            try:
                await self._try_surface(page, surf, base_url, results, state, budgets)
            except Exception:
                continue

        # Hand (b) reveal-by-diff, bounded by clicks / time / depth.
        depth = 0
        while depth < reveal_depth:
            if max_reveal_clicks <= 0:
                break
            if state["confirmed"] >= max_writes_per_page:
                return
            if _time_left_ms() <= 0:
                break
            try:
                candidates = await self._list_click_candidates(page, clicked_cids)
            except Exception:
                candidates = []
            if not candidates:
                break
            revealed_any = False
            for cand in candidates:
                if max_reveal_clicks <= 0:
                    break
                if _time_left_ms() <= 0:
                    break
                if state["confirmed"] >= max_writes_per_page:
                    return
                cid = str(cand.get("cid") or "")
                if not cid or cid in clicked_cids:
                    continue
                max_reveal_clicks -= 1
                clicked_cids.add(cid)
                try:
                    # Per-click adaptive wait cap is bounded by the remaining
                    # overall reveal budget so a slow reveal cannot exhaust it.
                    effective_settle = int(min(reveal_settle_ms, max(0.0, _time_left_ms())))
                    new_sids = await self._click_and_diff(page, cand, effective_settle)
                except Exception:
                    new_sids = []
                if new_sids:
                    revealed_any = True
                    try:
                        surfaces_after = await self._inventory_surfaces(page)
                    except Exception:
                        surfaces_after = []
                    surf_by_sid = {str(s.get("sid") or ""): s for s in surfaces_after}
                    for sid in new_sids:
                        if sid in processed_sids:
                            continue
                        processed_sids.add(sid)
                        s = surf_by_sid.get(sid)
                        if s:
                            try:
                                await self._try_surface(page, s, base_url, results, state, budgets)
                            except Exception:
                                pass
                        if state["confirmed"] >= max_writes_per_page:
                            return
            if not revealed_any:
                break
            depth += 1

    async def crawl(
        self,
        url: str,
        auth_headers: Dict[str, str] = None,
        cookies_str: str = None,
        timeout: int = 30000,
        max_pages: int = 6,
        max_clicks_per_page: int = 6,
        max_forms_per_page: int = 3,
        max_post_login_actions_per_page: int = 6,
        max_route_hints_per_page: int = 20,
        extra_paths: Optional[List[str]] = None,
        get_only: Optional[bool] = None,
        active_post: Optional[bool] = None,
        active_post_allowed_hosts: Optional[List[str]] = None,
        active_post_max_writes: Optional[int] = None,
        active_post_max_writes_per_page: Optional[int] = None,
        active_post_max_reveal_clicks: Optional[int] = None,
        active_post_reveal_depth: int = 2,
        active_post_reveal_time_budget_ms: Optional[int] = None,
        active_post_submit_attempts: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Navigates to the URL and intercepts all requests to find dynamic endpoints.
        """
        cfg = self._resolve_active_post_config(
            get_only,
            active_post,
            active_post_allowed_hosts,
            active_post_max_writes,
            active_post_max_writes_per_page,
            active_post_max_reveal_clicks,
            active_post_reveal_depth,
            active_post_reveal_time_budget_ms,
            active_post_submit_attempts,
        )
        get_only = cfg["get_only"]
        active_post = cfg["active_post"]
        allowed_hosts = cfg["allowed_hosts"]
        allowed_hosts_set = {str(h).lower() for h in allowed_hosts}
        skip_path_tokens = cfg["skip_path_tokens"]
        budgets = cfg

        seed_parsed = urlparse(str(url or ""))
        target_host = str(seed_parsed.hostname or "").lower()
        # Active-post mode is ON for the seed host only when the run is not
        # GET-only and the host is allowlisted. When OFF, the browser path is
        # GET-only (non-GET/HEAD aborted) and form submission is skipped.
        host_allowed = (not get_only) and (target_host in allowed_hosts_set)

        results = {
            "urls": set(),
            "endpoints": set(),
            "js_files": set(),
            "methods_by_url": {},
            "status_by_url": {},
            "errors": [],
            "write_requests": [],
            "marker_records": [],
            "save_endpoints": [],
        }
        
        try:
            async with async_playwright() as p:
                browser_args = {}
                if self.proxy:
                    browser_args["proxy"] = {"server": self.proxy}
                
                # Launch Chromium in headless mode
                browser = await p.chromium.launch(headless=True, **browser_args)
                
                context_args = {"ignore_https_errors": True}
                context = await browser.new_context(**context_args)
                
                # Apply cookies if provided
                if cookies_str:
                    cookie_list = []
                    # Parse simple cookie string (key=value; key2=value2)
                    domain = urlparse(url).hostname or "localhost"
                    for c_str in cookies_str.split(";"):
                        c_str = c_str.strip()
                        if "=" in c_str:
                            k, v = c_str.split("=", 1)
                            cookie_list.append({
                                "name": k,
                                "value": v,
                                "domain": domain,
                                "path": "/"
                            })
                    if cookie_list:
                        await context.add_cookies(cookie_list)
                
                # Apply auth headers
                if auth_headers:
                    await context.set_extra_http_headers(auth_headers)

                page = await context.new_page()

                # SGK-2026-0459: browser-path GET-only safety boundary (fail-closed).
                # GET/HEAD always pass; any other method passes only when active-post
                # mode is ON for the request host (not get_only, host allowlisted,
                # path not on the sensitive-path skip list). DELETE never passes.
                # A route error must never break the crawl, so the handler and the
                # install are guarded.
                try:
                    await page.route(
                        "**/*",
                        self._make_route_guard(get_only, allowed_hosts_set, skip_path_tokens),
                    )
                except Exception as e:
                    logger.debug(f"Failed to install active-post route guard: {e}")

                # Event listener for all requests
                def on_request(request):
                    req_url = request.url
                    # Skip data URIs
                    if req_url.startswith("data:"):
                        return

                    method = str(request.method or "GET").upper()
                    results["urls"].add(req_url)
                    results["methods_by_url"].setdefault(req_url, set()).add(method)

                    # Categorize
                    resource_type = request.resource_type
                    if resource_type in ["xhr", "fetch"]:
                        results["endpoints"].add(req_url)
                    elif resource_type == "script" or req_url.endswith(".js"):
                        results["js_files"].add(req_url)
                    elif "?" in req_url:
                        # Anything with a query parameter is a potential endpoint/candidate
                        results["endpoints"].add(req_url)

                    # SGK-2026-0459: capture non-GET/HEAD write requests with a body
                    # (marker round-trip confirmation of save endpoints).
                    if method not in ("GET", "HEAD"):
                        post_data = None
                        try:
                            post_data = request.post_data
                        except Exception:
                            post_data = None
                        if post_data:
                            content_type = ""
                            try:
                                content_type = str((request.headers or {}).get("content-type", "") or "")
                            except Exception:
                                content_type = ""
                            results["write_requests"].append({
                                "url": req_url,
                                "method": method,
                                "post_data": post_data,
                                "content_type": content_type,
                            })

                def on_response(response):
                    resp_url = response.url
                    if resp_url.startswith("data:"):
                        return
                    try:
                        results["status_by_url"][resp_url] = int(response.status)
                    except Exception:
                        return

                page.on("request", on_request)
                page.on("response", on_response)

                max_pages = max(1, int(max_pages or 1))
                max_clicks_per_page = max(0, int(max_clicks_per_page or 0))
                max_forms_per_page = max(0, int(max_forms_per_page or 0))
                max_post_login_actions_per_page = max(0, int(max_post_login_actions_per_page or 0))
                max_route_hints_per_page = max(1, int(max_route_hints_per_page or 1))
                journey_queue_cap = max(
                    max_pages * 5,
                    max_pages + max_route_hints_per_page + max_post_login_actions_per_page,
                    20,
                )

                common_paths = [
                    "/dashboard",
                    "/profile",
                    "/account",
                    "/account/profile",
                    "/account/settings",
                    "/account/security",
                    "/account/password",
                    "/account/notifications",
                    "/profile/edit",
                    "/users/me",
                    "/orders",
                    "/order",
                    "/orders/history",
                    "/orders/current",
                    "/checkout",
                    "/basket",
                    "/cart",
                    "/notifications",
                    "/messages",
                    "/messages/inbox",
                    "/billing",
                    "/billing/history",
                    "/invoices",
                    "/team",
                    "/projects",
                    "/activity",
                    "/support",
                    "/support/tickets",
                    "/api",
                    "/api/me",
                    "/api/profile",
                    "/api/orders",
                    "/api/account",
                    "/search?q=test",
                    "/reviews",
                    "/wallet",
                    "/chatbot",
                    "/chatbot/genai/state",
                    "/settings",
                    "/admin",
                ]
                if extra_paths:
                    for path in extra_paths:
                        path_str = str(path or "").strip()
                        if path_str and path_str not in common_paths:
                            common_paths.append(path_str)

                journey_urls: list[str] = []
                seen_journey: set[str] = set()

                def _append_journey(candidate: str) -> None:
                    c = str(candidate or "").strip()
                    if not c:
                        return
                    if not c.startswith(("http://", "https://")):
                        c = urljoin(url, c)
                    if not c.startswith(("http://", "https://")):
                        return
                    if not self._same_origin(url, c):
                        return
                    if c in seen_journey:
                        return
                    if len(journey_urls) >= journey_queue_cap:
                        return
                    if self._is_logout_like(c):
                        return
                    seen_journey.add(c)
                    journey_urls.append(c)

                _append_journey(url)
                for path in common_paths:
                    _append_journey(path)

                visited_journeys: set[str] = set()
                cursor = 0
                while cursor < len(journey_urls) and len(visited_journeys) < max_pages:
                    journey_url = journey_urls[cursor]
                    cursor += 1
                    if journey_url in visited_journeys:
                        continue
                    visited_journeys.add(journey_url)
                    try:
                        await page.goto(journey_url, wait_until="domcontentloaded", timeout=timeout)
                        await page.wait_for_timeout(300)
                        await self._exercise_post_login_actions(page, max_actions=max_post_login_actions_per_page)
                        await self._exercise_clickables(page, max_clicks=max_clicks_per_page)
                        # Form submission is a write: only exercise forms when
                        # active-post mode is ON for the seed host.
                        if host_allowed:
                            await self._exercise_forms(page, max_forms=max_forms_per_page)
                        # SGK-2026-0459: active save-sink discovery (hands a-d).
                        if active_post and host_allowed:
                            try:
                                await self._run_active_save_discovery(page, journey_url, results, budgets)
                            except Exception as e:
                                logger.debug(f"Active save discovery failed for {journey_url}: {e}")
                        await page.wait_for_timeout(260)

                        dynamic_links = await self._collect_internal_links(
                            page,
                            journey_url,
                            limit=max_route_hints_per_page,
                        )
                        route_hints = await self._collect_post_login_route_hints(
                            page,
                            journey_url,
                            limit=max_route_hints_per_page,
                        )
                        for link in dynamic_links + route_hints:
                            _append_journey(link)
                    except Exception as e:
                        logger.debug(f"Playwright journey navigation failed for {journey_url}: {e}")
                        continue
                
                await browser.close()
                
        except Exception as e:
            logger.error(f"PlaywrightCrawler error: {e}")
            results["errors"].append(str(e))

        # SGK-2026-0459 hand (d): confirm save endpoints ONLY via marker
        # round-trips in captured write request bodies (never fabricated).
        try:
            results["save_endpoints"] = self._derive_save_endpoints(
                results, url, budgets["max_writes"]
            )
        except Exception as e:
            logger.debug(f"Save endpoint derivation failed: {e}")
            results["save_endpoints"] = []

        # Convert sets to lists
        url_items = []
        for req_url in results["urls"]:
            url_items.append({
                "url": req_url,
                "method": self._preferred_method(results["methods_by_url"].get(req_url)),
                "response_status": int(results["status_by_url"].get(req_url, 0) or 0),
            })

        return {
            "urls": url_items,
            "endpoints": list(results["endpoints"]),
            "js_files": list(results["js_files"]),
            "errors": results["errors"],
            "save_endpoints": results.get("save_endpoints") or [],
        }

async def run_playwright_recon(target: str, auth_headers: Dict[str, str] = None, cookies: str = None, proxy: str = None) -> Dict[str, Any]:
    crawler = PlaywrightCrawler(proxy=proxy)
    return await crawler.crawl(target, auth_headers=auth_headers, cookies_str=cookies)

if __name__ == "__main__":
    # For CLI testing
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        res = asyncio.run(run_playwright_recon(target_url))
        print(json.dumps(res, indent=2))
