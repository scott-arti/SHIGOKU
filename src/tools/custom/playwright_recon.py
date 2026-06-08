"""
Playwright Reconnaissance Tool
Captures dynamic API endpoints and parameters by intercepting background XHR/Fetch requests.
"""

import sys
import json
import asyncio
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs

try:
    from playwright.async_api import async_playwright
except ImportError:
    pass

logger = logging.getLogger(__name__)

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
    ) -> Dict[str, Any]:
        """
        Navigates to the URL and intercepts all requests to find dynamic endpoints.
        """
        results = {
            "urls": set(),
            "endpoints": set(),
            "js_files": set(),
            "methods_by_url": {},
            "status_by_url": {},
            "errors": []
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
                    from urllib.parse import urlparse
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

                # Event listener for all requests
                def on_request(request):
                    req_url = request.url
                    # Skip data URIs
                    if req_url.startswith("data:"):
                        return
                    
                    results["urls"].add(req_url)
                    results["methods_by_url"][req_url] = request.method
                    
                    # Categorize
                    resource_type = request.resource_type
                    if resource_type in ["xhr", "fetch"]:
                        results["endpoints"].add(req_url)
                    elif resource_type == "script" or req_url.endswith(".js"):
                        results["js_files"].add(req_url)
                    elif "?" in req_url:
                        # Anything with a query parameter is a potential endpoint/candidate
                        results["endpoints"].add(req_url)

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
                        await self._exercise_forms(page, max_forms=max_forms_per_page)
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
            
        # Convert sets to lists
        url_items = []
        for req_url in results["urls"]:
            url_items.append({
                "url": req_url,
                "method": str(results["methods_by_url"].get(req_url, "GET") or "GET"),
                "response_status": int(results["status_by_url"].get(req_url, 0) or 0),
            })

        return {
            "urls": url_items,
            "endpoints": list(results["endpoints"]),
            "js_files": list(results["js_files"]),
            "errors": results["errors"]
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
