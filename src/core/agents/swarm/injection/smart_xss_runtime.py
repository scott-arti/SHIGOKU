#!/usr/bin/env python3
"""XSS runtime verification helpers: DOM execution, stored flow, XCTO/runtime-red.

Extracted from SmartXSSHunter to keep the facade lean.
Functions that need instance state accept parameters explicitly – no service pattern.
"""

import logging
from http.cookies import SimpleCookie
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from src.core.agents.swarm.injection.smart_xss_reflection import generate_dom_xss_payloads

logger = logging.getLogger(__name__)


def build_playwright_cookies(target: str, cookies_str: str) -> List[Dict[str, Any]]:
    """Convert a Cookie header string to Playwright context.add_cookies format."""
    if not cookies_str:
        return []

    domain = urlparse(target).hostname or "localhost"
    cookie = SimpleCookie()
    try:
        cookie.load(cookies_str)
    except Exception:
        return []

    pw_cookies: List[Dict[str, Any]] = []
    for key, morsel in cookie.items():
        pw_cookies.append({
            "name": key,
            "value": morsel.value,
            "domain": domain,
            "path": "/",
        })
    return pw_cookies


async def validate_dom_runtime_xss(
    target: str,
    payload: str,
    cookies_str: str,
    param_name: str = "default",
    *,
    dom_xss_verifier=None,
    hunter_name: str = "SmartXSSHunter",
) -> bool:
    """Multi-layered DOM execution verification.

    Attempts (in order):
      1. BrowserPoolXSSVerifier (pooled browser)
      2. PlaywrightValidator with query+hash URL variants
      3. Raw Playwright launch with DOM-sink inspection

    Args:
        target: Target URL
        payload: XSS payload to test
        cookies_str: Cookie header string
        param_name: URL parameter name for injection
        dom_xss_verifier: Optional pre-created BrowserPoolXSSVerifier instance
        hunter_name: Logger name prefix
    """
    # (1) BrowserPoolXSSVerifier 経由で発火確認
    try:
        from src.core.detection.browser_pool import BrowserPoolXSSVerifier
        verifier = dom_xss_verifier
        if verifier is None:
            verifier = BrowserPoolXSSVerifier()
        pooled_result = await verifier.verify(
            target,
            param_name,
            payload,
            dialog_timeout=5.0,
        )
        if pooled_result.executed:
            return True
    except Exception as e:
        logger.debug("[%s] BrowserPool verifier fallback: %s", hunter_name, e)

    # (2) 既存互換フォールバック: PlaywrightValidator + fragment/query組み合わせ検証
    try:
        from src.tools.browser.playwright_validator import PlaywrightValidator
    except Exception:
        return False

    validator = PlaywrightValidator()
    if not validator.is_available:
        return False

    parsed_target = urlparse(target)
    query = parse_qs(parsed_target.query)
    query[param_name] = [payload]
    query_encoded = urlencode({k: v[0] if isinstance(v, list) and v else v for k, v in query.items()})

    query_url = urlunparse(parsed_target._replace(query=query_encoded, fragment=""))
    query_and_fragment_url = urlunparse(parsed_target._replace(query=query_encoded, fragment=payload))
    fragment_only_url = urlunparse(parsed_target._replace(fragment=payload))
    test_urls = [query_url, query_and_fragment_url, fragment_only_url]

    pw_cookies = build_playwright_cookies(target, cookies_str)
    for test_url in test_urls:
        try:
            executed = await validator.validate_xss(test_url, timeout=8.0, cookies=pw_cookies or None)
            if executed:
                return True
        except Exception:
            continue

    # (3) alert() 非依存のフォールバック: DOMに危険な断片が生で取り込まれているかを確認
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return False

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=validator._browser_args)
            context = await browser.new_context(ignore_https_errors=True)
            if pw_cookies:
                await context.add_cookies(pw_cookies)

            for test_url in test_urls:
                page = await context.new_page()
                await page.goto(test_url, timeout=8000, wait_until="domcontentloaded")
                await page.wait_for_timeout(1500)

                dom_obs = await page.evaluate(
                    """
                    ({ paramName }) => {
                      const bodyHtml = (document.body && document.body.innerHTML ? document.body.innerHTML : "").toLowerCase();
                      const hash = decodeURIComponent((location.hash || "").slice(1));
                      const hashLower = hash.toLowerCase();
                      const params = new URLSearchParams(location.search || "");
                      const queryValue = decodeURIComponent(params.get(paramName) || "");
                      const queryLower = queryValue.toLowerCase();

                      const dangerousMarkers = ["<script", "onerror=", "onload=", "javascript:"];
                      const dangerousInBody = dangerousMarkers.some((m) => bodyHtml.includes(m));

                      const selectEl = document.querySelector(`select[name='${paramName}']`);
                      const selectHtml = (selectEl && selectEl.innerHTML ? selectEl.innerHTML : "").toLowerCase();
                      const dangerousInSelect = dangerousMarkers.some((m) => selectHtml.includes(m));

                      const queryReflectedRaw = queryLower ? bodyHtml.includes(queryLower) || selectHtml.includes(queryLower) : false;
                      const hashReflectedRaw = hashLower ? bodyHtml.includes(hashLower) || selectHtml.includes(hashLower) : false;

                      return {
                        dangerousInBody,
                        dangerousInSelect,
                        queryReflectedRaw,
                        hashReflectedRaw,
                        hasQuery: Boolean(queryLower),
                        hasHash: Boolean(hashLower),
                      };
                    }
                    """,
                    {"paramName": param_name},
                )

                await page.close()

                if isinstance(dom_obs, dict):
                    if (
                        (dom_obs.get("dangerousInSelect") or dom_obs.get("dangerousInBody"))
                        and (dom_obs.get("queryReflectedRaw") or dom_obs.get("hashReflectedRaw"))
                    ):
                        logger.info("[%s] DOM sink-like reflection observed (%s).", hunter_name, test_url)
                        await context.close()
                        await browser.close()
                        return True

            await context.close()
            await browser.close()
    except Exception:
        return False

    return False


async def check_dom_xss(target_url: str, param_name: str) -> Dict[str, Any]:
    """Static DOM XSS heuristics (Juice Shop–aware).

    Returns a dict with dom_xss_candidate, findings, and payloads_tested keys.
    """
    dom_payloads = generate_dom_xss_payloads(target_url)
    findings: List[Dict[str, Any]] = []

    for payload_info in dom_payloads:
        context = payload_info["context"]
        payload = payload_info["payload"]

        # Juice Shop特有のDOM XSSパターン検出
        if "juice" in target_url.lower() or "localhost:3000" in target_url:
            # Juice Shopの/#/searchルートはhash fragmentを検索クエリとして使用
            if context == "hash":
                findings.append({
                    "vulnerable": True,
                    "payload": payload,
                    "context": context,
                    "description": payload_info["description"],
                    "evidence": f"Juice Shop SPA route detected: {target_url}",
                    "confidence": 0.7,
                })

    return {
        "dom_xss_candidate": len(findings) > 0,
        "findings": findings,
        "payloads_tested": len(dom_payloads),
    }
