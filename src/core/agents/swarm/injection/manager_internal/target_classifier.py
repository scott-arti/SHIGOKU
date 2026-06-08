from urllib.parse import parse_qs, urlparse

from src.core.engine.tag_taxonomy_registry import (
    CATEGORY_API_CANDIDATE,
    CATEGORY_API_DATA,
    CATEGORY_API_ENDPOINT,
    CATEGORY_CSRF_CANDIDATE,
    CATEGORY_FILE_PARAM,
    CATEGORY_GRAPHQL_CANDIDATE,
    CATEGORY_ID_PARAM,
    CATEGORY_REDIRECT_PARAM,
    CATEGORY_SSRF_CANDIDATE,
    CATEGORY_XSS_CANDIDATE,
)


def classify_target_url(url: str, category: str = "") -> str:
    """カテゴリヒントとパス名からターゲットの脆弱性種別を推定する。"""
    category_hint = str(category or "").strip().lower()
    parsed = urlparse(url)
    path = parsed.path.lower()

    if category_hint in {"command_injection", "cmd_candidate"}:
        return "cmd_ssrf"
    if category_hint == CATEGORY_SSRF_CANDIDATE:
        return "ssrf"
    if category_hint == CATEGORY_CSRF_CANDIDATE:
        return "csrf"
    if category_hint == "cors_candidate":
        return "cors"
    if category_hint == "crlf_candidate":
        return "crlf"
    if category_hint == CATEGORY_GRAPHQL_CANDIDATE:
        return "graphql"
    if "/graphql" in path or "/gql" in path:
        return "graphql"
    if category_hint in {CATEGORY_API_CANDIDATE, CATEGORY_API_DATA, CATEGORY_API_ENDPOINT}:
        return "api"
    if category_hint == "ssti_candidate":
        return "ssti"
    if category_hint == CATEGORY_FILE_PARAM:
        return "lfi"
    if category_hint == CATEGORY_REDIRECT_PARAM:
        return "redirect"
    if category_hint == CATEGORY_XSS_CANDIDATE:
        return "xss"
    if category_hint == CATEGORY_ID_PARAM:
        if any(kw in path for kw in ["cmd", "exec", "ping", "command", "injection", "rce"]):
            return "cmd_ssrf"
        return "sqli"

    parsed_qs = parse_qs(parsed.query)

    if "csrf" in path:
        return "csrf"
    if "/graphql" in path or "/gql" in path:
        return "graphql"
    if "/api/" in path or "graphql" in path:
        return "api"

    redirect_params = {"redirect", "next", "dest", "out", "view", "link", "return"}
    if redirect_params & set(parsed_qs.keys()):
        return "redirect"

    if any(kw in path for kw in ["/render", "/tpl", "template_engine", "/jinja", "freemarker", "thymeleaf"]):
        return "ssti"

    if any(kw in path for kw in ["sqli", "sql", "db", "query", "blind"]):
        return "sqli"
    if any(kw in path for kw in ["xss", "cross", "script"]):
        return "xss"
    if any(kw in path for kw in ["lfi", "rfi", "/fi/", "file", "traversal", "inclusion", "path"]):
        return "lfi"
    if any(kw in path for kw in ["redirect", "ssrf", "open", "forward"]):
        return "redirect"
    if any(kw in path for kw in ["cmd", "exec", "ping", "command", "injection", "rce"]):
        return "cmd_ssrf"

    sqli_params = {"id", "user", "search", "query", "select", "where"}
    if sqli_params & set(k.lower() for k in parsed_qs.keys()):
        return "sqli"

    return "unknown"
