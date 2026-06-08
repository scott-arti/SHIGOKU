from typing import Dict, List

# Canonical category names used across recon pipeline / dispatcher / injection manager.
CATEGORY_AUTH = "auth"
CATEGORY_ADMIN = "admin"
CATEGORY_ID_PARAM = "id_param"
CATEGORY_REDIRECT_PARAM = "redirect_param"
CATEGORY_FILE_PARAM = "file_param"
CATEGORY_API_DATA = "api_data"
CATEGORY_API_CANDIDATE = "api_candidate"
CATEGORY_API_ENDPOINT = "api_endpoint"
CATEGORY_CSRF_CANDIDATE = "csrf_candidate"
CATEGORY_XSS_CANDIDATE = "xss_candidate"
CATEGORY_SSRF_CANDIDATE = "ssrf_candidate"
CATEGORY_CORS_CANDIDATE = "cors_candidate"
CATEGORY_GRAPHQL_CANDIDATE = "graphql_candidate"


PIPELINE_HISTORY_CANDIDATE_CATEGORIES = (
    CATEGORY_AUTH,
    CATEGORY_ID_PARAM,
    CATEGORY_REDIRECT_PARAM,
    CATEGORY_FILE_PARAM,
    CATEGORY_API_DATA,
    "basket_order",
    "product_search",
    "feedback_review",
    "client_route_dom",
    CATEGORY_ADMIN,
    CATEGORY_API_CANDIDATE,
    CATEGORY_CSRF_CANDIDATE,
)


CATEGORY_TO_TAGS: Dict[str, List[str]] = {
    CATEGORY_ID_PARAM: ["sqli_candidate", "idor_candidate"],
    CATEGORY_REDIRECT_PARAM: ["open_redirect", CATEGORY_SSRF_CANDIDATE],
    CATEGORY_FILE_PARAM: ["lfi_candidate", "rce_candidate"],
    "upload": ["file_upload", "rce_candidate"],
    CATEGORY_AUTH: ["auth_endpoint"],
    CATEGORY_ADMIN: ["admin_panel", "auth_required", CATEGORY_API_ENDPOINT],
    "product_search": [CATEGORY_API_ENDPOINT, "sqli_candidate", CATEGORY_XSS_CANDIDATE, "idor_candidate"],
    "basket_order": ["payment_flow", "idor_candidate", CATEGORY_API_ENDPOINT],
    "feedback_review": [CATEGORY_XSS_CANDIDATE, CATEGORY_API_ENDPOINT],
    "file_exposure_upload": ["file_upload", "lfi_candidate", "sensitive_data_exposure"],
    CATEGORY_API_DATA: [CATEGORY_API_ENDPOINT, "has_params"],
    "client_route_dom": [CATEGORY_XSS_CANDIDATE, "js_file"],
    "realtime": [CATEGORY_API_ENDPOINT, "auth_required"],
    "meta_observability": ["debug_info", CATEGORY_API_ENDPOINT],
    CATEGORY_CSRF_CANDIDATE: [CATEGORY_CSRF_CANDIDATE],
    CATEGORY_API_CANDIDATE: [CATEGORY_API_ENDPOINT],
    CATEGORY_CORS_CANDIDATE: [CATEGORY_CORS_CANDIDATE],
    "ssti_candidate": ["ssti_candidate", "template_engine"],
    "external_link": ["out_of_scope_candidate"],
    "invalid_candidate": ["invalid_url_candidate"],
    CATEGORY_GRAPHQL_CANDIDATE: [CATEGORY_GRAPHQL_CANDIDATE],
    CATEGORY_SSRF_CANDIDATE: [CATEGORY_SSRF_CANDIDATE],
}


SUBDOMAIN_TAG_TO_SWARM: Dict[str, str] = {
    "has_params": "injection",
    "form_action": "injection",
    CATEGORY_API_ENDPOINT: "injection",
    "auth_endpoint": "auth",
    "auth_required": "auth",
    "jwt_token": "auth",
    "oauth_flow": "auth",
    "mfa_enabled": "auth",
    "401_response": "auth",
    "403_response": "auth",
    "payment_flow": "logic",
    "user_flow": "logic",
    "cors_header": "logic",
    "file_upload": "logic",
    "upload": "logic",
    "js_file": "discovery",
    "unknown_path": "discovery",
    "env_file": "secret",
    "git_exposed": "secret",
    "cloud_url": "secret",
    "config_file": "secret",
    "ssl": "scanner",
    "tls": "scanner",
    "certificate": "scanner",
    "port_open": "scanner",
    "service": "scanner",
    "cve": "scanner",
    "osint": "intelligence",
    "github": "intelligence",
    "recon": "intelligence",
    "secret_leak": "intelligence",
    "force_fuzz": "fuzzing",
    "dir_brute": "fuzzing",
    "param_fuzz": "fuzzing",
    "fuzzing": "fuzzing",
}


URL_TAG_TO_SWARM: Dict[str, str] = {
    CATEGORY_ID_PARAM: "injection",
    CATEGORY_REDIRECT_PARAM: "injection",
    CATEGORY_FILE_PARAM: "injection",
    "rce_candidate": "injection",
    "lfi_candidate": "injection",
    "sqli_candidate": "injection",
    CATEGORY_XSS_CANDIDATE: "injection",
    CATEGORY_SSRF_CANDIDATE: "injection",
    "open_redirect": "injection",
    "idor_candidate": "logic",
    "hidden_param": "logic",
    "admin_endpoint": "logic",
    CATEGORY_AUTH: "auth",
    CATEGORY_ADMIN: "auth",
    "admin_blocked": "auth",
    "admin_panel": "logic",
    "jwt_detected": "auth",
    "upload": "logic",
    "debug_info": "discovery",
}


def _build_tag_to_swarm_mapping() -> Dict[str, str]:
    """
    Build unified tag->swarm mapping with collision safety.
    If the same tag maps to different swarms across sources, fail fast.
    """
    merged: Dict[str, str] = dict(SUBDOMAIN_TAG_TO_SWARM)
    for tag, swarm in URL_TAG_TO_SWARM.items():
        if tag in merged and merged[tag] != swarm:
            raise ValueError(
                f"Conflicting tag-to-swarm mapping for '{tag}': "
                f"subdomain='{merged[tag]}' vs url='{swarm}'"
            )
        merged[tag] = swarm
    return merged


TAG_TO_SWARM: Dict[str, str] = _build_tag_to_swarm_mapping()


def normalize_category(category: str) -> str:
    return str(category or "").strip().lower()


def tags_for_category(category: str) -> List[str]:
    key = normalize_category(category)
    return list(CATEGORY_TO_TAGS.get(key, []))
