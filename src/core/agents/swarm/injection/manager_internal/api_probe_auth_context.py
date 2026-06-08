from typing import Any, Dict, Tuple

from src.core.agents.swarm.injection.manager_internal.api_probe_headers import (
    normalize_header_keys,
)


def resolve_auth_b_context(
    *,
    auth: Dict[str, Any],
    auth_headers: Dict[str, Any],
    alternative_sessions: Dict[str, Any] | None = None,
) -> Tuple[Dict[str, Any], str]:
    auth_b_headers = auth.get("auth_b_headers", auth.get("alternative_auth_headers", {}))
    if not isinstance(auth_b_headers, dict):
        auth_b_headers = {}
    auth_b_headers = normalize_header_keys(auth_b_headers)
    auth_b_role = str(auth.get("auth_b_role", "") or "").strip()

    if auth_b_headers:
        return auth_b_headers, auth_b_role

    if not bool(auth.get("auth_matrix_from_multi_session", False)):
        return {}, ""

    try:
        alternatives = alternative_sessions if isinstance(alternative_sessions, dict) else {}
        current_auth = str(auth_headers.get("Authorization", "") or "").strip()
        current_cookie = str(auth_headers.get("Cookie", "") or "").strip()
        for role_name, session_data in alternatives.items():
            candidate_headers = session_data.get("headers", {}) if isinstance(session_data, dict) else {}
            if not isinstance(candidate_headers, dict):
                continue
            candidate_headers = normalize_header_keys(candidate_headers)
            candidate_auth = str(candidate_headers.get("Authorization", "") or "").strip()
            candidate_cookie = str(candidate_headers.get("Cookie", "") or "").strip()
            if current_auth and candidate_auth == current_auth and current_cookie == candidate_cookie:
                continue
            if not candidate_auth and not candidate_cookie:
                continue
            return candidate_headers, str(role_name or "").strip()
    except Exception:
        return {}, ""

    return {}, ""
