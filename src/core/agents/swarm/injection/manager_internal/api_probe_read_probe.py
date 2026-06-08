from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


def build_fallback_read_probe_url(api_probe_target: str) -> str:
    try:
        parsed_probe_target = urlparse(api_probe_target)
        fallback_query = parse_qs(parsed_probe_target.query, keep_blank_values=True)
        if "__shigoku_probe" not in fallback_query:
            fallback_query["__shigoku_probe"] = ["mass_assignment_read_probe"]
        if "role" not in fallback_query:
            fallback_query["role"] = ["admin"]
        if "is_admin" not in fallback_query:
            fallback_query["is_admin"] = ["true"]
        return urlunparse(
            parsed_probe_target._replace(query=urlencode(fallback_query, doseq=True))
        )
    except Exception:
        return ""
