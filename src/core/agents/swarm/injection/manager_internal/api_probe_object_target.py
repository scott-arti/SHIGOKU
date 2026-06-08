from typing import Any, Dict
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


def build_object_ab_target(url: str) -> Dict[str, Any]:
    candidate = str(url or "").strip()
    if not candidate:
        return {}

    parsed = urlparse(candidate)
    query = parse_qs(parsed.query, keep_blank_values=True)
    id_like_keys = ("id", "uid", "user_id", "account_id", "order_id", "profile_id")

    for key, values in query.items():
        lowered = str(key or "").strip().lower()
        if "id" not in lowered and lowered not in id_like_keys:
            continue
        if not values:
            continue
        current = str(values[0] or "").strip()
        if not current.isdigit():
            continue
        nxt = str(int(current) + 1)
        query[key] = [nxt]
        mutated = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
        return {
            "param": key,
            "resource_a": current,
            "resource_b": nxt,
            "mutated_url": mutated,
            "location": "query",
        }

    segments = [segment for segment in (parsed.path or "").split("/") if segment]
    for idx in range(len(segments) - 1, -1, -1):
        current = str(segments[idx] or "").strip()
        if not current.isdigit():
            continue
        nxt = str(int(current) + 1)
        mutated_segments = list(segments)
        mutated_segments[idx] = nxt
        new_path = "/" + "/".join(mutated_segments)
        mutated = urlunparse(parsed._replace(path=new_path))
        return {
            "param": "path_id",
            "resource_a": current,
            "resource_b": nxt,
            "mutated_url": mutated,
            "location": "path",
        }

    return {}
