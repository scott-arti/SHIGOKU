from typing import Any, Dict


def normalize_header_keys(raw_headers: Dict[str, Any]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    for key, value in (raw_headers or {}).items():
        token = str(key or "").strip()
        if not token:
            continue
        lowered = token.lower()
        if lowered == "authorization":
            normalized["Authorization"] = value
        elif lowered == "cookie":
            normalized["Cookie"] = value
        else:
            normalized[token] = value
    return normalized
