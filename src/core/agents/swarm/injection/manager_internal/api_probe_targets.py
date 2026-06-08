import re
from typing import List
from urllib.parse import urljoin, urlparse


def dedupe_urls(candidates: List[str]) -> List[str]:
    ordered: List[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        token = str(candidate or "").strip()
        if not token or token in seen:
            continue
        seen.add(token)
        ordered.append(token)
    return ordered


def extract_api_like_urls(source_url: str, page_body: str) -> List[str]:
    extracted: List[str] = []
    body = str(page_body or "")
    if not body:
        return extracted

    relative_patterns = [
        r"/vulnerabilities/api/v\d+/[A-Za-z0-9_./-]*",
        r"/api/v\d+/[A-Za-z0-9_./-]*",
        r"/api/[A-Za-z0-9_./-]*",
        r"/rest/[A-Za-z0-9_./-]*",
    ]
    for pattern in relative_patterns:
        for rel in re.findall(pattern, body):
            cleaned_rel = str(rel or "").strip().rstrip('\'" ),;')
            if cleaned_rel:
                extracted.append(urljoin(source_url, cleaned_rel))

    absolute_pattern = r"https?://[A-Za-z0-9._:-]+/(?:api|rest)/[A-Za-z0-9_./-]*"
    source_netloc = urlparse(source_url).netloc
    for absolute_url in re.findall(absolute_pattern, body):
        cleaned_abs = str(absolute_url or "").strip().rstrip('\'" ),;')
        if not cleaned_abs:
            continue
        if source_netloc and urlparse(cleaned_abs).netloc != source_netloc:
            continue
        extracted.append(cleaned_abs)

    return dedupe_urls(extracted)


def build_nearby_api_candidates(seed_url: str) -> List[str]:
    parsed = urlparse(seed_url)
    if not parsed.scheme or not parsed.netloc:
        return []
    segments = [segment for segment in (parsed.path or "").split("/") if segment]
    if not segments:
        return []

    base = f"{parsed.scheme}://{parsed.netloc}"
    joined = "/".join(segments)
    first_segment = segments[0]
    last_segment = segments[-1]

    candidates = [
        f"{base}/api/{joined}",
        f"{base}/api/v1/{joined}",
        f"{base}/api/v2/{joined}",
        f"{base}/rest/{joined}",
        f"{base}/api/{first_segment}",
        f"{base}/api/v1/{first_segment}",
        f"{base}/api/v2/{first_segment}",
        f"{base}/rest/{first_segment}",
        f"{base}/api/{last_segment}",
        f"{base}/api/v1/{last_segment}",
        f"{base}/api/v2/{last_segment}",
        f"{base}/rest/{last_segment}",
    ]
    return dedupe_urls(candidates)
