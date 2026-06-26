"""
Origin key normalizer.

Normalizes URLs to canonical origin form for rate limiting and admission decisions:
  - scheme (lowercase)
  - host (lowercase)
  - port (default ports 80/443 omitted)
  - no path, fragment, or query string
"""

from urllib.parse import urlparse


# Default ports per scheme (omitted from normalized origin)
_DEFAULT_PORTS: dict[str, int] = {
    "http": 80,
    "https": 443,
}


def normalize_origin_key(target_url: str) -> str:
    """Normalize a URL to its canonical origin key.

    Parses the URL and reconstructs it as `scheme://host[:port]` with:
      - scheme lowercased
      - host lowercased
      - default port (80 for http, 443 for https) omitted
      - non-default port preserved
      - path, fragment, query string stripped

    Args:
        target_url: A URL string to normalize.

    Returns:
        The normalized origin key string.

    Raises:
        ValueError: If the URL has no scheme or no host.
    """
    parsed = urlparse(target_url)

    if not parsed.scheme:
        raise ValueError(f"URL has no scheme: {target_url!r}")
    if not parsed.hostname:
        raise ValueError(f"URL has no host: {target_url!r}")

    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    port = parsed.port

    default_port = _DEFAULT_PORTS.get(scheme)
    if port is not None and port != default_port:
        return f"{scheme}://{host}:{port}"

    return f"{scheme}://{host}"
