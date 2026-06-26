"""
T-1.2: origin_key normalization tests.

Tests for normalize_origin_key() which normalizes URLs to canonical origin form:
scheme (lower) + host (lower) + port (default ports omitted), no path/fragment/query.
"""
import pytest
from src.core.engine.origin_normalizer import normalize_origin_key


class TestOriginKeyNormalization:
    """T-1.2: normalize_origin_key tests."""

    def test_https_default_port_omitted(self):
        """HTTPS with default port 443 → port omitted."""
        result = normalize_origin_key("HTTPS://Example.COM:443/path")
        assert result == "https://example.com"

    def test_http_non_default_port_preserved(self):
        """HTTP with non-default port 8080 → port preserved."""
        result = normalize_origin_key("http://sub.example.com:8080/x")
        assert result == "http://sub.example.com:8080"

    def test_http_default_port_omitted(self):
        """HTTP with default port 80 → port omitted."""
        result = normalize_origin_key("HTTP://Example.ORG:80/some/path?q=1")
        assert result == "http://example.org"

    def test_no_scheme_raises_value_error(self):
        """Scheme-less input raises ValueError."""
        with pytest.raises(ValueError):
            normalize_origin_key("example.com")

    def test_lowercase_scheme_and_host(self):
        """Scheme and host are lowercased."""
        result = normalize_origin_key("HTTPS://WWW.Example.COM/path")
        assert result == "https://www.example.com"

    def test_https_no_port_no_path(self):
        """HTTPS without port and without path."""
        result = normalize_origin_key("https://example.com")
        assert result == "https://example.com"

    def test_fragment_stripped(self):
        """Fragment is stripped from origin."""
        result = normalize_origin_key("https://example.com/page#section")
        assert result == "https://example.com"

    def test_query_stripped(self):
        """Query string is stripped from origin."""
        result = normalize_origin_key("https://example.com/search?q=test&page=1")
        assert result == "https://example.com"

    def test_path_stripped_deep(self):
        """Deep path is stripped from origin."""
        result = normalize_origin_key("https://api.example.com/v1/users/123/profile")
        assert result == "https://api.example.com"

    def test_missing_host_raises_value_error(self):
        """URL with no host raises ValueError."""
        with pytest.raises(ValueError):
            normalize_origin_key("https:///path-only")
