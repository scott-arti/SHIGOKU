"""Tests for MasterConductor cookie normalization for the preflight gate.

Verifies:
- String cookies are parsed to dict
- Dict cookies pass through unchanged
- None/empty returns an empty dict
"""

import pytest
from src.core.engine.master_conductor import MasterConductor


class TestNormalizeCookiesStringToDict:
    """Regression tests: MasterConductor._normalize_cookies_for_gate."""

    def test_normalize_cookies_string_to_dict_basic(self):
        """Cookie string 'a=1; b=2' becomes {'a': '1', 'b': '2'}."""
        result = MasterConductor._normalize_cookies_for_gate("a=1; b=2")
        assert result == {"a": "1", "b": "2"}

    def test_normalize_cookies_string_with_spaces(self):
        """Spaces around separators are stripped."""
        result = MasterConductor._normalize_cookies_for_gate(
            " session=abc ; token=xyz "
        )
        assert result == {"session": "abc", "token": "xyz"}

    def test_normalize_cookies_dict_passthrough(self):
        """A dict is returned unchanged."""
        original = {"session": "abc123", "csrftoken": "xyz"}
        result = MasterConductor._normalize_cookies_for_gate(original)
        assert result is original  # same object
        assert result == {"session": "abc123", "csrftoken": "xyz"}

    def test_normalize_cookies_none_returns_empty(self):
        """None input returns an empty dict."""
        result = MasterConductor._normalize_cookies_for_gate(None)
        assert result == {}

    def test_normalize_cookies_empty_string_returns_empty(self):
        """Empty string returns an empty dict."""
        result = MasterConductor._normalize_cookies_for_gate("")
        assert result == {}

    def test_normalize_cookies_single_pair(self):
        """Single key=value pair is parsed correctly."""
        result = MasterConductor._normalize_cookies_for_gate("session=abc")
        assert result == {"session": "abc"}

    def test_normalize_cookies_value_contains_equals(self):
        """Values containing '=' are handled correctly (split on first '=')."""
        result = MasterConductor._normalize_cookies_for_gate("token=abc=def")
        assert result == {"token": "abc=def"}

    def test_normalize_cookies_unexpected_type_returns_empty(self):
        """Non-string, non-dict, non-None input returns empty dict."""
        result = MasterConductor._normalize_cookies_for_gate(42)
        assert result == {}

        result = MasterConductor._normalize_cookies_for_gate([])
        assert result == {}
