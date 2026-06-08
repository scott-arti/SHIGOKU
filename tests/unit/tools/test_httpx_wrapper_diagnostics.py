from __future__ import annotations

import httpx

from src.tools.wrappers.httpx_wrapper import build_httpx_error_message, classify_httpx_error


def test_classify_httpx_error_returns_connect_timeout() -> None:
    error = httpx.ConnectTimeout("")

    assert classify_httpx_error(error) == "connect_timeout"


def test_build_httpx_error_message_fills_empty_connect_timeout_message() -> None:
    error = httpx.ConnectTimeout("")

    message = build_httpx_error_message(error, "connect_timeout")

    assert message == "connect timeout during request"


def test_build_httpx_error_message_preserves_non_empty_message() -> None:
    error = httpx.InvalidURL("bad url format")

    message = build_httpx_error_message(error, "invalid_url")

    assert message == "bad url format"
