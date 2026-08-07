"""Regression tests for runtime external-tool command resolution."""

from types import SimpleNamespace

from src.core.config.settings import Settings


def _settings_with_httpx_path(path: str) -> SimpleNamespace:
    return SimpleNamespace(tool_httpx_path=path)


def test_blank_tool_path_resolves_to_standard_command():
    settings = _settings_with_httpx_path("")

    assert Settings.resolve_tool_command(settings, "httpx") == "httpx"


def test_whitespace_tool_path_resolves_to_standard_command():
    settings = _settings_with_httpx_path("   ")

    assert Settings.resolve_tool_command(settings, "httpx") == "httpx"


def test_explicit_runtime_override_takes_precedence():
    settings = _settings_with_httpx_path("/configured/httpx")

    assert (
        Settings.resolve_tool_command(settings, "httpx", "/runtime/httpx")
        == "/runtime/httpx"
    )


def test_configured_custom_path_is_preserved_as_one_command():
    settings = _settings_with_httpx_path("/opt/Project Discovery/httpx")

    assert (
        Settings.resolve_tool_command(settings, "httpx")
        == "/opt/Project Discovery/httpx"
    )
