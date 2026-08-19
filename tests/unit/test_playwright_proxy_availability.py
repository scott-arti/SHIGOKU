"""SGK-2026-0454 T2: ②ブラウザ可用性判定（実体確認込み）・T3: ③proxy 引数検証。

T2: ブラウザ実体なしで unavailable を返し明示ログ（WARN）が出る／実体ありで起動できる。
T3: settings.get_proxy_url() が値ありのとき launch/new_context に proxy が渡る
    （mock で引数検証）。未設定時は proxy 引数を渡さない。資格情報が server に
    生で入らないことも確認。
"""
import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.tools.browser.playwright_validator import (
    PlaywrightValidator,
    build_playwright_proxy_config,
)


# ---------------------------------------------------------------------------
# T3: build_playwright_proxy_config の純粋関数検証
# ---------------------------------------------------------------------------

def test_proxy_config_simple_url():
    cfg = build_playwright_proxy_config("http://127.0.0.1:8081")
    assert cfg == {"server": "http://127.0.0.1:8081"}


def test_proxy_config_with_credentials_split_from_server():
    cfg = build_playwright_proxy_config("http://user:pass@127.0.0.1:8081")
    assert cfg["server"] == "http://127.0.0.1:8081"
    assert "user" not in cfg["server"]
    assert "pass" not in cfg["server"]
    assert cfg["username"] == "user"
    assert cfg["password"] == "pass"


def test_proxy_config_with_urlencoded_credentials():
    cfg = build_playwright_proxy_config("http://us%40er:p%40ss@127.0.0.1:8081")
    assert cfg["server"] == "http://127.0.0.1:8081"
    assert cfg["username"] == "us@er"
    assert cfg["password"] == "p@ss"


def test_proxy_config_none_and_empty_returns_none():
    assert build_playwright_proxy_config(None) is None
    assert build_playwright_proxy_config("") is None


def test_proxy_config_invalid_url_returns_none():
    assert build_playwright_proxy_config("not-a-url") is None
    assert build_playwright_proxy_config("://missing-scheme") is None


def test_proxy_config_default_port_by_scheme():
    assert build_playwright_proxy_config("https://proxy.example.com") == {
        "server": "https://proxy.example.com:443"
    }


def test_redact_proxy_url_hides_credentials():
    from src.tools.browser.playwright_validator import _redact_proxy_url
    redacted = _redact_proxy_url("http://user:pass@127.0.0.1:8081")
    assert "user" not in redacted
    assert "pass" not in redacted
    assert "***" in redacted


# ---------------------------------------------------------------------------
# T2: 可用性判定
# ---------------------------------------------------------------------------

def test_availability_false_without_browser_binary(caplog):
    """Playwright モジュールはあるがブラウザ実体がない → False + 明示 WARN"""
    with patch("src.tools.browser.playwright_validator.PlaywrightValidator._browser_binary_exists", return_value=False):
        with caplog.at_level("WARNING", logger="src.tools.browser.playwright_validator"):
            validator = PlaywrightValidator()
            assert validator.is_available is False
    assert any("chromium" in r.message for r in caplog.records)


def test_availability_false_without_playwright_module(caplog):
    """Playwright モジュール import 不可 → False + 明示 WARN"""
    real_import = __import__
    def _blocked_playwright_import(name, *args, **kwargs):
        if name == "playwright.async_api":
            raise ImportError("no playwright module")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=_blocked_playwright_import):
        with caplog.at_level("WARNING", logger="src.tools.browser.playwright_validator"):
            validator = PlaywrightValidator()
            assert validator.is_available is False
    assert any("Playwright module not found" in r.message for r in caplog.records)


def test_availability_true_with_browser_binary(caplog):
    with patch("src.tools.browser.playwright_validator.PlaywrightValidator._browser_binary_exists", return_value=True):
        validator = PlaywrightValidator()
        assert validator.is_available is True


# ---------------------------------------------------------------------------
# T3: 起動時の proxy 引数検証（mock）
# ---------------------------------------------------------------------------

class _FakeSettings:
    def get_proxy_url(self):
        return "http://127.0.0.1:8081"


def test_validate_xss_passes_proxy_when_configured():
    """get_proxy_url() 値あり → _proxy_config() が proxy dict を返す"""
    validator = PlaywrightValidator.__new__(PlaywrightValidator)
    validator._is_available = True
    validator._browser_args = ["--no-sandbox"]

    with patch(
        "src.core.config.settings.get_settings",
        return_value=_FakeSettings(),
    ):
        cfg = validator._proxy_config()
    assert cfg == {"server": "http://127.0.0.1:8081"}


def test_proxy_config_none_when_unset():
    class _NoProxySettings:
        def get_proxy_url(self):
            return None

    validator = PlaywrightValidator.__new__(PlaywrightValidator)
    with patch(
        "src.core.config.settings.get_settings",
        return_value=_NoProxySettings(),
    ):
        assert validator._proxy_config() is None


@pytest.mark.asyncio
async def test_validate_xss_launch_receives_proxy_kwarg():
    """launch が proxy キーワード込みで呼ばれる（mock 引数検証）"""
    validator = PlaywrightValidator.__new__(PlaywrightValidator)
    validator._is_available = True
    validator._browser_args = ["--no-sandbox"]

    mock_p = MagicMock()
    mock_browser = AsyncMock()
    mock_p.chromium.launch = AsyncMock(return_value=mock_browser)
    mock_context = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    mock_page = AsyncMock()
    mock_context.new_page = AsyncMock(return_value=mock_page)
    mock_page.on = MagicMock()
    mock_page.goto = AsyncMock()
    mock_page.wait_for_timeout = AsyncMock()

    class _CM:
        async def __aenter__(self):
            return mock_p

        async def __aexit__(self, *a):
            return None

    with (
        patch("playwright.async_api.async_playwright", MagicMock(return_value=_CM())),
        patch.object(validator, "_proxy_config", return_value={"server": "http://127.0.0.1:8081"}),
    ):
        result = await validator.validate_xss("http://example.com/search?q=test")

    assert result is False  # ダイアログなし
    launch_kwargs = mock_p.chromium.launch.call_args.kwargs
    assert launch_kwargs.get("proxy") == {"server": "http://127.0.0.1:8081"}
    ctx_kwargs = mock_browser.new_context.call_args.kwargs
    assert ctx_kwargs.get("proxy") == {"server": "http://127.0.0.1:8081"}


@pytest.mark.asyncio
async def test_validate_xss_launch_omits_proxy_when_unset():
    """proxy 未設定時は launch/new_context に proxy 引数が渡らない（直結・後方互換）"""
    validator = PlaywrightValidator.__new__(PlaywrightValidator)
    validator._is_available = True
    validator._browser_args = ["--no-sandbox"]

    mock_p = MagicMock()
    mock_browser = AsyncMock()
    mock_p.chromium.launch = AsyncMock(return_value=mock_browser)
    mock_context = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    mock_page = AsyncMock()
    mock_context.new_page = AsyncMock(return_value=mock_page)
    mock_page.on = MagicMock()
    mock_page.goto = AsyncMock()
    mock_page.wait_for_timeout = AsyncMock()

    class _CM:
        async def __aenter__(self):
            return mock_p

        async def __aexit__(self, *a):
            return None

    with (
        patch("playwright.async_api.async_playwright", MagicMock(return_value=_CM())),
        patch.object(validator, "_proxy_config", return_value=None),
    ):
        await validator.validate_xss("http://example.com/search?q=test")

    launch_kwargs = mock_p.chromium.launch.call_args.kwargs
    assert "proxy" not in launch_kwargs
    ctx_kwargs = mock_browser.new_context.call_args.kwargs
    assert "proxy" not in ctx_kwargs


# ---------------------------------------------------------------------------
# T3: browser_pool の proxy 配線
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_browser_pool_start_passes_proxy_when_configured():
    from src.core.detection import browser_pool as bp

    mb = bp._ManagedBrowser(slot_id=0, max_requests=100, metrics=bp.BrowserPoolMetrics())
    mock_ap = MagicMock()
    mock_ap.chromium.launch = AsyncMock(return_value=MagicMock())
    mock_ap.start = AsyncMock(return_value=mock_ap)

    with (
        patch("src.core.detection.browser_pool._PLAYWRIGHT_AVAILABLE", True),
        patch("src.core.detection.browser_pool.async_playwright", MagicMock(return_value=mock_ap)),
        patch(
            "src.core.detection.browser_pool._ManagedBrowser._build_proxy_config",
            return_value={"server": "http://127.0.0.1:8081"},
        ),
    ):
        await mb.start()

    launch_kwargs = mock_ap.chromium.launch.call_args.kwargs
    assert launch_kwargs.get("proxy") == {"server": "http://127.0.0.1:8081"}


@pytest.mark.asyncio
async def test_browser_pool_start_omits_proxy_when_unset():
    from src.core.detection import browser_pool as bp

    mb = bp._ManagedBrowser(slot_id=0, max_requests=100, metrics=bp.BrowserPoolMetrics())
    mock_ap = MagicMock()
    mock_ap.chromium.launch = AsyncMock(return_value=MagicMock())
    mock_ap.start = AsyncMock(return_value=mock_ap)

    with (
        patch("src.core.detection.browser_pool._PLAYWRIGHT_AVAILABLE", True),
        patch("src.core.detection.browser_pool.async_playwright", MagicMock(return_value=mock_ap)),
        patch(
            "src.core.detection.browser_pool._ManagedBrowser._build_proxy_config",
            return_value=None,
        ),
    ):
        await mb.start()

    launch_kwargs = mock_ap.chromium.launch.call_args.kwargs
    assert "proxy" not in launch_kwargs
