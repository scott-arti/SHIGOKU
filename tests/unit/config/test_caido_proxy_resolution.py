from types import SimpleNamespace
from unittest.mock import patch

from src.core.config.settings import Settings
from src.core.intel.caido_crawler import CaidoCrawler


def _resolve_proxy(*, scan_proxy: str = "", caido_url: str = "http://127.0.0.1:8080"):
    configured = SimpleNamespace(
        scan=SimpleNamespace(proxy=scan_proxy),
        caido=SimpleNamespace(url=caido_url),
    )
    return Settings.get_proxy_url(configured)


def test_explicit_scan_proxy_takes_priority_over_caido_url(monkeypatch):
    monkeypatch.setenv("SHIGOKU_CAIDO__URL", "http://127.0.0.1:8081")
    proxy_url = _resolve_proxy(
        scan_proxy="http://proxy.example:9090",
        caido_url="http://127.0.0.1:8081",
    )

    assert proxy_url == "http://proxy.example:9090"


def test_explicit_caido_url_is_used_for_scan_proxy(monkeypatch):
    monkeypatch.setenv("SHIGOKU_CAIDO__URL", "http://127.0.0.1:8081")
    proxy_url = _resolve_proxy(caido_url="http://127.0.0.1:8081")

    assert proxy_url == "http://127.0.0.1:8081"


def test_default_caido_url_does_not_force_proxy(monkeypatch):
    monkeypatch.delenv("SHIGOKU_CAIDO__URL", raising=False)
    proxy_url = _resolve_proxy()

    assert proxy_url is None


def test_caido_crawler_uses_resolved_caido_proxy(monkeypatch):
    monkeypatch.delenv("SHIGOKU_CRAWLER_PROXY", raising=False)

    with patch(
        "src.core.intel.caido_crawler.settings.get_proxy_url",
        return_value="http://127.0.0.1:8081",
    ):
        crawler = CaidoCrawler()

    assert crawler.proxy == "http://127.0.0.1:8081"
