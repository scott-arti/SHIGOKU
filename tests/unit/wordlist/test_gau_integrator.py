import pytest
from unittest.mock import AsyncMock, MagicMock

from src.core.wordlist.gau_integrator import GAUIntegrator


@pytest.fixture
def integrator(monkeypatch):
    async def _healthy(self):
        return True

    monkeypatch.setattr("src.core.wordlist.gau_integrator.GauAdapter.health_check", _healthy)
    inst = GAUIntegrator()
    inst._executor = MagicMock()
    return inst


@pytest.mark.asyncio
async def test_fetch_urls_uses_adapter_results(integrator):
    integrator._executor.execute = AsyncMock(
        return_value=MagicMock(status=MagicMock(value="success"), data=[{"url": "https://a.test/x"}, {"url": "https://a.test/y"}], error_message=None)
    )

    urls = await integrator.fetch_urls("a.test", timeout=5, providers=["wayback"])

    assert urls == ["https://a.test/x", "https://a.test/y"]
    assert integrator._executor.execute.await_count == 1


@pytest.mark.asyncio
async def test_fetch_urls_returns_empty_on_failure(integrator):
    integrator._executor.execute = AsyncMock(
        return_value=MagicMock(status=MagicMock(value="failure"), data=None, error_message="bad")
    )

    urls = await integrator.fetch_urls("a.test")

    assert urls == []
