import inspect

from src.core.wordlist.gau_integrator import GAUIntegrator


def test_gau_integrator_is_async_only_contract():
    assert inspect.iscoroutinefunction(GAUIntegrator.fetch_urls)
    assert inspect.iscoroutinefunction(GAUIntegrator.get_summary_for_ai)
    assert not hasattr(GAUIntegrator, "_run_async")
