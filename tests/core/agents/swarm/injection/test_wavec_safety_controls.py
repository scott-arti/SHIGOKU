from src.core.agents.swarm.injection.manager_internal.result_normalizer import (
    normalize_blind_correlation,
)


def test_normalize_blind_correlation_sets_dns_and_verdict():
    normalized = normalize_blind_correlation(
        {"time_based": {"confirmed": True}, "oob": {"confirmed": False, "hits": []}}
    )
    assert "dns" in normalized
    assert normalized["dns"]["confirmed"] is False
    assert normalized["correlated"] is False
    assert normalized["verdict"] == "tentative"


def test_normalize_blind_correlation_sets_confirmed_on_two_of_three():
    normalized = normalize_blind_correlation(
        {
            "time_based": {"confirmed": True},
            "oob": {"confirmed": True, "hits": ["abc"]},
            "dns": {"confirmed": False, "hits": []},
        }
    )
    assert normalized["correlated"] is True
    assert normalized["verdict"] == "confirmed"
