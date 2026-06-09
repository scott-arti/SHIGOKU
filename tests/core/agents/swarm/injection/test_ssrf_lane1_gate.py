from src.core.agents.swarm.injection.manager_internal.execution_policy import (
    ssrf_reachability_gate,
)


def test_ssrf_reachability_gate_accepts_query_param():
    ok, reason = ssrf_reachability_gate(
        "https://example.com/fetch?url=http://127.0.0.1",
        {"forms": [], "url_evidence": {}},
    )
    assert ok is True
    assert reason == "query_param"


def test_ssrf_reachability_gate_rejects_low_signal_target():
    ok, reason = ssrf_reachability_gate(
        "https://example.com/static/about",
        {"forms": [], "url_evidence": {"ssrf_score": 10, "score_breakdown": {}}},
    )
    assert ok is False
    assert reason == "no_ssrf_injection_point"
