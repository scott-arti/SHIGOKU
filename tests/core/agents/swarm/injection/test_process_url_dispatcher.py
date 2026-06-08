"""Unit tests for process_url_dispatcher functions."""

from src.core.agents.swarm.injection.manager_internal.process_url_dispatcher import (
    process_unknown_classification_only,
)
from src.core.agents.swarm.injection.manager import InjectionManagerAgent


def _default_agent():
    return InjectionManagerAgent(config={"model": "test-model"})


def test_process_unknown_classification_returns_expected_keys():
    agent = _default_agent()
    result = process_unknown_classification_only(
        url="http://example.com/user/123",
        base_params={},
        available_specialists=set(agent.specialists.keys()),
        source_agent_name=agent.name,
        excluded_params=agent.EXCLUDED_TESTED_PARAMS,
    )
    assert "findings_count" in result
    assert "findings_list" in result
    assert "tested_params" in result
    assert "unknown_profile" in result
    assert "idor_candidate" in result


def test_process_unknown_classification_has_hypotheses():
    agent = _default_agent()
    result = process_unknown_classification_only(
        url="http://example.com/search?q=test&id=123",
        base_params={},
        available_specialists=set(agent.specialists.keys()),
        source_agent_name=agent.name,
        excluded_params=agent.EXCLUDED_TESTED_PARAMS,
    )
    assert "hypotheses" in result["unknown_profile"]
    assert "signals" in result["unknown_profile"]


def test_process_unknown_classification_idor_path_may_create_finding():
    agent = _default_agent()
    result = process_unknown_classification_only(
        url="http://example.com/user/42",
        base_params={},
        available_specialists=set(agent.specialists.keys()),
        source_agent_name=agent.name,
        excluded_params=agent.EXCLUDED_TESTED_PARAMS,
    )
    assert result["findings_count"] in (0, 1)


def test_process_unknown_classification_no_specialist_gives_default():
    agent = _default_agent()
    result = process_unknown_classification_only(
        url="http://example.com/nothing/here",
        base_params={},
        available_specialists=set(agent.specialists.keys()),
        source_agent_name=agent.name,
        excluded_params=agent.EXCLUDED_TESTED_PARAMS,
    )
    assert result["unknown_profile"]["selected_specialists"] == ["xss", "sqli"]


def test_process_unknown_classification_same_as_inline():
    agent = _default_agent()
    url = "http://example.com/api/v1/users?id=1&role=admin"
    
    result = process_unknown_classification_only(
        url=url,
        base_params={},
        available_specialists=set(agent.specialists.keys()),
        source_agent_name=agent.name,
        excluded_params=agent.EXCLUDED_TESTED_PARAMS,
    )
    
    # Same as inline logic
    from src.core.agents.swarm.injection.manager_internal.unknown_hypotheses import (
        build_unknown_hypotheses,
        build_unknown_idor_candidate_finding,
    )
    from src.core.agents.swarm.injection.manager_internal.result_normalizer import (
        sanitize_tested_params,
    )
    
    up = build_unknown_hypotheses(url, {}, available_specialists=set(agent.specialists.keys()))
    tp = sanitize_tested_params(
        list(up.get("query_keys", [])) + list(up.get("form_fields", [])),
        excluded_params=agent.EXCLUDED_TESTED_PARAMS,
    )
    ic = build_unknown_idor_candidate_finding(
        url=url, tested_params=tp, unknown_profile=up,
        source_agent_name=agent.name, excluded_params=agent.EXCLUDED_TESTED_PARAMS,
    )
    
    assert result["findings_count"] == (1 if ic is not None else 0)
    assert result["tested_params"] == tp
    assert result["unknown_profile"] == up
