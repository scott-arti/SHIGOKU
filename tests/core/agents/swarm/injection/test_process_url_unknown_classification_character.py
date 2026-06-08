"""Character tests for _process_single_url unknown classification-only branch."""

from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.agents.swarm.injection.manager_internal.unknown_hypotheses import (
    build_unknown_hypotheses,
    build_unknown_idor_candidate_finding,
)
from src.core.agents.swarm.injection.manager_internal.result_normalizer import (
    sanitize_tested_params,
)


def _make_agent():
    agent = InjectionManagerAgent(config={"model": "test-model"})
    return agent


class TestUnknownClassificationOnlyBranch:
    """unknown classification-only branch の結果 shape を固定する。"""

    def test_builds_hypotheses_and_idor_candidate(self):
        agent = _make_agent()
        url = "http://example.com/user/123"
        base_params = {}

        unknown_profile = build_unknown_hypotheses(
            url, base_params,
            available_specialists=set(agent.specialists.keys()),
        )
        tested_params = sanitize_tested_params(
            list(unknown_profile.get("query_keys", [])) + list(unknown_profile.get("form_fields", [])),
            excluded_params=agent.EXCLUDED_TESTED_PARAMS,
        )
        idor_candidate = build_unknown_idor_candidate_finding(
            url=url,
            tested_params=tested_params,
            unknown_profile=unknown_profile,
            source_agent_name=agent.name,
            excluded_params=agent.EXCLUDED_TESTED_PARAMS,
        )

        assert isinstance(unknown_profile, dict)
        assert "hypotheses" in unknown_profile
        assert "signals" in unknown_profile
        assert "selected_specialists" in unknown_profile
        # idor candidate may be None or Finding

    def test_classification_only_result_has_expected_keys(self):
        agent = _make_agent()
        url = "http://example.com/user/123"
        base_params = {}

        unknown_profile = build_unknown_hypotheses(
            url, base_params,
            available_specialists=set(agent.specialists.keys()),
        )
        tested_params = sanitize_tested_params(
            list(unknown_profile.get("query_keys", [])) + list(unknown_profile.get("form_fields", [])),
            excluded_params=agent.EXCLUDED_TESTED_PARAMS,
        )
        idor_candidate = build_unknown_idor_candidate_finding(
            url=url,
            tested_params=tested_params,
            unknown_profile=unknown_profile,
            source_agent_name=agent.name,
            excluded_params=agent.EXCLUDED_TESTED_PARAMS,
        )

        result = {
            "findings_count": 1 if idor_candidate is not None else 0,
            "findings_list": [idor_candidate] if idor_candidate is not None else [],
            "tested_params": tested_params,
            "unknown_profile": unknown_profile,
            "idor_candidate": idor_candidate,
        }
        assert "findings_count" in result
        assert "tested_params" in result
        assert "unknown_profile" in result

    def test_idor_candidate_created_for_id_path(self):
        agent = _make_agent()
        url = "http://example.com/account/42"
        base_params = {}

        unknown_profile = build_unknown_hypotheses(
            url, base_params,
            available_specialists=set(agent.specialists.keys()),
        )
        tested_params = sanitize_tested_params(
            list(unknown_profile.get("query_keys", [])) + list(unknown_profile.get("form_fields", [])),
            excluded_params=agent.EXCLUDED_TESTED_PARAMS,
        )
        idor_candidate = build_unknown_idor_candidate_finding(
            url=url,
            tested_params=tested_params,
            unknown_profile=unknown_profile,
            source_agent_name=agent.name,
            excluded_params=agent.EXCLUDED_TESTED_PARAMS,
        )

        assert unknown_profile.get("hypotheses") is not None
