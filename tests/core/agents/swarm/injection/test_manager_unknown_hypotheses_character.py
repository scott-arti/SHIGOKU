from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.agents.swarm.injection.manager_internal.unknown_hypotheses import (
    build_unknown_hypotheses,
    build_unknown_idor_candidate_finding,
)


class TestBuildUnknownHypothesesCharacter:
    """build_unknown_hypotheses の外側挙動を固定するキャラクターテスト。"""

    @staticmethod
    def _make_agent() -> InjectionManagerAgent:
        return InjectionManagerAgent(config={"model": "test-model"})

    @staticmethod
    def _h(agent, url, base_params):
        return build_unknown_hypotheses(
            url, base_params,
            available_specialists=set(agent.specialists.keys()),
        )

    def test_basic_sqli_hypothesis(self) -> None:
        agent = self._make_agent()
        profile = self._h(agent, "http://example.com/search?q=test&id=123", {})
        assert "sqli" in profile["hypotheses"]
        assert "sqli_signal" in profile["signals"]

    def test_xss_hypothesis_from_query(self) -> None:
        agent = self._make_agent()
        profile = self._h(agent, "http://example.com/comment?q=hello", {})
        assert "xss" in profile["hypotheses"]

    def test_lfi_hypothesis_from_path(self) -> None:
        agent = self._make_agent()
        profile = self._h(agent, "http://example.com/download?file=report.pdf", {})
        assert "lfi" in profile["hypotheses"]

    def test_graphql_from_path(self) -> None:
        agent = self._make_agent()
        profile = self._h(agent, "http://example.com/graphql", {})
        assert "graphql" in profile["hypotheses"]

    def test_api_from_path(self) -> None:
        agent = self._make_agent()
        profile = self._h(agent, "http://example.com/api/v1/users", {})
        assert "api" in profile["hypotheses"]

    def test_idor_from_path(self) -> None:
        agent = self._make_agent()
        profile = self._h(agent, "http://example.com/api/v1/user/123", {})
        assert "idor" in profile["hypotheses"]

    def test_crlf_from_path(self) -> None:
        agent = self._make_agent()
        profile = self._h(agent, "http://example.com/redirect?next=http://evil.com", {})
        assert "crlf" in profile["hypotheses"]

    def test_csrf_from_path(self) -> None:
        agent = self._make_agent()
        profile = self._h(agent, "http://example.com/change_password", {})
        assert "csrf" in profile["hypotheses"]

    def test_form_tag_signal(self) -> None:
        agent = self._make_agent()
        profile = self._h(
            agent,
            "http://example.com/login",
            {
                "url_evidence": {
                    "has_form_tag": True,
                    "response_body_snippet": "<form>...</form>",
                }
            },
        )
        assert "form_tag_in_response" in profile["signals"]

    def test_csp_signal(self) -> None:
        agent = self._make_agent()
        profile = self._h(
            agent,
            "http://example.com/page",
            {
                "url_evidence": {
                    "response_headers": {
                        "Content-Security-Policy": "script-src 'unsafe-inline'",
                    }
                }
            },
        )
        assert "csp_present" in profile["signals"]
        assert "xss" in profile["hypotheses"]

    def test_secret_like_response(self) -> None:
        agent = self._make_agent()
        profile = self._h(
            agent,
            "http://example.com/api/keys",
            {
                "url_evidence": {
                    "response_body_snippet": "api_key: abc123 secret: xyz",
                }
            },
        )
        assert "secret_like_response" in profile["signals"]

    def test_json_api_content_type(self) -> None:
        agent = self._make_agent()
        profile = self._h(
            agent,
            "http://example.com/api/data",
            {
                "url_evidence": {
                    "response_headers": {"Content-Type": "application/json"},
                }
            },
        )
        assert "idor" in profile["hypotheses"]
        assert "api_json_surface" in profile["signals"]

    def test_admin_path_with_200_creates_authz_signal(self) -> None:
        agent = self._make_agent()
        profile = self._h(
            agent,
            "http://example.com/admin/users",
            {
                "url_evidence": {
                    "response_status": 200,
                }
            },
        )
        assert "idor" in profile["hypotheses"]
        assert "authz_boundary_signal" in profile["signals"]

    def test_no_hypotheses_falls_back_to_default(self) -> None:
        agent = self._make_agent()
        profile = self._h(agent, "http://example.com/nothing/here", {})
        assert "default_unknown_path" in profile["signals"]
        assert profile["selected_specialists"] == ["xss", "sqli"]

    def test_returns_path_and_query_keys(self) -> None:
        agent = self._make_agent()
        profile = self._h(agent, "http://example.com/search?q=test&page=1", {})
        assert "/search" in profile["path"]
        assert "q" in profile["query_keys"]
        assert "page" in profile["query_keys"]

    def test_form_fields_extracted(self) -> None:
        agent = self._make_agent()
        profile = self._h(
            agent,
            "http://example.com/login",
            {
                "forms": [
                    {"inputs": [{"name": "username"}, {"name": "password"}]}
                ]
            },
        )
        assert "username" in profile["form_fields"]
        assert "password" in profile["form_fields"]
        assert "xss" in profile["hypotheses"]

    def test_ssti_takes_priority_over_lfi(self) -> None:
        agent = self._make_agent()
        profile = self._h(agent, "http://example.com/render?template=main", {})
        assert "ssti" in profile["hypotheses"]


class TestBuildUnknownIdorCandidateFindingCharacter:
    """build_unknown_idor_candidate_finding のキャラクターテスト。"""

    @staticmethod
    def _make_agent() -> InjectionManagerAgent:
        return InjectionManagerAgent(config={"model": "test-model"})

    @staticmethod
    def _f(agent, url, tested_params, unknown_profile):
        return build_unknown_idor_candidate_finding(
            url=url,
            tested_params=tested_params,
            unknown_profile=unknown_profile,
            source_agent_name=agent.name,
            excluded_params=agent.EXCLUDED_TESTED_PARAMS,
        )

    def test_idor_hypothesis_creates_finding(self) -> None:
        agent = self._make_agent()
        finding = self._f(
            agent,
            "http://example.com/user/123",
            ["id"],
            {
                "hypotheses": ["idor", "api"],
                "signals": ["idor_signal", "api_signal"],
                "response_status": 200,
            },
        )
        assert finding is not None
        assert finding.title == "Potential IDOR/BOLA Object Access Surface"
        assert finding.vuln_type.name == "BROKEN_ACCESS_CONTROL"

    def test_no_idor_hypothesis_returns_none(self) -> None:
        agent = self._make_agent()
        finding = self._f(
            agent,
            "http://example.com/search?q=test",
            ["q"],
            {
                "hypotheses": ["sqli", "xss"],
                "signals": ["sqli_signal", "xss_signal"],
            },
        )
        assert finding is None

    def test_idor_hypothesis_without_signal_returns_none(self) -> None:
        agent = self._make_agent()
        finding = self._f(
            agent,
            "http://example.com/user/123",
            ["id"],
            {
                "hypotheses": ["idor"],
                "signals": ["api_signal"],
            },
        )
        assert finding is None

    def test_idor_finding_has_expected_tags(self) -> None:
        agent = self._make_agent()
        finding = self._f(
            agent,
            "http://example.com/order/456",
            ["order_id"],
            {
                "hypotheses": ["idor"],
                "signals": ["idor_signal"],
                "response_status": 200,
            },
        )
        assert finding is not None
        assert "idor" in finding.tags
        assert "manual_verify" in finding.tags
        assert finding.additional_info["detection_class"] == "idor_bola"
        assert finding.additional_info["heuristic_candidate"] is True
