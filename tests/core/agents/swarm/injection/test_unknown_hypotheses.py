from src.core.agents.swarm.injection.manager_internal.unknown_hypotheses import (
    build_unknown_hypotheses,
    build_unknown_idor_candidate_finding,
)

AVAILABLE_SPECIALISTS = {"sqli", "xss", "lfi", "ssti", "ssrf", "csrf", "crlf", "graphql", "cors", "cmd_ssrf", "redirect"}
EXCLUDED_PARAMS = {
    "scan_profile", "profile", "forms", "url_evidence", "detection_mode",
    "_auth", "_context", "method", "tags", "category", "count",
    "source_file", "targets", "extra_targets", "auth_headers", "headers", "cookies",
}


class TestBuildUnknownHypotheses:
    """build_unknown_hypotheses 抽出関数の単体テスト。"""

    def test_basic_sqli_hypothesis(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/search?q=test&id=123",
            base_params={},
            available_specialists=AVAILABLE_SPECIALISTS,
        )
        assert "sqli" in profile["hypotheses"]

    def test_xss_from_query_and_comment_path(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/comment?q=hello",
            base_params={},
            available_specialists=AVAILABLE_SPECIALISTS,
        )
        assert "xss" in profile["hypotheses"]

    def test_lfi_from_download_path(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/download?file=report.pdf",
            base_params={},
            available_specialists=AVAILABLE_SPECIALISTS,
        )
        assert "lfi" in profile["hypotheses"]

    def test_graphql_from_path(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/graphql",
            base_params={},
            available_specialists=AVAILABLE_SPECIALISTS,
        )
        assert "graphql" in profile["hypotheses"]

    def test_api_from_path(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/api/v1/users",
            base_params={},
            available_specialists=AVAILABLE_SPECIALISTS,
        )
        assert "api" in profile["hypotheses"]

    def test_idor_from_path(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/api/v1/user/123",
            base_params={},
            available_specialists=AVAILABLE_SPECIALISTS,
        )
        assert "idor" in profile["hypotheses"]

    def test_crlf_from_redirect(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/redirect?next=http://evil.com",
            base_params={},
            available_specialists=AVAILABLE_SPECIALISTS,
        )
        assert "crlf" in profile["hypotheses"]

    def test_csrf_from_password_path(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/change_password",
            base_params={},
            available_specialists=AVAILABLE_SPECIALISTS,
        )
        assert "csrf" in profile["hypotheses"]

    def test_form_tag_creates_signal(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/login",
            base_params={
                "url_evidence": {
                    "has_form_tag": True,
                    "response_body_snippet": "<form>...</form>",
                }
            },
            available_specialists=AVAILABLE_SPECIALISTS,
        )
        assert "form_tag_in_response" in profile["signals"]

    def test_csp_unsafe_inline_adds_xss(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/page",
            base_params={
                "url_evidence": {
                    "response_headers": {
                        "Content-Security-Policy": "script-src 'unsafe-inline'",
                    }
                }
            },
            available_specialists=AVAILABLE_SPECIALISTS,
        )
        assert "csp_present" in profile["signals"]
        assert "xss" in profile["hypotheses"]

    def test_secret_in_response_adds_signal(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/api/keys",
            base_params={
                "url_evidence": {
                    "response_body_snippet": "api_key: abc123 secret: xyz",
                }
            },
            available_specialists=AVAILABLE_SPECIALISTS,
        )
        assert "secret_like_response" in profile["signals"]

    def test_json_content_type_with_api_path(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/api/data",
            base_params={
                "url_evidence": {
                    "response_headers": {"Content-Type": "application/json"},
                }
            },
            available_specialists=AVAILABLE_SPECIALISTS,
        )
        assert "idor" in profile["hypotheses"]
        assert "api_json_surface" in profile["signals"]

    def test_admin_path_200_adds_authz_signal(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/admin/users",
            base_params={
                "url_evidence": {"response_status": 200},
            },
            available_specialists=AVAILABLE_SPECIALISTS,
        )
        assert "idor" in profile["hypotheses"]
        assert "authz_boundary_signal" in profile["signals"]

    def test_no_hypotheses_uses_default(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/nothing/here",
            base_params={},
            available_specialists=AVAILABLE_SPECIALISTS,
        )
        assert "default_unknown_path" in profile["signals"]
        assert profile["selected_specialists"] == ["xss", "sqli"]

    def test_form_fields_extracted(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/login",
            base_params={
                "forms": [
                    {"inputs": [{"name": "username"}, {"name": "password"}]}
                ]
            },
            available_specialists=AVAILABLE_SPECIALISTS,
        )
        assert "username" in profile["form_fields"]
        assert "password" in profile["form_fields"]
        assert "xss" in profile["hypotheses"]

    def test_ssti_prioritized_over_lfi(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/render?template=main",
            base_params={},
            available_specialists=AVAILABLE_SPECIALISTS,
        )
        assert "ssti" in profile["hypotheses"]

    def test_missing_specialist_filtered_out(self) -> None:
        profile = build_unknown_hypotheses(
            url="http://example.com/search?q=test&id=1",
            base_params={},
            available_specialists={"xss"},
        )
        for s in profile["selected_specialists"]:
            assert s in {"xss"}


class TestBuildUnknownIdorCandidateFinding:
    """build_unknown_idor_candidate_finding 抽出関数の単体テスト。"""

    def test_idor_hypothesis_creates_finding(self) -> None:
        finding = build_unknown_idor_candidate_finding(
            url="http://example.com/user/123",
            tested_params=["id"],
            unknown_profile={
                "hypotheses": ["idor", "api"],
                "signals": ["idor_signal", "api_signal"],
                "response_status": 200,
            },
            source_agent_name="test_agent",
            excluded_params=EXCLUDED_PARAMS,
        )
        assert finding is not None
        assert finding.title == "Potential IDOR/BOLA Object Access Surface"

    def test_no_idor_hypothesis_returns_none(self) -> None:
        finding = build_unknown_idor_candidate_finding(
            url="http://example.com/search?q=test",
            tested_params=["q"],
            unknown_profile={
                "hypotheses": ["sqli", "xss"],
                "signals": ["sqli_signal", "xss_signal"],
            },
            source_agent_name="test_agent",
            excluded_params=EXCLUDED_PARAMS,
        )
        assert finding is None

    def test_idor_without_signal_returns_none(self) -> None:
        finding = build_unknown_idor_candidate_finding(
            url="http://example.com/user/123",
            tested_params=["id"],
            unknown_profile={
                "hypotheses": ["idor"],
                "signals": ["api_signal"],
            },
            source_agent_name="test_agent",
            excluded_params=EXCLUDED_PARAMS,
        )
        assert finding is None

    def test_tags_and_metadata(self) -> None:
        finding = build_unknown_idor_candidate_finding(
            url="http://example.com/order/456",
            tested_params=["order_id"],
            unknown_profile={
                "hypotheses": ["idor"],
                "signals": ["idor_signal"],
                "response_status": 200,
            },
            source_agent_name="test_agent",
            excluded_params=EXCLUDED_PARAMS,
        )
        assert finding is not None
        assert "idor" in finding.tags
        assert "manual_verify" in finding.tags
        assert finding.additional_info["detection_class"] == "idor_bola"
        assert finding.additional_info["heuristic_candidate"] is True
        assert finding.source_agent == "test_agent"

    def test_excluded_params_filtered(self) -> None:
        finding = build_unknown_idor_candidate_finding(
            url="http://example.com/user/1",
            tested_params=["id", "scan_profile", "category", "legit"],
            unknown_profile={
                "hypotheses": ["idor"],
                "signals": ["idor_signal"],
            },
            source_agent_name="test_agent",
            excluded_params=EXCLUDED_PARAMS,
        )
        assert finding is not None
        tp = finding.additional_info["tested_params"]
        assert "scan_profile" not in tp
        assert "category" not in tp
        assert "id" in tp
        assert "legit" in tp
