from src.core.agents.swarm.injection.manager import InjectionManagerAgent


class TestClassifyUrlSsrf:
    def test_ssrf_candidate_tag_returns_ssrf(self):
        result = InjectionManagerAgent._classify_url("/api/data", "ssrf_candidate")
        assert result == "ssrf"

    def test_ssrf_candidate_beats_cmd_ssrf_path_heuristic(self):
        result = InjectionManagerAgent._classify_url("/exec/fetch", "ssrf_candidate")
        assert result == "ssrf"


class TestBuildUnknownHypothesesSsrf:
    def test_ssrf_signal_from_fetch_path_hint(self):
        manager = InjectionManagerAgent()
        result = manager._build_unknown_hypotheses("http://test.com/fetch?url=x", {})
        assert "ssrf" in result["hypotheses"]
        assert "ssrf_signal" in result["signals"]
        assert "ssrf" in result["selected_specialists"] or "cmd_ssrf" in result["selected_specialists"]


class TestSsrfSpecialistRegistration:
    def test_ssrf_in_per_url_timeout(self):
        assert "ssrf" in InjectionManagerAgent.PER_URL_TIMEOUT_BY_TYPE
        assert InjectionManagerAgent.PER_URL_TIMEOUT_BY_TYPE["ssrf"] == 180
