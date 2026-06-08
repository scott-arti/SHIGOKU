from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.agents.swarm.injection.manager_internal.unknown_hypotheses import (
    build_unknown_hypotheses,
)
from src.core.agents.swarm.injection.manager_internal.target_classifier import (
    classify_target_url,
)


class TestClassifyUrlSsrf:
    def test_ssrf_candidate_tag_returns_ssrf(self):
        result = classify_target_url("/api/data", "ssrf_candidate")
        assert result == "ssrf"

    def test_ssrf_candidate_beats_cmd_ssrf_path_heuristic(self):
        result = classify_target_url("/exec/fetch", "ssrf_candidate")
        assert result == "ssrf"


class TestBuildUnknownHypothesesSsrf:
    def test_ssrf_signal_from_fetch_path_hint(self):
        manager = InjectionManagerAgent()
        result = build_unknown_hypotheses("http://test.com/fetch?url=x", {}, available_specialists=set(manager.specialists.keys()))
        assert "ssrf" in result["hypotheses"]
        assert "ssrf_signal" in result["signals"]
        assert "ssrf" in result["selected_specialists"] or "cmd_ssrf" in result["selected_specialists"]


class TestSsrfSpecialistRegistration:
    def test_ssrf_in_per_url_timeout(self):
        assert "ssrf" in InjectionManagerAgent.PER_URL_TIMEOUT_BY_TYPE
        assert InjectionManagerAgent.PER_URL_TIMEOUT_BY_TYPE["ssrf"] == 180
