from src.core.agents.swarm.injection.manager_internal.specialist_router import (
    SPECIALIST_MAP,
    select_specialists,
)

AVAILABLE = {"sqli", "xss", "lfi", "ssti", "ssrf", "csrf", "crlf", "graphql", "cors", "cmd_ssrf", "redirect"}


class TestSpecialistRouter:

    def test_select_sqli_from_hypothesis(self) -> None:
        result = select_specialists(
            ["sqli", "xss"],
            available_specialists=AVAILABLE,
        )
        assert "sqli" in result
        assert "xss" in result

    def test_empty_hypotheses_returns_default(self) -> None:
        result = select_specialists(
            [],
            available_specialists=AVAILABLE,
        )
        assert result == ["xss", "sqli"]

    def test_unmatched_hypotheses_returns_default(self) -> None:
        result = select_specialists(
            ["nonexistent"],
            available_specialists=AVAILABLE,
        )
        assert result == ["xss", "sqli"]

    def test_deduplicates(self) -> None:
        result = select_specialists(
            ["sqli", "sqli", "xss"],
            available_specialists=AVAILABLE,
        )
        assert result == ["sqli", "xss"]

    def test_filters_unavailable(self) -> None:
        result = select_specialists(
            ["sqli", "lfi", "ssti"],
            available_specialists={"xss"},
        )
        assert result == []

    def test_api_maps_to_sqli(self) -> None:
        result = select_specialists(
            ["api"],
            available_specialists=AVAILABLE,
        )
        assert result == ["sqli"]

    def test_csrf_maps_to_xss(self) -> None:
        result = select_specialists(
            ["csrf"],
            available_specialists=AVAILABLE,
        )
        assert result == ["xss"]

    def test_idor_maps_to_sqli(self) -> None:
        result = select_specialists(
            ["idor"],
            available_specialists=AVAILABLE,
        )
        assert result == ["sqli"]

    def test_specialist_map_all_keys_valid(self) -> None:
        for hypothesis, specialist in SPECIALIST_MAP.items():
            assert isinstance(hypothesis, str)
            assert isinstance(specialist, str)
            assert len(hypothesis) > 0
            assert len(specialist) > 0
