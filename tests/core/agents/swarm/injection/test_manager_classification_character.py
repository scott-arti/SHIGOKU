import pytest

from src.core.agents.swarm.injection.manager import InjectionManagerAgent


@pytest.mark.parametrize(
    ("url", "category", "expected"),
    [
        ("http://example.com/greet", "ssti_candidate", "ssti"),
        ("http://example.com/render/page", "", "ssti"),
        ("http://example.com/view?file=doc.pdf", "file_param", "lfi"),
        ("http://example.com/api/v1/users", "api_candidate", "api"),
        ("http://example.com/api/data", "cors_candidate", "cors"),
        ("/exec/fetch", "ssrf_candidate", "ssrf"),
        ("/graphql", "", "graphql"),
        ("http://target.test/redirect?url=x", "crlf_candidate", "crlf"),
    ],
)
def test_injection_manager_classification_character(url: str, category: str, expected: str) -> None:
    assert InjectionManagerAgent._classify_url(url, category) == expected
