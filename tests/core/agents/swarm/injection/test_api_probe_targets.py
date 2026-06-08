from src.core.agents.swarm.injection.manager_internal.api_probe_targets import (
    build_nearby_api_candidates,
    dedupe_urls,
    extract_api_like_urls,
)


def test_dedupe_urls_preserves_first_seen_order_and_skips_blank_values():
    assert dedupe_urls(
        [
            "",
            "http://example.com/api/users",
            "http://example.com/api/users",
            " http://example.com/api/admin ",
            None,
            "http://example.com/api/admin",
        ]
    ) == [
        "http://example.com/api/users",
        "http://example.com/api/admin",
    ]


def test_extract_api_like_urls_preserves_current_regex_driven_candidate_extraction():
    body = """
    <a href="/api/v2/users/42">user</a>
    <script>const rest = "/rest/admin/audit";</script>
    <span>https://example.com/api/internal/status</span>
    <span>https://other.example.net/api/ignore/me</span>
    """

    assert extract_api_like_urls("http://example.com/docs/index.html", body) == [
        "http://example.com/api/v2/users/42",
        "http://example.com/api/internal/status",
        "http://example.com/api/ignore/me",
        "http://example.com/rest/admin/audit",
        "https://example.com/api/internal/status",
    ]


def test_build_nearby_api_candidates_expands_path_segments_without_duplicates():
    assert build_nearby_api_candidates("http://example.com/account/settings") == [
        "http://example.com/api/account/settings",
        "http://example.com/api/v1/account/settings",
        "http://example.com/api/v2/account/settings",
        "http://example.com/rest/account/settings",
        "http://example.com/api/account",
        "http://example.com/api/v1/account",
        "http://example.com/api/v2/account",
        "http://example.com/rest/account",
        "http://example.com/api/settings",
        "http://example.com/api/v1/settings",
        "http://example.com/api/v2/settings",
        "http://example.com/rest/settings",
    ]
