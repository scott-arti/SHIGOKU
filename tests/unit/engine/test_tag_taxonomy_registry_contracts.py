from src.core.engine.tag_taxonomy_registry import (
    CATEGORY_API_CANDIDATE,
    CATEGORY_AUTH,
    CATEGORY_CSRF_CANDIDATE,
    CATEGORY_ID_PARAM,
    CATEGORY_REDIRECT_PARAM,
    _build_tag_to_swarm_mapping,
    CATEGORY_TO_TAGS,
    SUBDOMAIN_TAG_TO_SWARM,
    URL_TAG_TO_SWARM,
    TAG_TO_SWARM,
    normalize_category,
    tags_for_category,
)


def test_normalize_category_lowercases_and_trims():
    assert normalize_category("  Auth ") == "auth"


def test_tags_for_category_has_core_security_categories():
    for category in (
        CATEGORY_AUTH,
        CATEGORY_ID_PARAM,
        CATEGORY_REDIRECT_PARAM,
        CATEGORY_API_CANDIDATE,
        CATEGORY_CSRF_CANDIDATE,
    ):
        tags = tags_for_category(category)
        assert isinstance(tags, list)
        assert len(tags) > 0


def test_unknown_category_returns_empty_tags():
    assert tags_for_category("unknown_category") == []


def test_tag_to_swarm_contains_core_candidate_tags():
    required = {
        "sqli_candidate",
        "xss_candidate",
        "ssrf_candidate",
        "open_redirect",
        "auth_endpoint",
        "api_endpoint",
    }
    for tag in required:
        assert tag in TAG_TO_SWARM
        assert TAG_TO_SWARM[tag] in {
            "injection",
            "auth",
            "logic",
            "discovery",
            "scanner",
            "secret",
            "intelligence",
            "fuzzing",
        }


def test_category_to_tags_keys_are_normalized():
    for key in CATEGORY_TO_TAGS.keys():
        assert key == key.strip().lower()


def test_build_tag_to_swarm_mapping_raises_on_conflict():
    import src.core.engine.tag_taxonomy_registry as registry

    original_sub = dict(registry.SUBDOMAIN_TAG_TO_SWARM)
    original_url = dict(registry.URL_TAG_TO_SWARM)
    try:
        registry.SUBDOMAIN_TAG_TO_SWARM = {"dup_tag": "injection"}
        registry.URL_TAG_TO_SWARM = {"dup_tag": "logic"}
        try:
            _build_tag_to_swarm_mapping()
            assert False, "expected ValueError"
        except ValueError as exc:
            assert "Conflicting tag-to-swarm mapping" in str(exc)
    finally:
        registry.SUBDOMAIN_TAG_TO_SWARM = original_sub
        registry.URL_TAG_TO_SWARM = original_url


def test_overlapping_tag_mapping_must_be_consistent():
    overlaps = set(SUBDOMAIN_TAG_TO_SWARM.keys()) & set(URL_TAG_TO_SWARM.keys())
    for tag in overlaps:
        assert SUBDOMAIN_TAG_TO_SWARM[tag] == URL_TAG_TO_SWARM[tag], f"inconsistent overlap tag={tag}"


def test_all_tag_keys_are_normalized_and_swarm_values_valid():
    valid_swarms = {
        "injection",
        "auth",
        "logic",
        "discovery",
        "scanner",
        "secret",
        "intelligence",
        "fuzzing",
    }
    for mapping in (SUBDOMAIN_TAG_TO_SWARM, URL_TAG_TO_SWARM, TAG_TO_SWARM):
        for tag, swarm in mapping.items():
            assert tag == tag.strip().lower()
            assert swarm in valid_swarms
