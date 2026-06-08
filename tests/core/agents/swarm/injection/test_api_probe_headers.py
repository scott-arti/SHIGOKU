from src.core.agents.swarm.injection.manager_internal.api_probe_headers import (
    normalize_header_keys,
)


def test_normalize_header_keys_canonicalizes_auth_and_cookie_names():
    assert normalize_header_keys(
        {
            "authorization": "Bearer token",
            "cookie": "sid=1",
            "X-Test": "ok",
            "": "skip",
        }
    ) == {
        "Authorization": "Bearer token",
        "Cookie": "sid=1",
        "X-Test": "ok",
    }
