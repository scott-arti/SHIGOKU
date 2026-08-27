import pytest

from src.core.agents.specialized.caido_auth import CaidoAuthResolver, CaidoAuthError, _TokenState
from src.core.agents.specialized.caido_sitemap_agent import CaidoSitemapAgent


def test_non_pat_token_is_returned_as_is():
    resolver = CaidoAuthResolver(
        instance_url="http://127.0.0.1:8080",
        configured_token="eyJhbGciOi...",
    )
    assert resolver.is_pat is False


def test_pat_websocket_url_is_normalized():
    resolver = CaidoAuthResolver(
        instance_url="http://127.0.0.1:8080/",
        configured_token="caido_example_pat",
    )
    assert resolver.is_pat is True
    assert resolver.websocket_url == "ws://127.0.0.1:8080/ws/graphql"


@pytest.mark.asyncio
async def test_get_access_token_returns_direct_non_pat_token():
    resolver = CaidoAuthResolver(
        instance_url="http://127.0.0.1:8080",
        configured_token="direct_access_token",
    )
    token = await resolver.get_access_token()
    assert token == "direct_access_token"


@pytest.mark.asyncio
async def test_pat_force_refresh_prefers_refresh_token(monkeypatch, tmp_path):
    resolver = CaidoAuthResolver(
        instance_url="http://127.0.0.1:8080",
        configured_token="caido_pat_1",
        cache_path=tmp_path / "caido_cache.json",
    )
    resolver._state = _TokenState(
        access_token="expired",
        refresh_token="refresh_1",
        expires_at="2000-01-01T00:00:00Z",
    )

    async def fake_refresh(refresh_token: str):
        assert refresh_token == "refresh_1"
        return _TokenState(access_token="refreshed_access", refresh_token="refresh_2")

    async def fake_exchange():
        raise AssertionError("exchange should not be used when refresh succeeds")

    monkeypatch.setattr(resolver, "_refresh_from_refresh_token", fake_refresh)
    monkeypatch.setattr(resolver, "_exchange_pat_for_access_token", fake_exchange)

    token = await resolver.get_access_token(force_refresh=True)
    assert token == "refreshed_access"


@pytest.mark.asyncio
async def test_pat_force_refresh_falls_back_to_exchange(monkeypatch, tmp_path):
    resolver = CaidoAuthResolver(
        instance_url="http://127.0.0.1:8080",
        configured_token="caido_pat_2",
        cache_path=tmp_path / "caido_cache.json",
    )
    resolver._state = _TokenState(
        access_token="expired",
        refresh_token="refresh_legacy",
        expires_at="2000-01-01T00:00:00Z",
    )

    async def fake_refresh(refresh_token: str):
        assert refresh_token == "refresh_legacy"
        return None

    async def fake_exchange():
        return _TokenState(access_token="exchanged_access", refresh_token="refresh_new")

    monkeypatch.setattr(resolver, "_refresh_from_refresh_token", fake_refresh)
    monkeypatch.setattr(resolver, "_exchange_pat_for_access_token", fake_exchange)

    token = await resolver.get_access_token(force_refresh=True)
    assert token == "exchanged_access"


@pytest.mark.asyncio
async def test_pat_exchange_failure_falls_back_to_guest(monkeypatch, tmp_path):
    resolver = CaidoAuthResolver(
        instance_url="http://127.0.0.1:8080",
        configured_token="caido_pat_3",
        cache_path=tmp_path / "caido_cache.json",
    )

    async def fake_refresh(_: str):
        return None

    async def fake_exchange():
        raise CaidoAuthError("cloud failure")

    async def fake_guest():
        return _TokenState(access_token="guest_access")

    monkeypatch.setattr(resolver, "_refresh_from_refresh_token", fake_refresh)
    monkeypatch.setattr(resolver, "_exchange_pat_for_access_token", fake_exchange)
    monkeypatch.setattr(resolver, "_login_as_guest_token", fake_guest)

    token = await resolver.get_access_token(force_refresh=True)
    assert token == "guest_access"


@pytest.mark.asyncio
async def test_pat_exchange_failure_raises_if_guest_fallback_fails(monkeypatch, tmp_path):
    resolver = CaidoAuthResolver(
        instance_url="http://127.0.0.1:8080",
        configured_token="caido_pat_4",
        cache_path=tmp_path / "caido_cache.json",
    )

    async def fake_refresh(_: str):
        return None

    async def fake_exchange():
        raise CaidoAuthError("cloud failure")

    async def fake_guest():
        return None

    monkeypatch.setattr(resolver, "_refresh_from_refresh_token", fake_refresh)
    monkeypatch.setattr(resolver, "_exchange_pat_for_access_token", fake_exchange)
    monkeypatch.setattr(resolver, "_login_as_guest_token", fake_guest)

    with pytest.raises(CaidoAuthError):
        await resolver.get_access_token(force_refresh=True)


@pytest.mark.asyncio
async def test_pat_generic_exchange_error_still_falls_back_to_guest(monkeypatch, tmp_path):
    resolver = CaidoAuthResolver(
        instance_url="http://127.0.0.1:8080",
        configured_token="caido_pat_5",
        cache_path=tmp_path / "caido_cache.json",
    )

    async def fake_refresh(_: str):
        return None

    async def fake_exchange():
        raise RuntimeError("dns resolution failed")

    async def fake_guest():
        return _TokenState(access_token="guest_after_generic_error")

    monkeypatch.setattr(resolver, "_refresh_from_refresh_token", fake_refresh)
    monkeypatch.setattr(resolver, "_exchange_pat_for_access_token", fake_exchange)
    monkeypatch.setattr(resolver, "_login_as_guest_token", fake_guest)

    token = await resolver.get_access_token(force_refresh=True)
    assert token == "guest_after_generic_error"


def test_invalid_token_error_detection():
    errors = [
        {
            "message": "Operation error",
            "extensions": {
                "CAIDO": {
                    "reason": "INVALID_TOKEN",
                    "code": "AUTHORIZATION",
                }
            },
        }
    ]
    assert CaidoSitemapAgent._has_invalid_token_error(errors) is True


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("http://127.0.0.1:8888/", "127.0.0.1"),
        ("http://[::1]:8888/", "::1"),
        ("https://example.com/path?q=1", "example.com"),
        ("example.com:8443", "example.com"),
        ("*.example.com", "example.com"),
        ("[::1]:8888", "::1"),
        ("http://localhost", "localhost"),
        ("", ""),
    ],
)
def test_normalize_domain_filter(raw, expected):
    assert CaidoSitemapAgent._normalize_domain_filter(raw) == expected


@pytest.mark.parametrize(
    ("host", "domain", "expected"),
    [
        ("127.0.0.1", "127.0.0.1", True),
        ("localhost", "127.0.0.1", True),
        ("::1", "127.0.0.1", True),
        ("[::1]:8888", "127.0.0.1", True),
        ("http://localhost", "127.0.0.1", True),
        ("api.example.com", "example.com", True),
        ("evil-example.com", "example.com", False),
        ("example.net", "example.com", False),
    ],
)
def test_host_matches_domain(host, domain, expected):
    normalized = CaidoSitemapAgent._normalize_domain_filter(domain)
    assert CaidoSitemapAgent._host_matches_domain(host, normalized) is expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("http://127.0.0.1:5001", 5001),
        ("http://127.0.0.1:5001/path", 5001),
        ("127.0.0.1:5001", 5001),
        ("localhost:5001", 5001),
        ("[::1]:8888", 8888),
        ("http://[::1]:8888/", 8888),
        ("example.com:8443", 8443),
        ("http://example.com:8080/path?q=1", 8080),
        ("http://localhost", None),
        ("localhost", None),
        ("example.com", None),
        ("*.example.com", None),
        ("", None),
        ("http://example.com:abc/", None),
    ],
)
def test_normalize_domain_port(raw, expected):
    assert CaidoSitemapAgent._normalize_domain_port(raw) == expected


def _caido_node(host, port, path, is_tls=False):
    return {
        "node": {
            "id": f"{host}:{port}:{path}",
            "host": host,
            "port": port,
            "isTls": is_tls,
            "method": "GET",
            "path": path,
            "query": "",
            "raw": "",
            "response": {"statusCode": 200},
        }
    }


def _fetch_harness(monkeypatch, edges, page_info=None):
    """CaidoSitemapAgent を GraphQL と ingest だけ差し替えたハーネスで返す。"""
    agent = CaidoSitemapAgent.__new__(CaidoSitemapAgent)
    info = page_info or {"hasPreviousPage": False, "startCursor": None}

    async def fake_query(_query, variables):
        return {"requests": {"pageInfo": info, "edges": edges}}

    async def fake_ingest(_url):
        return None

    monkeypatch.setattr(agent, "_query_graphql", fake_query)
    monkeypatch.setattr(agent, "_ingest_if_available", fake_ingest)
    return agent


@pytest.mark.asyncio
async def test_fetch_recent_requests_isolates_target_port(monkeypatch):
    """混在ポート履歴で target 127.0.0.1:5001 のURLのみ返し、
    別ポートのループバック履歴（別ローカルサービス）を除外する。"""
    agent = _fetch_harness(
        monkeypatch,
        edges=[
            _caido_node("127.0.0.1", 5001, "/current"),
            _caido_node("localhost", 3000, "/other-a"),
            _caido_node("127.0.0.1", 5002, "/other-port"),
            _caido_node("127.0.0.1", 5001, "/current-2"),
        ],
    )

    contexts = await CaidoSitemapAgent.fetch_recent_requests(agent, domain="http://127.0.0.1:5001", limit=50)
    urls = [ctx.url for ctx in contexts]
    assert urls == ["http://127.0.0.1:5001/current", "http://127.0.0.1:5001/current-2"]


@pytest.mark.asyncio
async def test_fetch_recent_requests_loopback_alias_same_port_passes(monkeypatch):
    """localhost:5001（別名・同ポート）はループバック等価のまま通す。"""
    agent = _fetch_harness(monkeypatch, edges=[_caido_node("localhost", 5001, "/alias")])

    contexts = await CaidoSitemapAgent.fetch_recent_requests(agent, domain="http://localhost:5001", limit=50)
    assert [ctx.url for ctx in contexts] == ["http://localhost:5001/alias"]


@pytest.mark.asyncio
async def test_fetch_recent_requests_without_port_accepts_all_ports(monkeypatch):
    """ポート未指定フィルタ（example.com）は従来どおり全ポート許容（後方互換）。"""
    agent = _fetch_harness(
        monkeypatch,
        edges=[
            _caido_node("example.com", 80, "/a"),
            _caido_node("example.com", 8080, "/b"),
            _caido_node("api.example.com", 443, "/c", is_tls=True),
        ],
    )

    contexts = await CaidoSitemapAgent.fetch_recent_requests(agent, domain="example.com", limit=50)
    urls = [ctx.url for ctx in contexts]
    assert urls == [
        "http://example.com/a",
        "http://example.com:8080/b",
        "https://api.example.com/c",
    ]


@pytest.mark.asyncio
async def test_fetch_recent_requests_paginates_until_domain_match(monkeypatch):
    agent = CaidoSitemapAgent.__new__(CaidoSitemapAgent)
    calls = []

    async def fake_query(_query, variables):
        calls.append(dict(variables))
        before = variables.get("before")
        if before is None:
            return {
                "requests": {
                    "pageInfo": {"hasPreviousPage": True, "startCursor": "cursor-1"},
                    "edges": [
                        {
                            "node": {
                                "id": "1",
                                "host": "example.com",
                                "port": 443,
                                "isTls": True,
                                "method": "GET",
                                "path": "/a",
                                "query": "",
                                "raw": "",
                                "response": {"statusCode": 200},
                            }
                        }
                    ],
                }
            }
        return {
            "requests": {
                "pageInfo": {"hasPreviousPage": False, "startCursor": None},
                "edges": [
                    {
                        "node": {
                            "id": "2",
                            "host": "127.0.0.1",
                            "port": 8888,
                            "isTls": False,
                            "method": "GET",
                            "path": "/target",
                            "query": "",
                            "raw": "",
                            "response": {"statusCode": 200},
                        }
                    }
                ],
            }
        }

    async def fake_ingest(_url):
        return None

    monkeypatch.setattr(agent, "_query_graphql", fake_query)
    monkeypatch.setattr(agent, "_ingest_if_available", fake_ingest)

    contexts = await CaidoSitemapAgent.fetch_recent_requests(agent, domain="http://127.0.0.1:8888/", limit=50)
    assert len(contexts) == 1
    assert contexts[0].url.startswith("http://127.0.0.1:8888/")
    assert len(calls) == 2
