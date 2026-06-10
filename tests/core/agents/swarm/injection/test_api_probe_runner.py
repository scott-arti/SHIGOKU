from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.agents.swarm.injection.manager_internal.api_probe_runner import (
    run_api_minimal_check,
)
from src.core.agents.swarm.injection.manager_internal.models import (
    ApiProbeDependencies,
)


def _response(status, body="", headers=None):
    return SimpleNamespace(status=status, body=body, headers=headers or {})


def _deps(request_client, findings_sink=None):
    if findings_sink is None:
        findings_sink = []
    return ApiProbeDependencies(
        request_client=request_client,
        findings_sink=findings_sink,
        source_agent_name="test-agent",
        excluded_params=frozenset(),
        looks_like_login_page=MagicMock(return_value=False),
        resolve_detection_mode=MagicMock(return_value="phase1"),
        current_context={"findings": findings_sink},
    )


@pytest.mark.asyncio
async def test_runner_unauthenticated_api_access():
    request_client = MagicMock()
    request_client.request = AsyncMock(
        side_effect=[
            SimpleNamespace(status=200, body='{"data":"ok"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"data":"ok"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=204, body="", headers={"Allow": "GET,OPTIONS"}),
            SimpleNamespace(status=401, body='{"error":"unauth"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauth"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauth"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauth"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauth"}', headers={"Content-Type": "application/json"}),
        ]
    )

    result = await run_api_minimal_check(
        url="http://example.com/api/users",
        base_params={"_auth": {"auth_headers": {"Authorization": "Bearer t"}, "cookies": ""}},
        deps=_deps(request_client),
    )

    assert result["findings_count"] >= 1
    assert result["comparison_checks"]


@pytest.mark.asyncio
async def test_runner_mass_assignment_reflected_recheck():
    request_client = MagicMock()
    request_client.request = AsyncMock(
        side_effect=[
            SimpleNamespace(status=200, body='{"user":"test"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"user":"test"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=204, body="", headers={"Allow": "POST,GET,OPTIONS"}),
            SimpleNamespace(status=200, body='{"role":"__shigoku_probe"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"role":"auditor"}', headers={"Content-Type": "application/json"}),
        ]
    )

    result = await run_api_minimal_check(
        url="http://example.com/api/data",
        base_params={"_auth": {"auth_headers": {}, "cookies": ""}},
        deps=_deps(request_client),
    )

    assert result["probe_sent"]
    assert result["findings_count"] >= 1


@pytest.mark.asyncio
async def test_runner_mass_assignment_call_sequence_and_final_evidence():
    request_client = MagicMock()
    request_client.request = AsyncMock(
        side_effect=[
            _response(200, '{"user":"test"}', {"Content-Type": "application/json"}),
            _response(200, '{"user":"test"}', {"Content-Type": "application/json"}),
            _response(204, "", {"Allow": "POST,GET,OPTIONS"}),
            _response(200, '{"role":"__shigoku_probe"}', {"Content-Type": "application/json"}),
            _response(200, '{"role":"auditor"}', {"Content-Type": "application/json"}),
        ]
    )
    findings_sink = []

    result = await run_api_minimal_check(
        url="http://example.com/api/data",
        base_params={"_auth": {"auth_headers": {}, "cookies": ""}},
        deps=_deps(request_client, findings_sink=findings_sink),
    )

    calls = request_client.request.call_args_list
    assert [
        (
            call.kwargs["method"],
            call.kwargs["url"],
            call.kwargs["timeout"],
            call.kwargs["use_cache"],
            call.kwargs["allow_redirects"],
        )
        for call in calls
    ] == [
        ("GET", "http://example.com/api/data", 30, False, True),
        ("GET", "http://example.com/api/data", 30, False, True),
        ("OPTIONS", "http://example.com/api/data", 20, False, False),
        ("POST", "http://example.com/api/data", 20, False, False),
        ("POST", "http://example.com/api/data", 20, False, False),
    ]
    assert calls[3].kwargs["json"]["__shigoku_probe"] == "mass_assignment"
    assert calls[4].kwargs["json"]["__shigoku_probe"] == "mass_assignment_reflect_recheck"
    assert result["probe_request_raw"].startswith("POST http://example.com/api/data HTTP/1.1")
    assert "mass_assignment_reflect_recheck" in result["probe_request_raw"]
    assert result["probe_response_raw"].startswith("HTTP/1.1 200")
    assert "auditor" in result["probe_response_raw"]
    assert len(findings_sink) == result["findings_count"]


@pytest.mark.asyncio
async def test_runner_authenticated_overposting():
    request_client = MagicMock()
    request_client.request = AsyncMock(
        side_effect=[
            SimpleNamespace(status=200, body='{"user":"test"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauth"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=204, body="", headers={"Allow": "GET,OPTIONS"}),
            SimpleNamespace(status=401, body='{"error":"unauth"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"role":"admin"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"role":"auditor"}', headers={"Content-Type": "application/json"}),
        ]
    )

    result = await run_api_minimal_check(
        url="http://example.com/api/protected",
        base_params={"_auth": {"auth_headers": {"Authorization": "Bearer t"}, "cookies": ""}},
        deps=_deps(request_client),
    )

    assert result["probe_sent"]


@pytest.mark.asyncio
async def test_runner_read_only_fallback():
    request_client = MagicMock()
    request_client.request = AsyncMock(
        side_effect=[
            SimpleNamespace(status=200, body='{"user":"test"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"user":"test"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=204, body="", headers={"Allow": "GET,OPTIONS"}),
            SimpleNamespace(status=200, body='q=__shigoku_probe&role=admin', headers={"Content-Type": "text/plain"}),
        ]
    )

    deps = _deps(request_client)
    result = await run_api_minimal_check(
        url="http://example.com/api/data",
        base_params={"_auth": {"auth_headers": {}, "cookies": ""}},
        deps=deps,
    )

    assert result["probe_sent"]


@pytest.mark.asyncio
async def test_runner_exception_path_logs_skipped_reason():
    request_client = MagicMock()
    request_client.request = AsyncMock(
        side_effect=[
            _response(200, "<html>auth</html>", {"Content-Type": "text/html"}),
            _response(200, "<html>unauth</html>", {"Content-Type": "text/html"}),
            _response(204, "", {"Allow": "GET,OPTIONS"}),
            *[_response(405, "", {}) for _ in range(15)],
            RuntimeError("read probe failed"),
        ]
    )

    result = await run_api_minimal_check(
        url="http://example.com/page",
        base_params={"_auth": {"auth_headers": {}, "cookies": ""}},
        deps=_deps(request_client),
    )

    last_call = request_client.request.call_args_list[-1]
    assert result["findings_count"] == 0
    assert result["probe_sent"] is False
    assert result["probe_skipped_reason"] == "write_method_not_discovered_and_read_probe_failed"
    assert result["probe_request_raw"] == ""
    assert last_call.kwargs["method"] == "GET"
    assert last_call.kwargs["timeout"] == 20
    assert last_call.kwargs["use_cache"] is False
    assert last_call.kwargs["allow_redirects"] is False
    assert "__shigoku_probe=mass_assignment_read_probe" in last_call.kwargs["url"]
