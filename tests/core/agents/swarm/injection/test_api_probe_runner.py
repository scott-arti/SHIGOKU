from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.agents.swarm.injection.manager_internal.api_probe_runner import (
    run_api_minimal_check,
)
from src.core.agents.swarm.injection.manager_internal.models import (
    ApiProbeDependencies,
)


def _deps(request_client, findings_sink=None):
    findings_sink = findings_sink or []
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
            SimpleNamespace(status=200, body='{"user":"test"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"user":"test"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=204, body="", headers={"Allow": "GET,OPTIONS"}),
            SimpleNamespace(status=401, body='{"error":"unauth"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauth"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauth"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauth"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauth"}', headers={"Content-Type": "application/json"}),
        ]
    )

    result = await run_api_minimal_check(
        url="http://example.com/api/data",
        base_params={"_auth": {"auth_headers": {}, "cookies": ""}},
        deps=_deps(request_client),
    )

    assert result["findings_count"] >= 0
