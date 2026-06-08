from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.agents.swarm.injection.manager import InjectionManagerAgent


@pytest.mark.asyncio
async def test_api_minimal_check_discovers_endpoint_exposed_from_api_landing_page():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}

    request_client = MagicMock()
    request_client.request = AsyncMock(
        side_effect=[
            SimpleNamespace(
                status=200,
                body='{"docs":"/api/v2/users/42"}',
                headers={"Content-Type": "application/json"},
            ),
            SimpleNamespace(
                status=401,
                body='{"error":"unauthorized"}',
                headers={"Content-Type": "application/json"},
            ),
            SimpleNamespace(
                status=200,
                body='{"user_id":42,"role":"admin"}',
                headers={"Content-Type": "application/json"},
            ),
            SimpleNamespace(
                status=200,
                body='{"user_id":42,"role":"admin"}',
                headers={"Content-Type": "application/json"},
            ),
            SimpleNamespace(status=204, body="", headers={"Allow": "GET,OPTIONS"}),
            SimpleNamespace(
                status=401,
                body='{"error":"unauthorized"}',
                headers={"Content-Type": "application/json"},
            ),
            SimpleNamespace(
                status=401,
                body='{"error":"unauthorized"}',
                headers={"Content-Type": "application/json"},
            ),
        ]
    )
    manager._resolve_request_client = MagicMock(return_value=request_client)

    result = await manager._run_api_minimal_check(
        url="http://example.com/api/",
        base_params={"_auth": {"auth_headers": {"Authorization": "Bearer token"}, "cookies": ""}},
    )

    assert result["findings_count"] == 1
    finding = manager.current_context["findings"][0]
    assert finding.title == "Unauthenticated Access to Discovered API Endpoint"
    assert finding.target_url == "http://example.com/api/v2/users/42"
    differential = finding.additional_info.get("authz_differential", {})
    assert differential.get("scenario") == "unauthenticated_discovered_api_access"
    assert "discovered_from_landing" in differential.get("signals", [])

