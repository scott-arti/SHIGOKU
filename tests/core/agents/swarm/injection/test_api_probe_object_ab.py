from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.agents.swarm.injection.manager_internal.api_probe_object_ab import (
    run_object_ab_comparison,
)


@pytest.mark.asyncio
async def test_run_object_ab_comparison_returns_defaults_without_candidate():
    request_client = MagicMock()
    request_client.request = AsyncMock()

    result = await run_object_ab_comparison(
        request_client=request_client,
        url="http://example.com/api/users",
        auth_headers={"Authorization": "Bearer token"},
        object_ab_candidate={},
    )

    assert result == {
        "performed": False,
        "comparison": {"performed": False},
        "baseline_body": "",
        "variant_body": "",
        "param_name": "",
    }
    request_client.request.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_object_ab_comparison_executes_baseline_and_variant_requests():
    request_client = MagicMock()
    request_client.request = AsyncMock(
        side_effect=[
            SimpleNamespace(status=200, body='{"user_id":1}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"user_id":2}', headers={"Content-Type": "application/json"}),
        ]
    )

    result = await run_object_ab_comparison(
        request_client=request_client,
        url="http://example.com/api/users?id=1",
        auth_headers={"Authorization": "Bearer token"},
        object_ab_candidate={
            "param": "id",
            "location": "query",
            "resource_a": "1",
            "resource_b": "2",
            "mutated_url": "http://example.com/api/users?id=2",
        },
    )

    assert result["performed"] is True
    assert result["param_name"] == "id"
    assert result["baseline_body"] == '{"user_id":1}'
    assert result["variant_body"] == '{"user_id":2}'
    assert result["comparison"] == {
        "performed": True,
        "param": "id",
        "location": "query",
        "resource_a": "1",
        "resource_b": "2",
        "url_a": "http://example.com/api/users?id=1",
        "url_b": "http://example.com/api/users?id=2",
        "status_a": 200,
        "status_b": 200,
        "body_length_a": 13,
        "body_length_b": 13,
    }
