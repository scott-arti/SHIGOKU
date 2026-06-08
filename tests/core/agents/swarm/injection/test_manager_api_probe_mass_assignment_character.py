from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.agents.swarm.injection.manager import InjectionManagerAgent


@pytest.mark.asyncio
async def test_api_minimal_check_preserves_reflection_reverification_metadata_for_unauth_mass_assignment():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}

    request_client = MagicMock()
    request_client.request = AsyncMock(
        side_effect=[
            SimpleNamespace(status=200, body='{"user":"demo"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=204, body="", headers={"Allow": "GET,POST,OPTIONS"}),
            SimpleNamespace(
                status=200,
                body='{"ok":true,"role":"admin","is_admin":true}',
                headers={"Content-Type": "application/json"},
            ),
            SimpleNamespace(
                status=200,
                body='{"ok":true,"role":"auditor","is_admin":false}',
                headers={"Content-Type": "application/json"},
            ),
        ]
    )
    manager._resolve_request_client = MagicMock(return_value=request_client)

    result = await manager._run_api_minimal_check(
        url="http://example.com/vulnerabilities/api/v2/user/",
        base_params={"_auth": {"auth_headers": {"Authorization": "Bearer token"}, "cookies": ""}},
    )

    assert result["findings_count"] == 1
    finding = manager.current_context["findings"][0]
    assert finding.title == "Potential API Mass Assignment / Over-Posting"
    assert "auto_reverified" in finding.tags
    assert finding.additional_info.get("payloads_used") == [
        '{"__shigoku_probe": "mass_assignment", "role": "admin", "is_admin": true}',
        '{"__shigoku_probe": "mass_assignment_reflect_recheck", "role": "auditor", "is_admin": false}',
    ]
    auto_reverification = finding.additional_info.get("auto_reverification", {})
    assert auto_reverification.get("performed") is True
    assert auto_reverification.get("reflection_detected") is True
    assert auto_reverification.get("reflection_reproduced") is True
    assert auto_reverification.get("reflection_recheck_status") == 200


@pytest.mark.asyncio
async def test_api_minimal_check_preserves_authenticated_overposting_metadata_when_auth_context_is_required():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}

    request_client = MagicMock()
    request_client.request = AsyncMock(
        side_effect=[
            SimpleNamespace(status=200, body='{"profile":"ok"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=204, body="", headers={"Allow": "GET,OPTIONS"}),
            SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"ok":true}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"ok":true}', headers={"Content-Type": "application/json"}),
        ]
    )
    manager._resolve_request_client = MagicMock(return_value=request_client)

    result = await manager._run_api_minimal_check(
        url="http://example.com/vulnerabilities/api/v2/user/",
        base_params={"_auth": {"auth_headers": {"Authorization": "Bearer token"}, "cookies": ""}},
    )

    assert result["findings_count"] == 1
    finding = manager.current_context["findings"][0]
    assert finding.title == "Potential Authenticated API Mass Assignment / Over-Posting"
    assert finding.additional_info.get("auth_context_required") is True
    assert finding.additional_info.get("payloads_used") == [
        '{"__shigoku_probe": "mass_assignment_auth", "role": "admin", "is_admin": true}',
        '{"__shigoku_probe": "mass_assignment_auth_recheck", "role": "auditor", "is_admin": false}',
    ]
    auto_reverification = finding.additional_info.get("auto_reverification", {})
    assert auto_reverification.get("performed") is True
    assert auto_reverification.get("reproduced") is True
    assert auto_reverification.get("recheck_status") == 200
