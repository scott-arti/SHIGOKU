from types import SimpleNamespace

import pytest

from src.core.agents.swarm.injection.manager_internal.builtin_probes import (
    run_csrf_minimal_check,
)


class _FakeRequestClient:
    def __init__(self, responses):
        self._responses = list(responses)

    async def request(self, **_kwargs):
        if not self._responses:
            raise AssertionError("No fake response prepared")
        return self._responses.pop(0)


@pytest.mark.asyncio
async def test_run_csrf_minimal_check_matches_existing_behavior() -> None:
    body = """
    <html>
      <form method="POST" action="/profile/update">
        <input name="email" value="user@example.com" />
        <input name="password" value="pw" />
      </form>
    </html>
    """
    response = SimpleNamespace(status=200, body=body, headers={"Content-Type": "text/html"})
    findings = []

    result = await run_csrf_minimal_check(
        url="http://example.com/profile",
        base_params={"_auth": {"auth_headers": {}, "cookies": ""}},
        request_client=_FakeRequestClient([response]),
        source_agent_name="InjectionManager",
        findings_sink=findings,
        looks_like_login_page=lambda value: False,
        resolve_detection_mode=lambda params, default: default,
        coerce_bool=lambda value, default: default if value is None else bool(value),
    )

    assert result["findings_count"] == 1
    assert "email" in result["tested_params"]
    assert findings
    finding = findings[0]
    assert finding.title == "CSRF Protection Missing (Tokenless Stateful Form)"
    assert finding.additional_info.get("forged_request_succeeded") is False
