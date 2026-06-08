from types import SimpleNamespace

import pytest

from src.core.agents.swarm.injection.manager import InjectionManagerAgent


class _FakeRequestClient:
    def __init__(self, responses):
        self._responses = list(responses)

    async def request(self, **_kwargs):
        if not self._responses:
            raise AssertionError("No fake response prepared")
        return self._responses.pop(0)


@pytest.mark.asyncio
async def test_manager_csrf_probe_character_tokenless_form_creates_finding() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}

    body = """
    <html>
      <form method="POST" action="/profile/update">
        <input name="email" value="user@example.com" />
        <input name="password" value="pw" />
      </form>
    </html>
    """
    response = SimpleNamespace(status=200, body=body, headers={"Content-Type": "text/html"})
    manager._resolve_request_client = lambda: _FakeRequestClient([response])

    result = await manager._run_csrf_minimal_check(
        "http://example.com/profile",
        {"_auth": {"auth_headers": {}, "cookies": ""}},
    )

    assert result["findings_count"] == 1
    assert "email" in result["tested_params"]
    assert manager.current_context["findings"]
    finding = manager.current_context["findings"][0]
    assert finding.title == "CSRF Protection Missing (Tokenless Stateful Form)"
    assert finding.additional_info.get("forged_request_succeeded") is False
