from __future__ import annotations

import pytest
from unittest.mock import AsyncMock

from src.core.agents.swarm.injection.smart_xss import SmartXSSHunter


class _SuiteSpy:
    def __init__(self):
        self.calls = []

    def record_payload_outcome(self, **kwargs):
        self.calls.append(kwargs)
        return {"trials": 1, "successes": 1}


@pytest.mark.asyncio
async def test_xcto10_runtime_send_request_updates_learning_on_reflection():
    hunter = SmartXSSHunter()
    hunter._waf_suite = _SuiteSpy()
    hunter.context = {
        "param": "q",
        "target": "http://example.com/search?q=1",
        "method": "GET",
        "auth_headers": {},
        "params": {"q": "1"},
    }

    hunter.smart_client.request = AsyncMock(
        return_value={"status": 200, "body": "<html><script>alert(1)</script></html>", "headers": {}}
    )

    await hunter._send_request("<script>alert(1)</script>")

    assert hunter._waf_suite.calls, "runtime must report outcome to XCTO-10 learner"
    assert hunter._waf_suite.calls[-1]["success"] is True


@pytest.mark.asyncio
async def test_xcto10_runtime_send_request_updates_learning_on_blocked():
    hunter = SmartXSSHunter()
    hunter._waf_suite = _SuiteSpy()
    hunter.context = {
        "param": "q",
        "target": "http://example.com/search?q=1",
        "method": "GET",
        "auth_headers": {},
        "params": {"q": "1"},
    }

    hunter.smart_client.request = AsyncMock(
        return_value={"status": 0, "body": "", "headers": {}, "error": "blocked"}
    )

    await hunter._send_request("<img src=x onerror=alert(1)>")

    assert hunter._waf_suite.calls, "blocked outcomes must also be learned"
    assert hunter._waf_suite.calls[-1]["blocked"] is True
