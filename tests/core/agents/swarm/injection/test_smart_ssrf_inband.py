"""SGK-2026-0482: SmartSSRFHunter の in-band SSRF opt-in 経路。

製品非依存 fixture のみ。サーバが URL 値フィールドを取得して応答本文を
in-band 反映し、かつクライアントが直接到達できないときだけ ssrf Finding を
発行する（fail-closed）。
"""
import asyncio
import json
from types import SimpleNamespace

import pytest

from src.core.agents.swarm.injection.smart_ssrf import SmartSSRFHunter
from src.core.agents.swarm.base import Task


class _StubClient:
    """POST(トリガ) は reflect_key 付き JSON を返す。GET(直接到達) は
    direct_status で可否を制御する（0=到達不可）。"""

    def __init__(self, reflected="INTERNAL-ONLY-BODY", direct_status=0):
        self._reflected = reflected
        self._direct_status = direct_status

    async def request(self, method, url, headers=None, data=None, timeout=30, **kw):
        if method.upper() == "GET":
            if self._direct_status <= 0:
                return SimpleNamespace(status=0, text="", body="", headers={}, error="unreachable")
            return SimpleNamespace(status=self._direct_status, text="ok", body="ok", headers={})
        payload = json.dumps({"response_from_api": self._reflected, "status": 200})
        return SimpleNamespace(status=200, text=payload, body=payload, headers={})

    async def close(self):
        pass


def _task():
    return Task(id="t", name="t", target="http://target.example/fetch", tags=["ssrf"], params={
        "ssrf_inband": {
            "endpoint": "http://target.example/fetch",
            "method": "POST",
            "url_field": "resource_url",
            "probe_url": "http://internal.invalid/",
            "reflect_key": "response_from_api",
            "body_template": {"other": "x"},
            "headers": {"Authorization": "Bearer t"},
        }
    })


def _run(client):
    spec = SmartSSRFHunter(config={})
    spec._client = client
    return asyncio.run(spec.execute(_task()))


def test_inband_finding_emitted_when_reflected_and_unreachable():
    fs = _run(_StubClient(reflected="INTERNAL-ONLY-BODY", direct_status=0))
    assert len(fs) == 1
    ev = fs[0].to_dict()["additional_info"]["ssrf_inband_evidence"]
    assert ev["fetched_url"] == "http://internal.invalid/"
    assert ev["server_reflected_body"] == "INTERNAL-ONLY-BODY"
    assert ev["client_direct_unreachable"] is True
    assert fs[0].to_dict()["vuln_type"].lower() == "ssrf"


def test_no_finding_when_client_can_reach_directly():
    fs = _run(_StubClient(reflected="BODY", direct_status=200))
    assert fs == []


def test_no_finding_when_no_reflection():
    fs = _run(_StubClient(reflected="", direct_status=0))
    assert fs == []


def test_no_finding_when_required_params_missing():
    spec = SmartSSRFHunter(config={})
    spec._client = _StubClient()
    task = Task(id="t", name="t", target="http://target.example/fetch", tags=["ssrf"],
                params={"ssrf_inband": {"endpoint": "http://target.example/fetch"}})
    assert asyncio.run(spec.execute(task)) == []
