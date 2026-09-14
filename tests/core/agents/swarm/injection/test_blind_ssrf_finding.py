"""SGK-2026-0495: SmartBlindSSRFHunter が OOB(帯域外)コールバックでブラインド SSRF を
確定グレードの Finding に変換することを検証する。製品非依存（合成・注入クライアント/受信器）。"""

import asyncio
from types import SimpleNamespace

from src.core.agents.swarm.injection.smart_blind_ssrf import SmartBlindSSRFHunter
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.models.finding import VulnType

_URL = "https://target.example/check_existence"


class _FakeOOBProvider:
    channel = "http"

    def __init__(self, will_callback=True):
        self.will_callback = will_callback
        self._n = 0

    async def start(self):
        pass

    async def stop(self):
        pass

    def new_callback(self):
        self._n += 1
        token = "ssrftok%d" % self._n
        return f"http://oob.example/callback/{token}", token

    async def poll(self, token, timeout=10.0):
        if not self.will_callback:
            return None
        return {"token": token, "channel": "http", "remote_ip": "10.0.0.9",
                "method": "HEAD", "path": f"/callback/{token}", "query_string": "",
                "timestamp": 1.0, "headers": {"Host": "oob.example", "User-Agent": "python-requests"}}


class _FakeHTTPClient:
    def __init__(self, status=200):
        self.status = status
        self.calls = []

    async def request(self, method, url, params=None, data=None, headers=None, use_proxy=True, **kw):
        self.calls.append({"method": method, "url": url, "params": params, "data": data})
        return SimpleNamespace(status=self.status, body="", text="", headers={})


def _run(oob, params=None):
    eng = SmartBlindSSRFHunter()
    eng._oob = oob
    eng._client = _FakeHTTPClient()
    task = Task(id="t", name="bssrf", target=_URL, tags=["ssrf"])
    task.params = params or {"ssrf_param": "url", "ssrf_modes": ["form"]}
    return asyncio.run(eng.execute(task))


def test_builds_payout_grade_finding_on_oob_callback():
    findings = _run(_FakeOOBProvider(will_callback=True))
    exp = [f for f in findings if f.vuln_type == VulnType.SSRF]
    assert exp, "blind SSRF finding not produced"
    d = exp[0].to_dict()
    ev = d["additional_info"]["oob_evidence"]
    assert ev["vuln_class"] == "ssrf"
    assert ev["interaction_received"] is True
    assert ev["token"] in ev["payload"]                    # token は送出値(callback URL)に存在
    assert ev["token"] in ev["interaction"]["path"]        # callback path に token
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True
    assert r.marker == "oob_interaction_received"


def test_no_finding_when_no_callback():
    findings = _run(_FakeOOBProvider(will_callback=False))
    assert [f for f in findings if f.vuln_type == VulnType.SSRF] == []


def test_query_mode_replay_descriptor():
    d = _run(_FakeOOBProvider(will_callback=True),
             params={"ssrf_param": "url", "ssrf_modes": ["query"]})[0].to_dict()
    replay = d["additional_info"]["oob_replay"]
    assert replay["mode"] == "query"
    assert replay["method"] == "GET"
    assert replay["payload_template"] == "{OOB}"


def test_json_mode_replay_descriptor():
    d = _run(_FakeOOBProvider(will_callback=True),
             params={"ssrf_param": "url", "ssrf_modes": ["json"]})[0].to_dict()
    replay = d["additional_info"]["oob_replay"]
    assert replay["mode"] == "json"
    assert replay["method"] == "POST"
    assert replay["content_type"] == "application/json"


def test_poc_starts_with_method_and_status_lines():
    d = _run(_FakeOOBProvider(will_callback=True))[0].to_dict()
    assert d["additional_info"]["poc_request"].split()[0] in ("GET", "POST")
    assert d["additional_info"]["poc_response"].startswith("HTTP/1.1 ")
    token = d["additional_info"]["oob_evidence"]["token"]
    assert f"/callback/{token}" in d["additional_info"]["poc_response"]
