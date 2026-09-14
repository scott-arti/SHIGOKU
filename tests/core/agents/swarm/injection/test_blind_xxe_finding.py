"""SGK-2026-0494: SmartBlindXXEHunter が OOB(帯域外)コールバックでブラインド XXE を
確定グレードの Finding に変換することを検証する。製品非依存（合成・注入クライアント/受信器）。"""

import asyncio
from types import SimpleNamespace

from src.core.agents.swarm.injection.smart_blind_xxe import SmartBlindXXEHunter
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.models.finding import VulnType

_URL = "https://target.example/home"


class _FakeOOBProvider:
    """new_callback で (url, token) を配り、poll でその token 付きの callback を模擬する。"""

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
        token = "shigokuxxetok%d" % self._n
        return f"http://oob.example/callback/{token}", token

    async def poll(self, token, timeout=10.0):
        if not self.will_callback:
            return None
        return {
            "token": token, "channel": "http", "remote_ip": "10.0.0.9",
            "method": "GET", "path": f"/callback/{token}", "query_string": "",
            "timestamp": 1.0, "headers": {"Host": "oob.example", "User-Agent": "curl"},
        }


class _FakeHTTPClient:
    """標的への送信を模擬（in-band は空＝ブラインド）。"""

    def __init__(self, status=200):
        self.status = status
        self.calls = []

    async def request(self, method, url, data=None, headers=None, use_proxy=True, **kw):
        self.calls.append({"method": method, "url": url, "data": data})
        return SimpleNamespace(status=self.status, body="", text="", headers={})


def _run(oob, client=None):
    eng = SmartBlindXXEHunter()
    eng._oob = oob
    eng._client = client or _FakeHTTPClient()
    task = Task(id="t", name="bxxe", target=_URL, tags=["xxe"])
    task.params = {"xxe_param": "xxe"}
    return asyncio.run(eng.execute(task))


def test_builds_payout_grade_finding_on_oob_callback():
    findings = _run(_FakeOOBProvider(will_callback=True))
    exp = [f for f in findings if f.vuln_type == VulnType.XXE]
    assert exp, "blind XXE finding not produced"
    d = exp[0].to_dict()
    ev = d["additional_info"]["oob_evidence"]
    assert ev["interaction_received"] is True
    assert ev["token"] in ev["payload"]                       # token は外部実体URLに存在
    assert ev["token"] in ev["interaction"]["path"]           # callback path に token
    assert d["additional_info"]["unique_oob_callback_received"] is True
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True
    assert r.marker == "oob_interaction_received"


def test_no_finding_when_no_callback():
    findings = _run(_FakeOOBProvider(will_callback=False))
    assert [f for f in findings if f.vuln_type == VulnType.XXE] == []


def test_replay_descriptor_has_placeholder_template():
    d = _run(_FakeOOBProvider(will_callback=True))[0].to_dict()
    replay = d["additional_info"]["oob_replay"]
    assert replay["method"] == "POST"
    assert "{OOB}" in replay["payload_template"]
    assert replay["mode"] in ("form", "raw")


def test_poc_starts_with_method_and_status_lines():
    # 再現性ゲートは poc がメソッド行/ステータス行で始まることを要求（SGK-2026-0494）。
    d = _run(_FakeOOBProvider(will_callback=True))[0].to_dict()
    assert d["additional_info"]["poc_request"].startswith("POST ")
    assert d["additional_info"]["poc_response"].startswith("HTTP/1.1 ")
    # 生の OOB inbound リクエストが raw で載る（要約コメントでない）。
    token = d["additional_info"]["oob_evidence"]["token"]
    assert f"/callback/{token}" in d["additional_info"]["poc_response"]
