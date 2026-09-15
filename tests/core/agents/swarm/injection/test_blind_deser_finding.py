"""SGK-2026-0496: SmartOOBDeserHunter が OOB コールバックガジェットで安全でない
デシリアライズを確定グレードの Finding に変換することを検証する。製品非依存
（合成・注入クライアント/受信器）。標的側の実行は無し（fake client は unpickle しない）。"""

import asyncio
from types import SimpleNamespace

from src.core.agents.swarm.injection.smart_blind_deser import SmartOOBDeserHunter
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.models.finding import VulnType

_URL = "https://target.example/sync"


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
        token = "desertok%d" % self._n
        return f"http://oob.example/callback/{token}", token

    async def poll(self, token, timeout=10.0):
        if not self.will_callback:
            return None
        return {"token": token, "channel": "http", "remote_ip": "10.0.0.9",
                "method": "GET", "path": f"/callback/{token}", "headers": {"Host": "oob.example"}}


class _FakeHTTPClient:
    def __init__(self, status=200):
        self.status = status
        self.calls = []

    async def request(self, method, url, data=None, headers=None, use_proxy=True, **kw):
        self.calls.append({"method": method, "url": url, "data": data})
        return SimpleNamespace(status=self.status, body="", text="", headers={})


def _run(oob, params=None):
    eng = SmartOOBDeserHunter()
    eng._oob = oob
    eng._client = _FakeHTTPClient()
    task = Task(id="t", name="bdes", target=_URL, tags=["deserialization"])
    task.params = params or {"deser_param": "data_obj", "deser_encoding": "hex"}
    return asyncio.run(eng.execute(task))


def test_builds_payout_grade_finding_on_oob_callback():
    findings = _run(_FakeOOBProvider(will_callback=True))
    exp = [f for f in findings if f.vuln_type == VulnType.DESERIALIZATION]
    assert exp, "OOB deserialization finding not produced"
    d = exp[0].to_dict()
    ev = d["additional_info"]["oob_evidence"]
    assert ev["vuln_class"] == "deserialization"
    assert ev["interaction_received"] is True
    assert ev["token"] in ev["payload"]              # token はガジェット内 callback に平文で存在
    assert ev["token"] in ev["interaction"]["path"]
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True
    assert r.marker == "oob_interaction_received"


def test_replay_uses_builder_path():
    d = _run(_FakeOOBProvider(will_callback=True))[0].to_dict()
    replay = d["additional_info"]["oob_replay"]
    assert replay["builder"] == "python_pickle"
    assert replay["encoding"] == "hex"
    assert replay["method"] == "POST"


def test_no_finding_when_no_callback():
    findings = _run(_FakeOOBProvider(will_callback=False))
    assert [f for f in findings if f.vuln_type == VulnType.DESERIALIZATION] == []


def test_hex_encoded_payload_sent():
    # 送出データは hex エンコードされた pickle（fake client の記録で検査）。
    eng = SmartOOBDeserHunter()
    eng._oob = _FakeOOBProvider(will_callback=True)
    client = _FakeHTTPClient()
    eng._client = client
    task = Task(id="t", name="bdes", target=_URL, tags=["deserialization"])
    task.params = {"deser_param": "data_obj", "deser_encoding": "hex"}
    asyncio.run(eng.execute(task))
    sent = client.calls[0]["data"]
    assert isinstance(sent, dict) and "data_obj" in sent
    bytes.fromhex(sent["data_obj"])  # 有効な hex（例外なら失敗）


class _FakeDNSOOBProvider:
    """DNS OOB プロバイダ模擬（channel=dns・poll は問い合わせ FQDN を path に写像）。"""

    channel = "dns"

    def __init__(self):
        self._n = 0

    async def start(self):
        pass

    async def stop(self):
        pass

    def new_callback(self):
        self._n += 1
        token = "dnsdesertok%d" % self._n
        return f"http://{token}.oob.test/", token

    async def poll(self, token, timeout=10.0):
        return {"token": token, "channel": "dns", "remote_ip": "10.0.0.9",
                "method": "DNS", "path": f"{token}.oob.test", "headers": {}}


def test_dns_channel_renders_dns_framed_poc():
    # SGK-2026-0501: DNS OOB は DNS クエリとして提示（HTTP 形式で書かない）。
    findings = _run(_FakeDNSOOBProvider())
    exp = [f for f in findings if f.vuln_type == VulnType.DESERIALIZATION]
    assert exp, "blind DNS deserialization finding not produced"
    d = exp[0].to_dict()
    poc_res = d["additional_info"]["poc_response"]
    ev = d["additional_info"]["oob_evidence"]
    assert ev["channel"] == "dns"
    assert "RAW OUT-OF-BAND DNS QUERIES" in poc_res
    assert "QNAME=" in poc_res
    assert "HTTP/1.1" not in poc_res.split("=====")[-1]  # OOB ブロックに HTTP 行を混ぜない
    assert ev["token"] in ev["interaction"]["path"]
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True          # 汎用 OOB マーカーは DNS でも発火（無改修）
    assert r.marker == "oob_interaction_received"
