"""SGK-2026-0498: SmartOOBDeserHunter の Java SnakeYAML(path モード)対応を検証する。
base64 ガジェットを URL パス末尾に付けて GET し、OOB コールバック(多段パス・JVM の
User-Agent)で確定グレードの Finding になること。製品非依存（合成 client/受信器・標的実行なし）。"""

import asyncio
import base64
from types import SimpleNamespace

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.agents.swarm.injection.smart_blind_deser import SmartOOBDeserHunter
from src.core.models.finding import VulnType

_URL = "https://target.example/config"


class _FakeJavaOOBProvider:
    """Java ScriptEngineManager が META-INF/services を多段パスで取得し、返したクラス名を
    取得しにくる挙動を模擬（token 入りの多段パス＋Java User-Agent）。"""

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
        token = "javatok%d" % self._n
        return f"http://127.0.0.1:13337/callback/{token}", token

    async def poll(self, token, timeout=10.0):
        if not self.will_callback:
            return None
        ua = {"User-Agent": "Java/1.8.0_212", "Host": "127.0.0.1:13337"}
        lines = [
            {"token": token, "method": "HEAD",
             "path": f"/callback/{token}/META-INF/services/javax.script.ScriptEngineFactory",
             "remote_ip": "127.0.0.1", "headers": ua},
            {"token": token, "method": "GET",
             "path": f"/callback/{token}/META-INF/services/javax.script.ScriptEngineFactory",
             "remote_ip": "127.0.0.1", "headers": ua},
            {"token": token, "method": "GET", "path": f"/callback/{token}/OK.class",
             "remote_ip": "127.0.0.1", "headers": ua},
        ]
        first = dict(lines[0])
        first["interactions"] = lines
        return first


class _RecordingClient:
    def __init__(self, status=500):
        self.status = status
        self.calls = []

    async def request(self, method, url, data=None, headers=None, use_proxy=True, **kw):
        self.calls.append({"method": method, "url": url, "data": data})
        return SimpleNamespace(status=self.status, body="", text="", headers={})


def _run(provider, client, params=None):
    eng = SmartOOBDeserHunter()
    eng._oob = provider
    eng._client = client
    task = Task(id="t", name="java-des", target=_URL, tags=["deserialization"])
    task.params = params or {
        "deser_kind": "java_snakeyaml", "deser_encoding": "base64", "deser_mode": "path",
    }
    return asyncio.run(eng.execute(task))


def test_java_path_mode_builds_payout_grade_finding():
    findings = _run(_FakeJavaOOBProvider(will_callback=True), _RecordingClient())
    exp = [f for f in findings if f.vuln_type == VulnType.DESERIALIZATION]
    assert exp, "Java OOB deserialization finding not produced"
    d = exp[0].to_dict()
    ev = d["additional_info"]["oob_evidence"]
    assert ev["token"] in ev["payload"]
    assert ev["token"] in ev["interaction"]["path"]
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True
    assert r.marker == "oob_interaction_received"


def test_java_path_mode_sends_get_with_base64_in_path():
    client = _RecordingClient()
    _run(_FakeJavaOOBProvider(will_callback=True), client)
    assert client.calls, "no request sent"
    call = client.calls[0]
    assert call["method"] == "GET"
    # base64 ガジェットが URL パス末尾に付く（/config/<base64>）。デコード可能な実バイト列。
    assert call["url"].startswith(_URL + "/")
    b64 = call["url"].rsplit("/", 1)[1]
    decoded = base64.b64decode(b64).decode("utf-8")
    assert "javax.script.ScriptEngineManager" in decoded


def test_java_poc_has_concrete_payload_and_jvm_user_agent():
    d = _run(_FakeJavaOOBProvider(will_callback=True), _RecordingClient())[0].to_dict()
    info = d["additional_info"]
    poc_req = info["poc_request"]
    poc_res = info["poc_response"]
    # PoC はプレースホルダではなく実際の base64 URL（judge の再現要件）。
    assert "<java_snakeyaml gadget" not in poc_req
    b64_part = poc_req.split(_URL + "/", 1)[1].split(" ", 1)[0]
    assert "ScriptEngineManager" in base64.b64decode(b64_part).decode("utf-8")
    # 生受信ログに JVM の User-Agent と ServiceLoader の class 取得行が含まれる。
    assert "Java/1.8.0_212" in poc_res
    assert "OK.class" in poc_res


def test_java_replay_descriptor_is_builder_path_get():
    d = _run(_FakeJavaOOBProvider(will_callback=True), _RecordingClient())[0].to_dict()
    replay = d["additional_info"]["oob_replay"]
    assert replay["builder"] == "java_snakeyaml"
    assert replay["encoding"] == "base64"
    assert replay["mode"] == "path"
    assert replay["method"] == "GET"


def test_java_no_finding_when_no_callback():
    findings = _run(_FakeJavaOOBProvider(will_callback=False), _RecordingClient())
    assert [f for f in findings if f.vuln_type == VulnType.DESERIALIZATION] == []
