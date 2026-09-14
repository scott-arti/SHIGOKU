"""SGK-2026-0497: SmartPrototypePollutionHunter がプロトタイプ汚染を in-band 差分で
確定グレードの Finding に変換することを検証する。製品非依存（合成・注入クライアント）。
fake サーバは lodash.merge 相当の汚染＋継承反映を模擬する。"""

import asyncio
import json
from types import SimpleNamespace

from src.core.agents.swarm.injection.smart_prototype_pollution import SmartPrototypePollutionHunter
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.models.finding import VulnType

_B = "https://target.example"


class _FakePPServer:
    """/message で __proto__ を汚染（グローバル）、/login で継承 admin を反映（Node.js 相当）。"""

    def __init__(self, vulnerable=True):
        self.vulnerable = vulnerable
        self.proto = {}

    async def request(self, method, url, data=None, headers=None, use_proxy=True, **kw):
        if url.endswith("/message"):
            body = json.loads(data) if isinstance(data, str) else (data or {})
            proto = body.get("__proto__")
            if self.vulnerable and isinstance(proto, dict):
                self.proto.update(proto)
            return SimpleNamespace(status=302, body="", text="", headers={})
        if url.endswith("/create"):
            return SimpleNamespace(status=200, body="created", text="created", headers={})
        if url.endswith("/login"):
            admin = self.proto.get("admin", "")   # 継承（新オブジェクトは own admin 無し）
            b = f"<h4>Admin: <B>{admin}</B></h4>"
            return SimpleNamespace(status=200, body=b, text=b, headers={})
        return SimpleNamespace(status=404, body="", text="", headers={})


def _scenario():
    return {
        "pp_sink": {"method": "POST", "url": f"{_B}/message", "mode": "json",
                    "body": {"__proto__": {"admin": "{marker}"}, "email": "e@e.co", "msg": "x"}},
        "pp_setup": [{"method": "POST", "url": f"{_B}/create", "mode": "form",
                      "body": {"username": "{uniq}", "password": "p"}}],
        "pp_observe": {"method": "POST", "url": f"{_B}/login", "mode": "form",
                       "body": {"username": "{uniq}", "password": "p"}},
        "pp_property": "admin",
    }


def _run(client, params=None):
    eng = SmartPrototypePollutionHunter()
    eng._client = client
    task = Task(id="t", name="pp", target=f"{_B}/message", tags=["prototype_pollution"])
    task.params = params or _scenario()
    return asyncio.run(eng.execute(task))


def test_builds_payout_grade_finding_on_pollution():
    findings = _run(_FakePPServer(vulnerable=True))
    exp = [f for f in findings if f.vuln_type == VulnType.PROTOTYPE_POLLUTION]
    assert exp, "prototype pollution finding not produced"
    d = exp[0].to_dict()
    ev = d["additional_info"]["prototype_pollution_evidence"]
    assert ev["pollute_property"] == "admin"
    assert ev["marker"] in ev["polluted_served_body"]      # 汚染後の新オブジェクトに出現
    assert ev["marker"] not in ev["control_served_body"]   # 汚染前は不在
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True
    assert r.marker == "prototype_pollution_confirmed"


def test_no_finding_when_not_vulnerable():
    # __proto__ を無視するサーバ（汚染されない）→ 差分にならない → 確定しない。
    findings = _run(_FakePPServer(vulnerable=False))
    assert [f for f in findings if f.vuln_type == VulnType.PROTOTYPE_POLLUTION] == []


def test_two_step_differential_poc():
    d = _run(_FakePPServer(vulnerable=True))[0].to_dict()
    poc_req = d["additional_info"]["poc_request"]
    assert "Step 1" in poc_req and "Step 2" in poc_req and "Step 3" in poc_req
    marker = d["additional_info"]["prototype_pollution_evidence"]["marker"]
    assert marker in d["additional_info"]["poc_response"]


def test_replay_descriptor_present():
    d = _run(_FakePPServer(vulnerable=True))[0].to_dict()
    replay = d["additional_info"]["prototype_pollution_replay"]
    assert isinstance(replay.get("sink"), dict)
    assert isinstance(replay.get("observe"), dict)
    assert "{marker}" in json.dumps(replay["sink"])
    assert replay["property"] == "admin"


def test_no_finding_without_scenario():
    eng = SmartPrototypePollutionHunter()
    eng._client = _FakePPServer(vulnerable=True)
    task = Task(id="t", name="pp", target=f"{_B}/message", tags=["prototype_pollution"])
    task.params = {}
    assert asyncio.run(eng.execute(task)) == []
