"""SGK-2026-0489: SmartRaceConditionHunter が TOCTOU レースを逐次/並列差分で確定
グレードの Finding に変換することを検証する。製品非依存（合成データ・注入クライアント）。"""

import asyncio
import re
from types import SimpleNamespace

from src.core.agents.swarm.injection.smart_race_condition import SmartRaceConditionHunter
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.models.finding import VulnType

_URL = "https://target.example/race"
_MARKER_RE = re.compile(r"SHIGOKU_RACE_[0-9a-f]+")


def _scenario():
    return {
        "race_trigger": {"method": "GET", "url": _URL,
                         "params": {"action": "validate", "person": 'x"; echo {marker} #'}},
        "race_observe": {"method": "GET", "url": _URL, "params": {"action": "run"}},
        "race_reset": {"method": "GET", "url": _URL, "params": {"action": "reset"}},
        "race_concurrency": 4,
        "race_rounds": 3,
    }


class _RaceClient:
    """逐次(最初の observe)ではマーカー非反映、並列(以降の observe)で反映＝本物の race。"""

    def __init__(self):
        self.seen = None
        self.observe_count = 0

    async def request(self, method, url, params=None, headers=None, use_proxy=True, **kw):
        params = params or {}
        person = str(params.get("person") or "")
        m = _MARKER_RE.search(person)
        if m:
            self.seen = m.group(0)
        if params.get("action") == "run":
            self.observe_count += 1
            if self.observe_count <= 1:  # 逐次コントロール
                body = '<div id="system-message">Default User</div>'
            else:  # 並列バースト
                body = f'<div id="system-message">{self.seen}</div>'
            return SimpleNamespace(status=200, body=body, text=body, headers={})
        return SimpleNamespace(status=200, body="ok", text="ok", headers={})


class _NeverReflectClient:
    async def request(self, method, url, params=None, headers=None, use_proxy=True, **kw):
        body = '<div id="system-message">Default User</div>'
        return SimpleNamespace(status=200, body=body, text=body, headers={})


class _AlwaysReflectClient:
    """逐次でもマーカーを反映（＝ロック/検証が無い＝TOCTOU でない）。"""

    async def request(self, method, url, params=None, headers=None, use_proxy=True, **kw):
        person = str((params or {}).get("person") or "")
        m = _MARKER_RE.search(person)
        mk = m.group(0) if m else "x"
        if (params or {}).get("action") == "run":
            body = f'<div id="system-message">{mk}</div>'
            return SimpleNamespace(status=200, body=body, text=body, headers={})
        # observe with no action → still reflect (always)
        return SimpleNamespace(status=200, body=f'<div>{mk}</div>', text="", headers={})


def _run(client, params=None):
    eng = SmartRaceConditionHunter()
    eng._client = client
    task = Task(id="t", name="race", target=_URL, tags=["race_condition"])
    task.params = params if params is not None else _scenario()
    return asyncio.run(eng.execute(task))


def test_builds_payout_grade_finding_on_differential():
    findings = _run(_RaceClient())
    exp = [f for f in findings if f.vuln_type == VulnType.RACE_CONDITION]
    assert exp, "race finding not produced"
    d = exp[0].to_dict()
    rev = d["additional_info"]["race_evidence"]
    assert rev["marker"] in rev["race_served_body"]
    assert rev["marker"] not in rev["control_served_body"]
    assert rev["race_status"] == 200
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True
    assert r.marker == "race_condition_toctou"


def test_two_step_differential_poc():
    d = _run(_RaceClient())[0].to_dict()
    poc_req = d["additional_info"]["poc_request"]
    poc_res = d["additional_info"]["poc_response"]
    assert "Step 1" in poc_req and "Step 2" in poc_req
    assert "concurrent" in poc_req.lower() or "並列" in poc_req or "burst" in poc_req.lower()
    marker = d["additional_info"]["race_evidence"]["marker"]
    assert marker in poc_res  # race side present


def test_replay_descriptor_present():
    d = _run(_RaceClient())[0].to_dict()
    replay = d["additional_info"]["race_replay"]
    assert isinstance(replay.get("observe"), dict)
    assert isinstance(replay.get("trigger"), dict)
    assert "{marker}" in str(replay["trigger"]["params"])


def test_no_finding_when_race_never_reflects():
    findings = _run(_NeverReflectClient())
    assert [f for f in findings if f.vuln_type == VulnType.RACE_CONDITION] == []


def test_no_finding_when_control_also_reflects():
    # 逐次でも反映＝ロック/検証が無い（TOCTOU でない）→ 確定しない。
    findings = _run(_AlwaysReflectClient())
    assert [f for f in findings if f.vuln_type == VulnType.RACE_CONDITION] == []


def test_no_finding_without_scenario():
    eng = SmartRaceConditionHunter()
    eng._client = _RaceClient()
    task = Task(id="t", name="race", target=_URL, tags=["race_condition"])
    task.params = {}
    assert asyncio.run(eng.execute(task)) == []
