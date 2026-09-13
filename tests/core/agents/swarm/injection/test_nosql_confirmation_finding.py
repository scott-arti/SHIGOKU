"""SGK-2026-0487: SmartNoSQLHunter が NoSQL 演算子注入を差分確認で確定グレードの
Finding に変換することを検証する。製品非依存（合成データ・注入クライアント）。
認証トークンは poc でマスクされ evidence.request_headers にのみ保持される。"""

import asyncio
import json
from types import SimpleNamespace

from src.core.agents.swarm.injection.smart_nosql import SmartNoSQLHunter
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.models.finding import VulnType

_URL = "https://target.example/api/validate-coupon"
_FAKE_TOKEN = "FAKE_BEARER_9f3xyz"
_COUPON = '{"coupon_code":"TRAC075","amount":"75"}'


class _DifferentialClient:
    """演算子(dict)→200+データ、リテラル(str)→500 を返す注入クライアント。"""

    def __init__(self):
        self.calls = []

    async def request(self, method, url, data=None, headers=None, use_proxy=True, **kw):
        self.calls.append({"method": method, "url": url, "data": data})
        body = json.loads(data) if data else {}
        val = body.get("coupon_code")
        if isinstance(val, dict):  # operator
            return SimpleNamespace(status=200, text=_COUPON, body=_COUPON, headers={})
        return SimpleNamespace(status=500, text="{}", body="{}", headers={})


class _AlwaysDataClient:
    """常に 200+データ（差分が作れない＝確定しないことの検証用）。"""

    async def request(self, method, url, data=None, headers=None, use_proxy=True, **kw):
        return SimpleNamespace(status=200, text=_COUPON, body=_COUPON, headers={})


def _run(client):
    eng = SmartNoSQLHunter()
    eng._client = client
    task = Task(id="t", name="nosql", target=_URL, tags=["nosql"])
    task.params = {
        "_auth": {"auth_headers": {"Authorization": "Bearer " + _FAKE_TOKEN}},
        "nosql_fields": ["coupon_code"],
    }
    return asyncio.run(eng.execute(task))


def test_builds_payout_grade_finding_on_differential():
    findings = _run(_DifferentialClient())
    exp = [f for f in findings if f.vuln_type == VulnType.NOSQL_INJECTION]
    assert exp, "NoSQLi finding not produced"
    d = exp[0].to_dict()
    ne = d["additional_info"]["nosql_evidence"]
    assert ne["field"] == "coupon_code"
    assert ne["operator_status"] == 200
    assert ne["control_status"] == 500
    assert "$ne" in ne["operator_payload"]
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True
    assert r.marker == "nosql_operator_injection"


def test_token_masked_in_poc_but_kept_in_evidence_for_replay():
    d = _run(_DifferentialClient())[0].to_dict()
    # poc は表示用でマスク
    assert _FAKE_TOKEN not in d["additional_info"]["poc_request"]
    assert "<redacted>" in d["additional_info"]["poc_request"]
    # evidence.request_headers は封印再現用に実 auth を保持
    assert d["evidence"]["request_headers"].get("Authorization") == "Bearer " + _FAKE_TOKEN


def test_replay_descriptor_carries_operator():
    d = _run(_DifferentialClient())[0].to_dict()
    replay = d["additional_info"]["nosql_replay"]
    assert replay["method"] == "POST"
    assert isinstance(replay["body"], dict)
    assert "$ne" in json.dumps(replay["body"])


def test_no_finding_when_control_also_succeeds():
    # 負のコントロールも成功する（差分が作れない）→ finding を作らない
    findings = _run(_AlwaysDataClient())
    assert [f for f in findings if f.vuln_type == VulnType.NOSQL_INJECTION] == []


def test_judge_visible_fields_have_no_raw_token():
    d = _run(_DifferentialClient())[0].to_dict()
    ev = d["evidence"]
    ai = d["additional_info"]
    visible = "".join([
        str(ev.get("response_body", "")),
        str(ai.get("poc_request", "")),
        str(ai.get("poc_response", "")),
    ])
    assert _FAKE_TOKEN not in visible
