"""SGK-2026-0488: SmartMassAssignmentHunter が特権フィールド昇格を差分確認で
確定グレードの Finding に変換することを検証する。製品非依存（合成データ・注入
クライアント）。任意 auth トークンは poc でマスクされ evidence.request_headers
にのみ保持される。"""

import asyncio
import json
from types import SimpleNamespace

from src.core.agents.swarm.injection.smart_mass_assignment import SmartMassAssignmentHunter
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.models.finding import VulnType

_URL = "https://target.example/api/Users"
_FAKE_TOKEN = "FAKE_BEARER_9f3xyz"
_BASE = {"email": "seed@target.example", "password": "x", "passwordRepeat": "x"}


class _MAClient:
    """role を送れば反映、送らなければサーバ既定 'customer' を返す（本物挙動）。"""

    def __init__(self):
        self.calls = []

    async def request(self, method, url, data=None, headers=None, use_proxy=True, **kw):
        self.calls.append({"data": data})
        body = json.loads(data) if data else {}
        role = body["role"] if "role" in body else "customer"
        resp = json.dumps({"status": "success",
                           "data": {"id": 1, "email": body.get("email"), "role": role}})
        return SimpleNamespace(status=201, text=resp, body=resp, headers={})


class _EchoClient:
    """送ったフィールドだけを反響（control では role が応答に現れない＝echo）。"""

    async def request(self, method, url, data=None, headers=None, use_proxy=True, **kw):
        body = json.loads(data) if data else {}
        d = {"id": 1, "email": body.get("email")}
        for k in ("role", "isAdmin", "is_admin", "verified"):
            if k in body:
                d[k] = body[k]
        resp = json.dumps({"data": d})
        return SimpleNamespace(status=201, text=resp, body=resp, headers={})


class _AlwaysAdminClient:
    """常に role=admin を返す（control でも既に admin＝昇格にならない）。"""

    async def request(self, method, url, data=None, headers=None, use_proxy=True, **kw):
        resp = json.dumps({"data": {"id": 1, "role": "admin"}})
        return SimpleNamespace(status=201, text=resp, body=resp, headers={})


def _run(client, params=None):
    eng = SmartMassAssignmentHunter()
    eng._client = client
    task = Task(id="t", name="ma", target=_URL, tags=["mass_assignment"])
    task.params = {"mass_assignment_base_body": dict(_BASE)}
    if params:
        task.params.update(params)
    return asyncio.run(eng.execute(task))


def test_builds_payout_grade_finding_on_differential():
    findings = _run(_MAClient())
    exp = [f for f in findings if f.vuln_type == VulnType.MASS_ASSIGNMENT]
    assert exp, "mass assignment finding not produced"
    d = exp[0].to_dict()
    mae = d["additional_info"]["mass_assignment_evidence"]
    assert mae["field"] == "role"
    assert mae["injected_field_value"] == "admin"
    assert mae["control_field_value"] == "customer"
    assert mae["injected_status"] == 201
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True
    assert r.marker == "privileged_field_assigned"


def test_two_step_differential_poc_shows_both_sides():
    d = _run(_MAClient())[0].to_dict()
    poc_req = d["additional_info"]["poc_request"]
    poc_res = d["additional_info"]["poc_response"]
    # control（フィールド無し）と injection（role:admin）の両ステップが載る。
    assert "Step 1" in poc_req and "Step 2" in poc_req
    assert '"role": "admin"' in poc_req or '"role":"admin"' in poc_req
    assert "customer" in poc_res and "admin" in poc_res


def test_replay_descriptor_fresh_body_carries_field():
    d = _run(_MAClient())[0].to_dict()
    replay = d["additional_info"]["mass_assignment_replay"]
    assert replay["method"] == "POST"
    assert isinstance(replay["body"], dict)
    assert replay["body"].get("role") == "admin"
    assert replay["field"] == "role"
    assert replay["expected_value"] == "admin"


def test_no_finding_when_echo_only():
    # control でフィールドが応答に現れない（server-controlled でない）→ 確定しない。
    findings = _run(_EchoClient())
    assert [f for f in findings if f.vuln_type == VulnType.MASS_ASSIGNMENT] == []


def test_no_finding_when_control_already_privileged():
    # control でも既に admin（差分が作れない）→ 確定しない。
    findings = _run(_AlwaysAdminClient())
    assert [f for f in findings if f.vuln_type == VulnType.MASS_ASSIGNMENT] == []


def test_no_finding_without_base_body():
    eng = SmartMassAssignmentHunter()
    eng._client = _MAClient()
    task = Task(id="t", name="ma", target=_URL, tags=["mass_assignment"])
    task.params = {}
    assert asyncio.run(eng.execute(task)) == []


def test_optional_auth_masked_in_poc_kept_in_evidence():
    d = _run(_MAClient(),
             {"_auth": {"auth_headers": {"Authorization": "Bearer " + _FAKE_TOKEN}}})[0].to_dict()
    assert _FAKE_TOKEN not in d["additional_info"]["poc_request"]
    assert "<redacted>" in d["additional_info"]["poc_request"]
    assert d["evidence"]["request_headers"].get("Authorization") == "Bearer " + _FAKE_TOKEN


def test_judge_visible_fields_have_no_raw_token():
    from src.core.validation.finding_validator import PoCJudge
    d = _run(_MAClient(),
             {"_auth": {"auth_headers": {"Authorization": "Bearer " + _FAKE_TOKEN}}})[0].to_dict()
    user_content = PoCJudge._build_user_payload(d)
    assert _FAKE_TOKEN not in user_content
