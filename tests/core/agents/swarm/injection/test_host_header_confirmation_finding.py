"""SGK-2026-0491: SmartHostHeaderHunter が Host ヘッダ注入（認可バイパス）を差分確認で
確定グレードの Finding に変換することを検証する。製品非依存（合成データ・注入クライアント）。"""

import asyncio
from types import SimpleNamespace

from src.core.agents.swarm.injection.smart_host_header import SmartHostHeaderHunter
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.models.finding import VulnType

_URL = "https://target.example/dashboard"
_SIG = "Mr Mark Oney"
# 署名が offset 1500 超に来るよう長いパディングを入れる（中心スニペット検証も兼ねる）。
_ADMIN_BODY = "<html>" + ("x" * 3000) + f"<td>{_SIG}</td><td>1000000</td></html>"
_DENY_BODY = "Redirecting... you should be redirected to /"


class _HostBypassServer:
    """Host が localhost/127.0.0.1 のときだけ admin body（署名入り）を返す。"""

    async def request(self, method, url, headers=None, allow_redirects=True, use_proxy=True, **kw):
        host = str((headers or {}).get("Host") or "").lower()
        if host in ("localhost", "127.0.0.1"):
            return SimpleNamespace(status=200, body=_ADMIN_BODY, text=_ADMIN_BODY, headers={})
        return SimpleNamespace(status=302, body=_DENY_BODY, text=_DENY_BODY, headers={"Location": "/"})


class _AlwaysAdminServer:
    """常に admin body（署名入り）を返す＝アクセス制御されていない → 確定しない。"""

    async def request(self, method, url, headers=None, allow_redirects=True, use_proxy=True, **kw):
        return SimpleNamespace(status=200, body=_ADMIN_BODY, text=_ADMIN_BODY, headers={})


class _NeverAdminServer:
    """常に拒否（署名が出ない）→ 確定しない。"""

    async def request(self, method, url, headers=None, allow_redirects=True, use_proxy=True, **kw):
        return SimpleNamespace(status=302, body=_DENY_BODY, text=_DENY_BODY, headers={"Location": "/"})


def _run(client, params=None):
    eng = SmartHostHeaderHunter()
    eng._client = client
    task = Task(id="t", name="hhi", target=_URL, tags=["host_header_injection"])
    task.params = params if params is not None else {"hhi_restricted_signature": _SIG}
    return asyncio.run(eng.execute(task))


def test_builds_payout_grade_finding_on_bypass():
    findings = _run(_HostBypassServer())
    exp = [f for f in findings if f.vuln_type == VulnType.HOST_HEADER_INJECTION]
    assert exp, "host header finding not produced"
    d = exp[0].to_dict()
    hh = d["additional_info"]["host_header_evidence"]
    assert hh["injected_header"] == "Host"
    assert hh["injected_host_value"] in ("localhost", "127.0.0.1")
    # 署名が offset>1500 でも中心スニペットで保持される。
    assert _SIG in hh["injected_served_body"]
    assert _SIG not in hh["control_served_body"]
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True
    assert r.marker == "host_header_auth_bypass"


def test_two_step_differential_poc():
    d = _run(_HostBypassServer())[0].to_dict()
    poc_req = d["additional_info"]["poc_request"]
    assert "Step 1" in poc_req and "Step 2" in poc_req
    assert _SIG in d["additional_info"]["poc_response"]


def test_replay_descriptor_present():
    d = _run(_HostBypassServer())[0].to_dict()
    replay = d["additional_info"]["host_header_replay"]
    assert replay["header"] == "Host"
    assert replay["signature"] == _SIG
    assert replay["value"] in ("localhost", "127.0.0.1")


def test_no_finding_when_not_access_controlled():
    # 非バイパスでも署名が出る → 差分にならない → 確定しない。
    findings = _run(_AlwaysAdminServer())
    assert [f for f in findings if f.vuln_type == VulnType.HOST_HEADER_INJECTION] == []


def test_no_finding_when_always_denied():
    findings = _run(_NeverAdminServer())
    assert [f for f in findings if f.vuln_type == VulnType.HOST_HEADER_INJECTION] == []


def test_no_finding_without_signature():
    findings = _run(_HostBypassServer(), params={})
    assert findings == []
